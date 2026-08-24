use std::net::SocketAddr;

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::any,
};
use anyhow::Context;
use base64::Engine as _;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::{AUTH_DATA, AUTH_MESSAGE};
use crate::data::KEY_BIN;
use crate::module_builder::LogEntryWithContent;
use crate::response::{self, entry_type_id_from_name, entry_type_name};
use crate::storage::LogEntryData;
use crate::utils;
use crate::{AppState, module_builder};

pub fn router(state: AppState) -> Router {
    Router::new()
        .fallback(any(ws_upgrade))
        .with_state(state)
}

async fn ws_upgrade(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    tracing::debug!("new connection from {}", addr);
    ws.max_message_size(50 * 1024 * 1024)
        .on_upgrade(move |socket| handle_ws(socket, state, addr))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, addr: SocketAddr) {
    let first = socket.recv().await;
    let token = match first {
        Some(Ok(ref msg)) => {
            match msg {
                Message::Text(t) => t.lines().next().unwrap_or("").trim().to_string(),
                _ => String::new(),
            }
        }
        Some(Err(e)) => {
            tracing::warn!("recv error: {e}");
            return;
        }
        None => {
            tracing::info!("[WS] <- Client disconnected before sending");
            return;
        }
    };

    if token.is_empty() {
        tracing::warn!("no token, closing");
        return;
    }

    state
        .ip_tokens
        .write()
        .await
        .insert(addr.ip(), token.clone());

    let username = state.storage.username().await;

    let auth = json!({
        "Type": "Auth",
        "Message": AUTH_MESSAGE,
        "Data": AUTH_DATA,
    });
    if socket
        .send(Message::Text(auth.to_string().into()))
        .await
        .is_err()
    {
        tracing::error!("auth send error");
        return;
    }

    let module_bin = if let Some(ref raw) = state.raw_module {
        raw.clone()
    } else {
        match build_user_module(&state, &username).await {
            Ok(bin) => bin,
            Err(e) => {
                tracing::error!("module build error: {e:?}");
                return;
            }
        }
    };

    if socket
        .send(Message::Binary(module_bin.into()))
        .await
        .is_err()
    {
        tracing::error!("module send error");
        return;
    }

    if socket
        .send(Message::Binary(KEY_BIN.to_vec().into()))
        .await
        .is_err()
    {
        tracing::error!("key send error");
        return;
    }

    let live_conn_id = Uuid::new_v4();
    let (live_tx, mut live_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    state
        .live_replies
        .write()
        .await
        .entry(token.clone())
        .or_default()
        .insert(live_conn_id, live_tx);
    let mut msg_count = 0u32;
    loop {
        tokio::select! {
            maybe_reply = live_rx.recv() => {
                match maybe_reply {
                    Some(reply) => send_reply(&mut socket, &reply, "[WS] Live").await,
                    None => break,
                }
            }
            maybe_msg = socket.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };

                match msg {
                    Ok(msg) => {
                        if matches!(msg, Message::Close(_)) {
                            break;
                        }
                        msg_count += 1;

                        if let Message::Binary(ref data) = msg {
                            handle_binary_msg(&state, &username, data, msg_count, &mut socket).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("ws error: {e}");
                        break;
                    }
                }
            }
        }
    }

    unregister_live_reply(&state, &token, live_conn_id).await;
    let _ = state.shutdown_tx.send(true);

    tracing::info!("disconnected ({msg_count} msgs)");
}

async fn build_user_module(state: &AppState, username: &str) -> anyhow::Result<Vec<u8>> {
    let user_data = state.storage.user_data().await;
    let log_entries = state.storage.log_entries().await;

    let mut entries_with_content: Vec<LogEntryWithContent> = Vec::new();
    for entry in &log_entries {
        let content = if entry.entry_type == "Script" || entry.entry_type == "Style" {
            state.storage.read_entry_content(entry.entry_id).await?
        } else {
            None
        };
        entries_with_content.push(LogEntryWithContent {
            entry_id: entry.entry_id,
            timestamp: entry.timestamp,
            entry_type: entry.entry_type.clone(),
            author: entry.author.clone(),
            name: entry.name.clone(),
            content,
            deleted: entry.deleted_at.is_some(),
        });
    }

    let user_languages = state.language_translations.read().await.clone();

    module_builder::build_module_bin(
        &state.base_module,
        username,
        user_data.type7_blob.as_deref(),
        user_data.last_loaded_config_id,
        user_data.last_loaded_style_id,
        &entries_with_content,
        &user_languages,
    )
}

async fn handle_binary_msg(
    state: &AppState,
    username: &str,
    data: &[u8],
    msg_num: u32,
    socket: &mut WebSocket,
) {
    use nl_parser::pipeline;

    let prefix = format!("msg#{msg_num}");

    let decompressed = match pipeline::decrypt(data) {
        Ok(decrypted) => match pipeline::decompress(&decrypted, pipeline::MAX_WS_DECOMPRESSED_SIZE)
        {
            Ok(d) => d,
            Err(_) => {
                tracing::debug!("{prefix} decompress failed");
                return;
            }
        },
        Err(_) => {
            tracing::debug!("{prefix} decrypt failed");
            return;
        }
    };

    match crate::client_msg::parse(&decompressed) {
        Ok(msg) => {
            if let crate::client_msg::ClientMsg::StateBlob { payload } = &msg {
                if let Err(e) = save_type7_blob(state, payload, &prefix).await {
                    tracing::error!("{prefix} type7 persist error: {e}");
                }
            }
            let reply = handle_client_msg(state, username, &msg, &prefix).await;
            if let Some(reply_bytes) = reply {
                send_reply(socket, &reply_bytes, &prefix).await;
            }
        }
        Err(e) => {
            tracing::warn!("parse error: {e}");
        }
    }
}

async fn send_reply(socket: &mut WebSocket, flatbuffer: &[u8], _prefix: &str) {
    use nl_parser::pipeline;
    let compressed = pipeline::compress(flatbuffer);
    match pipeline::encrypt(&compressed) {
        Ok(encrypted) => {
            if socket
                .send(Message::Binary(encrypted.into()))
                .await
                .is_err()
            {
                tracing::error!("send reply error");
            }
        }
        Err(e) => {
            tracing::error!("encrypt reply error: {e}");
        }
    }
}

async fn unregister_live_reply(state: &AppState, token: &str, conn_id: Uuid) {
    let mut live_replies = state.live_replies.write().await;
    if let Some(conns) = live_replies.get_mut(token) {
        conns.remove(&conn_id);
        if conns.is_empty() {
            live_replies.remove(token);
        }
    }
}

async fn handle_client_msg(
    state: &AppState,
    username: &str,
    msg: &crate::client_msg::ClientMsg,
    prefix: &str,
) -> Option<Vec<u8>> {
    use crate::client_msg::ClientMsg;

    match msg {
        ClientMsg::Init { .. } => None,

        ClientMsg::ConfigAck { entry_id } => {

            let log_entry = match state.storage.get_log_entry(*entry_id as i32).await {
                Some(row) => row,
                None => {
                    tracing::warn!(
                        "{prefix} ConfigAck entry_id={entry_id} had no matching log entry"
                    );
                    return None;
                }
            };

            if log_entry.entry_type != "Config" {
                return None;
            }

            let content = match state
                .storage
                .read_entry_content(*entry_id as i32)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    tracing::warn!("{prefix} ConfigAck entry_id={entry_id} no stored config");
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} load config error: {e}");
                    return None;
                }
            };

            if let Err(e) = state
                .storage
                .update_last_loaded_entry("Config", *entry_id as i32)
                .await
            {
                tracing::error!("{prefix} remember config error: {e}");
            }

            match response::build_case11_response(*entry_id, &content) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} build case11 reply error: {e}");
                    None
                }
            }
        }

        ClientMsg::ShareClick { .. } => None,

        ClientMsg::StateBlob { .. } => None,

        ClientMsg::LanguageAck { lang_code } => {
            let translations_guard = state.language_translations.read().await;
            let Some(value) = translations_guard.get(lang_code) else {
                tracing::warn!("{prefix} no translations for {lang_code}");
                return None;
            };
            let json_bytes = match nl_parser::module::serialize_translations_json(value) {
                Ok(b) => b,
                Err(e) => { tracing::error!("{prefix} serialize error: {e}"); return None; }
            };
            let json_str = match std::str::from_utf8(&json_bytes) {
                Ok(s) => s,
                Err(e) => { tracing::error!("{prefix} UTF-8 error: {e}"); return None; }
            };
            match response::build_language_ack_response_type12(lang_code, json_str) {
                Ok(reply) => Some(reply),
                Err(e) => { tracing::error!("{prefix} build error: {e}"); None }
            }
        }

        ClientMsg::CreateEntry {
            name,
            entry_type,
            expected_count: _,
            content,
        } => {
            let type_str = entry_type_name(*entry_type);

            let entry_id = match state.storage.next_entry_id().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} next entry_id error: {e}");
                    return None;
                }
            };

            let now_ts = utils::unix_timestamp();

            let log_entry = LogEntryData {
                entry_id,
                timestamp: now_ts,
                entry_type: type_str.to_string(),
                author: username.to_string(),
                name: name.clone(),
                created_at: utils::now_iso(),
                deleted_at: None,
            };

            if let Err(e) = state.storage.add_log_entry(log_entry).await {
                tracing::error!("{prefix} add log entry error: {e}");
                return None;
            }

            let initial_content = content.as_deref().unwrap_or("");
            let mut actual_content = match state.storage.read_entry_content(entry_id).await {
                Ok(Some(existing)) if !existing.is_empty() => existing,
                _ => {
                    if let Err(e) = state
                        .storage
                        .write_entry_content(entry_id, initial_content)
                        .await
                    {
                        tracing::error!("{prefix} write content error: {e}");
                        return None;
                    }
                    initial_content.to_string()
                }
            };

            if type_str == "Language" && !actual_content.is_empty() {
                if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&actual_content) {
                    let lang_code = name.clone();

                    let base_lang = value
                        .get("info")
                        .and_then(|i| i.get("base_lang"))
                        .and_then(|b| b.as_str())
                        .map(|s| s.to_string());
                    let has_strings = value
                        .get("strings")
                        .and_then(|s| s.as_object())
                        .map(|o| !o.is_empty())
                        .unwrap_or(false);

                    if !has_strings {
                        if let Some(ref base) = base_lang {
                            let translations_guard = state.language_translations.read().await;
                            if let Some(base_value) = translations_guard.get(base) {
                                if let Some(base_strings) = base_value.get("strings").cloned() {
                                    if let Some(obj) = value.as_object_mut() {
                                        obj.insert("strings".to_string(), base_strings);
                                    }
                                }
                            }
                        }
                        actual_content = serde_json::to_string(&value)
                            .unwrap_or_else(|_| actual_content.clone());
                    }

                    state
                        .language_translations
                        .write()
                        .await
                        .insert(lang_code.clone(), value);
                } else {
                    tracing::warn!("{prefix} language create invalid json for '{name}'");
                }
            }

            tracing::info!("created {type_str} #{entry_id} '{name}'");

            if type_str == "Language" {
                let eng_name = utils::extract_json_str(&actual_content, &["info", "full_name"])
                    .unwrap_or_else(|| name.to_string());
                let nat_name = utils::extract_json_str(&actual_content, &["info", "loc_name"])
                    .unwrap_or_else(|| eng_name.clone());
                match response::build_language_create_response(
                    entry_id as u32,
                    now_ts as u32,
                    name,
                    &eng_name,
                    &nat_name,
                    &actual_content,
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} language create build error: {e}");
                        None
                    }
                }
            } else {
                match response::build_create_response(
                    entry_id as u32,
                    now_ts as u32,
                    entry_type_id_from_name(type_str),
                    name,
                    username,
                    Some(&actual_content),
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} create build error: {e}");
                        None
                    }
                }
            }
        }

        ClientMsg::UpdateEntry {
            entry_id,
            entry_type,
            content,
            name,
            timestamp,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!("update {type_str} #{entry_id}");

            if let Some(ts) = timestamp {
                if let Err(e) = state
                    .storage
                    .update_log_entry_timestamp(*entry_id as i32, *ts as i32)
                    .await
                {
                    tracing::error!("{prefix} update timestamp error: {e}");
                }
            }

            if let Some(new_name) = name {
                let _ = state
                    .storage
                    .update_log_entry_name(*entry_id as i32, new_name)
                    .await;
            }

            if let Some(new_content) = content {
                if let Err(e) = state
                    .storage
                    .write_entry_content(*entry_id as i32, new_content)
                    .await
                {
                    tracing::error!("write {type_str} error: {e}");
                } else if type_str == "Language" {
                    let log = state.storage.log_entries().await;
                    if let Some(entry) = log.iter().find(|e| e.entry_id == *entry_id as i32) {
                        let code = &entry.name;
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(new_content) {
                            state.language_translations.write().await.insert(code.clone(), value);
                        }
                    }
                }
            }

            None
        }

        ClientMsg::DuplicateEntry {
            entry_id,
            entry_type,
            name,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!("dupe {type_str} #{entry_id}");

            let new_entry_id = match state.storage.next_entry_id().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} dupe next entry_id error: {e}");
                    return None;
                }
            };

            let now_ts = utils::unix_timestamp();

            let (source_author, source_name) = match state.storage.get_log_entry(*entry_id as i32).await {
                Some(entry) => (entry.author, entry.name),
                None => {
                    tracing::warn!("{prefix} dupe source entry_id={entry_id} not found");
                    (username.to_string(), type_str.to_string())
                }
            };

            let source_content = match state
                .storage
                .read_entry_content(*entry_id as i32)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source {type_str} entry_id={entry_id} has no content"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} dupe load source error: {e}");
                    return None;
                }
            };

            let duplicate_name = name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or(source_name);

            let log_entry = LogEntryData {
                entry_id: new_entry_id,
                timestamp: now_ts,
                entry_type: type_str.to_string(),
                author: source_author.clone(),
                name: duplicate_name.clone(),
                created_at: utils::now_iso(),
                deleted_at: None,
            };

            if let Err(e) = state.storage.add_log_entry(log_entry).await {
                tracing::error!("{prefix} dupe add log entry error: {e}");
                return None;
            }

            if let Err(e) = state
                .storage
                .write_entry_content(new_entry_id, &source_content)
                .await
            {
                tracing::error!("{prefix} dupe write content error: {e}");
                return None;
            }

            if type_str == "Language" {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&source_content) {
                    state.language_translations.write().await.insert(duplicate_name.clone(), value);
                }
            }

            if type_str == "Language" {
                let eng_name = utils::extract_json_str(&source_content, &["info", "full_name"])
                    .unwrap_or_else(|| duplicate_name.clone());
                let nat_name = utils::extract_json_str(&source_content, &["info", "loc_name"])
                    .unwrap_or_else(|| eng_name.clone());
                match response::build_language_create_response(
                    new_entry_id as u32,
                    now_ts as u32,
                    &duplicate_name,
                    &eng_name,
                    &nat_name,
                    &source_content,
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} dupe build error: {e}");
                        None
                    }
                }
            } else {
                match response::build_create_response(
                    new_entry_id as u32,
                    now_ts as u32,
                    entry_type_id_from_name(type_str),
                    &duplicate_name,
                    &source_author,
                    Some(&source_content),
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} dupe build error: {e}");
                        None
                    }
                }
            }
        }

        ClientMsg::DeleteEntry {
            entry_id,
            entry_type,
            action,
            _raw_payload: _,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!("delete {type_str} #{entry_id}");

            match action {
                crate::client_msg::DeleteAction::Delete => {
                    let _ = state.storage.move_to_trash(*entry_id as i32).await;
                }
                crate::client_msg::DeleteAction::DeletePermanently => {
                    let _ = state.storage.delete_from_trash(*entry_id as i32).await;
                }
                crate::client_msg::DeleteAction::Restore => {
                    let _ = state.storage.restore_from_trash(*entry_id as i32).await;
                }
            }

            None
        }

        ClientMsg::SharedSkins => None,
        ClientMsg::SharedFeatures { .. } => None,
        ClientMsg::Unknown { msg_type, .. } => {
            if *msg_type != 7 {
                tracing::warn!("unknown msg {msg_type}");
            }
            None
        }
    }
}

async fn save_type7_blob(
    state: &AppState,
    payload: &[u8],
    _prefix: &str,
) -> anyhow::Result<()> {
    let blob = extract_type7_blob_text(payload)?;

    if let Some(selection) = decode_style_selection(&blob) {
        match selection {
            StyleSelection::BuiltIn { .. } => {
                let _ = state.storage.set_last_loaded_style(None).await;
            }
            StyleSelection::Other(id) => {
                if let Ok(entry_id) = i32::try_from(id) {
                    if state.storage.entry_exists(entry_id).await {
                        let _ = state.storage.set_last_loaded_style(Some(entry_id)).await;
                    }
                }
            }
        }
    }

    state.storage.update_type7_blob(Some(&blob)).await?;
    Ok(())
}

#[allow(dead_code)]
enum StyleSelection {
    BuiltIn { id: i64, name: &'static str },
    Other(i64),
}

fn decode_style_selection(blob_b64: &str) -> Option<StyleSelection> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob_b64.trim())
        .ok()?;
    let value: serde_json::Value = rmp_serde::from_slice(&raw).ok()?;
    let selected = value
        .get(crate::config::STYLE_SELECTION_KEY_1)?
        .get(crate::config::STYLE_SELECTION_KEY_2)?
        .get(crate::config::STYLE_SELECTION_KEY_3)?
        .as_i64()?;

    match selected {
        0 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Blue",
        }),
        1 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Black",
        }),
        2 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Light",
        }),
        _ => Some(StyleSelection::Other(selected)),
    }
}

fn extract_type7_blob_text(payload: &[u8]) -> anyhow::Result<String> {
    fn is_b64ish(b: u8) -> bool {
        matches!(b,
            b'A'..=b'Z' |
            b'a'..=b'z' |
            b'0'..=b'9' |
            b'+' | b'/' | b'=' |
            b'-' | b'_')
    }

    let mut best = (0usize, 0usize);
    let mut start = None;

    for (idx, &byte) in payload.iter().enumerate() {
        if is_b64ish(byte) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            let len = idx - s;
            if len > best.1 {
                best = (s, len);
            }
        }
    }

    if let Some(s) = start {
        let len = payload.len() - s;
        if len > best.1 {
            best = (s, len);
        }
    }

    anyhow::ensure!(best.1 > 32, "type7 blob text not found");
    let text = std::str::from_utf8(&payload[best.0..best.0 + best.1])
        .context("type7 blob candidate was not UTF-8")?
        .trim_matches('\0')
        .to_string();
    anyhow::ensure!(!text.is_empty(), "type7 blob text empty");
    Ok(text)
}
