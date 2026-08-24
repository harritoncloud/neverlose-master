use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path as AxumPath, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;

use crate::{AppState, data::DEFAULT_AVATAR_PNG};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/getavatar", get(avatar_handler))
        .route("/api/getavatar", get(avatar_handler))
        .route("/getitem", get(getitem_handler))
        .route("/api/reqitem", get(reqitem_handler))
        .route("/api/items", get(items_handler))
        .route("/lua/{*name}", get(lua_handler))
        .fallback(fallback_handler)
        .with_state(state)
}

async fn avatar_handler(
    State(state): State<AppState>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Query(_params): Query<HashMap<String, String>>,
) -> Response {
    match state.storage.read_avatar().await {
        Ok(avatar) => return avatar_response(avatar),
        Err(e) => tracing::error!("[HTTP] failed to read avatar: {e}"),
    }

    avatar_response(DEFAULT_AVATAR_PNG.to_vec())
}

async fn lua_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Response {
    let body = match state.storage.get_script_by_name(&name).await {
        Ok(Some(script)) if !script.content.is_empty() => script.content.into_bytes(),
        _ => format!("-- lua library: {name}\n").into_bytes(),
    };

    bytes_response(StatusCode::OK, "text/plain; charset=utf-8", body)
}

async fn getitem_handler(Query(params): Query<HashMap<String, String>>) -> Response {
    let code = params.get("c").map(String::as_str).unwrap_or("");
    tracing::debug!("getitem c={}", crate::utils::preview_text(code, 64));

    match nl_parser::pipeline::encrypt(&[]) {
        Ok(encrypted) => bytes_response(StatusCode::OK, "application/octet-stream", encrypted),
        Err(e) => {
            tracing::error!("[HTTP] /getitem encryption failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn reqitem_handler(Query(params): Query<HashMap<String, String>>) -> Response {
    let requested = params
        .get("name")
        .and_then(|name| requested_lua_library_name(name));

    let Some(name) = requested else {
        return empty_ok();
    };

    let Some(body) = read_lua_library(&name) else {
        tracing::warn!(
            "[HTTP] /api/reqitem missing library {}, returning stub",
            name
        );
        return bytes_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            reqitem_library_json_stub(&name),
        );
    };

    bytes_response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        reqitem_library_json(&name, &body),
    )
}

async fn items_handler(
    State(state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Response {
    let log_entries = state.storage.log_entries().await;

    let mut scripts = Vec::new();
    let mut configs = Vec::new();
    let mut styles = Vec::new();

    for entry in &log_entries {
        match state.storage.read_entry_content(entry.entry_id).await {
            Ok(Some(content)) => {
                let item = json!({
                    "entry_id": entry.entry_id,
                    "name": entry.name,
                    "content": content,
                });
                match entry.entry_type.as_str() {
                    "Script" => scripts.push(item),
                    "Style" => styles.push(item),
                    _ => configs.push(item),
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(
                    "[HTTP] /api/items failed to read {} {}: {e}",
                    entry.entry_type,
                    entry.entry_id
                );
            }
        }
    }

    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "scripts": scripts,
            "configs": configs,
            "styles": styles,
        }),
    )
}

async fn fallback_handler() -> Response {
    bytes_response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        b"not found".to_vec(),
    )
}

fn avatar_response(bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header(
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header(header::PRAGMA, "no-cache")
        .header(header::EXPIRES, "0")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn empty_ok() -> Response {
    bytes_response(StatusCode::OK, "text/plain; charset=utf-8", Vec::new())
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    bytes_response(status, "application/json", value.to_string().into_bytes())
}

fn bytes_response(status: StatusCode, content_type: &'static str, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn requested_lua_library_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    let library_name = trimmed
        .strip_prefix("-- lua library:")
        .map(str::trim)
        .unwrap_or(trimmed);
    sanitize_lua_library_name(library_name)
}

fn sanitize_lua_library_name(name: &str) -> Option<String> {
    let normalized = name.trim().trim_matches('/').replace('\\', "/");
    if normalized.is_empty()
        || normalized.len() > 160
        || normalized
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || normalized.contains(':')
    {
        return None;
    }
    Some(normalized)
}

include!(concat!(env!("OUT_DIR"), "/embedded_lua.rs"));

fn read_lua_library(name: &str) -> Option<Vec<u8>> {
    if let Some(data) = get_embedded_lua(name) {
        return Some(data.to_vec());
    }

    let requested = std::path::Path::new(name);
    if let Some(stem) = requested.file_stem().and_then(|s| s.to_str()) {
        if let Some(data) = get_embedded_lua(stem) {
            return Some(data.to_vec());
        }
    }

    if let Some(data) = get_embedded_lua(&format!("{name}.lua")) {
        return Some(data.to_vec());
    }

    None
}

fn reqitem_library_json(name: &str, body: &[u8]) -> Vec<u8> {
    let body_text = String::from_utf8_lossy(body);
    let item = json!({
        "succ": true,
        "closure": 0,
        "name": name,
        "type": "library",
        "content": body_text,
        "source": body_text,
        "data": body_text,
        "body": body_text,
        "code": body_text,
    });
    let payload = json!({
        "succ": true,
        "closure": 0,
        "name": name,
        "type": "library",
        "content": body_text,
        "source": body_text,
        "data": body_text,
        "item": item,
        "library": item,
        "body": body_text,
        "script": item,
        "code": body_text,
    });
    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"succ\":false}".to_vec())
}

fn reqitem_library_json_stub(name: &str) -> Vec<u8> {
    let payload = json!({
        "succ": true,
        "closure": 0,
        "name": name,
        "type": "library",
        "content": "",
        "source": "",
        "data": "",
        "body": "",
        "code": "",
    });
    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"succ\":false}".to_vec())
}
