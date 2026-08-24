mod client_msg;
mod config;
mod data;
mod http;
mod models;
mod module_builder;
mod response;
mod storage;
mod tls;
mod utils;
mod ws;

use anyhow::Context;
use std::collections::HashMap;
use indexmap::IndexMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc, watch};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc as async_mpsc;

use crate::models::BaseModuleData;
use crate::storage::Storage;

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub base_module: BaseModuleData,
    pub raw_module: Option<Vec<u8>>,
    pub ip_tokens: Arc<RwLock<HashMap<IpAddr, String>>>,
    pub live_replies: Arc<RwLock<HashMap<String, HashMap<Uuid, mpsc::UnboundedSender<Vec<u8>>>>>>,
    pub shutdown_tx: watch::Sender<bool>,
    pub language_translations: Arc<RwLock<IndexMap<String, serde_json::Value>>>,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let base_module = parse_embedded_base_module().expect("failed to parse embedded base module");
    let cloud_path =
        nl_cloud_path().expect("failed to resolve nl_cloud directory path");
    let storage = Storage::load_or_init(cloud_path, data::DEFAULT_AVATAR_PNG)
        .await
        .expect("failed to initialize storage");

    let added = storage
        .scan_new_content()
        .await
        .expect("failed to scan for new content");
    if !added.is_empty() {
        tracing::info!("found {} new file(s)", added.len());
    }

    handle_boot_config_arg(&storage).await;

    let raw_module = load_raw_module_arg().expect("failed to load raw module override");
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    // Populate translations: English from seed module, plus user languages from disk.
    let mut language_translations: IndexMap<String, serde_json::Value> = IndexMap::new();
    let seed_languages: Vec<nl_parser::module::Language> =
        serde_json::from_value(base_module.languages_json.clone()).unwrap_or_default();

    // Load English translations only (only language in the module blob)
    if let Some(en) = seed_languages.iter().find(|l| l.code == "en") {
        if let Some(ref translations) = en.translations {
            language_translations.insert("en".to_string(), translations.clone());
        }
    }

    // Load user-created language translations from storage
    for entry in storage.log_entries().await {
        if entry.entry_type == "Language" && entry.deleted_at.is_none() {
            if let Ok(Some(content)) = storage.read_entry_content(entry.entry_id).await {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                    if !language_translations.contains_key(&entry.name) {
                        language_translations.insert(entry.name, value);
                    }
                }
            }
        }
    }

    let state = AppState {
        storage,
        base_module,
        raw_module,
        ip_tokens: Arc::new(RwLock::new(HashMap::new())),
        live_replies: Arc::new(RwLock::new(HashMap::new())),
        shutdown_tx,
        language_translations: Arc::new(RwLock::new(language_translations)),
    };

    let shutdown_watch = state.shutdown_tx.subscribe();
    tokio::spawn(watch_content_dirs(state.clone(), shutdown_watch));

    boot_servers(state).await;
}

async fn boot_servers(state: AppState) {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], config::HTTP_PORT));
    let ws_addr = SocketAddr::from(([127, 0, 0, 1], config::WS_PORT));

    let ws_tls = std::env::var("WS_TLS").unwrap_or_else(|_| "true".to_string());
    let ws_tls_enabled = ws_tls != "false";

    let cert_path =
        std::env::var("TLS_CERT").unwrap_or_else(|_| config::TLS_CERT_PATH.to_string());
    let key_path = std::env::var("TLS_KEY").unwrap_or_else(|_| config::TLS_KEY_PATH.to_string());

    let http_listener = TcpListener::bind(http_addr)
        .await
        .expect("failed to bind HTTP port");

    tracing::info!("http on {http_addr}");

    let http_server = axum::serve(
        http_listener,
        http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    );

    if ws_tls_enabled {
        tls::ensure_self_signed_certs(&cert_path, &key_path)
            .expect("failed to ensure TLS certificates");

        let rustls_config = tls::load_rustls_config(&cert_path, &key_path)
            .await
            .expect("failed to load TLS config");

        tracing::info!("ws on {ws_addr}");

        let ws_server = axum_server::bind_rustls(ws_addr, rustls_config)
            .serve(ws::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>());

        let mut shutdown_rx = state.shutdown_tx.subscribe();

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WSS server error: {e}"); }
            }
            _ = wait_for_embedded_shutdown(&mut shutdown_rx) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
            }
        }
    } else {
        let ws_listener = TcpListener::bind(ws_addr)
            .await
            .expect("failed to bind WS port");

        tracing::info!("ws on {ws_addr}");

        let ws_server = axum::serve(
            ws_listener,
            ws::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
        );

        let mut shutdown_rx = state.shutdown_tx.subscribe();

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WS server error: {e}"); }
            }
            _ = wait_for_embedded_shutdown(&mut shutdown_rx) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
            }
        }
    }
}

fn nl_cloud_path() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("NL_CLOUD_PATH") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        return Ok(path);
    }

    let exe = std::env::current_exe().context("failed to get current exe path")?;
    let dir = exe.parent().unwrap_or_else(|| Path::new("."));
    Ok(dir.join("nl_cloud"))
}

async fn wait_for_embedded_shutdown(rx: &mut watch::Receiver<bool>) {
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            break;
        }
    }
}

fn arg_value(args: &[String], flag: &str) -> anyhow::Result<Option<String>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };

    args.get(index + 1)
        .cloned()
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))
}

fn read_file(path: impl AsRef<Path>, label: &str) -> anyhow::Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn load_raw_module_arg() -> anyhow::Result<Option<Vec<u8>>> {
    let args: Vec<String> = std::env::args().collect();

    if let Some(path) = arg_value(&args, "--raw-module")? {
        let data = read_file(&path, "raw module")?;
        return Ok(Some(data));
    }

    if let Some(path) = arg_value(&args, "--raw-decrypted-module")? {
        let data = read_file(&path, "decrypted module")?;
        let encrypted =
            nl_parser::pipeline::save_module(&data).context("failed to compress+encrypt module")?;
        tracing::info!("encrypted module: {} bytes", encrypted.len());
        return Ok(Some(encrypted));
    }

    if let Some(path) = arg_value(&args, "--reencrypt-module")? {
        let data = read_file(&path, "module")?;
        let decompressed = nl_parser::pipeline::load_module(&data)
            .context("failed to decrypt+decompress module")?;
        let encrypted = nl_parser::pipeline::save_module(&decompressed)
            .context("failed to compress+encrypt module")?;
        tracing::info!("reencrypted module: {} bytes", encrypted.len());
        return Ok(Some(encrypted));
    }

    Ok(None)
}

async fn handle_boot_config_arg(storage: &Storage) {
    let args: Vec<String> = std::env::args().collect();
    let Ok(Some(entry_id_str)) = arg_value(&args, "--boot-config") else {
        return;
    };
    match entry_id_str.parse::<i32>() {
        Ok(entry_id) => {
            let log = storage.log_entries().await;
            if log
                .iter()
                .any(|e| e.entry_id == entry_id && e.entry_type == "Config")
            {
                storage
                    .set_last_loaded_config(Some(entry_id))
                    .await
                    .expect("failed to set boot config");
                tracing::info!("boot config: #{entry_id}");
            } else {
                tracing::warn!(
                    "--boot-config {} specified but no matching config entry found",
                    entry_id
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                "--boot-config requires a numeric entry_id, got '{}'",
                entry_id_str
            );
        }
    }
}

async fn watch_content_dirs(state: AppState, mut shutdown_rx: watch::Receiver<bool>) {
    let (tx, mut rx) = async_mpsc::channel::<PathBuf>(32);
    let mut watcher = match notify::recommended_watcher(move |e: Result<Event, notify::Error>| {
        if let Ok(e) = e {
            if !matches!(e.kind, EventKind::Access(_)) {
                for path in e.paths {
                    let _ = tx.try_send(path);
                }
            }
        }
    }) {
        Ok(w) => w,
        Err(e) => { tracing::error!("watch: failed to create watcher: {e}"); return; }
    };

    let root = state.storage.root_dir().to_path_buf();
    for sub in ["configs", "scripts", "styles", "languages", ".trash"] {
        let dir = root.join(sub);
        if dir.exists() {
            let _ = watcher.watch(&dir, RecursiveMode::NonRecursive);
        }
    }

    tracing::info!("watching {}", root.display());

    let mut debounce = tokio::time::interval(std::time::Duration::from_millis(500));
    let mut pending = false;
    let mut changed_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    loop {
        tokio::select! {
            path = rx.recv() => {
                if let Some(p) = path {
                    changed_paths.insert(p);
                }
                pending = true;
                debounce.reset();
            }
            _ = debounce.tick(), if pending => {
                pending = false;
                let paths = std::mem::take(&mut changed_paths);
                let username = state.storage.username().await;

                // Full scan for new files (creates + rename)
                let new_entries = match state.storage.scan_new_content().await {
                    Ok(e) => e,
                    Err(e) => { tracing::error!("watch: scan: {e}"); Vec::new() }
                };
                for entry in &new_entries {
                    let content = state.storage.read_entry_content(entry.entry_id).await.ok().flatten();
                    send_live_insert(&state, entry, &username, content.as_deref()).await;
                }

                let new_trash = match state.storage.scan_new_trash().await {
                    Ok(e) => e,
                    Err(e) => { tracing::error!("watch: trash scan: {e}"); Vec::new() }
                };
                for entry in &new_trash {
                    send_live_insert(&state, entry, &username, None).await;
                }

                // Send UpdateEntry for modified existing files (skip Language)
                for path in &paths {
                    if let Some((entry_id, entry_type, name, _ext)) = parse_watched_file(path) {
                        let log = state.storage.log_entries().await;
                        if let Some(entry) = log.iter().find(|e| e.entry_id == entry_id && e.name == name) {
                            if entry.deleted_at.is_none() {
                                if let Ok(Some(content)) = state.storage.read_entry_content(entry_id).await {
                    if let Ok(reply) = crate::response::build_live_update_reply(
                        entry_id as u32, entry_type, &content,
                    ) {
                                        let live = state.live_replies.read().await;
                                        for conns in live.values() {
                                            for sender in conns.values() {
                                                let _ = sender.send(reply.clone());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Clean up orphaned entries
                match state.storage.sync_removed().await {
                    Ok(removed) => {
                        for entry in &removed {
                            let entry_type_id = match entry.entry_type.as_str() {
                                "Script" => 1u32, "Style" => 2, "Language" => 3, _ => 0,
                            };
                            if let Ok(reply) = crate::response::build_live_delete_reply(
                                entry.entry_id as u32, entry_type_id,
                            ) {
                                let live = state.live_replies.read().await;
                                for conns in live.values() {
                                    for sender in conns.values() {
                                        let _ = sender.send(reply.clone());
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => tracing::error!("watch: sync_removed: {e}"),
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

async fn send_live_insert(state: &AppState, entry: &storage::LogEntryData, author: &str, content: Option<&str>) {
    let reply = match crate::response::build_live_insert_reply(
        entry.entry_id as u32,
        entry.timestamp as u32,
        &entry.entry_type,
        &entry.name,
        author,
        content,
    ) {
        Ok(r) => r,
        Err(e) => { tracing::error!("watch: build reply: {e}"); return; }
    };
    let live = state.live_replies.read().await;
    for conns in live.values() {
        for sender in conns.values() {
            let _ = sender.send(reply.clone());
        }
    }
}

/// Parse a watched file path into (entry_id, entry_type_id, name, extension).
fn parse_watched_file(path: &Path) -> Option<(i32, u32, String, String)> {
    let ext = path.extension()?.to_str()?;
    let fname = path.file_name()?.to_str()?;
    let stem = fname.strip_suffix(&format!(".{}", ext))?;
    let pos = stem.find('_')?;
    let id: i32 = stem[..pos].parse().ok()?;
    let name = stem[pos + 1..].to_string();
    let entry_type = match ext {
        "cfg" => 0u32,
        "lua" => 1,
        "style" => 2,
        "lang" => 3,
        _ => return None,
    };
    Some((id, entry_type, name, ext.to_string()))
}

fn parse_embedded_base_module() -> anyhow::Result<BaseModuleData> {
    use nl_parser::{module::Module, pipeline};

    let flat = pipeline::load_module(data::SEED_MODULE_BIN)
        .context("failed to decrypt+decompress seed module")?;
    let base = Module::base_from_flatbuffer(&flat)
        .context("failed to parse base module from flatbuffer")?;
    let skin_data_msgpack = Module::extract_raw_skin_data(&flat)
        .context("failed to extract skin data")?;
    let languages_json = serde_json::to_value(&base.languages)
        .context("failed to serialize languages")?;

    Ok(BaseModuleData {
        name: "default".to_string(),
        version: base.version as i32,
        author: base.author,
        checksum: base.checksum as i32,
        buffer_capacity: base.buffer_capacity as i32,
        enabled: base.enabled as i32,
        skin_data_msgpack,
        languages_json,
    })
}
