mod files;
mod scan;
mod trash;
pub mod types;
pub mod util;

pub use self::types::{LogEntryData, ScriptRow, UserData};
pub use self::util::now_iso;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use self::types::StateData;

pub struct Storage {
    root: PathBuf,
    inner: Arc<RwLock<StateData>>,
}

impl Storage {
    pub async fn load_or_init(root: PathBuf, default_avatar: &[u8]) -> Result<Self> {
        let dirs = [
            root.join("configs"),
            root.join("scripts"),
            root.join("styles"),
            root.join("languages"),
            root.join(".trash"),
        ];
        for dir in &dirs {
            tokio::fs::create_dir_all(dir)
                .await
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }

        let state_path = root.join("state.json");
        let state = if state_path.exists() {
            let json = tokio::fs::read_to_string(&state_path)
                .await
                .with_context(|| format!("failed to read {}", state_path.display()))?;
            serde_json::from_str(&json).with_context(|| "failed to parse state.json")?
        } else {
            let state = StateData {
                username: "astolfo".to_string(),
                type7_blob: None,
                type7_updated_at: None,
                last_loaded_config_id: None,
                last_loaded_style_id: None,
                next_entry_id: 3,
                log: Vec::new(),
                serial: String::new(),
                created_at: util::now_iso(),
            };
            util::persist_state(&state_path, &state).await?;
            state
        };

        let avatar_path = root.join("avatar.png");
        if !avatar_path.exists() {
            tokio::fs::write(&avatar_path, default_avatar)
                .await
                .with_context(|| "failed to write default avatar")?;
        }

        let storage = Storage {
            root,
            inner: Arc::new(RwLock::new(state)),
        };

        storage.cleanup_trash().await?;

        Ok(storage)
    }

    pub fn root_dir(&self) -> &Path {
        &self.root
    }

    pub fn avatar_path(&self) -> PathBuf {
        self.root.join("avatar.png")
    }

    pub async fn read_avatar(&self) -> Result<Vec<u8>> {
        tokio::fs::read(self.avatar_path())
            .await
            .with_context(|| "failed to read avatar")
    }

    pub async fn user_data(&self) -> UserData {
        let s = self.inner.read().await;
        UserData {
            username: s.username.clone(),
            type7_blob: s.type7_blob.clone(),
            type7_updated_at: s.type7_updated_at.clone(),
            last_loaded_config_id: s.last_loaded_config_id,
            last_loaded_style_id: s.last_loaded_style_id,
            serial: s.serial.clone(),
            created_at: s.created_at.clone(),
        }
    }

    pub async fn username(&self) -> String {
        self.inner.read().await.username.clone()
    }

    // ── User state ──

    pub async fn update_type7_blob(&self, blob: Option<&str>) -> Result<()> {
        let mut s = self.inner.write().await;
        s.type7_blob = blob.map(String::from);
        s.type7_updated_at = Some(util::now_iso());
        self.persist(&s).await
    }

    pub async fn set_last_loaded_config(&self, entry_id: Option<i32>) -> Result<()> {
        let mut s = self.inner.write().await;
        s.last_loaded_config_id = entry_id;
        self.persist(&s).await
    }

    pub async fn set_last_loaded_style(&self, entry_id: Option<i32>) -> Result<()> {
        let mut s = self.inner.write().await;
        s.last_loaded_style_id = entry_id;
        self.persist(&s).await
    }

    pub async fn update_last_loaded_entry(&self, entry_type: &str, entry_id: i32) -> Result<bool> {
        match entry_type {
            "Config" => {
                self.set_last_loaded_config(Some(entry_id)).await?;
                Ok(true)
            }
            "Style" => {
                self.set_last_loaded_style(Some(entry_id)).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    // ── Log entries ──

    pub async fn log_entries(&self) -> Vec<LogEntryData> {
        self.inner.read().await.log.clone()
    }

    pub async fn get_log_entry(&self, entry_id: i32) -> Option<LogEntryData> {
        self.inner
            .read()
            .await
            .log
            .iter()
            .find(|e| e.entry_id == entry_id)
            .cloned()
    }

    pub async fn add_log_entry(&self, entry: LogEntryData) -> Result<()> {
        let mut s = self.inner.write().await;
        s.log.push(entry);
        self.persist(&s).await
    }

    pub async fn update_log_entry_name(&self, entry_id: i32, new_name: &str) -> Result<bool> {
        let mut s = self.inner.write().await;
        let Some(entry) = s.log.iter_mut().find(|e| e.entry_id == entry_id) else {
            return Ok(false);
        };
        let old_path = Self::entry_path(&self.root, entry_id, &entry.entry_type, &entry.name);
        entry.name = new_name.to_string();
        let new_path = Self::entry_path(&self.root, entry_id, &entry.entry_type, &entry.name);
        self.persist(&s).await?;
        drop(s);
        if old_path.exists() && old_path != new_path {
            if let Some(parent) = new_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&old_path, &new_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to rename {} -> {}",
                        old_path.display(),
                        new_path.display()
                    )
                })?;
        }
        Ok(true)
    }

    pub async fn update_log_entry_timestamp(&self, entry_id: i32, timestamp: i32) -> Result<bool> {
        let mut s = self.inner.write().await;
        let Some(entry) = s.log.iter_mut().find(|e| e.entry_id == entry_id) else {
            return Ok(false);
        };
        entry.timestamp = timestamp;
        self.persist(&s).await?;
        Ok(true)
    }

    pub async fn next_entry_id(&self) -> Result<i32> {
        let mut s = self.inner.write().await;
        let next = s.next_entry_id;
        s.next_entry_id += 1;
        self.persist(&s).await?;
        Ok(next)
    }

    // ── Entry content (files) ──

    pub async fn read_entry_content(&self, entry_id: i32) -> Result<Option<String>> {
        let path = {
            let s = self.inner.read().await;
            s.log
                .iter()
                .find(|e| e.entry_id == entry_id)
                .map(|e| Self::entry_path(&self.root, entry_id, &e.entry_type, &e.name))
        };
        let Some(path) = path else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))
            .map(Some)
    }

    pub async fn write_entry_content(&self, entry_id: i32, content: &str) -> Result<()> {
        let path = {
            let s = self.inner.read().await;
            s.log
                .iter()
                .find(|e| e.entry_id == entry_id)
                .map(|e| Self::entry_path(&self.root, entry_id, &e.entry_type, &e.name))
        };
        let Some(path) = path else {
            anyhow::bail!("no log entry for entry_id {entry_id}")
        };
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, content)
            .await
            .with_context(|| format!("failed to write {}", path.display()))
    }

    pub async fn get_script_by_name(&self, name: &str) -> Result<Option<ScriptRow>> {
        let s = self.inner.read().await;
        let Some(entry) = s
            .log
            .iter()
            .find(|e| e.entry_type == "Script" && e.name == name)
        else {
            return Ok(None);
        };
        let path = Self::entry_path(&self.root, entry.entry_id, "Script", &entry.name);
        let entry_id = entry.entry_id;
        let entry_name = entry.name.clone();
        drop(s);
        let content = if path.exists() {
            tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("failed to read {}", path.display()))?
        } else {
            String::new()
        };
        Ok(Some(ScriptRow {
            entry_id,
            name: entry_name,
            content,
        }))
    }

    pub(crate) async fn persist(&self, state: &StateData) -> Result<()> {
        let state_path = self.root.join("state.json");
        util::persist_state(&state_path, state).await
    }
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Storage {
            root: self.root.clone(),
            inner: Arc::clone(&self.inner),
        }
    }
}
