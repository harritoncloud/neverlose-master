use anyhow::Result;

use super::types::LogEntryData;
use super::util;
use super::Storage;

impl Storage {
    pub async fn entry_exists(&self, entry_id: i32) -> bool {
        let s = self.inner.read().await;
        match s.log.iter().find(|e| e.entry_id == entry_id) {
            Some(e) => {
                Self::entry_path(&self.root, entry_id, &e.entry_type, &e.name).exists()
            }
            None => false,
        }
    }

    pub async fn scan_new_content(&self) -> Result<Vec<LogEntryData>> {
        self.scan_for_new(false).await
    }

    pub async fn scan_new_trash(&self) -> Result<Vec<LogEntryData>> {
        self.scan_for_new(true).await
    }

    async fn scan_for_new(&self, trash: bool) -> Result<Vec<LogEntryData>> {
        struct Found {
            path: std::path::PathBuf,
            entry_type: String,
            id: Option<i32>,
            name: String,
        }
        let mut found = Vec::new();

        if trash {
            let trash_dir = self.root.join(".trash");
            if !trash_dir.exists() {
                return Ok(Vec::new());
            }
            let mut entries = tokio::fs::read_dir(&trash_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let entry_type = match ext {
                    "cfg" => "Config",
                    "lua" => "Script",
                    "lang" => "Language",
                    _ => continue,
                };
                let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Some((id, name)) = Self::parse_entry_filename(fname, ext) else {
                    continue;
                };
                found.push(Found {
                    path,
                    entry_type: entry_type.to_string(),
                    id: Some(id),
                    name,
                });
            }
        } else {
            for (dir, entry_type, ext) in [
                ("configs", "Config", "cfg"),
                ("scripts", "Script", "lua"),
                ("styles", "Style", "style"),
                ("languages", "Language", "lang"),
            ] {
                let dir_path = self.root.join(dir);
                if !dir_path.exists() {
                    continue;
                }
                let mut entries = tokio::fs::read_dir(&dir_path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.extension().map_or(true, |e| e != ext) {
                        continue;
                    }
                    let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    let (id, name) = Self::parse_entry_filename_loose(fname, ext, -1);
                    found.push(Found {
                        path,
                        entry_type: entry_type.to_string(),
                        id: if id < 0 { None } else { Some(id) },
                        name,
                    });
                }
            }
        }

        if found.is_empty() {
            return Ok(Vec::new());
        }
        let mut s = self.inner.write().await;
        let author = s.username.clone();
        let mut new_entries: Vec<LogEntryData> = Vec::new();
        let mut moves: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
        for mut item in found {
            if trash {
                if s.log.iter().any(|e| e.entry_id == item.id.unwrap_or(-1)) {
                    continue;
                }
            } else {
                // Skip if an entry with this file's id+type already exists in the log.
                // The first check catches exact match (id+type+name).
                // The second check catches stale files whose id already maps to a
                // different name (e.g. race between create and scan).
                let id_already_exists = match item.id {
                    Some(file_id) => s.log.iter().any(|e| {
                        e.entry_id == file_id
                            && e.entry_type == item.entry_type
                            && e.name == item.name
                    }),
                    None => false,
                };
                if id_already_exists {
                    continue;
                }

                // Also skip if the exact file path matches any known entry
                let desired = Self::entry_path(
                    &self.root,
                    item.id.unwrap_or(-1),
                    &item.entry_type,
                    &item.name,
                );
                if item.path == desired
                    && s.log.iter().any(|e| {
                        Some(e.entry_id) == item.id
                            && e.entry_type == item.entry_type
                            && e.name == item.name
                    })
                {
                    continue;
                }

                let mut check_name = item.name.clone();
                let mut counter = 2u32;
                while s
                    .log
                    .iter()
                    .any(|e| e.entry_type == item.entry_type && e.name == check_name)
                {
                    check_name = format!("{} ({})", item.name, counter);
                    counter += 1;
                }
                item.name = check_name;
            }
            let entry_id = if trash {
                item.id.unwrap()
            } else {
                match item.id {
                    Some(file_id) if !s.log.iter().any(|e| e.entry_id == file_id) => file_id,
                    _ => {
                        let new_id = s.next_entry_id;
                        s.next_entry_id += 1;
                        new_id
                    }
                }
            };
            if entry_id >= s.next_entry_id {
                s.next_entry_id = entry_id + 1;
            }
            if !trash {
                let desired =
                    Self::entry_path(&self.root, entry_id, &item.entry_type, &item.name);
                if item.path != desired {
                    moves.push((item.path.clone(), desired));
                }
            }
            let entry = LogEntryData {
                entry_id,
                timestamp: util::unix_timestamp(),
                entry_type: item.entry_type,
                author: author.clone(),
                name: item.name,
                created_at: util::now_iso(),
                deleted_at: if trash {
                    Some(util::unix_timestamp())
                } else {
                    None
                },
            };
            s.log.push(entry.clone());
            new_entries.push(entry);
        }
        if !new_entries.is_empty() {
            self.persist(&s).await?;
        }
        drop(s);
        for (old, new) in moves {
            if old == new || !old.exists() {
                continue;
            }
            if new.exists() {
                continue;
            }
            if let Some(parent) = new.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    tracing::error!("Failed to create dir {}: {e}", parent.display());
                    continue;
                }
            }
            if let Err(e) = tokio::fs::rename(&old, &new).await {
                tracing::error!(
                    "Failed to rename {} -> {}: {e}",
                    old.display(),
                    new.display()
                );
                continue;
            }
            tracing::info!("renamed {} -> {}", old.display(), new.display());
        }
        Ok(new_entries)
    }
}
