use anyhow::{Context, Result};

use super::types::LogEntryData;
use super::util;
use super::Storage;

impl Storage {
    pub async fn move_to_trash(&self, entry_id: i32) -> Result<bool> {
        let (src, dst, _found) = {
            let s = self.inner.read().await;
            match s.log.iter().find(|e| e.entry_id == entry_id) {
                Some(e) => (
                    Self::entry_path(&self.root, entry_id, &e.entry_type, &e.name),
                    Self::trash_path(&self.root, entry_id, &e.entry_type, &e.name),
                    true,
                ),
                None => return Ok(false),
            }
        };
        let mut s = self.inner.write().await;
        if let Some(entry) = s.log.iter_mut().find(|e| e.entry_id == entry_id) {
            entry.deleted_at = Some(util::unix_timestamp());
        }
        self.persist(&s).await?;
        drop(s);
        if src.exists() {
            if let Some(parent) = dst.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&src, &dst)
                .await
                .with_context(|| format!("failed to move {} to trash", src.display()))?;
        }
        Ok(true)
    }

    pub async fn restore_from_trash(&self, entry_id: i32) -> Result<bool> {
        {
            let mut s = self.inner.write().await;
            if let Some(entry) = s.log.iter_mut().find(|e| e.entry_id == entry_id) {
                if entry.deleted_at.is_none() {
                    return Ok(false);
                }
                entry.deleted_at = None;
                self.persist(&s).await?;
            } else {
                return Ok(false);
            }
        }
        let prefix = format!("{}_", entry_id);
        let trash_dir = self.root.join(".trash");
        if !trash_dir.exists() {
            return Ok(true);
        }
        let mut entries = tokio::fs::read_dir(&trash_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !fname.starts_with(&prefix) {
                continue;
            }
            let s = self.inner.read().await;
            let Some(log) = s.log.iter().find(|e| e.entry_id == entry_id) else {
                continue;
            };
            let dest = Self::entry_path(&self.root, entry_id, &log.entry_type, &log.name);
            drop(s);
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&path, &dest)
                .await
                .with_context(|| {
                    format!(
                        "failed to restore {} -> {}",
                        path.display(),
                        dest.display()
                    )
                })?;
            return Ok(true);
        }
        Ok(true)
    }

    pub async fn delete_from_trash(&self, entry_id: i32) -> Result<bool> {
        let prefix = format!("{}_", entry_id);
        let trash_dir = self.root.join(".trash");
        if trash_dir.exists() {
            let mut entries = tokio::fs::read_dir(&trash_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n.starts_with(&prefix))
                {
                    tokio::fs::remove_file(&path).await?;
                    break;
                }
            }
        }
        let mut s = self.inner.write().await;
        let prev = s.log.len();
        s.log.retain(|e| e.entry_id != entry_id);
        if s.log.len() == prev {
            return Ok(false);
        }
        self.persist(&s).await?;
        Ok(true)
    }

    pub async fn sync_removed(&self) -> Result<Vec<LogEntryData>> {
        let mut s = self.inner.write().await;
        let mut removed = Vec::new();
        let mut to_remove = Vec::new();
        for entry in &s.log {
            if entry.deleted_at.is_some() {
                let path = Self::trash_path(
                    &self.root,
                    entry.entry_id,
                    &entry.entry_type,
                    &entry.name,
                );
                if !path.exists() {
                    to_remove.push(entry.entry_id);
                    removed.push(entry.clone());
                }
            } else {
                let path = Self::entry_path(
                    &self.root,
                    entry.entry_id,
                    &entry.entry_type,
                    &entry.name,
                );
                if !path.exists() {
                    to_remove.push(entry.entry_id);
                    removed.push(entry.clone());
                }
            }
        }
        if !to_remove.is_empty() {
            s.log.retain(|e| !to_remove.contains(&e.entry_id));
            self.persist(&s).await?;
        }
        Ok(removed)
    }

    pub async fn cleanup_trash(&self) -> Result<usize> {
        let cutoff = util::unix_timestamp() - 7 * 86400;
        let mut removed = 0;

        let trash_dir = self.root.join(".trash");
        if trash_dir.exists() {
            let mut entries = tokio::fs::read_dir(&trash_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Ok(meta) = path.metadata() else { continue };
                let Ok(modif) = meta.modified() else { continue };
                if modif
                    < std::time::UNIX_EPOCH + std::time::Duration::from_secs(cutoff as u64)
                {
                    tokio::fs::remove_file(&path).await?;
                    removed += 1;
                }
            }
        }

        let mut s = self.inner.write().await;
        let prev = s.log.len();
        s.log.retain(|e| {
            e.deleted_at.unwrap_or(0) == 0 || e.deleted_at.unwrap_or(0) > cutoff
        });
        removed += prev - s.log.len();
        if prev != s.log.len() {
            self.persist(&s).await?;
        }
        drop(s);

        if removed > 0 {
            tracing::info!("cleaned {} trash", removed);
        }
        Ok(removed)
    }
}
