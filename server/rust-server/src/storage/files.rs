use std::path::{Path, PathBuf};

use super::Storage;

impl Storage {
    pub(crate) fn entry_path(root: &Path, entry_id: i32, entry_type: &str, name: &str) -> PathBuf {
        let dir = match entry_type {
            "Script" => "scripts",
            "Style" => "styles",
            "Language" => "languages",
            _ => "configs",
        };
        let ext = match entry_type {
            "Script" => ".lua",
            "Style" => ".style",
            "Language" => ".lang",
            _ => ".cfg",
        };
        root.join(dir)
            .join(format!("{}_{}{}", entry_id, sanitize_filename(name), ext))
    }

    pub(crate) fn trash_path(root: &Path, entry_id: i32, entry_type: &str, name: &str) -> PathBuf {
        let ext = match entry_type {
            "Script" => ".lua",
            "Style" => ".style",
            "Language" => ".lang",
            _ => ".cfg",
        };
        root.join(".trash")
            .join(format!("{}_{}{}", entry_id, sanitize_filename(name), ext))
    }

    pub fn parse_entry_filename(fname: &str, ext: &str) -> Option<(i32, String)> {
        let stem = fname.strip_suffix(&format!(".{}", ext))?;
        let pos = stem.find('_')?;
        let id: i32 = stem[..pos].parse().ok()?;
        let name = stem[pos + 1..].to_string();
        Some((id, name))
    }

    pub(crate) fn parse_entry_filename_loose(fname: &str, ext: &str, fallback_id: i32) -> (i32, String) {
        let stem = fname.strip_suffix(&format!(".{}", ext)).unwrap_or(fname);
        match stem.find('_') {
            Some(pos) => match stem[..pos].parse::<i32>() {
                Ok(id) => (id, stem[pos + 1..].to_string()),
                Err(_) => (fallback_id, stem.to_string()),
            },
            None => (fallback_id, stem.to_string()),
        }
    }
}

pub(crate) fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let s = s.trim_end_matches(|c: char| c == '.' || c == ' ' || c.is_control());
    if s.is_empty() {
        "unnamed".to_string()
    } else {
        s.to_string()
    }
}
