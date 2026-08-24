pub fn preview_text(s: &str, max: usize) -> String {
    let mut p: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        p.push_str("...");
    }
    p
}

pub fn unix_timestamp() -> i32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i32
}

pub fn now_iso() -> String {
    crate::storage::now_iso()
}

pub fn extract_json_str(json: &str, path: &[&str]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut current: &serde_json::Value = &value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(|s| s.to_string())
}
