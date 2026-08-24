use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateData {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type7_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type7_updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_loaded_config_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_loaded_style_id: Option<i32>,
    pub next_entry_id: i32,
    pub log: Vec<LogEntryData>,
    pub serial: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntryData {
    pub entry_id: i32,
    pub timestamp: i32,
    pub entry_type: String,
    pub author: String,
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i32>,
}

pub struct UserData {
    pub username: String,
    pub type7_blob: Option<String>,
    pub type7_updated_at: Option<String>,
    pub last_loaded_config_id: Option<i32>,
    pub last_loaded_style_id: Option<i32>,
    pub serial: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptRow {
    pub entry_id: i32,
    pub name: String,
    pub content: String,
}
