#[derive(Debug, Clone)]
pub struct BaseModuleData {
    pub name: String,
    pub version: i32,
    pub author: String,
    pub checksum: i32,
    pub buffer_capacity: i32,
    pub enabled: i32,
    pub skin_data_msgpack: Vec<u8>,
    pub languages_json: serde_json::Value,
}
