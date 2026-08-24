use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nl_parser::flatcc_builder::{FlatccBuilder, Ref};
use nl_parser::module::{Language, LogEntry, Module, serialize_translations_json};
use nl_parser::pipeline;
use indexmap::IndexMap;

use crate::config;
use crate::models::BaseModuleData;

pub struct LogEntryWithContent {
    pub entry_id: i32,
    pub timestamp: i32,
    pub entry_type: String,
    pub author: String,
    pub name: String,
    pub content: Option<String>,
    pub deleted: bool,
}

pub fn build_module_bin(
    base: &BaseModuleData,
    username: &str,
    type7_blob: Option<&str>,
    last_loaded_config_id: Option<i32>,
    last_loaded_style_id: Option<i32>,
    log_entries: &[LogEntryWithContent],
    user_languages: &IndexMap<String, serde_json::Value>,
) -> Result<Vec<u8>> {
    let mut languages: Vec<Language> = serde_json::from_value(base.languages_json.clone())
        .context("deserialize languages from JSON")?;

    // Only include English from seed. Other seed languages (ru,li,cn,ro) stripped.
    languages.retain(|l| l.code == "en");

    // Update English translations. Add user-created languages for reboot persistence.
    for (code, translations) in user_languages {
        if let Some(lang) = languages.iter_mut().find(|l| l.code == *code) {
            lang.translations = Some(translations.clone());
        } else {
            let (english_name, native_name) = translations
                .get("info")
                .and_then(|info| {
                    let full = info.get("full_name")?.as_str().unwrap_or(code);
                    let loc = info.get("loc_name")?.as_str().unwrap_or(full);
                    Some((full.to_string(), loc.to_string()))
                })
                .unwrap_or_else(|| (code.clone(), code.clone()));
            // Look up entry_id from log for module persistence (field_0/field_1)
            let log = log_entries.iter().find(|e| e.entry_type == "Language" && e.name == *code);
            languages.push(Language {
                code: code.clone(),
                english_name,
                native_name,
                translations: Some(translations.clone()),
                entry_id: log.map(|e| e.entry_id as u32).unwrap_or(0),
                timestamp: log.map(|e| e.timestamp as u32).unwrap_or(0),
            });
            tracing::debug!("module_build: added custom language code={code}");
        }
    }

    let lang_count = languages.len();
    let filled_count = languages.iter().filter(|l| l.translations.is_some()).count();
    tracing::debug!("module_build: {filled_count}/{lang_count} languages have translations");

    let mut config_log = Vec::new();
    let mut script_log = Vec::new();
    let mut style_log = Vec::new();
    let mut ordered_entries: Vec<&LogEntryWithContent> = log_entries.iter().collect();
    ordered_entries.sort_by_key(|entry| {
        let load_bias = match entry.entry_type.as_str() {
            "Style" if Some(entry.entry_id) == last_loaded_style_id => 2,
            "Config" if Some(entry.entry_id) == last_loaded_config_id => 1,
            _ => 0,
        };
        (entry_type_replay_rank(&entry.entry_type), load_bias, entry.entry_id)
    });

    for entry in ordered_entries {
        let log_entry = LogEntry {
            entry_id: entry.entry_id as u32,
            timestamp: entry.timestamp as u32,
            name: entry.name.clone(),
            author: entry.author.clone(),
            lua_code: entry.content.clone(),
        };
        match entry.entry_type.as_str() {
            "Config" => config_log.push(log_entry),
            "Script" => script_log.push(log_entry),
            "Style" => style_log.push(LogEntry {
                entry_id: entry.entry_id as u32,
                timestamp: entry.timestamp as u32,
                name: entry.name.clone(),
                author: entry.author.clone(),
                lua_code: entry.content.clone(),
            }),
            _ => {}
        }
    }

    let deleted_ids: std::collections::HashSet<i32> = log_entries
        .iter()
        .filter(|e| e.deleted)
        .map(|e| e.entry_id)
        .collect();

    let style_activation = type7_blob
        .and_then(extract_style_id_from_type7)
        .filter(|id| *id >= 0)
        .map(|id| id as u32)
        .unwrap_or(base.enabled as u32);

    let inner_bytes = build_inner_flatbuffer(
        base, username, type7_blob, style_activation,
        &config_log, &script_log, &style_log, &languages, &deleted_ids,
    )?;

    let flatbuffer_bytes = build_outer_wrapper(base.version as u32, &inner_bytes);
    Module::from_flatbuffer(&flatbuffer_bytes).with_context(|| {
        format!("built invalid module flatbuffer")
    })?;
    let encrypted = pipeline::save_module(&flatbuffer_bytes).context("encrypt module")?;
    Ok(encrypted)
}

fn entry_type_replay_rank(entry_type: &str) -> i32 {
    match entry_type { "Style" => 0, "Config" => 1, "Script" => 2, _ => 3 }
}

fn build_outer_wrapper(version: u32, inner_bytes: &[u8]) -> Vec<u8> {
    let mut ob = FlatccBuilder::new();
    ob.force_defaults(true);
    let payload = ob.create_vector_u8(inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, version, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    ob.finish(wrapper)
}

struct LangStrings { entry_id: u32, timestamp: u32, code: Ref, english_name: Ref, native_name: Ref, translations: Option<Ref> }

fn build_inner_flatbuffer(
    base: &BaseModuleData, username: &str, type7_blob: Option<&str>,
    style_activation: u32, config_log: &[LogEntry], script_log: &[LogEntry],
    styles: &[LogEntry], languages: &[Language],
    deleted_ids: &std::collections::HashSet<i32>,
) -> Result<Vec<u8>> {
    let mut b = FlatccBuilder::new();

    let config_offsets: Vec<_> = config_log.iter().map(|e| build_log_entry_with_gap(&mut b, e, 8, deleted_ids.contains(&(e.entry_id as i32)))).collect();
    let script_offsets: Vec<_> = script_log.iter().map(|e| build_log_entry(&mut b, e, deleted_ids.contains(&(e.entry_id as i32)))).collect();
    let style_offsets: Vec<_> = styles.iter().map(|e| build_log_entry(&mut b, e, deleted_ids.contains(&(e.entry_id as i32)))).collect();

    let mut lang_data: Vec<LangStrings> = Vec::new();
    for lang in languages {
        let translations = match &lang.translations {
            Some(value) => {
                let json_bytes = serialize_translations_json(value)?;
                let json_str = std::str::from_utf8(&json_bytes).map_err(|e| anyhow::anyhow!("translations JSON not UTF-8: {e}"))?;
                tracing::debug!(
                    "module_build: lang code={} trans_bytes={} starts_with={:?}",
                    lang.code,
                    json_str.len(),
                    &json_str[..json_str.len().min(40)],
                );
                Some(b.create_string(json_str))
            }
            None => None,
        };
        let code = b.create_string(&lang.code);
        let english_name = b.create_string(&lang.english_name);
        let native_name = if lang.native_name == lang.english_name { english_name } else { b.create_string(&lang.native_name) };
        lang_data.push(LangStrings { entry_id: lang.entry_id, timestamp: lang.timestamp, code, english_name, native_name, translations });
    }

    b.push_zeros(4);
    let extra_data = match type7_blob.map(decode_type7_blob).transpose()? {
        Some(json_bytes) => b.create_vector_u8(&json_bytes),
        None => b.create_vector_u8(&[]),
    };
    let skin_data = b.create_vector_u8(&base.skin_data_msgpack);
    let auth_token = b.create_string(config::MODULE_AUTH_TOKEN);

    let lang_offsets = if lang_data.len() == 5 {
        let creation_order: &[usize] = &[0, 3, 2, 1, 4];
        let mut offsets = vec![Ref::dummy(); lang_data.len()];
        for &idx in creation_order { offsets[idx] = build_lang_table(&mut b, &lang_data[idx]); }
        offsets
    } else {
        lang_data.iter().map(|ls| build_lang_table(&mut b, ls)).collect()
    };

    let lang_vec = b.create_vector_offsets(&lang_offsets);
    let script_vec = b.create_vector_offsets(&script_offsets);
    let style_vec = b.create_vector_offsets(&style_offsets);
    let config_vec = b.create_vector_offsets(&config_offsets);

    b.start_table(13);
    b.table_add_offset(4, config_vec);
    b.table_add_offset(5, script_vec);
    b.table_add_offset(6, style_vec);
    b.table_add_offset(7, lang_vec);
    b.table_add_offset(1, extra_data);
    b.push_zeros(4);
    let author = b.create_string(username);
    b.table_add_offset(2, author);
    b.table_add_offset(9, skin_data);
    b.table_add_u32(3, base.checksum as u32, 0);
    b.table_add_u32(8, style_activation, u32::MAX);
    b.table_add_u32(12, base.buffer_capacity as u32, 0);
    b.table_add_offset(11, auth_token);
    let root = b.end_table();
    Ok(b.finish_minimal(root))
}

fn decode_type7_blob(blob_b64: &str) -> Result<Vec<u8>> {
    let raw = STANDARD.decode(blob_b64.trim()).context("type7_blob base64 decode failed")?;
    let value: serde_json::Value = rmp_serde::from_slice(&raw).context("type7_blob MessagePack decode failed")?;
    serde_json::to_vec(&value).context("type7_blob JSON encode failed")
}

fn extract_style_id_from_type7(blob_b64: &str) -> Option<i64> {
    let raw = STANDARD.decode(blob_b64.trim()).ok()?;
    let value: serde_json::Value = rmp_serde::from_slice(&raw).ok()?;
    value
        .get(crate::config::STYLE_SELECTION_KEY_1)?
        .get(crate::config::STYLE_SELECTION_KEY_2)?
        .get(crate::config::STYLE_SELECTION_KEY_3)?
        .as_i64()
}

fn build_lang_table(b: &mut FlatccBuilder, ls: &LangStrings) -> Ref {
    b.start_table(7);
    if ls.entry_id != 0 { b.table_add_u32(0, ls.entry_id, 0); }
    if ls.timestamp != 0 { b.table_add_u32(1, ls.timestamp, 0); }
    b.table_add_offset(2, ls.code);
    b.table_add_offset(4, ls.english_name);
    b.table_add_offset(5, ls.native_name);
    if let Some(t) = ls.translations { b.table_add_offset(6, t); }
    b.end_table()
}

fn build_log_entry(b: &mut FlatccBuilder, entry: &LogEntry, deleted: bool) -> Ref {
    let name = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);
    let lua_code = entry.lua_code.as_ref().map(|code| b.create_string(code));
    let dm = if deleted { Some(b.create_string("deleted")) } else { None };
    let slots = if lua_code.is_some() { 6 } else { 5 };
    b.start_table(slots);
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    if let Some(dm) = dm { b.table_add_offset(2, dm); }
    b.table_add_offset(3, name);
    b.table_add_offset(4, author);
    if let Some(lua_code) = lua_code { b.table_add_offset(5, lua_code); }
    b.end_table()
}

fn build_log_entry_with_gap(b: &mut FlatccBuilder, entry: &LogEntry, gap: usize, deleted: bool) -> Ref {
    let name = b.create_string(&entry.name);
    let author = b.create_string(&entry.author);
    b.push_zeros(gap);
    let dm = if deleted { Some(b.create_string("deleted")) } else { None };
    b.start_table(5);
    b.table_add_u32(0, entry.entry_id, 0);
    b.table_add_u32(1, entry.timestamp, 0);
    if let Some(dm) = dm { b.table_add_offset(2, dm); }
    b.table_add_offset(3, name);
    b.table_add_offset(4, author);
    b.end_table()
}
