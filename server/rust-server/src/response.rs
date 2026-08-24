use anyhow::Result;
use nl_parser::flatcc_builder::FlatccBuilder;

use crate::utils::extract_json_str;

pub fn entry_type_id_from_name(entry_type: &str) -> u32 {
    match entry_type {
        "Script" => 1,
        "Style" => 2,
        "Language" => 3,
        _ => 0,
    }
}

pub fn entry_type_name(entry_type: u32) -> &'static str {
    match entry_type {
        1 => "Script",
        2 => "Style",
        3 => "Language",
        _ => "Config",
    }
}

pub fn build_create_response(
    entry_id: u32,
    timestamp: u32,
    entry_type_id: u32,
    name: &str,
    author: &str,
    content: Option<&str>,
) -> Result<Vec<u8>> {
    let mut ib = FlatccBuilder::new();

    let name_str = ib.create_string(name);
    let author_str = ib.create_string(author);
    let content_str = content.map(|value| ib.create_string(value));
    ib.start_table(if content_str.is_some() { 6 } else { 5 });
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, timestamp, 0);
    ib.table_add_offset(3, name_str);
    ib.table_add_offset(4, author_str);
    if let Some(content_str) = content_str {
        ib.table_add_offset(5, content_str);
    }
    let log_entry = ib.end_table();

    let entries = ib.create_vector_offsets(&[log_entry]);

    ib.start_table(3);
    ib.table_add_u32(0, entry_type_id, 0);
    ib.table_add_offset(1, entries);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

pub fn build_language_create_response(
    entry_id: u32,
    timestamp: u32,
    lang_code: &str,
    english_name: &str,
    native_name: &str,
    translations_json: &str,
) -> Result<Vec<u8>> {
    let mut ib = FlatccBuilder::new();
    let ts = ib.create_string(translations_json);
    let code = ib.create_string(lang_code);
    let en = ib.create_string(english_name);
    let nn = ib.create_string(native_name);
    ib.start_table(7);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, timestamp, 0);
    ib.table_add_offset(2, code);
    ib.table_add_offset(4, en);
    ib.table_add_offset(5, nn);
    ib.table_add_offset(6, ts);
    let lang_entry = ib.end_table();

    let entries = ib.create_vector_offsets(&[lang_entry]);

    ib.start_table(3);
    ib.table_add_u32(0, 3, 0);
    ib.table_add_offset(1, entries);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    let mut ob = FlatccBuilder::new();
    let payload_vec = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0);
    ob.table_add_offset(1, payload_vec);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

pub fn build_case11_response(entry_id: u32, payload: &str) -> Result<Vec<u8>> {
    let inner_bytes = build_case11_inner(entry_id, None, Some(payload));

    let mut ob = FlatccBuilder::new();
    let payload_vec = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 11, 0);
    ob.table_add_offset(1, payload_vec);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

fn build_case11_inner(entry_id: u32, apply: Option<u32>, payload: Option<&str>) -> Vec<u8> {
    let mut ib = FlatccBuilder::new();
    let p = payload.map(|s| ib.create_string(s));
    ib.start_table(3);
    ib.table_add_u32(0, entry_id, 0);
    if let Some(a) = apply {
        ib.table_add_u32(1, a, 0);
    }
    if let Some(val) = p {
        ib.table_add_offset(2, val);
    }
    let root = ib.end_table();
    ib.finish_minimal(root)
}

pub fn build_language_ack_response_type12(lang_code: &str, translations_json: &str) -> Result<Vec<u8>> {
    let mut ib = FlatccBuilder::new();
    let code = ib.create_string(lang_code);
    let payload = ib.create_string(translations_json);
    ib.start_table(3);
    ib.table_add_offset(1, code);
    ib.table_add_offset(2, payload);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    let mut ob = FlatccBuilder::new();
    let payload_vec = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 12, 0);
    ob.table_add_offset(1, payload_vec);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

pub fn build_live_insert_reply(
    entry_id: u32,
    timestamp: u32,
    entry_type: &str,
    name: &str,
    author: &str,
    content: Option<&str>,
) -> Result<Vec<u8>> {
    if entry_type == "Language" {
        let content_str = content.unwrap_or("");
        let eng_name = extract_json_str(content_str, &["info", "full_name"])
            .unwrap_or_else(|| name.to_string());
        let nat_name = extract_json_str(content_str, &["info", "loc_name"])
            .unwrap_or_else(|| eng_name.clone());
        build_language_create_response(entry_id, timestamp, name, &eng_name, &nat_name, content_str)
    } else {
        build_create_response(
            entry_id,
            timestamp,
            entry_type_id_from_name(entry_type),
            name,
            author,
            content,
        )
    }
}

pub fn build_live_delete_reply(entry_id: u32, entry_type: u32) -> Result<Vec<u8>> {
    let mut ib = FlatccBuilder::new();
    ib.start_table(2);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, entry_type, 0);
    let inner = ib.end_table();
    let inner_bytes = ib.finish_minimal(inner);

    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 2, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

pub fn build_live_update_reply(entry_id: u32, entry_type: u32, content: &str) -> Result<Vec<u8>> {
    let mut ib = FlatccBuilder::new();
    let c = ib.create_string(content);
    ib.start_table(3);
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, entry_type, 0);
    ib.table_add_offset(2, c);
    let inner = ib.end_table();
    let inner_bytes = ib.finish_minimal(inner);

    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 1, 0);
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}
