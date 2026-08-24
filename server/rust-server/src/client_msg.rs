//! Parser for client WebSocket FlatBuffer messages.
//!
//! All client messages share an outer wrapper:
//!   table Wrapper { type: uint32 (id:0); payload: [ubyte] (id:1); }
//!
//! The payload is a nested FlatBuffer whose schema depends on `type`.

use anyhow::{Context, Result};

/// Parsed client message.
#[derive(Debug)]
pub enum ClientMsg {
    /// type=0: Client init, sends steam_id
    Init { _steam_id: String },
    /// type=10: Client acknowledges config entry
    ConfigAck { entry_id: u32 },
    /// type=6: Client clicked share for an entry class.
    ShareClick { _entry_type: u32 },
    /// type=7: Client persisted UI/inventory state blob.
    StateBlob { payload: Vec<u8> },
    /// type=3: Create a new log entry (script/config/style/language)
    CreateEntry {
        name: String,
        /// 0 = Config, 1 = Script, 2 = Style, 3 = Language
        entry_type: u32,
        /// Total entry count expected (including this new one)
        #[allow(dead_code)]
        expected_count: u32,
        content: Option<String>,
    },
    /// type=1: Update an existing log entry
    UpdateEntry {
        entry_id: u32,
        entry_type: u32,
        content: Option<String>,
        name: Option<String>,
        timestamp: Option<u32>,
    },
    /// type=4: Duplicate an existing log entry
    DuplicateEntry {
        entry_id: u32,
        /// 1 = Script, 0 = Config
        entry_type: u32,
        name: Option<String>,
    },
    /// type=2: Delete / restore / delete-permanently
    DeleteEntry {
        entry_id: u32,
        entry_type: u32,
        action: DeleteAction,
        _raw_payload: Vec<u8>,
    },
    /// type=11: Client requests translations for a language (field 1 = lang code string)
    LanguageAck {
        lang_code: String,
    },
    /// type=9: Shared skins sync probe (empty table, no fields)
    SharedSkins,
    /// type=8: Shared features/GC connectivity check
    SharedFeatures { _data: u32 },
    /// Unknown message type
    Unknown {
        msg_type: u32,
        _payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteAction {
    /// 3 fields (f2=257) → move to trash
    Delete,
    /// 4 fields (f2=257, f3=65793) → remove from trash permanently
    DeletePermanently,
    /// 2 fields (no f2) → restore from trash
    Restore,
}

pub fn parse(data: &[u8]) -> Result<ClientMsg> {
    let outer = parse_outer(data).context("parse outer wrapper")?;
    match outer.msg_type {
        0 => {
            let inner = Table::parse(outer.payload)?;
            let steam_id = inner.read_string(0).unwrap_or_default();
            Ok(ClientMsg::Init { _steam_id: steam_id })
        }
        10 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            Ok(ClientMsg::ConfigAck { entry_id })
        }
        6 => {
            let inner = Table::parse(outer.payload)?;
            let entry_type = inner.read_u32(0).unwrap_or(0);
            Ok(ClientMsg::ShareClick { _entry_type: entry_type })
        }
        3 => {
            let inner = Table::parse(outer.payload)?;
            let name = inner.read_string(0).unwrap_or_default();
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let content = inner.read_string(2);
            let expected_count = inner.read_u32(3).unwrap_or(0);
            Ok(ClientMsg::CreateEntry {
                name,
                entry_type,
                expected_count,
                content,
            })
        }
        1 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let content = inner.read_string(2);
            let name = inner.read_string(3);
            let timestamp = inner.read_u32(4);
            Ok(ClientMsg::UpdateEntry {
                entry_id,
                entry_type,
                content,
                name,
                timestamp,
            })
        }
        4 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let name = inner.read_string(2).or_else(|| inner.read_string(3));
            Ok(ClientMsg::DuplicateEntry {
                entry_id,
                entry_type,
                name,
            })
        }
        2 => {
            let inner = Table::parse(outer.payload)?;
            let entry_id = inner.read_u32(0).unwrap_or(0);
            let entry_type = inner.read_u32(1).unwrap_or(0);
            let has_f2 = inner.field_offset(2).is_some();
            let has_f3 = inner.field_offset(3).is_some();
            let action = match (has_f2, has_f3) {
                (true, true) => DeleteAction::DeletePermanently,
                (true, false) => DeleteAction::Delete,
                (false, _) => DeleteAction::Restore,
            };
            Ok(ClientMsg::DeleteEntry {
                entry_id,
                entry_type,
                action,
                _raw_payload: outer.payload.to_vec(),
            })
        }
        11 => {
            let inner = Table::parse(outer.payload)?;
            let lang_code = inner.read_string(1).unwrap_or_default();
            Ok(ClientMsg::LanguageAck { lang_code })
        }
        7 => Ok(ClientMsg::StateBlob {
            payload: outer.payload.to_vec(),
        }),
        8 => {
            let inner = Table::parse(outer.payload)?;
            let data = inner.read_u32(0).unwrap_or(0);
            Ok(ClientMsg::SharedFeatures { _data: data })
        }
        9 => Ok(ClientMsg::SharedSkins),
        t => Ok(ClientMsg::Unknown {
            msg_type: t,
            _payload: outer.payload.to_vec(),
        }),
    }
}

struct OuterMsg<'a> {
    msg_type: u32,
    payload: &'a [u8],
}

fn parse_outer(buf: &[u8]) -> Result<OuterMsg<'_>> {
    anyhow::ensure!(buf.len() >= 8, "outer too short: {} bytes", buf.len());
    let tbl = Table::parse(buf)?;

    // field[0] = type (u32), field[1] = payload ([ubyte] vector)
    let msg_type = tbl.read_u32(0).unwrap_or(0);
    let payload_field = tbl.field_offset(1);

    let payload = if let Some(foff) = payload_field {
        let abs = tbl.root_pos + foff;
        anyhow::ensure!(abs + 4 <= buf.len(), "payload offset out of bounds");
        let rel = read_u32(buf, abs) as usize;
        let vec_pos = abs + rel;
        anyhow::ensure!(vec_pos + 4 <= buf.len(), "payload vector out of bounds");
        let vec_len = read_u32(buf, vec_pos) as usize;
        anyhow::ensure!(
            vec_pos + 4 + vec_len <= buf.len(),
            "payload data out of bounds"
        );
        &buf[vec_pos + 4..vec_pos + 4 + vec_len]
    } else {
        &[]
    };

    Ok(OuterMsg { msg_type, payload })
}

/// Minimal FlatBuffer table reader.
struct Table<'a> {
    buf: &'a [u8],
    root_pos: usize,
    vt_pos: usize,
    vt_size: usize,
}

impl<'a> Table<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self> {
        anyhow::ensure!(buf.len() >= 4, "table too short");
        let root_off = read_u32(buf, 0) as usize;
        anyhow::ensure!(root_off + 4 <= buf.len(), "root offset out of bounds");
        let soff = read_i32(buf, root_off);
        let vt_pos = (root_off as i64 - soff as i64) as usize;
        anyhow::ensure!(vt_pos + 4 <= buf.len(), "vtable out of bounds");
        let vt_size = read_u16(buf, vt_pos) as usize;
        anyhow::ensure!(
            vt_pos + vt_size <= buf.len(),
            "vtable extends out of bounds"
        );
        Ok(Table {
            buf,
            root_pos: root_off,
            vt_pos,
            vt_size,
        })
    }

    fn num_fields(&self) -> usize {
        (self.vt_size - 4) / 2
    }

    fn field_offset(&self, field_id: usize) -> Option<usize> {
        if field_id >= self.num_fields() {
            return None;
        }
        let foff = read_u16(self.buf, self.vt_pos + 4 + field_id * 2) as usize;
        if foff == 0 { None } else { Some(foff) }
    }

    fn read_u32(&self, field_id: usize) -> Option<u32> {
        let foff = self.field_offset(field_id)?;
        let pos = self.root_pos + foff;
        if pos + 4 > self.buf.len() {
            return None;
        }
        Some(read_u32(self.buf, pos))
    }

    fn read_string(&self, field_id: usize) -> Option<String> {
        let foff = self.field_offset(field_id)?;
        let pos = self.root_pos + foff;
        if pos + 4 > self.buf.len() {
            return None;
        }
        let rel = read_u32(self.buf, pos) as usize;
        let str_pos = pos + rel;
        if str_pos + 4 > self.buf.len() {
            return None;
        }
        let len = read_u32(self.buf, str_pos) as usize;
        if str_pos + 4 + len > self.buf.len() {
            return None;
        }
        std::str::from_utf8(&self.buf[str_pos + 4..str_pos + 4 + len])
            .ok()
            .map(|s| s.to_string())
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

