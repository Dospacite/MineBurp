//! History operations shared by the desktop commands and the MCP tools.
//!
//! Both front ends filter, export, and import the same way; keeping one copy
//! here means a filter saved in the UI means exactly the same thing when an
//! agent applies it, and an export written by either is byte-for-byte alike.

mod filter;
mod paths;
mod pcapng;

use std::{collections::HashMap, io::Write as _, path::Path};

use mineburp_capture::{ImportOptions, ImportSummary};
use mineburp_core::{ConnectionSnapshot, PacketDetail};
use mineburp_project::{PacketQuery, ProjectError, ProjectStore};
use uuid::Uuid;

pub use filter::{ContentSearchMode, ContentSearchScope, PacketFilterInput};
pub use paths::{PathPurpose, validate_path};
pub use pcapng::{PcapExportSummary, write_pcapng};

/// Saves one batch: the connection rows first (packets reference them), then
/// the packets in one transaction.
///
/// One connection row per flow per batch rather than per frame: the counters
/// are cumulative, so only the last value matters.
pub fn persist<'a>(
    store: &ProjectStore,
    connections: impl IntoIterator<Item = &'a ConnectionSnapshot>,
    details: &[PacketDetail],
) -> Result<(), ProjectError> {
    for snapshot in connections {
        store.save_connection(snapshot)?;
    }
    store.insert_packets(details)?;
    Ok(())
}

/// Writes every packet matching `query` to `path` as a JSON array, newest first.
///
/// Pages through the history by id: a single history query is capped, and
/// holding the whole capture in memory to serialise it would not scale.
/// Returns how many packets were written. `path` must already be validated.
pub fn export_json(
    store: &ProjectStore,
    query: &PacketQuery,
    path: &Path,
) -> Result<usize, String> {
    const EXPORT_PAGE: usize = 500;
    let mut query = query.clone();
    query.limit = EXPORT_PAGE;
    query.offset = 0;
    query.after_id = None;
    // Pages back with `before_id`, which needs newest-first pages.
    query.oldest_first = false;
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    let mut out = std::io::BufWriter::new(file);
    let mut written = 0usize;
    out.write_all(b"[").map_err(|error| error.to_string())?;
    loop {
        let page = store
            .query_packets_filtered(&query)
            .map_err(|error| error.to_string())?;
        for packet in &page {
            if written > 0 {
                out.write_all(b",").map_err(|error| error.to_string())?;
            }
            out.write_all(b"\n  ").map_err(|error| error.to_string())?;
            serde_json::to_writer(&mut out, packet).map_err(|error| error.to_string())?;
            written += 1;
        }
        match page.last() {
            Some(last) if page.len() == EXPORT_PAGE => query.before_id = Some(last.id),
            _ => break,
        }
    }
    out.write_all(b"\n]\n").map_err(|error| error.to_string())?;
    out.flush().map_err(|error| error.to_string())?;
    Ok(written)
}

/// Writes every packet matching `query` to `path` as pcapng, oldest first.
/// `path` must already be validated.
pub fn export_pcapng(
    store: &ProjectStore,
    query: &PacketQuery,
    path: &Path,
) -> Result<PcapExportSummary, String> {
    let mut query = query.clone();
    query.offset = 0;
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    write_pcapng(store, &query, std::io::BufWriter::new(file))
}

/// Reads a pcap or pcapng file into `store`.
///
/// Flows are recognised by server port because an imported file has no
/// process to attribute them to. Retransmissions are removed and segments
/// reordered exactly as in live capture, then each TCP stream is split into
/// Minecraft packets. `path` must already be validated.
pub fn import_capture_file(
    store: &ProjectStore,
    path: &Path,
    options: &ImportOptions,
) -> Result<ImportSummary, String> {
    const BATCH: usize = 512;
    if store.is_read_only() {
        return Err("the open project is read-only".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut pending = Vec::with_capacity(BATCH);
    // One connection row per connection per batch: the snapshot each row
    // carries is cumulative, so only the latest matters.
    let mut touched: HashMap<Uuid, ConnectionSnapshot> = HashMap::new();
    let flush = |pending: &mut Vec<_>,
                 touched: &mut HashMap<Uuid, ConnectionSnapshot>|
     -> Result<(), String> {
        let result = persist(store, touched.values(), pending).map_err(|error| error.to_string());
        pending.clear();
        touched.clear();
        result
    };
    let mut summary =
        mineburp_capture::import_capture(std::io::BufReader::new(file), options, |row| {
            touched.insert(row.connection.id, row.connection);
            pending.push(row.detail);
            if pending.len() >= BATCH {
                flush(&mut pending, &mut touched)?;
            }
            Ok(())
        })
        .map_err(|error| error.to_string())?;
    flush(&mut pending, &mut touched)?;
    if summary.frames_imported == 0 && summary.error.is_none() {
        summary.error = Some(if options.server_ports.is_empty() {
            "the capture contains no TCP or UDP payloads".into()
        } else {
            format!(
                "no traffic on server port(s) {:?}; set the ports the server used",
                options.server_ports
            )
        });
    }
    Ok(summary)
}

/// Applies a user-supplied schema pack to a stored frame, if one matches.
///
/// Capture only records *which* schema matched, by name; walking its fields is
/// deferred to here so a loaded pack cannot slow down capture itself.
pub fn decode_with_schema_packs(
    packs: &[mineburp_protocol::SchemaPack],
    summary: &mineburp_core::PacketSummary,
    logical: &[u8],
) -> (Option<serde_json::Value>, Option<String>) {
    let Some(packet_id) = summary.packet_id else {
        return (None, None);
    };
    let Some(schema) = packs.iter().flat_map(|pack| &pack.schemas).find(|schema| {
        schema.matches(
            summary.state,
            summary.direction,
            packet_id,
            summary.channel.as_deref(),
            summary.protocol_version,
        )
    }) else {
        return (None, None);
    };
    // The stored bytes carry the packet-id VarInt; schemas describe the body.
    let body = mineburp_protocol::decode_var_i32(logical)
        .ok()
        .flatten()
        .and_then(|(_, prefix)| logical.get(prefix..))
        .unwrap_or_default();
    match mineburp_protocol::decode_schema(
        schema,
        body,
        mineburp_protocol::DecodeContext::default(),
    ) {
        Ok(fields) => (Some(fields), None),
        Err(error) => (None, Some(format!("schema `{}`: {error}", schema.name))),
    }
}

pub mod fields;

pub mod rules;
