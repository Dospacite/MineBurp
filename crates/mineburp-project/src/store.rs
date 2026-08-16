use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use mineburp_core::{
    Comparison, ConnectionSnapshot, Direction, Disposition, FilterExpression, FilterField,
    FilterValue, InterceptRule, PacketDetail, PacketSummary, ProtocolState, RepeaterTab,
    ReplacementRule, Target, TrafficSource,
};
use mineburp_protocol::SchemaPack;
use parking_lot::Mutex;
use regex::Regex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter, types::Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const PROJECT_SCHEMA_VERSION: i32 = 3;

const INSERT_PACKET_SQL: &str = "INSERT INTO packets(
        sequence, connection_id, timestamp_micros, source, direction, state,
        protocol_version, packet_id, name, channel, loader, size, disposition,
        flow_json, logical_bytes_zstd, decoded_json, decode_error, wire_json
     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)";

fn packet_params<'a>(
    detail: &'a PacketDetail,
    compressed: &'a [u8],
) -> Result<Vec<Value>, ProjectError> {
    Ok(vec![
        Value::from(i64::try_from(detail.summary.sequence).unwrap_or(i64::MAX)),
        Value::from(detail.summary.connection_id.to_string()),
        Value::from(detail.summary.timestamp_micros),
        Value::from(enum_json(&detail.summary.source)?),
        Value::from(enum_json(&detail.summary.direction)?),
        Value::from(enum_json(&detail.summary.state)?),
        detail
            .summary
            .protocol_version
            .map_or(Value::Null, |value| Value::from(i64::from(value))),
        detail
            .summary
            .packet_id
            .map_or(Value::Null, |value| Value::from(i64::from(value))),
        optional_text(detail.summary.name.as_deref()),
        optional_text(detail.summary.channel.as_deref()),
        optional_text(detail.summary.loader.as_deref()),
        Value::from(i64::try_from(detail.summary.size).unwrap_or(i64::MAX)),
        Value::from(enum_json(&detail.summary.disposition)?),
        optional_text(optional_json(detail.summary.flow.as_ref())?.as_deref()),
        Value::from(compressed.to_vec()),
        optional_text(optional_json(detail.decoded.as_ref())?.as_deref()),
        optional_text(detail.decode_error.as_deref()),
        Value::from(
            serde_json::to_string(&detail.wire)
                .map_err(|error| ProjectError::Corrupt(error.to_string()))?,
        ),
    ])
}

fn optional_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::from(text.to_owned()))
}

#[derive(Debug, Clone, Default)]
pub struct ProjectOptions {
    pub passphrase: Option<String>,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub path: PathBuf,
    pub name: String,
    pub encrypted: bool,
    pub schema_version: i32,
}

/// Free-text search over the columns a history row displays.
///
/// The three switches mirror the ones an operator expects from a proxy history:
/// a literal substring by default, an anchored regular expression when asked,
/// either of them case-sensitively, and the whole thing invertible so a noisy
/// packet can be filtered out rather than hunted for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchTerm {
    pub text: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub negate: bool,
}

/// How a payload search interprets the term it was given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ContentMode {
    /// A literal string, matched against the payload's bytes.
    #[default]
    Text,
    /// A byte sequence written in hex, with any separators ignored.
    Hex,
    /// A regular expression, matched against a lossy UTF-8 view of the payload.
    Regex,
}

/// How much of the payload the term has to account for.
///
/// [`Contains`](ContentScope::Contains) answers "is this in there"; the other
/// three answer "is this what the packet *is*", which is what makes it possible
/// to select — or, negated, exclude — every packet whose payload is exactly one
/// known sequence rather than every packet that merely carries it somewhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ContentScope {
    /// Anywhere in the payload.
    #[default]
    Contains,
    /// The payload is the term and nothing else.
    Equals,
    /// The payload begins with the term.
    Prefix,
    /// The payload ends with the term.
    Suffix,
}

/// A search through the stored payload bytes rather than the row's metadata.
///
/// Unlike every other filter this one cannot be answered from an indexed
/// column: payloads are compressed blobs, so each candidate row has to be
/// decompressed and scanned. It is deliberately a separate control from the
/// metadata search so the cost is something the operator opts into.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentQuery {
    /// One term per line; a payload matching any of them matches the search.
    ///
    /// A single-line term is the whole language for text and regular
    /// expressions. Hex terms additionally accept `start-end`, an inclusive
    /// range over sequences of the same length compared byte by byte, which is
    /// what makes "every frame that is one byte between `0c` and `0f`"
    /// expressible — and, negated, hideable.
    pub text: String,
    pub mode: ContentMode,
    pub scope: ContentScope,
    pub case_sensitive: bool,
    pub negate: bool,
}

/// A bounded, database-side history query. Keeping these filters in the
/// repository prevents the webview from repeatedly loading and rendering an
/// entire capture just to find a few relevant packets.
///
/// Every list field is a disjunction that is skipped entirely when empty, so an
/// untouched filter costs nothing in the generated SQL.
#[derive(Debug, Clone, Default)]
pub struct PacketQuery {
    pub connection_id: Option<Uuid>,
    pub offset: usize,
    pub limit: usize,
    pub search: Option<SearchTerm>,
    pub directions: Vec<Direction>,
    pub states: Vec<ProtocolState>,
    pub sources: Vec<TrafficSource>,
    pub dispositions: Vec<Disposition>,
    /// Substrings of the packet name to keep; empty keeps every name.
    pub include_names: Vec<String>,
    /// Substrings of the packet name to drop, applied after `include_names`.
    pub exclude_names: Vec<String>,
    pub min_size: Option<usize>,
    pub max_size: Option<usize>,
    /// The operator-written expression, already parsed by the caller.
    pub expression: Option<FilterExpression>,
    /// A search through the payload bytes. Always applied last.
    pub content: Option<ContentQuery>,
    /// Keyset cursor for older pages (`id < before_id`).
    ///
    /// Paging by offset drifts while capture is running — rows inserted between
    /// two requests shift every later page — so the history pages by id.
    pub before_id: Option<i64>,
    /// Keyset cursor for the live tail (`id > after_id`), used to append new
    /// packets without re-reading and re-rendering the page the operator is on.
    pub after_id: Option<i64>,
}

/// A slice of one packet's payload plus everything needed to describe it.
///
/// Large packets are read through this window so a multi-megabyte body never
/// has to cross the IPC boundary or reach the DOM in one piece.
#[derive(Debug, Clone)]
pub struct PacketWindow {
    pub summary: PacketSummary,
    pub wire: mineburp_core::WireMetadata,
    pub stored_decoded: Option<serde_json::Value>,
    pub stored_decode_error: Option<String>,
    pub total_bytes: usize,
    pub offset: usize,
    pub bytes: Bytes,
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("project compression error: {0}")]
    Compression(#[from] std::io::Error),
    #[error("project payload is corrupt: {0}")]
    Corrupt(String),
    #[error("project is read-only")]
    ReadOnly,
    #[error("project already exists: {0}")]
    AlreadyExists(PathBuf),
    #[error("project schema version {0} is newer than this build supports")]
    NewerSchema(i32),
    #[error("search pattern is not valid: {0}")]
    InvalidSearch(String),
    #[error("filter is not valid: {0}")]
    InvalidFilter(String),
}

#[derive(Debug, Clone)]
pub struct ProjectStore {
    connection: Arc<Mutex<Connection>>,
    info: ProjectInfo,
    read_only: bool,
}

impl ProjectStore {
    #[allow(clippy::needless_pass_by_value)]
    pub fn create(
        path: impl AsRef<Path>,
        name: &str,
        options: ProjectOptions,
    ) -> Result<Self, ProjectError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(ProjectError::AlreadyExists(path));
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(&path, flags)?;
        configure_connection(&connection, options.passphrase.as_deref(), false)?;
        migrate(&connection)?;
        connection.execute(
            "INSERT OR REPLACE INTO project_meta(key, value) VALUES ('name', ?1)",
            [name],
        )?;
        connection.execute(
            "INSERT OR REPLACE INTO project_meta(key, value) VALUES ('encrypted', ?1)",
            [if options.passphrase.is_some() {
                "true"
            } else {
                "false"
            }],
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            info: ProjectInfo {
                path,
                name: name.to_owned(),
                encrypted: options.passphrase.is_some(),
                schema_version: PROJECT_SCHEMA_VERSION,
            },
            read_only: false,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn open(path: impl AsRef<Path>, options: ProjectOptions) -> Result<Self, ProjectError> {
        let path = path.as_ref().to_path_buf();
        let flags = if options.read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        let connection = Connection::open_with_flags(&path, flags)?;
        configure_connection(
            &connection,
            options.passphrase.as_deref(),
            options.read_only,
        )?;
        let schema_version: i32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema_version > PROJECT_SCHEMA_VERSION {
            return Err(ProjectError::NewerSchema(schema_version));
        }
        if !options.read_only {
            migrate(&connection)?;
        }
        let name = meta_value(&connection, "name")?.unwrap_or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("MineBurp Project")
                .to_owned()
        });
        let encrypted = meta_value(&connection, "encrypted")?.is_some_and(|value| value == "true")
            || options.passphrase.is_some();
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            info: ProjectInfo {
                path,
                name,
                encrypted,
                schema_version: PROJECT_SCHEMA_VERSION,
            },
            read_only: options.read_only,
        })
    }

    #[must_use]
    pub fn info(&self) -> &ProjectInfo {
        &self.info
    }

    pub fn save_connection(&self, snapshot: &ConnectionSnapshot) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        self.connection.lock().execute(
            "INSERT INTO connections(
                id, target_host, target_port, listener_address, status, state,
                protocol_version, minecraft_version, loader, compression_threshold,
                encrypted_client, encrypted_server, packet_count, byte_count, last_error
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO UPDATE SET
                status=excluded.status, state=excluded.state,
                protocol_version=excluded.protocol_version,
                minecraft_version=excluded.minecraft_version, loader=excluded.loader,
                compression_threshold=excluded.compression_threshold,
                encrypted_client=excluded.encrypted_client,
                encrypted_server=excluded.encrypted_server,
                packet_count=excluded.packet_count, byte_count=excluded.byte_count,
                last_error=excluded.last_error",
            params![
                snapshot.id.to_string(),
                snapshot.target.host,
                snapshot.target.port,
                snapshot.listener_address,
                enum_json(&snapshot.status)?,
                enum_json(&snapshot.state)?,
                snapshot.protocol_version,
                snapshot.minecraft_version,
                snapshot.loader,
                snapshot.compression_threshold,
                snapshot.encrypted_client,
                snapshot.encrypted_server,
                i64::try_from(snapshot.packet_count).unwrap_or(i64::MAX),
                i64::try_from(snapshot.byte_count).unwrap_or(i64::MAX),
                snapshot.last_error,
            ],
        )?;
        Ok(())
    }

    /// Every connection the project knows about, busiest first.
    ///
    /// Proxied sessions and passively captured flows are both rows here, so this
    /// is the only listing that can offer the operator all of the traffic the
    /// history actually contains.
    pub fn list_connections(&self, limit: usize) -> Result<Vec<ConnectionSnapshot>, ProjectError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare_cached(
            "SELECT id, target_host, target_port, listener_address, status, state,
                    protocol_version, minecraft_version, loader, compression_threshold,
                    encrypted_client, encrypted_server, packet_count, byte_count, last_error
             FROM connections ORDER BY packet_count DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            Ok(ConnectionSnapshot {
                id: parse_uuid(&row.get::<_, String>(0)?)?,
                target: Target {
                    host: row.get(1)?,
                    port: row.get(2)?,
                },
                listener_address: row.get(3)?,
                status: parse_json(&row.get::<_, String>(4)?)?,
                state: parse_json(&row.get::<_, String>(5)?)?,
                protocol_version: row.get(6)?,
                minecraft_version: row.get(7)?,
                loader: row.get(8)?,
                compression_threshold: row.get(9)?,
                encrypted_client: row.get(10)?,
                encrypted_server: row.get(11)?,
                packet_count: row_u64(row, 12)?,
                byte_count: row_u64(row, 13)?,
                last_error: row.get(14)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectError::from)
    }

    /// Inserts a batch of packets in one transaction.
    ///
    /// Passive capture produces a row per TCP segment. Committing each one
    /// separately made `SQLite` the capture pipeline's bottleneck and forced the
    /// writer channel to drop frames, which is what made the live table appear
    /// to lose and reset packets under load.
    pub fn insert_packets(&self, details: &[PacketDetail]) -> Result<Vec<i64>, ProjectError> {
        self.ensure_writable()?;
        if details.is_empty() {
            return Ok(Vec::new());
        }
        // Compress outside the lock: it is the expensive part and it does not
        // need the database.
        let compressed = details
            .iter()
            .map(|detail| zstd::stream::encode_all(detail.logical_bytes.as_ref(), 1))
            .collect::<Result<Vec<_>, _>>()?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let mut ids = Vec::with_capacity(details.len());
        {
            let mut statement = transaction.prepare_cached(INSERT_PACKET_SQL)?;
            for (detail, payload) in details.iter().zip(&compressed) {
                statement.execute(params_from_iter(packet_params(detail, payload)?))?;
                ids.push(transaction.last_insert_rowid());
            }
        }
        transaction.commit()?;
        Ok(ids)
    }

    /// Reads one packet's metadata plus a bounded slice of its payload.
    pub fn packet_window(
        &self,
        id: i64,
        offset: usize,
        limit: usize,
    ) -> Result<Option<PacketWindow>, ProjectError> {
        let Some(detail) = self.packet_detail(id)? else {
            return Ok(None);
        };
        let total_bytes = detail.logical_bytes.len();
        let start = offset.min(total_bytes);
        let end = start.saturating_add(limit).min(total_bytes);
        Ok(Some(PacketWindow {
            summary: detail.summary,
            wire: detail.wire,
            stored_decoded: detail.decoded,
            stored_decode_error: detail.decode_error,
            total_bytes,
            offset: start,
            bytes: detail.logical_bytes.slice(start..end),
        }))
    }

    pub fn insert_packet(&self, detail: &PacketDetail) -> Result<i64, ProjectError> {
        self.ensure_writable()?;
        let compressed = zstd::stream::encode_all(detail.logical_bytes.as_ref(), 1)?;
        let connection = self.connection.lock();
        connection.execute(
            INSERT_PACKET_SQL,
            params_from_iter(packet_params(detail, &compressed)?),
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn query_packets(
        &self,
        connection_id: Option<Uuid>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<PacketSummary>, ProjectError> {
        self.query_packets_filtered(&PacketQuery {
            connection_id,
            offset,
            limit,
            ..PacketQuery::default()
        })
    }

    pub fn query_packets_filtered(
        &self,
        query: &PacketQuery,
    ) -> Result<Vec<PacketSummary>, ProjectError> {
        let mut builder = ClauseBuilder::default();
        if let Some(connection_id) = query.connection_id {
            builder.push(
                "connection_id = ?",
                [Value::from(connection_id.to_string())],
            );
        }
        builder.push_enum_set("direction", &query.directions)?;
        builder.push_enum_set("state", &query.states)?;
        builder.push_enum_set("source", &query.sources)?;
        builder.push_enum_set("disposition", &query.dispositions)?;
        if let Some(before_id) = query.before_id {
            builder.push("id < ?", [Value::from(before_id)]);
        }
        if let Some(after_id) = query.after_id {
            builder.push("id > ?", [Value::from(after_id)]);
        }
        if let Some(minimum) = query.min_size {
            builder.push(
                "size >= ?",
                [Value::from(i64::try_from(minimum).unwrap_or(0))],
            );
        }
        if let Some(maximum) = query.max_size {
            builder.push(
                "size <= ?",
                [Value::from(i64::try_from(maximum).unwrap_or(i64::MAX))],
            );
        }
        builder.push_name_list(&query.include_names, false);
        builder.push_name_list(&query.exclude_names, true);
        if let Some(search) = &query.search {
            push_search(&mut builder, search)?;
        }
        if let Some(expression) = &query.expression {
            let (sql, values) = compile_expression(expression)?;
            builder.push_owned(sql, values);
        }
        // Deliberately last: every clause above answers from an indexed column,
        // while this one decompresses a blob per surviving row. Pushing it to
        // the end of the conjunction lets the cheap filters reject first.
        let matcher = query
            .content
            .as_ref()
            // Whitespace-only text yields no terms, and a matcher with no terms
            // matches nothing — which would silently empty the history.
            .filter(|content| !content.text.trim().is_empty())
            .map(|content| {
                ContentMatcher::compile(content).map(|matcher| (Arc::new(matcher), content.negate))
            })
            .transpose()?;
        if let Some((_, negate)) = &matcher {
            let call = "payload_search(logical_bytes_zstd, size)";
            builder.push_owned(
                if *negate {
                    format!("NOT {call}")
                } else {
                    call.to_owned()
                },
                Vec::new(),
            );
        }

        let where_clause = builder.where_clause();
        let sql = format!(
            "SELECT id, sequence, connection_id, timestamp_micros, source, direction, state,
                    protocol_version, packet_id, name, channel, loader, size, disposition, flow_json
             FROM packets{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        );
        let connection = self.connection.lock();
        if let Some((matcher, _)) = matcher {
            register_payload_search(&connection, matcher)?;
        }
        let mut values = builder.values;
        let mut statement = connection.prepare(&sql)?;
        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<PacketSummary> {
            let connection_text: String = row.get(2)?;
            let source_text: String = row.get(4)?;
            let direction_text: String = row.get(5)?;
            let state_text: String = row.get(6)?;
            let disposition_text: String = row.get(13)?;
            let flow_text: Option<String> = row.get(14)?;
            Ok(PacketSummary {
                id: row.get(0)?,
                sequence: row_u64(row, 1)?,
                connection_id: parse_uuid(&connection_text)?,
                timestamp_micros: row.get(3)?,
                source: parse_json(&source_text)?,
                direction: parse_json(&direction_text)?,
                state: parse_json(&state_text)?,
                protocol_version: row.get(7)?,
                packet_id: row.get(8)?,
                name: row.get(9)?,
                channel: row.get(10)?,
                loader: row.get(11)?,
                size: row_usize(row, 12)?,
                disposition: parse_json(&disposition_text)?,
                flow: parse_optional_json(flow_text.as_deref())?,
            })
        };
        values.push(i64::try_from(query.limit).unwrap_or(i64::MAX).into());
        values.push(i64::try_from(query.offset).unwrap_or(i64::MAX).into());
        let rows = statement.query_map(params_from_iter(values), map_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectError::from)
    }

    pub fn packet_detail(&self, id: i64) -> Result<Option<PacketDetail>, ProjectError> {
        let connection = self.connection.lock();
        connection
            .query_row(
                "SELECT id, sequence, connection_id, timestamp_micros, source, direction, state,
                        protocol_version, packet_id, name, channel, loader, size, disposition,
                        flow_json, logical_bytes_zstd, decoded_json, decode_error, wire_json
                 FROM packets WHERE id=?1",
                [id],
                |row| {
                    let flow_text: Option<String> = row.get(14)?;
                    let compressed: Vec<u8> = row.get(15)?;
                    let decoded_text: Option<String> = row.get(16)?;
                    let wire_text: String = row.get(18)?;
                    let logical =
                        zstd::stream::decode_all(compressed.as_slice()).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                compressed.len(),
                                rusqlite::types::Type::Blob,
                                Box::new(error),
                            )
                        })?;
                    Ok(PacketDetail {
                        summary: PacketSummary {
                            id: row.get(0)?,
                            sequence: row_u64(row, 1)?,
                            connection_id: parse_uuid(&row.get::<_, String>(2)?)?,
                            timestamp_micros: row.get(3)?,
                            source: parse_json(&row.get::<_, String>(4)?)?,
                            direction: parse_json(&row.get::<_, String>(5)?)?,
                            state: parse_json(&row.get::<_, String>(6)?)?,
                            protocol_version: row.get(7)?,
                            packet_id: row.get(8)?,
                            name: row.get(9)?,
                            channel: row.get(10)?,
                            loader: row.get(11)?,
                            size: row_usize(row, 12)?,
                            disposition: parse_json(&row.get::<_, String>(13)?)?,
                            flow: parse_optional_json(flow_text.as_deref())?,
                        },
                        logical_bytes: Bytes::from(logical),
                        decoded: parse_optional_json(decoded_text.as_deref())?,
                        decode_error: row.get(17)?,
                        wire: parse_json(&wire_text)?,
                    })
                },
            )
            .optional()
            .map_err(ProjectError::from)
    }

    pub fn checkpoint(&self) -> Result<(), ProjectError> {
        self.connection
            .lock()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    pub fn save_schema_pack(&self, pack: &SchemaPack) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        pack.validate()
            .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
        let payload = serde_json::to_string(pack)
            .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
        let sha256 = hex_digest(Sha256::digest(payload.as_bytes()).as_slice());
        self.connection.lock().execute(
            "INSERT INTO schema_packs(id, version, sha256, payload_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id, version) DO UPDATE SET
               sha256=excluded.sha256, payload_json=excluded.payload_json",
            params![pack.manifest.id, pack.manifest.version, sha256, payload],
        )?;
        Ok(())
    }

    pub fn load_schema_packs(&self) -> Result<Vec<SchemaPack>, ProjectError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare("SELECT payload_json FROM schema_packs ORDER BY id ASC, version DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let payload = row?;
            serde_json::from_str(&payload).map_err(|error| ProjectError::Corrupt(error.to_string()))
        })
        .collect()
    }

    pub fn save_repeater_tab(&self, tab: &RepeaterTab) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        let payload =
            serde_json::to_string(tab).map_err(|error| ProjectError::Corrupt(error.to_string()))?;
        self.connection.lock().execute(
            "INSERT INTO repeater_tabs(id, name, payload_json, updated_at_micros)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, payload_json=excluded.payload_json,
               updated_at_micros=excluded.updated_at_micros",
            params![tab.id.to_string(), tab.name, payload, now_micros()],
        )?;
        Ok(())
    }

    pub fn delete_repeater_tab(&self, id: Uuid) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        self.connection
            .lock()
            .execute("DELETE FROM repeater_tabs WHERE id=?1", [id.to_string()])?;
        Ok(())
    }

    pub fn load_repeater_tabs(&self) -> Result<Vec<RepeaterTab>, ProjectError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare("SELECT payload_json FROM repeater_tabs ORDER BY updated_at_micros DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            serde_json::from_str(&row?).map_err(|error| ProjectError::Corrupt(error.to_string()))
        })
        .collect()
    }

    pub fn save_intercept_rules(&self, rules: &[InterceptRule]) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM intercept_rules", [])?;
        for (position, rule) in rules.iter().enumerate() {
            let payload = serde_json::to_string(rule)
                .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
            transaction.execute(
                "INSERT INTO intercept_rules(id, name, payload_json, position)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    rule.id.to_string(),
                    rule.name,
                    payload,
                    i64::try_from(position).unwrap_or(i64::MAX),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_intercept_rules(&self) -> Result<Vec<InterceptRule>, ProjectError> {
        let connection = self.connection.lock();
        let mut statement =
            connection.prepare("SELECT payload_json FROM intercept_rules ORDER BY position ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            serde_json::from_str(&row?).map_err(|error| ProjectError::Corrupt(error.to_string()))
        })
        .collect()
    }

    pub fn save_replacement_rules(&self, rules: &[ReplacementRule]) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM replacement_rules", [])?;
        for (position, rule) in rules.iter().enumerate() {
            let payload = serde_json::to_string(rule)
                .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
            transaction.execute(
                "INSERT INTO replacement_rules(id, name, payload_json, position)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    rule.id.to_string(),
                    rule.name,
                    payload,
                    i64::try_from(position).unwrap_or(i64::MAX),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_replacement_rules(&self) -> Result<Vec<ReplacementRule>, ProjectError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare("SELECT payload_json FROM replacement_rules ORDER BY position ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            serde_json::from_str(&row?).map_err(|error| ProjectError::Corrupt(error.to_string()))
        })
        .collect()
    }

    fn ensure_writable(&self) -> Result<(), ProjectError> {
        if self.read_only {
            Err(ProjectError::ReadOnly)
        } else {
            Ok(())
        }
    }
}

fn configure_connection(
    connection: &Connection,
    passphrase: Option<&str>,
    read_only: bool,
) -> Result<(), ProjectError> {
    if let Some(passphrase) = passphrase {
        connection.pragma_update(None, "key", passphrase)?;
    }
    if read_only {
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA query_only=ON;
             PRAGMA busy_timeout=5000;",
        )?;
    } else {
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA busy_timeout=5000;",
        )?;
    }
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    register_regexp(connection)?;
    Ok(())
}

/// Installs the payload matcher this query will use.
///
/// Registered per query rather than once per connection so the compiled matcher
/// is captured directly, which keeps the pattern out of the SQL and off the
/// per-row path. Re-registering replaces the previous definition.
fn register_payload_search(
    connection: &Connection,
    matcher: Arc<ContentMatcher>,
) -> Result<(), ProjectError> {
    use rusqlite::functions::FunctionFlags;

    connection.create_scalar_function(
        "payload_search",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |context| {
            let blob = context.get_raw(0).as_blob()?;
            // A payload that will not decompress is reported as "no match"
            // rather than failing the whole query: one corrupt row must not
            // make the history unreadable.
            let Ok(payload) = decode_bounded(blob) else {
                return Ok(false);
            };
            // The recorded size tells the matcher how much of the payload it is
            // holding — the decode stops at CONTENT_SCAN_LIMIT.
            let total = context
                .get::<i64>(1)
                .ok()
                .and_then(|size| usize::try_from(size).ok())
                .unwrap_or(payload.len())
                .max(payload.len());
            Ok(matcher.matches(&payload, total))
        },
    )?;
    Ok(())
}

/// Teaches `SQLite` the `REGEXP` operator used by regular-expression searches.
///
/// The compiled pattern is cached against the statement's argument, so a scan
/// compiles the expression once rather than once per row.
fn register_regexp(connection: &Connection) -> Result<(), ProjectError> {
    use std::sync::Arc as StdArc;

    use rusqlite::functions::FunctionFlags;

    connection.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |context| {
            let regex: StdArc<Regex> = context.get_or_create_aux(0, |raw| {
                Regex::new(raw.as_str()?).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        error.to_string(),
                    )))
                })
            })?;
            let subject = context.get_raw(1).as_str()?;
            Ok(regex.is_match(subject))
        },
    )?;
    Ok(())
}

fn migrate(connection: &Connection) -> Result<(), ProjectError> {
    let current: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > PROJECT_SCHEMA_VERSION {
        return Err(ProjectError::NewerSchema(current));
    }
    if current < 1 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS project_meta(
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS connections(
               id TEXT PRIMARY KEY,
               target_host TEXT NOT NULL,
               target_port INTEGER NOT NULL,
               listener_address TEXT NOT NULL,
               status TEXT NOT NULL,
               state TEXT NOT NULL,
               protocol_version INTEGER,
               minecraft_version TEXT,
               loader TEXT,
               compression_threshold INTEGER,
               encrypted_client INTEGER NOT NULL,
               encrypted_server INTEGER NOT NULL,
               packet_count INTEGER NOT NULL,
               byte_count INTEGER NOT NULL,
               last_error TEXT
             );
             CREATE TABLE IF NOT EXISTS packets(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               sequence INTEGER NOT NULL,
               connection_id TEXT NOT NULL,
               timestamp_micros INTEGER NOT NULL,
               source TEXT NOT NULL,
               direction TEXT NOT NULL,
               state TEXT NOT NULL,
               protocol_version INTEGER,
               packet_id INTEGER,
               name TEXT,
               channel TEXT,
               loader TEXT,
               size INTEGER NOT NULL,
               disposition TEXT NOT NULL,
               flow_json TEXT,
               logical_bytes_zstd BLOB NOT NULL,
               decoded_json TEXT,
               decode_error TEXT,
               wire_json TEXT NOT NULL,
               FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_packets_connection_id ON packets(connection_id, id DESC);
             CREATE INDEX IF NOT EXISTS idx_packets_name ON packets(name);
             CREATE INDEX IF NOT EXISTS idx_packets_channel ON packets(channel);
             CREATE TABLE IF NOT EXISTS repeater_tabs(
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               updated_at_micros INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS intercept_rules(
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               position INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS schema_packs(
               id TEXT NOT NULL,
               version TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               PRIMARY KEY(id, version)
             );
             PRAGMA user_version=1;
             COMMIT;",
        )?;
    }
    if current < 2 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE INDEX IF NOT EXISTS idx_packets_history_state
               ON packets(connection_id, source, direction, state, id DESC);
             CREATE INDEX IF NOT EXISTS idx_packets_history_global
               ON packets(source, direction, state, id DESC);
             PRAGMA user_version=2;
             COMMIT;",
        )?;
    }
    if current < 3 {
        add_replacement_rules(connection)?;
    }
    Ok(())
}

/// Schema 3: the rules that rewrite packets automatically.
fn add_replacement_rules(connection: &Connection) -> Result<(), ProjectError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS replacement_rules(
           id TEXT PRIMARY KEY,
           name TEXT NOT NULL,
           payload_json TEXT NOT NULL,
           position INTEGER NOT NULL
         );
         PRAGMA user_version=3;
         COMMIT;",
    )?;
    Ok(())
}

/// Accumulates `WHERE` fragments alongside their bound values.
///
/// Every filter is parameterised: operator-supplied text never reaches the SQL
/// string itself, so a filter expression cannot alter the statement.
#[derive(Debug, Default)]
struct ClauseBuilder {
    clauses: Vec<String>,
    values: Vec<Value>,
}

impl ClauseBuilder {
    fn push(&mut self, clause: &str, values: impl IntoIterator<Item = Value>) {
        self.clauses.push(clause.to_owned());
        self.values.extend(values);
    }

    fn push_owned(&mut self, clause: String, values: Vec<Value>) {
        self.clauses.push(clause);
        self.values.extend(values);
    }

    /// `column IN (…)` for a set of enum values; an empty set means "any".
    fn push_enum_set<T: Serialize>(
        &mut self,
        column: &str,
        selected: &[T],
    ) -> Result<(), ProjectError> {
        if selected.is_empty() {
            return Ok(());
        }
        let placeholders = vec!["?"; selected.len()].join(", ");
        let mut values = Vec::with_capacity(selected.len());
        for value in selected {
            values.push(Value::from(enum_json(value)?));
        }
        self.push_owned(format!("{column} IN ({placeholders})"), values);
        Ok(())
    }

    /// Keeps or drops rows whose name contains any of the given substrings.
    fn push_name_list(&mut self, names: &[String], exclude: bool) {
        let terms: Vec<&String> = names
            .iter()
            .filter(|name| !name.trim().is_empty())
            .collect();
        if terms.is_empty() {
            return;
        }
        let matches =
            vec!["LOWER(COALESCE(name, '')) LIKE LOWER(?) ESCAPE '\\'"; terms.len()].join(" OR ");
        let values = terms
            .iter()
            .map(|name| Value::from(format!("%{}%", escape_like(name.trim()))))
            .collect();
        let clause = if exclude {
            format!("NOT ({matches})")
        } else {
            format!("({matches})")
        };
        self.push_owned(clause, values);
    }

    fn where_clause(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }
}

/// The row columns a free-text search looks at — what the table shows.
const SEARCHABLE_COLUMNS: [&str; 4] = [
    "COALESCE(name, '')",
    "COALESCE(channel, '')",
    "COALESCE(loader, '')",
    "COALESCE(CAST(packet_id AS TEXT), '')",
];

fn push_search(builder: &mut ClauseBuilder, search: &SearchTerm) -> Result<(), ProjectError> {
    let text = search.text.trim();
    if text.is_empty() {
        return Ok(());
    }
    let (matches, values) = if search.regex {
        // Compiled here as well as in SQLite so an unfinished expression is
        // reported as a filter problem rather than as a database failure.
        let pattern = if search.case_sensitive {
            text.to_owned()
        } else {
            format!("(?i){text}")
        };
        Regex::new(&pattern).map_err(|error| ProjectError::InvalidSearch(error.to_string()))?;
        (
            SEARCHABLE_COLUMNS
                .iter()
                .map(|column| format!("{column} REGEXP ?"))
                .collect::<Vec<_>>()
                .join(" OR "),
            vec![Value::from(pattern); SEARCHABLE_COLUMNS.len()],
        )
    } else {
        // `instr` rather than `LIKE`: SQLite's LIKE folds ASCII case whatever
        // the operands look like, so a case-sensitive search built on it
        // silently matched everything. `instr` also treats the term as a
        // literal, so `%` and `_` in a packet name search for themselves.
        let (comparison, pattern) = if search.case_sensitive {
            ("instr({column}, ?) > 0", text.to_owned())
        } else {
            ("instr(LOWER({column}), ?) > 0", text.to_lowercase())
        };
        (
            SEARCHABLE_COLUMNS
                .iter()
                .map(|column| comparison.replace("{column}", column))
                .collect::<Vec<_>>()
                .join(" OR "),
            vec![Value::from(pattern); SEARCHABLE_COLUMNS.len()],
        )
    };
    let clause = if search.negate {
        format!("NOT ({matches})")
    } else {
        format!("({matches})")
    };
    builder.push_owned(clause, values);
    Ok(())
}

/// How much of one payload a content search will decompress and scan.
///
/// A chunk or registry packet can be megabytes; without a ceiling a single
/// pathological row would decide how long the whole query takes.
const CONTENT_SCAN_LIMIT: usize = 1 << 20;

/// One alternative of a payload search.
#[derive(Debug)]
enum ContentTerm {
    /// A literal byte needle.
    Bytes(Vec<u8>),
    /// An inclusive range over sequences of the same length, compared byte by
    /// byte. `0c-0f` selects the four one-byte payloads between them; `0100-01ff`
    /// selects every two-byte payload that starts with `01`.
    Range { start: Vec<u8>, end: Vec<u8> },
}

impl ContentTerm {
    fn matches(&self, haystack: &[u8], total: usize, scope: ContentScope, truncated: bool) -> bool {
        match self {
            Self::Bytes(needle) => {
                if needle.is_empty() {
                    return true;
                }
                match scope {
                    ContentScope::Contains => contains(haystack, needle),
                    // Comparing the recorded size first settles almost every row
                    // without touching the bytes, and makes truncation moot: a
                    // payload that equals the needle is needle-sized.
                    ContentScope::Equals => total == needle.len() && haystack == needle.as_slice(),
                    ContentScope::Prefix => haystack.starts_with(needle),
                    ContentScope::Suffix => !truncated && haystack.ends_with(needle),
                }
            }
            Self::Range { start, end } => {
                let width = start.len();
                if width == 0 {
                    return false;
                }
                let within = |slice: &[u8]| slice >= start.as_slice() && slice <= end.as_slice();
                match scope {
                    ContentScope::Contains => haystack.windows(width).any(within),
                    ContentScope::Equals => total == width && within(haystack),
                    ContentScope::Prefix => haystack.len() >= width && within(&haystack[..width]),
                    ContentScope::Suffix => {
                        !truncated
                            && haystack.len() >= width
                            && within(&haystack[haystack.len() - width..])
                    }
                }
            }
        }
    }
}

/// A payload search compiled once, then reused for every row.
///
/// Every variant holds a list, because a search is a set of alternatives: a row
/// matches when any one of them does. That is what makes "hide these four
/// frames" one query instead of four.
#[derive(Debug)]
enum ContentMatcher {
    /// Literal terms. `fold_case` lowercases ASCII on both sides, which is what
    /// makes a text search behave the way the metadata search does.
    Terms {
        terms: Vec<ContentTerm>,
        fold_case: bool,
        scope: ContentScope,
    },
    /// The scope is compiled into each pattern as anchors. `needs_tail` records
    /// whether it anchored the end, which decides whether a payload the scan
    /// truncated can be judged at all.
    Regex {
        patterns: Vec<Regex>,
        needs_tail: bool,
    },
}

impl ContentMatcher {
    fn compile(query: &ContentQuery) -> Result<Self, ProjectError> {
        let lines = query
            .text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        match query.mode {
            ContentMode::Regex => {
                // The operator's pattern goes inside a non-capturing group so an
                // alternation at the top level cannot escape the anchors.
                let patterns = lines
                    .map(|line| {
                        let anchored = match query.scope {
                            ContentScope::Contains => line.to_owned(),
                            ContentScope::Equals => format!("^(?:{line})$"),
                            ContentScope::Prefix => format!("^(?:{line})"),
                            ContentScope::Suffix => format!("(?:{line})$"),
                        };
                        let pattern = if query.case_sensitive {
                            anchored
                        } else {
                            format!("(?i){anchored}")
                        };
                        Regex::new(&pattern)
                            .map_err(|error| ProjectError::InvalidSearch(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Regex {
                    patterns,
                    needs_tail: matches!(query.scope, ContentScope::Equals | ContentScope::Suffix),
                })
            }
            ContentMode::Text => Ok(Self::Terms {
                terms: lines
                    .map(|line| {
                        ContentTerm::Bytes(if query.case_sensitive {
                            line.as_bytes().to_vec()
                        } else {
                            line.to_lowercase().into_bytes()
                        })
                    })
                    .collect(),
                fold_case: !query.case_sensitive,
                scope: query.scope,
            }),
            ContentMode::Hex => Ok(Self::Terms {
                terms: lines.map(parse_hex_term).collect::<Result<Vec<_>, _>>()?,
                fold_case: false,
                scope: query.scope,
            }),
        }
    }

    /// Matches one payload. `total` is the packet's recorded size, which is
    /// larger than `payload` when the scan hit [`CONTENT_SCAN_LIMIT`]; a scope
    /// that depends on the end of the payload cannot be decided in that case and
    /// reports no match rather than judging a prefix as if it were the whole.
    fn matches(&self, payload: &[u8], total: usize) -> bool {
        let truncated = payload.len() < total;
        match self {
            Self::Terms {
                terms,
                fold_case,
                scope,
            } => {
                let folded;
                let haystack: &[u8] = if *fold_case {
                    folded = payload.to_ascii_lowercase();
                    &folded
                } else {
                    payload
                };
                terms
                    .iter()
                    .any(|term| term.matches(haystack, total, *scope, truncated))
            }
            // A payload is rarely valid UTF-8 end to end; a lossy view lets a
            // pattern match the printable runs without discarding the packet.
            Self::Regex {
                patterns,
                needs_tail,
            } => {
                if *needs_tail && truncated {
                    return false;
                }
                let text = String::from_utf8_lossy(payload);
                patterns.iter().any(|pattern| pattern.is_match(&text))
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Reads one hex term: a byte sequence, or `start-end` for an inclusive range.
///
/// A dash is unambiguous here — [`parse_hex`] treats every other separator as
/// noise and a dash has never been one of them — so the range syntax cannot
/// change what an existing search means.
fn parse_hex_term(line: &str) -> Result<ContentTerm, ProjectError> {
    let Some((start, end)) = line.split_once('-') else {
        return Ok(ContentTerm::Bytes(parse_hex(line)?));
    };
    if end.contains('-') {
        return Err(ProjectError::InvalidSearch(
            "a hex range is written as start-end".into(),
        ));
    }
    let start = parse_hex(start)?;
    let end = parse_hex(end)?;
    if start.len() != end.len() || start.is_empty() {
        return Err(ProjectError::InvalidSearch(
            "both ends of a hex range must be the same number of bytes".into(),
        ));
    }
    if start > end {
        return Err(ProjectError::InvalidSearch(format!(
            "the start of a hex range must not be greater than its end (`{line}`)"
        )));
    }
    Ok(ContentTerm::Range { start, end })
}

/// Reads a byte sequence written as hex, ignoring whatever separates the pairs.
fn parse_hex(input: &str) -> Result<Vec<u8>, ProjectError> {
    let digits: String = input
        .chars()
        .filter(|character| !character.is_whitespace() && *character != ',' && *character != ':')
        .collect();
    let digits = digits.strip_prefix("0x").unwrap_or(&digits);
    if digits.is_empty() {
        return Ok(Vec::new());
    }
    if digits.len() % 2 != 0 {
        return Err(ProjectError::InvalidSearch(
            "hex search needs complete byte pairs".into(),
        ));
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).map_err(|_| {
                ProjectError::InvalidSearch(format!(
                    "`{}` is not a hex byte",
                    &digits[index..index + 2]
                ))
            })
        })
        .collect()
}

/// Decompresses at most [`CONTENT_SCAN_LIMIT`] bytes of a stored payload.
fn decode_bounded(blob: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut output = Vec::new();
    zstd::stream::Decoder::new(blob)?
        .take(CONTENT_SCAN_LIMIT as u64)
        .read_to_end(&mut output)?;
    Ok(output)
}

/// Translates a filter expression into parameterised SQL.
///
/// The in-memory evaluator in `mineburp-core` is the specification: an absent
/// optional field never matches, including under `!=`, and text comparisons are
/// case-insensitive. Both rules are reproduced here so the same expression
/// selects the same packets whether it runs against a live stream or the
/// project.
fn compile_expression(expression: &FilterExpression) -> Result<(String, Vec<Value>), ProjectError> {
    match expression {
        FilterExpression::MatchAll => Ok(("1".into(), Vec::new())),
        FilterExpression::Not { expression } => {
            let (sql, values) = compile_expression(expression)?;
            Ok((format!("NOT ({sql})"), values))
        }
        FilterExpression::And { expressions } => compile_group(expressions, "AND"),
        FilterExpression::Or { expressions } => compile_group(expressions, "OR"),
        FilterExpression::Predicate {
            field,
            comparison,
            value,
        } => compile_predicate(*field, *comparison, value),
    }
}

fn compile_group(
    expressions: &[FilterExpression],
    joiner: &str,
) -> Result<(String, Vec<Value>), ProjectError> {
    if expressions.is_empty() {
        // An empty AND matches everything; an empty OR matches nothing. Both
        // follow the iterator semantics the in-memory evaluator uses.
        return Ok((if joiner == "AND" { "1" } else { "0" }.into(), Vec::new()));
    }
    let mut parts = Vec::with_capacity(expressions.len());
    let mut values = Vec::new();
    for expression in expressions {
        let (sql, bound) = compile_expression(expression)?;
        parts.push(sql);
        values.extend(bound);
    }
    Ok((format!("({})", parts.join(&format!(" {joiner} "))), values))
}

fn compile_predicate(
    field: FilterField,
    comparison: Comparison,
    value: &FilterValue,
) -> Result<(String, Vec<Value>), ProjectError> {
    let column = match field {
        FilterField::Source => "source",
        FilterField::Direction => "direction",
        FilterField::State => "state",
        FilterField::Protocol => "protocol_version",
        FilterField::PacketId => "packet_id",
        FilterField::Name => "name",
        FilterField::Channel => "channel",
        FilterField::Loader => "loader",
        FilterField::Size => "size",
        FilterField::Disposition => "disposition",
        FilterField::Connection => "connection_id",
    };

    let sql = if field.is_numeric() {
        let FilterValue::Integer(number) = value else {
            return Err(ProjectError::InvalidFilter(format!(
                "`{column}` requires an integer value"
            )));
        };
        let operator = match comparison {
            Comparison::Equal => "=",
            Comparison::NotEqual => "<>",
            Comparison::Greater => ">",
            Comparison::GreaterOrEqual => ">=",
            Comparison::Less => "<",
            Comparison::LessOrEqual => "<=",
            // `contains` on a number is a digit match in the evaluator.
            Comparison::Contains => {
                return Ok((
                    format!("(CAST({column} AS TEXT) LIKE ? ESCAPE '\\')"),
                    vec![Value::from(format!(
                        "%{}%",
                        escape_like(&number.to_string())
                    ))],
                ));
            }
        };
        return Ok((
            format!("({column} IS NOT NULL AND {column} {operator} ?)"),
            vec![Value::from(*number)],
        ));
    } else {
        let FilterValue::String(text) = value else {
            return Err(ProjectError::InvalidFilter(format!(
                "`{column}` requires a text value"
            )));
        };
        // Enum columns are stored as JSON, so an equality test compares against
        // the quoted form while a substring test does not.
        let stored = |text: &str| {
            if field.is_enumerated() {
                format!("\"{text}\"")
            } else {
                text.to_owned()
            }
        };
        let guard = if field.is_optional() {
            format!("{column} IS NOT NULL AND ")
        } else {
            String::new()
        };
        match comparison {
            Comparison::Equal => (
                format!("({guard}LOWER({column}) = LOWER(?))"),
                vec![Value::from(stored(text))],
            ),
            Comparison::NotEqual => (
                format!("({guard}LOWER({column}) <> LOWER(?))"),
                vec![Value::from(stored(text))],
            ),
            Comparison::Contains => (
                format!("({guard}LOWER({column}) LIKE LOWER(?) ESCAPE '\\')"),
                vec![Value::from(format!("%{}%", escape_like(text)))],
            ),
            Comparison::Greater
            | Comparison::GreaterOrEqual
            | Comparison::Less
            | Comparison::LessOrEqual => {
                // Ordering comparisons are meaningless on text, and the
                // evaluator returns false rather than guessing.
                ("0".to_owned(), Vec::new())
            }
        }
    };
    Ok(sql)
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn meta_value(connection: &Connection, key: &str) -> Result<Option<String>, ProjectError> {
    connection
        .query_row(
            "SELECT value FROM project_meta WHERE key=?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(ProjectError::from)
}

fn enum_json<T: Serialize>(value: &T) -> Result<String, ProjectError> {
    serde_json::to_string(value).map_err(|error| ProjectError::Corrupt(error.to_string()))
}

fn optional_json<T: Serialize>(value: Option<&T>) -> Result<Option<String>, ProjectError> {
    value
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| ProjectError::Corrupt(error.to_string()))
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn row_usize(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<usize> {
    let value = row.get::<_, i64>(index)?;
    usize::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn parse_json<T: for<'de> Deserialize<'de>>(value: &str) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_optional_json<T: for<'de> Deserialize<'de>>(
    value: Option<&str>,
) -> rusqlite::Result<Option<T>> {
    value.map(parse_json).transpose()
}

fn parse_uuid(value: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mineburp_core::{
        ConnectionStatus, Direction, Disposition, InterceptDecision, InterceptRule, PacketDetail,
        PacketSummary, ProtocolState, RepeaterTab, Target, TrafficSource, WireMetadata,
    };
    use mineburp_protocol::{SchemaPack, SchemaPackManifest};
    use tempfile::tempdir;

    use super::*;

    fn snapshot(id: Uuid) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id,
            target: Target {
                host: "localhost".into(),
                port: 25_565,
            },
            listener_address: "127.0.0.1:30000".into(),
            status: ConnectionStatus::Active,
            state: ProtocolState::Play,
            protocol_version: Some(767),
            minecraft_version: Some("1.21.1".into()),
            loader: Some("fabric".into()),
            compression_threshold: Some(256),
            encrypted_client: true,
            encrypted_server: true,
            packet_count: 1,
            byte_count: 4,
            last_error: None,
        }
    }

    /// A small corpus spanning every filterable column.
    fn corpus() -> Vec<PacketSummary> {
        let connection = Uuid::from_u128(7);
        let base = PacketSummary {
            id: 0,
            sequence: 0,
            connection_id: connection,
            timestamp_micros: 0,
            source: TrafficSource::Minecraft,
            direction: Direction::ClientToServer,
            state: ProtocolState::Play,
            protocol_version: Some(767),
            packet_id: Some(1),
            name: None,
            channel: None,
            loader: None,
            size: 10,
            disposition: Disposition::Forwarded,
            flow: None,
        };
        vec![
            PacketSummary {
                sequence: 1,
                name: Some("keep_alive".into()),
                size: 8,
                ..base.clone()
            },
            PacketSummary {
                sequence: 2,
                direction: Direction::ServerToClient,
                state: ProtocolState::Login,
                name: Some("encryption_request".into()),
                packet_id: Some(1),
                size: 260,
                disposition: Disposition::Edited,
                ..base.clone()
            },
            PacketSummary {
                sequence: 3,
                name: Some("custom_payload".into()),
                channel: Some("fabric:registry/sync".into()),
                loader: Some("fabric".into()),
                size: 4_096,
                ..base.clone()
            },
            PacketSummary {
                sequence: 4,
                source: TrafficSource::SideChannel,
                state: ProtocolState::Opaque,
                name: Some("TCP payload".into()),
                packet_id: None,
                protocol_version: None,
                size: 1_400,
                disposition: Disposition::Observed,
                ..base.clone()
            },
            PacketSummary {
                sequence: 5,
                direction: Direction::ServerToClient,
                name: Some("KEEP_ALIVE_RESPONSE".into()),
                size: 9,
                disposition: Disposition::Dropped,
                ..base
            },
        ]
    }

    /// Payload bytes for each corpus row, indexed by sequence - 1.
    fn payloads() -> Vec<Vec<u8>> {
        vec![
            b"\x00\x01keep alive token".to_vec(),
            b"\xde\xad\xbe\xefencrypted blob".to_vec(),
            b"fabric:registry/sync\x00PAYLOAD".to_vec(),
            b"\x17\x03\x03 opaque transport bytes".to_vec(),
            b"Hello WORLD from the server".to_vec(),
        ]
    }

    fn seeded_store(directory: &tempfile::TempDir) -> (ProjectStore, Vec<PacketSummary>) {
        let store = ProjectStore::create(
            directory.path().join("filter.mineburp"),
            "Filters",
            ProjectOptions::default(),
        )
        .unwrap();
        let summaries = corpus();
        store
            .save_connection(&snapshot(summaries[0].connection_id))
            .unwrap();
        let details = summaries
            .iter()
            .zip(payloads())
            .map(|(summary, payload)| PacketDetail {
                summary: summary.clone(),
                logical_bytes: Bytes::from(payload),
                decoded: None,
                decode_error: None,
                wire: WireMetadata::default(),
            })
            .collect::<Vec<_>>();
        store.insert_packets(&details).unwrap();
        (store, summaries)
    }

    fn sequences(rows: &[PacketSummary]) -> Vec<u64> {
        let mut found = rows.iter().map(|row| row.sequence).collect::<Vec<_>>();
        found.sort_unstable();
        found
    }

    fn run(store: &ProjectStore, query: PacketQuery) -> Vec<u64> {
        sequences(
            &store
                .query_packets_filtered(&PacketQuery { limit: 50, ..query })
                .unwrap(),
        )
    }

    #[test]
    fn selects_by_enum_sets_and_size_bounds() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);

        assert_eq!(
            run(
                &store,
                PacketQuery {
                    directions: vec![Direction::ServerToClient],
                    ..PacketQuery::default()
                }
            ),
            vec![2, 5]
        );
        // An enum set is a disjunction, not a second AND.
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    states: vec![ProtocolState::Login, ProtocolState::Opaque],
                    ..PacketQuery::default()
                }
            ),
            vec![2, 4]
        );
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    dispositions: vec![Disposition::Dropped, Disposition::Edited],
                    ..PacketQuery::default()
                }
            ),
            vec![2, 5]
        );
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    sources: vec![TrafficSource::SideChannel],
                    ..PacketQuery::default()
                }
            ),
            vec![4]
        );
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    min_size: Some(9),
                    max_size: Some(1_400),
                    ..PacketQuery::default()
                }
            ),
            vec![2, 4, 5]
        );
        // An untouched filter must not narrow anything.
        assert_eq!(run(&store, PacketQuery::default()), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn searches_with_case_regex_and_negation() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        let search = |term: SearchTerm| {
            run(
                &store,
                PacketQuery {
                    search: Some(term),
                    ..PacketQuery::default()
                },
            )
        };

        assert_eq!(
            search(SearchTerm {
                text: "keep_alive".into(),
                ..SearchTerm::default()
            }),
            vec![1, 5],
            "a plain search ignores case by default"
        );
        assert_eq!(
            search(SearchTerm {
                text: "keep_alive".into(),
                case_sensitive: true,
                ..SearchTerm::default()
            }),
            vec![1]
        );
        assert_eq!(
            search(SearchTerm {
                text: "^keep_alive$".into(),
                regex: true,
                ..SearchTerm::default()
            }),
            vec![1],
            "an anchored pattern excludes the longer name"
        );
        assert_eq!(
            search(SearchTerm {
                text: "keep_alive".into(),
                negate: true,
                ..SearchTerm::default()
            }),
            vec![2, 3, 4],
            "negation keeps rows whose searchable columns are all NULL"
        );
        // The search spans the columns the table shows, not just the name.
        assert_eq!(
            search(SearchTerm {
                text: "fabric".into(),
                ..SearchTerm::default()
            }),
            vec![3]
        );
    }

    #[test]
    fn rejects_an_unparseable_regular_expression() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        let error = store
            .query_packets_filtered(&PacketQuery {
                limit: 10,
                search: Some(SearchTerm {
                    text: "keep_alive(".into(),
                    regex: true,
                    ..SearchTerm::default()
                }),
                ..PacketQuery::default()
            })
            .expect_err("an unfinished group must be reported");
        assert!(
            matches!(error, ProjectError::InvalidSearch(_)),
            "expected a search error, got {error:?}"
        );
    }

    #[test]
    fn include_and_exclude_name_lists_compose() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    include_names: vec!["keep_alive".into(), "custom".into()],
                    ..PacketQuery::default()
                }
            ),
            vec![1, 3, 5]
        );
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    include_names: vec!["keep_alive".into(), "custom".into()],
                    exclude_names: vec!["response".into()],
                    ..PacketQuery::default()
                }
            ),
            vec![1, 3]
        );
    }

    #[test]
    fn searches_inside_payload_bytes() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        let content = |query: ContentQuery| {
            run(
                &store,
                PacketQuery {
                    content: Some(query),
                    ..PacketQuery::default()
                },
            )
        };

        assert_eq!(
            content(ContentQuery {
                text: "keep alive".into(),
                ..ContentQuery::default()
            }),
            vec![1],
            "a text search reads the payload, not the row's name"
        );
        assert_eq!(
            content(ContentQuery {
                text: "hello world".into(),
                ..ContentQuery::default()
            }),
            vec![5],
            "text search folds case by default"
        );
        assert_eq!(
            content(ContentQuery {
                text: "hello world".into(),
                case_sensitive: true,
                ..ContentQuery::default()
            }),
            Vec::<u64>::new()
        );
        assert_eq!(
            content(ContentQuery {
                text: "Hello WORLD".into(),
                case_sensitive: true,
                ..ContentQuery::default()
            }),
            vec![5]
        );
    }

    #[test]
    fn searches_payloads_by_hex_and_regular_expression() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        let content = |query: ContentQuery| {
            run(
                &store,
                PacketQuery {
                    content: Some(query),
                    ..PacketQuery::default()
                },
            )
        };

        assert_eq!(
            content(ContentQuery {
                text: "de ad be ef".into(),
                mode: ContentMode::Hex,
                ..ContentQuery::default()
            }),
            vec![2],
            "separators inside a hex needle are ignored"
        );
        assert_eq!(
            content(ContentQuery {
                text: "0xdeadbeef".into(),
                mode: ContentMode::Hex,
                ..ContentQuery::default()
            }),
            vec![2]
        );
        // Binary bytes that are not valid UTF-8 must still be findable.
        assert_eq!(
            content(ContentQuery {
                text: "170303".into(),
                mode: ContentMode::Hex,
                ..ContentQuery::default()
            }),
            vec![4]
        );
        assert_eq!(
            content(ContentQuery {
                text: r"registry/\w+".into(),
                mode: ContentMode::Regex,
                ..ContentQuery::default()
            }),
            vec![3],
            "a regex reads the printable runs of a mostly binary payload"
        );
        // A scope anchors the pattern, so a regex can describe the whole payload
        // rather than any run inside it.
        assert_eq!(
            content(ContentQuery {
                text: "hello.*server".into(),
                mode: ContentMode::Regex,
                scope: ContentScope::Equals,
                ..ContentQuery::default()
            }),
            vec![5]
        );
        assert_eq!(
            content(ContentQuery {
                text: "WORLD".into(),
                mode: ContentMode::Regex,
                scope: ContentScope::Equals,
                ..ContentQuery::default()
            }),
            Vec::<u64>::new(),
            "a fragment of the payload is not the payload"
        );
    }

    /// The scope is what makes "every packet that *is* this" expressible: with
    /// `Contains` alone, excluding one-byte keep-alive-shaped frames also
    /// excluded every larger packet that happens to carry the same byte.
    #[test]
    fn payload_scope_separates_being_a_sequence_from_containing_it() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("scopes.mineburp"),
            "Scopes",
            ProjectOptions::default(),
        )
        .unwrap();
        let base = corpus()[0].clone();
        store
            .save_connection(&snapshot(base.connection_id))
            .unwrap();
        let payloads: Vec<Vec<u8>> = vec![
            vec![0x0c],
            vec![0x0c, 0x00, 0xff],
            vec![0xff, 0x00, 0x0c],
            vec![0x0c],
        ];
        let details = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| PacketDetail {
                summary: PacketSummary {
                    sequence: u64::try_from(index).unwrap() + 1,
                    size: payload.len(),
                    ..base.clone()
                },
                logical_bytes: Bytes::from(payload.clone()),
                decoded: None,
                decode_error: None,
                wire: WireMetadata::default(),
            })
            .collect::<Vec<_>>();
        store.insert_packets(&details).unwrap();

        let scoped = |scope: ContentScope, negate: bool| {
            run(
                &store,
                PacketQuery {
                    content: Some(ContentQuery {
                        text: "0c".into(),
                        mode: ContentMode::Hex,
                        scope,
                        negate,
                        ..ContentQuery::default()
                    }),
                    ..PacketQuery::default()
                },
            )
        };

        assert_eq!(scoped(ContentScope::Contains, false), vec![1, 2, 3, 4]);
        assert_eq!(scoped(ContentScope::Equals, false), vec![1, 4]);
        assert_eq!(
            scoped(ContentScope::Equals, true),
            vec![2, 3],
            "excluding the packets that are exactly 0x0c must keep the ones that merely carry it"
        );
        assert_eq!(scoped(ContentScope::Prefix, false), vec![1, 2, 4]);
        assert_eq!(scoped(ContentScope::Suffix, false), vec![1, 3, 4]);
    }

    /// A term list and a range are what turn "hide this frame" into "hide these
    /// frames": one query per rule the operator has in mind, not one per byte.
    #[test]
    fn payload_terms_list_alternatives_and_hex_ranges() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("terms.mineburp"),
            "Terms",
            ProjectOptions::default(),
        )
        .unwrap();
        let base = corpus()[0].clone();
        store
            .save_connection(&snapshot(base.connection_id))
            .unwrap();
        // Sequences 1..=5 are the one-byte frames 0x0b..=0x0f; 6 is longer.
        let payloads: Vec<Vec<u8>> = vec![
            vec![0x0b],
            vec![0x0c],
            vec![0x0d],
            vec![0x0e],
            vec![0x0f],
            vec![0x0c, 0x2a, 0x0f],
        ];
        let details = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| PacketDetail {
                summary: PacketSummary {
                    sequence: u64::try_from(index).unwrap() + 1,
                    size: payload.len(),
                    ..base.clone()
                },
                logical_bytes: Bytes::from(payload.clone()),
                decoded: None,
                decode_error: None,
                wire: WireMetadata::default(),
            })
            .collect::<Vec<_>>();
        store.insert_packets(&details).unwrap();

        let hex = |text: &str, scope: ContentScope, negate: bool| {
            run(
                &store,
                PacketQuery {
                    content: Some(ContentQuery {
                        text: text.into(),
                        mode: ContentMode::Hex,
                        scope,
                        negate,
                        ..ContentQuery::default()
                    }),
                    ..PacketQuery::default()
                },
            )
        };

        assert_eq!(
            hex("0c\n0f", ContentScope::Equals, false),
            vec![2, 5],
            "a term per line is a set of alternatives"
        );
        assert_eq!(
            hex("0c\n0f", ContentScope::Equals, true),
            vec![1, 3, 4, 6],
            "negating the set hides exactly those frames and nothing else"
        );
        assert_eq!(
            hex("0c-0f", ContentScope::Equals, false),
            vec![2, 3, 4, 5],
            "a range covers both ends inclusively"
        );
        assert_eq!(
            hex("0c-0f", ContentScope::Equals, true),
            vec![1, 6],
            "the longer frame is not in the range even though its bytes are"
        );
        assert_eq!(
            hex("0c-0f", ContentScope::Contains, false),
            vec![2, 3, 4, 5, 6],
            "under contains, a range looks for any byte window inside it"
        );
        assert_eq!(
            hex("0b\n0d-0e", ContentScope::Equals, false),
            vec![1, 3, 4],
            "sequences and ranges mix in one search"
        );
        // A multi-byte range compares the sequences byte by byte.
        assert_eq!(hex("0c000f-0cff0f", ContentScope::Equals, false), vec![6]);

        let attempt = |text: &str| {
            store.query_packets_filtered(&PacketQuery {
                limit: 10,
                content: Some(ContentQuery {
                    text: text.into(),
                    mode: ContentMode::Hex,
                    ..ContentQuery::default()
                }),
                ..PacketQuery::default()
            })
        };
        for malformed in ["0f-0c", "0c-0f0f", "0c-0d-0e"] {
            assert!(
                matches!(attempt(malformed), Err(ProjectError::InvalidSearch(_))),
                "`{malformed}` must be reported rather than quietly matching nothing"
            );
        }
    }

    #[test]
    fn payload_search_negates_and_composes_with_cheap_filters() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    content: Some(ContentQuery {
                        text: "PAYLOAD".into(),
                        negate: true,
                        case_sensitive: true,
                        ..ContentQuery::default()
                    }),
                    ..PacketQuery::default()
                }
            ),
            vec![1, 2, 4, 5]
        );
        // The metadata filters still narrow first; content only decides the rest.
        assert_eq!(
            run(
                &store,
                PacketQuery {
                    directions: vec![Direction::ServerToClient],
                    content: Some(ContentQuery {
                        text: "server".into(),
                        ..ContentQuery::default()
                    }),
                    ..PacketQuery::default()
                }
            ),
            vec![5]
        );
    }

    #[test]
    fn rejects_malformed_hex_and_regex_payload_searches() {
        let directory = tempdir().unwrap();
        let (store, _) = seeded_store(&directory);
        let attempt = |query: ContentQuery| {
            store.query_packets_filtered(&PacketQuery {
                limit: 10,
                content: Some(query),
                ..PacketQuery::default()
            })
        };

        let odd = attempt(ContentQuery {
            text: "abc".into(),
            mode: ContentMode::Hex,
            ..ContentQuery::default()
        })
        .expect_err("an odd digit count is not a byte sequence");
        assert!(matches!(odd, ProjectError::InvalidSearch(_)), "got {odd:?}");

        let bad_digit = attempt(ContentQuery {
            text: "zz".into(),
            mode: ContentMode::Hex,
            ..ContentQuery::default()
        })
        .expect_err("non-hex digits must be rejected");
        assert!(matches!(bad_digit, ProjectError::InvalidSearch(_)));

        let bad_regex = attempt(ContentQuery {
            text: "chat(".into(),
            mode: ContentMode::Regex,
            ..ContentQuery::default()
        })
        .expect_err("an unfinished group must be rejected");
        assert!(matches!(bad_regex, ProjectError::InvalidSearch(_)));
    }

    /// The whole point of compiling expressions to SQL: the same expression must
    /// select the same packets in the database as it does in memory, where the
    /// proxy evaluates it against live traffic.
    #[test]
    fn expressions_select_the_same_packets_as_the_in_memory_evaluator() {
        let directory = tempdir().unwrap();
        let (store, summaries) = seeded_store(&directory);
        let expressions = [
            "*",
            "direction == client_to_server",
            "direction != client_to_server",
            "state == login || state == opaque",
            "size > 1000",
            "size <= 9",
            "name ~ keep",
            "name == keep_alive",
            "name != keep_alive",
            "channel ~ fabric",
            "loader == fabric",
            "id == 1",
            "id != 1",
            "protocol >= 767",
            "disposition == dropped",
            "source == side_channel",
            "direction == client_to_server && size < 100",
            "loader == fabric || disposition == edited",
            "state == play && name ~ alive && direction == server_to_client",
        ];
        for text in expressions {
            let expression = FilterExpression::parse(text).expect(text);
            let in_memory = sequences(
                &summaries
                    .iter()
                    .filter(|summary| expression.matches(summary))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let in_sql = run(
                &store,
                PacketQuery {
                    expression: Some(expression),
                    ..PacketQuery::default()
                },
            );
            assert_eq!(
                in_sql, in_memory,
                "`{text}` disagreed between SQL and memory"
            );
        }
    }

    #[test]
    fn lists_every_connection_busiest_first() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("connections.mineburp");
        let store = ProjectStore::create(&path, "Test", ProjectOptions::default()).unwrap();
        let quiet = Uuid::new_v4();
        let busy = Uuid::new_v4();
        store.save_connection(&snapshot(quiet)).unwrap();
        let mut heavy = snapshot(busy);
        heavy.packet_count = 900;
        heavy.state = ProtocolState::Opaque;
        store.save_connection(&heavy).unwrap();

        let listed = store.list_connections(10).unwrap();
        assert_eq!(
            listed.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![busy, quiet]
        );
        assert_eq!(listed[0].packet_count, 900);
        assert_eq!(listed[0].state, ProtocolState::Opaque);
        assert_eq!(listed[0].target.port, 25_565);
        assert_eq!(store.list_connections(1).unwrap().len(), 1);
    }

    #[test]
    fn replacement_rules_round_trip() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("rules.mineburp"),
            "Rules",
            ProjectOptions::default(),
        )
        .unwrap();
        let rule = ReplacementRule {
            id: Uuid::new_v4(),
            name: "Blank the brand".into(),
            enabled: true,
            expression: "name == custom_payload".into(),
            edits: vec![mineburp_core::PacketEdit::Field {
                name: "channel".into(),
                value: "minecraft:brand".into(),
            }],
        };
        store
            .save_replacement_rules(std::slice::from_ref(&rule))
            .unwrap();
        assert_eq!(store.load_replacement_rules().unwrap(), vec![rule]);
        store.save_replacement_rules(&[]).unwrap();
        assert!(
            store.load_replacement_rules().unwrap().is_empty(),
            "saving an empty set clears the rules rather than merging"
        );
    }

    #[test]
    fn packet_round_trip_plain_project() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("test.mineburp");
        let store = ProjectStore::create(&path, "Test", ProjectOptions::default()).unwrap();
        let id = Uuid::new_v4();
        store.save_connection(&snapshot(id)).unwrap();
        let detail = PacketDetail {
            summary: PacketSummary {
                id: 0,
                sequence: 1,
                connection_id: id,
                timestamp_micros: 42,
                source: TrafficSource::Minecraft,
                direction: Direction::ClientToServer,
                state: ProtocolState::Play,
                protocol_version: Some(767),
                packet_id: Some(0),
                name: Some("keep_alive".into()),
                channel: None,
                loader: None,
                size: 4,
                disposition: Disposition::Forwarded,
                flow: None,
            },
            logical_bytes: Bytes::from_static(&[0, 1, 2, 3]),
            decoded: None,
            decode_error: None,
            wire: WireMetadata::default(),
        };
        let packet_id = store.insert_packet(&detail).unwrap();
        let loaded = store.packet_detail(packet_id).unwrap().unwrap();
        assert_eq!(loaded.logical_bytes, detail.logical_bytes);
        assert_eq!(store.query_packets(None, 0, 10).unwrap().len(), 1);

        let mut non_matching = detail.clone();
        non_matching.summary.sequence = 2;
        non_matching.summary.direction = Direction::ServerToClient;
        non_matching.summary.state = ProtocolState::Login;
        non_matching.summary.name = Some("encryption_request".into());
        store.insert_packet(&non_matching).unwrap();
        let matching = store
            .query_packets_filtered(&PacketQuery {
                search: Some(SearchTerm {
                    text: "keep_alive".into(),
                    ..SearchTerm::default()
                }),
                directions: vec![Direction::ClientToServer],
                states: vec![ProtocolState::Play],
                sources: vec![TrafficSource::Minecraft],
                limit: 10,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].name.as_deref(), Some("keep_alive"));

        let tab = RepeaterTab {
            id: Uuid::new_v4(),
            name: "Probe".into(),
            connection_id: id,
            direction: Direction::ClientToServer,
            state: ProtocolState::Play,
            logical_bytes: Bytes::from_static(&[1, 2]),
            decoded: None,
        };
        store.save_repeater_tab(&tab).unwrap();
        assert_eq!(store.load_repeater_tabs().unwrap(), vec![tab]);

        let rule = InterceptRule {
            id: Uuid::new_v4(),
            name: "Hold plugin data".into(),
            enabled: true,
            expression: "channel contains fabric".into(),
            action: InterceptDecision::Hold,
        };
        store
            .save_intercept_rules(std::slice::from_ref(&rule))
            .unwrap();
        assert_eq!(store.load_intercept_rules().unwrap(), vec![rule]);

        let schema = SchemaPack {
            manifest: SchemaPackManifest {
                id: "test.pack".into(),
                name: "Test".into(),
                version: "1.0.0".into(),
                minecraft_versions: vec!["1.21.1".into()],
                loaders: vec!["fabric".into()],
            },
            schemas: Vec::new(),
        };
        store.save_schema_pack(&schema).unwrap();
        assert_eq!(store.load_schema_packs().unwrap(), vec![schema]);
    }

    fn packet(connection: Uuid, sequence: u64, payload: &[u8]) -> PacketDetail {
        PacketDetail {
            summary: PacketSummary {
                id: 0,
                sequence,
                connection_id: connection,
                timestamp_micros: i64::try_from(sequence).unwrap(),
                source: TrafficSource::SideChannel,
                direction: Direction::ClientToServer,
                state: ProtocolState::Opaque,
                protocol_version: None,
                packet_id: None,
                name: Some("TCP payload".into()),
                channel: None,
                loader: None,
                size: payload.len(),
                disposition: Disposition::Observed,
                flow: None,
            },
            logical_bytes: Bytes::copy_from_slice(payload),
            decoded: None,
            decode_error: None,
            wire: WireMetadata::default(),
        }
    }

    #[test]
    fn batched_insert_matches_individual_insert() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("batch.mineburp"),
            "Batch",
            ProjectOptions::default(),
        )
        .unwrap();
        let connection = Uuid::new_v4();
        store.save_connection(&snapshot(connection)).unwrap();

        let batch: Vec<PacketDetail> = (1..=64)
            .map(|index| packet(connection, index, &[u8::try_from(index % 251).unwrap(); 9]))
            .collect();
        let ids = store.insert_packets(&batch).unwrap();
        assert_eq!(ids.len(), 64);

        let stored = store.packet_detail(ids[10]).unwrap().unwrap();
        assert_eq!(stored.logical_bytes, batch[10].logical_bytes);
        assert_eq!(stored.summary.sequence, batch[10].summary.sequence);
        assert_eq!(store.query_packets(None, 0, 100).unwrap().len(), 64);
        assert!(store.insert_packets(&[]).unwrap().is_empty());
    }

    #[test]
    fn keyset_cursors_page_without_drifting() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("keyset.mineburp"),
            "Keyset",
            ProjectOptions::default(),
        )
        .unwrap();
        let connection = Uuid::new_v4();
        store.save_connection(&snapshot(connection)).unwrap();
        let ids = store
            .insert_packets(
                &(1..=10)
                    .map(|index| packet(connection, index, &[1, 2, 3]))
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        let newest = store
            .query_packets_filtered(&PacketQuery {
                limit: 3,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(newest[0].id, ids[9]);

        // Rows arriving after the first page must not shift the older page.
        store
            .insert_packets(&[packet(connection, 11, &[9])])
            .unwrap();
        let older = store
            .query_packets_filtered(&PacketQuery {
                before_id: Some(newest[2].id),
                limit: 3,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(
            older.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![ids[6], ids[5], ids[4]]
        );

        let tail = store
            .query_packets_filtered(&PacketQuery {
                after_id: Some(ids[9]),
                limit: 10,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].sequence, 11);
    }

    #[test]
    fn packet_windows_bound_large_payloads() {
        let directory = tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("window.mineburp"),
            "Window",
            ProjectOptions::default(),
        )
        .unwrap();
        let connection = Uuid::new_v4();
        store.save_connection(&snapshot(connection)).unwrap();
        let payload: Vec<u8> = (0..4_096)
            .map(|index| u8::try_from(index % 256).unwrap())
            .collect();
        let id = store
            .insert_packet(&packet(connection, 1, &payload))
            .unwrap();

        let head = store.packet_window(id, 0, 512).unwrap().unwrap();
        assert_eq!(head.total_bytes, 4_096);
        assert_eq!(head.bytes.len(), 512);
        assert_eq!(head.bytes[..4], payload[..4]);

        let middle = store.packet_window(id, 4_000, 512).unwrap().unwrap();
        assert_eq!(middle.offset, 4_000);
        assert_eq!(middle.bytes.len(), 96);

        // Offsets past the end are clamped rather than erroring.
        let past = store.packet_window(id, 99_999, 512).unwrap().unwrap();
        assert!(past.bytes.is_empty());
        assert_eq!(past.offset, 4_096);
        assert!(store.packet_window(id + 9_999, 0, 8).unwrap().is_none());
    }

    #[test]
    fn encrypted_project_rejects_wrong_passphrase() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("secure.mineburp");
        drop(
            ProjectStore::create(
                &path,
                "Secure",
                ProjectOptions {
                    passphrase: Some("correct horse".into()),
                    read_only: false,
                },
            )
            .unwrap(),
        );
        assert!(
            ProjectStore::open(
                &path,
                ProjectOptions {
                    passphrase: Some("wrong battery".into()),
                    read_only: false
                },
            )
            .is_err()
        );
    }
}
