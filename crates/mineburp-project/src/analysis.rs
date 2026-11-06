//! Analyst state kept alongside the capture: annotations, saved filters,
//! traffic statistics, and history maintenance.

use std::path::Path;

use bytes::Bytes;
use mineburp_core::{ConnectionSnapshot, Direction, PacketSummary, Target};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{
    PacketQuery, ProjectError, ProjectStore, SUMMARY_COLUMNS, compile_query, decode_payload,
    now_micros, parse_json, parse_uuid, row_u64, summary_from_row,
};

/// The longest note an annotation may carry.
const MAX_NOTE_BYTES: usize = 16 * 1024;
/// The most annotations one lookup returns — a screen of rows, many times over.
const MAX_ANNOTATION_LOOKUP: usize = 2_000;
const MAX_BUCKETS: usize = 2_000;

/// What the operator has marked on one packet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketAnnotation {
    pub packet_id: i64,
    pub bookmarked: bool,
    /// `#rrggbb`, or a lowercase colour token the UI defines (`red`, `amber`).
    pub color: Option<String>,
    pub note: Option<String>,
    pub updated_at_micros: i64,
}

/// A named history filter. The filter is stored exactly as the UI sent it, so
/// the UI owns its shape and a saved filter round-trips without loss.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedFilter {
    pub id: Uuid,
    pub name: String,
    pub filter: serde_json::Value,
    #[serde(default)]
    pub created_at_micros: i64,
    #[serde(default)]
    pub updated_at_micros: i64,
}

/// How [`ProjectStore::traffic_stats`] slices time and ranks names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StatsOptions {
    /// Bucket width; derived from `max_buckets` and the matched time span
    /// when unset.
    pub bucket_micros: Option<i64>,
    pub max_buckets: usize,
    /// How many names and connections each ranking lists.
    pub top: usize,
}

impl Default for StatsOptions {
    fn default() -> Self {
        Self {
            bucket_micros: None,
            max_buckets: 200,
            top: 20,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficBucket {
    pub start_micros: i64,
    pub client_to_server_packets: u64,
    pub client_to_server_bytes: u64,
    pub server_to_client_packets: u64,
    pub server_to_client_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NameStat {
    pub name: Option<String>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStat {
    pub connection_id: Uuid,
    pub packets: u64,
    pub bytes: u64,
}

/// Packets whose size is in `[min, max)`; `max` is `None` for the last bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeBucket {
    pub min: u64,
    pub max: Option<u64>,
    pub packets: u64,
}

/// A summary of everything a history filter matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub client_to_server_packets: u64,
    pub client_to_server_bytes: u64,
    pub server_to_client_packets: u64,
    pub server_to_client_bytes: u64,
    pub first_timestamp_micros: Option<i64>,
    pub last_timestamp_micros: Option<i64>,
    pub bucket_micros: i64,
    pub buckets: Vec<TrafficBucket>,
    pub top_by_count: Vec<NameStat>,
    pub top_by_bytes: Vec<NameStat>,
    pub top_connections: Vec<ConnectionStat>,
    pub size_histogram: Vec<SizeBucket>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSummary {
    pub packets: u64,
    pub connections: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactSummary {
    pub bytes_before: u64,
    pub bytes_after: u64,
}

/// Size histogram boundaries: powers of four from 16 bytes.
const SIZE_EDGES: [u64; 8] = [16, 64, 256, 1_024, 4_096, 16_384, 65_536, 262_144];

impl ProjectStore {
    /// Sets or clears one packet's annotation and returns what is stored now:
    /// `None` when the update cleared everything, which deletes the row.
    pub fn set_annotation(
        &self,
        packet_id: i64,
        bookmarked: bool,
        color: Option<String>,
        note: Option<String>,
    ) -> Result<Option<PacketAnnotation>, ProjectError> {
        self.ensure_writable()?;
        let color = color
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let note = note.filter(|value| !value.trim().is_empty());
        if let Some(color) = &color {
            validate_color(color)?;
        }
        if note
            .as_ref()
            .is_some_and(|note| note.len() > MAX_NOTE_BYTES)
        {
            return Err(ProjectError::InvalidAnnotation(format!(
                "a note is limited to {MAX_NOTE_BYTES} bytes"
            )));
        }
        let connection = self.connection.lock();
        let exists = connection
            .query_row("SELECT 1 FROM packets WHERE id = ?1", [packet_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if !exists {
            return Err(ProjectError::PacketNotFound(packet_id));
        }
        if !bookmarked && color.is_none() && note.is_none() {
            connection.execute(
                "DELETE FROM packet_annotations WHERE packet_id = ?1",
                [packet_id],
            )?;
            return Ok(None);
        }
        let annotation = PacketAnnotation {
            packet_id,
            bookmarked,
            color,
            note,
            updated_at_micros: now_micros(),
        };
        connection.execute(
            "INSERT INTO packet_annotations(packet_id, bookmarked, color, note, updated_at_micros)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(packet_id) DO UPDATE SET
               bookmarked = excluded.bookmarked, color = excluded.color,
               note = excluded.note, updated_at_micros = excluded.updated_at_micros",
            params![
                annotation.packet_id,
                annotation.bookmarked,
                annotation.color,
                annotation.note,
                annotation.updated_at_micros,
            ],
        )?;
        Ok(Some(annotation))
    }

    /// The annotations of whichever of `packet_ids` have one.
    pub fn annotations(&self, packet_ids: &[i64]) -> Result<Vec<PacketAnnotation>, ProjectError> {
        if packet_ids.is_empty() {
            return Ok(Vec::new());
        }
        if packet_ids.len() > MAX_ANNOTATION_LOOKUP {
            return Err(ProjectError::InvalidAnnotation(format!(
                "at most {MAX_ANNOTATION_LOOKUP} packets can be looked up at once"
            )));
        }
        let ids = serde_json::to_string(packet_ids)
            .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
        self.with_reader(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT packet_id, bookmarked, color, note, updated_at_micros
                 FROM packet_annotations
                 WHERE packet_id IN (SELECT value FROM json_each(?1))
                 ORDER BY packet_id",
            )?;
            let rows = statement.query_map([ids], annotation_from_row)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ProjectError::from)
        })
    }

    /// Every annotation in the project, newest first, up to `limit`.
    pub fn list_annotations(&self, limit: usize) -> Result<Vec<PacketAnnotation>, ProjectError> {
        self.with_reader(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT packet_id, bookmarked, color, note, updated_at_micros
                 FROM packet_annotations ORDER BY packet_id DESC LIMIT ?1",
            )?;
            let rows = statement.query_map(
                [i64::try_from(limit).unwrap_or(i64::MAX)],
                annotation_from_row,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ProjectError::from)
        })
    }

    /// Creates or replaces a saved filter, keyed by its id.
    pub fn save_filter(&self, filter: &SavedFilter) -> Result<SavedFilter, ProjectError> {
        self.ensure_writable()?;
        let name = filter.name.trim();
        if name.is_empty() || name.len() > 200 {
            return Err(ProjectError::InvalidFilter(
                "a saved filter needs a name of at most 200 bytes".into(),
            ));
        }
        let payload = serde_json::to_string(&filter.filter)
            .map_err(|error| ProjectError::Corrupt(error.to_string()))?;
        let now = now_micros();
        let connection = self.connection.lock();
        connection.execute(
            "INSERT INTO saved_filters(id, name, filter_json, created_at_micros, updated_at_micros)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, filter_json = excluded.filter_json,
               updated_at_micros = excluded.updated_at_micros",
            params![filter.id.to_string(), name, payload, now],
        )?;
        let created = connection.query_row(
            "SELECT created_at_micros FROM saved_filters WHERE id = ?1",
            [filter.id.to_string()],
            |row| row.get(0),
        )?;
        Ok(SavedFilter {
            id: filter.id,
            name: name.to_owned(),
            filter: filter.filter.clone(),
            created_at_micros: created,
            updated_at_micros: now,
        })
    }

    pub fn load_saved_filters(&self) -> Result<Vec<SavedFilter>, ProjectError> {
        self.with_reader(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT id, name, filter_json, created_at_micros, updated_at_micros
                 FROM saved_filters ORDER BY name COLLATE NOCASE, id",
            )?;
            let rows = statement.query_map([], |row| {
                let filter_text: String = row.get(2)?;
                Ok(SavedFilter {
                    id: parse_uuid(&row.get::<_, String>(0)?)?,
                    name: row.get(1)?,
                    filter: parse_json(&filter_text)?,
                    created_at_micros: row.get(3)?,
                    updated_at_micros: row.get(4)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ProjectError::from)
        })
    }

    pub fn delete_saved_filter(&self, id: Uuid) -> Result<bool, ProjectError> {
        self.ensure_writable()?;
        let removed = self
            .connection
            .lock()
            .execute("DELETE FROM saved_filters WHERE id = ?1", [id.to_string()])?;
        Ok(removed > 0)
    }

    /// Counts, bytes, a timeline, rankings, and a size histogram over every
    /// packet `query` matches. `limit` and `offset` are ignored; the cursors
    /// are honoured.
    pub fn traffic_stats(
        &self,
        query: &PacketQuery,
        options: StatsOptions,
    ) -> Result<TrafficStats, ProjectError> {
        let compiled = compile_query(query)?;
        self.with_reader(|source| {
            compiled.install(source)?;
            let mut connection = rusqlite::Connection::open("")?;
            connection.execute_batch("CREATE TABLE packets(timestamp_micros INTEGER, size INTEGER, direction TEXT, name TEXT, connection_id TEXT);")?;
            {
                let transaction = connection.transaction()?;
                let mut insert = transaction.prepare("INSERT INTO packets VALUES (?1,?2,?3,?4,?5)")?;
                let mut select = source.prepare(&format!("SELECT timestamp_micros,size,direction,name,connection_id FROM packets{}", compiled.where_clause))?;
                let mut rows = select.query(params_from_iter(compiled.values.iter()))?;
                while let Some(row) = rows.next()? {
                    insert.execute(rusqlite::params![row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, String>(4)?])?;
                }
                drop(insert);
                transaction.commit()?;
            }
            let connection = &connection;
            let where_clause = String::new();
            let values: Vec<rusqlite::types::Value> = Vec::new();
            let mut stats = TrafficStats::default();
            let (count, bytes, first, last): (i64, i64, Option<i64>, Option<i64>) = connection
                .query_row(
                    &format!(
                        "SELECT COUNT(*), COALESCE(SUM(size), 0), MIN(timestamp_micros),
                                MAX(timestamp_micros)
                         FROM packets{where_clause}"
                    ),
                    params_from_iter(values.iter()),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
            stats.total_packets = u64::try_from(count).unwrap_or(0);
            stats.total_bytes = u64::try_from(bytes).unwrap_or(0);
            stats.first_timestamp_micros = first;
            stats.last_timestamp_micros = last;
            let (Some(first), Some(last)) = (first, last) else {
                return Ok(stats);
            };
            let max_buckets = options.max_buckets.clamp(1, MAX_BUCKETS);
            let span = last.saturating_sub(first).saturating_add(1).max(1);
            let count = i64::try_from(max_buckets).unwrap_or(1);
            let minimum_width = ((span + count - 1) / count).max(1);
            stats.bucket_micros = options
                .bucket_micros
                .filter(|width| *width > 0)
                .map_or(minimum_width, |width| width.max(minimum_width));
            stats.buckets = time_buckets(
                connection,
                &where_clause,
                &values,
                first,
                stats.bucket_micros,
            )?;
            for bucket in &stats.buckets {
                stats.client_to_server_packets += bucket.client_to_server_packets;
                stats.client_to_server_bytes += bucket.client_to_server_bytes;
                stats.server_to_client_packets += bucket.server_to_client_packets;
                stats.server_to_client_bytes += bucket.server_to_client_bytes;
            }
            let top = i64::try_from(options.top.clamp(1, 200)).unwrap_or(20);
            stats.top_by_count = name_ranking(connection, &where_clause, &values, "2", top)?;
            stats.top_by_bytes = name_ranking(connection, &where_clause, &values, "3", top)?;
            stats.top_connections = connection_ranking(connection, &where_clause, &values, top)?;
            stats.size_histogram = size_histogram(connection, &where_clause, &values)?;
            Ok(stats)
        })
    }

    /// Deletes every packet `query` matches (`limit` and `offset` ignored),
    /// with their annotations. With `prune_connections`, connections left with
    /// no packets that are no longer active are removed too.
    pub fn delete_packets(
        &self,
        query: &PacketQuery,
        prune_connections: bool,
    ) -> Result<DeleteSummary, ProjectError> {
        self.ensure_writable()?;
        let compiled = compile_query(query)?;
        let maximum: i64 = self.connection.lock().query_row(
            "SELECT COALESCE(MAX(id), 0) FROM packets",
            [],
            |row| row.get(0),
        )?;
        let mut packets = 0;
        let mut start = 0_i64;
        while start < maximum {
            let end = start.saturating_add(4096).min(maximum);
            let connection = self.connection.lock();
            compiled.install(&connection)?;
            let conjunction = if compiled.where_clause.is_empty() {
                " WHERE "
            } else {
                " AND "
            };
            packets += connection.execute(
                &format!(
                    "DELETE FROM packets{}{conjunction}id > {start} AND id <= {end}",
                    compiled.where_clause
                ),
                params_from_iter(compiled.values.iter()),
            )?;
            drop(connection);
            start = end;
        }
        let connection = self.connection.lock();
        let connections = if prune_connections {
            connection.execute(
                "DELETE FROM connections
                 WHERE status <> '\"active\"'
                   AND NOT EXISTS (SELECT 1 FROM packets WHERE connection_id = connections.id)",
                [],
            )?
        } else {
            0
        };
        Ok(DeleteSummary {
            packets: packets as u64,
            connections: connections as u64,
        })
    }

    /// Returns the space deleted history occupied to the filesystem.
    pub fn compact(&self) -> Result<CompactSummary, ProjectError> {
        self.ensure_writable()?;
        let before = file_size(&self.info().path);
        self.compact_export()?;
        Ok(CompactSummary {
            bytes_before: before,
            bytes_after: file_size(&self.info().path),
        })
    }

    /// One connection's snapshot, if the project has it.
    pub fn connection(&self, id: Uuid) -> Result<Option<ConnectionSnapshot>, ProjectError> {
        self.with_reader(|connection| {
            connection
                .query_row(
                    "SELECT id, target_host, target_port, listener_address, status, state,
                            protocol_version, minecraft_version, loader, compression_threshold,
                            encrypted_client, encrypted_server, packet_count, byte_count, last_error
                     FROM connections WHERE id = ?1",
                    [id.to_string()],
                    |row| {
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
                    },
                )
                .optional()
                .map_err(ProjectError::from)
        })
    }

    /// Visits every packet `query` matches, oldest first, with its payload,
    /// a page at a time. `visit` returning an error stops the walk.
    pub fn for_each_packet(
        &self,
        query: &PacketQuery,
        page_size: usize,
        mut visit: impl FnMut(&PacketSummary, &Bytes) -> Result<(), String>,
    ) -> Result<u64, ProjectError> {
        let compiled = compile_query(&PacketQuery {
            after_id: None,
            before_id: None,
            ..query.clone()
        })?;
        let page_size = page_size.clamp(1, 1_000);
        let mut cursor = query.after_id.unwrap_or(i64::MIN);
        let mut visited = 0_u64;
        loop {
            let mut where_clause = if compiled.where_clause.is_empty() {
                " WHERE id > ?".to_owned()
            } else {
                format!("{} AND id > ?", compiled.where_clause)
            };
            if query.before_id.is_some() {
                where_clause.push_str(" AND id < ?");
            }
            let sql = format!(
                "SELECT {SUMMARY_COLUMNS}, logical_bytes_zstd
                 FROM packets{where_clause} ORDER BY id ASC LIMIT ?"
            );
            let page = self.with_reader(|connection| {
                compiled.install(connection)?;
                let mut values = compiled.values.clone();
                values.push(Value::from(cursor));
                if let Some(before) = query.before_id {
                    values.push(Value::from(before));
                }
                values.push(Value::from(i64::try_from(page_size).unwrap_or(500)));
                let mut statement = connection.prepare(&sql)?;
                let rows = statement.query_map(params_from_iter(values), |row| {
                    Ok((summary_from_row(row)?, row.get::<_, Vec<u8>>(15)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(ProjectError::from)
            })?;
            let Some(last) = page.last().map(|(summary, _)| summary.id) else {
                return Ok(visited);
            };
            for (summary, compressed) in &page {
                let payload = Bytes::from(decode_payload(compressed, summary.size)?);
                visit(summary, &payload).map_err(ProjectError::Interrupted)?;
                visited += 1;
            }
            if page.len() < page_size {
                return Ok(visited);
            }
            cursor = last;
        }
    }
}

fn annotation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PacketAnnotation> {
    Ok(PacketAnnotation {
        packet_id: row.get(0)?,
        bookmarked: row.get(1)?,
        color: row.get(2)?,
        note: row.get(3)?,
        updated_at_micros: row.get(4)?,
    })
}

fn validate_color(color: &str) -> Result<(), ProjectError> {
    let hex = color
        .strip_prefix('#')
        .is_some_and(|digits| digits.len() == 6 && digits.chars().all(|c| c.is_ascii_hexdigit()));
    let token = (1..=32).contains(&color.len())
        && color.starts_with(|c: char| c.is_ascii_lowercase())
        && color
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if hex || token {
        Ok(())
    } else {
        Err(ProjectError::InvalidAnnotation(format!(
            "`{color}` is not a colour; use #rrggbb or a lowercase colour name"
        )))
    }
}

fn time_buckets(
    connection: &Connection,
    where_clause: &str,
    values: &[Value],
    first: i64,
    width: i64,
) -> Result<Vec<TrafficBucket>, ProjectError> {
    let mut bound = vec![Value::from(first), Value::from(width)];
    bound.extend(values.iter().cloned());
    let mut statement = connection.prepare(&format!(
        "SELECT (timestamp_micros - ?) / ? AS bucket, direction, COUNT(*), COALESCE(SUM(size), 0)
         FROM packets{where_clause} GROUP BY bucket, direction ORDER BY bucket"
    ))?;
    let rows = statement.query_map(params_from_iter(bound), |row| {
        let direction: String = row.get(1)?;
        Ok((
            row.get::<_, i64>(0)?,
            parse_json::<Direction>(&direction)?,
            row_u64(row, 2)?,
            row_u64(row, 3)?,
        ))
    })?;
    let mut buckets: Vec<TrafficBucket> = Vec::new();
    for row in rows {
        let (index, direction, packets, bytes) = row?;
        let start = first.saturating_add(index.saturating_mul(width));
        if buckets
            .last()
            .is_none_or(|bucket| bucket.start_micros != start)
        {
            buckets.push(TrafficBucket {
                start_micros: start,
                ..TrafficBucket::default()
            });
        }
        let bucket = buckets.last_mut().expect("a bucket was just pushed");
        match direction {
            Direction::ClientToServer => {
                bucket.client_to_server_packets += packets;
                bucket.client_to_server_bytes += bytes;
            }
            Direction::ServerToClient => {
                bucket.server_to_client_packets += packets;
                bucket.server_to_client_bytes += bytes;
            }
        }
    }
    Ok(buckets)
}

fn name_ranking(
    connection: &Connection,
    where_clause: &str,
    values: &[Value],
    order_column: &str,
    top: i64,
) -> Result<Vec<NameStat>, ProjectError> {
    let mut bound = values.to_vec();
    bound.push(Value::from(top));
    let mut statement = connection.prepare(&format!(
        "SELECT name, COUNT(*), COALESCE(SUM(size), 0) FROM packets{where_clause}
         GROUP BY name ORDER BY {order_column} DESC, name LIMIT ?"
    ))?;
    let rows = statement.query_map(params_from_iter(bound), |row| {
        Ok(NameStat {
            name: row.get(0)?,
            packets: row_u64(row, 1)?,
            bytes: row_u64(row, 2)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ProjectError::from)
}

fn connection_ranking(
    connection: &Connection,
    where_clause: &str,
    values: &[Value],
    top: i64,
) -> Result<Vec<ConnectionStat>, ProjectError> {
    let mut bound = values.to_vec();
    bound.push(Value::from(top));
    let mut statement = connection.prepare(&format!(
        "SELECT connection_id, COUNT(*), COALESCE(SUM(size), 0) FROM packets{where_clause}
         GROUP BY connection_id ORDER BY 2 DESC, connection_id LIMIT ?"
    ))?;
    let rows = statement.query_map(params_from_iter(bound), |row| {
        Ok(ConnectionStat {
            connection_id: parse_uuid(&row.get::<_, String>(0)?)?,
            packets: row_u64(row, 1)?,
            bytes: row_u64(row, 2)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ProjectError::from)
}

fn size_histogram(
    connection: &Connection,
    where_clause: &str,
    values: &[Value],
) -> Result<Vec<SizeBucket>, ProjectError> {
    let cases = SIZE_EDGES
        .iter()
        .enumerate()
        .map(|(index, edge)| format!("WHEN size < {edge} THEN {index}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut statement = connection.prepare(&format!(
        "SELECT CASE {cases} ELSE {} END AS bucket, COUNT(*) FROM packets{where_clause}
         GROUP BY bucket",
        SIZE_EDGES.len()
    ))?;
    let mut counts = [0_u64; SIZE_EDGES.len() + 1];
    let rows = statement.query_map(params_from_iter(values.iter()), |row| {
        Ok((row.get::<_, i64>(0)?, row_u64(row, 1)?))
    })?;
    for row in rows {
        let (index, count) = row?;
        if let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|index| counts.get_mut(index))
        {
            *slot = count;
        }
    }
    Ok(counts
        .iter()
        .enumerate()
        .map(|(index, packets)| SizeBucket {
            min: if index == 0 { 0 } else { SIZE_EDGES[index - 1] },
            max: SIZE_EDGES.get(index).copied(),
            packets: *packets,
        })
        .collect())
}

fn file_size(path: &Path) -> u64 {
    let mut total = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        total += std::fs::metadata(&sidecar).map_or(0, |metadata| metadata.len());
    }
    total
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mineburp_core::{
        ConnectionStatus, Disposition, PacketDetail, ProtocolState, TrafficSource, WireMetadata,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::ProjectOptions;

    fn snapshot(id: Uuid, status: ConnectionStatus) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id,
            target: Target {
                host: "play.example".into(),
                port: 25_566,
            },
            listener_address: "127.0.0.1:30000".into(),
            status,
            state: ProtocolState::Play,
            protocol_version: Some(767),
            minecraft_version: None,
            loader: None,
            compression_threshold: None,
            encrypted_client: false,
            encrypted_server: false,
            packet_count: 0,
            byte_count: 0,
            last_error: None,
        }
    }

    fn detail(
        connection: Uuid,
        sequence: u64,
        timestamp: i64,
        direction: Direction,
        name: &str,
        payload: &[u8],
    ) -> PacketDetail {
        PacketDetail {
            summary: PacketSummary {
                id: 0,
                sequence,
                connection_id: connection,
                timestamp_micros: timestamp,
                source: TrafficSource::Minecraft,
                direction,
                state: ProtocolState::Play,
                protocol_version: Some(767),
                packet_id: Some(1),
                name: Some(name.into()),
                channel: None,
                loader: None,
                size: payload.len(),
                disposition: Disposition::Forwarded,
                flow: None,
            },
            logical_bytes: Bytes::copy_from_slice(payload),
            decoded: None,
            decode_error: None,
            wire: WireMetadata::default(),
        }
    }

    /// Two connections; one closed. Six packets over 50 ms.
    fn seeded(directory: &tempfile::TempDir) -> (ProjectStore, Vec<i64>, Uuid, Uuid) {
        let store = ProjectStore::create(
            directory.path().join("analysis.mineburp"),
            "Analysis",
            ProjectOptions::default(),
        )
        .unwrap();
        let live = Uuid::from_u128(1);
        let closed = Uuid::from_u128(2);
        store
            .save_connection(&snapshot(live, ConnectionStatus::Active))
            .unwrap();
        store
            .save_connection(&snapshot(closed, ConnectionStatus::Closed))
            .unwrap();
        let rows = [
            (live, 0, Direction::ClientToServer, "chat", vec![1_u8; 10]),
            (
                live,
                10_000,
                Direction::ServerToClient,
                "chunk",
                vec![2; 5_000],
            ),
            (live, 20_000, Direction::ClientToServer, "chat", vec![3; 12]),
            (
                live,
                30_000,
                Direction::ServerToClient,
                "keep_alive",
                vec![4; 9],
            ),
            (
                closed,
                40_000,
                Direction::ClientToServer,
                "chat",
                vec![5; 30],
            ),
            (
                closed,
                50_000,
                Direction::ServerToClient,
                "chunk",
                vec![6; 70_000],
            ),
        ];
        let details = rows
            .iter()
            .enumerate()
            .map(
                |(index, (connection, timestamp, direction, name, payload))| {
                    detail(
                        *connection,
                        index as u64 + 1,
                        *timestamp,
                        *direction,
                        name,
                        payload,
                    )
                },
            )
            .collect::<Vec<_>>();
        let ids = store.insert_packets(&details).unwrap();
        (store, ids, live, closed)
    }

    #[test]
    fn annotations_round_trip_filter_and_clear() {
        let directory = tempdir().unwrap();
        let (store, ids, _, _) = seeded(&directory);
        let stored = store
            .set_annotation(
                ids[1],
                true,
                Some("#ff8800".into()),
                Some("big chunk".into()),
            )
            .unwrap()
            .expect("stored");
        assert!(stored.bookmarked);
        store
            .set_annotation(ids[3], false, Some("amber".into()), None)
            .unwrap();
        let found = store.annotations(&[ids[0], ids[1], ids[3]]).unwrap();
        assert_eq!(
            found.iter().map(|row| row.packet_id).collect::<Vec<_>>(),
            vec![ids[1], ids[3]]
        );
        assert_eq!(found[0].note.as_deref(), Some("big chunk"));

        let bookmarked = store
            .query_packets_filtered(&PacketQuery {
                bookmarked: Some(true),
                limit: 50,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(bookmarked.len(), 1);
        assert_eq!(bookmarked[0].id, ids[1]);
        let others = store
            .query_packets_filtered(&PacketQuery {
                bookmarked: Some(false),
                limit: 50,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(others.len(), ids.len() - 1);

        // Clearing every part removes the row.
        assert!(
            store
                .set_annotation(ids[3], false, None, Some("  ".into()))
                .unwrap()
                .is_none()
        );
        assert_eq!(store.list_annotations(10).unwrap().len(), 1);
    }

    #[test]
    fn annotations_are_validated() {
        let directory = tempdir().unwrap();
        let (store, ids, _, _) = seeded(&directory);
        assert!(matches!(
            store.set_annotation(ids[0], false, Some("#12345".into()), None),
            Err(ProjectError::InvalidAnnotation(_))
        ));
        assert!(matches!(
            store.set_annotation(ids[0], false, Some("Red; drop".into()), None),
            Err(ProjectError::InvalidAnnotation(_))
        ));
        assert!(matches!(
            store.set_annotation(ids[0], false, None, Some("x".repeat(MAX_NOTE_BYTES + 1))),
            Err(ProjectError::InvalidAnnotation(_))
        ));
        assert!(matches!(
            store.set_annotation(999_999, true, None, None),
            Err(ProjectError::PacketNotFound(999_999))
        ));
        assert!(
            store
                .annotations(&vec![1; MAX_ANNOTATION_LOOKUP + 1])
                .is_err()
        );
    }

    #[test]
    fn saved_filters_round_trip() {
        let directory = tempdir().unwrap();
        let (store, _, _, _) = seeded(&directory);
        let id = Uuid::from_u128(77);
        let filter = serde_json::json!({ "expression": "name ~ chat", "states": ["play"] });
        let saved = store
            .save_filter(&SavedFilter {
                id,
                name: " Chat only ".into(),
                filter: filter.clone(),
                created_at_micros: 0,
                updated_at_micros: 0,
            })
            .unwrap();
        assert_eq!(saved.name, "Chat only");
        assert!(saved.created_at_micros > 0);
        let renamed = store
            .save_filter(&SavedFilter {
                name: "Chat".into(),
                ..saved.clone()
            })
            .unwrap();
        assert_eq!(renamed.created_at_micros, saved.created_at_micros);
        let loaded = store.load_saved_filters().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Chat");
        assert_eq!(loaded[0].filter, filter);
        assert!(store.delete_saved_filter(id).unwrap());
        assert!(!store.delete_saved_filter(id).unwrap());
        assert!(store.load_saved_filters().unwrap().is_empty());
        assert!(
            store
                .save_filter(&SavedFilter {
                    name: "   ".into(),
                    ..saved
                })
                .is_err()
        );
    }

    #[test]
    fn statistics_summarise_what_a_filter_matches() {
        let directory = tempdir().unwrap();
        let (store, _, live, _) = seeded(&directory);
        let stats = store
            .traffic_stats(
                &PacketQuery::default(),
                StatsOptions {
                    bucket_micros: Some(25_000),
                    ..StatsOptions::default()
                },
            )
            .unwrap();
        assert_eq!(stats.total_packets, 6);
        assert_eq!(stats.total_bytes, 10 + 5_000 + 12 + 9 + 30 + 70_000);
        assert_eq!(stats.first_timestamp_micros, Some(0));
        assert_eq!(stats.last_timestamp_micros, Some(50_000));
        assert_eq!(stats.bucket_micros, 25_000);
        assert_eq!(
            stats
                .buckets
                .iter()
                .map(|b| b.start_micros)
                .collect::<Vec<_>>(),
            vec![0, 25_000, 50_000]
        );
        assert_eq!(stats.buckets[0].client_to_server_packets, 2);
        assert_eq!(stats.buckets[0].server_to_client_bytes, 5_000);
        assert_eq!(stats.client_to_server_packets, 3);
        assert_eq!(stats.top_by_count[0].name.as_deref(), Some("chat"));
        assert_eq!(stats.top_by_count[0].packets, 3);
        assert_eq!(stats.top_by_bytes[0].name.as_deref(), Some("chunk"));
        assert_eq!(stats.top_connections[0].connection_id, live);
        let histogram: u64 = stats.size_histogram.iter().map(|b| b.packets).sum();
        assert_eq!(histogram, 6);
        assert_eq!(
            stats.size_histogram[0].packets, 3,
            "9, 10 and 12 bytes are < 16"
        );
        assert_eq!(stats.size_histogram.last().unwrap().packets, 0);
        assert_eq!(
            stats.size_histogram[7].packets, 1,
            "70 000 bytes is in [65 536, 262 144)"
        );

        // The same filter language narrows the statistics.
        let chat = store
            .traffic_stats(
                &PacketQuery {
                    include_names: vec!["chat".into()],
                    ..PacketQuery::default()
                },
                StatsOptions::default(),
            )
            .unwrap();
        assert_eq!(chat.total_packets, 3);
        assert!(chat.buckets.len() <= StatsOptions::default().max_buckets);

        let empty = store
            .traffic_stats(
                &PacketQuery {
                    min_size: Some(1 << 30),
                    ..PacketQuery::default()
                },
                StatsOptions::default(),
            )
            .unwrap();
        assert_eq!(empty.total_packets, 0);
        assert!(empty.buckets.is_empty());
    }

    #[test]
    fn a_tiny_bucket_request_is_widened_to_the_bucket_limit() {
        let directory = tempdir().unwrap();
        let (store, _, _, _) = seeded(&directory);
        let stats = store
            .traffic_stats(
                &PacketQuery::default(),
                StatsOptions {
                    bucket_micros: Some(1),
                    max_buckets: 5,
                    top: 1,
                },
            )
            .unwrap();
        assert!(stats.buckets.len() <= 5);
        assert_eq!(stats.top_by_count.len(), 1);
    }

    #[test]
    fn deleting_history_removes_rows_annotations_and_idle_connections() {
        let directory = tempdir().unwrap();
        let (store, ids, live, closed) = seeded(&directory);
        store.set_annotation(ids[4], true, None, None).unwrap();
        let removed = store
            .delete_packets(
                &PacketQuery {
                    connection_id: Some(closed),
                    ..PacketQuery::default()
                },
                true,
            )
            .unwrap();
        assert_eq!(removed.packets, 2);
        assert_eq!(removed.connections, 1);
        assert!(store.list_annotations(10).unwrap().is_empty(), "cascaded");
        assert!(store.connection(closed).unwrap().is_none());
        assert!(store.connection(live).unwrap().is_some());

        // An active connection is never pruned, even when emptied.
        let removed = store.delete_packets(&PacketQuery::default(), true).unwrap();
        assert_eq!(removed.packets, 4);
        assert_eq!(removed.connections, 0);
        let compacted = store.compact().unwrap();
        assert!(compacted.bytes_after > 0);
        assert!(store.query_packets(None, 0, 10).unwrap().is_empty());
    }

    #[test]
    fn walks_matching_packets_oldest_first_with_payloads() {
        let directory = tempdir().unwrap();
        let (store, ids, _, _) = seeded(&directory);
        let mut seen = Vec::new();
        let visited = store
            .for_each_packet(
                &PacketQuery {
                    include_names: vec!["ch".into()],
                    before_id: Some(ids[5]),
                    ..PacketQuery::default()
                },
                2,
                |summary, payload| {
                    assert_eq!(payload.len(), summary.size);
                    seen.push(summary.id);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(visited, 4);
        assert_eq!(seen, vec![ids[0], ids[1], ids[2], ids[4]]);
        let stopped = store.for_each_packet(&PacketQuery::default(), 10, |_, _| Err("stop".into()));
        assert!(matches!(stopped, Err(ProjectError::Interrupted(_))));
    }
}
