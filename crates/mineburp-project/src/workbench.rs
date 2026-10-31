//! Bounded project-owned workbench documents and channel aggregates.
use crate::store::{PacketQuery, ProjectError, ProjectStore, compile_query, now_micros};
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
fn document_key(key: &str) -> Result<(), ProjectError> {
    if matches!(key, "intruder" | "sequencer") {
        Ok(())
    } else {
        Err(ProjectError::Corrupt("Unknown workbench document".into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStat {
    pub channel: String,
    pub direction: String,
    pub state: String,
    pub protocol_version: Option<i32>,
    pub packets: u64,
    pub bytes: u64,
    pub connections: u64,
    pub first_timestamp_micros: i64,
    pub last_timestamp_micros: i64,
    pub sample_packet_id: i64,
}

impl ProjectStore {
    pub fn workbench_document(&self, key: &str) -> Result<Option<serde_json::Value>, ProjectError> {
        document_key(key)?;
        self.with_reader(|connection| {
            let payload: Option<String> = connection.query_row("SELECT payload_json FROM workbench_documents WHERE key=?1 AND length(CAST(payload_json AS BLOB)) <= ?2", params![key, 16_777_216_i64], |row| row.get(0)).optional()?;
            payload.map(|text| serde_json::from_str(&text).map_err(|e| ProjectError::Corrupt(e.to_string()))).transpose()
        })
    }
    pub fn save_workbench_document(
        &self,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        document_key(key)?;
        let payload =
            serde_json::to_string(value).map_err(|e| ProjectError::Corrupt(e.to_string()))?;
        if payload.len() > MAX_DOCUMENT {
            return Err(ProjectError::Corrupt(
                "Workbench document exceeds 16 MiB".into(),
            ));
        }
        self.connection.lock().execute("INSERT INTO workbench_documents(key,payload_json,updated_at_micros) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET payload_json=excluded.payload_json,updated_at_micros=excluded.updated_at_micros", params![key,payload,now_micros()])?;
        Ok(())
    }
    /// Aggregates the complete filtered capture, never just loaded UI rows.
    pub fn channel_stats(&self, query: &PacketQuery) -> Result<Vec<ChannelStat>, ProjectError> {
        let compiled = compile_query(query)?;
        self.with_reader(|connection| {
            compiled.install(connection)?;
            let clause = if compiled.where_clause.is_empty() { " WHERE channel IS NOT NULL".into() } else { format!("{} AND channel IS NOT NULL",compiled.where_clause) };
            let mut statement = connection.prepare(&format!("SELECT channel,direction,state,protocol_version,COUNT(*),COALESCE(SUM(size),0),COUNT(DISTINCT connection_id),MIN(timestamp_micros),MAX(timestamp_micros),MAX(id) FROM packets{clause} GROUP BY channel,direction,state,protocol_version ORDER BY COUNT(*) DESC,channel,direction,state,protocol_version LIMIT 501"))?;
            statement.query_map(params_from_iter(compiled.values.iter()), |r| Ok(ChannelStat { channel:r.get(0)?,direction:r.get(1)?,state:r.get(2)?,protocol_version:r.get(3)?, packets:crate::store::row_u64(r,4)?,bytes:crate::store::row_u64(r,5)?,connections:crate::store::row_u64(r,6)?,first_timestamp_micros:r.get(7)?,last_timestamp_micros:r.get(8)?,sample_packet_id:r.get(9)? }))?.collect::<Result<Vec<_>,_>>().map_err(ProjectError::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectOptions;
    #[test]
    fn work_is_project_owned_survives_reopen_and_respects_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("work.mineburp");
        let store = ProjectStore::create(&path, "Work", ProjectOptions::default()).unwrap();
        let value = serde_json::json!({"version":1,"data":{"payloads":["a","b"],"results":[{"result":"sent"}]}});
        store.save_workbench_document("intruder", &value).unwrap();
        assert!(store.save_workbench_document("other", &value).is_err());
        drop(store);
        let store = ProjectStore::open(&path, ProjectOptions::default()).unwrap();
        assert_eq!(
            store.workbench_document("intruder").unwrap(),
            Some(value.clone())
        );
        assert_eq!(store.workbench_document("sequencer").unwrap(), None);
        let copy = directory.path().join("copy.mineburp");
        store
            .save_as(&copy, "Copy", ProjectOptions::default())
            .unwrap();
        assert_eq!(
            ProjectStore::open(&copy, ProjectOptions::default())
                .unwrap()
                .workbench_document("intruder")
                .unwrap(),
            Some(value.clone())
        );
        drop(store);
        let readonly = ProjectStore::open(
            &path,
            ProjectOptions {
                read_only: true,
                ..ProjectOptions::default()
            },
        )
        .unwrap();
        assert!(matches!(
            readonly.save_workbench_document("intruder", &value),
            Err(ProjectError::ReadOnly)
        ));
    }
    #[test]
    fn channel_aggregation_counts_the_full_filtered_capture() {
        use bytes::Bytes;
        use mineburp_core::*;
        let directory = tempfile::tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("channels.mineburp"),
            "Channels",
            ProjectOptions::default(),
        )
        .unwrap();
        let id = uuid::Uuid::new_v4();
        store
            .save_connection(&ConnectionSnapshot {
                id,
                target: Target {
                    host: "test".into(),
                    port: 25565,
                },
                listener_address: String::new(),
                status: ConnectionStatus::Closed,
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
            })
            .unwrap();
        for index in 0..300 {
            store
                .insert_packet(&PacketDetail {
                    summary: PacketSummary {
                        id: 0,
                        sequence: index,
                        connection_id: id,
                        timestamp_micros: i64::try_from(index).unwrap(),
                        source: TrafficSource::Minecraft,
                        direction: if index < 275 {
                            Direction::ClientToServer
                        } else {
                            Direction::ServerToClient
                        },
                        state: ProtocolState::Play,
                        protocol_version: Some(767),
                        packet_id: Some(1),
                        name: Some("custom_payload".into()),
                        channel: Some("test:channel".into()),
                        loader: None,
                        size: 2,
                        disposition: Disposition::Forwarded,
                        flow: None,
                    },
                    logical_bytes: Bytes::from_static(&[1, 2]),
                    decoded: None,
                    decode_error: None,
                    wire: WireMetadata::default(),
                })
                .unwrap();
        }
        let rows = store
            .channel_stats(&PacketQuery {
                limit: 1,
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].packets, 275);
        assert_eq!(rows[0].bytes, 550);
        assert_eq!(rows[0].connections, 1);
        let rows = store
            .channel_stats(&PacketQuery {
                expression: Some(FilterExpression::parse("direction == server_to_client").unwrap()),
                ..PacketQuery::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].packets, 25);
    }
}
