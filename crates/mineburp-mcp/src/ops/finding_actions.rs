//! Shared desktop/MCP finding actions.
use mineburp_core::{Evidence, Finding};
use mineburp_project::ProjectStore;
use serde_json::{Value, json};
use uuid::Uuid;
#[allow(
    clippy::too_many_lines,
    reason = "shared action dispatch keeps the desktop and MCP contracts together"
)]
pub fn finding_action(store: &ProjectStore, action: &str, args: &Value) -> Result<Value, String> {
    let parse = |key: &str| {
        args.get(key)
            .cloned()
            .ok_or_else(|| format!("missing {key}"))
    };
    let id = || -> Result<Uuid, String> {
        serde_json::from_value(parse("id")?).map_err(|e| e.to_string())
    };
    let evidence = || -> Result<Evidence, String> {
        serde_json::from_value(parse("evidence")?).map_err(|e| e.to_string())
    };
    let finding = || -> Result<Finding, String> {
        serde_json::from_value(parse("finding")?).map_err(|e| e.to_string())
    };
    match action {
        "list" => Ok(json!(
            store
                .list_findings(
                    serde_json::from_value(args.get("status").cloned().unwrap_or(Value::Null))
                        .map_err(|e| e.to_string())?,
                    serde_json::from_value(args.get("severity").cloned().unwrap_or(Value::Null))
                        .map_err(|e| e.to_string())?
                )
                .map_err(|e| e.to_string())?
        )),
        "evidence_status" => {
            let f = store
                .get_finding(id()?)
                .map_err(|e| e.to_string())?
                .ok_or("finding missing")?;
            let mut statuses = Vec::new();
            for evidence in f.evidence {
                let missing = match &evidence {
                    Evidence::Packet(id) => store
                        .packet_detail(*id)
                        .map_err(|e| e.to_string())?
                        .is_none(),
                    Evidence::Connection(id) => {
                        store.connection(*id).map_err(|e| e.to_string())?.is_none()
                    }
                    Evidence::Repeater(id) => !store
                        .load_repeater_tabs()
                        .map_err(|e| e.to_string())?
                        .iter()
                        .any(|t| t.id == *id),
                    Evidence::Rule(id) => !store
                        .load_replacement_rules()
                        .map_err(|e| e.to_string())?
                        .iter()
                        .any(|r| r.id == *id),
                };
                statuses.push(json!({"evidence": evidence, "missing": missing}));
            }
            Ok(json!(statuses))
        }
        "get" => Ok(json!(store.get_finding(id()?).map_err(|e| e.to_string())?)),
        "create" => Ok(json!(
            store
                .create_finding(finding()?)
                .map_err(|e| e.to_string())?
        )),
        "update" => Ok(json!(
            store
                .update_finding(finding()?)
                .map_err(|e| e.to_string())?
        )),
        "delete" => {
            store.delete_finding(id()?).map_err(|e| e.to_string())?;
            Ok(json!(null))
        }
        "add_evidence" => Ok(json!(
            store
                .add_finding_evidence(id()?, evidence()?)
                .map_err(|e| e.to_string())?
        )),
        "remove_evidence" => Ok(json!(
            store
                .remove_finding_evidence(id()?, &evidence()?)
                .map_err(|e| e.to_string())?
        )),
        "export" => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or("missing path")?;
            let html = match args
                .get("reportFormat")
                .and_then(Value::as_str)
                .unwrap_or("markdown")
            {
                "html" => true,
                "markdown" => false,
                _ => return Err("reportFormat must be markdown or html".into()),
            };
            super::export_findings_with_overwrite(
                store,
                std::path::Path::new(path),
                html,
                args.get("overwrite")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )?;
            if let Some(pcap) = args.get("pcapPath").and_then(Value::as_str) {
                let path = std::path::Path::new(pcap);
                super::validate_path(path, super::PathPurpose::ExportPcap, &[&store.info().path])?;
                let overwrite = args
                    .get("overwrite")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                super::check_export_target(path, overwrite)?;
                let temporary =
                    tempfile::NamedTempFile::new_in(path.parent().ok_or("missing parent")?)
                        .map_err(|e| e.to_string())?;
                let ids = store
                    .list_findings(None, None)
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .flat_map(|f| f.evidence)
                    .filter_map(|e| {
                        if let Evidence::Packet(id) = e {
                            Some(id)
                        } else {
                            None
                        }
                    })
                    .collect();
                super::pcapng::write_pcapng_filtered(
                    store,
                    &mineburp_project::PacketQuery::default(),
                    temporary.reopen().map_err(|e| e.to_string())?,
                    Some(&ids),
                )?;
                super::publish_export(temporary, path, overwrite)?;
            }
            Ok(json!({"path":path}))
        }
        _ => Err(format!("unknown findings action {action}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn insert_hostile_packet(store: &ProjectStore) -> i64 {
        let connection = mineburp_core::ConnectionSnapshot {
            id: Uuid::new_v4(),
            target: mineburp_core::Target {
                host: "<script>host</script>".into(),
                port: 25565,
            },
            listener_address: "127.0.0.1:1".into(),
            status: mineburp_core::ConnectionStatus::Closed,
            state: mineburp_core::ProtocolState::Play,
            protocol_version: Some(767),
            minecraft_version: None,
            loader: None,
            compression_threshold: None,
            encrypted_client: false,
            encrypted_server: false,
            packet_count: 0,
            byte_count: 0,
            last_error: None,
        };
        store.save_connection(&connection).unwrap();
        let packet = mineburp_core::PacketDetail {
            summary: mineburp_core::PacketSummary {
                id: 0,
                sequence: 0,
                connection_id: connection.id,
                timestamp_micros: 1,
                source: mineburp_core::TrafficSource::Minecraft,
                direction: mineburp_core::Direction::ClientToServer,
                state: mineburp_core::ProtocolState::Play,
                protocol_version: Some(767),
                packet_id: Some(0),
                name: Some("<script>packet</script>".into()),
                channel: None,
                loader: None,
                size: 1,
                disposition: mineburp_core::Disposition::Forwarded,
                flow: None,
            },
            logical_bytes: bytes::Bytes::from_static(&[0]),
            decoded: None,
            decode_error: None,
            wire: mineburp_core::WireMetadata::default(),
        };
        store.insert_packets(&[packet]).unwrap();
        store
            .query_packets_filtered(&mineburp_project::PacketQuery {
                limit: 1,
                ..Default::default()
            })
            .unwrap()[0]
            .id
    }
    #[tokio::test]
    async fn offline_tool_crud_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProjectStore::create(
            dir.path().join("test.mineburp"),
            "Test",
            mineburp_project::ProjectOptions::default(),
        )
        .unwrap();
        let host = crate::OfflineHost::new(Some(store.clone()));
        let finding = json!({"id":Uuid::nil(),"title":"<script>alert(1)</script>","severity":"high","status":"open","description":"<img src=x>","reproductionSteps":"test","createdAtMicros":0,"updatedAtMicros":0,"tags":[],"evidence":[{"kind":"packet","id":123}]});
        let result = crate::tools::dispatch(
            &host,
            "findings",
            json!({"action":"create","finding":finding,"format":"json"}),
        )
        .await
        .unwrap();
        let f: Finding = serde_json::from_str(&result).unwrap();
        let result =
            crate::tools::dispatch(&host, "findings", json!({"action":"list","format":"json"}))
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<Finding>>(&result).unwrap().len(),
            1
        );
        let packet_id = insert_hostile_packet(&store);
        store
            .add_finding_evidence(f.id, Evidence::Packet(packet_id))
            .unwrap();
        let html = super::super::render_findings(&store, true).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;packet"));
        assert!(html.contains("&lt;script&gt;host"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Packet #123: missing"));
        store
            .delete_packets(&mineburp_project::PacketQuery::default(), true)
            .unwrap();
        assert!(
            store
                .get_finding(f.id)
                .unwrap()
                .unwrap()
                .evidence
                .contains(&Evidence::Packet(packet_id))
        );
        assert!(
            super::super::render_findings(&store, false)
                .unwrap()
                .contains(&format!("Packet #{packet_id}: missing"))
        );
        crate::tools::dispatch(&host, "findings", json!({"action":"delete","id":f.id}))
            .await
            .unwrap();
        assert!(store.list_findings(None, None).unwrap().is_empty());
    }
}
