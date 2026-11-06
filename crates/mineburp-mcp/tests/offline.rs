//! Drives the MCP tools end to end against a real project file.

#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "each test is one scripted session"
)]

use std::sync::Arc;

use bytes::Bytes;
use mineburp_core::{
    ConnectionSnapshot, ConnectionStatus, Direction, Disposition, PacketDetail, PacketSummary,
    ProtocolState, Target, TrafficSource, WireMetadata,
};
use mineburp_mcp::{McpServer, OfflineHost};
use mineburp_project::{ProjectOptions, ProjectStore};
use serde_json::{Value, json};
use uuid::Uuid;

/// Handshake for protocol 767 to localhost:25565, next state login.
const HANDSHAKE: &str = "00ff05096c6f63616c686f737463dd02";

fn connection(id: Uuid) -> ConnectionSnapshot {
    ConnectionSnapshot {
        id,
        target: Target {
            host: "mc.example".into(),
            port: 25_565,
        },
        listener_address: "127.0.0.1:1".into(),
        status: ConnectionStatus::Closed,
        state: ProtocolState::Login,
        protocol_version: Some(767),
        minecraft_version: Some("1.21.1".into()),
        loader: None,
        compression_threshold: None,
        encrypted_client: false,
        encrypted_server: false,
        packet_count: 3,
        byte_count: 40,
        last_error: None,
    }
}

fn packet(connection: Uuid, at: i64, state: ProtocolState, name: &str, hex: &str) -> PacketDetail {
    let bytes = hex::decode(hex).unwrap();
    PacketDetail {
        summary: PacketSummary {
            id: 0,
            sequence: 0,
            connection_id: connection,
            timestamp_micros: 1_700_000_000_000_000 + at,
            source: TrafficSource::Minecraft,
            direction: Direction::ClientToServer,
            state,
            protocol_version: Some(767),
            packet_id: Some(0),
            name: Some(name.into()),
            channel: None,
            loader: None,
            size: bytes.len(),
            disposition: Disposition::Forwarded,
            flow: None,
        },
        logical_bytes: Bytes::from(bytes),
        decoded: None,
        decode_error: None,
        wire: WireMetadata::default(),
    }
}

struct Session {
    server: McpServer,
    _directory: tempfile::TempDir,
    directory: std::path::PathBuf,
}

impl Session {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("work.mineburp"),
            "Work",
            ProjectOptions::default(),
        )
        .unwrap();
        let id = Uuid::from_u128(0xabcd_ef01_0000_0000_0000_0000_0000_0001);
        store.save_connection(&connection(id)).unwrap();
        store
            .insert_packets(&[
                // The proxy stores its built-in decode with every row.
                PacketDetail {
                    decoded: Some(json!({
                        "protocol_version": 767,
                        "server_address": "localhost",
                        "server_port": 25565,
                        "next_state": 2,
                    })),
                    ..packet(id, 0, ProtocolState::Handshake, "intention", HANDSHAKE)
                },
                // Login start: name "Steve" and a UUID.
                packet(
                    id,
                    1_000,
                    ProtocolState::Login,
                    "hello",
                    "000553746576650000000000000000000000000000000001",
                ),
            ])
            .unwrap();
        Self {
            server: McpServer::new(Arc::new(OfflineHost::new(Some(store)))),
            directory: directory.path().to_path_buf(),
            _directory: directory,
        }
    }

    async fn ok(&self, tool: &str, arguments: Value) -> String {
        let result = self.server.call(tool, arguments.clone()).await;
        let text = result["content"][0]["text"].as_str().unwrap().to_owned();
        assert_eq!(
            result["isError"], false,
            "{tool} {arguments} failed: {text}"
        );
        text
    }

    async fn err(&self, tool: &str, arguments: Value) -> String {
        let result = self.server.call(tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool} should fail");
        result["content"][0]["text"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn reads_history_compactly() {
    let session = Session::new();
    let status = session.ok("status", json!({})).await;
    assert!(
        status.contains("mode: offline") && status.contains("project: Work"),
        "{status}"
    );

    let rows = session.ok("packets", json!({})).await;
    assert!(rows.starts_with("2 packet(s) on c=abcdef01"), "{rows}");
    assert!(rows.contains("C>S handshake 0x00 intention 16B"), "{rows}");
    assert!(
        rows.contains("cursors: older before=1 | newer after=2"),
        "{rows}"
    );

    let filtered = session
        .ok(
            "packets",
            json!({ "expr": "state == login", "connection": "abcd" }),
        )
        .await;
    assert!(filtered.starts_with("1 packet(s)"), "{filtered}");
    assert!(
        session
            .ok("packets", json!({ "after": 2 }))
            .await
            .contains("no packets after #2")
    );

    let detail = session
        .ok("packet", json!({ "id": 1, "layout": true }))
        .await;
    assert!(detail.contains("decode: handshake"), "{detail}");
    assert!(detail.contains("localhost"), "{detail}");
    assert!(detail.contains("layout (offset"), "{detail}");
    assert!(detail.contains(HANDSHAKE), "{detail}");
    // The stored built-in decode is not shown a second time as a schema decode.
    assert!(!detail.contains("schema decode"), "{detail}");
    assert_eq!(detail.matches("server_port: 25565").count(), 1, "{detail}");

    let connections = session.ok("connections", json!({})).await;
    assert!(
        connections.contains("abcdef01 mc.example:25565 closed login 1.21.1(p767)"),
        "{connections}"
    );

    let stats = session.ok("stats", json!({ "timeline": true })).await;
    assert!(stats.starts_with("2 packets"), "{stats}");

    assert!(
        session
            .err("packet", json!({ "id": 99 }))
            .await
            .contains("does not exist")
    );
    assert!(
        session
            .err("intercept", json!({}))
            .await
            .contains("desktop app")
    );
}

#[tokio::test]
async fn edits_annotates_and_manages_project_state() {
    let session = Session::new();

    let rewritten = session
        .ok(
            "rewrite",
            json!({ "packet": 1, "set": { "server_address": "evil.test" } }),
        )
        .await;
    assert!(rewritten.contains(&hex::encode("evil.test")), "{rewritten}");

    let decoded = session
        .ok("decode", json!({ "hex": HANDSHAKE, "state": "handshake" }))
        .await;
    assert!(decoded.contains("server_port: 25565"), "{decoded}");

    let annotated = session
        .ok(
            "annotate",
            json!({ "id": 2, "note": "login name", "color": "amber" }),
        )
        .await;
    assert!(annotated.contains("#2 [amber] login name"), "{annotated}");
    let bookmarked = session
        .ok("annotate", json!({ "ids": [1, 2], "bookmark": true }))
        .await;
    assert!(
        bookmarked.contains("#2 ★ [amber] login name"),
        "{bookmarked}"
    );
    let only_bookmarked = session.ok("packets", json!({ "bookmarked": true })).await;
    assert!(
        only_bookmarked.starts_with("2 packet(s)"),
        "{only_bookmarked}"
    );

    session
        .ok(
            "filters",
            json!({ "action": "save", "name": "logins", "filter": { "states": ["login"] } }),
        )
        .await;
    let saved = session.ok("packets", json!({ "saved": "logins" })).await;
    assert!(saved.starts_with("1 packet(s)"), "{saved}");
    let validated = session
        .ok(
            "filters",
            json!({ "action": "validate", "expr": "size > 3" }),
        )
        .await;
    assert_eq!(validated, "valid");
    assert!(
        session
            .err(
                "filters",
                json!({ "action": "validate", "expr": "size !! 3" })
            )
            .await
            .contains("operator")
    );

    let added = session
        .ok("rules", json!({ "action": "add", "name": "host", "expr": "state == handshake", "set": { "server_address": "x" } }))
        .await;
    assert!(added.contains("[on] host | state == handshake"), "{added}");
    let preview = session
        .ok(
            "rules",
            json!({ "action": "preview", "id": "host", "packet": 1 }),
        )
        .await;
    assert!(preview.contains("matches this packet"), "{preview}");
    session
        .ok(
            "rules",
            json!({ "action": "update", "id": "host", "enabled": false }),
        )
        .await;
    assert!(session.ok("rules", json!({})).await.contains("[off] host"));
    session
        .ok("rules", json!({ "action": "remove", "id": "host" }))
        .await;

    let json_path = session.directory.join("out.json");
    let exported = session
        .ok(
            "project",
            json!({ "action": "export", "path": json_path, "filter": { "states": ["login"] } }),
        )
        .await;
    assert_eq!(exported, "wrote 1 packets as JSON");
    let pcap_path = session.directory.join("out.pcapng");
    session
        .ok("project", json!({ "action": "export", "path": pcap_path }))
        .await;
    let imported = session
        .ok("project", json!({ "action": "import", "path": pcap_path }))
        .await;
    assert!(imported.contains("imported 2 rows"), "{imported}");

    assert!(
        session
            .err("project", json!({ "action": "delete_packets" }))
            .await
            .contains("confirm")
    );
    let deleted = session
        .ok(
            "project",
            json!({ "action": "delete_packets", "filter": { "states": ["login"] } }),
        )
        .await;
    assert!(deleted.starts_with("deleted 2 packets"), "{deleted}");

    let protocol = session
        .ok(
            "protocol",
            json!({ "query": "1.21.1", "table": true, "state": "login" }),
        )
        .await;
    assert!(protocol.contains("p767 login packet ids"), "{protocol}");
    let item = session
        .ok(
            "protocol",
            json!({ "query": "767", "registry": "item", "name": "diamond_sword" }),
        )
        .await;
    assert!(item.contains("diamond_sword"), "{item}");
}

#[tokio::test]
async fn semantically_empty_delete_filters_require_confirmation() {
    let session = Session::new();
    for filter in [json!({"expr":""}), json!({"states":[]})] {
        let error = session
            .err(
                "project",
                json!({"action":"delete_packets","filter":filter}),
            )
            .await;
        assert!(error.contains("confirm=true"), "{error}");
    }
    let text = session.ok("packets", json!({"format":"json"})).await;
    let rows: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn project_scope_round_trip_and_validation() {
    let session = Session::new();
    assert_eq!(session.ok("project", json!({"action":"scope"})).await, "[]");
    let patterns = json!(["*.example.com:25565", "10.0.0.0/8", "[2001:db8::/32]:25565"]);
    let result = session
        .ok("project", json!({"action":"scope", "patterns":patterns}))
        .await;
    assert_eq!(serde_json::from_str::<Value>(&result).unwrap(), patterns);
    assert_eq!(
        session.ok("project", json!({"action":"scope"})).await,
        result
    );
    assert!(
        session
            .err(
                "project",
                json!({"action":"scope", "patterns":["10.0.0.0/99"]})
            )
            .await
            .contains("CIDR")
    );
    assert_eq!(
        session
            .ok("project", json!({"action":"scope", "patterns":[]}))
            .await,
        "[]"
    );
}
