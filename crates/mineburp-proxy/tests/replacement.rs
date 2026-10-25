//! Drives a replacement rule through a real session.
//!
//! The rewrite engine is unit tested on its own; what this covers is the part
//! that can only break in the proxy: that a rule is selected by its expression,
//! applied to the frame that goes on the wire, and that the peer receives the
//! rewritten packet rather than the original.

use std::time::Duration;

use common::{Link, ORIGINAL, PROTOCOL_VERSION, run_server};
use mineburp_core::{PacketEdit, ReplacementRule, Target};
use mineburp_protocol::{Handshake, encode_handshake};
use mineburp_proxy::{ProxyService, SessionOptions};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

mod common;

const REWRITTEN: &str = r#"{"description":"Rewritten by a rule"}"#;

#[tokio::test]
async fn a_replacement_rule_rewrites_a_field_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(run_server(listener));

    let proxy = ProxyService::new();
    proxy
        .set_replacement_rules(vec![ReplacementRule {
            id: Uuid::new_v4(),
            name: "Rewrite the motd".into(),
            enabled: true,
            expression: "direction == server_to_client && name == status_response".into(),
            // A field edit rewrites the string's length prefix with it, which a
            // byte-level edit could not do.
            edits: vec![PacketEdit::Field {
                name: "response".into(),
                value: REWRITTEN.into(),
            }],
        }])
        .expect("the rule compiles");

    let snapshot = proxy
        .start_session(SessionOptions::new(Target {
            host: "127.0.0.1".into(),
            port: target_port,
        }))
        .await
        .expect("session");

    let stream = TcpStream::connect(&snapshot.listener_address)
        .await
        .expect("connect to the private route");
    let mut client = Link::new(stream);
    client
        .send(
            0,
            &encode_handshake(&Handshake {
                protocol_version: PROTOCOL_VERSION,
                server_address: "play.example.test".into(),
                server_port: 25_565,
                next_state: 1,
            })
            .expect("handshake"),
        )
        .await;
    client.send(0, &[]).await;

    let response = client.receive().await;
    assert_eq!(response.id, 0, "status response");
    let text = String::from_utf8(response.body[1..].to_vec()).expect("utf-8 body");
    assert_eq!(
        text, REWRITTEN,
        "the client must receive the rewritten field, prefix and all"
    );

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server side must finish")
        .expect("the server task must not panic");
}

#[tokio::test]
async fn a_disabled_rule_leaves_traffic_alone() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(run_server(listener));

    let proxy = ProxyService::new();
    proxy
        .set_replacement_rules(vec![ReplacementRule {
            id: Uuid::new_v4(),
            name: "Disabled".into(),
            enabled: false,
            expression: String::new(),
            edits: vec![PacketEdit::Frame { bytes: "00".into() }],
        }])
        .expect("the rule compiles");

    let snapshot = proxy
        .start_session(SessionOptions::new(Target {
            host: "127.0.0.1".into(),
            port: target_port,
        }))
        .await
        .expect("session");
    let mut client = Link::new(
        TcpStream::connect(&snapshot.listener_address)
            .await
            .expect("connect"),
    );
    client
        .send(
            0,
            &encode_handshake(&Handshake {
                protocol_version: PROTOCOL_VERSION,
                server_address: "play.example.test".into(),
                server_port: 25_565,
                next_state: 1,
            })
            .expect("handshake"),
        )
        .await;
    client.send(0, &[]).await;

    let response = client.receive().await;
    let text = String::from_utf8(response.body[1..].to_vec()).expect("utf-8 body");
    assert_eq!(text, ORIGINAL, "a disabled rule must not touch the packet");

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server side must finish")
        .expect("the server task must not panic");
}
