//! Drives Intercept through a real session: a held frame must not reach the
//! peer until the operator decides, and what they decide is what arrives.

use std::time::Duration;

use bytes::Bytes;
use common::{Link, ORIGINAL, PROTOCOL_VERSION, run_server, string_bytes};
use mineburp_core::Target;
use mineburp_protocol::{Handshake, encode_handshake};
use mineburp_proxy::{InterceptDecision, InterceptSettings, ProxyService, SessionOptions};
use tokio::net::{TcpListener, TcpStream};

mod common;

const EDITED: &str = r#"{"description":"Edited in Intercept"}"#;

/// Starts a status server behind the proxy and sends the client's half.
async fn status_exchange(proxy: &ProxyService) -> (Link, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(run_server(listener));
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
    (client, server)
}

fn hold_server_responses(proxy: &ProxyService) {
    proxy
        .set_intercept_settings(InterceptSettings {
            enabled: true,
            client_to_server: false,
            server_to_client: true,
            ..InterceptSettings::default()
        })
        .expect("settings");
}

async fn wait_for_held(proxy: &ProxyService) -> u64 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(held) = proxy.intercepted().first() {
                return held.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the response must be held")
}

#[tokio::test]
async fn a_handshake_can_be_held_before_the_protocol_state_advances() {
    let proxy = ProxyService::new();
    proxy
        .set_intercept_settings(InterceptSettings {
            enabled: true,
            client_to_server: true,
            server_to_client: false,
            expression: "state == handshake".into(),
            ..InterceptSettings::default()
        })
        .expect("settings");
    let (mut client, server) = status_exchange(&proxy).await;

    let id = wait_for_held(&proxy).await;
    let held = proxy.intercepted();
    assert_eq!(
        held[0].summary.state,
        mineburp_core::ProtocolState::Handshake
    );
    assert_eq!(
        proxy.sessions()[0].state,
        mineburp_core::ProtocolState::Handshake,
        "holding the handshake must not advance the session"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.receive())
            .await
            .is_err(),
        "the server cannot answer before the handshake is forwarded"
    );

    proxy
        .resolve_intercept(id, InterceptDecision::Forward)
        .expect("forward handshake");
    let response = client.receive().await;
    assert_eq!(&response.body[1..], ORIGINAL.as_bytes());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server finishes")
        .expect("server task");
}

#[tokio::test]
async fn a_held_frame_waits_and_is_forwarded_as_edited() {
    let proxy = ProxyService::new();
    hold_server_responses(&proxy);
    let (mut client, server) = status_exchange(&proxy).await;

    let id = wait_for_held(&proxy).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.receive())
            .await
            .is_err(),
        "nothing may reach the client while the frame is held"
    );

    let mut edited = vec![0_u8];
    edited.extend(string_bytes(EDITED));
    proxy
        .resolve_intercept(id, InterceptDecision::Replace(Bytes::from(edited)))
        .expect("resolve");

    let response = client.receive().await;
    assert_eq!(&response.body[1..], EDITED.as_bytes());
    assert!(proxy.intercepted().is_empty());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server finishes")
        .expect("server task");
}

#[tokio::test]
async fn turning_intercept_off_releases_held_frames_unchanged() {
    let proxy = ProxyService::new();
    hold_server_responses(&proxy);
    let (mut client, _server) = status_exchange(&proxy).await;
    wait_for_held(&proxy).await;

    proxy
        .set_intercept_settings(InterceptSettings::default())
        .expect("settings");
    let response = client.receive().await;
    assert_eq!(&response.body[1..], ORIGINAL.as_bytes());
}

#[tokio::test]
async fn an_unframeable_replacement_keeps_the_frame_held() {
    let proxy = ProxyService::new();
    hold_server_responses(&proxy);
    let (_client, _server) = status_exchange(&proxy).await;
    let id = wait_for_held(&proxy).await;

    assert!(
        proxy
            .resolve_intercept(id, InterceptDecision::Replace(Bytes::new()))
            .is_err()
    );
    assert_eq!(
        proxy.intercepted().len(),
        1,
        "the operator can still fix it"
    );
    proxy
        .resolve_intercept(id, InterceptDecision::Drop)
        .expect("drop");
    assert!(proxy.intercepted().is_empty());
}
