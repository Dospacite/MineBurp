//! Session behaviour that only shows over real sockets: what is delivered when
//! a peer closes, what may overtake a held frame, how the handshake address is
//! forwarded, and when the live table forgets a session.

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{Link, ORIGINAL, PROTOCOL_VERSION, string_bytes};
use mineburp_core::{Direction, ProtocolState, Target};
use mineburp_protocol::{Handshake, PacketRegistry, decode_handshake, encode_handshake};
use mineburp_proxy::{
    InterceptDecision, InterceptSettings, LinkConditions, NetworkConditions, ProxyError,
    ProxyService, SessionOptions,
};
use mineburp_session::{TransparentRouteProvider as _, TransparentTarget};
use tokio::net::{TcpListener, TcpStream};

mod common;

const CLIENT_ADDRESS: &str = "play.example.test";

fn handshake(next_state: i32) -> Vec<u8> {
    encode_handshake(&Handshake {
        protocol_version: PROTOCOL_VERSION,
        server_address: CLIENT_ADDRESS.into(),
        server_port: 25_565,
        next_state,
    })
    .expect("handshake")
    .to_vec()
}

fn play_id(direction: Direction, name: &str) -> i32 {
    PacketRegistry::packet_id(ProtocolState::Play, direction, name, Some(PROTOCOL_VERSION))
        .unwrap_or_else(|| panic!("{name} is tabulated"))
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn session(proxy: &ProxyService, listener: &TcpListener) -> Link {
    session_to(proxy, listener.local_addr().expect("addr").port()).await
}

async fn session_to(proxy: &ProxyService, port: u16) -> Link {
    let snapshot = proxy
        .start_session(SessionOptions::new(Target {
            host: "127.0.0.1".into(),
            port,
        }))
        .await
        .expect("session");
    Link::new(
        TcpStream::connect(&snapshot.listener_address)
            .await
            .expect("connect"),
    )
}

/// Takes both peers through an offline-mode login and configuration into play.
async fn enter_play(client: &mut Link, server: &mut Link) {
    client.send(0, &handshake(2)).await;
    let mut login_start = string_bytes("MineBurpTester");
    login_start.extend_from_slice(&[0_u8; 16]);
    client.send(0, &login_start).await;
    assert_eq!(server.receive().await.id, 0, "handshake");
    assert_eq!(server.receive().await.id, 0, "login start");

    let mut success = vec![0_u8; 16];
    success.extend(string_bytes("MineBurpTester"));
    success.push(0);
    server.send(2, &success).await;
    assert_eq!(client.receive().await.id, 2, "login success");
    client.send(3, &[]).await;
    assert_eq!(server.receive().await.id, 3, "login acknowledged");

    server.send(0x03, &[]).await;
    assert_eq!(client.receive().await.id, 0x03, "finish configuration");
    client.send(0x03, &[]).await;
    assert_eq!(server.receive().await.id, 0x03, "acknowledge finish");
}

#[tokio::test]
async fn keep_alives_overtake_a_held_frame() {
    let proxy = ProxyService::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mut client = session(&proxy, &listener).await;
    let (stream, _) = listener.accept().await.expect("accept");
    let mut server = Link::new(stream);
    enter_play(&mut client, &mut server).await;
    // Holding from here on: configuration frames would be held too.
    proxy
        .set_intercept_settings(InterceptSettings {
            enabled: true,
            client_to_server: false,
            server_to_client: true,
            ..InterceptSettings::default()
        })
        .expect("settings");

    let chat = play_id(Direction::ServerToClient, "system_chat");
    let keep_alive = play_id(Direction::ServerToClient, "keep_alive");
    server.send(chat, &string_bytes("held")).await;
    wait_until(|| !proxy.intercepted().is_empty(), "the held frame").await;
    server.send(keep_alive, &42_i64.to_be_bytes()).await;

    let first = tokio::time::timeout(Duration::from_secs(2), client.receive())
        .await
        .expect("the keep-alive is not stuck behind the held frame");
    assert_eq!(first.id, keep_alive);

    let held = proxy.intercepted()[0].id;
    proxy
        .resolve_intercept(held, InterceptDecision::Forward)
        .expect("forward");
    assert_eq!(client.receive().await.id, chat, "the held frame follows");
}

#[tokio::test]
async fn a_held_frame_is_forwarded_when_its_deadline_passes() {
    let proxy = ProxyService::new();
    proxy
        .set_intercept_settings(InterceptSettings {
            enabled: true,
            client_to_server: false,
            server_to_client: true,
            auto_forward_after_ms: Some(150),
            ..InterceptSettings::default()
        })
        .expect("settings");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(common::run_server(listener));
    let mut client = session_to(&proxy, port).await;
    client.send(0, &handshake(1)).await;
    client.send(0, &[]).await;

    wait_until(|| !proxy.intercepted().is_empty(), "the held frame").await;
    let held = &proxy.intercepted()[0];
    let deadline = held.deadline_micros.expect("a deadline is reported");
    assert!(deadline > held.held_at_micros);

    let response = tokio::time::timeout(Duration::from_secs(2), client.receive())
        .await
        .expect("forwarded without a verdict");
    assert_eq!(&response.body[1..], ORIGINAL.as_bytes());
    assert!(proxy.intercepted().is_empty());
    let _ = server.await;
}

#[tokio::test]
async fn queued_frames_reach_the_client_after_the_server_closes() {
    let proxy = ProxyService::new();
    // Holds the response in the writer long after the server has gone.
    proxy
        .set_network_conditions(NetworkConditions {
            server_to_client: LinkConditions {
                delay_ms: 300,
                ..LinkConditions::default()
            },
            ..NetworkConditions::default()
        })
        .expect("conditions");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mut client = session(&proxy, &listener).await;
    let started = Instant::now();
    client.send(0, &handshake(1)).await;
    client.send(0, &[]).await;
    let (stream, _) = listener.accept().await.expect("accept");
    let mut server = Link::new(stream);
    server.receive().await;
    server.receive().await;
    server.send(0, &string_bytes(ORIGINAL)).await;
    drop(server);

    let response = client.receive().await;
    assert_eq!(&response.body[1..], ORIGINAL.as_bytes());
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "the configured delay applied"
    );
    wait_until(|| proxy.sessions().is_empty(), "the session to be removed").await;
}

#[tokio::test]
async fn invalid_network_conditions_are_refused() {
    let proxy = ProxyService::new();
    let result = proxy.set_network_conditions(NetworkConditions {
        client_to_server: LinkConditions {
            bandwidth_bytes_per_second: Some(0),
            ..LinkConditions::default()
        },
        ..NetworkConditions::default()
    });
    assert!(matches!(result, Err(ProxyError::NetworkConditions(_))));
    assert_eq!(proxy.network_conditions(), NetworkConditions::default());
}

#[tokio::test]
async fn routed_clients_keep_their_handshake_address() {
    let proxy = ProxyService::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let route = proxy
        .open_transparent_route(TransparentTarget {
            host: "127.0.0.1".into(),
            port,
        })
        .await
        .expect("route");
    let mut client = Link::new(
        TcpStream::connect(("127.0.0.1", route))
            .await
            .expect("connect"),
    );
    client.send(0, &handshake(1)).await;
    let (stream, _) = listener.accept().await.expect("accept");
    let mut server = Link::new(stream);
    let forwarded = decode_handshake(&server.receive().await.body).expect("handshake");
    assert_eq!(forwarded.server_address, CLIENT_ADDRESS);
    assert_eq!(forwarded.server_port, 25_565);
}

#[tokio::test]
async fn direct_sessions_rewrite_the_handshake_to_the_target() {
    let proxy = ProxyService::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let mut client = session(&proxy, &listener).await;
    client.send(0, &handshake(1)).await;
    let (stream, _) = listener.accept().await.expect("accept");
    let mut server = Link::new(stream);
    let forwarded = decode_handshake(&server.receive().await.body).expect("handshake");
    assert_eq!(forwarded.server_address, "127.0.0.1");
    assert_eq!(forwarded.server_port, port);
}

#[tokio::test]
async fn repeater_refuses_to_inject_during_login() {
    let proxy = ProxyService::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mut client = session(&proxy, &listener).await;
    client.send(0, &handshake(2)).await;
    let (_server, _) = listener.accept().await.expect("accept");
    wait_until(
        || {
            proxy
                .sessions()
                .first()
                .is_some_and(|session| session.state == ProtocolState::Login)
        },
        "login",
    )
    .await;
    let id = proxy.sessions()[0].id;
    let result = proxy
        .repeater_send(id, Direction::ClientToServer, Bytes::from_static(&[0, 1]))
        .await;
    assert!(matches!(result, Err(ProxyError::ConnectionNotReady(_))));
}
