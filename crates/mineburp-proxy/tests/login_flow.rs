//! Drives a complete online-mode login through the proxy.
//!
//! The unit tests cover the encryption bridge and the state machine in
//! isolation, which is how a session that could not actually complete a login
//! went unnoticed. This runs a real client and a real server against a real
//! session: handshake, encrypted key exchange, compression, and the 1.20.2+
//! configuration phase, over sockets.

use std::{sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use mineburp_core::Target;
use mineburp_protocol::{
    EncryptionRequest, EncryptionResponse, FrameCodec, Handshake, MinecraftCipher, PacketFrame,
    encode_handshake, encode_var_i32,
};
use mineburp_proxy::{ProxyEvent, ProxyService, SessionOptions};
use mineburp_session::{SessionJoinProvider, SessionJoinRequest};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    rand_core::OsRng,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

const PROTOCOL_VERSION: i32 = 767;
const COMPRESSION_THRESHOLD: i32 = 2;
const SHARED_SECRET: [u8; 16] = [0x5a; 16];
const SERVER_VERIFY_TOKEN: [u8; 4] = [9, 8, 7, 6];

/// Stands in for the client-assistance broker: the join always succeeds.
#[derive(Debug)]
struct AlwaysJoins;

#[async_trait::async_trait]
impl SessionJoinProvider for AlwaysJoins {
    async fn join_server(&self, request: &SessionJoinRequest) -> Result<(), String> {
        assert_ne!(
            request.client_server_hash, request.upstream_server_hash,
            "the client and upstream hashes must differ; the proxy substitutes its own key"
        );
        Ok(())
    }
}

/// One end of a Minecraft connection: framing plus its own cipher state.
struct Link {
    stream: TcpStream,
    buffer: BytesMut,
    codec: FrameCodec,
    cipher: Option<MinecraftCipher>,
}

impl Link {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            codec: FrameCodec::default(),
            cipher: None,
        }
    }

    fn enable_encryption(&mut self) {
        self.cipher = Some(MinecraftCipher::new(SHARED_SECRET));
    }

    fn set_compression(&mut self, threshold: i32) {
        self.codec.set_compression_threshold(Some(threshold));
    }

    async fn send(&mut self, id: i32, body: &[u8]) {
        let frame = PacketFrame {
            id,
            body: Bytes::copy_from_slice(body),
            compressed: false,
            wire_length: 0,
        };
        let mut bytes = self.codec.encode(&frame).expect("encode").to_vec();
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.encrypt(&mut bytes);
        }
        self.stream.write_all(&bytes).await.expect("write");
        self.stream.flush().await.expect("flush");
    }

    async fn receive(&mut self) -> PacketFrame {
        loop {
            if let Some(frame) = self.codec.try_decode(&mut self.buffer).expect("decode") {
                return frame;
            }
            let mut chunk = vec![0_u8; 8 * 1024];
            let read = self.stream.read(&mut chunk).await.expect("read");
            assert_ne!(read, 0, "the peer closed the connection mid-login");
            chunk.truncate(read);
            if let Some(cipher) = self.cipher.as_mut() {
                cipher.decrypt(&mut chunk);
            }
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

fn string_bytes(value: &str) -> Vec<u8> {
    let mut output = encode_var_i32(i32::try_from(value.len()).unwrap()).to_vec();
    output.extend_from_slice(value.as_bytes());
    output
}

/// The upstream server: issues the key exchange, then compresses and encrypts.
async fn run_server(listener: TcpListener, private_key: RsaPrivateKey, should_authenticate: bool) {
    let (stream, _) = listener.accept().await.expect("accept");
    let mut link = Link::new(stream);

    let handshake = link.receive().await;
    assert_eq!(
        handshake.id, 0,
        "first server-bound packet must be handshake"
    );
    let decoded = mineburp_protocol::decode_handshake(&handshake.body).expect("handshake");
    assert_eq!(decoded.next_state, 2, "the client asked to log in");

    let login_start = link.receive().await;
    assert_eq!(login_start.id, 0, "login start");

    let public_key_der = RsaPublicKey::from(&private_key)
        .to_public_key_der()
        .expect("server key");
    let request = EncryptionRequest {
        server_id: String::new(),
        public_key_der: Bytes::copy_from_slice(public_key_der.as_ref()),
        verify_token: Bytes::copy_from_slice(&SERVER_VERIFY_TOKEN),
        trailing: Bytes::new(),
        should_authenticate,
    };
    link.send(1, &request.encode().expect("encode request"))
        .await;

    let response_frame = link.receive().await;
    assert_eq!(response_frame.id, 1, "encryption response");
    let response =
        EncryptionResponse::decode(&response_frame.body, PROTOCOL_VERSION).expect("response");
    let secret = private_key
        .decrypt(Pkcs1v15Encrypt, &response.encrypted_secret)
        .expect("decrypt secret");
    assert_eq!(
        secret.as_slice(),
        SHARED_SECRET,
        "the proxy must forward the same shared secret upstream"
    );
    let token = private_key
        .decrypt(Pkcs1v15Encrypt, &response.encrypted_verify_token)
        .expect("decrypt token");
    assert_eq!(token.as_slice(), SERVER_VERIFY_TOKEN, "verify token");
    link.enable_encryption();

    // Set Compression is itself uncompressed; everything after it is not.
    link.send(3, &encode_var_i32(COMPRESSION_THRESHOLD)).await;
    link.set_compression(COMPRESSION_THRESHOLD);

    let mut login_success = string_bytes("MineBurpTester");
    login_success.extend_from_slice(&[0_u8; 16]);
    link.send(2, &login_success).await;

    let acknowledged = link.receive().await;
    assert_eq!(acknowledged.id, 3, "login acknowledged");

    // Configuration, then the empty finish/acknowledge pair into play.
    link.send(0x0e, &string_bytes("minecraft:brand")).await;
    link.send(0x03, &[]).await;
    let finish = link.receive().await;
    assert_eq!(finish.id, 0x03, "acknowledge finish configuration");
    assert!(
        finish.body.is_empty(),
        "the acknowledgement carries no body"
    );

    link.send(0x22, b"play-payload").await;
}

/// Fails the test if the proxy asks for a join the server did not want.
#[derive(Debug)]
struct NeverJoins;

#[async_trait::async_trait]
impl SessionJoinProvider for NeverJoins {
    async fn join_server(&self, _request: &SessionJoinRequest) -> Result<(), String> {
        Err("the server said not to authenticate, so no join may be made".into())
    }
}

#[tokio::test]
async fn online_mode_login_completes_through_the_proxy() {
    login_through_the_proxy(true, Arc::new(AlwaysJoins)).await;
}

/// A 1.20.5+ server can encrypt without authenticating; the vanilla client
/// then skips its join, so the proxy must not wait for one.
#[tokio::test]
async fn a_server_that_skips_authentication_gets_no_join() {
    login_through_the_proxy(false, Arc::new(NeverJoins)).await;
}

async fn login_through_the_proxy(
    should_authenticate: bool,
    provider: Arc<dyn SessionJoinProvider>,
) {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("server key");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(run_server(listener, private_key, should_authenticate));

    let proxy = ProxyService::new();
    let mut events = proxy.subscribe();
    proxy.set_session_join_provider(Some(provider));
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
                next_state: 2,
            })
            .expect("handshake"),
        )
        .await;
    let mut login_start = string_bytes("MineBurpTester");
    login_start.extend_from_slice(&[0_u8; 16]);
    client.send(0, &login_start).await;

    let request_frame = client.receive().await;
    assert_eq!(request_frame.id, 1, "encryption request");
    let request = EncryptionRequest::decode(&request_frame.body).expect("request");
    assert_eq!(
        request.should_authenticate, should_authenticate,
        "the client sees the server's authentication choice"
    );
    let proxy_key = RsaPublicKey::from_public_key_der(&request.public_key_der)
        .expect("the proxy must present its own key");
    let response = EncryptionResponse {
        encrypted_secret: Bytes::from(
            proxy_key
                .encrypt(&mut OsRng, Pkcs1v15Encrypt, &SHARED_SECRET)
                .expect("encrypt secret"),
        ),
        encrypted_verify_token: Bytes::from(
            proxy_key
                .encrypt(&mut OsRng, Pkcs1v15Encrypt, &request.verify_token)
                .expect("encrypt token"),
        ),
        signature: None,
    };
    client
        .send(
            1,
            &response.encode(PROTOCOL_VERSION).expect("encode response"),
        )
        .await;
    client.enable_encryption();

    let compression = client.receive().await;
    assert_eq!(compression.id, 3, "set compression reaches the client");
    client.set_compression(COMPRESSION_THRESHOLD);

    let success = client.receive().await;
    assert_eq!(success.id, 2, "login success reaches the client");

    client.send(3, &[]).await;

    let brand = client.receive().await;
    assert_eq!(brand.id, 0x0e, "configuration payload reaches the client");
    let finish = client.receive().await;
    assert_eq!(finish.id, 0x03, "finish configuration reaches the client");
    client.send(0x03, &[]).await;

    let play = client.receive().await;
    assert_eq!(play.body.as_ref(), b"play-payload", "play traffic flows");

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server side must finish")
        .expect("the server task must not panic");

    // A finished session leaves the live table; its last published snapshot
    // is the record of what the proxy negotiated.
    let mut last = None;
    while let Ok(Ok(event)) = tokio::time::timeout(Duration::from_millis(500), events.recv()).await
    {
        if let ProxyEvent::Connection(connection) = event {
            last = Some(connection);
        }
    }
    let session = last.expect("the session published its snapshot");
    assert!(
        session.encrypted_client && session.encrypted_server,
        "both links encrypted"
    );
    assert_eq!(
        session.compression_threshold,
        Some(COMPRESSION_THRESHOLD),
        "the proxy tracked the negotiated compression threshold"
    );
}
