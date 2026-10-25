//! A tiny status-phase peer shared by the session-level tests.

use bytes::{Bytes, BytesMut};
use mineburp_protocol::{FrameCodec, PacketFrame, encode_var_i32};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

pub const PROTOCOL_VERSION: i32 = 767;
pub const ORIGINAL: &str = r#"{"description":"Original"}"#;

pub struct Link {
    stream: TcpStream,
    buffer: BytesMut,
    codec: FrameCodec,
}

impl Link {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            codec: FrameCodec::default(),
        }
    }

    pub async fn send(&mut self, id: i32, body: &[u8]) {
        let frame = PacketFrame {
            id,
            body: Bytes::copy_from_slice(body),
            compressed: false,
            wire_length: 0,
        };
        let bytes = self.codec.encode(&frame).expect("encode");
        self.stream.write_all(&bytes).await.expect("write");
        self.stream.flush().await.expect("flush");
    }

    pub async fn receive(&mut self) -> PacketFrame {
        loop {
            if let Some(frame) = self.codec.try_decode(&mut self.buffer).expect("decode") {
                return frame;
            }
            let mut chunk = vec![0_u8; 8 * 1024];
            let read = self.stream.read(&mut chunk).await.expect("read");
            assert_ne!(read, 0, "the peer closed the connection early");
            chunk.truncate(read);
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

pub fn string_bytes(value: &str) -> Vec<u8> {
    let mut output = encode_var_i32(i32::try_from(value.len()).unwrap()).to_vec();
    output.extend_from_slice(value.as_bytes());
    output
}

/// A status server: reads the handshake and the request, answers with a list ping.
pub async fn run_server(listener: TcpListener) {
    let (stream, _) = listener.accept().await.expect("accept");
    let mut link = Link::new(stream);

    let handshake = link.receive().await;
    assert_eq!(handshake.id, 0, "handshake first");
    let request = link.receive().await;
    assert_eq!(request.id, 0, "status request");
    link.send(0, &string_bytes(ORIGINAL)).await;
}
