//! Importing an external pcap or pcapng file.
//!
//! An imported capture has no process to attribute flows to, so Minecraft
//! traffic is recognised by server port instead. Everything up to reassembled
//! bytes — parsing, padding trimming, retransmission removal, reordering — is
//! the same code the live capture runs. Those bytes are then split into
//! Minecraft packets ([`crate::minecraft_stream`]): each packet becomes one
//! row with its state, id and name, and what cannot be framed — an encrypted
//! stream, a stream the capture joined part-way — is kept as labelled raw rows.

use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::{
    CaptureError, SideChannelFrame,
    minecraft_stream::{ImportedPacket, SplitOptions, Splitter},
    pcap::CaptureReader,
    pipeline::{FrameContext, Pipeline, PortPolicy},
};

/// What to import from a capture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportOptions {
    /// Flows touching one of these ports are imported, and the side on the
    /// port is the server. Empty imports every TCP and UDP flow.
    pub server_ports: Vec<u16>,
    /// The most rows one import will produce.
    pub max_frames: u64,
    /// Split TCP streams into Minecraft packets. Off stores each reassembled
    /// chunk as one raw row, for traffic that is not Minecraft.
    pub split_packets: bool,
    /// Protocol version to assume for connections whose handshake is not in
    /// the capture. Without it, such packets are named from their shape.
    pub protocol_version: Option<i32>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            server_ports: vec![25_565],
            max_frames: 2_000_000,
            split_packets: true,
            protocol_version: None,
        }
    }
}

/// How an import went. A file that is corrupt part-way through still imports
/// what came before the damage; `error` says where it stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub records_read: u64,
    /// Rows written: packets plus raw rows.
    pub frames_imported: u64,
    pub bytes_imported: u64,
    pub duplicates_removed: u64,
    pub segments_reordered: u64,
    pub gaps: u64,
    /// Minecraft packets split out of the streams.
    pub packets_decoded: u64,
    /// Rows kept as raw bytes: encrypted or unsynchronised stream data,
    /// undecodable frames, UDP datagrams.
    pub raw_rows: u64,
    pub connections: u64,
    /// Connections that switched to encryption; what follows the switch is
    /// raw, because the capture does not contain the shared secret.
    pub encrypted_connections: u64,
    /// Connections the capture joined after their handshake.
    pub midstream_connections: u64,
    /// Directions where no frame boundary was ever found.
    pub unsynchronised_streams: u64,
    /// Times a stream lost its framing (a hole in the capture, a bad length).
    pub desyncs: u64,
    /// Times a frame boundary was found by searching.
    pub resyncs: u64,
    /// Frames whose length was sound but whose contents were not.
    pub frame_errors: u64,
    /// Packets read from a `MineBurp` export as it described them.
    pub exported_packets: u64,
    /// The import stopped at `max_frames`.
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
struct Progress {
    rows: u64,
    bytes: u64,
    truncated: bool,
    sink_error: Option<String>,
}

impl Progress {
    fn deliver(
        &mut self,
        max_rows: u64,
        sink: &mut impl FnMut(ImportedPacket) -> Result<(), String>,
        row: ImportedPacket,
    ) {
        if self.sink_error.is_some() {
            return;
        }
        if self.rows >= max_rows {
            self.truncated = true;
            return;
        }
        self.rows += 1;
        self.bytes += row.detail.summary.size as u64;
        if let Err(error) = sink(row) {
            self.sink_error = Some(error);
        }
    }

    fn stopped(&self) -> bool {
        self.truncated || self.sink_error.is_some()
    }
}

fn feed(
    splitter: &mut Splitter,
    progress: &mut Progress,
    max_rows: u64,
    sink: &mut impl FnMut(ImportedPacket) -> Result<(), String>,
    frame: SideChannelFrame,
    context: &FrameContext,
) {
    if progress.stopped() {
        return;
    }
    splitter.push(frame, context, &mut |row| {
        progress.deliver(max_rows, sink, row);
    });
}

/// Reads a capture and hands each row to `sink`, in capture order.
///
/// `sink` returning an error stops the import; that error is the result.
pub fn import_capture(
    input: impl Read,
    options: &ImportOptions,
    mut sink: impl FnMut(ImportedPacket) -> Result<(), String>,
) -> Result<ImportSummary, CaptureError> {
    let mut reader = CaptureReader::new(input)
        .map_err(|error| CaptureError::Backend(format!("not a readable capture: {error}")))?;
    let mut pipeline = Pipeline::new(PortPolicy {
        server_ports: options.server_ports.clone(),
    });
    let mut splitter = Splitter::new(SplitOptions {
        raw_only: !options.split_packets,
        assumed_protocol: options.protocol_version,
    });
    let mut summary = ImportSummary::default();
    let mut progress = Progress::default();
    let max_rows = options.max_frames;
    let mut last_timestamp = i64::MIN;
    loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                summary.records_read += 1;
                last_timestamp = last_timestamp.max(record.timestamp_micros);
                pipeline.push(&record, &mut |frame, context| {
                    feed(
                        &mut splitter,
                        &mut progress,
                        max_rows,
                        &mut sink,
                        frame,
                        &context,
                    );
                });
                // Gaps are timed in capture time, not wall time.
                if summary.records_read % 256 == 0 {
                    pipeline.expire(last_timestamp, &mut |frame, context| {
                        feed(
                            &mut splitter,
                            &mut progress,
                            max_rows,
                            &mut sink,
                            frame,
                            &context,
                        );
                    });
                }
            }
            Ok(None) => break,
            Err(error) => {
                summary.error = Some(format!(
                    "stopped after {} record(s): {error}",
                    summary.records_read
                ));
                break;
            }
        }
        if progress.stopped() {
            break;
        }
    }
    pipeline.finish(&mut |frame, context| {
        feed(
            &mut splitter,
            &mut progress,
            max_rows,
            &mut sink,
            frame,
            &context,
        );
    });
    splitter.finish(&mut |row| progress.deliver(max_rows, &mut sink, row));
    if let Some(error) = progress.sink_error {
        return Err(CaptureError::Backend(error));
    }
    summary.frames_imported = progress.rows;
    summary.bytes_imported = progress.bytes;
    summary.truncated = progress.truncated;
    let stats = pipeline.stats().reassembly;
    summary.duplicates_removed = stats.duplicates;
    summary.segments_reordered = stats.reordered;
    summary.gaps = stats.gaps;
    let split = splitter.stats();
    summary.packets_decoded = split.packets;
    summary.raw_rows = split.raw_rows;
    summary.connections = split.connections;
    summary.encrypted_connections = split.encrypted_connections;
    summary.midstream_connections = split.midstream_connections;
    summary.unsynchronised_streams = split.unsynchronised_streams;
    summary.desyncs = split.desyncs;
    summary.resyncs = split.resyncs;
    summary.frame_errors = split.frame_errors;
    summary.exported_packets = split.exported_packets;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mineburp_core::{Direction, ProtocolState};
    use mineburp_protocol::{
        FrameCodec, Handshake, PacketFrame, PacketRegistry, encode_handshake, encode_var_i32,
    };

    use super::*;
    use crate::{packet::tests::ipv4_tcp, pcap::PcapngWriter};

    const PROTOCOL: i32 = 767;
    const THRESHOLD: Option<i32> = Some(256);

    type Endpoint = ([u8; 4], u16);

    /// One TCP connection written into a pcapng file, segment by segment.
    struct Session {
        writer: PcapngWriter<Vec<u8>>,
        interface: u32,
        client: Endpoint,
        server: Endpoint,
        client_next: u32,
        server_next: u32,
        time: i64,
        last_client: (u32, Vec<u8>),
    }

    impl Session {
        fn new(handshake: bool) -> Self {
            let mut writer = PcapngWriter::new(Vec::new(), "test").expect("writer");
            let interface = writer.add_interface(101, "raw").expect("interface");
            let mut session = Self {
                writer,
                interface,
                client: ([192, 168, 1, 2], 51_000),
                server: ([203, 0, 113, 9], 25_565),
                client_next: 1_000,
                server_next: 9_000,
                time: 1_700_000_000_000_000,
                last_client: (0, Vec::new()),
            };
            if handshake {
                let (client, server) = (session.client, session.server);
                session.write(client, server, 999, 0x02, &[]);
                session.write(server, client, 8_999, 0x12, &[]);
            }
            session
        }

        fn write(
            &mut self,
            from: Endpoint,
            to: Endpoint,
            sequence: u32,
            flags: u8,
            payload: &[u8],
        ) {
            self.time += 1_000;
            self.writer
                .write_packet(
                    self.interface,
                    self.time,
                    &ipv4_tcp(from, to, sequence, flags, payload),
                    None,
                )
                .expect("packet");
        }

        fn client(&mut self, payload: &[u8]) -> i64 {
            let (from, to, sequence) = (self.client, self.server, self.client_next);
            self.write(from, to, sequence, 0x18, payload);
            self.last_client = (sequence, payload.to_vec());
            self.client_next += u32::try_from(payload.len()).unwrap();
            self.time
        }

        fn server(&mut self, payload: &[u8]) -> i64 {
            let (from, to, sequence) = (self.server, self.client, self.server_next);
            self.write(from, to, sequence, 0x18, payload);
            self.server_next += u32::try_from(payload.len()).unwrap();
            self.time
        }

        /// Skips the server's next `length` bytes, as a capture that dropped
        /// a segment would.
        fn lose_server(&mut self, length: usize) {
            self.server_next += u32::try_from(length).unwrap();
        }

        fn retransmit_client(&mut self) {
            let (sequence, payload) = self.last_client.clone();
            let (from, to) = (self.client, self.server);
            self.write(from, to, sequence, 0x18, &payload);
        }

        fn bytes(self) -> Vec<u8> {
            self.writer.into_inner()
        }
    }

    fn frame(threshold: Option<i32>, id: i32, body: &[u8]) -> Vec<u8> {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(threshold);
        codec
            .encode(&PacketFrame {
                id,
                body: Bytes::copy_from_slice(body),
                compressed: false,
                wire_length: 0,
            })
            .expect("frame")
            .to_vec()
    }

    fn id(state: ProtocolState, direction: Direction, name: &str) -> i32 {
        PacketRegistry::packet_id(state, direction, name, Some(PROTOCOL))
            .unwrap_or_else(|| panic!("{name} has an id in {PROTOCOL}"))
    }

    fn string(text: &str) -> Vec<u8> {
        let mut output = encode_var_i32(i32::try_from(text.len()).unwrap()).to_vec();
        output.extend_from_slice(text.as_bytes());
        output
    }

    fn handshake(next_state: i32) -> Vec<u8> {
        let body = encode_handshake(&Handshake {
            protocol_version: PROTOCOL,
            server_address: "mc.example".into(),
            server_port: 25_565,
            next_state,
        })
        .expect("handshake");
        frame(None, 0, &body)
    }

    fn login_start() -> Vec<u8> {
        let mut body = string("Steve");
        body.extend_from_slice(&[7_u8; 16]);
        frame(None, 0, &body)
    }

    fn keep_alive(threshold: Option<i32>, direction: Direction, value: i64) -> Vec<u8> {
        frame(
            threshold,
            id(ProtocolState::Play, direction, "keep_alive"),
            &value.to_be_bytes(),
        )
    }

    fn import(bytes: &[u8], options: &ImportOptions) -> (Vec<ImportedPacket>, ImportSummary) {
        let mut rows = Vec::new();
        let summary = import_capture(bytes, options, |row| {
            rows.push(row);
            Ok(())
        })
        .expect("import");
        (rows, summary)
    }

    fn names(rows: &[ImportedPacket]) -> Vec<&str> {
        rows.iter()
            .map(|row| row.detail.summary.name.as_deref().unwrap_or("?"))
            .collect()
    }

    /// Bytes that do not compress.
    fn noise(length: usize, mut state: u32) -> Vec<u8> {
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one session, start to finish")]
    fn splits_an_offline_session_through_compression_into_packets() {
        let mut session = Session::new(true);
        // Two frames in one segment.
        session.client(&[handshake(2), login_start()].concat());
        session.server(&frame(None, 3, &encode_var_i32(256)));
        let mut success = vec![7_u8; 16];
        success.extend(string("Steve"));
        success.extend([0, 1]);
        session.server(&frame(THRESHOLD, 2, &success));
        session.client(&frame(THRESHOLD, 3, &[]));
        // A retransmission must not become a second packet.
        session.retransmit_client();
        // A compressed frame split across two segments.
        let registry = frame(
            THRESHOLD,
            id(
                ProtocolState::Configuration,
                Direction::ServerToClient,
                "registry_data",
            ),
            &[[0x0d_u8].as_slice(), &noise(2_000, 7)].concat(),
        );
        session.server(&registry[..300]);
        let completed_at = session.server(&registry[300..]);
        session.server(&frame(
            THRESHOLD,
            id(
                ProtocolState::Configuration,
                Direction::ServerToClient,
                "finish_configuration",
            ),
            &[],
        ));
        session.client(&frame(
            THRESHOLD,
            id(
                ProtocolState::Configuration,
                Direction::ClientToServer,
                "finish_configuration_ack",
            ),
            &[],
        ));
        session.server(&keep_alive(THRESHOLD, Direction::ServerToClient, 42));
        session.client(&keep_alive(THRESHOLD, Direction::ClientToServer, 42));

        let (rows, summary) = import(&session.bytes(), &ImportOptions::default());
        assert_eq!(
            names(&rows),
            [
                "handshake",
                "login_start",
                "set_compression",
                "login_success",
                "login_acknowledged",
                "registry_data",
                "finish_configuration",
                "finish_configuration_ack",
                "keep_alive",
                "keep_alive",
            ]
        );
        let states: Vec<ProtocolState> = rows.iter().map(|row| row.detail.summary.state).collect();
        assert_eq!(
            states,
            [
                ProtocolState::Handshake,
                ProtocolState::Login,
                ProtocolState::Login,
                ProtocolState::Login,
                ProtocolState::Login,
                ProtocolState::Configuration,
                ProtocolState::Configuration,
                ProtocolState::Configuration,
                ProtocolState::Play,
                ProtocolState::Play,
            ]
        );
        let registry_row = &rows[5].detail;
        assert!(registry_row.wire.compressed);
        assert_eq!(registry_row.summary.timestamp_micros, completed_at);
        assert_eq!(registry_row.summary.size, registry_row.logical_bytes.len());
        assert_eq!(rows[8].detail.summary.direction, Direction::ServerToClient);
        assert_eq!(
            rows[8].detail.summary.packet_id,
            Some(id(
                ProtocolState::Play,
                Direction::ServerToClient,
                "keep_alive"
            ))
        );
        // Ids and bodies are the logical frame: id VarInt, then the body.
        assert_eq!(rows[9].detail.logical_bytes[1..], 42_i64.to_be_bytes());
        let connection = &rows.last().expect("rows").connection;
        assert_eq!(connection.protocol_version, Some(PROTOCOL));
        assert_eq!(connection.minecraft_version.as_deref(), Some("1.21.1"));
        assert_eq!(connection.compression_threshold, THRESHOLD);
        assert_eq!(connection.state, ProtocolState::Play);
        assert_eq!(connection.packet_count, 10);
        assert!(
            rows.iter()
                .all(|row| row.detail.summary.connection_id == connection.id)
        );
        assert_eq!(summary.packets_decoded, 10);
        assert_eq!(summary.raw_rows, 0);
        assert_eq!(summary.connections, 1);
        assert_eq!(summary.duplicates_removed, 1);
        assert_eq!(summary.frames_imported, 10);
    }

    #[test]
    fn an_online_session_is_kept_raw_after_encryption_starts() {
        let mut session = Session::new(true);
        session.client(&[handshake(2), login_start()].concat());
        let mut request = string("");
        request.extend(encode_var_i32(4));
        request.extend([1, 2, 3, 4]);
        request.extend(encode_var_i32(4));
        request.extend([9, 9, 9, 9]);
        request.push(1);
        // The ciphertext after the request rides in the same segment.
        session.server(&[frame(None, 1, &request), vec![0xa7, 0x13, 0xfe]].concat());
        let mut response = encode_var_i32(4).to_vec();
        response.extend([5, 5, 5, 5]);
        response.extend(encode_var_i32(4));
        response.extend([6, 6, 6, 6]);
        session.client(&[frame(None, 1, &response), vec![0x44; 5]].concat());
        session.server(&[0x91; 40]);
        session.client(&[0x2c; 30]);

        let (rows, summary) = import(&session.bytes(), &ImportOptions::default());
        assert_eq!(
            names(&rows),
            [
                "handshake",
                "login_start",
                "encryption_request",
                "Encrypted TCP payload",
                "encryption_response",
                "Encrypted TCP payload",
                "Encrypted TCP payload",
                "Encrypted TCP payload",
            ]
        );
        let encrypted: Vec<&ImportedPacket> = rows
            .iter()
            .filter(|row| row.detail.summary.state == ProtocolState::Opaque)
            .collect();
        assert_eq!(encrypted.len(), 4);
        assert!(encrypted.iter().all(|row| row.detail.wire.encrypted));
        assert_eq!(
            encrypted[0].detail.logical_bytes.as_ref(),
            [0xa7, 0x13, 0xfe]
        );
        assert_eq!(
            encrypted[0].detail.summary.direction,
            Direction::ServerToClient
        );
        let connection = &rows.last().expect("rows").connection;
        assert!(connection.encrypted_client && connection.encrypted_server);
        assert_eq!(summary.encrypted_connections, 1);
        assert_eq!(summary.packets_decoded, 4);
        assert_eq!(summary.raw_rows, 4);
    }

    #[test]
    fn a_capture_that_starts_mid_stream_finds_its_frames() {
        let mut session = Session::new(false);
        // The tail of a frame whose start the capture missed.
        let mut server = vec![0x05, 0x01, 0x02];
        for value in 1..=4 {
            server.extend(keep_alive(THRESHOLD, Direction::ServerToClient, value));
        }
        server.extend(frame(
            THRESHOLD,
            id(ProtocolState::Play, Direction::ServerToClient, "ping"),
            &7_i32.to_be_bytes(),
        ));
        session.server(&server);
        let mut client = Vec::new();
        for value in 1..=3 {
            client.extend(keep_alive(THRESHOLD, Direction::ClientToServer, value));
        }
        session.client(&client);

        let options = ImportOptions {
            protocol_version: Some(PROTOCOL),
            ..ImportOptions::default()
        };
        let (rows, summary) = import(&session.bytes(), &options);
        assert_eq!(
            names(&rows),
            [
                "Unsynchronised TCP payload",
                "keep_alive",
                "keep_alive",
                "keep_alive",
                "keep_alive",
                "ping",
                "keep_alive",
                "keep_alive",
                "keep_alive",
            ]
        );
        assert_eq!(rows[0].detail.logical_bytes.as_ref(), [0x05, 0x01, 0x02]);
        assert!(
            rows[1..]
                .iter()
                .all(|row| row.detail.summary.state == ProtocolState::Play)
        );
        assert_eq!(rows[1].connection.protocol_version, Some(PROTOCOL));
        assert_eq!(summary.midstream_connections, 1);
        assert_eq!(summary.resyncs, 2);
        assert_eq!(summary.packets_decoded, 8);
        assert_eq!(summary.raw_rows, 1);
    }

    #[test]
    fn a_hole_in_the_capture_costs_one_resynchronisation() {
        let mut session = Session::new(false);
        let options = ImportOptions {
            protocol_version: Some(PROTOCOL),
            ..ImportOptions::default()
        };
        let mut opening = Vec::new();
        for value in 1..=3 {
            opening.extend(keep_alive(THRESHOLD, Direction::ServerToClient, value));
        }
        session.server(&opening);
        let lost = keep_alive(THRESHOLD, Direction::ServerToClient, 99);
        session.lose_server(lost.len());
        for value in 4..=7 {
            session.server(&keep_alive(THRESHOLD, Direction::ServerToClient, value));
        }
        let (rows, summary) = import(&session.bytes(), &options);
        assert_eq!(names(&rows), ["keep_alive"; 7]);
        assert_eq!(summary.gaps, 1);
        assert_eq!(summary.desyncs, 1);
        // Once to find the stream, once after the hole.
        assert_eq!(summary.resyncs, 2);
        assert_eq!(summary.raw_rows, 0);
        let values: Vec<i64> = rows
            .iter()
            .map(|row| i64::from_be_bytes(row.detail.logical_bytes[1..9].try_into().unwrap()))
            .collect();
        assert_eq!(values, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn a_stream_that_never_frames_is_kept_raw() {
        let mut session = Session::new(false);
        let noise = noise(1_000_000, 0x2545_f491);
        for chunk in noise.chunks(1_400) {
            session.server(chunk);
        }
        let (rows, summary) = import(&session.bytes(), &ImportOptions::default());
        let total: usize = rows.iter().map(|row| row.detail.logical_bytes.len()).sum();
        assert_eq!(total, noise.len(), "every byte is kept");
        assert!(
            rows.iter()
                .all(|row| row.detail.summary.state == ProtocolState::Opaque)
        );
        assert_eq!(summary.unsynchronised_streams, 1);
        assert_eq!(summary.packets_decoded, 0);
    }

    #[test]
    fn hostile_streams_never_panic_and_keep_every_byte() {
        let mut state = 0x9e37_79b9_u32;
        for round in 0..40_u32 {
            let mut session = Session::new(round % 2 == 0);
            let mut sent = 0;
            for _ in 0..30 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let length = (state % 900) as usize;
                let payload: Vec<u8> = (0..length)
                    .map(|index| {
                        // Mostly small values, so lengths and ids look plausible.
                        let byte = state
                            .rotate_left(u32::try_from(index % 32).unwrap())
                            .to_le_bytes()[0];
                        if round % 3 == 0 { byte } else { byte & 0x1f }
                    })
                    .collect();
                sent += payload.len();
                if state & 1 == 0 {
                    session.client(&payload);
                } else {
                    session.server(&payload);
                }
            }
            let (rows, _) = import(&session.bytes(), &ImportOptions::default());
            let kept: usize = rows.iter().map(|row| row.detail.wire.frame_length).sum();
            assert_eq!(kept, sent, "round {round}");
        }
    }

    #[test]
    fn unsplit_import_keeps_tcp_chunks_as_rows() {
        let mut writer = PcapngWriter::new(Vec::new(), "test").expect("writer");
        let interface = writer.add_interface(101, "raw").expect("interface");
        let client = ([192, 168, 1, 2], 51_000);
        let server = ([203, 0, 113, 9], 25_565);
        for (time, packet) in [
            (10, ipv4_tcp(client, server, 1, 0x02, b"")),
            (11, ipv4_tcp(client, server, 2, 0x18, b"\x10\x00")),
            (12, ipv4_tcp(server, client, 50, 0x18, b"\x02\x01")),
            (13, ipv4_tcp(([1, 1, 1, 1], 443), client, 9, 0x18, b"tls")),
        ] {
            writer
                .write_packet(interface, time, &packet, None)
                .expect("packet");
        }
        let options = ImportOptions {
            split_packets: false,
            ..ImportOptions::default()
        };
        let (rows, summary) = import(&writer.into_inner(), &options);
        assert_eq!(summary.records_read, 4);
        assert_eq!(summary.frames_imported, 2);
        assert!(summary.error.is_none());
        let first = &rows[0].detail;
        assert_eq!(first.logical_bytes.as_ref(), b"\x10\x00");
        assert_eq!(first.summary.state, ProtocolState::Opaque);
        let flow = first.summary.flow.as_ref().expect("flow");
        assert_eq!(flow.remote_address, "203.0.113.9:25565");
        assert!(flow.process_id.is_none());
        assert_eq!(first.summary.timestamp_micros, 11);
        assert_eq!(rows[0].connection.target.port, 25_565);
    }

    #[test]
    fn a_truncated_file_imports_what_precedes_the_damage() {
        let mut writer = PcapngWriter::new(Vec::new(), "test").expect("writer");
        let interface = writer.add_interface(101, "raw").expect("interface");
        let client = ([10, 0, 0, 1], 40_000);
        let server = ([10, 0, 0, 2], 25_565);
        writer
            .write_packet(
                interface,
                1,
                &ipv4_tcp(client, server, 1, 0x18, b"ok"),
                None,
            )
            .expect("packet");
        writer
            .write_packet(
                interface,
                2,
                &ipv4_tcp(client, server, 3, 0x18, b"cut"),
                None,
            )
            .expect("packet");
        let mut bytes = writer.into_inner();
        bytes.truncate(bytes.len() - 10);
        let summary = import_capture(bytes.as_slice(), &ImportOptions::default(), |_| Ok(()))
            .expect("partial import");
        assert_eq!(summary.bytes_imported, 2);
        assert!(summary.error.is_some());
    }

    #[test]
    fn rejects_a_file_that_is_not_a_capture() {
        assert!(
            import_capture(&b"hello world"[..], &ImportOptions::default(), |_| Ok(())).is_err()
        );
    }

    #[test]
    fn stops_at_the_row_limit() {
        let mut writer = PcapngWriter::new(Vec::new(), "test").expect("writer");
        let interface = writer.add_interface(101, "raw").expect("interface");
        let client = ([10, 0, 0, 1], 40_000);
        let server = ([10, 0, 0, 2], 25_565);
        for index in 0..10_u32 {
            writer
                .write_packet(
                    interface,
                    i64::from(index),
                    &ipv4_tcp(client, server, index, 0x18, b"x"),
                    None,
                )
                .expect("packet");
        }
        let options = ImportOptions {
            max_frames: 3,
            split_packets: false,
            ..ImportOptions::default()
        };
        let summary =
            import_capture(writer.into_inner().as_slice(), &options, |_| Ok(())).expect("import");
        assert_eq!(summary.frames_imported, 3);
        assert!(summary.truncated);
    }
}
