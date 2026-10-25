//! Writing history out for other tools.

use std::{collections::HashMap, io::Write};

use mineburp_capture::{EXPORT_INTERFACE, PcapngWriter, SYNTHETIC_LINKTYPE, SyntheticStreams};
use mineburp_core::{Direction, PacketSummary, ProtocolState};
use mineburp_project::{PacketQuery, ProjectStore};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapExportSummary {
    pub packets: u64,
    pub connections: u64,
}

/// Writes every packet `query` matches as pcapng, oldest first.
///
/// Each connection becomes one synthetic TCP stream. A decoded packet is
/// written as an uncompressed Minecraft frame — `VarInt` length, then the
/// packet id and body — so the stream reads like a connection with
/// compression and encryption switched off. A row that was never decoded
/// (passive capture, an encrypted stream) is written as the raw bytes it holds.
/// Every packet carries a comment the bundled Wireshark dissector reads:
/// `mineburp: name=…; state=…; direction=…; id=…; framing=…`.
pub fn write_pcapng(
    store: &ProjectStore,
    query: &PacketQuery,
    output: impl Write,
) -> Result<PcapExportSummary, String> {
    let mut writer = PcapngWriter::new(output, "MineBurp").map_err(|error| error.to_string())?;
    let interface = writer
        .add_interface(SYNTHETIC_LINKTYPE, EXPORT_INTERFACE)
        .map_err(|error| error.to_string())?;
    let mut streams = SyntheticStreams::default();
    let mut server_ports: HashMap<Uuid, u16> = HashMap::new();
    let mut last_timestamp = 0_i64;
    let mut summary = PcapExportSummary::default();
    store
        .for_each_packet(query, 500, |packet, payload| {
            let port = if let Some(port) = server_ports.get(&packet.connection_id) {
                *port
            } else {
                let port = store
                    .connection(packet.connection_id)
                    .ok()
                    .flatten()
                    .map_or(25_565, |connection| connection.target.port);
                server_ports.insert(packet.connection_id, port);
                summary.connections += 1;
                port
            };
            let framed = packet.state != ProtocolState::Opaque;
            let bytes = if framed {
                let mut frame = Vec::with_capacity(payload.len() + 5);
                write_var_u32(&mut frame, u32::try_from(payload.len()).unwrap_or(u32::MAX));
                frame.extend_from_slice(payload);
                frame
            } else {
                payload.to_vec()
            };
            let segments = streams.segments(
                packet.connection_id,
                port,
                packet.direction == Direction::ClientToServer,
                &bytes,
            );
            // The comment goes on the packet's *last* segment: a dissector
            // reassembling a packet split across segments sees the whole
            // packet, and its frame's comment, on that one.
            let last = segments.len().saturating_sub(1);
            let comment = comment(packet, framed);
            for (index, segment) in segments.iter().enumerate() {
                let note = (index == last).then_some(comment.as_str());
                writer
                    .write_packet(interface, packet.timestamp_micros, segment, note)
                    .map_err(|error| error.to_string())?;
            }
            last_timestamp = last_timestamp.max(packet.timestamp_micros);
            summary.packets += 1;
            Ok(())
        })
        .map_err(|error| error.to_string())?;
    for segment in streams.close_all() {
        writer
            .write_packet(interface, last_timestamp, &segment, None)
            .map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())?;
    Ok(summary)
}

fn comment(packet: &PacketSummary, framed: bool) -> String {
    let state = serde_json::to_value(packet.state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let disposition = serde_json::to_value(packet.disposition)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    // `;` separates fields, so it is replaced in the free-text name.
    let name = packet.name.as_deref().unwrap_or("").replace(';', ",");
    format!(
        "mineburp: name={name}; state={state}; direction={}; id={}; protocol={}; disposition={disposition}; framing={}; row={}; connection={}",
        match packet.direction {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        },
        packet
            .packet_id
            .map(|id| format!("0x{id:02x}"))
            .unwrap_or_default(),
        packet
            .protocol_version
            .map(|version| version.to_string())
            .unwrap_or_default(),
        if framed { "frame" } else { "raw" },
        packet.id,
        packet.connection_id,
    )
}

fn write_var_u32(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            output.push(byte);
            return;
        }
        output.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mineburp_capture::{CaptureReader, ImportOptions, ImportedPacket, import_capture};
    use mineburp_core::{
        ConnectionSnapshot, ConnectionStatus, Disposition, PacketDetail, Target, TrafficSource,
        WireMetadata,
    };
    use mineburp_project::ProjectOptions;

    use super::*;

    fn reimport(output: &[u8]) -> (Vec<ImportedPacket>, mineburp_capture::ImportSummary) {
        let mut rows = Vec::new();
        let summary = import_capture(
            output,
            &ImportOptions {
                server_ports: vec![25_570],
                ..ImportOptions::default()
            },
            |row| {
                rows.push(row);
                Ok(())
            },
        )
        .unwrap();
        (rows, summary)
    }

    fn snapshot(id: Uuid) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id,
            target: Target {
                host: "mc.example".into(),
                port: 25_570,
            },
            listener_address: "127.0.0.1:1".into(),
            status: ConnectionStatus::Closed,
            state: ProtocolState::Play,
            protocol_version: Some(767),
            minecraft_version: None,
            loader: None,
            compression_threshold: None,
            encrypted_client: true,
            encrypted_server: true,
            packet_count: 0,
            byte_count: 0,
            last_error: None,
        }
    }

    fn packet(
        connection: Uuid,
        direction: Direction,
        state: ProtocolState,
        payload: &[u8],
    ) -> PacketDetail {
        PacketDetail {
            summary: PacketSummary {
                id: 0,
                sequence: 0,
                connection_id: connection,
                timestamp_micros: 1_700_000_000_000_000,
                source: TrafficSource::Minecraft,
                direction,
                state,
                protocol_version: Some(767),
                packet_id: Some(0),
                name: Some("chat; message".into()),
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

    #[test]
    fn exported_streams_carry_framed_packets_and_comments() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("export.mineburp"),
            "Export",
            ProjectOptions::default(),
        )
        .unwrap();
        let connection = Uuid::from_u128(5);
        store.save_connection(&snapshot(connection)).unwrap();
        store
            .insert_packets(&[
                packet(
                    connection,
                    Direction::ClientToServer,
                    ProtocolState::Handshake,
                    b"\x00\x01",
                ),
                packet(
                    connection,
                    Direction::ServerToClient,
                    ProtocolState::Play,
                    b"\x05hello",
                ),
                packet(
                    connection,
                    Direction::ServerToClient,
                    ProtocolState::Opaque,
                    b"\xde\xad",
                ),
            ])
            .unwrap();
        let mut output = Vec::new();
        let summary = write_pcapng(&store, &PacketQuery::default(), &mut output).unwrap();
        assert_eq!(
            summary,
            PcapExportSummary {
                packets: 3,
                connections: 1
            }
        );
        // `MINEBURP_EXPORT_SAMPLE=/path.pcapng` keeps the file, for checking
        // the Wireshark dissector against a real export.
        if let Some(path) = std::env::var_os("MINEBURP_EXPORT_SAMPLE") {
            std::fs::write(path, &output).unwrap();
        }

        // Handshake, three data segments, two FINs.
        let mut reader = CaptureReader::new(output.as_slice()).unwrap();
        let mut records = 0;
        while reader.next_record().unwrap().is_some() {
            records += 1;
        }
        assert_eq!(records, 3 + 3 + 2);
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("mineburp: name=chat, message; state=handshake; direction=c2s"));
        assert!(text.contains("framing=raw"));

        // Reading the export back yields the packets as they were recorded:
        // states, framing and names come from the comments, so a decrypted
        // play packet stays a play packet rather than ciphertext.
        let (rows, summary) = reimport(&output);
        assert_eq!(summary.exported_packets, 2);
        assert_eq!(rows.len(), 3);
        let first = &rows[0].detail.summary;
        assert_eq!(first.state, ProtocolState::Handshake);
        assert_eq!(first.name.as_deref(), Some("chat, message"));
        assert_eq!(first.packet_id, Some(0));
        assert_eq!(first.protocol_version, Some(767));
        assert_eq!(first.disposition, Disposition::Forwarded);
        assert_eq!(rows[0].detail.logical_bytes.as_ref(), b"\x00\x01");
        assert_eq!(rows[1].detail.summary.state, ProtocolState::Play);
        assert_eq!(rows[1].detail.summary.packet_id, Some(5));
        assert_eq!(rows[1].detail.summary.direction, Direction::ServerToClient);
        assert_eq!(rows[1].detail.logical_bytes.as_ref(), b"\x05hello");
        assert_eq!(rows[2].detail.summary.state, ProtocolState::Opaque);
        assert_eq!(rows[2].detail.logical_bytes.as_ref(), b"\xde\xad");
        assert_eq!(rows[2].connection.protocol_version, Some(767));
        assert_eq!(rows[2].connection.target.port, 25_570);
    }

    #[test]
    fn a_large_packet_spans_segments_and_reads_back_whole() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProjectStore::create(
            directory.path().join("large.mineburp"),
            "Large",
            ProjectOptions::default(),
        )
        .unwrap();
        let connection = Uuid::from_u128(6);
        store.save_connection(&snapshot(connection)).unwrap();
        let body = (0..70_000_u32)
            .map(|value| u8::try_from(value % 251).unwrap())
            .collect::<Vec<_>>();
        store
            .insert_packets(&[packet(
                connection,
                Direction::ServerToClient,
                ProtocolState::Play,
                &body,
            )])
            .unwrap();
        let mut output = Vec::new();
        write_pcapng(&store, &PacketQuery::default(), &mut output).unwrap();
        if let Some(path) = std::env::var_os("MINEBURP_EXPORT_SAMPLE_LARGE") {
            std::fs::write(path, &output).unwrap();
        }
        let (rows, _) = reimport(&output);
        assert_eq!(rows.len(), 1, "one packet across three segments");
        assert_eq!(rows[0].detail.logical_bytes.as_ref(), body.as_slice());
        assert_eq!(rows[0].detail.summary.state, ProtocolState::Play);
        // VarInt(70 000) is three bytes.
        assert_eq!(rows[0].detail.wire.frame_length, 3 + body.len());
    }

    #[test]
    fn var_ints_encode_like_the_protocol() {
        for (value, expected) in [
            (0_u32, vec![0_u8]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (2_097_151, vec![0xff, 0xff, 0x7f]),
        ] {
            let mut output = Vec::new();
            write_var_u32(&mut output, value);
            assert_eq!(output, expected);
        }
    }
}
