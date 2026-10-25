//! Synthetic TCP/IPv4 streams for exporting decrypted traffic as pcapng.
//!
//! A proxied connection's packets exist in the project only as logical frames:
//! decrypted, decompressed, without their TCP segments. To make them readable
//! in Wireshark each connection is given a pair of addresses and a TCP stream
//! of its own, opened with a three-way handshake so the dissector sees a
//! well-formed conversation, and every frame becomes one or more segments with
//! correct sequence numbers and checksums.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use uuid::Uuid;

/// `LINKTYPE_RAW`: each record is a bare IP packet.
pub const SYNTHETIC_LINKTYPE: u16 = 101;

/// Payload carried per synthetic segment; IPv4's 16-bit total length bounds it.
const MAX_SEGMENT_PAYLOAD: usize = 32 * 1024;

#[derive(Debug, Clone, Copy)]
struct Flow {
    client: SocketAddrV4,
    server: SocketAddrV4,
    /// Next sequence number each side will send.
    client_next: u32,
    server_next: u32,
    closed: bool,
}

/// The endpoints a connection was given in the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticEndpoints {
    pub client: SocketAddrV4,
    pub server: SocketAddrV4,
}

/// Allocates one synthetic TCP stream per connection id.
#[derive(Debug, Default)]
pub struct SyntheticStreams {
    flows: HashMap<Uuid, Flow>,
    allocated: u32,
}

impl SyntheticStreams {
    /// Raw IPv4 packets carrying `payload` on `connection`'s stream. The first
    /// call for a connection also returns its handshake.
    pub fn segments(
        &mut self,
        connection: Uuid,
        server_port: u16,
        client_sent: bool,
        payload: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let flow = self.flow(connection, server_port, &mut packets);
        for chunk in payload.chunks(MAX_SEGMENT_PAYLOAD) {
            let (source, destination, sequence, acknowledgement) = if client_sent {
                (flow.client, flow.server, flow.client_next, flow.server_next)
            } else {
                (flow.server, flow.client, flow.server_next, flow.client_next)
            };
            packets.push(tcp_packet(
                source,
                destination,
                sequence,
                acknowledgement,
                FLAG_ACK | FLAG_PSH,
                chunk,
            ));
            let length = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
            if client_sent {
                flow.client_next = flow.client_next.wrapping_add(length);
            } else {
                flow.server_next = flow.server_next.wrapping_add(length);
            }
        }
        packets
    }

    /// The endpoints assigned to a connection, if it has been seen.
    #[must_use]
    pub fn endpoints(&self, connection: Uuid) -> Option<SyntheticEndpoints> {
        self.flows.get(&connection).map(|flow| SyntheticEndpoints {
            client: flow.client,
            server: flow.server,
        })
    }

    /// FIN segments closing every open stream, so a reader sees each
    /// conversation end.
    pub fn close_all(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut flows: Vec<_> = self
            .flows
            .values_mut()
            .filter(|flow| !flow.closed)
            .collect();
        flows.sort_by_key(|flow| flow.client);
        for flow in flows {
            packets.push(tcp_packet(
                flow.client,
                flow.server,
                flow.client_next,
                flow.server_next,
                FLAG_ACK | FLAG_FIN,
                &[],
            ));
            flow.client_next = flow.client_next.wrapping_add(1);
            packets.push(tcp_packet(
                flow.server,
                flow.client,
                flow.server_next,
                flow.client_next,
                FLAG_ACK | FLAG_FIN,
                &[],
            ));
            flow.server_next = flow.server_next.wrapping_add(1);
            flow.closed = true;
        }
        packets
    }

    fn flow(
        &mut self,
        connection: Uuid,
        server_port: u16,
        packets: &mut Vec<Vec<u8>>,
    ) -> &mut Flow {
        if !self.flows.contains_key(&connection) {
            let index = self.allocated;
            self.allocated = self.allocated.wrapping_add(1);
            let [_, _, high, low] = index.to_be_bytes();
            let client = SocketAddrV4::new(
                Ipv4Addr::new(10, 1, high, low),
                40_000 + u16::try_from(index % 20_000).unwrap_or(0),
            );
            let server = SocketAddrV4::new(
                Ipv4Addr::new(10, 2, high, low),
                if server_port == 0 {
                    25_565
                } else {
                    server_port
                },
            );
            // Fixed initial sequence numbers keep exports reproducible.
            let client_isn = 1_000;
            let server_isn = 5_000;
            packets.push(tcp_packet(client, server, client_isn, 0, FLAG_SYN, &[]));
            packets.push(tcp_packet(
                server,
                client,
                server_isn,
                client_isn + 1,
                FLAG_SYN | FLAG_ACK,
                &[],
            ));
            packets.push(tcp_packet(
                client,
                server,
                client_isn + 1,
                server_isn + 1,
                FLAG_ACK,
                &[],
            ));
            self.flows.insert(
                connection,
                Flow {
                    client,
                    server,
                    client_next: client_isn + 1,
                    server_next: server_isn + 1,
                    closed: false,
                },
            );
        }
        self.flows
            .get_mut(&connection)
            .expect("flow was just inserted")
    }
}

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

fn tcp_packet(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_length = 20 + payload.len();
    let total = 20 + tcp_length;
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    // Don't fragment.
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    let header = checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());

    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&source.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65_535_u16.to_be_bytes());
    tcp[20..].copy_from_slice(payload);
    let mut pseudo = [0_u8; 12];
    pseudo[0..4].copy_from_slice(&source.ip().octets());
    pseudo[4..8].copy_from_slice(&destination.ip().octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&u16::try_from(tcp_length).unwrap_or(u16::MAX).to_be_bytes());
    let sum = checksum(&[&pseudo, tcp]);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// The Internet checksum over the concatenation of `parts`.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &byte in *part {
            match odd.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => odd = Some(byte),
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{linktype, parse_frame};

    #[test]
    fn a_stream_opens_carries_data_and_closes() {
        let mut streams = SyntheticStreams::default();
        let connection = Uuid::from_u128(1);
        let first = streams.segments(connection, 25_566, true, b"\x02\x00\x01");
        assert_eq!(first.len(), 4, "handshake plus one data segment");
        let syn = parse_frame(linktype::RAW, &first[0]).expect("syn parses");
        assert!(syn.tcp.expect("tcp").syn);
        let data = parse_frame(linktype::RAW, &first[3]).expect("data parses");
        assert_eq!(data.payload, b"\x02\x00\x01");
        assert_eq!(data.destination.port(), 25_566);
        assert_eq!(data.tcp.expect("tcp").sequence, 1_001);

        let reply = streams.segments(connection, 25_566, false, b"ok");
        assert_eq!(reply.len(), 1);
        let reply = parse_frame(linktype::RAW, &reply[0]).expect("reply parses");
        assert_eq!(reply.tcp.expect("tcp").sequence, 5_001);
        assert_eq!(reply.source, data.destination);

        let next = streams.segments(connection, 25_566, true, b"z");
        let next = parse_frame(linktype::RAW, &next[0]).expect("parses");
        assert_eq!(next.tcp.expect("tcp").sequence, 1_004);
        assert_eq!(streams.close_all().len(), 2);
        assert!(streams.close_all().is_empty());
    }

    #[test]
    fn connections_get_distinct_endpoints_and_large_payloads_split() {
        let mut streams = SyntheticStreams::default();
        streams.segments(Uuid::from_u128(1), 0, true, b"a");
        let big = vec![0_u8; MAX_SEGMENT_PAYLOAD * 2 + 1];
        let packets = streams.segments(Uuid::from_u128(2), 0, true, &big);
        assert_eq!(packets.len(), 3 + 3);
        let first = streams.endpoints(Uuid::from_u128(1)).expect("endpoints");
        let second = streams.endpoints(Uuid::from_u128(2)).expect("endpoints");
        assert_ne!(first.client, second.client);
        assert_eq!(first.server.port(), 25_565);
    }

    #[test]
    fn checksums_verify() {
        let packet = tcp_packet(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2),
            1,
            2,
            FLAG_ACK,
            b"odd",
        );
        assert_eq!(checksum(&[&packet[..20]]), 0);
        let mut pseudo = [0_u8; 12];
        pseudo[0..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&23_u16.to_be_bytes());
        assert_eq!(checksum(&[&pseudo, &packet[20..]]), 0);
    }
}
