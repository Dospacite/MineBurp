//! Link-layer, IP, and transport parsing for captured frames.
//!
//! Every reader is bounds-checked and returns `None` on anything it cannot
//! vouch for: a frame from the wire or from an imported file is untrusted, and a
//! malformed one must be skipped rather than misread or allowed to panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Link types this parser understands, by their pcap `LINKTYPE_*` number.
pub(crate) mod linktype {
    pub const NULL: u32 = 0;
    pub const ETHERNET: u32 = 1;
    pub const RAW_LEGACY: u32 = 12;
    pub const RAW: u32 = 101;
    pub const LOOP: u32 = 108;
    pub const LINUX_SLL: u32 = 113;
    pub const IPV4: u32 = 228;
    pub const IPV6: u32 = 229;
    pub const LINUX_SLL2: u32 = 276;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The TCP header fields reassembly needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpInfo {
    pub sequence: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

/// One transport segment, with its payload trimmed to what the IP header says
/// it carries — link-layer padding is not payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: Transport,
    pub tcp: Option<TcpInfo>,
    pub payload: &'a [u8],
    /// The capture's own direction hint, when the link layer records one
    /// (Linux cooked capture marks outgoing frames).
    pub outgoing: Option<bool>,
}

/// Parses one captured frame of the given link type.
pub(crate) fn parse_frame(link: u32, frame: &[u8]) -> Option<Segment<'_>> {
    let (network, outgoing) = match link {
        linktype::ETHERNET => (ethernet_payload(frame)?, None),
        linktype::LINUX_SLL => {
            let packet_type = be16(frame, 0)?;
            let protocol = be16(frame, 14)?;
            ((protocol, frame.get(16..)?), Some(packet_type == 4))
        }
        linktype::LINUX_SLL2 => {
            let protocol = be16(frame, 0)?;
            let packet_type = *frame.get(10)?;
            ((protocol, frame.get(20..)?), Some(packet_type == 4))
        }
        linktype::NULL | linktype::LOOP => {
            // A four-byte address family in host (NULL) or network (LOOP)
            // order. The family numbers for IPv6 differ by platform, so the
            // IP version nibble decides instead.
            let body = frame.get(4..)?;
            ((ether_type_for_version(body)?, body), None)
        }
        linktype::RAW | linktype::RAW_LEGACY => ((ether_type_for_version(frame)?, frame), None),
        linktype::IPV4 => ((0x0800, frame), None),
        linktype::IPV6 => ((0x86dd, frame), None),
        _ => return None,
    };
    let (ether_type, packet) = network;
    let mut segment = match ether_type {
        0x0800 => parse_ipv4(packet)?,
        0x86dd => parse_ipv6(packet)?,
        _ => return None,
    };
    segment.outgoing = outgoing;
    Some(segment)
}

fn ether_type_for_version(packet: &[u8]) -> Option<u16> {
    match packet.first()? >> 4 {
        4 => Some(0x0800),
        6 => Some(0x86dd),
        _ => None,
    }
}

/// Strips an Ethernet header and any 802.1Q / 802.1ad VLAN tags.
fn ethernet_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    let mut offset = 12;
    let mut ether_type = be16(frame, offset)?;
    // Two tags (QinQ) is the most a real frame carries; a few more costs
    // nothing and bounds the loop.
    for _ in 0..4 {
        if !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        offset += 4;
        ether_type = be16(frame, offset)?;
    }
    Some((ether_type, frame.get(offset + 2..)?))
}

fn parse_ipv4(packet: &[u8]) -> Option<Segment<'_>> {
    let version_ihl = *packet.first()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(version_ihl & 0x0f) * 4;
    if header_length < 20 {
        return None;
    }
    let total_length = usize::from(be16(packet, 2)?);
    if total_length < header_length {
        return None;
    }
    // A fragment cannot be parsed as a transport segment: later fragments
    // carry no transport header, and the first one carries a truncated body.
    let flags_offset = be16(packet, 6)?;
    let more_fragments = flags_offset & 0x2000 != 0;
    let fragment_offset = flags_offset & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return None;
    }
    let protocol = *packet.get(9)?;
    let source = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
    let destination = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
    // Trailing bytes past the IP total length are link padding (Ethernet pads
    // short frames to 60 bytes), never payload. A snapped frame may be shorter
    // than the IP header claims; take what was captured.
    let end = total_length.min(packet.len());
    parse_transport(
        packet.get(header_length..end)?,
        protocol,
        IpAddr::V4(source),
        IpAddr::V4(destination),
    )
}

fn parse_ipv6(packet: &[u8]) -> Option<Segment<'_>> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let payload_length = usize::from(be16(packet, 4)?);
    let mut next_header = *packet.get(6)?;
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let end = (40 + payload_length).min(packet.len());
    let mut offset = 40;
    // Walk extension headers to the transport header. Bounded: a chain longer
    // than this is not something a real stack sends.
    for _ in 0..8 {
        match next_header {
            // Hop-by-hop, routing, destination options: length in 8-byte
            // units, not counting the first 8.
            0 | 43 | 60 => {
                let length = (usize::from(*packet.get(offset + 1)?) + 1) * 8;
                next_header = *packet.get(offset)?;
                offset = offset.checked_add(length)?;
            }
            // Fragment header: only an unfragmented "atomic fragment" can be
            // parsed; anything else lacks its transport header or its body.
            44 => {
                let fragment = be16(packet, offset + 2)?;
                if fragment & 0xfff9 != 0 {
                    return None;
                }
                next_header = *packet.get(offset)?;
                offset = offset.checked_add(8)?;
            }
            // Authentication header: length in 4-byte units, minus 2.
            51 => {
                let length = (usize::from(*packet.get(offset + 1)?) + 2) * 4;
                next_header = *packet.get(offset)?;
                offset = offset.checked_add(length)?;
            }
            _ => break,
        }
        if offset > end {
            return None;
        }
    }
    parse_transport(
        packet.get(offset..end)?,
        next_header,
        IpAddr::V6(source),
        IpAddr::V6(destination),
    )
}

fn parse_transport(
    segment: &[u8],
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
) -> Option<Segment<'_>> {
    let source_port = be16(segment, 0)?;
    let destination_port = be16(segment, 2)?;
    let (transport, payload, tcp) = match protocol {
        6 => {
            let header_length = usize::from(segment.get(12)? >> 4) * 4;
            if header_length < 20 {
                return None;
            }
            let flags = *segment.get(13)?;
            let tcp = TcpInfo {
                sequence: be32(segment, 4)?,
                syn: flags & 0x02 != 0,
                fin: flags & 0x01 != 0,
                rst: flags & 0x04 != 0,
            };
            (Transport::Tcp, segment.get(header_length..)?, Some(tcp))
        }
        17 => {
            let length = usize::from(be16(segment, 4)?);
            if length < 8 {
                return None;
            }
            let end = length.min(segment.len());
            (Transport::Udp, segment.get(8..end)?, None)
        }
        _ => return None,
    };
    Some(Segment {
        source: SocketAddr::new(normalize(source), source_port),
        destination: SocketAddr::new(normalize(destination), destination_port),
        transport,
        tcp,
        payload,
        outgoing: None,
    })
}

/// Folds IPv4-mapped IPv6 addresses to IPv4 so a dual-stack socket and the
/// frames it sends compare equal.
pub(crate) fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
    ]))
}

fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds an IPv4 + TCP packet (no link layer) carrying `payload`.
    pub(crate) fn ipv4_tcp(
        source: ([u8; 4], u16),
        destination: ([u8; 4], u16),
        sequence: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut packet = vec![0_u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.0);
        packet[16..20].copy_from_slice(&destination.0);
        packet[20..22].copy_from_slice(&source.1.to_be_bytes());
        packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = flags;
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn identifies_sll2_outgoing_ipv4_tcp_payload() {
        let ip = ipv4_tcp(
            ([127, 0, 0, 1], 50_000),
            ([1, 2, 3, 4], 25_565),
            7,
            0x18,
            b"abc",
        );
        let mut frame = vec![0_u8; 20];
        frame[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[10] = 4;
        frame.extend_from_slice(&ip);

        let parsed = parse_frame(linktype::LINUX_SLL2, &frame).expect("parsed frame");
        assert_eq!(parsed.outgoing, Some(true));
        assert_eq!(parsed.source.to_string(), "127.0.0.1:50000");
        assert_eq!(parsed.destination.to_string(), "1.2.3.4:25565");
        assert_eq!(parsed.payload, b"abc");
        assert_eq!(parsed.tcp.expect("tcp").sequence, 7);
    }

    #[test]
    fn identifies_sll_incoming_ipv4_udp_payload() {
        let mut frame = vec![0_u8; 16 + 20 + 8 + 3];
        frame[14..16].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = 16;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&31_u16.to_be_bytes());
        frame[ip + 9] = 17;
        frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
        frame[ip + 16..ip + 20].copy_from_slice(&[127, 0, 0, 1]);
        let udp = ip + 20;
        frame[udp..udp + 2].copy_from_slice(&53_u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&50_000_u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&11_u16.to_be_bytes());
        frame[udp + 8..].copy_from_slice(b"dns");

        let parsed = parse_frame(linktype::LINUX_SLL, &frame).expect("parsed frame");
        assert_eq!(parsed.outgoing, Some(false));
        assert_eq!(parsed.source.to_string(), "1.2.3.4:53");
        assert_eq!(parsed.payload, b"dns");
        assert!(parsed.tcp.is_none());
    }

    #[test]
    fn trims_ethernet_padding_to_the_ip_length() {
        // A bare ACK: 40 bytes of IP, padded to Ethernet's 46-byte minimum.
        let ip = ipv4_tcp(
            ([10, 0, 0, 1], 40_000),
            ([10, 0, 0, 2], 25_565),
            1,
            0x10,
            b"",
        );
        let mut frame = vec![0_u8; 14];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&[0; 6]);
        let parsed = parse_frame(linktype::ETHERNET, &frame).expect("parsed frame");
        assert!(parsed.payload.is_empty(), "padding is not payload");
    }

    #[test]
    fn strips_vlan_tags() {
        let ip = ipv4_tcp(
            ([10, 0, 0, 1], 40_000),
            ([10, 0, 0, 2], 25_565),
            1,
            0x18,
            b"hi",
        );
        let mut frame = vec![0_u8; 12];
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        frame.extend_from_slice(&[0, 5]);
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        let parsed = parse_frame(linktype::ETHERNET, &frame).expect("parsed frame");
        assert_eq!(parsed.payload, b"hi");
    }

    #[test]
    fn skips_ipv4_fragments_and_bad_headers() {
        let mut ip = ipv4_tcp(([10, 0, 0, 1], 1), ([10, 0, 0, 2], 2), 1, 0x18, b"x");
        ip[6] = 0x20; // more fragments
        assert!(parse_frame(linktype::RAW, &ip).is_none());
        let mut ip = ipv4_tcp(([10, 0, 0, 1], 1), ([10, 0, 0, 2], 2), 1, 0x18, b"x");
        ip[0] = 0x44; // header length 16
        assert!(parse_frame(linktype::RAW, &ip).is_none());
        let mut ip = ipv4_tcp(([10, 0, 0, 1], 1), ([10, 0, 0, 2], 2), 1, 0x18, b"x");
        ip[32] = 2 << 4; // TCP data offset 8
        assert!(parse_frame(linktype::RAW, &ip).is_none());
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let mut packet = vec![0_u8; 40 + 8 + 20 + 2];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&30_u16.to_be_bytes());
        packet[6] = 0; // hop-by-hop
        packet[23] = 1; // ::1
        packet[39] = 1;
        packet[40] = 6; // next: TCP
        packet[41] = 0; // 8 bytes
        let tcp = 48;
        packet[tcp..tcp + 2].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&25_565_u16.to_be_bytes());
        packet[tcp + 12] = 5 << 4;
        packet[tcp + 20..].copy_from_slice(b"ok");
        let parsed = parse_frame(linktype::RAW, &packet).expect("parsed frame");
        assert_eq!(parsed.source.to_string(), "[::1]:40000");
        assert_eq!(parsed.payload, b"ok");
    }

    #[test]
    fn folds_ipv4_mapped_addresses() {
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert_eq!(normalize(mapped), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn never_panics_on_truncated_frames() {
        let ip = ipv4_tcp(([10, 0, 0, 1], 1), ([10, 0, 0, 2], 2), 1, 0x18, b"payload");
        for link in [
            linktype::NULL,
            linktype::ETHERNET,
            linktype::RAW,
            linktype::LINUX_SLL,
            linktype::LINUX_SLL2,
            linktype::IPV4,
            linktype::IPV6,
        ] {
            for length in 0..ip.len() {
                let _ = parse_frame(link, &ip[..length]);
            }
        }
    }
}
