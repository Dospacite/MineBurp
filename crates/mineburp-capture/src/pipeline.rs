//! From captured records to published frames.
//!
//! Live capture and file import share everything after the record is read:
//! link/IP/transport parsing, dropping empty segments, TCP sequence tracking,
//! and flow identities. They differ only in how a flow is accepted and which
//! side of it is the client — live capture asks the process-attribution filter,
//! an import goes by server port — so that decision is the one thing passed in.

use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use mineburp_core::{Direction, FlowMetadata};
use uuid::Uuid;

use crate::{
    SideChannelFrame,
    minecraft_filter::{Attribution, FlowKey, HOLD_LIMIT, HoldQueue, MinecraftFlowFilter},
    packet::{Segment, TcpInfo, Transport, parse_frame},
    pcap::CaptureRecord,
    reassembly::{ReassemblyStats, SegmentMeta, TcpReassembler},
};

/// A segment detached from the record buffer it was parsed from.
#[derive(Debug, Clone)]
pub(crate) struct OwnedSegment {
    timestamp_micros: i64,
    transport: Transport,
    source: SocketAddr,
    destination: SocketAddr,
    tcp: Option<TcpInfo>,
    payload: Vec<u8>,
    meta: SegmentMeta,
}

impl OwnedSegment {
    fn from_segment(segment: &Segment<'_>, timestamp_micros: i64, meta: SegmentMeta) -> Self {
        Self {
            timestamp_micros,
            transport: segment.transport,
            source: segment.source,
            destination: segment.destination,
            tcp: segment.tcp,
            payload: segment.payload.to_vec(),
            meta,
        }
    }

    fn key(&self) -> FlowKey {
        FlowKey::new(self.transport, self.source, self.destination)
    }
}

/// Counters the pipeline keeps, merged into `CaptureStats` by its owner.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PipelineStats {
    pub frames_seen: u64,
    pub frames_emitted: u64,
    pub bytes_emitted: u64,
    /// Frames for a Minecraft flow that could not be kept (hold queue full or
    /// held past its limit).
    pub frames_dropped: u64,
    pub frames_held: u64,
    pub reassembly: ReassemblyStats,
}

/// What a frame's reader needs to know beyond its bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FrameContext {
    /// Bytes before this frame were lost; anything framing the stream must
    /// find its place again.
    pub after_gap: bool,
    /// The comment of the record that carried the frame.
    pub comment: Option<String>,
    /// The frame came from a `MineBurp` export interface.
    pub mineburp_export: bool,
}

impl From<SegmentMeta> for FrameContext {
    fn from(meta: SegmentMeta) -> Self {
        Self {
            after_gap: false,
            comment: meta.comment,
            mineburp_export: meta.mineburp_export,
        }
    }
}

/// Which side of a flow is the client, decided per segment.
pub(crate) trait FlowPolicy {
    fn decide(&mut self, segment: &OwnedSegment) -> Decision;
    fn observe_close(&mut self, _segment: &OwnedSegment) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Accept {
        client_sent: bool,
        process_id: Option<u32>,
    },
    Reject,
    Defer,
}

/// Live policy: the flow must belong to a Minecraft client JVM.
impl FlowPolicy for MinecraftFlowFilter {
    fn decide(&mut self, segment: &OwnedSegment) -> Decision {
        match self.attribute(segment.transport, segment.source, segment.destination) {
            Attribution::Minecraft { pid, outgoing } => Decision::Accept {
                client_sent: outgoing,
                process_id: Some(pid),
            },
            Attribution::Unrelated => Decision::Reject,
            Attribution::Unknown => Decision::Defer,
        }
    }

    fn observe_close(&mut self, segment: &OwnedSegment) {
        MinecraftFlowFilter::observe_close(
            self,
            segment.transport,
            segment.source,
            segment.destination,
        );
    }
}

/// Import policy: a flow is Minecraft traffic when it touches a server port.
#[derive(Debug, Clone)]
pub(crate) struct PortPolicy {
    pub server_ports: Vec<u16>,
}

impl FlowPolicy for PortPolicy {
    fn decide(&mut self, segment: &OwnedSegment) -> Decision {
        let source = segment.source.port();
        let destination = segment.destination.port();
        let client_sent = if self.server_ports.contains(&destination) {
            true
        } else if self.server_ports.contains(&source) {
            false
        } else if self.server_ports.is_empty() {
            // No server port configured: everything is imported, and the
            // side using the ephemeral port is taken to be the client.
            source >= 32_768 && destination < 32_768
        } else {
            return Decision::Reject;
        };
        Decision::Accept {
            client_sent,
            process_id: None,
        }
    }
}

/// Turns records into frames under a [`FlowPolicy`].
#[derive(Debug)]
pub(crate) struct Pipeline<P> {
    policy: P,
    reassembler: TcpReassembler,
    held: HoldQueue<OwnedSegment>,
    flows: FlowTracker,
    stats: PipelineStats,
    /// Accepted flows' client side, so gap-expiry output can be published
    /// with the right direction without asking the policy again.
    accepted: indexmap::IndexMap<FlowKey, (SocketAddr, Option<u32>)>,
}

impl<P: FlowPolicy> Pipeline<P> {
    pub(crate) fn new(policy: P) -> Self {
        Self {
            policy,
            reassembler: TcpReassembler::default(),
            held: HoldQueue::default(),
            flows: FlowTracker::default(),
            stats: PipelineStats::default(),
            accepted: indexmap::IndexMap::new(),
        }
    }

    pub(crate) fn stats(&self) -> PipelineStats {
        PipelineStats {
            frames_held: self.held.len() as u64,
            reassembly: self.reassembler.stats(),
            ..self.stats
        }
    }

    /// Parses and routes one record.
    pub(crate) fn push(
        &mut self,
        record: &CaptureRecord,
        emit: &mut impl FnMut(SideChannelFrame, FrameContext),
    ) {
        self.stats.frames_seen += 1;
        let Some(segment) = parse_frame(record.linktype, &record.data) else {
            return;
        };
        let control = segment.tcp.is_some_and(|tcp| tcp.syn || tcp.fin || tcp.rst);
        // A bare ACK or an empty datagram carries nothing to record and
        // nothing reassembly needs.
        if segment.payload.is_empty() && !control {
            return;
        }
        let owned = OwnedSegment::from_segment(
            &segment,
            record.timestamp_micros,
            SegmentMeta {
                comment: record.comment.clone(),
                mineburp_export: record.mineburp_export,
            },
        );
        self.route(owned, emit);
    }

    fn route(
        &mut self,
        segment: OwnedSegment,
        emit: &mut impl FnMut(SideChannelFrame, FrameContext),
    ) {
        let key = segment.key();
        match self.policy.decide(&segment) {
            Decision::Accept {
                client_sent,
                process_id,
            } => {
                // Earlier frames of this flow may still be held: they go first.
                if self.held.holds(&key) {
                    self.retry_held(emit);
                }
                self.accept(segment, client_sent, process_id, emit);
            }
            Decision::Reject => {}
            Decision::Defer => {
                let size = segment.payload.len();
                if !self.held.push(key, size, segment) {
                    self.stats.frames_dropped += 1;
                }
            }
        }
    }

    fn accept(
        &mut self,
        segment: OwnedSegment,
        client_sent: bool,
        process_id: Option<u32>,
        emit: &mut impl FnMut(SideChannelFrame, FrameContext),
    ) {
        let key = segment.key();
        let client = if client_sent {
            segment.source
        } else {
            segment.destination
        };
        if self.accepted.len() >= 16_384 && !self.accepted.contains_key(&key) {
            self.accepted.shift_remove_index(0);
        }
        self.accepted.insert(key, (client, process_id));
        match segment.tcp {
            Some(tcp) => {
                if tcp.fin || tcp.rst {
                    self.policy.observe_close(&segment);
                }
                let released = self.reassembler.push(
                    segment.source,
                    segment.destination,
                    tcp,
                    segment.timestamp_micros,
                    &segment.payload,
                    segment.meta.clone(),
                );
                for item in released {
                    self.publish(
                        segment.transport,
                        segment.source,
                        segment.destination,
                        client,
                        process_id,
                        item.timestamp_micros,
                        item.payload,
                        FrameContext {
                            after_gap: item.after_gap,
                            ..item.meta.into()
                        },
                        emit,
                    );
                }
            }
            None => {
                if !segment.payload.is_empty() {
                    self.publish(
                        segment.transport,
                        segment.source,
                        segment.destination,
                        client,
                        process_id,
                        segment.timestamp_micros,
                        segment.payload,
                        segment.meta.into(),
                        emit,
                    );
                }
            }
        }
    }

    /// Re-decides every held frame; the still-undecided go back, the expired
    /// are dropped.
    pub(crate) fn retry_held(&mut self, emit: &mut impl FnMut(SideChannelFrame, FrameContext)) {
        if self.held.len() == 0 {
            return;
        }
        for (held_at, key, segment) in self.held.take_all() {
            match self.policy.decide(&segment) {
                Decision::Accept {
                    client_sent,
                    process_id,
                } => self.accept(segment, client_sent, process_id, emit),
                Decision::Reject => {}
                Decision::Defer if held_at.elapsed() >= HOLD_LIMIT => {
                    self.stats.frames_dropped += 1;
                }
                Decision::Defer => {
                    let size = segment.payload.len();
                    self.held.restore(held_at, key, size, segment);
                }
            }
        }
    }

    /// Releases reassembly gaps that have been open too long as of `now`.
    pub(crate) fn expire(
        &mut self,
        now_micros: i64,
        emit: &mut impl FnMut(SideChannelFrame, FrameContext),
    ) {
        for (source, destination, item) in self.reassembler.expire(now_micros) {
            let key = FlowKey::new(Transport::Tcp, source, destination);
            let Some((client, process_id)) = self.accepted.get(&key).copied() else {
                continue;
            };
            self.publish(
                Transport::Tcp,
                source,
                destination,
                client,
                process_id,
                item.timestamp_micros,
                item.payload,
                FrameContext {
                    after_gap: item.after_gap,
                    ..item.meta.into()
                },
                emit,
            );
        }
    }

    /// Releases everything still buffered, at the end of a stream.
    pub(crate) fn finish(&mut self, emit: &mut impl FnMut(SideChannelFrame, FrameContext)) {
        self.retry_held(emit);
        self.expire(i64::MAX, emit);
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        transport: Transport,
        source: SocketAddr,
        destination: SocketAddr,
        client: SocketAddr,
        process_id: Option<u32>,
        timestamp_micros: i64,
        payload: Vec<u8>,
        context: FrameContext,
        emit: &mut impl FnMut(SideChannelFrame, FrameContext),
    ) {
        if payload.is_empty() {
            return;
        }
        let client_sent = source == client;
        let (local, remote) = if client_sent {
            (source, destination)
        } else {
            (destination, source)
        };
        let local = local.to_string();
        let remote = remote.to_string();
        let stream_id = self.flows.stream_id(transport.name(), &local, &remote);
        self.stats.frames_emitted += 1;
        self.stats.bytes_emitted += payload.len() as u64;
        emit(
            SideChannelFrame {
                id: Uuid::new_v4(),
                timestamp_micros,
                direction: if client_sent {
                    Direction::ClientToServer
                } else {
                    Direction::ServerToClient
                },
                protocol: transport.name().into(),
                flow: FlowMetadata {
                    transport: transport.name().into(),
                    local_address: local,
                    remote_address: remote,
                    process_id,
                    stream_id: Some(stream_id),
                },
                payload: Bytes::from(payload),
            },
            context,
        );
    }
}

/// Gives every observed transport flow a stable identity.
///
/// Both directions of one connection share the id, so a UDP query session or a
/// TCP download reads as one flow in the history instead of one row per
/// datagram with nothing to group by. The table is bounded; when a very long
/// capture exhausts it, the oldest flows are forgotten and re-registered if
/// the peer sends again.
#[derive(Debug, Default)]
pub(crate) struct FlowTracker {
    flows: indexmap::IndexMap<(String, String, String), Uuid>,
}

impl FlowTracker {
    const CAPACITY: usize = 4_096;

    pub(crate) fn stream_id(&mut self, transport: &str, local: &str, remote: &str) -> Uuid {
        // Canonical order makes both directions of a flow one entry.
        let key = if local <= remote {
            (transport.to_owned(), local.to_owned(), remote.to_owned())
        } else {
            (transport.to_owned(), remote.to_owned(), local.to_owned())
        };
        if let Some(id) = self.flows.get(&key) {
            return *id;
        }
        let id = Uuid::new_v4();
        if self.flows.len() >= Self::CAPACITY {
            self.flows.shift_remove_index(0);
        }
        self.flows.insert(key, id);
        id
    }
}

pub(crate) fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{linktype, tests::ipv4_tcp};

    fn record(timestamp: i64, data: Vec<u8>) -> CaptureRecord {
        CaptureRecord {
            linktype: linktype::RAW,
            timestamp_micros: timestamp,
            data,
            comment: None,
            mineburp_export: false,
        }
    }

    #[test]
    fn both_directions_of_a_flow_share_one_identity() {
        let mut tracker = FlowTracker::default();
        let outgoing = tracker.stream_id("tcp", "127.0.0.1:52000", "203.0.113.5:25565");
        let incoming = tracker.stream_id("tcp", "203.0.113.5:25565", "127.0.0.1:52000");
        assert_eq!(outgoing, incoming);
        let other = tracker.stream_id("tcp", "127.0.0.1:52000", "203.0.113.5:25566");
        assert_ne!(outgoing, other);
    }

    #[test]
    fn a_full_flow_table_forgets_its_oldest_entry() {
        let mut tracker = FlowTracker::default();
        let first = tracker.stream_id("udp", "10.0.0.1:1", "10.0.0.2:2");
        for port in (3_u16..).take(FlowTracker::CAPACITY) {
            tracker.stream_id("udp", "10.0.0.1:9", &format!("10.0.0.2:{port}"));
        }
        assert_eq!(tracker.flows.len(), FlowTracker::CAPACITY);
        assert_ne!(tracker.stream_id("udp", "10.0.0.1:1", "10.0.0.2:2"), first);
    }

    #[test]
    fn port_policy_reassembles_and_orients_a_stream() {
        let mut pipeline = Pipeline::new(PortPolicy {
            server_ports: vec![25_565],
        });
        let client = ([10, 0, 0, 1], 40_000);
        let server = ([10, 0, 0, 2], 25_565);
        let mut frames = Vec::new();
        let mut emit = |frame: SideChannelFrame, _: FrameContext| frames.push(frame);
        pipeline.push(
            &record(1, ipv4_tcp(client, server, 100, 0x18, b"he")),
            &mut emit,
        );
        // Retransmission, then a bare ACK, then the next bytes out of order.
        pipeline.push(
            &record(2, ipv4_tcp(client, server, 100, 0x18, b"he")),
            &mut emit,
        );
        pipeline.push(
            &record(3, ipv4_tcp(server, client, 7, 0x10, b"")),
            &mut emit,
        );
        pipeline.push(
            &record(4, ipv4_tcp(client, server, 104, 0x18, b"o")),
            &mut emit,
        );
        pipeline.push(
            &record(5, ipv4_tcp(client, server, 102, 0x18, b"ll")),
            &mut emit,
        );
        pipeline.push(
            &record(6, ipv4_tcp(server, client, 7, 0x18, b"hi")),
            &mut emit,
        );
        // Unrelated traffic on other ports is not imported.
        pipeline.push(
            &record(
                7,
                ipv4_tcp(([10, 0, 0, 3], 1), ([10, 0, 0, 4], 2), 0, 0x18, b"x"),
            ),
            &mut emit,
        );
        let client_bytes: Vec<u8> = frames
            .iter()
            .filter(|frame| frame.direction == Direction::ClientToServer)
            .flat_map(|frame| frame.payload.to_vec())
            .collect();
        assert_eq!(client_bytes, b"hello");
        let server_frame = frames
            .iter()
            .find(|frame| frame.direction == Direction::ServerToClient)
            .expect("server frame");
        assert_eq!(server_frame.payload.as_ref(), b"hi");
        assert_eq!(server_frame.flow.local_address, "10.0.0.1:40000");
        assert_eq!(server_frame.timestamp_micros, 6);
        assert_eq!(pipeline.stats().reassembly.duplicates, 1);
        assert_eq!(frames.len(), 4);
        assert!(
            frames
                .iter()
                .all(|frame| frame.flow.stream_id == frames[0].flow.stream_id)
        );
    }
}
