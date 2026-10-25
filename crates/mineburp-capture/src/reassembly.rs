//! Per-flow TCP sequence tracking.
//!
//! A passive capture sees every copy of every segment: retransmissions arrive
//! twice, a lost-and-resent segment arrives after the ones that followed it, and
//! a capture that starts mid-connection sees no handshake. Stored as they came,
//! those segments put duplicate and out-of-order bytes into the history, and any
//! reader that frames the stream — a Minecraft length prefix, a dissector —
//! mis-frames everything after the first one.
//!
//! The tracker releases each direction's bytes once, in sequence order. It is
//! bounded in both directions it could grow: buffered out-of-order bytes per
//! flow, and the number of flows. When a gap never fills (the capture itself
//! dropped the segment), the buffered bytes are released after the gap rather
//! than held forever, so a lost frame costs one hole and not the rest of the
//! connection.

use std::{collections::BTreeMap, net::SocketAddr};

use indexmap::IndexMap;

use crate::packet::TcpInfo;

/// Out-of-order bytes buffered per direction before a gap is given up on.
const MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024;
/// How far ahead of the expected sequence a segment may land and still be
/// buffered; anything further is treated as a new stream position.
const MAX_WINDOW: u32 = 16 * 1024 * 1024;
/// How long a gap may stay open, in capture time, before it is skipped.
const GAP_TIMEOUT_MICROS: i64 = 750_000;
/// Directions tracked at once; the least recently seen is forgotten first.
const MAX_FLOWS: usize = 8_192;

/// Bytes ready to publish, with the capture time of the segment that carried
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Released {
    pub timestamp_micros: i64,
    pub payload: Vec<u8>,
    /// Bytes are missing between the previous release and this one: a hole
    /// was skipped or the stream position jumped. A reader framing the stream
    /// has lost its place.
    pub after_gap: bool,
    /// What the record that carried these bytes said about them.
    pub meta: SegmentMeta,
}

/// Per-record facts that travel with a segment's bytes through reassembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SegmentMeta {
    /// The record's pcapng comment.
    pub comment: Option<String>,
    /// The record came from a `MineBurp` export interface.
    pub mineburp_export: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReassemblyStats {
    pub duplicates: u64,
    pub reordered: u64,
    pub gaps: u64,
}

#[derive(Debug, Default)]
struct Direction {
    /// The next sequence number expected, once the stream position is known.
    next: Option<u32>,
    /// Segments that arrived ahead of `next`, keyed by absolute sequence
    /// number.
    pending: BTreeMap<u32, (i64, Vec<u8>, SegmentMeta)>,
    buffered: usize,
    /// Capture time the oldest open gap was first seen.
    gap_since: Option<i64>,
    /// Set when bytes were skipped; the next release reports it.
    gap_pending: bool,
    closed: bool,
}

/// Tracks TCP directions keyed by `(source, destination)`.
#[derive(Debug, Default)]
pub(crate) struct TcpReassembler {
    flows: IndexMap<(SocketAddr, SocketAddr), Direction>,
    stats: ReassemblyStats,
}

impl TcpReassembler {
    pub(crate) fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    /// Accepts one segment and returns whatever bytes it makes contiguous.
    pub(crate) fn push(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        tcp: TcpInfo,
        timestamp_micros: i64,
        payload: &[u8],
        meta: SegmentMeta,
    ) -> Vec<Released> {
        let key = (source, destination);
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.flows.shift_remove_index(0);
        }
        // Move the flow to the back so eviction drops the least recently seen.
        let mut direction = self.flows.shift_remove(&key).unwrap_or_default();
        let released = direction.accept(tcp, timestamp_micros, payload, meta, &mut self.stats);
        let finished = direction.closed && direction.pending.is_empty();
        if !finished {
            self.flows.insert(key, direction);
        }
        released
    }

    /// Releases every gap older than the timeout, as of `now_micros`.
    pub(crate) fn expire(&mut self, now_micros: i64) -> Vec<(SocketAddr, SocketAddr, Released)> {
        let mut released = Vec::new();
        for (key, direction) in &mut self.flows {
            if direction
                .gap_since
                .is_some_and(|since| now_micros.saturating_sub(since) >= GAP_TIMEOUT_MICROS)
            {
                for item in direction.skip_gap(&mut self.stats) {
                    released.push((key.0, key.1, item));
                }
            }
        }
        released
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.flows.len()
    }
}

impl Direction {
    fn accept(
        &mut self,
        tcp: TcpInfo,
        timestamp: i64,
        payload: &[u8],
        meta: SegmentMeta,
        stats: &mut ReassemblyStats,
    ) -> Vec<Released> {
        let mut released = Vec::new();
        // SYN consumes one sequence number and fixes the stream position.
        let data_sequence = if tcp.syn {
            let next = tcp.sequence.wrapping_add(1);
            if self.next.is_none() {
                self.next = Some(next);
            }
            next
        } else {
            tcp.sequence
        };
        if tcp.fin || tcp.rst {
            self.closed = true;
        }
        if payload.is_empty() {
            return released;
        }
        let next = *self.next.get_or_insert(data_sequence);
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let ahead = data_sequence.wrapping_sub(next);
        if ahead == 0 {
            self.deliver(timestamp, payload.to_vec(), meta, &mut released);
            self.drain(&mut released);
            return released;
        }
        if ahead < MAX_WINDOW {
            // A segment beyond a hole: hold it until the hole fills.
            if self.buffered + payload.len() > MAX_BUFFERED_BYTES {
                // Out of room: give up on the hole now rather than drop data.
                released.extend(self.skip_gap(stats));
                released.extend(self.accept(tcp, timestamp, payload, meta, stats));
                return released;
            }
            if self.pending.contains_key(&data_sequence) {
                stats.duplicates += 1;
            } else {
                self.buffered += payload.len();
                self.pending
                    .insert(data_sequence, (timestamp, payload.to_vec(), meta));
                self.gap_since.get_or_insert(timestamp);
                stats.reordered += 1;
            }
            return released;
        }
        // Behind `next`: a retransmission, wholly or partly already delivered.
        let behind = next.wrapping_sub(data_sequence);
        if behind < MAX_WINDOW {
            if behind >= length {
                stats.duplicates += 1;
                return released;
            }
            // Overlap: deliver only the bytes past what was already released.
            let fresh = payload[behind as usize..].to_vec();
            self.deliver(timestamp, fresh, meta, &mut released);
            self.drain(&mut released);
            return released;
        }
        // Far outside the window either way: the stream position jumped (a
        // capture that missed a large stretch). Resynchronise on this segment.
        stats.gaps += 1;
        self.pending.clear();
        self.buffered = 0;
        self.gap_since = None;
        self.gap_pending = true;
        self.next = Some(data_sequence);
        self.deliver(timestamp, payload.to_vec(), meta, &mut released);
        released
    }

    fn deliver(
        &mut self,
        timestamp: i64,
        payload: Vec<u8>,
        meta: SegmentMeta,
        released: &mut Vec<Released>,
    ) {
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        self.next = Some(self.next.unwrap_or(0).wrapping_add(length));
        released.push(Released {
            timestamp_micros: timestamp,
            payload,
            after_gap: std::mem::take(&mut self.gap_pending),
            meta,
        });
    }

    /// Delivers buffered segments that have become contiguous.
    fn drain(&mut self, released: &mut Vec<Released>) {
        while let Some(next) = self.next {
            // Find a buffered segment that starts at or before `next`.
            let candidate = self
                .pending
                .iter()
                .find(|(sequence, (_, payload, _))| {
                    let behind = next.wrapping_sub(**sequence);
                    // Starts at `next`, or before it but still reaches past it.
                    behind < MAX_WINDOW && behind < u32::try_from(payload.len()).unwrap_or(u32::MAX)
                })
                .map(|(sequence, _)| *sequence);
            // Discard buffered segments that are now wholly behind `next`.
            let stale: Vec<u32> = self
                .pending
                .iter()
                .filter(|(sequence, (_, payload, _))| {
                    let behind = next.wrapping_sub(**sequence);
                    behind != 0
                        && behind < MAX_WINDOW
                        && behind >= u32::try_from(payload.len()).unwrap_or(u32::MAX)
                })
                .map(|(sequence, _)| *sequence)
                .collect();
            for sequence in stale {
                if let Some((_, payload, _)) = self.pending.remove(&sequence) {
                    self.buffered -= payload.len();
                }
            }
            let Some(sequence) = candidate else {
                break;
            };
            let Some((timestamp, payload, meta)) = self.pending.remove(&sequence) else {
                break;
            };
            self.buffered -= payload.len();
            let skip = next.wrapping_sub(sequence) as usize;
            self.deliver(
                timestamp,
                payload[skip.min(payload.len())..].to_vec(),
                meta,
                released,
            );
        }
        if self.pending.is_empty() {
            self.gap_since = None;
        }
    }

    /// Abandons the oldest hole: jumps to the first buffered segment and
    /// releases everything contiguous from there.
    fn skip_gap(&mut self, stats: &mut ReassemblyStats) -> Vec<Released> {
        let mut released = Vec::new();
        let Some(next) = self.next else {
            return released;
        };
        // The buffered segment nearest ahead of `next`, in sequence space.
        let Some(sequence) = self
            .pending
            .keys()
            .copied()
            .min_by_key(|sequence| sequence.wrapping_sub(next))
        else {
            self.gap_since = None;
            return released;
        };
        stats.gaps += 1;
        self.gap_pending = true;
        self.next = Some(sequence);
        self.drain(&mut released);
        self.gap_since = if self.pending.is_empty() {
            None
        } else {
            // A further hole remains; its clock starts now.
            released.last().map(|item| item.timestamp_micros)
        };
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn tcp(sequence: u32) -> TcpInfo {
        TcpInfo {
            sequence,
            syn: false,
            fin: false,
            rst: false,
        }
    }

    fn collect(released: Vec<Released>) -> Vec<u8> {
        released.into_iter().flat_map(|item| item.payload).collect()
    }

    #[test]
    fn in_order_segments_pass_straight_through() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        assert_eq!(
            collect(tracker.push(a, b, tcp(100), 0, b"abc", SegmentMeta::default())),
            b"abc"
        );
        assert_eq!(
            collect(tracker.push(a, b, tcp(103), 1, b"de", SegmentMeta::default())),
            b"de"
        );
    }

    #[test]
    fn retransmissions_are_released_once() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(100), 0, b"abc", SegmentMeta::default());
        assert!(
            tracker
                .push(a, b, tcp(100), 1, b"abc", SegmentMeta::default())
                .is_empty()
        );
        // A retransmission that overlaps and extends releases only the tail.
        assert_eq!(
            collect(tracker.push(a, b, tcp(101), 2, b"bcdef", SegmentMeta::default())),
            b"def"
        );
        assert_eq!(tracker.stats().duplicates, 1);
    }

    #[test]
    fn out_of_order_segments_are_reordered() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(100), 0, b"ab", SegmentMeta::default());
        assert!(
            tracker
                .push(a, b, tcp(104), 1, b"ef", SegmentMeta::default())
                .is_empty()
        );
        assert!(
            tracker
                .push(a, b, tcp(106), 2, b"g", SegmentMeta::default())
                .is_empty()
        );
        assert_eq!(
            collect(tracker.push(a, b, tcp(102), 3, b"cd", SegmentMeta::default())),
            b"cdefg"
        );
        assert_eq!(tracker.stats().reordered, 2);
    }

    #[test]
    fn syn_fixes_the_stream_position() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        let syn = TcpInfo {
            syn: true,
            ..tcp(999)
        };
        assert!(
            tracker
                .push(a, b, syn, 0, b"", SegmentMeta::default())
                .is_empty()
        );
        // The first data byte is at ISN + 1; an early later segment waits.
        assert!(
            tracker
                .push(a, b, tcp(1_002), 1, b"c", SegmentMeta::default())
                .is_empty()
        );
        assert_eq!(
            collect(tracker.push(a, b, tcp(1_000), 2, b"ab", SegmentMeta::default())),
            b"abc"
        );
    }

    #[test]
    fn a_hole_that_never_fills_is_skipped_after_the_timeout() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(0), 0, b"a", SegmentMeta::default());
        tracker.push(a, b, tcp(5), 10, b"f", SegmentMeta::default());
        assert!(tracker.expire(100).is_empty());
        let released = tracker.expire(10 + GAP_TIMEOUT_MICROS);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].2.payload, b"f");
        assert!(
            released[0].2.after_gap,
            "a reader must learn it lost its place"
        );
        // The stream carries on from after the skipped hole.
        let next = tracker.push(a, b, tcp(6), 20, b"g", SegmentMeta::default());
        assert!(!next[0].after_gap);
        assert_eq!(collect(next), b"g");
        assert_eq!(tracker.stats().gaps, 1);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(u32::MAX - 1), 0, b"ab", SegmentMeta::default());
        assert_eq!(
            collect(tracker.push(a, b, tcp(0), 1, b"cd", SegmentMeta::default())),
            b"cd"
        );
        assert!(
            tracker
                .push(a, b, tcp(u32::MAX), 2, b"bc", SegmentMeta::default())
                .is_empty()
        );
    }

    #[test]
    fn a_closed_flow_is_forgotten() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(0), 0, b"x", SegmentMeta::default());
        assert_eq!(tracker.tracked(), 1);
        let fin = TcpInfo {
            fin: true,
            ..tcp(1)
        };
        tracker.push(a, b, fin, 1, b"", SegmentMeta::default());
        assert_eq!(tracker.tracked(), 0);
    }

    #[test]
    fn buffering_is_bounded() {
        let mut tracker = TcpReassembler::default();
        let (a, b) = (address(1), address(2));
        tracker.push(a, b, tcp(0), 0, b"a", SegmentMeta::default());
        let chunk = vec![7_u8; 64 * 1024];
        let mut released = 0;
        // Leave a one-byte hole, then flood past the buffer limit.
        for index in 0..64_u32 {
            released += tracker
                .push(
                    a,
                    b,
                    tcp(2 + index * 65_536),
                    i64::from(index),
                    &chunk,
                    SegmentMeta::default(),
                )
                .len();
        }
        assert!(released > 0, "the hole was given up on instead of growing");
    }
}
