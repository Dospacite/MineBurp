//! Splitting imported TCP streams into Minecraft packets.
//!
//! Reassembly hands over each direction of a connection as contiguous bytes,
//! in capture order. This module frames them the way the game does — a
//! `VarInt` length, then the packet, compressed once the server asks for it —
//! and follows the protocol state from the packets themselves, the same way
//! the proxy does: the handshake names the protocol and the next state, Set
//! Compression switches framing, login success or its acknowledgement moves on
//! to configuration or play, and the two configuration acknowledgements are
//! recognised by their id in the version's table.
//!
//! Three things stop a stream from being framed, and each leaves the bytes in
//! the history as clearly labelled raw rows instead of guessed packets:
//!
//! - **Encryption.** After an Encryption Request (server) or Response (client)
//!   that direction is AES/CFB8 under a secret the capture does not contain.
//! - **A capture that starts mid-connection.** With no handshake there is no
//!   frame boundary to start from, so the reader searches for one: an offset
//!   where several consecutive frames parse, inflate, and (when the protocol is
//!   known) decode as the packets their ids name. Compression is guessed the
//!   same way. A direction that never synchronises is kept raw.
//! - **A hole in the capture.** Bytes reassembly gave up on cost the reader
//!   its place; it searches again from the bytes after the hole.
//!
//! `MineBurp`'s own pcapng exports are read differently: their streams hold
//! decrypted, uncompressed frames, and every packet's last segment carries a
//! comment with its state and framing, so those are taken as written.

use std::{cmp::Reverse, collections::BinaryHeap, sync::OnceLock};

use bytes::{Bytes, BytesMut};
use indexmap::IndexMap;
use mineburp_core::{
    ConnectionSnapshot, ConnectionStatus, Direction, Disposition, FlowMetadata, PacketDetail,
    PacketSummary, ProtocolState, Target, TrafficSource, WireMetadata,
};
use mineburp_protocol::{
    FrameCodec, PacketRegistry, decode_common_packet, decode_handshake, decode_var_i32,
    decode_with_definition, has_definition, identify_packet, plugin_channel,
};
use uuid::Uuid;

use crate::{SideChannelFrame, pipeline::FrameContext};

/// Largest frame accepted, wire or inflated: vanilla's own inflate limit.
const MAX_FRAME: usize = 8 * 1024 * 1024;
/// Connections tracked at once; the oldest is finished early beyond this.
const MAX_CONNECTIONS: usize = 4_096;
/// Bytes buffered across every connection waiting for a frame to complete.
const BUFFER_BUDGET: usize = 128 * 1024 * 1024;
/// Offsets searched for a frame boundary before a window is given up on.
const SEEK_WINDOW: usize = 8 * 1024;
/// Bytes a search may hold while waiting for a candidate frame to complete.
/// Ciphertext is full of offsets that look like the start of a long frame,
/// so this also bounds how long an encrypted stream holds the search up.
const SEEK_BUFFER_LIMIT: usize = 256 * 1024;
/// A probe frame larger than this is not believed while searching.
const SEEK_FRAME_LIMIT: usize = SEEK_BUFFER_LIMIT;
/// Windows searched without a boundary before a direction is kept raw.
const SEEK_ATTEMPTS: u32 = 3;
/// A handshake is a few hundred bytes; a longer first frame is not one.
const HANDSHAKE_LIMIT: usize = 1024;
/// Frames that must parse in a row for a boundary to be believed.
const COMPRESSED_PROBE_FRAMES: usize = 3;
const UNCOMPRESSED_PROBE_FRAMES: usize = 5;
/// Threshold assumed for a compressed stream whose Set Compression was not
/// captured. Only the framing depends on it being `Some`.
const GUESSED_THRESHOLD: i32 = 256;

/// One history row an import produces, and its connection as of that row.
#[derive(Debug, Clone)]
pub struct ImportedPacket {
    pub detail: PacketDetail,
    pub connection: ConnectionSnapshot,
}

/// How a capture's streams are read.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SplitOptions {
    /// Store each TCP chunk as one raw row instead of framing it.
    pub raw_only: bool,
    /// Protocol assumed for connections whose handshake was not captured.
    pub assumed_protocol: Option<i32>,
}

/// What splitting found, merged into the import summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SplitStats {
    pub packets: u64,
    pub raw_rows: u64,
    pub connections: u64,
    pub encrypted_connections: u64,
    pub midstream_connections: u64,
    pub unsynchronised_streams: u64,
    pub desyncs: u64,
    pub resyncs: u64,
    pub frame_errors: u64,
    pub exported_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// No bytes read yet; whether the stream begins at a handshake is open.
    Start,
    Framed,
    /// Looking for a frame boundary.
    Seeking,
    Encrypted,
    /// Gave up on finding a boundary.
    Unsynchronised,
}

#[derive(Debug, Clone, Copy)]
enum RawKind {
    Encrypted,
    Unsynchronised,
    Truncated,
    Datagram,
    Unsplit,
}

impl RawKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Encrypted => "Encrypted TCP payload",
            Self::Unsynchronised => "Unsynchronised TCP payload",
            Self::Truncated => "Incomplete frame at end of capture",
            Self::Datagram => "UDP payload",
            Self::Unsplit => "TCP payload",
        }
    }
}

#[derive(Debug)]
struct Half {
    mode: Mode,
    buffer: BytesMut,
    codec: FrameCodec,
    search: Search,
    seek_failures: u32,
    last_timestamp: i64,
}

impl Half {
    /// Probes waiting candidates that now have their bytes, then offsets not
    /// yet probed, for the first that starts believable frames.
    fn find_boundary(
        &mut self,
        framings: &[Option<i32>],
        context: &ProbeContext,
    ) -> Option<(usize, Option<i32>)> {
        while let Some(Reverse((needed, offset, threshold))) = self.search.waiting.peek().copied() {
            if needed > self.buffer.len() {
                break;
            }
            self.search.waiting.pop();
            match probe(&self.buffer[offset..], threshold, context) {
                Probe::Valid => return Some((offset, threshold)),
                Probe::Incomplete(more) => self.search.wait(offset + more, offset, threshold),
                Probe::Invalid => {}
            }
        }
        let end = self.buffer.len().min(SEEK_WINDOW);
        while self.search.scanned < end {
            let offset = self.search.scanned;
            self.search.scanned += 1;
            for threshold in framings {
                match probe(&self.buffer[offset..], *threshold, context) {
                    Probe::Valid => return Some((offset, *threshold)),
                    Probe::Incomplete(more) => self.search.wait(offset + more, offset, *threshold),
                    Probe::Invalid => {}
                }
            }
        }
        None
    }

    fn new() -> Self {
        Self {
            mode: Mode::Start,
            buffer: BytesMut::new(),
            codec: FrameCodec::new(MAX_FRAME),
            search: Search::default(),
            seek_failures: 0,
            last_timestamp: 0,
        }
    }
}

/// Where a search for a frame boundary has got to. Every offset is probed
/// once; one that ran out of bytes is probed again only when enough have
/// arrived, so a long search costs each offset a few probes, not one per
/// arriving segment.
#[derive(Debug, Default)]
struct Search {
    /// The first offset never probed.
    scanned: usize,
    /// Candidates waiting for bytes: (buffer length they need, offset,
    /// framing), soonest satisfied first.
    waiting: BinaryHeap<Reverse<(usize, usize, Option<i32>)>>,
}

impl Search {
    fn reset(&mut self, from: usize) {
        self.scanned = from;
        self.waiting.clear();
    }

    fn wait(&mut self, needed: usize, offset: usize, threshold: Option<i32>) {
        // A candidate that needs more than a search may hold never resolves.
        if needed <= SEEK_BUFFER_LIMIT {
            self.waiting.push(Reverse((needed, offset, threshold)));
        }
    }
}

#[derive(Debug)]
struct Connection {
    snapshot: ConnectionSnapshot,
    flow: FlowMetadata,
    /// The handshake was read, so state, compression and encryption are
    /// followed rather than guessed.
    anchored: bool,
    /// The capture began after the handshake.
    midstream: bool,
    /// Compression guessed while searching a mid-stream capture; both
    /// directions share it once either has found a boundary.
    #[allow(
        clippy::option_option,
        reason = "unguessed, guessed uncompressed, guessed compressed"
    )]
    guessed_threshold: Option<Option<i32>>,
    export: bool,
    client: Half,
    server: Half,
    sequence: u64,
}

/// Frames every imported connection. See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct Splitter {
    connections: IndexMap<Uuid, Connection>,
    options: SplitOptions,
    buffered: usize,
    stats: SplitStats,
}

impl Splitter {
    pub(crate) fn new(options: SplitOptions) -> Self {
        Self {
            options,
            ..Self::default()
        }
    }

    pub(crate) fn stats(&self) -> SplitStats {
        self.stats
    }

    /// Reads one reassembled chunk of a stream.
    pub(crate) fn push(
        &mut self,
        frame: SideChannelFrame,
        context: &FrameContext,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let key = frame.flow.stream_id.unwrap_or(frame.id);
        if !self.connections.contains_key(&key) {
            if self.connections.len() >= MAX_CONNECTIONS
                && let Some((_, mut oldest)) = self.connections.shift_remove_index(0)
            {
                self.buffered = self.buffered.saturating_sub(oldest.buffered());
                oldest.finish(&mut self.stats, out);
            }
            let connection = Connection::new(key, &frame, context, self.options);
            self.stats.connections += 1;
            self.connections.insert(key, connection);
        }
        let Some(connection) = self.connections.get_mut(&key) else {
            return;
        };
        let before = connection.buffered();
        connection.accept(frame, context, self.options, &mut self.stats, out);
        self.buffered = self.buffered.saturating_sub(before) + connection.buffered();
        if self.buffered > BUFFER_BUDGET {
            self.shed(out);
        }
    }

    /// Releases whatever is still buffered at the end of the capture.
    pub(crate) fn finish(&mut self, out: &mut impl FnMut(ImportedPacket)) {
        for (_, mut connection) in self.connections.drain(..) {
            connection.finish(&mut self.stats, out);
        }
        self.buffered = 0;
    }

    /// Gives up framing on the largest buffers until the budget holds again:
    /// a hostile capture can claim enormous frames on thousands of streams.
    fn shed(&mut self, out: &mut impl FnMut(ImportedPacket)) {
        while self.buffered > BUFFER_BUDGET {
            let Some((key, direction)) = self
                .connections
                .iter()
                .flat_map(|(key, connection)| {
                    [
                        (
                            *key,
                            Direction::ClientToServer,
                            connection.client.buffer.len(),
                        ),
                        (
                            *key,
                            Direction::ServerToClient,
                            connection.server.buffer.len(),
                        ),
                    ]
                })
                .max_by_key(|(_, _, length)| *length)
                .filter(|(_, _, length)| *length > 0)
                .map(|(key, direction, _)| (key, direction))
            else {
                self.buffered = 0;
                return;
            };
            let Some(connection) = self.connections.get_mut(&key) else {
                return;
            };
            let before = connection.buffered();
            connection.lose_place(direction, &mut self.stats, out);
            self.buffered = self.buffered.saturating_sub(before) + connection.buffered();
        }
    }
}

impl Connection {
    fn new(
        id: Uuid,
        frame: &SideChannelFrame,
        context: &FrameContext,
        options: SplitOptions,
    ) -> Self {
        let midstream_version = options.assumed_protocol;
        Self {
            snapshot: ConnectionSnapshot {
                id,
                target: target_from_authority(&frame.flow.remote_address),
                listener_address: frame.flow.local_address.clone(),
                status: ConnectionStatus::Closed,
                state: if frame.protocol == "tcp" && !options.raw_only {
                    ProtocolState::Handshake
                } else {
                    ProtocolState::Opaque
                },
                protocol_version: None,
                minecraft_version: midstream_version.and_then(release_name),
                loader: None,
                compression_threshold: None,
                encrypted_client: false,
                encrypted_server: false,
                packet_count: 0,
                byte_count: 0,
                last_error: None,
            },
            flow: frame.flow.clone(),
            anchored: false,
            midstream: false,
            guessed_threshold: None,
            export: context.mineburp_export,
            client: Half::new(),
            server: Half::new(),
            sequence: 0,
        }
    }

    fn buffered(&self) -> usize {
        self.client.buffer.len() + self.server.buffer.len()
    }

    fn half(&mut self, direction: Direction) -> &mut Half {
        match direction {
            Direction::ClientToServer => &mut self.client,
            Direction::ServerToClient => &mut self.server,
        }
    }

    fn accept(
        &mut self,
        frame: SideChannelFrame,
        context: &FrameContext,
        options: SplitOptions,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let direction = frame.direction;
        let timestamp = frame.timestamp_micros;
        self.half(direction).last_timestamp = timestamp;
        if frame.protocol != "tcp" {
            self.raw(
                direction,
                timestamp,
                frame.payload,
                RawKind::Datagram,
                counts,
                out,
            );
            return;
        }
        if options.raw_only {
            self.raw(
                direction,
                timestamp,
                frame.payload,
                RawKind::Unsplit,
                counts,
                out,
            );
            return;
        }
        if self.export {
            self.accept_exported(
                direction,
                timestamp,
                &frame.payload,
                context.comment.as_deref(),
                counts,
                out,
            );
            return;
        }
        match self.half(direction).mode {
            Mode::Encrypted => {
                self.raw(
                    direction,
                    timestamp,
                    frame.payload,
                    RawKind::Encrypted,
                    counts,
                    out,
                );
                return;
            }
            Mode::Unsynchronised => {
                self.raw(
                    direction,
                    timestamp,
                    frame.payload,
                    RawKind::Unsynchronised,
                    counts,
                    out,
                );
                return;
            }
            Mode::Framed if context.after_gap => {
                counts.desyncs += 1;
                self.snapshot.last_error =
                    Some("bytes missing from the capture; framing was searched for again".into());
                let half = self.half(direction);
                half.buffer.clear();
                half.mode = Mode::Seeking;
                half.search.reset(0);
            }
            Mode::Seeking if context.after_gap => {
                // What was buffered no longer joins on to what follows.
                let stale = self.half(direction).buffer.split().freeze();
                if !stale.is_empty() {
                    self.raw(
                        direction,
                        timestamp,
                        stale,
                        RawKind::Unsynchronised,
                        counts,
                        out,
                    );
                }
                self.half(direction).search.reset(0);
            }
            _ => {}
        }
        self.half(direction)
            .buffer
            .extend_from_slice(&frame.payload);
        self.process(direction, options, counts, out);
    }

    /// Advances one direction as far as its buffered bytes allow.
    fn process(
        &mut self,
        direction: Direction,
        options: SplitOptions,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        loop {
            match self.half(direction).mode {
                Mode::Start => {
                    if !self.start(direction, options, counts, out) {
                        return;
                    }
                }
                Mode::Framed => {
                    self.read_frames(direction, counts, out);
                    // Framing was lost or the direction went encrypted:
                    // carry on in the new mode.
                    if self.half(direction).mode == Mode::Framed {
                        return;
                    }
                }
                Mode::Seeking => {
                    if !self.seek(direction, counts, out) {
                        return;
                    }
                }
                Mode::Encrypted | Mode::Unsynchronised => {
                    let timestamp = self.half(direction).last_timestamp;
                    let kind = if self.half(direction).mode == Mode::Encrypted {
                        RawKind::Encrypted
                    } else {
                        RawKind::Unsynchronised
                    };
                    let rest = self.half(direction).buffer.split().freeze();
                    if !rest.is_empty() {
                        self.raw(direction, timestamp, rest, kind, counts, out);
                    }
                    return;
                }
            }
        }
    }

    /// Decides whether a stream begins at its handshake. Returns whether the
    /// mode changed and processing should continue.
    fn start(
        &mut self,
        direction: Direction,
        options: SplitOptions,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) -> bool {
        if self.anchored {
            self.half(direction).mode = Mode::Framed;
            return true;
        }
        if self.midstream {
            self.half(direction).mode = Mode::Seeking;
            return true;
        }
        if direction == Direction::ServerToClient {
            // The client always speaks first. Server bytes while the client's
            // first frame is still arriving wait for it; otherwise the capture
            // began after the handshake.
            if !self.client.buffer.is_empty() {
                return false;
            }
            self.begin_midstream(options, counts);
            return true;
        }
        match handshake_at_start(&self.client.buffer) {
            Opening::Wait => false,
            Opening::Handshake => {
                self.anchored = true;
                self.client.mode = Mode::Framed;
                // Server bytes that arrived early can be read now.
                if self.server.mode == Mode::Start && !self.server.buffer.is_empty() {
                    self.server.mode = Mode::Framed;
                    self.process(Direction::ServerToClient, options, counts, out);
                }
                true
            }
            Opening::Other => {
                self.begin_midstream(options, counts);
                if !self.server.buffer.is_empty() {
                    self.process(Direction::ServerToClient, options, counts, out);
                }
                true
            }
        }
    }

    fn begin_midstream(&mut self, options: SplitOptions, counts: &mut SplitStats) {
        self.midstream = true;
        counts.midstream_connections += 1;
        // Play is where nearly all of a connection's life is spent.
        self.snapshot.state = ProtocolState::Play;
        self.snapshot.protocol_version = options.assumed_protocol;
        self.snapshot.minecraft_version = options.assumed_protocol.and_then(release_name);
        for half in [&mut self.client, &mut self.server] {
            if half.mode == Mode::Start {
                half.mode = Mode::Seeking;
            }
        }
    }

    /// Searches for a frame boundary. Returns whether the mode changed and
    /// processing should continue.
    fn seek(
        &mut self,
        direction: Direction,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) -> bool {
        let framings: Vec<Option<i32>> = if self.anchored {
            vec![self.half(direction).codec.compression_threshold()]
        } else if let Some(guess) = self.guessed_threshold {
            vec![guess]
        } else {
            // Compressed first: an uncompressed reading of a compressed
            // stream also parses, as packet id 0 over and over.
            vec![Some(GUESSED_THRESHOLD), None]
        };
        let context = ProbeContext {
            state: self.snapshot.state,
            direction,
            protocol: self.snapshot.protocol_version,
        };
        loop {
            let half = self.half(direction);
            let found = half.find_boundary(&framings, &context);
            if let Some((offset, threshold)) = found {
                let timestamp = half.last_timestamp;
                let skipped = half.buffer.split_to(offset).freeze();
                half.codec.set_compression_threshold(threshold);
                half.mode = Mode::Framed;
                half.search.reset(0);
                // Each hole gets its own allowance of failed windows.
                half.seek_failures = 0;
                if !self.anchored && self.guessed_threshold.is_none() {
                    self.guessed_threshold = Some(threshold);
                    self.snapshot.compression_threshold = threshold;
                    let other = self.half(opposite(direction));
                    other.codec.set_compression_threshold(threshold);
                }
                counts.resyncs += 1;
                if !skipped.is_empty() {
                    self.raw(
                        direction,
                        timestamp,
                        skipped,
                        RawKind::Unsynchronised,
                        counts,
                        out,
                    );
                }
                return true;
            }
            let window_spent = half.search.scanned >= SEEK_WINDOW && half.search.waiting.is_empty();
            let waited_too_long = half.buffer.len() > SEEK_BUFFER_LIMIT;
            if !window_spent && !waited_too_long {
                return false;
            }
            // Nothing in this window starts a frame: keep it raw and look on.
            let timestamp = half.last_timestamp;
            let take = SEEK_WINDOW.min(half.buffer.len());
            let skipped = half.buffer.split_to(take).freeze();
            half.search.reset(0);
            half.seek_failures += 1;
            let given_up = half.seek_failures >= SEEK_ATTEMPTS;
            if given_up {
                half.mode = Mode::Unsynchronised;
                counts.unsynchronised_streams += 1;
            }
            self.raw(
                direction,
                timestamp,
                skipped,
                RawKind::Unsynchronised,
                counts,
                out,
            );
            if given_up {
                return true;
            }
        }
    }

    /// Frames everything complete in one direction's buffer.
    fn read_frames(
        &mut self,
        direction: Direction,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        loop {
            let half = self.half(direction);
            let timestamp = half.last_timestamp;
            let (length, prefix) = match decode_var_i32(&half.buffer) {
                Ok(Some(found)) => found,
                Ok(None) => return,
                Err(_) => {
                    self.lose_framing(direction, "frame length is not a VarInt", counts);
                    return;
                }
            };
            let Some(length) = usize::try_from(length)
                .ok()
                .filter(|length| *length <= MAX_FRAME)
            else {
                self.lose_framing(direction, "frame length is out of range", counts);
                return;
            };
            if half.buffer.len() < prefix + length {
                return;
            }
            let wire = half.buffer.split_to(prefix + length).freeze();
            let decoded = half.codec.try_decode(&mut BytesMut::from(&wire[..]));
            // A bad frame whose length was sound leaves the stream in step;
            // only its contents are reported.
            let frame = match decoded {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    counts.frame_errors += 1;
                    self.error_row(
                        direction,
                        timestamp,
                        wire,
                        "frame is incomplete".into(),
                        counts,
                        out,
                    );
                    continue;
                }
                Err(error) => {
                    counts.frame_errors += 1;
                    self.error_row(direction, timestamp, wire, error.to_string(), counts, out);
                    continue;
                }
            };
            let state = self.snapshot.state;
            let logical = frame.logical_bytes();
            self.packet(
                direction,
                timestamp,
                state,
                frame.id,
                &frame.body,
                logical,
                WireMetadata {
                    frame_length: wire.len(),
                    logical_length: frame.body.len() + varint_length(frame.id),
                    compressed: frame.compressed,
                    encrypted: false,
                    truncated: false,
                },
                counts,
                out,
            );
            if self.follow(direction, state, frame.id, &frame.body, counts, out) {
                return;
            }
        }
    }

    /// Applies the state change a packet causes. Returns `true` when the
    /// direction went encrypted and reading it must stop.
    fn follow(
        &mut self,
        direction: Direction,
        state: ProtocolState,
        id: i32,
        body: &[u8],
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) -> bool {
        let protocol = self.snapshot.protocol_version;
        match (state, direction, id) {
            (ProtocolState::Handshake, Direction::ClientToServer, 0) => {
                if let Ok(handshake) = decode_handshake(body) {
                    let version = self
                        .snapshot
                        .protocol_version
                        .unwrap_or(handshake.protocol_version);
                    self.snapshot.protocol_version = Some(version);
                    self.snapshot.minecraft_version = release_name(version);
                    self.snapshot.state = match handshake.next_state {
                        1 => ProtocolState::Status,
                        // 3 is a transfer, which logs in like 2.
                        _ => ProtocolState::Login,
                    };
                }
            }
            // Encryption Request from the server, Response from the client.
            (ProtocolState::Login, _, 1) => {
                self.encrypt(direction, counts, out);
                return true;
            }
            (ProtocolState::Login, Direction::ServerToClient, 3) => {
                if let Ok(Some((threshold, _))) = decode_var_i32(body) {
                    let threshold = (threshold >= 0).then_some(threshold);
                    self.client.codec.set_compression_threshold(threshold);
                    self.server.codec.set_compression_threshold(threshold);
                    self.snapshot.compression_threshold = threshold;
                }
            }
            (ProtocolState::Login, Direction::ServerToClient, 2)
                if protocol.is_some_and(|version| version < 764) =>
            {
                self.snapshot.state = ProtocolState::Play;
            }
            (ProtocolState::Login, Direction::ClientToServer, _)
                if protocol.is_some_and(|version| version >= 764)
                    && id
                        == PacketRegistry::packet_id(
                            ProtocolState::Login,
                            direction,
                            "login_acknowledged",
                            protocol,
                        )
                        .unwrap_or(3) =>
            {
                self.snapshot.state = ProtocolState::Configuration;
            }
            (ProtocolState::Configuration, Direction::ClientToServer, _)
                if PacketRegistry::packet_id(
                    ProtocolState::Configuration,
                    direction,
                    "finish_configuration_ack",
                    protocol,
                ) == Some(id) =>
            {
                self.snapshot.state = ProtocolState::Play;
            }
            (ProtocolState::Play, Direction::ClientToServer, _)
                if PacketRegistry::packet_id(
                    ProtocolState::Play,
                    direction,
                    "configuration_acknowledged",
                    protocol,
                ) == Some(id) =>
            {
                self.snapshot.state = ProtocolState::Configuration;
            }
            _ => {}
        }
        false
    }

    /// Marks a direction encrypted; everything after the packet that switched
    /// it is ciphertext.
    fn encrypt(
        &mut self,
        direction: Direction,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        if !self.snapshot.encrypted_client && !self.snapshot.encrypted_server {
            counts.encrypted_connections += 1;
        }
        match direction {
            Direction::ClientToServer => self.snapshot.encrypted_client = true,
            Direction::ServerToClient => self.snapshot.encrypted_server = true,
        }
        let half = self.half(direction);
        half.mode = Mode::Encrypted;
        let timestamp = half.last_timestamp;
        let rest = half.buffer.split().freeze();
        if !rest.is_empty() {
            self.raw(direction, timestamp, rest, RawKind::Encrypted, counts, out);
        }
    }

    /// The stream stopped making sense at the head of the buffer; the caller
    /// carries on searching for a boundary.
    fn lose_framing(&mut self, direction: Direction, reason: &str, counts: &mut SplitStats) {
        counts.desyncs += 1;
        self.snapshot.last_error = Some(format!("{reason}; framing was searched for again"));
        let half = self.half(direction);
        half.mode = Mode::Seeking;
        // Offset 0 is where the bad frame starts; it cannot be the answer.
        half.search.reset(1);
    }

    /// Drops a direction's buffer to stay within the memory budget.
    fn lose_place(
        &mut self,
        direction: Direction,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let half = self.half(direction);
        let timestamp = half.last_timestamp;
        let dropped = half.buffer.split().freeze();
        if matches!(half.mode, Mode::Framed | Mode::Start) {
            half.mode = Mode::Seeking;
        }
        half.search.reset(0);
        counts.desyncs += 1;
        self.snapshot.last_error = Some("a frame exceeded the import's memory budget".into());
        self.raw(
            direction,
            timestamp,
            dropped,
            RawKind::Unsynchronised,
            counts,
            out,
        );
    }

    fn finish(&mut self, counts: &mut SplitStats, out: &mut impl FnMut(ImportedPacket)) {
        let export = self.export;
        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            let half = self.half(direction);
            let timestamp = half.last_timestamp;
            let kind = match half.mode {
                Mode::Framed => RawKind::Truncated,
                Mode::Encrypted => RawKind::Encrypted,
                _ if export => RawKind::Truncated,
                _ => RawKind::Unsynchronised,
            };
            let rest = half.buffer.split().freeze();
            if !rest.is_empty() {
                self.raw(direction, timestamp, rest, kind, counts, out);
            }
        }
    }

    // --- MineBurp exports ---

    fn accept_exported(
        &mut self,
        direction: Direction,
        timestamp: i64,
        payload: &[u8],
        comment: Option<&str>,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        self.half(direction).buffer.extend_from_slice(payload);
        let Some(comment) = comment.and_then(ExportComment::parse) else {
            // A packet's earlier segments carry no comment; its last one does.
            if self.half(direction).buffer.len() > MAX_FRAME + 5 {
                let rest = self.half(direction).buffer.split().freeze();
                self.raw(
                    direction,
                    timestamp,
                    rest,
                    RawKind::Unsynchronised,
                    counts,
                    out,
                );
            }
            return;
        };
        let bytes = self.half(direction).buffer.split().freeze();
        if let Some(protocol) = comment.protocol {
            self.snapshot.protocol_version = Some(protocol);
            self.snapshot.minecraft_version = release_name(protocol);
        }
        let disposition = comment.disposition.unwrap_or(Disposition::Observed);
        if !comment.framed {
            let name = comment
                .name
                .unwrap_or_else(|| RawKind::Unsplit.label().into());
            self.emit_raw(
                direction,
                timestamp,
                bytes,
                name,
                false,
                disposition,
                counts,
                out,
            );
            return;
        }
        let state = comment.state.unwrap_or(self.snapshot.state);
        self.snapshot.state = state;
        let parsed = decode_var_i32(&bytes)
            .ok()
            .flatten()
            .and_then(|(length, prefix)| {
                let logical = bytes.slice(prefix..);
                (usize::try_from(length).ok() == Some(logical.len())).then_some(logical)
            });
        let Some(logical) = parsed else {
            counts.frame_errors += 1;
            self.error_row(
                direction,
                timestamp,
                bytes,
                "exported frame length does not match its packet".into(),
                counts,
                out,
            );
            return;
        };
        let Some((id, id_length)) = decode_var_i32(&logical).ok().flatten() else {
            counts.frame_errors += 1;
            self.error_row(
                direction,
                timestamp,
                logical,
                "exported frame has no packet id".into(),
                counts,
                out,
            );
            return;
        };
        let body = logical.slice(id_length..);
        let wire = WireMetadata {
            frame_length: bytes.len(),
            logical_length: logical.len(),
            compressed: false,
            encrypted: false,
            truncated: false,
        };
        counts.exported_packets += 1;
        let detail = self.packet_detail(
            direction,
            timestamp,
            state,
            id,
            &body,
            logical,
            wire,
            comment.name,
            disposition,
        );
        self.deliver(detail, counts, out);
    }

    // --- rows ---

    #[allow(clippy::too_many_arguments)]
    fn packet(
        &mut self,
        direction: Direction,
        timestamp: i64,
        state: ProtocolState,
        id: i32,
        body: &[u8],
        logical: Bytes,
        wire: WireMetadata,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let detail = self.packet_detail(
            direction,
            timestamp,
            state,
            id,
            body,
            logical,
            wire,
            None,
            Disposition::Observed,
        );
        self.deliver(detail, counts, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn packet_detail(
        &mut self,
        direction: Direction,
        timestamp: i64,
        state: ProtocolState,
        id: i32,
        body: &[u8],
        logical: Bytes,
        wire: WireMetadata,
        name: Option<String>,
        disposition: Disposition,
    ) -> PacketDetail {
        let protocol = self.snapshot.protocol_version;
        let common = decode_common_packet(state, direction, id, body, protocol);
        let mut channel = common.channel;
        let mut loader = common.loader;
        let name = name.or_else(|| identify_packet(state, direction, id, body, protocol));
        // Modern custom payloads carry no common-decoder branch because their
        // packet id is version-specific; read their channel from the preamble so
        // imported captures are searchable by channel like live ones.
        if channel.is_none()
            && matches!(name.as_deref(), Some("custom_payload" | "plugin_message"))
            && let Some((found, found_loader)) = plugin_channel(body)
        {
            channel = Some(found);
            loader = loader.or(found_loader);
        }
        if self.snapshot.loader.is_none() {
            self.snapshot.loader.clone_from(&loader);
        }
        PacketDetail {
            summary: self.summary(
                direction,
                timestamp,
                state,
                Some(id),
                name,
                logical.len(),
                disposition,
                channel,
                loader,
            ),
            logical_bytes: logical,
            decoded: None,
            decode_error: None,
            wire,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn summary(
        &mut self,
        direction: Direction,
        timestamp: i64,
        state: ProtocolState,
        packet_id: Option<i32>,
        name: Option<String>,
        size: usize,
        disposition: Disposition,
        channel: Option<String>,
        loader: Option<String>,
    ) -> PacketSummary {
        self.sequence += 1;
        PacketSummary {
            id: 0,
            sequence: self.sequence,
            connection_id: self.snapshot.id,
            timestamp_micros: timestamp,
            source: TrafficSource::SideChannel,
            direction,
            state,
            protocol_version: self.snapshot.protocol_version,
            packet_id,
            name,
            channel,
            loader: loader.or_else(|| self.snapshot.loader.clone()),
            size,
            disposition,
            flow: Some(self.flow.clone()),
        }
    }

    fn raw(
        &mut self,
        direction: Direction,
        timestamp: i64,
        payload: Bytes,
        kind: RawKind,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let encrypted = matches!(kind, RawKind::Encrypted);
        self.emit_raw(
            direction,
            timestamp,
            payload,
            kind.label().into(),
            encrypted,
            Disposition::Observed,
            counts,
            out,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_raw(
        &mut self,
        direction: Direction,
        timestamp: i64,
        payload: Bytes,
        name: String,
        encrypted: bool,
        disposition: Disposition,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let size = payload.len();
        let detail = PacketDetail {
            summary: self.summary(
                direction,
                timestamp,
                ProtocolState::Opaque,
                None,
                Some(name),
                size,
                disposition,
                None,
                None,
            ),
            logical_bytes: payload,
            decoded: None,
            decode_error: None,
            wire: WireMetadata {
                frame_length: size,
                logical_length: size,
                compressed: false,
                encrypted,
                truncated: false,
            },
        };
        counts.raw_rows += 1;
        self.deliver_counted(detail, out);
    }

    fn error_row(
        &mut self,
        direction: Direction,
        timestamp: i64,
        wire: Bytes,
        error: String,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        let size = wire.len();
        let state = self.snapshot.state;
        let detail = PacketDetail {
            summary: self.summary(
                direction,
                timestamp,
                state,
                None,
                Some("Undecodable frame".into()),
                size,
                Disposition::Observed,
                None,
                None,
            ),
            logical_bytes: wire,
            decoded: None,
            decode_error: Some(error),
            wire: WireMetadata {
                frame_length: size,
                logical_length: size,
                compressed: false,
                encrypted: false,
                truncated: false,
            },
        };
        counts.raw_rows += 1;
        self.deliver_counted(detail, out);
    }

    fn deliver(
        &mut self,
        detail: PacketDetail,
        counts: &mut SplitStats,
        out: &mut impl FnMut(ImportedPacket),
    ) {
        counts.packets += 1;
        self.deliver_counted(detail, out);
    }

    fn deliver_counted(&mut self, detail: PacketDetail, out: &mut impl FnMut(ImportedPacket)) {
        self.snapshot.packet_count += 1;
        self.snapshot.byte_count += detail.summary.size as u64;
        out(ImportedPacket {
            detail,
            connection: self.snapshot.clone(),
        });
    }
}

const fn opposite(direction: Direction) -> Direction {
    match direction {
        Direction::ClientToServer => Direction::ServerToClient,
        Direction::ServerToClient => Direction::ClientToServer,
    }
}

fn varint_length(value: i32) -> usize {
    let mut value = value.cast_unsigned();
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn release_name(protocol: i32) -> Option<String> {
    static REGISTRY: OnceLock<PacketRegistry> = OnceLock::new();
    REGISTRY
        .get_or_init(PacketRegistry::bundled)
        .version(protocol)
        .map(|version| version.canonical.clone())
}

fn target_from_authority(authority: &str) -> Target {
    if let Some(ipv6) = authority.strip_prefix('[')
        && let Some((host, port)) = ipv6.rsplit_once("]:")
    {
        return Target {
            host: host.to_owned(),
            port: port.parse().unwrap_or_default(),
        };
    }
    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "0"));
    Target {
        host: host.to_owned(),
        port: port.parse().unwrap_or_default(),
    }
}

// --- the opening of a stream ---

enum Opening {
    Wait,
    Handshake,
    Other,
}

/// Whether a client stream begins with a handshake frame.
fn handshake_at_start(buffer: &[u8]) -> Opening {
    let (length, prefix) = match decode_var_i32(buffer) {
        Ok(Some(found)) => found,
        Ok(None) => return Opening::Wait,
        Err(_) => return Opening::Other,
    };
    let Some(length) = usize::try_from(length)
        .ok()
        .filter(|length| (1..=HANDSHAKE_LIMIT).contains(length))
    else {
        return Opening::Other;
    };
    let Some(frame) = buffer.get(prefix..prefix + length) else {
        return Opening::Wait;
    };
    let Ok(Some((0, id_length))) = decode_var_i32(frame) else {
        return Opening::Other;
    };
    match decode_handshake(&frame[id_length..]) {
        // A compressed play frame can read as id 0 too; a real handshake names
        // a protocol and the address the player typed.
        Ok(handshake)
            if (1..=3).contains(&handshake.next_state)
                && handshake.protocol_version > 0
                && !handshake.server_address.is_empty() =>
        {
            Opening::Handshake
        }
        _ => Opening::Other,
    }
}

// --- searching for a frame boundary ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Valid,
    Invalid,
    /// The bytes ran out; this many, from the probe's start, are needed.
    Incomplete(usize),
}

struct ProbeContext {
    state: ProtocolState,
    direction: Direction,
    protocol: Option<i32>,
}

/// Whether `input` starts with enough well-formed frames, under `threshold`'s
/// framing, to believe a boundary is there.
fn probe(input: &[u8], threshold: Option<i32>, context: &ProbeContext) -> Probe {
    let required = if threshold.is_some() {
        COMPRESSED_PROBE_FRAMES
    } else {
        UNCOMPRESSED_PROBE_FRAMES
    };
    let tabulated = PacketRegistry::is_tabulated(context.state, context.protocol);
    let described = has_definition(context.protocol);
    let mut codec = FrameCodec::new(MAX_FRAME);
    codec.set_compression_threshold(threshold);
    let mut position = 0;
    let mut described_ok = 0;
    let mut named = 0;
    for _ in 0..required {
        let rest = &input[position..];
        let (length, prefix) = match decode_var_i32(rest) {
            Ok(Some(found)) => found,
            Ok(None) => return Probe::Incomplete(position + rest.len() + 1),
            Err(_) => return Probe::Invalid,
        };
        let Some(length) = usize::try_from(length)
            .ok()
            .filter(|length| (1..=SEEK_FRAME_LIMIT).contains(length))
        else {
            return Probe::Invalid;
        };
        let Some(frame) = rest.get(prefix..prefix + length) else {
            return Probe::Incomplete(position + prefix + length);
        };
        if !plausible_frame(frame, threshold) {
            return Probe::Invalid;
        }
        // Uncompressed frames are read in place; only inflating needs a copy.
        let (id, body) = if threshold.is_none() {
            let Ok(Some((id, id_length))) = decode_var_i32(frame) else {
                return Probe::Invalid;
            };
            (id, Bytes::copy_from_slice(&frame[id_length..]))
        } else {
            let Ok(Some(decoded)) = codec.try_decode(&mut BytesMut::from(&rest[..prefix + length]))
            else {
                return Probe::Invalid;
            };
            (decoded.id, decoded.body)
        };
        if !(0..=0xff).contains(&id) {
            return Probe::Invalid;
        }
        if tabulated
            && PacketRegistry::table_packet_name(
                context.state,
                context.direction,
                id,
                context.protocol,
            )
            .is_none()
        {
            return Probe::Invalid;
        }
        // Import-only boundary validation, never the live capture path.
        // Definition node/depth limits and NBT text work limits bound this probe.
        if described {
            if decode_with_definition(
                context.state,
                context.direction,
                id,
                &body,
                context.protocol,
            )
            .is_some_and(|decode| decode.is_complete())
            {
                described_ok += 1;
            }
        } else if identify_packet(
            context.state,
            context.direction,
            id,
            &body,
            context.protocol,
        )
        .is_some()
        {
            named += 1;
        }
        position += prefix + length;
    }
    let believed = if described {
        // One packet the description reads differently is tolerated.
        described_ok + 1 >= required
    } else if threshold.is_none() {
        // Uncompressed framing is the easy one to fake; insist that some of
        // the frames read as real packets.
        named >= 2
    } else {
        true
    };
    if believed {
        Probe::Valid
    } else {
        Probe::Invalid
    }
}

/// Cheap structural checks before inflating anything.
fn plausible_frame(frame: &[u8], threshold: Option<i32>) -> bool {
    if threshold.is_none() {
        return matches!(decode_var_i32(frame), Ok(Some((0..=0xff, _))));
    }
    let Ok(Some((data_length, prefix))) = decode_var_i32(frame) else {
        return false;
    };
    match usize::try_from(data_length) {
        Ok(0) => matches!(decode_var_i32(&frame[prefix..]), Ok(Some((0..=0xff, _)))),
        Ok(length) if length <= MAX_FRAME => {
            // A zlib stream: deflate method, and a header checksum.
            let zlib = &frame[prefix..];
            zlib.len() >= 2
                && zlib[0] & 0x0f == 8
                && (u16::from(zlib[0]) << 8 | u16::from(zlib[1])) % 31 == 0
        }
        _ => false,
    }
}

// --- MineBurp export comments ---

/// What `MineBurp`'s pcapng export says about a packet:
/// `mineburp: name=…; state=…; direction=…; id=…; protocol=…;
/// disposition=…; framing=frame|raw; row=…; connection=…`.
#[derive(Debug, Default, PartialEq, Eq)]
struct ExportComment {
    name: Option<String>,
    state: Option<ProtocolState>,
    protocol: Option<i32>,
    disposition: Option<Disposition>,
    framed: bool,
}

impl ExportComment {
    fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("mineburp:")?;
        let mut comment = Self::default();
        let mut framing = None;
        for part in rest.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key {
                "name" if !value.is_empty() => comment.name = Some(value.to_owned()),
                "state" => comment.state = enum_value(value),
                "protocol" => comment.protocol = value.parse().ok(),
                "disposition" => comment.disposition = enum_value(value),
                "framing" => framing = Some(value == "frame"),
                _ => {}
            }
        }
        comment.framed = framing?;
        Some(comment)
    }
}

fn enum_value<T: serde::de::DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
}
