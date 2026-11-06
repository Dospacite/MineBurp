use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Bytes, BytesMut};
use mineburp_core::{
    ConnectionId, ConnectionSnapshot, ConnectionStatus, Direction, Disposition, PacketDetail,
    PacketSummary, ProtocolState, ReplacementRule, Target, TrafficSource, WireMetadata,
};
use mineburp_project::{ProjectError, ProjectStore};
use mineburp_protocol::{
    EncryptionRequest, FrameCodec, HandshakeError, PacketFrame, PacketRegistry, ProtocolError,
    SchemaError, SchemaPack, decode_common_packet, decode_handshake, decode_var_i32,
    encode_handshake,
};
use mineburp_session::{
    SessionJoinProvider, SessionJoinRequest, TransparentRouteProvider, TransparentTarget,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc},
    task::JoinSet,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    CompiledFilter, EncryptionBridgeError, FilterParseError, InterceptDecision, InterceptError,
    InterceptSettings, InterceptedPacket, Interceptor, NetworkConditions, NetworkConditionsError,
    encryption::{EncryptionBridge, LinkCipher},
    network::Shaper,
};

const SOCKET_BUFFER_CAPACITY: usize = 64 * 1024;
const WRITER_QUEUE_CAPACITY: usize = 512;

/// Bytes one writer may have queued before its reader waits.
///
/// A frame-count bound alone allowed 512 maximum-size frames — gigabytes — to
/// pile up behind a stalled peer.
const WRITER_QUEUE_BYTES: usize = 32 * 1024 * 1024;

/// How long a closing session gives its writers to deliver what is queued —
/// the server's disconnect reason, above all — before the sockets are dropped.
const DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// Frames read while one is held, waiting their turn, are capped so a held
/// frame cannot make the proxy buffer an unbounded amount of traffic.
const HELD_BACKLOG_BYTES: usize = 8 * 1024 * 1024;

/// Private routes the agent may have open but not yet connected to.
const MAX_PENDING_ROUTES: usize = 32;
/// Private routes the agent may request per second.
const ROUTES_PER_SECOND: u32 = 20;

/// How many packets may wait for one database transaction.
///
/// A busy Minecraft connection emits far more packets per second than `SQLite`
/// can commit individually; committing a transaction per packet was the
/// proxy's serialization point. The queue also drains on a short timer, so a
/// quiet connection's last packets still land within [`FLUSH_INTERVAL`].
const INSERT_BATCH_LIMIT: usize = 64;
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub target: Target,
    pub listen_port: Option<u16>,
    pub max_frame_length: usize,
    /// A transparent route is created before the client swaps its destination.
    /// It must not leave an unbounded number of unused loopback listeners when
    /// a connection attempt is cancelled by the game.
    pub accept_timeout: Duration,
    /// Forward the client's handshake address unchanged.
    ///
    /// A client routed here by the agent wrote the hostname from its server
    /// list, which is what virtual-host proxies (Velocity, `BungeeCord` forced
    /// hosts, `TCPShield`) route on. A client pointed at the loopback listener by
    /// hand wrote `127.0.0.1`, so that one is rewritten to the target.
    pub preserve_client_address: bool,
}

impl SessionOptions {
    #[must_use]
    pub fn new(target: Target) -> Self {
        Self {
            target,
            listen_port: None,
            max_frame_length: 16 * 1024 * 1024,
            accept_timeout: Duration::from_secs(15),
            preserve_client_address: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ProxyEvent {
    Connection(ConnectionSnapshot),
    Packet(PacketSummary),
    Error {
        connection_id: ConnectionId,
        message: String,
    },
    /// The Intercept queue changed; `pending` frames are now held.
    InterceptQueue {
        pending: usize,
    },
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error(transparent)]
    EncryptionBridge(#[from] EncryptionBridgeError),
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error("online-mode session authentication failed: {0}")]
    Authentication(String),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error(transparent)]
    InvalidFilter(#[from] FilterParseError),
    #[error("connection {0} does not exist")]
    UnknownConnection(ConnectionId),
    #[error("connection {0} is not ready for live injection")]
    ConnectionNotReady(ConnectionId),
    #[error("the client did not connect to its private route in time")]
    ClientRouteTimedOut,
    #[error("session task stopped")]
    SessionStopped,
    #[error(transparent)]
    Intercept(#[from] InterceptError),
    #[error(transparent)]
    NetworkConditions(#[from] NetworkConditionsError),
    #[error("too many private routes were requested; try again shortly")]
    RouteLimit,
}

/// A replacement rule with its selector already parsed.
///
/// An empty expression means "every packet", which is why the filter is
/// optional rather than a parsed `true` — the expression language has no
/// literal for it.
#[derive(Debug)]
struct CompiledReplacement {
    source: ReplacementRule,
    filter: Option<CompiledFilter>,
}

#[derive(Debug, Clone)]
struct SessionHandle {
    snapshot: Arc<RwLock<ConnectionSnapshot>>,
    client_writer: Arc<RwLock<Option<WriterSender>>>,
    server_writer: Arc<RwLock<Option<WriterSender>>>,
    compression_threshold: Arc<RwLock<Option<i32>>>,
    client_cipher: Arc<LinkCipher>,
    server_cipher: Arc<LinkCipher>,
    encryption_bridge: Arc<EncryptionBridge>,
    /// Set when the server has sent start-configuration from play, so the
    /// client's acknowledgement is only believed after the offer.
    reconfiguration_offered: Arc<AtomicBool>,
    /// Orders every row the session records, Repeater sends included.
    sequence: Arc<AtomicU64>,
    /// Set when the snapshot changed since it was last persisted and published.
    snapshot_dirty: Arc<AtomicBool>,
    cancel: CancellationToken,
}

impl SessionHandle {
    fn new(snapshot: ConnectionSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(snapshot)),
            client_writer: Arc::new(RwLock::new(None)),
            server_writer: Arc::new(RwLock::new(None)),
            compression_threshold: Arc::new(RwLock::new(None)),
            client_cipher: Arc::new(LinkCipher::new()),
            server_cipher: Arc::new(LinkCipher::new()),
            encryption_bridge: Arc::new(EncryptionBridge::new()),
            reconfiguration_offered: Arc::new(AtomicBool::new(false)),
            sequence: Arc::new(AtomicU64::new(1)),
            snapshot_dirty: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
        }
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct OutboundBytes {
    bytes: Bytes,
    encrypt: bool,
    /// When the proxy received the frame, which network delay is measured from.
    queued_at: Instant,
    /// Returns this frame's share of the writer's byte budget once written.
    _budget: Option<OwnedSemaphorePermit>,
}

/// The sending half of a writer queue, bounded by bytes as well as frames.
#[derive(Debug, Clone)]
struct WriterSender {
    frames: mpsc::Sender<OutboundBytes>,
    budget: Arc<Semaphore>,
}

impl WriterSender {
    fn channel() -> (Self, mpsc::Receiver<OutboundBytes>) {
        let (frames, receiver) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        (
            Self {
                frames,
                budget: Arc::new(Semaphore::new(WRITER_QUEUE_BYTES)),
            },
            receiver,
        )
    }

    /// Queues bytes, waiting while the writer already holds its byte budget.
    /// A frame larger than the whole budget waits for an empty queue.
    async fn send(&self, bytes: Bytes, encrypt: bool) -> Result<(), ProxyError> {
        let cost = u32::try_from(bytes.len().clamp(1, WRITER_QUEUE_BYTES)).unwrap_or(u32::MAX);
        let permit = Arc::clone(&self.budget)
            .acquire_many_owned(cost)
            .await
            .map_err(|_| ProxyError::SessionStopped)?;
        self.frames
            .send(OutboundBytes {
                bytes,
                encrypt,
                queued_at: Instant::now(),
                _budget: Some(permit),
            })
            .await
            .map_err(|_| ProxyError::SessionStopped)
    }
}

/// The reader's socket and buffers, lent to a held frame so the reader can
/// keep draining while it waits.
struct HoldIo<'a> {
    reader: &'a mut ReadHalf<TcpStream>,
    buffer: &'a mut BytesMut,
    codec: &'a FrameCodec,
    read_cipher: &'a LinkCipher,
    writer: &'a WriterSender,
    /// Frames read behind a held frame, processed in order once it is decided.
    pending: &'a mut VecDeque<PacketFrame>,
    pending_bytes: usize,
    classification_blocked: bool,
    closed: bool,
}

impl HoldIo<'_> {
    fn can_read(&self) -> bool {
        !self.closed
            && !self.classification_blocked
            && self.pending_bytes + self.buffer.len() < HELD_BACKLOG_BYTES
    }

    async fn read_more(&mut self) -> Result<(), ProxyError> {
        let mut chunk = vec![0_u8; SOCKET_BUFFER_CAPACITY];
        let read = self.reader.read(&mut chunk).await?;
        if read == 0 {
            // The peer stopped sending; the held frame still gets its verdict.
            self.closed = true;
            return Ok(());
        }
        chunk.truncate(read);
        self.read_cipher.decrypt(&mut chunk);
        self.buffer.extend_from_slice(&chunk);
        Ok(())
    }
}

/// Everything one direction's reader owns.
struct ReaderContext {
    reader: ReadHalf<TcpStream>,
    writer: WriterSender,
    handle: SessionHandle,
    direction: Direction,
    opaque: Arc<RwLock<bool>>,
    max_frame_length: usize,
    preserve_address: bool,
}

enum HoldEvent {
    Stopped,
    Decided(InterceptDecision),
    Read(Result<(), ProxyError>),
}

/// Removes a held entry when its wait ends without the operator's verdict.
struct HeldGuard<'a> {
    service: &'a ProxyService,
    id: u64,
}

impl Drop for HeldGuard<'_> {
    fn drop(&mut self) {
        if self.service.interceptor.discard(self.id) {
            self.service.announce_intercept_queue();
        }
    }
}

/// The cipher that decrypts what arrives travelling in `direction`.
fn inbound_cipher(handle: &SessionHandle, direction: Direction) -> &LinkCipher {
    match direction {
        Direction::ClientToServer => &handle.client_cipher,
        Direction::ServerToClient => &handle.server_cipher,
    }
}

/// The cipher that encrypts what leaves travelling in `direction`.
fn outbound_cipher(handle: &SessionHandle, direction: Direction) -> &LinkCipher {
    match direction {
        Direction::ClientToServer => &handle.server_cipher,
        Direction::ServerToClient => &handle.client_cipher,
    }
}

/// Packets that move a 1.20.2+ connection between configuration and play,
/// named by the per-version table.
fn transition_name(
    state: ProtocolState,
    direction: Direction,
    packet_id: Option<i32>,
    protocol: Option<i32>,
) -> Option<&'static str> {
    let name = PacketRegistry::table_packet_name(state, direction, packet_id?, protocol)?;
    matches!(
        (state, direction, name),
        (
            ProtocolState::Configuration,
            Direction::ServerToClient,
            "finish_configuration"
        ) | (
            ProtocolState::Configuration,
            Direction::ClientToServer,
            "finish_configuration_ack"
        ) | (
            ProtocolState::Play,
            Direction::ServerToClient,
            "start_configuration"
        ) | (
            ProtocolState::Play,
            Direction::ClientToServer,
            "configuration_acknowledged"
        )
    )
    .then_some(name)
}

fn is_state_transition(
    state: ProtocolState,
    direction: Direction,
    packet_id: Option<i32>,
    protocol: Option<i32>,
) -> bool {
    matches!((state, direction, packet_id),
        (ProtocolState::Login, Direction::ServerToClient, Some(2)) if protocol.is_some_and(|p| p < 764))
        || matches!((state, direction, packet_id),
        (ProtocolState::Login, Direction::ClientToServer, Some(3)) if protocol.is_some_and(|p| p >= 764))
        || transition_name(state, direction, packet_id, protocol).is_some()
}

/// A held frame after which buffered bytes need a different decoder.
///
/// Encryption Response starts the cipher in both directions. Set Compression
/// changes the frame codec for every packet that follows it. Decoding bytes
/// behind either packet before the operator forwards it irreversibly puts a
/// wrongly decoded frame into the backlog.
fn changes_stream_encoding(
    state: ProtocolState,
    direction: Direction,
    packet_id: Option<i32>,
) -> bool {
    matches!(
        (state, direction, packet_id),
        (ProtocolState::Login, Direction::ClientToServer, Some(1))
            | (ProtocolState::Login, Direction::ServerToClient, Some(3))
    )
}

#[derive(Debug, Clone)]
pub struct ProxyService {
    registry: Arc<PacketRegistry>,
    project: Arc<RwLock<Option<ProjectStore>>>,
    sessions: Arc<RwLock<HashMap<ConnectionId, SessionHandle>>>,
    replacements: Arc<RwLock<Vec<CompiledReplacement>>>,
    session_join_provider: Arc<RwLock<Option<Arc<dyn SessionJoinProvider>>>>,
    schema_packs: Arc<RwLock<Vec<SchemaPack>>>,
    events: broadcast::Sender<ProxyEvent>,
    queue: Arc<PersistenceQueue>,
    next_packet_id: Arc<AtomicI64>,
    interceptor: Arc<Interceptor>,
    network: Arc<RwLock<NetworkConditions>>,
    /// Start of the current one-second route window and routes opened in it.
    route_window: Arc<Mutex<(Instant, u32)>>,
}

impl Default for ProxyService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyService {
    #[must_use]
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(2_048);
        let project = Arc::new(RwLock::new(None));
        let queue = Arc::new(PersistenceQueue {
            project: Arc::clone(&project),
            events: events.clone(),
            pending: Mutex::new(Vec::new()),
            lifecycle: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
            wake: tokio::sync::Notify::new(),
            dirty: Mutex::new(HashMap::new()),
            flusher_started: AtomicBool::new(false),
        });
        let service = Self {
            registry: Arc::new(PacketRegistry::bundled()),
            project,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            replacements: Arc::new(RwLock::new(Vec::new())),
            session_join_provider: Arc::new(RwLock::new(None)),
            schema_packs: Arc::new(RwLock::new(Vec::new())),
            events,
            queue,
            next_packet_id: Arc::new(AtomicI64::new(1)),
            interceptor: Arc::new(Interceptor::default()),
            network: Arc::new(RwLock::new(NetworkConditions::default())),
            route_window: Arc::new(Mutex::new((Instant::now(), 0))),
        };
        let _ = service.start_persistence_flusher();
        service
    }

    /// Starts the worker that commits bounded batches on notification or a timer.
    ///
    /// Construction can happen outside a Tokio runtime, notably in Tauri's
    /// synchronous setup callback. Such callers must invoke this once from
    /// their async runtime. Repeated calls are harmless.
    #[must_use]
    pub fn start_persistence_flusher(&self) -> bool {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        if self.queue.flusher_started.swap(true, Ordering::AcqRel) {
            return true;
        }
        // The weak reference lets the ticker end once the last service handle
        // drops instead of pinning the service alive forever.
        let ticker_queue = Arc::downgrade(&self.queue);
        runtime.spawn(async move {
            let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(queue) = ticker_queue.upgrade() else {
                    break;
                };
                tokio::select! { () = queue.wake.notified() => {}, _ = ticker.tick() => {} }
                queue.flush().await;
            }
        });
        true
    }

    /// The delay, jitter and bandwidth applied to every proxied connection.
    #[must_use]
    pub fn network_conditions(&self) -> NetworkConditions {
        *self.network.read()
    }

    /// Changes network shaping. It applies to frames written from now on,
    /// including on connections that are already open.
    pub fn set_network_conditions(&self, conditions: NetworkConditions) -> Result<(), ProxyError> {
        conditions.validate()?;
        *self.network.write() = conditions;
        Ok(())
    }

    pub fn set_project(&self, project: Option<ProjectStore>) {
        *self.project.write() = project;
    }

    pub fn set_session_join_provider(&self, provider: Option<Arc<dyn SessionJoinProvider>>) {
        *self.session_join_provider.write() = provider;
    }

    pub fn set_schema_packs(&self, packs: Vec<SchemaPack>) -> Result<(), ProxyError> {
        for pack in &packs {
            pack.validate()?;
        }
        *self.schema_packs.write() = packs;
        Ok(())
    }

    /// The currently loaded schema packs, for decoding a packet on demand.
    #[must_use]
    pub fn schema_packs(&self) -> Vec<SchemaPack> {
        self.schema_packs.read().clone()
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.events.subscribe()
    }

    /// Installs the rules that rewrite packets automatically.
    pub fn set_replacement_rules(&self, rules: Vec<ReplacementRule>) -> Result<(), ProxyError> {
        let compiled = rules
            .into_iter()
            .map(|source| {
                let filter = if source.expression.trim().is_empty() {
                    None
                } else {
                    Some(CompiledFilter::parse(&source.expression)?)
                };
                Ok(CompiledReplacement { source, filter })
            })
            .collect::<Result<Vec<_>, FilterParseError>>()?;
        *self.replacements.write() = compiled;
        Ok(())
    }

    #[must_use]
    pub fn intercept_settings(&self) -> InterceptSettings {
        self.interceptor.settings()
    }

    /// Changes what Intercept holds. Turning it off forwards everything held.
    pub fn set_intercept_settings(&self, settings: InterceptSettings) -> Result<(), ProxyError> {
        self.interceptor.set_settings(settings)?;
        self.announce_intercept_queue();
        Ok(())
    }

    /// Frames Intercept is holding, oldest first.
    #[must_use]
    pub fn intercepted(&self) -> Vec<InterceptedPacket> {
        self.interceptor.pending()
    }

    /// Releases one held frame. A replacement must still frame as a packet;
    /// if it does not, the frame stays held so the operator can fix it.
    pub fn resolve_intercept(
        &self,
        id: u64,
        decision: InterceptDecision,
    ) -> Result<(), ProxyError> {
        if let InterceptDecision::Replace(bytes) = &decision {
            PacketFrame::from_logical_bytes(bytes.clone())?;
        }
        self.interceptor.resolve(id, decision)?;
        self.announce_intercept_queue();
        Ok(())
    }

    /// Forwards every held frame unchanged and reports how many there were.
    pub fn forward_all_intercepted(&self) -> usize {
        let released = self.interceptor.release_all();
        self.announce_intercept_queue();
        released
    }

    fn announce_intercept_queue(&self) {
        let _ = self.events.send(ProxyEvent::InterceptQueue {
            pending: self.interceptor.pending_count(),
        });
    }

    /// Holds a frame until the operator decides, its deadline passes, or its
    /// session ends.
    ///
    /// While it waits, the reader keeps draining its socket: keep-alives and
    /// pings are forwarded at once, so holding a frame cannot make the server
    /// time the player out, and everything else queues behind the held frame
    /// in order.
    async fn await_intercept(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        detail: &PacketDetail,
        io: &mut HoldIo<'_>,
    ) -> Result<InterceptDecision, ProxyError> {
        let target = handle.snapshot.read().target.authority();
        let wait = self.interceptor.auto_forward_after();
        let held_at = now_micros();
        let deadline_micros = wait.map(|wait| {
            held_at.saturating_add(i64::try_from(wait.as_micros()).unwrap_or(i64::MAX))
        });
        let (id, decision) = self.interceptor.hold(
            detail.summary.clone(),
            target,
            detail.logical_bytes.clone(),
            held_at,
            deadline_micros,
        );
        // Releases the entry however this wait ends — including the task
        // being aborted — so the queue never shows a frame nobody is waiting on.
        let _guard = HeldGuard { service: self, id };
        self.announce_intercept_queue();

        // Frames that change protocol state or stream encoding must not be
        // prefetched. What follows needs the new state, cipher, or codec.
        let allow_bypass = !is_state_transition(
            detail.summary.state,
            direction,
            detail.summary.packet_id,
            detail.summary.protocol_version,
        ) && !changes_stream_encoding(
            detail.summary.state,
            direction,
            detail.summary.packet_id,
        );
        if allow_bypass {
            self.drain_held_backlog(handle, direction, io).await?;
        }
        let deadline = async move {
            match wait {
                Some(wait) => tokio::time::sleep(wait).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(deadline);
        tokio::pin!(decision);
        loop {
            let event = tokio::select! {
                biased;
                () = handle.cancel.cancelled() => HoldEvent::Stopped,
                // A dropped sender means the queue was cleared without a verdict.
                decision = &mut decision => HoldEvent::Decided(
                    decision.unwrap_or(InterceptDecision::Forward),
                ),
                () = &mut deadline => HoldEvent::Decided(InterceptDecision::Forward),
                read = io.read_more(), if allow_bypass && io.can_read() => HoldEvent::Read(read),
            };
            match event {
                HoldEvent::Stopped => return Err(ProxyError::SessionStopped),
                HoldEvent::Decided(decision) => return Ok(decision),
                HoldEvent::Read(read) => {
                    read?;
                    self.drain_held_backlog(handle, direction, io).await?;
                }
            }
        }
    }

    /// Frames every complete frame buffered behind a held one: keep-alives
    /// and pings go straight out, the rest wait for the held frame's verdict.
    async fn drain_held_backlog(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        io: &mut HoldIo<'_>,
    ) -> Result<(), ProxyError> {
        if io.classification_blocked {
            return Ok(());
        }
        while let Some(frame) = io.codec.try_decode(io.buffer)? {
            let (state, protocol) = {
                let snapshot = handle.snapshot.read();
                (snapshot.state, snapshot.protocol_version)
            };
            let name = mineburp_protocol::identify_packet(
                state,
                direction,
                frame.id,
                &frame.body,
                protocol,
            );
            if self
                .interceptor
                .bypasses_hold(state, direction, frame.id, protocol, name.as_deref())
            {
                self.forward_unchanged(handle, direction, &frame, io.writer)
                    .await?;
            } else {
                let barrier = is_state_transition(state, direction, Some(frame.id), protocol)
                    || changes_stream_encoding(state, direction, Some(frame.id));
                io.pending_bytes += frame.body.len() + 64;
                io.pending.push_back(frame);
                if barrier {
                    io.classification_blocked = true;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Records and sends a frame exactly as it was read.
    async fn forward_unchanged(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        frame: &PacketFrame,
        writer: &WriterSender,
    ) -> Result<(), ProxyError> {
        let state = handle.snapshot.read().state;
        let encrypted = inbound_cipher(handle, direction).is_active();
        let mut detail = self.make_detail(
            handle,
            direction,
            frame,
            Disposition::Forwarded,
            state,
            encrypted,
        );
        if self.should_block(&detail.summary) {
            detail.summary.disposition = Disposition::Dropped;
            detail.summary.sequence = handle.next_sequence();
            self.record_packet(detail).await;
            self.queue.mark_dirty(handle);
            return Ok(());
        }
        let mut outbound = frame.clone();
        if let Some(bytes) = self.rewrite(&detail, state, direction) {
            match PacketFrame::from_logical_bytes(bytes) {
                Ok(replaced) => {
                    outbound = replaced;
                    detail = self.make_detail(
                        handle,
                        direction,
                        &outbound,
                        Disposition::Edited,
                        state,
                        encrypted,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "a replacement rule produced an unusable frame");
                }
            }
        }
        detail.summary.sequence = handle.next_sequence();
        self.record_packet(detail).await;
        self.queue.mark_dirty(handle);
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(*handle.compression_threshold.read());
        writer
            .send(
                codec.encode(&outbound)?,
                outbound_cipher(handle, direction).is_active(),
            )
            .await
    }

    pub async fn start_session(
        &self,
        options: SessionOptions,
    ) -> Result<ConnectionSnapshot, ProxyError> {
        let listener = TcpListener::bind(("127.0.0.1", options.listen_port.unwrap_or(0))).await?;
        let listener_address = listener.local_addr()?.to_string();
        let id = Uuid::new_v4();
        let snapshot = ConnectionSnapshot {
            id,
            target: options.target.clone(),
            listener_address,
            status: ConnectionStatus::Listening,
            state: ProtocolState::Handshake,
            protocol_version: None,
            minecraft_version: None,
            loader: None,
            compression_threshold: None,
            encrypted_client: false,
            encrypted_server: false,
            packet_count: 0,
            byte_count: 0,
            last_error: None,
        };
        let handle = SessionHandle::new(snapshot.clone());
        self.sessions.write().insert(id, handle.clone());
        self.publish_snapshot(&handle).await;
        let service = self.clone();
        tokio::spawn(async move {
            if let Err(error) = service.run_session(listener, handle, options).await {
                service.fail_session(id, error.to_string()).await;
            }
            // The final snapshot is in the project; the live table only
            // tracks sessions that can still carry traffic.
            service.sessions.write().remove(&id);
        });
        Ok(snapshot)
    }

    /// Admits one private route request, or refuses it when too many are
    /// waiting for a client or too many arrived in the last second.
    fn admit_route(&self) -> Result<(), ProxyError> {
        let waiting = self
            .sessions
            .read()
            .values()
            .filter(|handle| {
                matches!(
                    handle.snapshot.read().status,
                    ConnectionStatus::Listening | ConnectionStatus::Connecting
                )
            })
            .count();
        if waiting >= MAX_PENDING_ROUTES {
            return Err(ProxyError::RouteLimit);
        }
        let mut window = self.route_window.lock();
        let now = Instant::now();
        if now.duration_since(window.0) >= Duration::from_secs(1) {
            *window = (now, 0);
        }
        if window.1 >= ROUTES_PER_SECOND {
            return Err(ProxyError::RouteLimit);
        }
        window.1 += 1;
        Ok(())
    }

    /// Loopback ports this service is currently accepting private routes on.
    ///
    /// Passive capture sees the client's socket to those ports as ordinary
    /// Minecraft traffic, but it is the *encrypted* half of a stream the proxy
    /// is already recording in the clear, so the desktop layer uses this to
    /// avoid filling the history with an unreadable duplicate of every packet.
    #[must_use]
    pub fn listener_ports(&self) -> Vec<u16> {
        self.sessions
            .read()
            .values()
            .filter_map(|handle| {
                handle
                    .snapshot
                    .read()
                    .listener_address
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
            })
            .collect()
    }

    #[must_use]
    pub fn sessions(&self) -> Vec<ConnectionSnapshot> {
        self.sessions
            .read()
            .values()
            .map(|handle| handle.snapshot.read().clone())
            .collect()
    }

    pub fn stop_session(&self, id: ConnectionId) -> Result<(), ProxyError> {
        let handle = self
            .sessions
            .read()
            .get(&id)
            .cloned()
            .ok_or(ProxyError::UnknownConnection(id))?;
        handle.cancel.cancel();
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Closing;
        });
        Ok(())
    }

    pub async fn repeater_send(
        &self,
        connection_id: ConnectionId,
        direction: Direction,
        logical_bytes: Bytes,
    ) -> Result<(), ProxyError> {
        let handle = self
            .sessions
            .read()
            .get(&connection_id)
            .cloned()
            .ok_or(ProxyError::UnknownConnection(connection_id))?;
        // Compression and encryption are both settled during login, and only
        // from configuration onwards does neither change under an injected
        // frame — before that, the framing chosen here could be stale by the
        // time the writer sends it.
        let state = handle.snapshot.read().state;
        if !matches!(state, ProtocolState::Configuration | ProtocolState::Play) {
            return Err(ProxyError::ConnectionNotReady(connection_id));
        }
        let frame = PacketFrame::from_logical_bytes(logical_bytes.clone())?;
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(*handle.compression_threshold.read());
        let encoded = codec.encode(&frame)?;
        let sender = match direction {
            Direction::ClientToServer => handle.server_writer.read().clone(),
            Direction::ServerToClient => handle.client_writer.read().clone(),
        }
        .ok_or(ProxyError::ConnectionNotReady(connection_id))?;
        sender
            .send(encoded, outbound_cipher(&handle, direction).is_active())
            .await?;

        let mut detail = self.make_detail(
            &handle,
            direction,
            &frame,
            Disposition::Replayed,
            state,
            false,
        );
        detail.summary.sequence = handle.next_sequence();
        self.record_packet(detail).await;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_session(
        &self,
        listener: TcpListener,
        handle: SessionHandle,
        options: SessionOptions,
    ) -> Result<(), ProxyError> {
        let accept = tokio::time::timeout(options.accept_timeout, listener.accept());
        let (client, _) = tokio::select! {
            accepted = accept => accepted.map_err(|_| ProxyError::ClientRouteTimedOut)??,
            () = handle.cancel.cancelled() => {
                update_snapshot(&handle, |snapshot| snapshot.status = ConnectionStatus::Closed);
                self.publish_snapshot(&handle).await;
                return Ok(());
            },
        };
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Connecting;
        });
        let server = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(options.target.authority())) => {
                result.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream connect timed out"))??
            }
            () = handle.cancel.cancelled() => {
                update_snapshot(&handle, |snapshot| snapshot.status = ConnectionStatus::Closed);
                self.publish_snapshot(&handle).await;
                return Ok(());
            }
        };
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Active;
        });
        self.publish_snapshot(&handle).await;

        let (client_reader, client_writer) = tokio::io::split(client);
        let (server_reader, server_writer) = tokio::io::split(server);
        let (to_client, client_rx) = WriterSender::channel();
        let (to_server, server_rx) = WriterSender::channel();
        *handle.client_writer.write() = Some(to_client.clone());
        *handle.server_writer.write() = Some(to_server.clone());

        let opaque = Arc::new(RwLock::new(false));
        let max_frame_length = options.max_frame_length;
        let preserve_address = options.preserve_client_address;
        let mut writers = JoinSet::new();
        writers.spawn(writer_loop(
            client_writer,
            client_rx,
            handle.client_cipher.clone(),
            handle.cancel.clone(),
            Arc::clone(&self.network),
            Direction::ServerToClient,
        ));
        writers.spawn(writer_loop(
            server_writer,
            server_rx,
            handle.server_cipher.clone(),
            handle.cancel.clone(),
            Arc::clone(&self.network),
            Direction::ClientToServer,
        ));

        let mut readers = JoinSet::new();
        for (reader, writer, direction) in [
            (client_reader, to_server, Direction::ClientToServer),
            (server_reader, to_client, Direction::ServerToClient),
        ] {
            let service = self.clone();
            let handle = handle.clone();
            let opaque = opaque.clone();
            readers.spawn(async move {
                service
                    .reader_loop(ReaderContext {
                        reader,
                        writer,
                        handle,
                        direction,
                        opaque,
                        max_frame_length,
                        preserve_address,
                    })
                    .await
            });
        }

        let outcome = tokio::select! {
            () = handle.cancel.cancelled() => Ok(()),
            result = readers.join_next() => match result {
                Some(Ok(result)) => result,
                _ => Ok(()),
            },
        };
        // One side finished. Stop the other reader so nothing new is queued,
        // then let both writers deliver what already is — a server's
        // disconnect reason is usually the last frame before it closes.
        readers.shutdown().await;
        *handle.client_writer.write() = None;
        *handle.server_writer.write() = None;
        let drained = tokio::time::timeout(DRAIN_DEADLINE, async {
            while writers.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::debug!("writers did not drain before the deadline");
        }
        handle.cancel.cancel();
        writers.shutdown().await;
        outcome?;
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Closed;
            snapshot.state = ProtocolState::Closed;
        });
        self.publish_snapshot(&handle).await;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn reader_loop(&self, context: ReaderContext) -> Result<(), ProxyError> {
        let ReaderContext {
            mut reader,
            writer,
            handle,
            direction,
            opaque,
            max_frame_length,
            preserve_address,
        } = context;
        let mut buffer = BytesMut::with_capacity(SOCKET_BUFFER_CAPACITY);
        // Frames read while an earlier one was held, still to be processed.
        let mut backlog: VecDeque<PacketFrame> = VecDeque::new();
        let mut pending_bytes = 0;
        let mut closed = false;
        loop {
            if handle.cancel.is_cancelled() {
                return Ok(());
            }
            if *opaque.read() {
                if !buffer.is_empty() {
                    let bytes = buffer.split().freeze();
                    writer.send(bytes.clone(), false).await?;
                    self.record_opaque(&handle, direction, bytes).await;
                }
                if closed {
                    return Ok(());
                }
                let mut chunk = vec![0_u8; SOCKET_BUFFER_CAPACITY];
                let read = reader.read(&mut chunk).await?;
                if read == 0 {
                    return Ok(());
                }
                chunk.truncate(read);
                let bytes = Bytes::from(chunk);
                writer.send(bytes.clone(), false).await?;
                self.record_opaque(&handle, direction, bytes).await;
                continue;
            }

            let mut codec = FrameCodec::new(max_frame_length);
            codec.set_compression_threshold(*handle.compression_threshold.read());
            loop {
                let frame = match backlog.pop_front() {
                    Some(frame) => {
                        pending_bytes -= frame.body.len() + 64;
                        frame
                    }
                    None => match codec.try_decode(&mut buffer)? {
                        Some(frame) => frame,
                        None => break,
                    },
                };
                let read_cipher = inbound_cipher(&handle, direction);
                let classification_blocked = backlog.back().is_some_and(|frame| {
                    let snapshot = handle.snapshot.read();
                    is_state_transition(
                        snapshot.state,
                        direction,
                        Some(frame.id),
                        snapshot.protocol_version,
                    ) || changes_stream_encoding(snapshot.state, direction, Some(frame.id))
                });
                let mut io = HoldIo {
                    reader: &mut reader,
                    buffer: &mut buffer,
                    codec: &codec,
                    read_cipher,
                    writer: &writer,
                    pending: &mut backlog,
                    pending_bytes,
                    classification_blocked,
                    closed,
                };
                let cipher_started = self
                    .process_frame(
                        &handle,
                        direction,
                        frame,
                        &mut io,
                        &opaque,
                        preserve_address,
                    )
                    .await?;
                closed = io.closed;
                pending_bytes = io.pending_bytes;
                if cipher_started && !buffer.is_empty() {
                    // Whatever followed the encryption response in the same read
                    // was copied into the buffer before this link had a cipher,
                    // so it is still ciphertext. Without decrypting it here the
                    // very first encrypted packets — login acknowledged and the
                    // whole configuration phase — frame as garbage and the
                    // session dies on a bogus length.
                    let mut pending = buffer.split().to_vec();
                    read_cipher.decrypt(&mut pending);
                    buffer.extend_from_slice(&pending);
                }
                if *opaque.read() {
                    // The rest of the buffer is ciphertext the proxy cannot
                    // read; the opaque path above relays it as-is.
                    break;
                }
                codec.set_compression_threshold(*handle.compression_threshold.read());
            }
            if *opaque.read() {
                continue;
            }
            if closed && backlog.is_empty() {
                return Ok(());
            }
            let mut chunk = vec![0_u8; SOCKET_BUFFER_CAPACITY];
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            chunk.truncate(read);
            inbound_cipher(&handle, direction).decrypt(&mut chunk);
            buffer.extend_from_slice(&chunk);
        }
    }

    /// Applies the proxy's bookkeeping rewrites to the frame about to be sent:
    /// the handshake's target address and both halves of the key exchange.
    ///
    /// `outbound` is the frame after rules and Intercept, so edited fields
    /// (including `should_authenticate`) survive and only the proxy's key,
    /// verify token, and address are substituted. Returns the shared secret
    /// when this frame completes the key exchange.
    async fn bridge_outbound(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        state: ProtocolState,
        arrived: &PacketFrame,
        outbound: &mut PacketFrame,
        preserve_address: bool,
    ) -> Result<Option<[u8; 16]>, ProxyError> {
        if state == ProtocolState::Handshake
            && direction == Direction::ClientToServer
            && outbound.id == 0
            && !preserve_address
            && let Ok(mut handshake) = decode_handshake(&outbound.body)
        {
            let original = decode_handshake(&arrived.body).ok();
            let (host, markers) = split_address(&handshake.server_address);
            let host_unchanged = original
                .as_ref()
                .is_none_or(|original| split_address(&original.server_address).0 == host);
            let markers = markers.to_owned();
            let port_unchanged = original
                .as_ref()
                .is_none_or(|original| original.server_port == handshake.server_port);
            // An edited host or port is the operator's choice; only what the
            // client chose is replaced with the real target.
            let target = handle.snapshot.read().target.clone();
            if host_unchanged {
                handshake.server_address = format!("{}{markers}", target.host);
            }
            if port_unchanged {
                handshake.server_port = target.port;
            }
            outbound.body = encode_handshake(&handshake)?;
        }

        if state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && outbound.id == 1
            && self.session_join_provider.read().is_some()
        {
            let protocol_version = handle.snapshot.read().protocol_version.unwrap_or_default();
            let request = EncryptionRequest::decode_for(&outbound.body, protocol_version)
                .map_err(EncryptionBridgeError::from)?;
            // RSA key generation is tens of milliseconds of CPU; it must not
            // stall a runtime worker every other session shares.
            let key = tokio::task::spawn_blocking(EncryptionBridge::generate_key)
                .await
                .map_err(|_| ProxyError::SessionStopped)??;
            outbound.body =
                handle
                    .encryption_bridge
                    .intercept_request(request, key, protocol_version)?;
        }

        if state == ProtocolState::Login
            && direction == Direction::ClientToServer
            && outbound.id == 1
            && handle.encryption_bridge.is_negotiating()
        {
            let provider = { self.session_join_provider.read().clone() };
            if let Some(provider) = provider {
                let protocol_version = handle.snapshot.read().protocol_version.unwrap_or_default();
                let mut negotiation = handle
                    .encryption_bridge
                    .intercept_response(&outbound.body, protocol_version)?;
                // The client was sent this flag. When it is false the client
                // does not join, so there is no join to correlate, and the
                // server decides for itself whether to accept the login.
                if negotiation.should_authenticate {
                    provider
                        .join_server(&SessionJoinRequest {
                            client_server_hash: std::mem::take(&mut negotiation.client_server_hash),
                            upstream_server_hash: std::mem::take(
                                &mut negotiation.upstream_server_hash,
                            ),
                        })
                        .await
                        .map_err(ProxyError::Authentication)?;
                }
                outbound.body = std::mem::take(&mut negotiation.server_response);
                return Ok(Some(negotiation.shared_secret));
            }
        }
        Ok(None)
    }

    /// Handles one decoded frame and reports whether this link's cipher was
    /// activated by it, which the reader loop needs in order to decrypt bytes it
    /// had already buffered.
    #[allow(clippy::too_many_lines)]
    async fn process_frame(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        frame: PacketFrame,
        io: &mut HoldIo<'_>,
        opaque: &RwLock<bool>,
        preserve_address: bool,
    ) -> Result<bool, ProxyError> {
        let state = handle.snapshot.read().state;
        let mut outbound = frame.clone();

        let current_state = handle.snapshot.read().state;
        let input_encrypted = inbound_cipher(handle, direction).is_active();
        // The row shows the frame as it arrived; the proxy's own handshake and
        // key-exchange rewrites are bookkeeping, not traffic under test.
        let mut detail = self.make_detail(
            handle,
            direction,
            &frame,
            Disposition::Forwarded,
            state,
            input_encrypted,
        );
        if self.should_block(&detail.summary) {
            detail.summary.disposition = Disposition::Dropped;
            detail.summary.sequence = handle.next_sequence();
            self.record_packet(detail).await;
            self.queue.mark_dirty(handle);
            return Ok(false);
        }
        // A rule that rewrites a packet has already decided what goes on the
        // wire, and the recorded row is what was actually sent.
        if let Some(bytes) = self.rewrite(&detail, state, direction) {
            match PacketFrame::from_logical_bytes(bytes) {
                Ok(replaced) => {
                    outbound = replaced;
                    detail = self.make_detail(
                        handle,
                        direction,
                        &outbound,
                        Disposition::Edited,
                        state,
                        input_encrypted,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "a replacement rule produced an unusable frame");
                }
            }
        }
        // Intercept sees the frame as the rules left it, and what it forwards
        // is what gets recorded.
        if self.interceptor.should_hold(&detail.summary) {
            match self.await_intercept(handle, direction, &detail, io).await? {
                InterceptDecision::Forward => {}
                InterceptDecision::Replace(bytes) => {
                    outbound = PacketFrame::from_logical_bytes(bytes)?;
                    detail = self.make_detail(
                        handle,
                        direction,
                        &outbound,
                        Disposition::Edited,
                        state,
                        input_encrypted,
                    );
                }
                InterceptDecision::Drop => {
                    // The peer never sees it, so it cannot move the protocol state.
                    detail.summary.disposition = Disposition::Dropped;
                    detail.summary.sequence = handle.next_sequence();
                    self.record_packet(detail).await;
                    self.queue.mark_dirty(handle);
                    return Ok(false);
                }
            }
        }
        // The proxy's own rewrites run on what will actually be sent, after
        // rules and Intercept, so an edit can never undo them.
        let activate_encryption = self
            .bridge_outbound(
                handle,
                direction,
                state,
                &frame,
                &mut outbound,
                preserve_address,
            )
            .await?;
        detail.summary.sequence = handle.next_sequence();
        self.record_packet(detail).await;

        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(*handle.compression_threshold.read());
        let encoded = codec.encode(&outbound)?;
        // The frame that completes the key exchange still travels in the
        // clear. Every frame after it is encrypted, so both ciphers are live
        // before this one can reach the server: a fast server's first
        // encrypted reply must never meet a link without its cipher.
        let encrypt =
            activate_encryption.is_none() && outbound_cipher(handle, direction).is_active();
        let mut cipher_started = false;
        if let Some(shared_secret) = activate_encryption {
            handle.client_cipher.activate(shared_secret);
            handle.server_cipher.activate(shared_secret);
            cipher_started = true;
            update_snapshot(handle, |snapshot| {
                snapshot.encrypted_client = true;
                snapshot.encrypted_server = true;
            });
        }
        if state == ProtocolState::Handshake
            && direction == Direction::ClientToServer
            && outbound.id == 0
            && let Ok(handshake) = decode_handshake(&outbound.body)
        {
            update_snapshot(handle, |snapshot| {
                snapshot.protocol_version = Some(handshake.protocol_version);
                snapshot.minecraft_version = self
                    .registry
                    .version(handshake.protocol_version)
                    .map(|version| version.canonical.clone());
                snapshot.state = if handshake.next_state == 1 {
                    ProtocolState::Status
                } else {
                    ProtocolState::Login
                };
                snapshot.loader = loader_from_address(&handshake.server_address);
            });
        }
        io.writer.send(encoded, encrypt).await?;

        // From here on the state follows what was actually forwarded: the
        // peer acts on the frame it received, not the one that arrived.
        let sent = &outbound;
        if current_state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && sent.id == 3
            && let Some((threshold, _)) = decode_var_i32(&sent.body)?
        {
            // A negative threshold switches compression off.
            let threshold = (threshold >= 0).then_some(threshold);
            *handle.compression_threshold.write() = threshold;
            update_snapshot(handle, |snapshot| {
                snapshot.compression_threshold = threshold;
            });
        }
        let protocol_version = handle.snapshot.read().protocol_version;
        if current_state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && sent.id == 2
            && protocol_version.is_some_and(|version| version < 764)
        {
            update_snapshot(handle, |snapshot| snapshot.state = ProtocolState::Play);
        }
        if current_state == ProtocolState::Login
            && direction == Direction::ClientToServer
            && sent.id == 3
            && protocol_version.is_some_and(|version| version >= 764)
        {
            update_snapshot(handle, |snapshot| {
                snapshot.state = ProtocolState::Configuration;
            });
        }
        if current_state == ProtocolState::Login
            && direction == Direction::ClientToServer
            && sent.id == 1
            && activate_encryption.is_none()
        {
            *opaque.write() = true;
            update_snapshot(handle, |snapshot| {
                snapshot.state = ProtocolState::Opaque;
                snapshot.encrypted_client = true;
                snapshot.encrypted_server = true;
            });
        }
        track_configuration_phase(handle, direction, sent, current_state);
        self.queue.mark_dirty(handle);
        Ok(cipher_started)
    }
    /// Runs every enabled replacement rule whose selector matches, in order.
    ///
    /// A rule that fails — an unknown field, a bad pattern — is reported and
    /// skipped rather than dropping the connection: an operator's typo in a
    /// rule must not disconnect the game they are testing.
    fn should_block(&self, summary: &PacketSummary) -> bool {
        self.replacements.read().iter().any(|rule| {
            rule.source.enabled
                && rule.source.action == mineburp_core::ReplacementAction::Drop
                && rule
                    .filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(summary))
        })
    }

    fn rewrite(
        &self,
        detail: &PacketDetail,
        state: ProtocolState,
        direction: Direction,
    ) -> Option<Bytes> {
        // Handshake and login belong to the proxy: it rewrites the address and
        // bridges the key exchange there, and a rule editing those frames
        // would undo that work or desynchronise the framing.
        if matches!(state, ProtocolState::Handshake | ProtocolState::Login) {
            return None;
        }
        let rules = self.replacements.read();
        let matching: Vec<&ReplacementRule> = rules
            .iter()
            .filter(|rule| {
                rule.source.enabled
                    && rule.source.action == mineburp_core::ReplacementAction::Rewrite
                    && !rule.source.edits.is_empty()
                    && rule
                        .filter
                        .as_ref()
                        .is_none_or(|filter| filter.matches(&detail.summary))
            })
            .map(|rule| &rule.source)
            .collect();
        if matching.is_empty() {
            return None;
        }
        let mut frame = detail.logical_bytes.to_vec();
        let mut changed = false;
        for rule in matching {
            match mineburp_protocol::apply_edits(
                state,
                direction,
                detail.summary.protocol_version,
                &frame,
                &rule.edits,
            ) {
                Ok(next) => {
                    changed |= next != frame;
                    frame = next;
                }
                Err(mineburp_protocol::RewriteError::UnknownField(_)) => {}
                Err(error) => {
                    tracing::warn!(rule = %rule.name, %error, "replacement rule skipped");
                }
            }
        }
        changed.then(|| Bytes::from(frame))
    }

    fn make_detail(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        frame: &PacketFrame,
        disposition: Disposition,
        state: ProtocolState,
        encrypted: bool,
    ) -> PacketDetail {
        let snapshot = handle.snapshot.read();
        let logical = frame.logical_bytes();
        let common = decode_common_packet(
            state,
            direction,
            frame.id,
            &frame.body,
            snapshot.protocol_version,
        );
        let mut channel = common.channel;
        let mut loader = common.loader.or_else(|| snapshot.loader.clone());
        // Names every row it can, not just the ids that are stable across
        // versions: play packets are identified from the shape of their body,
        // which is the only thing that survives Mojang renumbering them.
        let mut name = mineburp_protocol::identify_packet(
            state,
            direction,
            frame.id,
            &frame.body,
            snapshot.protocol_version,
        );
        // Modern custom payloads are `channel` + opaque data with no common
        // decoder branch (their id moves every release), so the channel would
        // otherwise be missing from the row and invisible to channel filters.
        if channel.is_none()
            && matches!(name.as_deref(), Some("custom_payload" | "plugin_message"))
            && let Some((found, found_loader)) = mineburp_protocol::plugin_channel(&frame.body)
        {
            channel = Some(found);
            loader = loader.or(found_loader);
        }
        // Matching a schema is a cheap predicate and gives the row its name.
        // Running the schema *decode* here is not: it walked every field of
        // every captured packet, including ones nobody opens. The decode now
        // happens when a packet is selected, from the same schema packs.
        let matched_schema_name = {
            self.schema_packs
                .read()
                .iter()
                .flat_map(|pack| &pack.schemas)
                .find(|schema| {
                    schema.matches(
                        state,
                        direction,
                        frame.id,
                        channel.as_deref(),
                        snapshot.protocol_version,
                    )
                })
                .map(|schema| schema.name.clone())
        };
        if let Some(schema_name) = matched_schema_name {
            name = Some(schema_name);
        }
        let decoded = common.fields;
        let decode_error = common.error;
        PacketDetail {
            summary: PacketSummary {
                id: 0,
                sequence: 0,
                connection_id: snapshot.id,
                timestamp_micros: now_micros(),
                source: TrafficSource::Minecraft,
                direction,
                state,
                protocol_version: snapshot.protocol_version,
                packet_id: Some(frame.id),
                name,
                channel,
                loader,
                size: logical.len(),
                disposition,
                flow: None,
            },
            logical_bytes: logical,
            decoded,
            decode_error,
            wire: WireMetadata {
                frame_length: frame.wire_length,
                logical_length: frame.body.len(),
                compressed: frame.compressed,
                encrypted,
                truncated: false,
            },
        }
    }

    async fn record_opaque(&self, handle: &SessionHandle, direction: Direction, bytes: Bytes) {
        let detail = {
            let snapshot = handle.snapshot.read();
            PacketDetail {
                summary: PacketSummary {
                    id: 0,
                    sequence: handle.next_sequence(),
                    connection_id: snapshot.id,
                    timestamp_micros: now_micros(),
                    source: TrafficSource::Minecraft,
                    direction,
                    state: ProtocolState::Opaque,
                    protocol_version: snapshot.protocol_version,
                    packet_id: None,
                    name: Some("encrypted_stream".into()),
                    channel: None,
                    loader: snapshot.loader.clone(),
                    size: bytes.len(),
                    disposition: Disposition::Observed,
                    flow: None,
                },
                logical_bytes: bytes.clone(),
                decoded: None,
                decode_error: Some(
                    "online-mode stream is encrypted end-to-end in this build".into(),
                ),
                wire: WireMetadata {
                    frame_length: bytes.len(),
                    logical_length: bytes.len(),
                    compressed: false,
                    encrypted: true,
                    truncated: false,
                },
            }
        };
        self.record_packet(detail).await;
    }

    /// Records one packet: counters immediately, persistence coalesced.
    ///
    /// With a project open the detail joins a batch that is committed either
    /// when [`INSERT_BATCH_LIMIT`] packets are waiting or when the periodic
    /// flusher next runs, whichever comes first; the row's `Packet` event is
    /// published once its real database id exists. Without a project the id is
    /// minted locally and the event goes out straight away.
    async fn record_packet(&self, mut detail: PacketDetail) {
        {
            let session = {
                self.sessions
                    .read()
                    .get(&detail.summary.connection_id)
                    .cloned()
            };
            if let Some(handle) = session {
                update_snapshot(&handle, |snapshot| {
                    snapshot.packet_count += 1;
                    snapshot.byte_count += u64::try_from(detail.summary.size).unwrap_or(u64::MAX);
                });
            }
        }
        if self.project.read().is_some() {
            self.queue.push(detail).await;
        } else {
            detail.summary.id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
            let _ = self.events.send(ProxyEvent::Packet(detail.summary));
        }
    }

    /// Publishes lifecycle changes immediately and queues their persistence.
    /// Per-packet counters go through the flush ticker.
    #[allow(clippy::unused_async)]
    async fn publish_snapshot(&self, handle: &SessionHandle) {
        handle.snapshot_dirty.store(false, Ordering::Release);
        let snapshot = handle.snapshot.read().clone();
        let _ = self.events.send(ProxyEvent::Connection(snapshot.clone()));
        self.queue.lifecycle.lock().insert(snapshot.id, snapshot);
    }

    async fn fail_session(&self, id: ConnectionId, message: String) {
        let handle = { self.sessions.read().get(&id).cloned() };
        if let Some(handle) = handle {
            update_snapshot(&handle, |snapshot| {
                snapshot.status = ConnectionStatus::Failed;
                snapshot.last_error = Some(message.clone());
            });
            self.publish_snapshot(&handle).await;
        }
        let _ = self.events.send(ProxyEvent::Error {
            connection_id: id,
            message,
        });
    }
}

/// Coalesces packet persistence into batched database transactions.
///
/// The queue shares the service's project handle, so installing or replacing a
/// project is visible to in-flight batches: each flush reads whatever project
/// is current and commits into it.
#[derive(Debug)]
struct PersistenceQueue {
    project: Arc<RwLock<Option<ProjectStore>>>,
    events: broadcast::Sender<ProxyEvent>,
    pending: Mutex<Vec<PacketDetail>>,
    lifecycle: Mutex<HashMap<ConnectionId, ConnectionSnapshot>>,
    dropped: AtomicU64,
    wake: tokio::sync::Notify,
    /// Sessions whose snapshot changed since the last flush.
    dirty: Mutex<HashMap<ConnectionId, DirtySnapshot>>,
    flusher_started: AtomicBool,
}

/// A session's live snapshot and the flag saying it needs saving.
type DirtySnapshot = (Arc<RwLock<ConnectionSnapshot>>, Arc<AtomicBool>);

impl PersistenceQueue {
    /// Notes that a session's snapshot changed; the next flush saves it once,
    /// however many packets changed it in between.
    fn mark_dirty(&self, handle: &SessionHandle) {
        if !handle.snapshot_dirty.swap(true, Ordering::AcqRel) {
            let id = handle.snapshot.read().id;
            self.dirty.lock().insert(
                id,
                (
                    Arc::clone(&handle.snapshot),
                    Arc::clone(&handle.snapshot_dirty),
                ),
            );
        }
    }

    async fn flush_snapshots(&self) {
        let dirty = std::mem::take(&mut *self.dirty.lock());
        for (_, (snapshot, flag)) in dirty {
            flag.store(false, Ordering::Release);
            let snapshot = snapshot.read().clone();
            let _ = self.events.send(ProxyEvent::Connection(snapshot.clone()));
            self.persist_snapshot(snapshot).await;
        }
    }

    /// Saves a snapshot and publishes it. A failed save is reported and the
    /// session carries on: losing a counter update must not disconnect the
    /// game being tested.
    async fn persist_snapshot(&self, snapshot: ConnectionSnapshot) {
        let project = { self.project.read().clone() };
        if let Some(project) = project {
            let row = snapshot.clone();
            let saved = tokio::task::spawn_blocking(move || project.save_connection(&row)).await;
            let failure = match saved {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(error) => Some(error.to_string()),
            };
            if let Some(error) = failure {
                tracing::warn!(%error, "a connection snapshot could not be persisted");
                let _ = self.events.send(ProxyEvent::Error {
                    connection_id: snapshot.id,
                    message: format!("the connection could not be saved to the project: {error}"),
                });
            }
        }
    }
    #[allow(clippy::unused_async)]
    async fn push(&self, detail: PacketDetail) {
        let mut pending = self.pending.lock();
        let bytes: usize = pending.iter().map(|row| row.logical_bytes.len() + 64).sum();
        if pending.len() >= INSERT_BATCH_LIMIT
            || bytes.saturating_add(detail.logical_bytes.len() + 64) > 32 * 1024 * 1024
        {
            let count = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = self.events.send(ProxyEvent::Error {
                connection_id: detail.summary.connection_id,
                message: format!("project persistence queue full: {count} packet rows dropped"),
            });
            return;
        }
        pending.push(detail);
        if pending.len() >= INSERT_BATCH_LIMIT {
            self.wake.notify_one();
        }
    }

    /// Commits everything queued so far in one transaction.
    ///
    /// A failed batch is reported per connection and dropped rather than
    /// re-queued: retrying a failing insert on the hot path would stall the
    /// sessions behind it, and the operator sees the error either way.
    async fn flush(&self) {
        self.flush_packets().await;
        self.flush_lifecycle().await;
        self.flush_snapshots().await;
    }

    async fn flush_lifecycle(&self) {
        let lifecycle = std::mem::take(&mut *self.lifecycle.lock());
        for snapshot in lifecycle.into_values() {
            self.persist_snapshot(snapshot).await;
        }
    }

    async fn flush_packets(&self) {
        let batch = std::mem::take(&mut *self.pending.lock());
        if batch.is_empty() {
            return;
        }
        self.flush_lifecycle().await;
        let Some(project) = self.project.read().clone() else {
            return;
        };
        let mut summaries = Vec::with_capacity(batch.len());
        for detail in &batch {
            summaries.push(detail.summary.clone());
        }
        let insert = tokio::task::spawn_blocking(move || project.insert_packets(&batch)).await;
        match insert {
            Ok(Ok(ids)) => {
                for (mut summary, id) in summaries.into_iter().zip(ids) {
                    summary.id = id;
                    let _ = self.events.send(ProxyEvent::Packet(summary));
                }
            }
            Ok(Err(error)) => self.report_batch_failure(&summaries, error),
            Err(error) => {
                self.report_batch_failure(&summaries, ProxyError::SessionStopped);
                tracing::error!(%error, "the packet persistence worker stopped");
            }
        }
    }

    fn report_batch_failure(&self, summaries: &[PacketSummary], error: impl std::fmt::Display) {
        tracing::warn!(%error, "a packet batch could not be persisted");
        let mut reported: Vec<ConnectionId> = Vec::new();
        for summary in summaries {
            if reported.contains(&summary.connection_id) {
                continue;
            }
            reported.push(summary.connection_id);
            let _ = self.events.send(ProxyEvent::Error {
                connection_id: summary.connection_id,
                message: format!("packets could not be written to the project: {error}"),
            });
        }
    }
}

#[async_trait::async_trait]
impl TransparentRouteProvider for ProxyService {
    async fn open_transparent_route(&self, target: TransparentTarget) -> Result<u16, String> {
        self.admit_route().map_err(|error| error.to_string())?;
        let mut options = SessionOptions::new(Target {
            host: target.host,
            port: target.port,
        });
        options.preserve_client_address = true;
        let snapshot = self
            .start_session(options)
            .await
            .map_err(|error| error.to_string())?;
        snapshot
            .listener_address
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .ok_or_else(|| "the internal proxy did not provide a loopback port".into())
    }
}

/// Writes one direction's queue to its socket, in order, applying the
/// configured network conditions.
///
/// Queued frames are preferred over cancellation, and a closed queue ends the
/// loop with a clean shutdown of the write half, so whatever the session
/// queued before it closed — a disconnect reason, typically — is delivered.
async fn writer_loop(
    mut writer: WriteHalf<TcpStream>,
    mut receiver: mpsc::Receiver<OutboundBytes>,
    cipher: Arc<LinkCipher>,
    cancel: CancellationToken,
    network: Arc<RwLock<NetworkConditions>>,
    direction: Direction,
) -> Result<(), ProxyError> {
    let mut shaper = Shaper::default();
    loop {
        let message = tokio::select! {
            biased;
            message = receiver.recv() => message,
            () = cancel.cancelled() => return Ok(()),
        };
        let Some(message) = message else {
            let _ = writer.shutdown().await;
            return Ok(());
        };
        let link = network.read().for_direction(direction);
        if !link.is_neutral() {
            let release = shaper.release_at(&link, message.queued_at, Instant::now());
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(release) => {}
                () = cancel.cancelled() => return Ok(()),
            }
        }
        let mut bytes = BytesMut::from(message.bytes.as_ref());
        if message.encrypt {
            cipher.encrypt(&mut bytes);
        }
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        if !link.is_neutral() {
            shaper.sent(&link, Instant::now(), bytes.len());
        }
    }
}

fn update_snapshot(handle: &SessionHandle, update: impl FnOnce(&mut ConnectionSnapshot)) {
    update(&mut handle.snapshot.write());
}

/// Follows the configuration/play boundary introduced in 1.20.2.
///
/// The four packets that move a connection between the two states are named by
/// the version's id table. Recognising them by an empty body was wrong from
/// 1.21.2 on, where the bundle delimiter and the client's per-tick message are
/// empty too: every entity bundle flipped the session into configuration.
/// Only a release with no table falls back to that shape rule.
fn track_configuration_phase(
    handle: &SessionHandle,
    direction: Direction,
    frame: &PacketFrame,
    state: ProtocolState,
) {
    let protocol = handle.snapshot.read().protocol_version;
    if protocol.is_none_or(|version| version < 764) {
        return;
    }
    if PacketRegistry::is_tabulated(state, protocol) {
        match transition_name(state, direction, Some(frame.id), protocol) {
            // Finish configuration is answered by the client's acknowledgement,
            // and both sides are in play once that is on the wire.
            Some("finish_configuration_ack") => enter_play(handle),
            // Start configuration is only an offer; the client's
            // acknowledgement is what actually moves the stream out of play.
            Some("start_configuration") => handle
                .reconfiguration_offered
                .store(true, Ordering::Release),
            Some("configuration_acknowledged")
                if handle.reconfiguration_offered.swap(false, Ordering::AcqRel) =>
            {
                enter_configuration(handle);
            }
            _ => {}
        }
        return;
    }
    if !frame.body.is_empty() {
        return;
    }
    match (state, direction) {
        (ProtocolState::Configuration, Direction::ClientToServer) => enter_play(handle),
        (ProtocolState::Play, Direction::ServerToClient) => handle
            .reconfiguration_offered
            .store(true, Ordering::Release),
        (ProtocolState::Play, Direction::ClientToServer)
            if handle.reconfiguration_offered.swap(false, Ordering::AcqRel) =>
        {
            enter_configuration(handle);
        }
        _ => {}
    }
}

fn enter_play(handle: &SessionHandle) {
    handle
        .reconfiguration_offered
        .store(false, Ordering::Release);
    update_snapshot(handle, |snapshot| snapshot.state = ProtocolState::Play);
}

fn enter_configuration(handle: &SessionHandle) {
    update_snapshot(handle, |snapshot| {
        snapshot.state = ProtocolState::Configuration;
    });
}

/// Splits a handshake address into the host and the loader markers that
/// follow its first NUL (`\0FML2\0`, `\0FORGE`, ...), which stay attached.
fn split_address(address: &str) -> (&str, &str) {
    address
        .find('\0')
        .map_or((address, ""), |index| address.split_at(index))
}

fn loader_from_address(address: &str) -> Option<String> {
    let (_, markers) = split_address(address);
    if markers.contains("\0FML3\0") {
        Some("neoforge".into())
    } else if markers.contains("\0FML2\0")
        || markers.contains("\0FML\0")
        // Forge for 1.20.2+ appends `\0FORGE`, optionally followed by its
        // network version.
        || markers.split('\0').any(|marker| marker.starts_with("FORGE"))
    {
        Some("forge".into())
    } else {
        None
    }
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use mineburp_project::ProjectOptions;

    use super::*;

    fn handle(protocol_version: i32) -> SessionHandle {
        SessionHandle::new(ConnectionSnapshot {
            id: Uuid::nil(),
            target: Target {
                host: "example.test".into(),
                port: 25_565,
            },
            listener_address: "127.0.0.1:0".into(),
            status: ConnectionStatus::Active,
            state: ProtocolState::Configuration,
            protocol_version: Some(protocol_version),
            minecraft_version: None,
            loader: None,
            compression_threshold: None,
            encrypted_client: true,
            encrypted_server: true,
            packet_count: 0,
            byte_count: 0,
            last_error: None,
        })
    }

    fn frame(id: i32, body: &'static [u8]) -> PacketFrame {
        PacketFrame {
            id,
            body: Bytes::from_static(body),
            compressed: false,
            wire_length: body.len() + 1,
        }
    }

    fn id(state: ProtocolState, direction: Direction, name: &str, protocol: i32) -> i32 {
        PacketRegistry::packet_id(state, direction, name, Some(protocol))
            .unwrap_or_else(|| panic!("{name} is tabulated for {protocol}"))
    }

    fn state_of(handle: &SessionHandle) -> ProtocolState {
        handle.snapshot.read().state
    }

    #[tokio::test]
    async fn queued_transitions_leave_following_bytes_raw() {
        for (state, packet_id) in [
            (ProtocolState::Login, 3),
            (ProtocolState::Configuration, 3),
            (ProtocolState::Login, 2),
        ] {
            let service = ProxyService::new();
            let handle = handle(767);
            handle.snapshot.write().state = state;
            if packet_id == 2 {
                handle.snapshot.write().protocol_version = Some(763);
            }
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_server, _) = listener.accept().await.unwrap();
            let (mut reader, _) = tokio::io::split(client);
            let codec = FrameCodec::default();
            let mut buffer =
                BytesMut::from(codec.encode(&frame(packet_id, &[0])).unwrap().as_ref());
            // These bytes must not be decoded with the old compression setting.
            let following = [0xff, 0xff, 0xff, 0xff, 0x7f];
            buffer.extend_from_slice(&following);
            let (writer, _) = WriterSender::channel();
            let mut pending = VecDeque::new();
            let mut io = HoldIo {
                reader: &mut reader,
                buffer: &mut buffer,
                codec: &codec,
                read_cipher: inbound_cipher(&handle, Direction::ServerToClient),
                writer: &writer,
                pending: &mut pending,
                pending_bytes: 0,
                classification_blocked: false,
                closed: false,
            };
            service
                .drain_held_backlog(&handle, Direction::ServerToClient, &mut io)
                .await
                .unwrap();
            assert!(io.classification_blocked);
            assert_eq!(io.pending.len(), 1);
            assert_eq!(io.buffer.as_ref(), following);
            service
                .drain_held_backlog(&handle, Direction::ServerToClient, &mut io)
                .await
                .unwrap();
            assert_eq!(io.buffer.as_ref(), following);
        }
    }

    #[test]
    fn login_boundaries_stop_prefetch() {
        assert!(is_state_transition(
            ProtocolState::Login,
            Direction::ServerToClient,
            Some(2),
            Some(763)
        ));
        assert!(is_state_transition(
            ProtocolState::Login,
            Direction::ClientToServer,
            Some(3),
            Some(764)
        ));
        assert!(changes_stream_encoding(
            ProtocolState::Login,
            Direction::ServerToClient,
            Some(3)
        ));
    }

    #[test]
    fn a_synchronous_embedder_can_start_the_quiet_batch_flusher() {
        // Tauri constructs desktop state from a synchronous setup callback.
        // Reproduce that ordering instead of using `#[tokio::test]`, which
        // would let the constructor start the flusher by itself.
        let service = ProxyService::new();
        assert!(!service.queue.flusher_started.load(Ordering::Acquire));

        let directory = tempfile::tempdir().expect("temporary directory");
        let store = ProjectStore::create(
            directory.path().join("quiet.mineburp"),
            "Quiet",
            ProjectOptions::default(),
        )
        .expect("create project");
        let connection = handle(767).snapshot.read().clone();
        store
            .save_connection(&connection)
            .expect("save connection before its packet");
        service.set_project(Some(store.clone()));

        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
            .block_on(async {
                assert!(service.start_persistence_flusher());
                assert!(
                    service.start_persistence_flusher(),
                    "starting twice is safe"
                );
                service
                    .record_packet(PacketDetail {
                        summary: PacketSummary {
                            id: 0,
                            sequence: 1,
                            connection_id: connection.id,
                            timestamp_micros: 1,
                            source: TrafficSource::Minecraft,
                            direction: Direction::ClientToServer,
                            state: ProtocolState::Play,
                            protocol_version: Some(767),
                            packet_id: Some(0),
                            name: Some("quiet_probe".into()),
                            channel: None,
                            loader: None,
                            size: 1,
                            disposition: Disposition::Forwarded,
                            flow: None,
                        },
                        logical_bytes: Bytes::from_static(&[0]),
                        decoded: None,
                        decode_error: None,
                        wire: WireMetadata::default(),
                    })
                    .await;
                tokio::time::sleep(FLUSH_INTERVAL * 3).await;
            });

        let packets = store
            .query_packets(Some(connection.id), 0, 10)
            .expect("query persisted packet");
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].name.as_deref(), Some("quiet_probe"));
    }

    #[test]
    fn acknowledging_finish_configuration_enters_play() {
        let session = handle(767);
        let ack = id(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            "finish_configuration_ack",
            767,
        );
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(ack, &[]),
            ProtocolState::Configuration,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
    }

    #[test]
    fn other_empty_configuration_packets_do_not_enter_play() {
        let session = handle(767);
        let keep_alive = id(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            "client_information",
            767,
        );
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(keep_alive, &[]),
            ProtocolState::Configuration,
        );
        assert_eq!(state_of(&session), ProtocolState::Configuration);
    }

    #[test]
    fn play_only_returns_to_configuration_after_the_server_offers_it() {
        let session = handle(767);
        session.snapshot.write().state = ProtocolState::Play;
        let start = id(
            ProtocolState::Play,
            Direction::ServerToClient,
            "start_configuration",
            767,
        );
        let ack = id(
            ProtocolState::Play,
            Direction::ClientToServer,
            "configuration_acknowledged",
            767,
        );

        // An acknowledgement on its own must not rewrite the state.
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(ack, &[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);

        track_configuration_phase(
            &session,
            Direction::ServerToClient,
            &frame(start, &[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(ack, &[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Configuration);
    }

    /// From 1.21.2 the bundle delimiter and the client's tick end are both
    /// empty, and both are constant traffic during play.
    #[test]
    fn bundle_delimiters_and_tick_ends_leave_play_alone() {
        let protocol = 768;
        let session = handle(protocol);
        session.snapshot.write().state = ProtocolState::Play;
        let bundle = id(
            ProtocolState::Play,
            Direction::ServerToClient,
            "bundle_delimiter",
            protocol,
        );
        let tick_end = id(
            ProtocolState::Play,
            Direction::ClientToServer,
            "client_tick_end",
            protocol,
        );
        for _ in 0..3 {
            track_configuration_phase(
                &session,
                Direction::ServerToClient,
                &frame(bundle, &[]),
                ProtocolState::Play,
            );
            track_configuration_phase(
                &session,
                Direction::ClientToServer,
                &frame(tick_end, &[]),
                ProtocolState::Play,
            );
            assert_eq!(state_of(&session), ProtocolState::Play);
        }
    }

    #[test]
    fn releases_without_a_configuration_phase_are_left_alone() {
        let session = handle(340);
        session.snapshot.write().state = ProtocolState::Play;
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(0, &[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
    }

    #[test]
    fn replacement_rules_never_touch_handshake_or_login() {
        let service = ProxyService::new();
        service
            .set_replacement_rules(vec![ReplacementRule {
                action: mineburp_core::ReplacementAction::Rewrite,
                id: Uuid::nil(),
                name: "everything".into(),
                enabled: true,
                expression: String::new(),
                edits: vec![mineburp_core::PacketEdit::Frame {
                    bytes: "00 01".into(),
                }],
            }])
            .expect("rules");
        let session = handle(767);
        for state in [ProtocolState::Handshake, ProtocolState::Login] {
            let detail = service.make_detail(
                &session,
                Direction::ServerToClient,
                &frame(1, &[9, 9]),
                Disposition::Forwarded,
                state,
                false,
            );
            assert!(
                service
                    .rewrite(&detail, state, Direction::ServerToClient)
                    .is_none()
            );
        }
        let detail = service.make_detail(
            &session,
            Direction::ServerToClient,
            &frame(1, &[9, 9]),
            Disposition::Forwarded,
            ProtocolState::Play,
            false,
        );
        assert!(
            service
                .rewrite(&detail, ProtocolState::Play, Direction::ServerToClient)
                .is_some()
        );
    }

    #[test]
    fn modern_custom_payload_rows_carry_the_channel() {
        let service = ProxyService::new();
        let session = handle(771);
        let mut body = vec![18];
        body.extend_from_slice(b"mineburp:inventory");
        body.extend_from_slice(&[2, 0, 0, 0, 1]);
        let packet = PacketFrame {
            id: 0x15,
            body: Bytes::from(body),
            compressed: false,
            wire_length: 0,
        };
        let detail = service.make_detail(
            &session,
            Direction::ClientToServer,
            &packet,
            Disposition::Forwarded,
            ProtocolState::Play,
            false,
        );
        assert_eq!(detail.summary.name.as_deref(), Some("custom_payload"));
        assert_eq!(
            detail.summary.channel.as_deref(),
            Some("mineburp:inventory")
        );
    }

    #[test]
    fn loader_markers_are_recognised() {
        assert_eq!(
            split_address("play.example\0FORGE"),
            ("play.example", "\0FORGE")
        );
        assert_eq!(split_address("play.example"), ("play.example", ""));
        assert_eq!(
            loader_from_address("play.example\0FORGE").as_deref(),
            Some("forge")
        );
        assert_eq!(
            loader_from_address("localhost\0FML2\0").as_deref(),
            Some("forge")
        );
        assert_eq!(
            loader_from_address("localhost\0FML3\0").as_deref(),
            Some("neoforge")
        );
        assert_eq!(loader_from_address("forge.example.net"), None);
    }

    #[tokio::test]
    async fn writer_budget_bounds_queued_bytes() {
        let (sender, mut receiver) = WriterSender::channel();
        sender
            .send(Bytes::from(vec![0_u8; WRITER_QUEUE_BYTES]), false)
            .await
            .expect("first frame fits the empty budget");
        let blocked = tokio::time::timeout(
            Duration::from_millis(50),
            sender.send(Bytes::from_static(&[1]), false),
        )
        .await;
        assert!(blocked.is_err(), "a full budget makes the reader wait");
        drop(receiver.recv().await);
        tokio::time::timeout(
            Duration::from_secs(1),
            sender.send(Bytes::from_static(&[1]), false),
        )
        .await
        .expect("written bytes return to the budget")
        .expect("send");
    }

    #[test]
    fn route_requests_are_rate_limited() {
        let service = ProxyService::new();
        for _ in 0..ROUTES_PER_SECOND {
            service.admit_route().expect("within the limit");
        }
        assert!(matches!(service.admit_route(), Err(ProxyError::RouteLimit)));
    }
}
