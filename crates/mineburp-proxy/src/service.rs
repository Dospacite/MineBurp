use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Bytes, BytesMut};
use mineburp_core::{
    ConnectionId, ConnectionSnapshot, ConnectionStatus, Direction, Disposition, InterceptDecision,
    InterceptRule, PacketDetail, PacketSummary, ProtocolState, Target, TrafficSource, WireMetadata,
};
use mineburp_project::{ProjectError, ProjectStore};
use mineburp_protocol::{
    FrameCodec, HandshakeError, PacketFrame, PacketRegistry, ProtocolError, SchemaError,
    SchemaPack, decode_common_packet, decode_handshake, decode_var_i32, encode_handshake,
};
use mineburp_session::{
    SessionJoinProvider, SessionJoinRequest, TransparentRouteProvider, TransparentTarget,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    CompiledFilter, EncryptionBridgeError, FilterParseError,
    encryption::{EncryptionBridge, LinkCipher},
};

const SOCKET_BUFFER_CAPACITY: usize = 64 * 1024;
const WRITER_QUEUE_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub target: Target,
    pub listen_port: Option<u16>,
    pub max_frame_length: usize,
    /// A transparent route is created before the client swaps its destination.
    /// It must not leave an unbounded number of unused loopback listeners when
    /// a connection attempt is cancelled by the game.
    pub accept_timeout: Duration,
}

impl SessionOptions {
    #[must_use]
    pub fn new(target: Target) -> Self {
        Self {
            target,
            listen_port: None,
            max_frame_length: 16 * 1024 * 1024,
            accept_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldPacket {
    pub id: Uuid,
    pub packet: PacketDetail,
}

#[derive(Debug, Clone)]
pub enum HeldPacketDecision {
    Forward,
    Drop,
    Replace(Bytes),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ProxyEvent {
    Connection(ConnectionSnapshot),
    Packet(PacketSummary),
    Held(HeldPacket),
    Error {
        connection_id: ConnectionId,
        message: String,
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
    #[error("held packet {0} does not exist")]
    UnknownHeldPacket(Uuid),
    #[error("the client did not connect to its private route in time")]
    ClientRouteTimedOut,
    #[error("session task stopped")]
    SessionStopped,
}

#[derive(Debug)]
struct CompiledRule {
    source: InterceptRule,
    filter: CompiledFilter,
}

#[derive(Debug)]
struct PendingHeld {
    decision: oneshot::Sender<HeldPacketDecision>,
}

#[derive(Debug, Clone)]
struct SessionHandle {
    snapshot: Arc<RwLock<ConnectionSnapshot>>,
    client_writer: Arc<RwLock<Option<mpsc::Sender<OutboundBytes>>>>,
    server_writer: Arc<RwLock<Option<mpsc::Sender<OutboundBytes>>>>,
    compression_threshold: Arc<RwLock<Option<i32>>>,
    client_cipher: Arc<LinkCipher>,
    server_cipher: Arc<LinkCipher>,
    encryption_bridge: Arc<EncryptionBridge>,
    /// Set when the server has offered to re-enter configuration from play, so
    /// the client's empty acknowledgement is only believed after the offer.
    reconfiguration_offered: Arc<AtomicBool>,
    cancel: CancellationToken,
}

#[derive(Debug)]
struct OutboundBytes {
    bytes: Bytes,
    encrypt: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyService {
    registry: Arc<PacketRegistry>,
    project: Arc<RwLock<Option<ProjectStore>>>,
    sessions: Arc<RwLock<HashMap<ConnectionId, SessionHandle>>>,
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    held: Arc<RwLock<HashMap<Uuid, PendingHeld>>>,
    session_join_provider: Arc<RwLock<Option<Arc<dyn SessionJoinProvider>>>>,
    schema_packs: Arc<RwLock<Vec<SchemaPack>>>,
    events: broadcast::Sender<ProxyEvent>,
    next_packet_id: Arc<AtomicI64>,
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
        Self {
            registry: Arc::new(PacketRegistry::bundled()),
            project: Arc::new(RwLock::new(None)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(Vec::new())),
            held: Arc::new(RwLock::new(HashMap::new())),
            session_join_provider: Arc::new(RwLock::new(None)),
            schema_packs: Arc::new(RwLock::new(Vec::new())),
            events,
            next_packet_id: Arc::new(AtomicI64::new(1)),
        }
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

    pub fn set_intercept_rules(&self, rules: Vec<InterceptRule>) -> Result<(), ProxyError> {
        let compiled = rules
            .into_iter()
            .map(|source| {
                let filter = CompiledFilter::parse(&source.expression)?;
                Ok(CompiledRule { source, filter })
            })
            .collect::<Result<Vec<_>, FilterParseError>>()?;
        *self.rules.write() = compiled;
        Ok(())
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
        let handle = SessionHandle {
            snapshot: Arc::new(RwLock::new(snapshot.clone())),
            client_writer: Arc::new(RwLock::new(None)),
            server_writer: Arc::new(RwLock::new(None)),
            compression_threshold: Arc::new(RwLock::new(None)),
            client_cipher: Arc::new(LinkCipher::new()),
            server_cipher: Arc::new(LinkCipher::new()),
            encryption_bridge: Arc::new(EncryptionBridge::new()),
            reconfiguration_offered: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
        };
        self.sessions.write().insert(id, handle.clone());
        self.persist_connection(&snapshot).await?;
        let _ = self.events.send(ProxyEvent::Connection(snapshot.clone()));
        let service = self.clone();
        tokio::spawn(async move {
            if let Err(error) = service.run_session(listener, handle, options).await {
                service.fail_session(id, error.to_string()).await;
            }
        });
        Ok(snapshot)
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

    pub fn resolve_held(&self, id: Uuid, decision: HeldPacketDecision) -> Result<(), ProxyError> {
        let pending = self
            .held
            .write()
            .remove(&id)
            .ok_or(ProxyError::UnknownHeldPacket(id))?;
        pending
            .decision
            .send(decision)
            .map_err(|_| ProxyError::SessionStopped)
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
        if handle.snapshot.read().state == ProtocolState::Opaque {
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
        let encrypt = match direction {
            Direction::ClientToServer => handle.server_cipher.is_active(),
            Direction::ServerToClient => handle.client_cipher.is_active(),
        };
        sender
            .send(OutboundBytes {
                bytes: encoded,
                encrypt,
            })
            .await
            .map_err(|_| ProxyError::SessionStopped)?;

        let detail = self.make_detail(
            &handle,
            direction,
            &frame,
            Disposition::Replayed,
            handle.snapshot.read().state,
            false,
        );
        self.record_packet(detail).await?;
        Ok(())
    }

    async fn run_session(
        &self,
        listener: TcpListener,
        handle: SessionHandle,
        options: SessionOptions,
    ) -> Result<(), ProxyError> {
        let accept = tokio::time::timeout(options.accept_timeout, listener.accept());
        let (client, _) = tokio::select! {
            accepted = accept => accepted.map_err(|_| ProxyError::ClientRouteTimedOut)??,
            () = handle.cancel.cancelled() => return Ok(()),
        };
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Connecting;
        });
        let server = TcpStream::connect(options.target.authority()).await?;
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Active;
        });
        self.publish_snapshot(&handle).await?;

        let (client_reader, client_writer) = tokio::io::split(client);
        let (server_reader, server_writer) = tokio::io::split(server);
        let (to_client, client_rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        let (to_server, server_rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        *handle.client_writer.write() = Some(to_client.clone());
        *handle.server_writer.write() = Some(to_server.clone());

        let opaque = Arc::new(RwLock::new(false));
        let sequence = Arc::new(AtomicU64::new(1));
        let max_frame_length = options.max_frame_length;
        let mut tasks = JoinSet::new();
        tasks.spawn(writer_loop(
            client_writer,
            client_rx,
            handle.client_cipher.clone(),
            handle.cancel.clone(),
        ));
        tasks.spawn(writer_loop(
            server_writer,
            server_rx,
            handle.server_cipher.clone(),
            handle.cancel.clone(),
        ));

        let client_service = self.clone();
        let client_handle = handle.clone();
        let client_read_cipher = client_handle.client_cipher.clone();
        let client_opaque = opaque.clone();
        let client_sequence = sequence.clone();
        tasks.spawn(async move {
            client_service
                .reader_loop(
                    client_reader,
                    to_server,
                    client_handle,
                    Direction::ClientToServer,
                    client_opaque,
                    client_sequence,
                    max_frame_length,
                    client_read_cipher,
                )
                .await
        });

        let server_service = self.clone();
        let server_handle = handle.clone();
        let server_read_cipher = server_handle.server_cipher.clone();
        let server_opaque = opaque;
        tasks.spawn(async move {
            server_service
                .reader_loop(
                    server_reader,
                    to_client,
                    server_handle,
                    Direction::ServerToClient,
                    server_opaque,
                    sequence,
                    max_frame_length,
                    server_read_cipher,
                )
                .await
        });

        tokio::select! {
            () = handle.cancel.cancelled() => {},
            result = tasks.join_next() => {
                if let Some(Ok(Err(error))) = result {
                    return Err(error);
                }
            }
        }
        handle.cancel.cancel();
        tasks.shutdown().await;
        update_snapshot(&handle, |snapshot| {
            snapshot.status = ConnectionStatus::Closed;
            snapshot.state = ProtocolState::Closed;
        });
        self.publish_snapshot(&handle).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn reader_loop(
        &self,
        mut reader: ReadHalf<TcpStream>,
        writer: mpsc::Sender<OutboundBytes>,
        handle: SessionHandle,
        direction: Direction,
        opaque: Arc<RwLock<bool>>,
        sequence: Arc<AtomicU64>,
        max_frame_length: usize,
        read_cipher: Arc<LinkCipher>,
    ) -> Result<(), ProxyError> {
        let mut buffer = BytesMut::with_capacity(SOCKET_BUFFER_CAPACITY);
        loop {
            if handle.cancel.is_cancelled() {
                return Ok(());
            }
            if *opaque.read() {
                if !buffer.is_empty() {
                    let bytes = buffer.split().freeze();
                    writer
                        .send(OutboundBytes {
                            bytes: bytes.clone(),
                            encrypt: false,
                        })
                        .await
                        .map_err(|_| ProxyError::SessionStopped)?;
                    self.record_opaque(&handle, direction, bytes, &sequence)
                        .await?;
                }
                let mut chunk = vec![0_u8; SOCKET_BUFFER_CAPACITY];
                let read = reader.read(&mut chunk).await?;
                if read == 0 {
                    return Ok(());
                }
                chunk.truncate(read);
                let bytes = Bytes::from(chunk);
                writer
                    .send(OutboundBytes {
                        bytes: bytes.clone(),
                        encrypt: false,
                    })
                    .await
                    .map_err(|_| ProxyError::SessionStopped)?;
                self.record_opaque(&handle, direction, bytes, &sequence)
                    .await?;
                continue;
            }

            let mut codec = FrameCodec::new(max_frame_length);
            codec.set_compression_threshold(*handle.compression_threshold.read());
            while let Some(frame) = codec.try_decode(&mut buffer)? {
                let cipher_started = self
                    .process_frame(&handle, direction, frame, &writer, &opaque, &sequence)
                    .await?;
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
                codec.set_compression_threshold(*handle.compression_threshold.read());
            }
            let mut chunk = vec![0_u8; SOCKET_BUFFER_CAPACITY];
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            chunk.truncate(read);
            read_cipher.decrypt(&mut chunk);
            buffer.extend_from_slice(&chunk);
        }
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
        writer: &mpsc::Sender<OutboundBytes>,
        opaque: &Arc<RwLock<bool>>,
        sequence: &AtomicU64,
    ) -> Result<bool, ProxyError> {
        let state = handle.snapshot.read().state;
        let mut outbound = frame.clone();
        let mut activate_encryption = None;
        if state == ProtocolState::Handshake
            && direction == Direction::ClientToServer
            && frame.id == 0
            && let Ok(mut handshake) = decode_handshake(&frame.body)
        {
            let marker_suffix = handshake
                .server_address
                .find('\0')
                .map(|index| handshake.server_address[index..].to_owned())
                .unwrap_or_default();
            handshake.server_address =
                format!("{}{}", handle.snapshot.read().target.host, marker_suffix);
            handshake.server_port = handle.snapshot.read().target.port;
            outbound.body = encode_handshake(&handshake)?;
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

        if state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && frame.id == 1
            && self.session_join_provider.read().is_some()
        {
            outbound.body = handle.encryption_bridge.intercept_request(&frame.body)?;
        }
        if state == ProtocolState::Login && direction == Direction::ClientToServer && frame.id == 1
        {
            let provider = { self.session_join_provider.read().clone() };
            if let Some(provider) = provider {
                let protocol_version = handle.snapshot.read().protocol_version.unwrap_or_default();
                let negotiation = handle
                    .encryption_bridge
                    .intercept_response(&frame.body, protocol_version)?;
                provider
                    .join_server(&SessionJoinRequest {
                        client_server_hash: negotiation.client_server_hash,
                        upstream_server_hash: negotiation.upstream_server_hash,
                    })
                    .await
                    .map_err(ProxyError::Authentication)?;
                outbound.body = negotiation.server_response;
                activate_encryption = Some(negotiation.shared_secret);
            }
        }

        let current_state = handle.snapshot.read().state;
        let input_encrypted = match direction {
            Direction::ClientToServer => handle.client_cipher.is_active(),
            Direction::ServerToClient => handle.server_cipher.is_active(),
        };
        let mut detail = self.make_detail(
            handle,
            direction,
            &frame,
            Disposition::Forwarded,
            state,
            input_encrypted,
        );
        detail.summary.sequence = sequence.fetch_add(1, Ordering::Relaxed);
        let system_edited = outbound != frame;
        let decision = if system_edited {
            InterceptDecision::Forward
        } else {
            self.intercept_decision(&detail.summary)
        };
        let (disposition, replacement) = match decision {
            InterceptDecision::Forward => (
                if system_edited {
                    Disposition::Edited
                } else {
                    Disposition::Forwarded
                },
                None,
            ),
            InterceptDecision::Drop => (Disposition::Dropped, None),
            InterceptDecision::DelayMillis(milliseconds) => {
                tokio::time::sleep(Duration::from_millis(milliseconds)).await;
                (Disposition::Delayed, None)
            }
            InterceptDecision::Hold => {
                let held_id = Uuid::new_v4();
                let (decision_tx, decision_rx) = oneshot::channel();
                self.held.write().insert(
                    held_id,
                    PendingHeld {
                        decision: decision_tx,
                    },
                );
                let _ = self.events.send(ProxyEvent::Held(HeldPacket {
                    id: held_id,
                    packet: detail.clone(),
                }));
                match decision_rx.await.map_err(|_| ProxyError::SessionStopped)? {
                    HeldPacketDecision::Forward => (Disposition::Forwarded, None),
                    HeldPacketDecision::Drop => (Disposition::Dropped, None),
                    HeldPacketDecision::Replace(bytes) => (Disposition::Edited, Some(bytes)),
                }
            }
        };
        detail.summary.disposition = disposition;
        self.record_packet(detail).await?;

        if disposition != Disposition::Dropped {
            let outbound = if let Some(bytes) = replacement {
                PacketFrame::from_logical_bytes(bytes)?
            } else {
                outbound
            };
            let mut codec = FrameCodec::default();
            codec.set_compression_threshold(*handle.compression_threshold.read());
            let encrypt = if activate_encryption.is_some() {
                false
            } else {
                match direction {
                    Direction::ClientToServer => handle.server_cipher.is_active(),
                    Direction::ServerToClient => handle.client_cipher.is_active(),
                }
            };
            writer
                .send(OutboundBytes {
                    bytes: codec.encode(&outbound)?,
                    encrypt,
                })
                .await
                .map_err(|_| ProxyError::SessionStopped)?;
        }

        let mut cipher_started = false;
        if disposition != Disposition::Dropped
            && let Some(shared_secret) = activate_encryption
        {
            handle.client_cipher.activate(shared_secret);
            handle.server_cipher.activate(shared_secret);
            cipher_started = true;
            update_snapshot(handle, |snapshot| {
                snapshot.encrypted_client = true;
                snapshot.encrypted_server = true;
            });
        }

        if current_state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && frame.id == 3
            && let Some((threshold, _)) = decode_var_i32(&frame.body)?
        {
            *handle.compression_threshold.write() = Some(threshold);
            update_snapshot(handle, |snapshot| {
                snapshot.compression_threshold = Some(threshold);
            });
        }
        if current_state == ProtocolState::Login
            && direction == Direction::ServerToClient
            && frame.id == 2
            && handle
                .snapshot
                .read()
                .protocol_version
                .is_some_and(|version| version < 764)
        {
            update_snapshot(handle, |snapshot| snapshot.state = ProtocolState::Play);
        }
        if current_state == ProtocolState::Login
            && direction == Direction::ClientToServer
            && frame.id == 3
            && handle
                .snapshot
                .read()
                .protocol_version
                .is_some_and(|version| version >= 764)
        {
            update_snapshot(handle, |snapshot| {
                snapshot.state = ProtocolState::Configuration;
            });
        }
        if current_state == ProtocolState::Login
            && direction == Direction::ClientToServer
            && frame.id == 1
            && activate_encryption.is_none()
        {
            *opaque.write() = true;
            update_snapshot(handle, |snapshot| {
                snapshot.state = ProtocolState::Opaque;
                snapshot.encrypted_client = true;
                snapshot.encrypted_server = true;
            });
        }
        track_configuration_phase(handle, direction, &frame, current_state);
        self.publish_snapshot(handle).await?;
        Ok(cipher_started)
    }
    fn intercept_decision(&self, packet: &PacketSummary) -> InterceptDecision {
        self.rules
            .read()
            .iter()
            .find(|rule| rule.source.enabled && rule.filter.matches(packet))
            .map_or(InterceptDecision::Forward, |rule| {
                rule.source.action.clone()
            })
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
        let channel = common.channel;
        let loader = common.loader.or_else(|| snapshot.loader.clone());
        let mut name = self
            .registry
            .packet_name(state, direction, frame.id, snapshot.protocol_version)
            .map(str::to_owned);
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

    async fn record_opaque(
        &self,
        handle: &SessionHandle,
        direction: Direction,
        bytes: Bytes,
        sequence: &AtomicU64,
    ) -> Result<(), ProxyError> {
        let detail = {
            let snapshot = handle.snapshot.read();
            PacketDetail {
                summary: PacketSummary {
                    id: 0,
                    sequence: sequence.fetch_add(1, Ordering::Relaxed),
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
        self.record_packet(detail).await?;
        Ok(())
    }

    async fn record_packet(&self, mut detail: PacketDetail) -> Result<(), ProxyError> {
        let project = self.project.read().clone();
        if let Some(project) = project {
            let cloned = detail.clone();
            let id = tokio::task::spawn_blocking(move || project.insert_packet(&cloned))
                .await
                .map_err(|_| ProxyError::SessionStopped)??;
            detail.summary.id = id;
        } else {
            detail.summary.id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        }
        let session = {
            self.sessions
                .read()
                .get(&detail.summary.connection_id)
                .cloned()
        };
        if let Some(handle) = session {
            update_snapshot(&handle, |snapshot| {
                snapshot.packet_count += 1;
                snapshot.byte_count += detail.summary.size as u64;
            });
        }
        let _ = self.events.send(ProxyEvent::Packet(detail.summary));
        Ok(())
    }

    async fn publish_snapshot(&self, handle: &SessionHandle) -> Result<(), ProxyError> {
        let snapshot = handle.snapshot.read().clone();
        self.persist_connection(&snapshot).await?;
        let _ = self.events.send(ProxyEvent::Connection(snapshot));
        Ok(())
    }

    async fn persist_connection(&self, snapshot: &ConnectionSnapshot) -> Result<(), ProxyError> {
        let project = { self.project.read().clone() };
        if let Some(project) = project {
            let snapshot = snapshot.clone();
            tokio::task::spawn_blocking(move || project.save_connection(&snapshot))
                .await
                .map_err(|_| ProxyError::SessionStopped)??;
        }
        Ok(())
    }

    async fn fail_session(&self, id: ConnectionId, message: String) {
        let handle = { self.sessions.read().get(&id).cloned() };
        if let Some(handle) = handle {
            update_snapshot(&handle, |snapshot| {
                snapshot.status = ConnectionStatus::Failed;
                snapshot.last_error = Some(message.clone());
            });
            let _ = self.publish_snapshot(&handle).await;
        }
        let _ = self.events.send(ProxyEvent::Error {
            connection_id: id,
            message,
        });
    }
}

#[async_trait::async_trait]
impl TransparentRouteProvider for ProxyService {
    async fn open_transparent_route(&self, target: TransparentTarget) -> Result<u16, String> {
        let snapshot = self
            .start_session(SessionOptions::new(Target {
                host: target.host,
                port: target.port,
            }))
            .await
            .map_err(|error| error.to_string())?;
        snapshot
            .listener_address
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .ok_or_else(|| "the internal proxy did not provide a loopback port".into())
    }
}

async fn writer_loop(
    mut writer: WriteHalf<TcpStream>,
    mut receiver: mpsc::Receiver<OutboundBytes>,
    cipher: Arc<LinkCipher>,
    cancel: CancellationToken,
) -> Result<(), ProxyError> {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            message = receiver.recv() => {
                let Some(message) = message else { return Ok(()); };
                let mut bytes = BytesMut::from(message.bytes.as_ref());
                if message.encrypt {
                    cipher.encrypt(&mut bytes);
                }
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }
}

fn update_snapshot(handle: &SessionHandle, update: impl FnOnce(&mut ConnectionSnapshot)) {
    update(&mut handle.snapshot.write());
}

/// Follows the configuration/play boundary introduced in 1.20.2.
///
/// Configuration and play ids are renumbered nearly every release, so this reads
/// the exchange by its shape rather than from a per-version id table: each half
/// of the handshake is the only empty-bodied packet its direction can carry in
/// that state. Missing this transition left every packet after the configuration
/// phase labelled `configuration`, and therefore decoded against the wrong state.
fn track_configuration_phase(
    handle: &SessionHandle,
    direction: Direction,
    frame: &PacketFrame,
    state: ProtocolState,
) {
    let modern = handle
        .snapshot
        .read()
        .protocol_version
        .is_some_and(|version| version >= 764);
    if !modern || !frame.body.is_empty() {
        return;
    }
    match (state, direction) {
        // Finish configuration, then the client's acknowledgement: both sides
        // are in play once that acknowledgement is on the wire.
        (ProtocolState::Configuration, Direction::ClientToServer) => {
            handle
                .reconfiguration_offered
                .store(false, Ordering::Release);
            update_snapshot(handle, |snapshot| snapshot.state = ProtocolState::Play);
        }
        // Start configuration is only an offer; the client's acknowledgement is
        // what actually moves the stream back out of play.
        (ProtocolState::Play, Direction::ServerToClient) => {
            handle
                .reconfiguration_offered
                .store(true, Ordering::Release);
        }
        (ProtocolState::Play, Direction::ClientToServer)
            if handle.reconfiguration_offered.swap(false, Ordering::AcqRel) =>
        {
            update_snapshot(handle, |snapshot| {
                snapshot.state = ProtocolState::Configuration;
            });
        }
        _ => {}
    }
}

fn loader_from_address(address: &str) -> Option<String> {
    if address.contains("\0FML3\0") {
        Some("neoforge".into())
    } else if address.contains("\0FML2\0") || address.contains("\0FML\0") {
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
    use super::*;

    fn handle(protocol_version: i32) -> SessionHandle {
        SessionHandle {
            snapshot: Arc::new(RwLock::new(ConnectionSnapshot {
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
            })),
            client_writer: Arc::new(RwLock::new(None)),
            server_writer: Arc::new(RwLock::new(None)),
            compression_threshold: Arc::new(RwLock::new(None)),
            client_cipher: Arc::new(LinkCipher::new()),
            server_cipher: Arc::new(LinkCipher::new()),
            encryption_bridge: Arc::new(EncryptionBridge::new()),
            reconfiguration_offered: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
        }
    }

    fn frame(body: &'static [u8]) -> PacketFrame {
        PacketFrame {
            id: 3,
            body: Bytes::from_static(body),
            compressed: false,
            wire_length: body.len() + 1,
        }
    }

    fn state_of(handle: &SessionHandle) -> ProtocolState {
        handle.snapshot.read().state
    }

    #[test]
    fn acknowledging_finish_configuration_enters_play() {
        let session = handle(767);
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(&[]),
            ProtocolState::Configuration,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
    }

    #[test]
    fn play_only_returns_to_configuration_after_the_server_offers_it() {
        let session = handle(767);
        session.snapshot.write().state = ProtocolState::Play;

        // An empty client packet on its own must not rewrite the state.
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(&[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);

        track_configuration_phase(
            &session,
            Direction::ServerToClient,
            &frame(&[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(&[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Configuration);
    }

    #[test]
    fn packets_with_a_body_never_move_the_state() {
        let session = handle(767);
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(&[1, 2, 3]),
            ProtocolState::Configuration,
        );
        assert_eq!(state_of(&session), ProtocolState::Configuration);
    }

    #[test]
    fn releases_without_a_configuration_phase_are_left_alone() {
        let session = handle(340);
        session.snapshot.write().state = ProtocolState::Play;
        track_configuration_phase(
            &session,
            Direction::ClientToServer,
            &frame(&[]),
            ProtocolState::Play,
        );
        assert_eq!(state_of(&session), ProtocolState::Play);
    }
}
