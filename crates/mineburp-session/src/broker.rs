use std::{
    collections::HashMap,
    fmt,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use serde::Serialize;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, RwLock, Semaphore, mpsc, oneshot},
    time::{Instant, timeout},
};
use uuid::Uuid;

use crate::{SessionJoinProvider, SessionJoinRequest, TransparentRouteProvider, TransparentTarget};

/// Wire protocol version. Version 2 replaced the plaintext capability in
/// `HELLO` with a mutual HMAC challenge, so a version 1 agent is refused.
const PROTOCOL_VERSION: &str = "2";
const MAX_LINE_LENGTH: usize = 16 * 1024;
const NONCE_LENGTH: usize = 32;
/// Domain-separation labels: each side's proof is useless as the other's.
const BROKER_PROOF_LABEL: &[u8] = b"mineburp-client-assistance-v2 broker";
const AGENT_PROOF_LABEL: &[u8] = b"mineburp-client-assistance-v2 agent";
/// Open loopback connections, authenticated or not. One Minecraft client holds
/// one long-lived connection plus a short route request per server connect.
const MAX_CONNECTIONS: usize = 64;
/// Ready sessions a single agent may hold at once.
const MAX_ROUTES_PER_AGENT: usize = 64;

/// Deadlines for the broker. Tests shorten them; production uses `default`.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// From accept until the agent has authenticated and named its purpose.
    handshake: Duration,
    /// How long a `READY` session stays claimable. Matches the agent's own
    /// 60-second credential lifetime.
    route_lifetime: Duration,
    /// How long a join waits for the matching `READY` to arrive.
    route_wait: Duration,
    /// How long a join waits for the agent's `RESULT`.
    join: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            route_lifetime: Duration::from_mins(1),
            route_wait: Duration::from_secs(3),
            join: Duration::from_secs(12),
        }
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("client-assistance broker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("client-assistance broker is not bound to loopback")]
    NotLoopback,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientAssistStatus {
    pub endpoint: String,
    pub connected_agents: usize,
    pub ready_sessions: usize,
}

#[derive(Clone)]
pub struct ClientAssistBroker {
    endpoint: SocketAddr,
    capability: Arc<str>,
    state: Arc<BrokerState>,
}

impl fmt::Debug for ClientAssistBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientAssistBroker")
            .field("endpoint", &self.endpoint)
            .field(
                "connected_agents",
                &self.state.connected_agents.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ClientAssistServer {
    listener: std::net::TcpListener,
    broker: ClientAssistBroker,
}

#[derive(Debug)]
struct BrokerState {
    routes: RwLock<HashMap<String, SessionRoute>>,
    pending: Mutex<HashMap<Uuid, PendingJoin>>,
    route_changed: Notify,
    connected_agents: AtomicUsize,
    connections: Arc<Semaphore>,
    timing: Timing,
    transparent_intercept_enabled: AtomicBool,
    transparent_route_provider: RwLock<Option<Arc<dyn TransparentRouteProvider>>>,
}

#[derive(Debug, Clone)]
struct SessionRoute {
    agent_id: Uuid,
    profile_id: String,
    sender: mpsc::Sender<BrokerCommand>,
    expires_at: Instant,
}

/// A join waiting on one agent. Only that agent's `RESULT` may answer it.
#[derive(Debug)]
struct PendingJoin {
    agent_id: Uuid,
    sender: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug)]
struct BrokerCommand {
    request_id: Uuid,
    client_hash: String,
    upstream_hash: String,
}

impl ClientAssistBroker {
    /// Binds a capability-protected loopback broker without requiring an async
    /// runtime. Call [`ClientAssistServer::run`] on the application runtime.
    pub fn bind() -> Result<(Self, ClientAssistServer), BrokerError> {
        Self::bind_with_timing(Timing::default())
    }

    fn bind_with_timing(timing: Timing) -> Result<(Self, ClientAssistServer), BrokerError> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        if !endpoint.ip().is_loopback() {
            return Err(BrokerError::NotLoopback);
        }
        let mut secret = [0_u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let mut capability = String::with_capacity(secret.len() * 2);
        for byte in secret {
            write!(&mut capability, "{byte:02x}").expect("writing to a String cannot fail");
        }
        let broker = Self {
            endpoint,
            capability: capability.into(),
            state: Arc::new(BrokerState {
                routes: RwLock::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                route_changed: Notify::new(),
                connected_agents: AtomicUsize::new(0),
                connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
                timing,
                transparent_intercept_enabled: AtomicBool::new(false),
                transparent_route_provider: RwLock::new(None),
            }),
        };
        let server = ClientAssistServer {
            listener,
            broker: broker.clone(),
        };
        Ok((broker, server))
    }

    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub async fn status(&self) -> ClientAssistStatus {
        ClientAssistStatus {
            endpoint: self.endpoint.to_string(),
            connected_agents: self.state.connected_agents.load(Ordering::Relaxed),
            ready_sessions: {
                let now = Instant::now();
                self.state
                    .routes
                    .read()
                    .await
                    .values()
                    .filter(|route| route.expires_at > now)
                    .count()
            },
        }
    }

    pub async fn set_transparent_route_provider(
        &self,
        provider: Option<Arc<dyn TransparentRouteProvider>>,
    ) {
        *self.state.transparent_route_provider.write().await = provider;
    }

    /// Sets the desktop-owned private route provider during synchronous startup.
    /// Setup owns this lock before the broker starts accepting connections, so a
    /// non-blocking acquisition avoids entering a Tokio blocking section.
    pub fn set_transparent_route_provider_blocking(
        &self,
        provider: Option<Arc<dyn TransparentRouteProvider>>,
    ) {
        *self
            .state
            .transparent_route_provider
            .try_write()
            .expect("the route provider is not shared during startup") = provider;
    }

    pub fn set_transparent_intercept_enabled(&self, enabled: bool) {
        self.state
            .transparent_intercept_enabled
            .store(enabled, Ordering::Release);
    }

    #[must_use]
    pub fn transparent_intercept_enabled(&self) -> bool {
        self.state
            .transparent_intercept_enabled
            .load(Ordering::Acquire)
    }

    /// Atomically refreshes the small configuration read by the Java agent.
    /// The capability is never returned through the desktop command surface.
    pub fn write_agent_config(&self, path: &Path) -> Result<(), BrokerError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary)?;
        writeln!(output, "protocol={PROTOCOL_VERSION}")?;
        writeln!(output, "host={}", self.endpoint.ip())?;
        writeln!(output, "port={}", self.endpoint.port())?;
        writeln!(output, "capability={}", self.capability)?;
        writeln!(
            output,
            "transparent_intercept={}",
            self.transparent_intercept_enabled()
        )?;
        output.sync_all()?;
        drop(output);
        // std::fs::rename replaces atomically on Unix. Windows rename does not
        // replace an existing destination, so remove only this one known file.
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(temporary, path)?;
        Ok(())
    }

    async fn take_route(&self, client_hash: &str) -> Result<SessionRoute, String> {
        let deadline = Instant::now() + self.state.timing.route_wait;
        loop {
            let notified = self.state.route_changed.notified();
            {
                let mut routes = self.state.routes.write().await;
                let now = Instant::now();
                routes.retain(|_, route| route.expires_at > now);
                if let Some(route) = routes.remove(client_hash) {
                    return Ok(route);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || timeout(remaining, notified).await.is_err() {
                return Err(
                    "no client-assisted session matched this handshake; launch Minecraft with the MineBurp Java agent"
                        .into(),
                );
            }
        }
    }

    async fn open_transparent_route(&self, target: TransparentTarget) -> Result<u16, String> {
        if !self.transparent_intercept_enabled() {
            return Err("transparent interception is disabled".into());
        }
        let provider = self
            .state
            .transparent_route_provider
            .read()
            .await
            .clone()
            .ok_or("the desktop interception service is unavailable")?;
        provider.open_transparent_route(target).await
    }
}

#[async_trait]
impl SessionJoinProvider for ClientAssistBroker {
    async fn join_server(&self, request: &SessionJoinRequest) -> Result<(), String> {
        let route = self.take_route(&request.client_server_hash).await?;
        let request_id = Uuid::new_v4();
        let (result_tx, result_rx) = oneshot::channel();
        self.state.pending.lock().await.insert(
            request_id,
            PendingJoin {
                agent_id: route.agent_id,
                sender: result_tx,
            },
        );
        if route
            .sender
            .send(BrokerCommand {
                request_id,
                client_hash: request.client_server_hash.clone(),
                upstream_hash: request.upstream_server_hash.clone(),
            })
            .await
            .is_err()
        {
            self.state.pending.lock().await.remove(&request_id);
            return Err(format!(
                "the client-assistance agent for profile {} disconnected",
                route.profile_id
            ));
        }
        match timeout(self.state.timing.join, result_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("the client-assistance result channel closed".into()),
            Err(_) => {
                self.state.pending.lock().await.remove(&request_id);
                Err("the client-assisted upstream session join timed out".into())
            }
        }
    }
}

// Accept failures such as descriptor exhaustion must not kill the broker.
async fn retry_accept<T, F, Fut>(mut accept: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, io::Error>>,
{
    loop {
        match accept().await {
            Ok(accepted) => return accepted,
            Err(error) => {
                tracing::warn!(%error, "client-assistance accept failed; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod accept_regression {
    use super::*;

    #[tokio::test]
    async fn accept_errors_are_retried() {
        let mut calls = 0;
        let result = retry_accept(|| {
            calls += 1;
            std::future::ready(if calls < 3 {
                Err(io::Error::from_raw_os_error(24))
            } else {
                Ok(42)
            })
        })
        .await;
        assert_eq!(result, 42);
        assert_eq!(calls, 3);
    }
}

impl ClientAssistServer {
    /// Accepts authenticated Java-agent connections until the runtime stops.
    pub async fn run(self) -> Result<(), BrokerError> {
        let listener = TcpListener::from_std(self.listener)?;
        loop {
            let (stream, peer) = retry_accept(|| listener.accept()).await;
            if !peer.ip().is_loopback() {
                continue;
            }
            // Excess connections are closed rather than queued, so a local
            // process cannot exhaust tasks or memory by opening sockets.
            let Ok(permit) = Arc::clone(&self.broker.state.connections).try_acquire_owned() else {
                tracing::debug!("client-assistance connection limit reached");
                continue;
            };
            let broker = self.broker.clone();
            tokio::spawn(async move {
                if let Err(error) = run_agent_connection(broker, stream).await {
                    tracing::debug!(%error, "client-assistance agent disconnected");
                }
                drop(permit);
            });
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_agent_connection(
    broker: ClientAssistBroker,
    stream: TcpStream,
) -> Result<(), io::Error> {
    let agent_id = Uuid::new_v4();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    // Everything up to the agent naming its purpose shares one deadline, so an
    // unauthenticated socket cannot hold a connection slot open.
    let handshake = timeout(
        broker.state.timing.handshake,
        authenticate_agent(&broker, &mut reader, &mut writer, agent_id),
    )
    .await;
    let first_line = match handshake {
        Ok(Ok(Some(line))) => line,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            let _ = writer.write_all(b"ERROR\ttimeout\n").await;
            return Ok(());
        }
    };
    if first_line != "SESSION" {
        let response = match parse_route_request(&first_line) {
            Some(target) => match broker.open_transparent_route(target).await {
                Ok(port) => format!("ROUTE_OK\t{port}\n"),
                Err(error) => format!("ROUTE_ERR\t{}\n", encode_field(&error)),
            },
            None => "ERROR\tbad_request\n".to_owned(),
        };
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }
    let (command_tx, mut command_rx) = mpsc::channel::<BrokerCommand>(8);
    broker
        .state
        .connected_agents
        .fetch_add(1, Ordering::Relaxed);

    let writer_task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            let line = format!(
                "JOIN\t{}\t{}\t{}\n",
                command.request_id,
                encode_field(&command.client_hash),
                encode_field(&command.upstream_hash),
            );
            writer.write_all(line.as_bytes()).await?;
            writer.flush().await?;
        }
        Ok::<(), io::Error>(())
    });

    let read_result = async {
        while let Some(line) = read_protocol_line(&mut reader).await? {
            let fields = line.split('\t').collect::<Vec<_>>();
            match fields.as_slice() {
                ["READY", client_hash, profile_id] => {
                    let Some(client_hash) = decode_field(client_hash) else {
                        continue;
                    };
                    let Some(profile_id) = decode_field(profile_id) else {
                        continue;
                    };
                    let route = SessionRoute {
                        agent_id,
                        profile_id,
                        sender: command_tx.clone(),
                        expires_at: Instant::now() + broker.state.timing.route_lifetime,
                    };
                    if register_route(&broker, client_hash, route).await {
                        broker.state.route_changed.notify_waiters();
                    }
                }
                ["RESULT", request_id, "OK"] => {
                    deliver_result(&broker, agent_id, request_id, Ok(())).await;
                }
                ["RESULT", request_id, "ERR", message] => {
                    let message = decode_field(message).unwrap_or_else(|| {
                        "the Minecraft session service rejected the join".into()
                    });
                    deliver_result(&broker, agent_id, request_id, Err(message)).await;
                }
                _ => {}
            }
        }
        Ok::<(), io::Error>(())
    }
    .await;

    broker
        .state
        .routes
        .write()
        .await
        .retain(|_, route| route.agent_id != agent_id);
    // Joins this agent can no longer answer fail now instead of timing out.
    broker
        .state
        .pending
        .lock()
        .await
        .retain(|_, join| join.agent_id != agent_id);
    broker
        .state
        .connected_agents
        .fetch_sub(1, Ordering::Relaxed);
    writer_task.abort();
    read_result
}

async fn read_protocol_line<R>(reader: &mut R) -> io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::with_capacity(256);
    let read = reader
        .take((MAX_LINE_LENGTH + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client-assistance protocol line exceeded the limit",
        ));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "client-assistance protocol line was not UTF-8",
        )
    })
}

/// Runs the broker half of the mutual challenge and returns the agent's first
/// command (`SESSION` or `ROUTE ...`). `None` means the connection ended or the
/// agent was refused; the refusal reason has already been written.
///
/// ```text
/// agent  → HELLO      2  <agent nonce>
/// broker → CHALLENGE  <broker nonce>  <broker proof>
/// agent  → AUTH       <agent proof>
/// broker → HELLO_OK   <agent id>
/// agent  → SESSION | ROUTE <host> <port>
/// ```
///
/// Each proof is HMAC-SHA256 keyed by the capability over a role label and
/// both nonces. The capability itself never crosses the socket, the agent
/// checks the broker's proof before revealing anything, and the broker's fresh
/// nonce makes a recorded `AUTH` useless on any other connection.
async fn authenticate_agent<R, W>(
    broker: &ClientAssistBroker,
    reader: &mut R,
    writer: &mut W,
    agent_id: Uuid,
) -> io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(hello) = read_protocol_line(reader).await? else {
        return Ok(None);
    };
    let fields = hello.split('\t').collect::<Vec<_>>();
    let agent_nonce = match fields.as_slice() {
        ["HELLO", version, nonce] if *version == PROTOCOL_VERSION => decode_nonce(nonce),
        ["HELLO", ..] => {
            writer
                .write_all(format!("ERROR\tunsupported_protocol\t{PROTOCOL_VERSION}\n").as_bytes())
                .await?;
            return Ok(None);
        }
        _ => None,
    };
    let Some(agent_nonce) = agent_nonce else {
        writer.write_all(b"ERROR\tbad_request\n").await?;
        return Ok(None);
    };
    let mut broker_nonce = [0_u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut broker_nonce);
    let key = broker.capability.as_bytes();
    let broker_proof = handshake_proof(key, BROKER_PROOF_LABEL, &agent_nonce, &broker_nonce);
    writer
        .write_all(
            format!(
                "CHALLENGE\t{}\t{}\n",
                URL_SAFE_NO_PAD.encode(broker_nonce),
                URL_SAFE_NO_PAD.encode(broker_proof)
            )
            .as_bytes(),
        )
        .await?;
    let Some(auth) = read_protocol_line(reader).await? else {
        return Ok(None);
    };
    let expected = handshake_proof(key, AGENT_PROOF_LABEL, &agent_nonce, &broker_nonce);
    let accepted = match auth.split('\t').collect::<Vec<_>>().as_slice() {
        ["AUTH", proof] => URL_SAFE_NO_PAD
            .decode(proof)
            .is_ok_and(|proof| proof.len() == expected.len() && bool::from(proof.ct_eq(&expected))),
        _ => false,
    };
    if !accepted {
        writer.write_all(b"ERROR\tauthentication_failed\n").await?;
        return Ok(None);
    }
    writer
        .write_all(format!("HELLO_OK\t{agent_id}\n").as_bytes())
        .await?;
    read_protocol_line(reader).await
}

fn decode_nonce(value: &str) -> Option<[u8; NONCE_LENGTH]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

fn handshake_proof(
    key: &[u8],
    label: &[u8],
    agent_nonce: &[u8; NONCE_LENGTH],
    broker_nonce: &[u8; NONCE_LENGTH],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(label);
    mac.update(&[0]);
    mac.update(agent_nonce);
    mac.update(broker_nonce);
    mac.finalize().into_bytes().into()
}

/// Records a `READY` for its agent. A hash another agent still holds is left
/// alone, and one agent cannot hold more than [`MAX_ROUTES_PER_AGENT`].
async fn register_route(
    broker: &ClientAssistBroker,
    client_hash: String,
    route: SessionRoute,
) -> bool {
    let mut routes = broker.state.routes.write().await;
    let now = Instant::now();
    routes.retain(|_, existing| existing.expires_at > now);
    if routes
        .get(&client_hash)
        .is_some_and(|existing| existing.agent_id != route.agent_id)
    {
        tracing::debug!("refused a READY for a session another agent holds");
        return false;
    }
    let held = routes
        .iter()
        .filter(|(hash, existing)| existing.agent_id == route.agent_id && **hash != client_hash)
        .count();
    if held >= MAX_ROUTES_PER_AGENT {
        tracing::debug!("refused a READY over the per-agent session limit");
        return false;
    }
    routes.insert(client_hash, route);
    true
}

async fn deliver_result(
    broker: &ClientAssistBroker,
    agent_id: Uuid,
    request_id: &str,
    result: Result<(), String>,
) {
    let Ok(request_id) = Uuid::parse_str(request_id) else {
        return;
    };
    let mut pending = broker.state.pending.lock().await;
    // Only the agent the join was sent to may answer it.
    if pending
        .get(&request_id)
        .is_some_and(|join| join.agent_id == agent_id)
        && let Some(join) = pending.remove(&request_id)
    {
        let _ = join.sender.send(result);
    }
}

fn encode_field(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_field(value: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    String::from_utf8(bytes).ok()
}

fn parse_route_request(line: &str) -> Option<TransparentTarget> {
    let fields = line.split('\t').collect::<Vec<_>>();
    let ["ROUTE", host, port] = fields.as_slice() else {
        return None;
    };
    let host = decode_field(host)?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() || host.len() > 253 || host.contains(['\r', '\n', '\0']) || port == 0 {
        return None;
    }
    Some(TransparentTarget { host, port })
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Lines},
        net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    };

    use super::*;

    type AgentLines = Lines<BufReader<OwnedReadHalf>>;

    fn fast_timing() -> Timing {
        Timing {
            handshake: Duration::from_millis(200),
            route_lifetime: Duration::from_mins(1),
            route_wait: Duration::from_millis(300),
            join: Duration::from_secs(2),
        }
    }

    async fn next_line(lines: &mut AgentLines) -> Option<String> {
        timeout(Duration::from_secs(2), lines.next_line())
            .await
            .expect("the broker answered in time")
            .unwrap()
    }

    /// The agent half of the handshake, written independently of the broker's
    /// own code so a symmetric mistake cannot pass. Returns the broker's reply
    /// to `AUTH` together with the open connection.
    async fn handshake(
        broker: &ClientAssistBroker,
        key: &[u8],
        agent_nonce: [u8; NONCE_LENGTH],
    ) -> (AgentLines, OwnedWriteHalf, String, String) {
        let stream = TcpStream::connect(broker.endpoint()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(format!("HELLO\t2\t{}\n", URL_SAFE_NO_PAD.encode(agent_nonce)).as_bytes())
            .await
            .unwrap();
        let challenge = next_line(&mut lines).await.unwrap();
        let fields = challenge.split('\t').collect::<Vec<_>>();
        assert_eq!(fields[0], "CHALLENGE");
        let broker_nonce = decode_nonce(fields[1]).unwrap();
        let broker_proof = URL_SAFE_NO_PAD.decode(fields[2]).unwrap();
        // The broker proves the capability before the agent reveals anything.
        assert_eq!(
            broker_proof,
            handshake_proof(
                broker.capability.as_bytes(),
                BROKER_PROOF_LABEL,
                &agent_nonce,
                &broker_nonce
            )
        );
        let auth = format!(
            "AUTH\t{}\n",
            URL_SAFE_NO_PAD.encode(handshake_proof(
                key,
                AGENT_PROOF_LABEL,
                &agent_nonce,
                &broker_nonce
            ))
        );
        writer.write_all(auth.as_bytes()).await.unwrap();
        let reply = next_line(&mut lines).await.unwrap_or_default();
        (lines, writer, reply, auth)
    }

    async fn session_agent(broker: &ClientAssistBroker) -> (AgentLines, OwnedWriteHalf) {
        let mut nonce = [0_u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);
        let (lines, mut writer, reply, _) =
            handshake(broker, broker.capability.as_bytes(), nonce).await;
        assert!(reply.starts_with("HELLO_OK\t"), "{reply}");
        writer.write_all(b"SESSION\n").await.unwrap();
        (lines, writer)
    }

    async fn ready(writer: &mut OwnedWriteHalf, client_hash: &str) {
        writer
            .write_all(
                format!(
                    "READY\t{}\t{}\n",
                    encode_field(client_hash),
                    encode_field("profile-id")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    fn join(
        broker: &ClientAssistBroker,
        client_hash: &str,
    ) -> tokio::task::JoinHandle<Result<(), String>> {
        let provider = broker.clone();
        let request = SessionJoinRequest {
            client_server_hash: client_hash.into(),
            upstream_server_hash: "upstream hash".into(),
        };
        tokio::spawn(async move { provider.join_server(&request).await })
    }

    #[test]
    fn proofs_are_bound_to_role_key_and_both_nonces() {
        let (a, b) = ([1_u8; NONCE_LENGTH], [2_u8; NONCE_LENGTH]);
        let agent = handshake_proof(b"key", AGENT_PROOF_LABEL, &a, &b);
        assert_ne!(agent, handshake_proof(b"key", BROKER_PROOF_LABEL, &a, &b));
        assert_ne!(agent, handshake_proof(b"other", AGENT_PROOF_LABEL, &a, &b));
        assert_ne!(agent, handshake_proof(b"key", AGENT_PROOF_LABEL, &b, &a));
    }

    #[test]
    fn broker_only_binds_loopback() {
        let (broker, _server) = ClientAssistBroker::bind().unwrap();
        assert_eq!(
            broker.endpoint().ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn agent_configuration_can_be_securely_replaced() {
        let directory = std::env::temp_dir().join(format!("mineburp-session-{}", Uuid::new_v4()));
        let path = directory.join("client-assistance.properties");
        let (first, _server) = ClientAssistBroker::bind().unwrap();
        first.write_agent_config(&path).unwrap();
        let first_text = fs::read_to_string(&path).unwrap();
        let (second, _server) = ClientAssistBroker::bind().unwrap();
        second.write_agent_config(&path).unwrap();
        let second_text = fs::read_to_string(&path).unwrap();
        assert_ne!(first_text, second_text);
        assert!(second_text.contains(&format!("port={}", second.endpoint().port())));
        assert!(second_text.contains(&format!("protocol={PROTOCOL_VERSION}")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn routes_a_one_use_join_request_to_the_matching_agent() {
        let (broker, server) = ClientAssistBroker::bind().unwrap();
        let server_task = tokio::spawn(server.run());
        let (mut lines, mut writer) = session_agent(&broker).await;
        ready(&mut writer, "client hash").await;

        let join_task = join(&broker, "client hash");
        let join_line = next_line(&mut lines).await.unwrap();
        let fields = join_line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields[0], "JOIN");
        assert_eq!(decode_field(fields[2]).as_deref(), Some("client hash"));
        assert_eq!(decode_field(fields[3]).as_deref(), Some("upstream hash"));
        writer
            .write_all(format!("RESULT\t{}\tOK\n", fields[1]).as_bytes())
            .await
            .unwrap();
        assert!(join_task.await.unwrap().is_ok());
        assert_eq!(broker.status().await.ready_sessions, 0);

        server_task.abort();
    }

    #[tokio::test]
    async fn refuses_an_agent_that_does_not_know_the_capability() {
        let (broker, server) = ClientAssistBroker::bind().unwrap();
        let server_task = tokio::spawn(server.run());
        let (mut lines, _writer, reply, _) =
            handshake(&broker, b"not the capability", [7; NONCE_LENGTH]).await;
        assert_eq!(reply, "ERROR\tauthentication_failed");
        assert_eq!(next_line(&mut lines).await, None);
        server_task.abort();
    }

    #[tokio::test]
    async fn a_recorded_auth_is_useless_on_another_connection() {
        let (broker, server) = ClientAssistBroker::bind().unwrap();
        let server_task = tokio::spawn(server.run());
        let nonce = [9_u8; NONCE_LENGTH];
        let (_lines, _writer, reply, recorded_auth) =
            handshake(&broker, broker.capability.as_bytes(), nonce).await;
        assert!(reply.starts_with("HELLO_OK\t"));

        // Same agent nonce, recorded AUTH: the broker's fresh nonce differs.
        let stream = TcpStream::connect(broker.endpoint()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(format!("HELLO\t2\t{}\n", URL_SAFE_NO_PAD.encode(nonce)).as_bytes())
            .await
            .unwrap();
        assert!(
            next_line(&mut lines)
                .await
                .unwrap()
                .starts_with("CHALLENGE\t")
        );
        writer.write_all(recorded_auth.as_bytes()).await.unwrap();
        assert_eq!(
            next_line(&mut lines).await.as_deref(),
            Some("ERROR\tauthentication_failed")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn a_version_one_agent_is_told_which_protocol_to_speak() {
        let (broker, server) = ClientAssistBroker::bind().unwrap();
        let server_task = tokio::spawn(server.run());
        let stream = TcpStream::connect(broker.endpoint()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        // The old plaintext form, carrying the real capability.
        writer
            .write_all(format!("HELLO\t1\t{}\n", broker.capability).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            next_line(&mut lines).await.as_deref(),
            Some("ERROR\tunsupported_protocol\t2")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn a_silent_connection_is_closed_after_the_handshake_deadline() {
        let (broker, server) = ClientAssistBroker::bind_with_timing(fast_timing()).unwrap();
        let server_task = tokio::spawn(server.run());
        let stream = TcpStream::connect(broker.endpoint()).await.unwrap();
        let (reader, _writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        assert_eq!(
            next_line(&mut lines).await.as_deref(),
            Some("ERROR\ttimeout")
        );
        assert_eq!(next_line(&mut lines).await, None);

        // An authenticated agent that never names its purpose is closed too.
        let mut nonce = [0_u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);
        let (mut lines, _writer, reply, _) =
            handshake(&broker, broker.capability.as_bytes(), nonce).await;
        assert!(reply.starts_with("HELLO_OK\t"));
        assert_eq!(
            next_line(&mut lines).await.as_deref(),
            Some("ERROR\ttimeout")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn ready_sessions_expire() {
        let timing = Timing {
            route_lifetime: Duration::from_millis(100),
            ..fast_timing()
        };
        let (broker, server) = ClientAssistBroker::bind_with_timing(timing).unwrap();
        let server_task = tokio::spawn(server.run());
        let (_lines, mut writer) = session_agent(&broker).await;
        ready(&mut writer, "stale hash").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(broker.status().await.ready_sessions, 1);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(broker.status().await.ready_sessions, 0);
        let error = join(&broker, "stale hash").await.unwrap().unwrap_err();
        assert!(error.contains("no client-assisted session"), "{error}");
        server_task.abort();
    }

    #[tokio::test]
    async fn another_agent_can_neither_take_over_nor_answer_a_session() {
        let (broker, server) = ClientAssistBroker::bind_with_timing(fast_timing()).unwrap();
        let server_task = tokio::spawn(server.run());
        let (mut owner_lines, mut owner) = session_agent(&broker).await;
        let (mut other_lines, mut other) = session_agent(&broker).await;
        ready(&mut owner, "shared hash").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        ready(&mut other, "shared hash").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let join_task = join(&broker, "shared hash");
        let join_line = next_line(&mut owner_lines).await.unwrap();
        let request_id = join_line.split('\t').nth(1).unwrap().to_owned();
        // The other agent saw nothing and its answer is ignored.
        other
            .write_all(format!("RESULT\t{request_id}\tOK\n").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!join_task.is_finished());
        owner
            .write_all(
                format!(
                    "RESULT\t{request_id}\tERR\t{}\n",
                    encode_field("owner says no")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(join_task.await.unwrap(), Err("owner says no".into()));
        assert!(
            timeout(Duration::from_millis(100), other_lines.next_line())
                .await
                .is_err(),
            "the other agent must not receive the join"
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn rejects_a_protocol_line_over_the_limit_without_unbounded_reading() {
        let input = vec![b'x'; MAX_LINE_LENGTH + 2];
        let mut reader = BufReader::new(input.as_slice());
        let error = read_protocol_line(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
