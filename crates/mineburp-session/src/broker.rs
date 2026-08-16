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
use rand::RngCore as _;
use serde::Serialize;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
    time::{Instant, timeout},
};
use uuid::Uuid;

use crate::{SessionJoinProvider, SessionJoinRequest, TransparentRouteProvider, TransparentTarget};

const PROTOCOL_VERSION: &str = "1";
const JOIN_TIMEOUT: Duration = Duration::from_secs(12);
const ROUTE_WAIT: Duration = Duration::from_secs(3);
const MAX_LINE_LENGTH: usize = 16 * 1024;

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
    pending: Mutex<HashMap<Uuid, oneshot::Sender<Result<(), String>>>>,
    route_changed: Notify,
    connected_agents: AtomicUsize,
    transparent_intercept_enabled: AtomicBool,
    transparent_route_provider: RwLock<Option<Arc<dyn TransparentRouteProvider>>>,
}

#[derive(Debug, Clone)]
struct SessionRoute {
    agent_id: Uuid,
    profile_id: String,
    sender: mpsc::Sender<BrokerCommand>,
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
            ready_sessions: self.state.routes.read().await.len(),
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
        let deadline = Instant::now() + ROUTE_WAIT;
        loop {
            let notified = self.state.route_changed.notified();
            if let Some(route) = self.state.routes.write().await.remove(client_hash) {
                return Ok(route);
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
        self.state
            .pending
            .lock()
            .await
            .insert(request_id, result_tx);
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
        match timeout(JOIN_TIMEOUT, result_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("the client-assistance result channel closed".into()),
            Err(_) => {
                self.state.pending.lock().await.remove(&request_id);
                Err("the client-assisted upstream session join timed out".into())
            }
        }
    }
}

impl ClientAssistServer {
    /// Accepts authenticated Java-agent connections until the runtime stops.
    pub async fn run(self) -> Result<(), BrokerError> {
        let listener = TcpListener::from_std(self.listener)?;
        loop {
            let (stream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let broker = self.broker.clone();
            tokio::spawn(async move {
                if let Err(error) = run_agent_connection(broker, stream).await {
                    tracing::debug!(%error, "client-assistance agent disconnected");
                }
            });
        }
    }
}

async fn run_agent_connection(
    broker: ClientAssistBroker,
    stream: TcpStream,
) -> Result<(), io::Error> {
    let agent_id = Uuid::new_v4();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let Some(hello) = read_protocol_line(&mut reader).await? else {
        return Ok(());
    };
    if hello.len() > MAX_LINE_LENGTH || !valid_hello(&hello, &broker.capability) {
        writer.write_all(b"ERROR\tauthentication_failed\n").await?;
        return Ok(());
    }
    writer
        .write_all(format!("HELLO_OK\t{agent_id}\n").as_bytes())
        .await?;
    let Some(first_line) = read_protocol_line(&mut reader).await? else {
        return Ok(());
    };
    if let Some(target) = parse_route_request(&first_line) {
        let response = match broker.open_transparent_route(target).await {
            Ok(port) => format!("ROUTE_OK\t{port}\n"),
            Err(error) => format!("ROUTE_ERR\t{}\n", encode_field(&error)),
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
        let mut next_line = Some(first_line);
        loop {
            let line = match next_line.take() {
                Some(line) => line,
                None => match read_protocol_line(&mut reader).await? {
                    Some(line) => line,
                    None => break,
                },
            };
            let fields = line.split('\t').collect::<Vec<_>>();
            match fields.as_slice() {
                ["READY", client_hash, profile_id] => {
                    let Some(client_hash) = decode_field(client_hash) else {
                        continue;
                    };
                    let Some(profile_id) = decode_field(profile_id) else {
                        continue;
                    };
                    broker.state.routes.write().await.insert(
                        client_hash,
                        SessionRoute {
                            agent_id,
                            profile_id,
                            sender: command_tx.clone(),
                        },
                    );
                    broker.state.route_changed.notify_waiters();
                }
                ["RESULT", request_id, "OK"] => {
                    deliver_result(&broker, request_id, Ok(())).await;
                }
                ["RESULT", request_id, "ERR", message] => {
                    let message = decode_field(message).unwrap_or_else(|| {
                        "the Minecraft session service rejected the join".into()
                    });
                    deliver_result(&broker, request_id, Err(message)).await;
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

fn valid_hello(line: &str, capability: &str) -> bool {
    let fields = line.split('\t').collect::<Vec<_>>();
    let ["HELLO", version, supplied] = fields.as_slice() else {
        return false;
    };
    *version == PROTOCOL_VERSION
        && supplied.len() == capability.len()
        && supplied.as_bytes().ct_eq(capability.as_bytes()).unwrap_u8() == 1
}

async fn deliver_result(broker: &ClientAssistBroker, request_id: &str, result: Result<(), String>) {
    let Ok(request_id) = Uuid::parse_str(request_id) else {
        return;
    };
    if let Some(sender) = broker.state.pending.lock().await.remove(&request_id) {
        let _ = sender.send(result);
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
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    use super::*;

    #[test]
    fn hello_requires_the_exact_capability() {
        assert!(valid_hello("HELLO\t1\tsecret", "secret"));
        assert!(!valid_hello("HELLO\t1\twrong", "secret"));
        assert!(!valid_hello("HELLO\t2\tsecret", "secret"));
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
        let stream = TcpStream::connect(broker.endpoint()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(format!("HELLO\t1\t{}\n", broker.capability).as_bytes())
            .await
            .unwrap();
        assert!(
            lines
                .next_line()
                .await
                .unwrap()
                .unwrap()
                .starts_with("HELLO_OK\t")
        );
        writer
            .write_all(
                format!(
                    "READY\t{}\t{}\n",
                    encode_field("client hash"),
                    encode_field("profile-id")
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let provider = broker.clone();
        let join_task = tokio::spawn(async move {
            provider
                .join_server(&SessionJoinRequest {
                    client_server_hash: "client hash".into(),
                    upstream_server_hash: "upstream hash".into(),
                })
                .await
        });
        let join_line = timeout(Duration::from_secs(2), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
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
    async fn rejects_a_protocol_line_over_the_limit_without_unbounded_reading() {
        let input = vec![b'x'; MAX_LINE_LENGTH + 2];
        let mut reader = BufReader::new(input.as_slice());
        let error = read_protocol_line(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
