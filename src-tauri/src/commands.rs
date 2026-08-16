#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri command state is supplied by its by-value State extractor"
)]

use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mineburp_auth::{AuthClient, AuthConfig, MinecraftProfile, MinecraftSession};
use mineburp_capture::{CaptureCapabilities, CaptureStats};
use mineburp_core::{
    ConnectionSnapshot, Direction, Disposition, FilterExpression, FilterField, InterceptRule,
    PacketSummary, ProtocolState, RepeaterTab, TrafficSource,
};
use mineburp_launcher::{AgentSetupOutcome, InstanceDescriptor, LaunchOutcome, LaunchRequest};
use mineburp_project::{
    ContentMode, ContentQuery, PacketQuery, ProjectInfo, ProjectOptions, ProjectStore, SearchTerm,
};
use mineburp_protocol::{
    DecodeContext, PacketInsight, PacketRegistry, ProtocolVersion, SchemaPack, decode_schema,
    inspect_logical,
};
use mineburp_proxy::HeldPacketDecision;
use serde::{Deserialize, Serialize};
use tauri::State;
use url::Url;
use uuid::Uuid;

use crate::state::{AuthenticatedAccount, DesktopState, PendingAuth};

type CommandResult<T> = Result<T, String>;
const AUTH_CALLBACK_URL: &str = "http://localhost:53682/callback";

#[derive(Debug, Serialize)]
pub struct AppCapabilities {
    side_capture: CaptureCapabilities,
    project_encryption: bool,
    protocol_min: i32,
    protocol_max: i32,
}

#[derive(Debug, Serialize)]
pub struct DecryptModeStatus {
    enabled: bool,
    route_adapter: &'static str,
    active_sessions: usize,
}

#[tauri::command]
pub fn app_capabilities(state: State<'_, DesktopState>) -> AppCapabilities {
    let registry = PacketRegistry::bundled();
    let protocols = registry.supported_protocols();
    AppCapabilities {
        side_capture: state.capture.capabilities(),
        project_encryption: true,
        protocol_min: protocols.first().map_or(4, |entry| entry.protocol),
        protocol_max: protocols.last().map_or(4, |entry| entry.protocol),
    }
}

#[tauri::command]
pub fn decrypt_mode_status(state: State<'_, DesktopState>) -> DecryptModeStatus {
    DecryptModeStatus {
        enabled: state.decrypt_mode_enabled(),
        route_adapter: "private client-assisted loopback routes",
        active_sessions: state.proxy.sessions().len(),
    }
}

#[tauri::command]
pub fn decrypt_mode_set(
    state: State<'_, DesktopState>,
    enabled: bool,
) -> CommandResult<DecryptModeStatus> {
    state
        .set_decrypt_mode(enabled)
        .map_err(|error| error.to_string())?;
    Ok(decrypt_mode_status(state))
}

#[tauri::command]
pub async fn capture_start(state: State<'_, DesktopState>) -> CommandResult<()> {
    state
        .capture
        .start()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn capture_stop(state: State<'_, DesktopState>) -> CommandResult<()> {
    state
        .capture
        .stop()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn capture_stats(state: State<'_, DesktopState>) -> CommandResult<CaptureStats> {
    Ok(state.capture.stats().await)
}

/// A project plus whether it is the scratch project `MineBurp` opened for itself.
///
/// The UI needs the distinction: a temporary project keeps capture on disk from
/// the first packet, but it is deleted when the session ends, so it must not be
/// presented as somewhere work has been saved.
#[derive(Debug, Serialize)]
pub struct ProjectView {
    #[serde(flatten)]
    info: ProjectInfo,
    temporary: bool,
}

impl ProjectView {
    fn new(info: ProjectInfo, temporary: bool) -> Self {
        Self { info, temporary }
    }
}

#[tauri::command]
pub async fn project_create(
    state: State<'_, DesktopState>,
    path: PathBuf,
    name: String,
    passphrase: Option<String>,
) -> CommandResult<ProjectView> {
    let store = tauri::async_runtime::spawn_blocking(move || {
        ProjectStore::create(
            path,
            &name,
            ProjectOptions {
                passphrase,
                read_only: false,
            },
        )
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    let info = store.info().clone();
    let asset_store = store.clone();
    let (packs, rules) = tauri::async_runtime::spawn_blocking(move || {
        Ok::<_, mineburp_project::ProjectError>((
            asset_store.load_schema_packs()?,
            asset_store.load_intercept_rules()?,
        ))
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    state
        .proxy
        .set_schema_packs(packs)
        .map_err(|error| error.to_string())?;
    state
        .proxy
        .set_intercept_rules(rules)
        .map_err(|error| error.to_string())?;
    state.adopt_project(store);
    Ok(ProjectView::new(info, false))
}

#[tauri::command]
pub async fn project_open(
    state: State<'_, DesktopState>,
    path: PathBuf,
    passphrase: Option<String>,
    read_only: Option<bool>,
) -> CommandResult<ProjectView> {
    let read_only = read_only.unwrap_or(false);
    let store = tauri::async_runtime::spawn_blocking(move || {
        ProjectStore::open(
            path,
            ProjectOptions {
                passphrase,
                read_only,
            },
        )
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    let info = store.info().clone();
    let asset_store = store.clone();
    let (packs, rules) = tauri::async_runtime::spawn_blocking(move || {
        Ok::<_, mineburp_project::ProjectError>((
            asset_store.load_schema_packs()?,
            asset_store.load_intercept_rules()?,
        ))
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    state
        .proxy
        .set_schema_packs(packs)
        .map_err(|error| error.to_string())?;
    state
        .proxy
        .set_intercept_rules(rules)
        .map_err(|error| error.to_string())?;
    state.adopt_project(store);
    Ok(ProjectView::new(info, false))
}

#[tauri::command]
pub fn project_current(state: State<'_, DesktopState>) -> Option<ProjectView> {
    let info = state
        .project
        .read()
        .as_ref()
        .map(|store| store.info().clone())?;
    Some(ProjectView::new(info, state.project_is_temporary()))
}

/// Every connection the open project knows about.
///
/// Proxy sessions alone are not the whole picture: passive capture writes one
/// connection row per observed flow, and those are the only handle the operator
/// has for filtering traffic that never went through the proxy.
#[tauri::command]
pub async fn connections_query(
    state: State<'_, DesktopState>,
) -> CommandResult<Vec<ConnectionSnapshot>> {
    const CONNECTION_LIMIT: usize = 200;
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.list_connections(CONNECTION_LIMIT))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn project_checkpoint(state: State<'_, DesktopState>) -> CommandResult<()> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.checkpoint())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// The history filter as the webview describes it.
///
/// One serialisable object rather than a dozen command arguments: the filter
/// grew past the point where positional parameters stayed readable, and the UI
/// already keeps it as a single piece of state.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PacketFilterInput {
    connection_id: Option<Uuid>,
    offset: usize,
    limit: usize,
    search: Option<String>,
    search_regex: bool,
    search_case_sensitive: bool,
    search_negate: bool,
    directions: Vec<Direction>,
    states: Vec<ProtocolState>,
    sources: Vec<TrafficSource>,
    dispositions: Vec<Disposition>,
    include_names: Vec<String>,
    exclude_names: Vec<String>,
    min_size: Option<usize>,
    max_size: Option<usize>,
    /// The operator's filter expression, in the same language intercept rules use.
    expression: Option<String>,
    /// A search through the payload bytes rather than the row's metadata.
    content: Option<String>,
    content_mode: ContentSearchMode,
    content_case_sensitive: bool,
    content_negate: bool,
    before_id: Option<i64>,
    after_id: Option<i64>,
}

/// How the webview labels the payload-search modes.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSearchMode {
    #[default]
    Text,
    Hex,
    Regex,
}

impl From<ContentSearchMode> for ContentMode {
    fn from(mode: ContentSearchMode) -> Self {
        match mode {
            ContentSearchMode::Text => Self::Text,
            ContentSearchMode::Hex => Self::Hex,
            ContentSearchMode::Regex => Self::Regex,
        }
    }
}

impl PacketFilterInput {
    fn into_query(self) -> CommandResult<PacketQuery> {
        let expression = self
            .expression
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(FilterExpression::parse)
            .transpose()
            .map_err(|error| error.to_string())?;
        let search = self
            .search
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .map(|text| SearchTerm {
                text,
                regex: self.search_regex,
                case_sensitive: self.search_case_sensitive,
                negate: self.search_negate,
            });
        let content = self
            .content
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .map(|text| ContentQuery {
                text,
                mode: self.content_mode.into(),
                case_sensitive: self.content_case_sensitive,
                negate: self.content_negate,
            });
        Ok(PacketQuery {
            connection_id: self.connection_id,
            offset: self.offset,
            // Fetching an extra row lets the renderer show an exact "load
            // older" affordance without asking SQLite for a total on every
            // live refresh.
            limit: self.limit.clamp(1, 500),
            search,
            directions: self.directions,
            states: self.states,
            sources: self.sources,
            dispositions: self.dispositions,
            include_names: self.include_names,
            exclude_names: self.exclude_names,
            min_size: self.min_size,
            max_size: self.max_size,
            expression,
            content,
            before_id: self.before_id,
            after_id: self.after_id,
        })
    }
}

#[tauri::command]
pub async fn packets_query(
    state: State<'_, DesktopState>,
    filter: PacketFilterInput,
) -> CommandResult<Vec<PacketSummary>> {
    let store = current_project(&state)?;
    let query = filter.into_query()?;
    tauri::async_runtime::spawn_blocking(move || store.query_packets_filtered(&query))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// The vocabulary the filter expression accepts, for the UI's help affordance.
#[derive(Debug, Serialize)]
pub struct FilterVocabulary {
    fields: Vec<&'static str>,
    operators: Vec<&'static str>,
    states: Vec<&'static str>,
    directions: Vec<&'static str>,
    sources: Vec<&'static str>,
    dispositions: Vec<&'static str>,
}

#[tauri::command]
pub fn filter_vocabulary() -> FilterVocabulary {
    FilterVocabulary {
        fields: FilterField::NAMES.to_vec(),
        operators: vec!["==", "!=", ">", ">=", "<", "<=", "~"],
        states: vec![
            "handshake",
            "status",
            "login",
            "configuration",
            "play",
            "opaque",
            "closed",
        ],
        directions: vec!["client_to_server", "server_to_client"],
        sources: vec!["minecraft", "side_channel"],
        dispositions: vec![
            "forwarded",
            "dropped",
            "edited",
            "delayed",
            "replayed",
            "observed",
            "failed",
        ],
    }
}

/// Validates a filter expression without running it, for live UI feedback.
#[tauri::command]
pub fn filter_validate(expression: String) -> CommandResult<()> {
    if expression.trim().is_empty() {
        return Ok(());
    }
    FilterExpression::parse(&expression)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Bytes shipped with the first look at a packet.
///
/// Enough to fill several screens of the hex view; the rest is paged in through
/// [`packet_bytes`] only if the operator scrolls to it, which is what keeps a
/// multi-megabyte packet openable at all.
const DETAIL_WINDOW_BYTES: usize = 8 * 1024;
const MAX_WINDOW_BYTES: usize = 256 * 1024;

/// A packet prepared for display: metadata, a decode, and a slice of bytes.
///
/// Payloads travel as base64 rather than as a JSON array of byte numbers, which
/// costs about a fifth of the bytes and a fraction of the parse time.
#[derive(Debug, Serialize)]
pub struct PacketView {
    summary: PacketSummary,
    wire: mineburp_core::WireMetadata,
    insight: PacketInsight,
    /// The decode stored at capture time, when a schema pack matched.
    stored_decoded: Option<serde_json::Value>,
    stored_decode_error: Option<String>,
    total_bytes: usize,
    bytes_offset: usize,
    bytes_base64: String,
}

#[derive(Debug, Serialize)]
pub struct ByteWindow {
    offset: usize,
    total: usize,
    base64: String,
}

/// Loads one packet and decodes it *now*.
///
/// Decoding is done here rather than during capture on purpose: at Minecraft
/// packet rates, decoding every packet up front burns CPU on rows nobody opens
/// and is a large part of what made a busy capture unusable.
#[tauri::command]
pub async fn packet_detail(
    state: State<'_, DesktopState>,
    id: i64,
) -> CommandResult<Option<PacketView>> {
    let store = current_project(&state)?;
    let packs = state.proxy.schema_packs();
    tauri::async_runtime::spawn_blocking(move || {
        let window = store.packet_window(id, 0, DETAIL_WINDOW_BYTES)?;
        Ok::<_, mineburp_project::ProjectError>(window.map(|window| {
            let mut insight = inspect_logical(
                window.summary.state,
                window.summary.direction,
                &window.bytes,
                window.summary.protocol_version,
            );
            let schema_decode = decode_with_schema_packs(&packs, &window);
            if window.total_bytes > window.bytes.len() {
                insight.notes.push(format!(
                    "Decoded from the first {} of {} bytes; the rest is paged in on demand.",
                    window.bytes.len(),
                    window.total_bytes
                ));
            }
            let (schema_decoded, schema_error) = schema_decode;
            PacketView {
                summary: window.summary,
                wire: window.wire,
                insight,
                stored_decoded: schema_decoded.or(window.stored_decoded),
                stored_decode_error: schema_error.or(window.stored_decode_error),
                total_bytes: window.total_bytes,
                bytes_offset: window.offset,
                bytes_base64: STANDARD.encode(&window.bytes),
            }
        }))
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

/// Applies a user-supplied schema pack to a packet, if one matches.
///
/// Capture only records *which* schema matched, by name; walking its fields is
/// deferred to here so a loaded pack cannot slow down capture itself.
fn decode_with_schema_packs(
    packs: &[SchemaPack],
    window: &mineburp_project::PacketWindow,
) -> (Option<serde_json::Value>, Option<String>) {
    let summary = &window.summary;
    let Some(packet_id) = summary.packet_id else {
        return (None, None);
    };
    let Some(schema) = packs.iter().flat_map(|pack| &pack.schemas).find(|schema| {
        schema.matches(
            summary.state,
            summary.direction,
            packet_id,
            summary.channel.as_deref(),
            summary.protocol_version,
        )
    }) else {
        return (None, None);
    };
    // The stored bytes carry the packet-id VarInt; schemas describe the body.
    let body = mineburp_protocol::decode_var_i32(&window.bytes)
        .ok()
        .flatten()
        .and_then(|(_, prefix)| window.bytes.get(prefix..))
        .unwrap_or_default();
    match decode_schema(schema, body, DecodeContext::default()) {
        Ok(fields) => (Some(fields), None),
        Err(error) => (None, Some(format!("schema `{}`: {error}", schema.name))),
    }
}

/// Pages through a stored packet's payload so the hex view can render a large
/// packet a window at a time.
#[tauri::command]
pub async fn packet_bytes(
    state: State<'_, DesktopState>,
    id: i64,
    offset: usize,
    limit: usize,
) -> CommandResult<Option<ByteWindow>> {
    let store = current_project(&state)?;
    let limit = limit.clamp(1, MAX_WINDOW_BYTES);
    tauri::async_runtime::spawn_blocking(move || {
        Ok::<_, mineburp_project::ProjectError>(store.packet_window(id, offset, limit)?.map(
            |window| ByteWindow {
                offset: window.offset,
                total: window.total_bytes,
                base64: STANDARD.encode(&window.bytes),
            },
        ))
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

/// Decodes an arbitrary logical frame on demand — used by the Repeater, which
/// composes frames that were never captured.
#[tauri::command]
pub fn inspect_bytes(
    logical_base64: String,
    protocol_state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
) -> CommandResult<PacketInsight> {
    let bytes = STANDARD
        .decode(logical_base64)
        .map_err(|error| error.to_string())?;
    Ok(inspect_logical(
        protocol_state,
        direction,
        &bytes,
        protocol_version,
    ))
}

#[tauri::command]
pub fn proxy_sessions(state: State<'_, DesktopState>) -> Vec<ConnectionSnapshot> {
    state.proxy.sessions()
}

#[tauri::command]
pub async fn intercept_rules_set(
    state: State<'_, DesktopState>,
    rules: Vec<InterceptRule>,
) -> CommandResult<()> {
    state
        .proxy
        .set_intercept_rules(rules.clone())
        .map_err(|error| error.to_string())?;
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.save_intercept_rules(&rules))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn intercept_rules_get(
    state: State<'_, DesktopState>,
) -> CommandResult<Vec<InterceptRule>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.load_intercept_rules())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum HeldResolution {
    Forward,
    Drop,
    ReplaceBase64(String),
}

#[tauri::command]
pub fn held_resolve(
    state: State<'_, DesktopState>,
    id: Uuid,
    resolution: HeldResolution,
) -> CommandResult<()> {
    let resolution = match resolution {
        HeldResolution::Forward => HeldPacketDecision::Forward,
        HeldResolution::Drop => HeldPacketDecision::Drop,
        HeldResolution::ReplaceBase64(value) => HeldPacketDecision::Replace(Bytes::from(
            STANDARD.decode(value).map_err(|error| error.to_string())?,
        )),
    };
    state
        .proxy
        .resolve_held(id, resolution)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn repeater_send(
    state: State<'_, DesktopState>,
    connection_id: Uuid,
    direction: Direction,
    logical_base64: String,
) -> CommandResult<()> {
    let bytes = STANDARD
        .decode(logical_base64)
        .map_err(|error| error.to_string())?;
    state
        .proxy
        .repeater_send(connection_id, direction, Bytes::from(bytes))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn repeater_tabs(state: State<'_, DesktopState>) -> CommandResult<Vec<RepeaterTab>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.load_repeater_tabs())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn repeater_tab_save(
    state: State<'_, DesktopState>,
    tab: RepeaterTab,
) -> CommandResult<()> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.save_repeater_tab(&tab))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn repeater_tab_delete(state: State<'_, DesktopState>, id: Uuid) -> CommandResult<()> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.delete_repeater_tab(id))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn protocol_versions() -> Vec<ProtocolVersion> {
    PacketRegistry::bundled()
        .supported_protocols()
        .into_iter()
        .cloned()
        .collect()
}

#[tauri::command]
pub async fn schema_validate(
    state: State<'_, DesktopState>,
    schema_json: String,
) -> CommandResult<SchemaPack> {
    let pack: SchemaPack = serde_json::from_str(&schema_json).map_err(|error| error.to_string())?;
    pack.validate().map_err(|error| error.to_string())?;
    let store = current_project(&state)?;
    let saved_pack = pack.clone();
    let packs = tauri::async_runtime::spawn_blocking(move || {
        store.save_schema_pack(&saved_pack)?;
        store.load_schema_packs()
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error: mineburp_project::ProjectError| error.to_string())?;
    state
        .proxy
        .set_schema_packs(packs)
        .map_err(|error| error.to_string())?;
    Ok(pack)
}

#[tauri::command]
pub async fn launcher_instances(
    state: State<'_, DesktopState>,
) -> CommandResult<Vec<InstanceDescriptor>> {
    Ok(state
        .launchers
        .discover_all()
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect())
}

#[tauri::command]
pub async fn launcher_launch(
    state: State<'_, DesktopState>,
    request: LaunchRequest,
) -> CommandResult<LaunchOutcome> {
    state
        .launchers
        .launch(&request)
        .await
        .map_err(|error| error.to_string())
}

#[derive(Debug, Serialize)]
pub struct ClientAssistView {
    endpoint: String,
    connected_agents: usize,
    ready_sessions: usize,
    agent_path: PathBuf,
    config_path: PathBuf,
    jvm_argument: String,
    direct_oauth_available: bool,
}

#[tauri::command]
pub async fn client_assist_status(
    state: State<'_, DesktopState>,
) -> CommandResult<ClientAssistView> {
    let status = state.client_assist.status().await;
    Ok(ClientAssistView {
        endpoint: status.endpoint,
        connected_agents: status.connected_agents,
        ready_sessions: status.ready_sessions,
        agent_path: state.agent_path.clone(),
        config_path: state.agent_config_path.clone(),
        jvm_argument: state.client_assist_jvm_argument(),
        direct_oauth_available: microsoft_client_id().is_some(),
    })
}

#[tauri::command]
pub async fn launcher_client_assist_configure(
    state: State<'_, DesktopState>,
    instance: InstanceDescriptor,
    enabled: bool,
) -> CommandResult<AgentSetupOutcome> {
    state
        .launchers
        .configure_client_assist(&instance, &state.client_assist_jvm_argument(), enabled)
        .await
        .map_err(|error| error.to_string())
}

#[derive(Debug, Serialize)]
pub struct AuthStart {
    url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionView {
    profile: MinecraftProfile,
    expires_at_epoch_seconds: u64,
}

impl From<&MinecraftSession> for AuthSessionView {
    fn from(session: &MinecraftSession) -> Self {
        Self {
            profile: session.profile.clone(),
            expires_at_epoch_seconds: session.expires_at_epoch_seconds,
        }
    }
}

#[tauri::command]
pub fn auth_begin(state: State<'_, DesktopState>) -> CommandResult<AuthStart> {
    let client_id = microsoft_client_id().ok_or(
        "direct Microsoft sign-in is not bundled; client assistance uses the account already signed into your launcher",
    )?;
    let redirect_uri = Url::parse(AUTH_CALLBACK_URL).map_err(|error| error.to_string())?;
    let client = AuthClient::new(AuthConfig {
        client_id: client_id.to_owned(),
        redirect_uri,
    });
    let mut request = client
        .authorization_request()
        .map_err(|error| error.to_string())?;
    let verifier = request
        .verifier
        .take()
        .ok_or("authorization verifier was not generated")?;
    *state.pending_auth.write() = Some(PendingAuth {
        client,
        verifier,
        state: request.state.clone(),
    });
    Ok(AuthStart {
        url: request.url.to_string(),
    })
}

fn microsoft_client_id() -> Option<&'static str> {
    option_env!("MINEBURP_MICROSOFT_CLIENT_ID").filter(|value| !value.trim().is_empty())
}

#[tauri::command]
pub async fn auth_complete(
    state: State<'_, DesktopState>,
    callback_url: String,
) -> CommandResult<AuthSessionView> {
    let (code, returned_state) = parse_auth_callback(&callback_url)?;
    let pending = state
        .pending_auth
        .write()
        .take()
        .ok_or("no sign-in is pending")?;
    if pending.state != returned_state {
        return Err("OAuth state did not match".into());
    }
    let session = pending
        .client
        .exchange_code(&code, &pending.verifier)
        .await
        .map_err(|error| error.to_string())?;
    let account = AuthenticatedAccount {
        client: pending.client,
        session,
    };
    let view = AuthSessionView::from(&account.session);
    state
        .proxy
        .set_session_join_provider(Some(std::sync::Arc::new(account.clone())));
    *state.auth_session.write() = Some(account);
    Ok(view)
}

fn parse_auth_callback(callback_url: &str) -> CommandResult<(String, String)> {
    let callback = Url::parse(callback_url.trim())
        .map_err(|_| "paste the complete callback URL from the browser address bar".to_owned())?;
    if callback.scheme() != "http"
        || callback.host_str() != Some("localhost")
        || callback.port() != Some(53_682)
        || callback.path() != "/callback"
    {
        return Err("the OAuth callback URL did not target MineBurp".into());
    }

    let parameters: std::collections::HashMap<_, _> = callback.query_pairs().into_owned().collect();
    if let Some(error) = parameters.get("error") {
        let description = parameters
            .get("error_description")
            .map_or("Microsoft sign-in was not completed", String::as_str);
        return Err(format!("{error}: {description}"));
    }
    let code = parameters
        .get("code")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or("the callback URL did not contain an authorization code")?;
    let returned_state = parameters
        .get("state")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or("the callback URL did not contain OAuth state")?;
    Ok((code, returned_state))
}

#[tauri::command]
pub fn auth_session(state: State<'_, DesktopState>) -> Option<AuthSessionView> {
    state
        .auth_session
        .read()
        .as_ref()
        .map(|account| AuthSessionView::from(&account.session))
}

#[tauri::command]
pub async fn auth_refresh(state: State<'_, DesktopState>) -> CommandResult<AuthSessionView> {
    let account = state
        .auth_session
        .read()
        .clone()
        .ok_or("no account is signed in")?;
    let session = account
        .client
        .refresh(&account.session.refresh_token)
        .await
        .map_err(|error| error.to_string())?;
    let refreshed = AuthenticatedAccount {
        client: account.client,
        session,
    };
    let view = AuthSessionView::from(&refreshed.session);
    state
        .proxy
        .set_session_join_provider(Some(std::sync::Arc::new(refreshed.clone())));
    *state.auth_session.write() = Some(refreshed);
    Ok(view)
}

#[tauri::command]
pub fn auth_sign_out(state: State<'_, DesktopState>) {
    *state.pending_auth.write() = None;
    *state.auth_session.write() = None;
    state.use_client_assist_provider();
}

fn current_project(state: &State<'_, DesktopState>) -> CommandResult<ProjectStore> {
    state
        .project
        .read()
        .clone()
        .ok_or_else(|| "no project is open".into())
}

#[cfg(test)]
mod tests {
    use super::{PacketFilterInput, parse_auth_callback};

    fn filter_from(json: &str) -> PacketFilterInput {
        serde_json::from_str(json).expect("the webview's filter shape must deserialize")
    }

    #[test]
    fn an_empty_filter_object_is_a_complete_filter() {
        let query = filter_from("{}").into_query().expect("empty filter");
        assert!(query.search.is_none());
        assert!(query.expression.is_none());
        assert!(query.states.is_empty() && query.directions.is_empty());
        // Every list defaulting to empty is what makes "no filter" mean "everything".
        assert_eq!(query.limit, 1, "an unset limit is clamped into range");
    }

    #[test]
    fn search_switches_and_enum_sets_survive_the_boundary() {
        let query = filter_from(
            r#"{
                "search": "  keep_alive  ",
                "searchRegex": true,
                "searchCaseSensitive": true,
                "searchNegate": true,
                "states": ["play", "configuration"],
                "dispositions": ["dropped"],
                "excludeNames": ["chunk"],
                "minSize": 16,
                "limit": 250
            }"#,
        )
        .into_query()
        .expect("filter");
        let search = query.search.expect("a search term");
        assert_eq!(
            search.text, "keep_alive",
            "surrounding space is not part of the term"
        );
        assert!(search.regex && search.case_sensitive && search.negate);
        assert_eq!(query.states.len(), 2);
        assert_eq!(query.dispositions.len(), 1);
        assert_eq!(query.exclude_names, vec!["chunk".to_owned()]);
        assert_eq!(query.min_size, Some(16));
        assert_eq!(query.limit, 250);
    }

    #[test]
    fn a_blank_search_or_expression_is_dropped_rather_than_matched() {
        let query = filter_from(r#"{"search": "   ", "expression": "  "}"#)
            .into_query()
            .expect("filter");
        assert!(query.search.is_none());
        assert!(query.expression.is_none());
    }

    #[test]
    fn an_unparseable_expression_is_reported_to_the_operator() {
        let error = filter_from(r#"{"expression": "state !! play"}"#)
            .into_query()
            .expect_err("an unknown operator must be rejected");
        assert!(
            error.contains("operator"),
            "the message should name the problem, got `{error}`"
        );
    }

    #[test]
    fn a_payload_search_carries_its_mode_across_the_boundary() {
        let query = filter_from(
            r#"{"content": " de ad be ef ", "contentMode": "hex", "contentNegate": true}"#,
        )
        .into_query()
        .expect("filter");
        let content = query.content.expect("a content search");
        assert_eq!(content.text, "de ad be ef");
        assert!(content.negate);
        assert!(matches!(content.mode, mineburp_project::ContentMode::Hex));
    }

    #[test]
    fn a_blank_payload_search_is_dropped() {
        let query = filter_from(r#"{"content": "  ", "contentMode": "regex"}"#)
            .into_query()
            .expect("filter");
        assert!(
            query.content.is_none(),
            "a blank term must not scan payloads"
        );
    }

    #[test]
    fn a_valid_expression_reaches_the_query() {
        let query = filter_from(r#"{"expression": "state == play && size > 256"}"#)
            .into_query()
            .expect("filter");
        assert!(query.expression.is_some());
    }

    #[test]
    fn parses_and_decodes_auth_callback() {
        let (code, state) = parse_auth_callback(
            "http://localhost:53682/callback?code=space%2Bplus&state=expected-state",
        )
        .expect("valid callback");

        assert_eq!(code, "space+plus");
        assert_eq!(state, "expected-state");
    }

    #[test]
    fn rejects_callback_for_another_listener() {
        let error = parse_auth_callback(
            "http://localhost:1234/callback?code=secret&state=unexpected-state",
        )
        .expect_err("wrong callback port must fail");

        assert_eq!(error, "the OAuth callback URL did not target MineBurp");
    }
}
