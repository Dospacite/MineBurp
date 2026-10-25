#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri command state is supplied by its by-value State extractor"
)]

use std::{io::Write as _, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mineburp_auth::{AuthClient, AuthConfig, MinecraftProfile, MinecraftSession};
use mineburp_capture::{CaptureCapabilities, CaptureStats, ImportOptions, ImportSummary};
use mineburp_core::{
    ConnectionSnapshot, Direction, Disposition, FilterExpression, FilterField, PacketEdit,
    PacketSummary, ProtocolState, RepeaterTab, ReplacementRule, TrafficSource,
};
use mineburp_launcher::{AgentSetupOutcome, InstanceDescriptor, LaunchOutcome, LaunchRequest};
use mineburp_project::{
    CompactSummary, ContentMode, ContentQuery, ContentScope, DeleteSummary, PacketAnnotation,
    PacketQuery, ProjectInfo, ProjectOptions, ProjectStore, SavedFilter, SearchTerm, StatsOptions,
    TrafficStats,
};
use mineburp_protocol::{
    DecodeContext, FieldKind, PacketInsight, PacketLayout, PacketRegistry, ProtocolVersion,
    SchemaPack, apply_edits, decode_schema, encode_field, inspect_logical, layout_logical,
};
use mineburp_proxy::{InterceptDecision, InterceptSettings, NetworkConditions};
use serde::{Deserialize, Serialize};
use tauri::State;
use url::Url;
use uuid::Uuid;

use crate::{
    capture_project::persist,
    export::{PcapExportSummary, write_pcapng},
    paths::{PathPurpose, validate_path},
    state::{AuthenticatedAccount, DesktopState, PendingAuth},
};

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

/// Probing capture runs `dumpcap -D`, which can take seconds; a synchronous
/// command would run it on the main thread and freeze the window.
#[tauri::command]
pub async fn app_capabilities(state: State<'_, DesktopState>) -> CommandResult<AppCapabilities> {
    let capture = state.capture.clone();
    let side_capture = tauri::async_runtime::spawn_blocking(move || capture.capabilities())
        .await
        .map_err(|error| error.to_string())?;
    let registry = PacketRegistry::bundled();
    let protocols = registry.supported_protocols();
    Ok(AppCapabilities {
        side_capture,
        project_encryption: true,
        protocol_min: protocols.first().map_or(4, |entry| entry.protocol),
        protocol_max: protocols.last().map_or(4, |entry| entry.protocol),
    })
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
    let path = validate_path(&path, PathPurpose::NewProject, &[])?;
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
    install_project(&state, store).await
}

#[tauri::command]
pub async fn project_open(
    state: State<'_, DesktopState>,
    path: PathBuf,
    passphrase: Option<String>,
    read_only: Option<bool>,
) -> CommandResult<ProjectView> {
    let read_only = read_only.unwrap_or(false);
    let path = validate_path(&path, PathPurpose::ExistingProject, &[])?;
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
    install_project(&state, store).await
}

/// Copies the open project — usually the temporary session — to `path` and
/// switches to the copy, so everything captured so far is kept.
#[tauri::command]
pub async fn project_save_as(
    state: State<'_, DesktopState>,
    path: PathBuf,
    name: String,
    passphrase: Option<String>,
) -> CommandResult<ProjectView> {
    let source = current_project(&state)?;
    let path = validate_path(&path, PathPurpose::NewProject, &[])?;
    let store = tauri::async_runtime::spawn_blocking(move || {
        source.save_as(
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
    install_project(&state, store).await
}

/// Loads a project's schema packs and rules into the proxy and makes it current.
async fn install_project(state: &DesktopState, store: ProjectStore) -> CommandResult<ProjectView> {
    let info = store.info().clone();
    let asset_store = store.clone();
    let (packs, replacements) = tauri::async_runtime::spawn_blocking(move || {
        Ok::<_, mineburp_project::ProjectError>((
            asset_store.load_schema_packs()?,
            asset_store.load_replacement_rules()?,
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
        .set_replacement_rules(replacements)
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
#[allow(clippy::struct_excessive_bools)]
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
    /// The operator's filter expression, in the same language replacement rules use.
    expression: Option<String>,
    /// A search through the payload bytes rather than the row's metadata.
    content: Option<String>,
    content_mode: ContentSearchMode,
    content_scope: ContentSearchScope,
    content_case_sensitive: bool,
    content_negate: bool,
    before_id: Option<i64>,
    after_id: Option<i64>,
    /// Only bookmarked rows (`true`) or only rows without a bookmark (`false`).
    bookmarked: Option<bool>,
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

/// How much of the payload the term has to account for.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSearchScope {
    #[default]
    Contains,
    Equals,
    Prefix,
    Suffix,
}

impl From<ContentSearchScope> for ContentScope {
    fn from(scope: ContentSearchScope) -> Self {
        match scope {
            ContentSearchScope::Contains => Self::Contains,
            ContentSearchScope::Equals => Self::Equals,
            ContentSearchScope::Prefix => Self::Prefix,
            ContentSearchScope::Suffix => Self::Suffix,
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
                scope: self.content_scope.into(),
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
            bookmarked: self.bookmarked,
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

/// Writes every packet matching `filter` to `path` as a JSON array, newest first.
///
/// Pages through the history by id in the backend: a single history query is
/// capped, and handing the webview the whole capture to serialise would stall it.
/// Returns how many packets were written.
#[tauri::command]
pub async fn packets_export(
    state: State<'_, DesktopState>,
    path: PathBuf,
    filter: PacketFilterInput,
) -> CommandResult<usize> {
    const EXPORT_PAGE: usize = 500;
    let store = current_project(&state)?;
    let path = validate_path(&path, PathPurpose::ExportJson, &[&store.info().path])?;
    let mut query = filter.into_query()?;
    query.limit = EXPORT_PAGE;
    query.offset = 0;
    query.after_id = None;
    tauri::async_runtime::spawn_blocking(move || -> CommandResult<usize> {
        let file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
        let mut out = std::io::BufWriter::new(file);
        let mut written = 0usize;
        out.write_all(b"[").map_err(|error| error.to_string())?;
        loop {
            let page = store
                .query_packets_filtered(&query)
                .map_err(|error| error.to_string())?;
            for packet in &page {
                if written > 0 {
                    out.write_all(b",").map_err(|error| error.to_string())?;
                }
                out.write_all(b"\n  ").map_err(|error| error.to_string())?;
                serde_json::to_writer(&mut out, packet).map_err(|error| error.to_string())?;
                written += 1;
            }
            match page.last() {
                Some(last) if page.len() == EXPORT_PAGE => query.before_id = Some(last.id),
                _ => break,
            }
        }
        out.write_all(b"\n]\n").map_err(|error| error.to_string())?;
        out.flush().map_err(|error| error.to_string())?;
        Ok(written)
    })
    .await
    .map_err(|error| error.to_string())?
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
            let insight = inspect_logical(
                window.summary.state,
                window.summary.direction,
                &window.bytes,
                window.summary.protocol_version,
            );
            let (schema_decoded, schema_error) = decode_with_schema_packs(&packs, &window);
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

/// Runs CPU-bound work on the blocking pool.
///
/// A synchronous Tauri command runs on the main thread, so decoding a large
/// frame there froze the whole window for as long as the decode took.
async fn off_main<T: Send + 'static>(
    work: impl FnOnce() -> CommandResult<T> + Send + 'static,
) -> CommandResult<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| error.to_string())?
}

/// Walks a frame into editable field spans — the Repeater's decoded view.
#[tauri::command]
pub async fn packet_layout(
    logical_base64: String,
    protocol_state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
) -> CommandResult<PacketLayout> {
    off_main(move || {
        let bytes = STANDARD
            .decode(logical_base64)
            .map_err(|error| error.to_string())?;
        Ok(layout_logical(
            protocol_state,
            direction,
            &bytes,
            protocol_version,
        ))
    })
    .await
}

/// Re-encodes one decoded field and splices it back into the frame.
///
/// The splice happens here rather than in the webview so that the wire encoding
/// of every field kind — and the length prefix a resized field has to rewrite —
/// lives in one place next to the decoder that produced the span.
#[tauri::command]
pub async fn field_edit(
    logical_base64: String,
    offset: usize,
    length: usize,
    kind: FieldKind,
    value: serde_json::Value,
) -> CommandResult<String> {
    off_main(move || splice_field(&logical_base64, offset, length, kind, &value)).await
}

fn splice_field(
    logical_base64: &str,
    offset: usize,
    length: usize,
    kind: FieldKind,
    value: &serde_json::Value,
) -> CommandResult<String> {
    let bytes = STANDARD
        .decode(logical_base64)
        .map_err(|error| error.to_string())?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or("field span is outside the frame")?;
    let encoded = encode_field(kind, value)?;
    let mut edited = Vec::with_capacity(bytes.len() - length + encoded.len());
    edited.extend_from_slice(&bytes[..offset]);
    edited.extend_from_slice(&encoded);
    edited.extend_from_slice(&bytes[end..]);
    Ok(STANDARD.encode(&edited))
}

/// Decodes an arbitrary logical frame on demand — used by the Repeater, which
/// composes frames that were never captured.
#[tauri::command]
pub async fn inspect_bytes(
    logical_base64: String,
    protocol_state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
) -> CommandResult<PacketInsight> {
    off_main(move || {
        let bytes = STANDARD
            .decode(logical_base64)
            .map_err(|error| error.to_string())?;
        Ok(inspect_logical(
            protocol_state,
            direction,
            &bytes,
            protocol_version,
        ))
    })
    .await
}

#[tauri::command]
pub fn proxy_sessions(state: State<'_, DesktopState>) -> Vec<ConnectionSnapshot> {
    state.proxy.sessions()
}

#[tauri::command]
pub fn intercept_settings_get(state: State<'_, DesktopState>) -> InterceptSettings {
    state.proxy.intercept_settings()
}

/// Changes what Intercept holds; turning it off forwards everything held.
#[tauri::command]
pub fn intercept_settings_set(
    state: State<'_, DesktopState>,
    settings: InterceptSettings,
) -> CommandResult<InterceptSettings> {
    state
        .proxy
        .set_intercept_settings(settings)
        .map_err(|error| error.to_string())?;
    Ok(state.proxy.intercept_settings())
}

/// A frame Intercept is holding, as the webview shows it.
#[derive(Debug, Serialize)]
pub struct InterceptedView {
    id: u64,
    summary: PacketSummary,
    target: String,
    held_at_micros: i64,
    /// When the frame is forwarded automatically, if Intercept has a deadline.
    deadline_micros: Option<i64>,
    bytes_base64: String,
}

#[tauri::command]
pub fn intercept_pending(state: State<'_, DesktopState>) -> Vec<InterceptedView> {
    state
        .proxy
        .intercepted()
        .into_iter()
        .map(|held| InterceptedView {
            id: held.id,
            summary: held.summary,
            target: held.target,
            held_at_micros: held.held_at_micros,
            deadline_micros: held.deadline_micros,
            bytes_base64: STANDARD.encode(&held.logical_bytes),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptAction {
    Forward,
    Drop,
}

/// Releases one held frame. `logical_base64`, when given, replaces the frame.
#[tauri::command]
pub fn intercept_resolve(
    state: State<'_, DesktopState>,
    id: u64,
    action: InterceptAction,
    logical_base64: Option<String>,
) -> CommandResult<()> {
    let decision = match (action, logical_base64) {
        (InterceptAction::Drop, _) => InterceptDecision::Drop,
        (InterceptAction::Forward, None) => InterceptDecision::Forward,
        (InterceptAction::Forward, Some(encoded)) => InterceptDecision::Replace(Bytes::from(
            STANDARD
                .decode(encoded)
                .map_err(|error| error.to_string())?,
        )),
    };
    state
        .proxy
        .resolve_intercept(id, decision)
        .map_err(|error| error.to_string())
}

/// Forwards every held frame unchanged and returns how many there were.
#[tauri::command]
pub fn intercept_forward_all(state: State<'_, DesktopState>) -> usize {
    state.proxy.forward_all_intercepted()
}

/// The delay, jitter and bandwidth limit applied to proxied connections.
#[tauri::command]
pub fn network_conditions_get(state: State<'_, DesktopState>) -> NetworkConditions {
    state.proxy.network_conditions()
}

/// Changes network shaping for every proxied connection, open ones included.
#[tauri::command]
pub fn network_conditions_set(
    state: State<'_, DesktopState>,
    conditions: NetworkConditions,
) -> CommandResult<NetworkConditions> {
    state
        .proxy
        .set_network_conditions(conditions)
        .map_err(|error| error.to_string())?;
    Ok(state.proxy.network_conditions())
}

/// The rules that rewrite packets automatically, as the operator ordered them.
#[tauri::command]
pub async fn replacement_rules_set(
    state: State<'_, DesktopState>,
    rules: Vec<ReplacementRule>,
) -> CommandResult<()> {
    state
        .proxy
        .set_replacement_rules(rules.clone())
        .map_err(|error| error.to_string())?;
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.save_replacement_rules(&rules))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn replacement_rules_get(
    state: State<'_, DesktopState>,
) -> CommandResult<Vec<ReplacementRule>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.load_replacement_rules())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// Runs a rule's edits against one frame without sending anything.
///
/// The rules tab uses this to show the operator what a rule does to a real
/// packet before it is ever applied to live traffic.
#[tauri::command]
pub async fn replacement_preview(
    logical_base64: String,
    protocol_state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
    edits: Vec<PacketEdit>,
) -> CommandResult<String> {
    off_main(move || {
        let bytes = STANDARD
            .decode(logical_base64)
            .map_err(|error| error.to_string())?;
        let rewritten = apply_edits(protocol_state, direction, protocol_version, &bytes, &edits)
            .map_err(|error| error.to_string())?;
        Ok(STANDARD.encode(rewritten))
    })
    .await
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
    // The state is checked before the pending sign-in is taken: a stray or
    // forged callback must not cancel the sign-in the operator is completing.
    let pending = take_matching(&state.pending_auth, |pending| {
        pending.state == returned_state
    })?;
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

/// Takes the value out of `slot` only when `matches` accepts it, leaving a
/// non-matching value in place.
fn take_matching<T>(
    slot: &parking_lot::RwLock<Option<T>>,
    matches: impl FnOnce(&T) -> bool,
) -> CommandResult<T> {
    let mut slot = slot.write();
    match slot.as_ref() {
        None => Err("no sign-in is pending".into()),
        Some(current) if !matches(current) => Err("OAuth state did not match".into()),
        Some(_) => slot.take().ok_or_else(|| "no sign-in is pending".into()),
    }
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

/// Stops every history query that is running, e.g. a payload search the
/// operator has replaced with a new filter.
#[tauri::command]
pub fn packets_query_cancel(state: State<'_, DesktopState>) -> CommandResult<()> {
    current_project(&state)?.interrupt_reads();
    Ok(())
}

/// Writes every packet matching `filter` to `path` as pcapng, oldest first,
/// one synthetic TCP stream per connection. See `tools/wireshark/`.
#[tauri::command]
pub async fn packets_export_pcapng(
    state: State<'_, DesktopState>,
    path: PathBuf,
    filter: PacketFilterInput,
) -> CommandResult<PcapExportSummary> {
    let store = current_project(&state)?;
    let path = validate_path(&path, PathPurpose::ExportPcap, &[&store.info().path])?;
    let mut query = filter.into_query()?;
    query.offset = 0;
    tauri::async_runtime::spawn_blocking(move || {
        let file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
        write_pcapng(&store, &query, std::io::BufWriter::new(file))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Reads a pcap or pcapng file into the open project.
///
/// Flows are recognised by server port (`options.serverPorts`, default
/// 25565) because an imported file has no process to attribute them to.
/// Retransmissions are removed and segments reordered exactly as in live
/// capture, then each TCP stream is split into Minecraft packets: one row per
/// packet, with its state, id and name. Encrypted or unsynchronised stream
/// data is kept as labelled raw rows.
#[tauri::command]
pub async fn capture_import(
    state: State<'_, DesktopState>,
    path: PathBuf,
    options: Option<ImportOptions>,
) -> CommandResult<ImportSummary> {
    const BATCH: usize = 512;
    let store = current_project(&state)?;
    if store.is_read_only() {
        return Err("the open project is read-only".into());
    }
    let path = validate_path(&path, PathPurpose::ImportCapture, &[])?;
    let options = options.unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || {
        let file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
        let mut pending = Vec::with_capacity(BATCH);
        // One connection row per connection per batch: the snapshot each row
        // carries is cumulative, so only the latest matters.
        let mut touched: std::collections::HashMap<Uuid, ConnectionSnapshot> =
            std::collections::HashMap::new();
        let flush = |pending: &mut Vec<_>,
                     touched: &mut std::collections::HashMap<Uuid, ConnectionSnapshot>|
         -> Result<(), String> {
            let result =
                persist(&store, touched.values(), pending).map_err(|error| error.to_string());
            pending.clear();
            touched.clear();
            result
        };
        let mut summary =
            mineburp_capture::import_capture(std::io::BufReader::new(file), &options, |row| {
                touched.insert(row.connection.id, row.connection);
                pending.push(row.detail);
                if pending.len() >= BATCH {
                    flush(&mut pending, &mut touched)?;
                }
                Ok(())
            })
            .map_err(|error| error.to_string())?;
        flush(&mut pending, &mut touched)?;
        if summary.frames_imported == 0 && summary.error.is_none() {
            summary.error = Some(if options.server_ports.is_empty() {
                "the capture contains no TCP or UDP payloads".into()
            } else {
                format!(
                    "no traffic on server port(s) {:?}; set the ports the server used",
                    options.server_ports
                )
            });
        }
        Ok(summary)
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Deletes every packet matching `filter` (its `limit` is ignored).
#[tauri::command]
pub async fn packets_delete(
    state: State<'_, DesktopState>,
    filter: PacketFilterInput,
    prune_connections: Option<bool>,
) -> CommandResult<DeleteSummary> {
    let store = current_project(&state)?;
    let query = filter.into_query()?;
    let prune = prune_connections.unwrap_or(true);
    tauri::async_runtime::spawn_blocking(move || store.delete_packets(&query, prune))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// Returns space freed by deleted history to the filesystem.
#[tauri::command]
pub async fn project_compact(state: State<'_, DesktopState>) -> CommandResult<CompactSummary> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.compact())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// Counts, a timeline, rankings, and a size histogram for `filter`.
#[tauri::command]
pub async fn traffic_stats(
    state: State<'_, DesktopState>,
    filter: PacketFilterInput,
    options: Option<StatsOptions>,
) -> CommandResult<TrafficStats> {
    let store = current_project(&state)?;
    let query = filter.into_query()?;
    let options = options.unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || store.traffic_stats(&query, options))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// The annotations of the given packets — the rows on screen.
#[tauri::command]
pub async fn packet_annotations_get(
    state: State<'_, DesktopState>,
    ids: Vec<i64>,
) -> CommandResult<Vec<PacketAnnotation>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.annotations(&ids))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// Every annotation in the project, newest packet first.
#[tauri::command]
pub async fn packet_annotations_list(
    state: State<'_, DesktopState>,
    limit: Option<usize>,
) -> CommandResult<Vec<PacketAnnotation>> {
    let store = current_project(&state)?;
    let limit = limit.unwrap_or(1_000).clamp(1, 10_000);
    tauri::async_runtime::spawn_blocking(move || store.list_annotations(limit))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// Sets one packet's bookmark, colour, and note; returns `null` when the
/// update cleared all three.
#[tauri::command]
pub async fn packet_annotation_set(
    state: State<'_, DesktopState>,
    packet_id: i64,
    bookmarked: bool,
    color: Option<String>,
    note: Option<String>,
) -> CommandResult<Option<PacketAnnotation>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        store.set_annotation(packet_id, bookmarked, color, note)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn saved_filters_list(state: State<'_, DesktopState>) -> CommandResult<Vec<SavedFilter>> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.load_saved_filters())
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

/// A saved filter as the webview sends it: an id is assigned when absent.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedFilterInput {
    id: Option<Uuid>,
    name: String,
    filter: serde_json::Value,
}

/// Creates or updates a saved filter. The filter must be one the history
/// accepts, so a saved filter can always be applied.
#[tauri::command]
pub async fn saved_filter_save(
    state: State<'_, DesktopState>,
    filter: SavedFilterInput,
) -> CommandResult<SavedFilter> {
    let store = current_project(&state)?;
    serde_json::from_value::<PacketFilterInput>(filter.filter.clone())
        .map_err(|error| format!("the saved filter is not a history filter: {error}"))?
        .into_query()?;
    let saved = SavedFilter {
        id: filter.id.unwrap_or_else(Uuid::new_v4),
        name: filter.name,
        filter: filter.filter,
        created_at_micros: 0,
        updated_at_micros: 0,
    };
    tauri::async_runtime::spawn_blocking(move || store.save_filter(&saved))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn saved_filter_delete(state: State<'_, DesktopState>, id: Uuid) -> CommandResult<bool> {
    let store = current_project(&state)?;
    tauri::async_runtime::spawn_blocking(move || store.delete_saved_filter(id))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
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
    use super::{PacketFilterInput, parse_auth_callback, take_matching};

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
        assert!(
            matches!(content.scope, mineburp_project::ContentScope::Contains),
            "an unstated scope stays the substring search it has always been"
        );

        let scoped =
            filter_from(r#"{"content": "0c", "contentMode": "hex", "contentScope": "equals"}"#)
                .into_query()
                .expect("filter");
        assert!(matches!(
            scoped.content.expect("a content search").scope,
            mineburp_project::ContentScope::Equals
        ));
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
    fn a_mismatched_callback_does_not_cancel_the_pending_sign_in() {
        let slot = parking_lot::RwLock::new(Some("expected".to_owned()));
        assert!(take_matching(&slot, |state| state == "forged").is_err());
        assert!(slot.read().is_some(), "the real sign-in is still pending");
        assert_eq!(
            take_matching(&slot, |state| state == "expected").unwrap(),
            "expected"
        );
        assert!(take_matching(&slot, |_| true).is_err(), "taken once");
    }

    #[test]
    fn the_bookmark_filter_reaches_the_query() {
        let query = filter_from(r#"{"bookmarked": true}"#)
            .into_query()
            .expect("filter");
        assert_eq!(query.bookmarked, Some(true));
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
