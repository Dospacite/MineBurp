mod capture_project;
mod commands;
#[cfg(all(feature = "desktop-runtime", unix))]
mod mcp;
mod setup;
mod state;

#[cfg(feature = "desktop-runtime")]
use std::time::Duration;

#[cfg(feature = "desktop-runtime")]
use tauri::{Emitter, Manager};

/// How often live traffic is pushed to the webview.
///
/// One IPC message per captured packet saturates the webview long before the
/// capture backend breaks a sweat, so events are coalesced onto this cadence.
/// Roughly seven updates a second still reads as live to an operator.
#[cfg(feature = "desktop-runtime")]
const LIVE_FLUSH: Duration = Duration::from_millis(140);

#[cfg(feature = "desktop-runtime")]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(setup)
        .invoke_handler(tauri::generate_handler![
            commands::replacement_rule_preview,
            commands::payload_generate,
            commands::decoder_transform,
            commands::workbench_document_get,
            commands::workbench_document_save,
            commands::channel_stats,
            commands::packet_field_values,
            commands::intruder_plan,
            commands::sequencer_analyze,
            commands::app_capabilities,
            commands::setup_check,
            commands::decrypt_mode_status,
            commands::decrypt_mode_set,
            commands::capture_start,
            commands::capture_stop,
            commands::capture_stats,
            commands::project_create,
            commands::project_open,
            commands::project_save_as,
            commands::project_current,
            commands::lab_listener_active,
            commands::lab_listener_stop,
            commands::lab_listener_start,
            commands::project_scope_set,
            commands::project_scope_get,
            commands::project_recovered_save_as,
            commands::project_recovered_delete,
            commands::project_recovered_list,
            commands::project_checkpoint,
            commands::connections_query,
            commands::packets_query,
            commands::packets_export,
            commands::packets_export_pcapng,
            commands::packets_delete,
            commands::packets_query_cancel,
            commands::capture_import,
            commands::project_compact,
            commands::traffic_stats,
            commands::packet_annotations_get,
            commands::packet_annotations_list,
            commands::packet_annotation_set,
            commands::saved_filters_list,
            commands::saved_filter_save,
            commands::saved_filter_delete,
            commands::filter_vocabulary,
            commands::filter_validate,
            commands::packet_detail,
            commands::packet_bytes,
            commands::inspect_bytes,
            commands::packet_layout,
            commands::packet_layout_stored,
            commands::field_edit,
            commands::proxy_sessions,
            commands::intercept_settings_get,
            commands::intercept_settings_set,
            commands::intercept_pending,
            commands::intercept_resolve,
            commands::intercept_forward_all,
            commands::network_conditions_get,
            commands::network_conditions_set,
            commands::replacement_rules_set,
            commands::replacement_rules_get,
            commands::replacement_preview,
            commands::repeater_send,
            commands::repeater_tabs,
            commands::repeater_tab_save,
            commands::repeater_tab_delete,
            commands::protocol_versions,
            commands::schema_validate,
            commands::launcher_instances,
            commands::launcher_launch,
            commands::client_assist_status,
            commands::launcher_client_assist_configure,
            commands::auth_begin,
            commands::auth_complete,
            commands::auth_session,
            commands::auth_refresh,
            commands::auth_sign_out,
        ])
        .build(tauri::generate_context!())
        .expect("MineBurp desktop runtime failed");
    app.run(|handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            // The scratch project is session scratch space, not a saved
            // assessment; leaving it behind would quietly fill the temp
            // directory with abandoned captures.
            #[cfg(unix)]
            mcp::stop();
            let state = handle.state::<state::DesktopState>();
            // Windows refuses to delete a file any handle still holds, so the
            // capture writer and live sessions stop before the project closes.
            let capture = state.capture.clone();
            let _ = tauri::async_runtime::block_on(async move {
                tokio::time::timeout(std::time::Duration::from_secs(2), capture.stop()).await
            });
            for session in state.proxy.sessions() {
                let _ = state.proxy.stop_session(session.id);
            }
            state.discard_temporary_project();
        }
    });
}

/// Builds the desktop state, opens the scratch project, and starts the event
/// pumps.
#[cfg(feature = "desktop-runtime")]
fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let bundled_agent = app
        .path()
        .resource_dir()?
        .join("resources/mineburp-agent.jar");
    let development_agent = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../agent/build/mineburp-agent.jar");
    let agent_path = if bundled_agent.is_file() {
        bundled_agent
    } else {
        development_agent
    };
    let agent_path = if agent_path.is_file() {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let bytes = std::fs::read(&agent_path)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let directory = app.path().app_data_dir()?.join("agent");
        std::fs::create_dir_all(&directory)?;
        let destination = directory.join(format!("mineburp-agent-{}.jar", &digest[..16]));
        if !destination.is_file() || std::fs::read(&destination)? != bytes {
            let temporary = directory.join(format!(".agent-{}.tmp", uuid::Uuid::new_v4()));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            }
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, &destination)?;
        }
        destination
    } else {
        agent_path
    };
    let agent_config_path = app
        .path()
        .app_config_dir()?
        .join("client-assistance.properties");
    let state = state::DesktopState::new(agent_path, agent_config_path)?;
    let persistence_proxy = state.proxy.clone();
    tauri::async_runtime::spawn(async move {
        // `setup` is synchronous, so `ProxyService::new` cannot see Tauri's
        // Tokio runtime. Start the low-volume batch flusher from inside it.
        let _ = persistence_proxy.start_persistence_flusher();
    });
    let handle = app.handle().clone();
    let report = error_reporter(handle.clone());
    // A scratch project is opened before capture starts so nothing that
    // arrives in the first seconds has to live in memory or be dropped.
    let sessions_dir = app.path().app_data_dir()?.join("sessions");
    state::remove_abandoned_sessions(&sessions_dir);
    if let Err(error) = state.open_temporary_project(&sessions_dir) {
        report(
            "project",
            format!("MineBurp could not open a temporary project: {error}"),
        );
    }
    let receiver = state.proxy.subscribe();
    let capture_receiver = state.capture.subscribe();
    let capture_project = capture_project::spawn_capture_project_writer(
        state.project.clone(),
        state.proxy.clone(),
        report.clone(),
    );
    let capture_handle = handle.clone();
    #[cfg(unix)]
    let (mcp_handle, mcp_report) = (handle.clone(), report.clone());
    tauri::async_runtime::spawn(pump_proxy_events(handle, receiver));
    tauri::async_runtime::spawn(pump_capture(
        capture_handle,
        capture_receiver,
        capture_project,
        report,
    ));
    app.manage(state);
    // After `manage`: the MCP host looks the state up on every call.
    #[cfg(unix)]
    mcp::start(&mcp_handle, move |message| mcp_report("mcp", message));
    Ok(())
}

/// Forwards proxy events, collapsing the high-volume per-packet event.
///
/// The history reads packet rows from the project, so shipping one IPC message
/// per packet only competed with the traffic the operator is trying to read. A
/// periodic count is enough for the UI to know it should pull the tail.
#[cfg(feature = "desktop-runtime")]
async fn pump_proxy_events(
    handle: tauri::AppHandle,
    mut events: tokio::sync::broadcast::Receiver<mineburp_proxy::ProxyEvent>,
) {
    use tokio::sync::broadcast::error::RecvError;

    let mut appended = 0_u64;
    let mut ticker = tokio::time::interval(LIVE_FLUSH);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            next = events.recv() => match next {
                Ok(mineburp_proxy::ProxyEvent::Packet(_)) => appended += 1,
                Ok(event) => {
                    let _ = handle.emit("proxy-event", event);
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            _ = ticker.tick() => {
                if appended > 0 {
                    let _ = handle.emit("proxy-packets-appended", appended);
                    appended = 0;
                }
            }
        }
    }
}

/// Hands captured frames to the project writer and tells the UI to pull.
///
/// Frames used to be mirrored into a bounded in-memory ring so a live table
/// could show them, which meant a busy capture aged rows out before anyone read
/// them. Everything now goes to the project, so this only has to keep the writer
/// fed and publish a coalesced "there are new rows" signal.
#[cfg(feature = "desktop-runtime")]
async fn pump_capture(
    handle: tauri::AppHandle,
    mut frames: tokio::sync::broadcast::Receiver<mineburp_capture::SideChannelFrame>,
    writer: tokio::sync::mpsc::Sender<mineburp_capture::SideChannelFrame>,
    report: capture_project::ErrorReporter,
) {
    use tokio::sync::broadcast::error::RecvError;

    let mut appended = 0_u64;
    let mut ticker = tokio::time::interval(LIVE_FLUSH);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            next = frames.recv() => match next {
                // Awaiting the writer applies real backpressure instead of
                // discarding the frame: the writer commits in batches, so a
                // full queue drains in milliseconds.
                Ok(frame) => match writer.send(frame).await {
                    Ok(()) => appended += 1,
                    Err(_) => break,
                },
                Err(RecvError::Lagged(missed)) => {
                    report(
                        "capture",
                        format!("{missed} captured frame(s) were lost because saving fell behind"),
                    );
                }
                Err(RecvError::Closed) => break,
            },
            _ = ticker.tick() => {
                if appended > 0 {
                    let _ = handle.emit("capture-packets-appended", appended);
                    appended = 0;
                }
            }
        }
    }
}

/// A failure the operator should hear about, as the webview receives it.
#[cfg(feature = "desktop-runtime")]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendError {
    source: &'static str,
    message: String,
    /// How many identical reports this one stands for.
    repeated: u64,
}

/// Emits `backend-error` events, collapsing a repeated failure.
///
/// A broken writer fails once per batch, several times a second; one event per
/// failure would bury the UI. The same message is reported at most once per
/// [`ERROR_COALESCE`], with a count of how many it stands for.
#[cfg(feature = "desktop-runtime")]
fn error_reporter(handle: tauri::AppHandle) -> capture_project::ErrorReporter {
    use std::time::Instant;

    const ERROR_COALESCE: Duration = Duration::from_secs(2);
    let last: parking_lot::Mutex<Option<(String, Instant, u64)>> = parking_lot::Mutex::new(None);
    std::sync::Arc::new(move |source, message: String| {
        eprintln!("MineBurp {source} error: {message}");
        let mut last = last.lock();
        let now = Instant::now();
        if let Some((previous, at, suppressed)) = last.as_mut()
            && *previous == message
            && now.duration_since(*at) < ERROR_COALESCE
        {
            *suppressed += 1;
            return;
        }
        let repeated = last
            .as_ref()
            .filter(|(previous, _, _)| *previous == message)
            .map_or(1, |(_, _, suppressed)| suppressed + 1);
        *last = Some((message.clone(), now, 0));
        let _ = handle.emit(
            "backend-error",
            BackendError {
                source,
                message,
                repeated,
            },
        );
    })
}

#[cfg(not(feature = "desktop-runtime"))]
pub fn run() {
    panic!("MineBurp was built without the desktop-runtime feature");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    /// The command names in `generate_handler!`.
    fn registered() -> BTreeSet<String> {
        let source = include_str!("lib.rs");
        let start = source.find("generate_handler![").expect("handler list");
        let end = start + source[start..].find("])").expect("end of handler list");
        source[start..end]
            .split("commands::")
            .skip(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect()
            })
            .collect()
    }

    /// A command that is registered but has no permission is refused at
    /// runtime, which no compile step would notice.
    #[test]
    fn every_command_has_a_permission_and_a_grant() {
        let commands = registered();
        let build = include_str!("../build.rs");
        let list_start = build.find("const COMMANDS").expect("command list");
        let list_end = list_start + build[list_start..].find("];").expect("end of command list");
        let manifest: BTreeSet<String> = build[list_start..list_end]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect();
        assert_eq!(
            manifest, commands,
            "build.rs COMMANDS must match generate_handler!"
        );
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json"))
                .expect("capability JSON");
        let granted: BTreeSet<String> = capability["permissions"]
            .as_array()
            .expect("permissions")
            .iter()
            .filter_map(|value| value.as_str()?.strip_prefix("allow-"))
            .map(|name| name.replace('-', "_"))
            .collect();
        assert_eq!(
            granted, commands,
            "capabilities/default.json must grant every command"
        );
    }
}
