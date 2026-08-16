mod capture_project;
mod commands;
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
        .setup(|app| {
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
            let agent_config_path = app
                .path()
                .app_config_dir()?
                .join("client-assistance.properties");
            let state = state::DesktopState::new(agent_path, agent_config_path)?;
            // A scratch project is opened before capture starts so nothing that
            // arrives in the first seconds has to live in memory or be dropped.
            if let Err(error) = state.open_temporary_project() {
                eprintln!("MineBurp could not open a temporary project: {error}");
            }
            let receiver = state.proxy.subscribe();
            let capture_receiver = state.capture.subscribe();
            let capture_project = capture_project::spawn_capture_project_writer(
                state.project.clone(),
                state.proxy.clone(),
            );
            let handle = app.handle().clone();
            let capture_handle = handle.clone();
            tauri::async_runtime::spawn(pump_proxy_events(handle, receiver));
            tauri::async_runtime::spawn(pump_capture(
                capture_handle,
                capture_receiver,
                capture_project,
            ));
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_capabilities,
            commands::decrypt_mode_status,
            commands::decrypt_mode_set,
            commands::capture_start,
            commands::capture_stop,
            commands::capture_stats,
            commands::project_create,
            commands::project_open,
            commands::project_current,
            commands::project_checkpoint,
            commands::connections_query,
            commands::packets_query,
            commands::filter_vocabulary,
            commands::filter_validate,
            commands::packet_detail,
            commands::packet_bytes,
            commands::inspect_bytes,
            commands::packet_layout,
            commands::field_edit,
            commands::proxy_sessions,
            commands::intercept_rules_set,
            commands::intercept_rules_get,
            commands::replacement_rules_set,
            commands::replacement_rules_get,
            commands::replacement_preview,
            commands::held_resolve,
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
            handle
                .state::<state::DesktopState>()
                .discard_temporary_project();
        }
    });
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
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
) {
    use tokio::sync::broadcast::error::RecvError;

    let mut appended = 0_u64;
    let mut ticker = tokio::time::interval(LIVE_FLUSH);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
                    eprintln!("MineBurp capture relay fell behind by {missed} frame(s)");
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

#[cfg(not(feature = "desktop-runtime"))]
pub fn run() {
    panic!("MineBurp was built without the desktop-runtime feature");
}
