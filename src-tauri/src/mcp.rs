//! Serves the MCP tools on the desktop app's live state.
//!
//! The server listens on a private Unix socket (see `mineburp_mcp::socket`);
//! `mineburp-mcp` bridges an MCP client's stdio to it. Set `MINEBURP_MCP=0`
//! to keep the app from listening at all.

use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use mineburp_capture::SideCapture;
use mineburp_launcher::{AgentSetupOutcome, InstanceDescriptor, LaunchOutcome, LaunchRequest};
use mineburp_mcp::{Host, McpServer};
use mineburp_project::ProjectStore;
use mineburp_proxy::ProxyService;
use tauri::{AppHandle, Emitter, Manager};

use crate::state::DesktopState;

/// The desktop app as an MCP host. State is looked up per call, so the host
/// can exist before `DesktopState` is managed and never outlives it.
pub struct DesktopHost {
    handle: AppHandle,
}

impl DesktopHost {
    fn state(&self) -> tauri::State<'_, DesktopState> {
        self.handle.state::<DesktopState>()
    }
}

#[async_trait]
impl Host for DesktopHost {
    fn mode(&self) -> &'static str {
        "desktop"
    }

    fn project(&self) -> Option<ProjectStore> {
        self.state().project.read().clone()
    }

    fn project_is_temporary(&self) -> bool {
        self.state().project_is_temporary()
    }

    async fn install_project(&self, store: ProjectStore) -> Result<(), String> {
        self.state().install_project(store).await.map(|_| ())
    }

    fn proxy(&self) -> Option<ProxyService> {
        Some(self.state().proxy.clone())
    }

    fn capture(&self) -> Option<Arc<dyn SideCapture>> {
        Some(self.state().capture.clone())
    }

    fn decrypt_mode(&self) -> Option<bool> {
        Some(self.state().decrypt_mode_enabled())
    }

    fn set_decrypt_mode(&self, enabled: bool) -> Result<(), String> {
        self.state()
            .set_decrypt_mode(enabled)
            .map_err(|error| error.to_string())
    }

    async fn launcher_instances(&self) -> Result<Vec<InstanceDescriptor>, String> {
        Ok(self
            .state()
            .launchers
            .discover_all()
            .await
            .into_iter()
            .filter_map(Result::ok)
            .collect())
    }

    async fn launch(&self, request: LaunchRequest) -> Result<LaunchOutcome, String> {
        self.state()
            .launchers
            .launch(&request)
            .await
            .map_err(|error| error.to_string())
    }

    async fn configure_client_assist(
        &self,
        instance: InstanceDescriptor,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, String> {
        let state = self.state();
        let argument = state.client_assist_jvm_argument();
        state
            .launchers
            .configure_client_assist(&instance, &argument, enabled)
            .await
            .map_err(|error| error.to_string())
    }

    async fn client_assist_summary(&self) -> Option<String> {
        let state = self.state();
        let status = state.client_assist.status().await;
        Some(format!(
            "{} agent(s) connected, {} ready session(s); JVM argument: {}",
            status.connected_agents,
            status.ready_sessions,
            state.client_assist_jvm_argument()
        ))
    }

    fn notify(&self, topic: &str) {
        let _ = self.handle.emit("mcp-change", topic);
    }
}

/// Starts the MCP socket unless `MINEBURP_MCP=0`. Failures are reported, not
/// fatal: the app works without it.
pub fn start(handle: &AppHandle, report: impl Fn(String) + Send + 'static) {
    if std::env::var("MINEBURP_MCP").is_ok_and(|value| value == "0") {
        return;
    }
    let server = Arc::new(McpServer::new(Arc::new(DesktopHost {
        handle: handle.clone(),
    })));
    let path = mineburp_mcp::socket::default_socket_path();
    tauri::async_runtime::spawn(async move {
        match mineburp_mcp::socket::bind(&path).await {
            Ok(listener) => {
                let _ = BOUND.set(path.clone());
                eprintln!("MineBurp MCP listening on {}", path.display());
                mineburp_mcp::socket::serve_listener(listener, path, server).await;
            }
            Err(error) => report(format!("MCP server not started: {error}")),
        }
    });
}

/// The socket this process bound, so exit never removes another instance's.
static BOUND: OnceLock<PathBuf> = OnceLock::new();

/// Removes the socket on exit.
pub fn stop() {
    if let Some(path) = BOUND.get() {
        mineburp_mcp::socket::remove(path);
    }
}
