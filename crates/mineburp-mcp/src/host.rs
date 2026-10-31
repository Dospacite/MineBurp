//! What the MCP tools need from whoever runs them.

use std::sync::Arc;

use async_trait::async_trait;
use mineburp_capture::SideCapture;
use mineburp_launcher::{AgentSetupOutcome, InstanceDescriptor, LaunchOutcome, LaunchRequest};
use mineburp_project::ProjectStore;
use mineburp_protocol::SchemaPack;
use mineburp_proxy::ProxyService;
use parking_lot::RwLock;

/// Returned by live operations when no desktop app is attached.
pub const DESKTOP_ONLY: &str =
    "this needs the running MineBurp desktop app (the MCP server is in offline mode)";

/// The application state the tools act on.
///
/// Everything has an offline answer except the live surfaces — proxy,
/// capture, decrypt mode, launchers — which default to "not available".
#[async_trait]
pub trait Host: Send + Sync + 'static {
    /// `desktop` or `offline`.
    fn mode(&self) -> &'static str;

    fn project(&self) -> Option<ProjectStore>;

    /// Whether the open project is the scratch session deleted on exit.
    fn project_is_temporary(&self) -> bool {
        false
    }

    /// Makes `store` the open project, loading its schema packs and rules
    /// into the proxy where there is one.
    async fn install_project(&self, store: ProjectStore) -> Result<(), String>;

    fn proxy(&self) -> Option<ProxyService> {
        None
    }

    fn capture(&self) -> Option<Arc<dyn SideCapture>> {
        None
    }

    fn decrypt_mode(&self) -> Option<bool> {
        None
    }

    fn set_decrypt_mode(&self, _enabled: bool) -> Result<(), String> {
        Err(DESKTOP_ONLY.into())
    }

    async fn launcher_instances(&self) -> Result<Vec<InstanceDescriptor>, String> {
        Err(DESKTOP_ONLY.into())
    }

    async fn launch(&self, _request: LaunchRequest) -> Result<LaunchOutcome, String> {
        Err(DESKTOP_ONLY.into())
    }

    async fn configure_client_assist(
        &self,
        _instance: InstanceDescriptor,
        _enabled: bool,
    ) -> Result<AgentSetupOutcome, String> {
        Err(DESKTOP_ONLY.into())
    }

    /// One or two lines on the client-assistance broker, for `status`.
    async fn client_assist_summary(&self) -> Option<String> {
        None
    }

    /// Tells the UI something changed underneath it (`project`, `rules`,
    /// `intercept`, `network`, `packets`, `schemas`, `repeater`, ...).
    fn notify(&self, _topic: &str) {}

    /// The schema packs currently used for decoding.
    fn schema_packs(&self) -> Vec<SchemaPack> {
        if let Some(proxy) = self.proxy() {
            return proxy.schema_packs();
        }
        self.project()
            .and_then(|store| store.load_schema_packs().ok())
            .unwrap_or_default()
    }
}

/// A host with only a project file: analysis, decoding, rules, and
/// annotations work; live traffic control does not.
#[derive(Debug, Default)]
pub struct OfflineHost {
    project: RwLock<Option<ProjectStore>>,
}

impl OfflineHost {
    #[must_use]
    pub fn new(project: Option<ProjectStore>) -> Self {
        Self {
            project: RwLock::new(project),
        }
    }
}

#[async_trait]
impl Host for OfflineHost {
    fn mode(&self) -> &'static str {
        "offline"
    }

    fn project(&self) -> Option<ProjectStore> {
        self.project.read().clone()
    }

    async fn install_project(&self, store: ProjectStore) -> Result<(), String> {
        *self.project.write() = Some(store);
        Ok(())
    }
}
