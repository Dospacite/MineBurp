use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use mineburp_auth::{AuthClient, MinecraftSession, PkceVerifier};
use mineburp_capture::{SideCapture, SystemCapture};
use mineburp_launcher::{LauncherConfig, LauncherService};
use mineburp_project::{ProjectError, ProjectOptions, ProjectStore};
use mineburp_proxy::ProxyService;
use mineburp_session::{BrokerError, ClientAssistBroker, SessionJoinProvider, SessionJoinRequest};
use parking_lot::RwLock;
use uuid::Uuid;

pub struct PendingAuth {
    pub client: AuthClient,
    pub verifier: PkceVerifier,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAccount {
    pub client: AuthClient,
    pub session: MinecraftSession,
}

#[async_trait::async_trait]
impl SessionJoinProvider for AuthenticatedAccount {
    async fn join_server(&self, request: &SessionJoinRequest) -> Result<(), String> {
        self.client
            .join_server_hash(&self.session, &request.upstream_server_hash)
            .await
            .map_err(|error| error.to_string())
    }
}

pub struct DesktopState {
    pub proxy: ProxyService,
    pub project: Arc<RwLock<Option<ProjectStore>>>,
    /// Path of the scratch project `MineBurp` opened for itself, if the current
    /// project is that one. Capture always has somewhere to write, so packets
    /// are never held in a buffer that can age out from under the operator.
    pub temporary_project: RwLock<Option<PathBuf>>,
    pub launchers: LauncherService,
    pub capture: Arc<dyn SideCapture>,
    pub pending_auth: RwLock<Option<PendingAuth>>,
    pub auth_session: RwLock<Option<AuthenticatedAccount>>,
    pub client_assist: ClientAssistBroker,
    pub agent_path: PathBuf,
    pub agent_config_path: PathBuf,
}

impl DesktopState {
    pub fn new(agent_path: PathBuf, agent_config_path: PathBuf) -> Result<Self, BrokerError> {
        let (client_assist, server) = ClientAssistBroker::bind()?;
        let proxy = ProxyService::new();
        proxy.set_session_join_provider(Some(Arc::new(client_assist.clone())));
        // Routes are capability-protected and are still gated by the disabled-by-
        // default `transparent_intercept` setting in the agent configuration.
        // Keeping the provider ready avoids a race when a user enables decrypt
        // mode and immediately launches a configured instance.
        client_assist.set_transparent_route_provider_blocking(Some(Arc::new(proxy.clone())));
        client_assist.write_agent_config(&agent_config_path)?;
        tauri::async_runtime::spawn(async move {
            if let Err(error) = server.run().await {
                eprintln!("MineBurp client-assistance broker stopped: {error}");
            }
        });
        Ok(Self {
            proxy,
            project: Arc::new(RwLock::new(None)),
            temporary_project: RwLock::new(None),
            launchers: LauncherService::new(default_launcher_config()),
            capture: capture_backend(),
            pending_auth: RwLock::new(None),
            auth_session: RwLock::new(None),
            client_assist,
            agent_path,
            agent_config_path,
        })
    }

    /// Opens a scratch project so a fresh session records to disk immediately.
    ///
    /// Without one, decrypted proxy packets were assigned an id and then thrown
    /// away, and passive capture only lived in a bounded in-memory ring — which
    /// is why a running capture appeared to contain nothing but encrypted
    /// traffic. It is deleted when a real project replaces it.
    pub fn open_temporary_project(&self) -> Result<ProjectStore, ProjectError> {
        let path = env::temp_dir().join(format!("mineburp-session-{}.mineburp", Uuid::new_v4()));
        let store = ProjectStore::create(&path, "Temporary session", ProjectOptions::default())?;
        self.proxy.set_project(Some(store.clone()));
        *self.project.write() = Some(store.clone());
        *self.temporary_project.write() = Some(path);
        Ok(store)
    }

    /// Installs a project the operator chose, dropping any scratch project.
    pub fn adopt_project(&self, store: ProjectStore) {
        let discarded = self.temporary_project.write().take();
        self.proxy.set_project(Some(store.clone()));
        *self.project.write() = Some(store);
        if let Some(path) = discarded {
            remove_project_files(&path);
        }
    }

    /// Closes and removes the scratch project, if the session is still on one.
    pub fn discard_temporary_project(&self) {
        let Some(path) = self.temporary_project.write().take() else {
            return;
        };
        self.proxy.set_project(None);
        *self.project.write() = None;
        remove_project_files(&path);
    }

    #[must_use]
    pub fn project_is_temporary(&self) -> bool {
        self.temporary_project.read().is_some()
    }

    pub fn client_assist_jvm_argument(&self) -> String {
        format!(
            "-javaagent:{}=config={}",
            quote_jvm_path(&self.agent_path),
            quote_jvm_path(&self.agent_config_path)
        )
    }

    pub fn use_client_assist_provider(&self) {
        self.proxy
            .set_session_join_provider(Some(Arc::new(self.client_assist.clone())));
    }

    pub fn set_decrypt_mode(&self, enabled: bool) -> Result<(), BrokerError> {
        let previous = self.client_assist.transparent_intercept_enabled();
        self.client_assist
            .set_transparent_intercept_enabled(enabled);
        if let Err(error) = self
            .client_assist
            .write_agent_config(&self.agent_config_path)
        {
            self.client_assist
                .set_transparent_intercept_enabled(previous);
            return Err(error);
        }
        Ok(())
    }

    #[must_use]
    pub fn decrypt_mode_enabled(&self) -> bool {
        self.client_assist.transparent_intercept_enabled()
    }
}

/// Best-effort removal of a project and its `SQLite` sidecars.
///
/// A handle may still be alive in the capture writer, so failures are expected
/// on platforms that refuse to unlink an open file and are not worth surfacing:
/// the file is in the system temporary directory either way.
fn remove_project_files(path: &Path) {
    let _ = fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = OsString::from(path);
        sidecar.push(suffix);
        let _ = fs::remove_file(PathBuf::from(sidecar));
    }
}

fn quote_jvm_path(path: &std::path::Path) -> String {
    let value = path.to_string_lossy();
    if value.chars().any(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value.into_owned()
    }
}

fn capture_backend() -> Arc<dyn SideCapture> {
    Arc::new(SystemCapture::default())
}

fn default_launcher_config() -> LauncherConfig {
    let home = env::var_os("HOME").map(PathBuf::from);
    let app_data = env::var_os("APPDATA").map(PathBuf::from);
    let local_data = env::var_os("LOCALAPPDATA").map(PathBuf::from);

    #[cfg(target_os = "linux")]
    let config = LauncherConfig {
        official_executable: Some(PathBuf::from("minecraft-launcher")),
        official_root: home.as_ref().map(|path| path.join(".minecraft")),
        prism_executable: Some(PathBuf::from("prismlauncher")),
        prism_root: home
            .as_ref()
            .map(|path| path.join(".local/share/PrismLauncher")),
        multimc_executable: Some(PathBuf::from("multimc")),
        multimc_root: home.as_ref().map(|path| path.join(".local/share/multimc")),
        modrinth_executable: Some(PathBuf::from("modrinth-app")),
        modrinth_root: home
            .as_ref()
            .map(|path| path.join(".local/share/ModrinthApp")),
        curse_forge_executable: Some(preferred_executable(
            &home
                .as_ref()
                .map(|path| {
                    vec![
                        path.join("AppImages/curseforge.appimage"),
                        path.join("Applications/CurseForge.AppImage"),
                        path.join(".local/bin/curseforge"),
                    ]
                })
                .unwrap_or_default(),
            "xdg-open",
        )),
        curse_forge_root: home
            .as_ref()
            .map(|path| path.join("Documents/curseforge/minecraft")),
    };

    #[cfg(target_os = "windows")]
    let config = LauncherConfig {
        official_executable: Some(PathBuf::from("MinecraftLauncher.exe")),
        official_root: app_data.as_ref().map(|path| path.join(".minecraft")),
        prism_executable: app_data
            .as_ref()
            .map(|path| path.join("PrismLauncher/prismlauncher.exe")),
        prism_root: app_data.as_ref().map(|path| path.join("PrismLauncher")),
        multimc_executable: local_data
            .as_ref()
            .map(|path| path.join("MultiMC/MultiMC.exe")),
        multimc_root: local_data.as_ref().map(|path| path.join("MultiMC")),
        modrinth_executable: local_data
            .as_ref()
            .map(|path| path.join("Programs/Modrinth App/Modrinth App.exe")),
        modrinth_root: app_data
            .as_ref()
            .map(|path| path.join("com.modrinth.theseus")),
        curse_forge_executable: Some(PathBuf::from("explorer.exe")),
        curse_forge_root: home.as_ref().map(|path| path.join("curseforge/minecraft")),
    };

    #[cfg(target_os = "macos")]
    let config = LauncherConfig {
        official_executable: Some(PathBuf::from(
            "/Applications/Minecraft.app/Contents/MacOS/launcher",
        )),
        official_root: home
            .as_ref()
            .map(|path| path.join("Library/Application Support/minecraft")),
        prism_executable: Some(PathBuf::from(
            "/Applications/Prism Launcher.app/Contents/MacOS/prismlauncher",
        )),
        prism_root: home
            .as_ref()
            .map(|path| path.join("Library/Application Support/PrismLauncher")),
        multimc_executable: Some(PathBuf::from(
            "/Applications/MultiMC.app/Contents/MacOS/MultiMC",
        )),
        multimc_root: home
            .as_ref()
            .map(|path| path.join("Library/Application Support/multimc")),
        modrinth_executable: Some(PathBuf::from(
            "/Applications/Modrinth App.app/Contents/MacOS/Modrinth App",
        )),
        modrinth_root: home
            .as_ref()
            .map(|path| path.join("Library/Application Support/com.modrinth.theseus")),
        curse_forge_executable: Some(PathBuf::from("open")),
        curse_forge_root: home
            .as_ref()
            .map(|path| path.join("Documents/curseforge/minecraft")),
    };

    let _ = (app_data, local_data);
    config
}

fn preferred_executable(candidates: &[PathBuf], fallback: &str) -> PathBuf {
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| PathBuf::from(fallback))
}
