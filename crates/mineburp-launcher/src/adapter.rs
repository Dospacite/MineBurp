use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{LaunchError, LaunchOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LauncherKind {
    Official,
    Prism,
    MultiMc,
    Modrinth,
    CurseForge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderKind {
    Vanilla,
    Fabric,
    Quilt,
    Forge,
    NeoForge,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceDescriptor {
    pub id: String,
    pub launcher: LauncherKind,
    pub name: String,
    pub path: PathBuf,
    pub minecraft_version: Option<String>,
    pub loader: LoaderKind,
    pub icon_path: Option<PathBuf>,
    /// Whether `MineBurp` can update this instance's JVM arguments reversibly.
    pub supports_agent_configuration: bool,
    /// Whether the instance currently contains `MineBurp`'s Java-agent argument.
    pub client_assist_configured: bool,
    #[serde(default)]
    pub client_assist_stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSetupKind {
    Managed,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSetupOutcome {
    pub kind: AgentSetupKind,
    pub configured: bool,
    pub jvm_argument: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchRequest {
    pub instance: InstanceDescriptor,
    pub profile_name: Option<String>,
}

#[async_trait]
pub trait LauncherAdapter: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> LauncherKind;
    async fn discover(&self) -> Result<Vec<InstanceDescriptor>, LaunchError>;
    async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError>;

    async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        let _ = instance;
        Ok(AgentSetupOutcome {
            kind: AgentSetupKind::Manual,
            configured: false,
            jvm_argument: jvm_argument.to_owned(),
            message: if enabled {
                "Add this value to the launcher's custom Java arguments, then relaunch Minecraft."
            } else {
                "Remove the MineBurp -javaagent value in this launcher's Java settings."
            }
            .into(),
        })
    }
}
