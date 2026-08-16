use std::{
    collections::HashMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AgentSetupKind, AgentSetupOutcome, InstanceDescriptor, LaunchError, LaunchOutcome,
    LaunchRequest, LauncherAdapter, LauncherKind, LoaderKind, process::spawn_launcher,
};

const AGENT_MARKER: &str = "mineburp-agent.jar";

#[derive(Debug, Clone, Default)]
pub struct LauncherConfig {
    pub official_executable: Option<PathBuf>,
    pub official_root: Option<PathBuf>,
    pub prism_executable: Option<PathBuf>,
    pub prism_root: Option<PathBuf>,
    pub multimc_executable: Option<PathBuf>,
    pub multimc_root: Option<PathBuf>,
    pub modrinth_executable: Option<PathBuf>,
    pub modrinth_root: Option<PathBuf>,
    pub curse_forge_executable: Option<PathBuf>,
    pub curse_forge_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct LauncherService {
    adapters: HashMap<LauncherKind, Arc<dyn LauncherAdapter>>,
}

impl LauncherService {
    #[must_use]
    pub fn new(config: LauncherConfig) -> Self {
        let mut adapters: HashMap<LauncherKind, Arc<dyn LauncherAdapter>> = HashMap::new();
        adapters.insert(
            LauncherKind::Official,
            Arc::new(OfficialAdapter {
                executable: config.official_executable,
                root: config.official_root,
            }),
        );
        adapters.insert(
            LauncherKind::Prism,
            Arc::new(MultiMcAdapter::new(
                LauncherKind::Prism,
                config.prism_executable,
                config.prism_root,
            )),
        );
        adapters.insert(
            LauncherKind::MultiMc,
            Arc::new(MultiMcAdapter::new(
                LauncherKind::MultiMc,
                config.multimc_executable,
                config.multimc_root,
            )),
        );
        adapters.insert(
            LauncherKind::Modrinth,
            Arc::new(ModrinthAdapter {
                executable: config.modrinth_executable,
                root: config.modrinth_root,
            }),
        );
        adapters.insert(
            LauncherKind::CurseForge,
            Arc::new(CurseForgeAdapter {
                executable: config.curse_forge_executable,
                root: config.curse_forge_root,
            }),
        );
        Self { adapters }
    }

    pub async fn discover_all(&self) -> Vec<Result<InstanceDescriptor, LaunchError>> {
        let mut instances = Vec::new();
        for adapter in self.adapters.values() {
            match adapter.discover().await {
                Ok(found) => instances.extend(found.into_iter().map(Ok)),
                Err(error) => instances.push(Err(error)),
            }
        }
        instances
    }

    /// Launches an instance with the adapter that discovered it.
    ///
    /// # Errors
    ///
    /// Returns an error when the adapter is missing, the launcher cannot be
    /// executed, or privilege lowering cannot be completed safely.
    pub async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let adapter = self
            .adapters
            .get(&request.instance.launcher)
            .cloned()
            .ok_or_else(|| LaunchError::InstanceNotFound(request.instance.id.clone()))?;
        let instance = rediscover_instance(&adapter, &request.instance.id).await?;
        let verified_request = LaunchRequest {
            instance,
            profile_name: request.profile_name.clone(),
        };
        adapter.launch(&verified_request).await
    }

    pub async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        let adapter = self
            .adapters
            .get(&instance.launcher)
            .cloned()
            .ok_or_else(|| LaunchError::InstanceNotFound(instance.id.clone()))?;
        let instance = rediscover_instance(&adapter, &instance.id).await?;
        adapter
            .configure_client_assist(&instance, jvm_argument, enabled)
            .await
    }
}

async fn rediscover_instance(
    adapter: &Arc<dyn LauncherAdapter>,
    instance_id: &str,
) -> Result<InstanceDescriptor, LaunchError> {
    adapter
        .discover()
        .await?
        .into_iter()
        .find(|instance| instance.id == instance_id)
        .ok_or_else(|| LaunchError::InstanceNotFound(instance_id.to_owned()))
}

#[derive(Debug)]
struct OfficialAdapter {
    executable: Option<PathBuf>,
    root: Option<PathBuf>,
}

#[async_trait]
impl LauncherAdapter for OfficialAdapter {
    fn kind(&self) -> LauncherKind {
        LauncherKind::Official
    }

    async fn discover(&self) -> Result<Vec<InstanceDescriptor>, LaunchError> {
        let Some(root) = &self.root else {
            return Ok(Vec::new());
        };
        discover_official_instances(root)
    }

    async fn launch(&self, _request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable("Minecraft Launcher"))?;
        spawn_launcher(Command::new(&executable), executable)
    }

    async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        configure_official_profile(instance, jvm_argument, enabled)
    }
}

#[derive(Debug)]
struct MultiMcAdapter {
    kind: LauncherKind,
    executable: Option<PathBuf>,
    root: Option<PathBuf>,
}

impl MultiMcAdapter {
    fn new(kind: LauncherKind, executable: Option<PathBuf>, root: Option<PathBuf>) -> Self {
        Self {
            kind,
            executable,
            root,
        }
    }

    fn label(&self) -> &'static str {
        match self.kind {
            LauncherKind::Prism => "Prism Launcher",
            LauncherKind::MultiMc => "MultiMC",
            LauncherKind::Official | LauncherKind::Modrinth | LauncherKind::CurseForge => {
                unreachable!()
            }
        }
    }
}

#[async_trait]
impl LauncherAdapter for MultiMcAdapter {
    fn kind(&self) -> LauncherKind {
        self.kind
    }

    async fn discover(&self) -> Result<Vec<InstanceDescriptor>, LaunchError> {
        let Some(root) = &self.root else {
            return Ok(Vec::new());
        };
        discover_multimc_instances(root, self.kind)
    }

    async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable(self.label()))?;
        let mut command = Command::new(&executable);
        command.arg("--launch").arg(&request.instance.id);
        if let Some(profile_name) = &request.profile_name {
            command.arg("--profile").arg(profile_name);
        }
        spawn_launcher(command, executable)
    }

    async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        configure_multimc_profile(instance, jvm_argument, enabled)
    }
}

#[derive(Debug)]
struct ModrinthAdapter {
    executable: Option<PathBuf>,
    root: Option<PathBuf>,
}

#[async_trait]
impl LauncherAdapter for ModrinthAdapter {
    fn kind(&self) -> LauncherKind {
        LauncherKind::Modrinth
    }

    async fn discover(&self) -> Result<Vec<InstanceDescriptor>, LaunchError> {
        let Some(root) = &self.root else {
            return Ok(Vec::new());
        };
        discover_modrinth_instances(root)
    }

    async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable("Modrinth App"))?;
        let mut launch_url = url::Url::parse("modrinth://launch/instance")
            .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
        launch_url
            .path_segments_mut()
            .map_err(|()| LaunchError::InvalidMetadata("invalid Modrinth launch URL".into()))?
            .push(&request.instance.id);
        let mut command = Command::new(&executable);
        command.arg(launch_url.as_str());
        spawn_launcher(command, executable)
    }
}

/// `CurseForge` exposes a stable profile-launch deep link. Discovery and process
/// launch remain isolated here so launcher-specific behavior does not leak into
/// the UI or desktop command layer.
#[derive(Debug)]
struct CurseForgeAdapter {
    executable: Option<PathBuf>,
    root: Option<PathBuf>,
}

#[async_trait]
impl LauncherAdapter for CurseForgeAdapter {
    fn kind(&self) -> LauncherKind {
        LauncherKind::CurseForge
    }

    async fn discover(&self) -> Result<Vec<InstanceDescriptor>, LaunchError> {
        let Some(root) = &self.root else {
            return Ok(Vec::new());
        };
        discover_curse_forge_instances(root)
    }

    async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable("CurseForge"))?;
        let mut launch_url = url::Url::parse("curseforge://launch-game")
            .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
        launch_url
            .query_pairs_mut()
            .append_pair("instanceId", &request.instance.id)
            .append_pair("gameId", "432");
        let mut command = Command::new(&executable);
        command.arg(launch_url.as_str());
        spawn_launcher(command, executable)
    }
}

fn discover_official_instances(root: &Path) -> Result<Vec<InstanceDescriptor>, LaunchError> {
    let profiles_path = root.join("launcher_profiles.json");
    if !profiles_path.is_file() {
        return Ok(Vec::new());
    }
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&profiles_path)?)
        .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
    let Some(profiles) = document.get("profiles").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut instances = profiles
        .iter()
        .map(|(id, profile)| {
            let version = profile
                .get("lastVersionId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let name = profile
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .unwrap_or(id)
                .to_owned();
            let loader = version
                .as_deref()
                .map_or(LoaderKind::Vanilla, infer_official_loader);
            let configured = profile
                .get("javaArgs")
                .and_then(Value::as_str)
                .is_some_and(|arguments| arguments.contains(AGENT_MARKER));
            InstanceDescriptor {
                id: id.clone(),
                launcher: LauncherKind::Official,
                name,
                path: profiles_path.clone(),
                minecraft_version: version,
                loader,
                icon_path: None,
                supports_agent_configuration: true,
                client_assist_configured: configured,
            }
        })
        .collect::<Vec<_>>();
    instances.sort_by_key(|instance| instance.name.to_lowercase());
    Ok(instances)
}

fn discover_multimc_instances(
    root: &Path,
    launcher: LauncherKind,
) -> Result<Vec<InstanceDescriptor>, LaunchError> {
    let instance_root = if root.join("instances").is_dir() {
        root.join("instances")
    } else {
        root.to_owned()
    };
    if !instance_root.is_dir() {
        return Err(LaunchError::MissingRoot(instance_root));
    }
    let mut instances = Vec::new();
    for entry in std::fs::read_dir(instance_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let config = parse_properties(&path.join("instance.cfg")).unwrap_or_default();
        let id = entry.file_name().to_string_lossy().into_owned();
        let name = config.get("name").cloned().unwrap_or_else(|| id.clone());
        let (minecraft_version, loader) = parse_mmc_components(&path.join("mmc-pack.json"));
        let icon_path = config
            .get("iconKey")
            .map(|key| root.join("icons").join(format!("{key}.png")))
            .filter(|icon| icon.is_file());
        instances.push(InstanceDescriptor {
            id,
            launcher,
            name,
            path,
            minecraft_version,
            loader,
            icon_path,
            supports_agent_configuration: true,
            client_assist_configured: config
                .get("JvmArgs")
                .is_some_and(|arguments| arguments.contains(AGENT_MARKER)),
        });
    }
    instances.sort_by_key(|instance| instance.name.to_lowercase());
    Ok(instances)
}

fn discover_modrinth_instances(root: &Path) -> Result<Vec<InstanceDescriptor>, LaunchError> {
    let profile_root = if root.join("profiles").is_dir() {
        root.join("profiles")
    } else {
        root.to_owned()
    };
    if !profile_root.is_dir() {
        return Err(LaunchError::MissingRoot(profile_root));
    }
    let mut instances = Vec::new();
    for entry in std::fs::read_dir(profile_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let id = entry.file_name().to_string_lossy().into_owned();
        let metadata = std::fs::read_to_string(path.join("profile.json")).unwrap_or_default();
        let name = json_string(&metadata, "name").unwrap_or_else(|| id.clone());
        let minecraft_version = json_string(&metadata, "game_version");
        let loader = infer_loader(&metadata);
        instances.push(InstanceDescriptor {
            id,
            launcher: LauncherKind::Modrinth,
            name,
            path,
            minecraft_version,
            loader,
            icon_path: None,
            supports_agent_configuration: false,
            client_assist_configured: false,
        });
    }
    instances.sort_by_key(|instance| instance.name.to_lowercase());
    Ok(instances)
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CurseForgeMetadata {
    guid: Option<String>,
    name: Option<String>,
    game_version: Option<String>,
    base_mod_loader: Option<CurseForgeLoader>,
    profile_image_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CurseForgeLoader {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<u32>,
    #[serde(default)]
    is_vanilla: bool,
}

#[derive(Debug, Default, Deserialize)]
struct CurseForgeManifest {
    name: Option<String>,
    minecraft: Option<CurseForgeMinecraft>,
}

#[derive(Debug, Default, Deserialize)]
struct CurseForgeMinecraft {
    version: Option<String>,
    #[serde(default, rename = "modLoaders")]
    mod_loaders: Vec<CurseForgeManifestLoader>,
}

#[derive(Debug, Default, Deserialize)]
struct CurseForgeManifestLoader {
    id: String,
    #[serde(default)]
    primary: bool,
}

fn discover_curse_forge_instances(root: &Path) -> Result<Vec<InstanceDescriptor>, LaunchError> {
    let instance_root = if root.join("Instances").is_dir() {
        root.join("Instances")
    } else {
        root.to_owned()
    };
    if !instance_root.is_dir() {
        return Err(LaunchError::MissingRoot(instance_root));
    }

    let mut instances = Vec::new();
    for entry in std::fs::read_dir(instance_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(metadata) = read_json::<CurseForgeMetadata>(&path.join("minecraftinstance.json"))
        else {
            continue;
        };
        let Some(id) = metadata.guid.clone().filter(|id| !id.is_empty()) else {
            continue;
        };
        let manifest = read_json::<CurseForgeManifest>(&path.join("manifest.json"));

        let folder_name = entry.file_name().to_string_lossy().into_owned();
        let name = metadata
            .name
            .clone()
            .or_else(|| manifest.as_ref().and_then(|value| value.name.clone()))
            .unwrap_or(folder_name);
        let minecraft_version = metadata.game_version.clone().or_else(|| {
            manifest
                .as_ref()
                .and_then(|value| value.minecraft.as_ref())
                .and_then(|value| value.version.clone())
        });
        let loader = curse_forge_loader(Some(&metadata), manifest.as_ref());
        let icon_path = metadata
            .profile_image_path
            .clone()
            .map(|icon| {
                if icon.is_absolute() {
                    icon
                } else {
                    path.join(icon)
                }
            })
            .filter(|icon| icon.is_file());

        instances.push(InstanceDescriptor {
            id,
            launcher: LauncherKind::CurseForge,
            name,
            path,
            minecraft_version,
            loader,
            icon_path,
            supports_agent_configuration: false,
            client_assist_configured: false,
        });
    }
    instances.sort_by_key(|instance| instance.name.to_lowercase());
    Ok(instances)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ManagedAgentState {
    #[serde(default)]
    arguments: HashMap<String, String>,
}

fn configure_multimc_profile(
    instance: &InstanceDescriptor,
    jvm_argument: &str,
    enabled: bool,
) -> Result<AgentSetupOutcome, LaunchError> {
    let config_path = instance.path.join("instance.cfg");
    let state_path = instance.path.join(".mineburp-client-assistance.json");
    let text = std::fs::read_to_string(&config_path)?;
    let properties = parse_properties(&config_path)?;
    let current = properties.get("JvmArgs").cloned().unwrap_or_default();
    let mut state = read_json::<ManagedAgentState>(&state_path).unwrap_or_default();
    let previous = state.arguments.remove(&instance.id);
    let updated = update_managed_argument(&current, previous.as_deref(), jvm_argument, enabled)?;
    std::fs::write(&config_path, set_property(&text, "JvmArgs", &updated))?;
    if enabled {
        state
            .arguments
            .insert(instance.id.clone(), jvm_argument.to_owned());
    }
    write_agent_state(&state_path, &state)?;
    Ok(managed_outcome(enabled, jvm_argument))
}

fn configure_official_profile(
    instance: &InstanceDescriptor,
    jvm_argument: &str,
    enabled: bool,
) -> Result<AgentSetupOutcome, LaunchError> {
    let profiles_path = &instance.path;
    let mut document: Value = serde_json::from_str(&std::fs::read_to_string(profiles_path)?)
        .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
    let profile = document
        .get_mut("profiles")
        .and_then(Value::as_object_mut)
        .and_then(|profiles| profiles.get_mut(&instance.id))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| LaunchError::InstanceNotFound(instance.id.clone()))?;
    let current = profile
        .get("javaArgs")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let state_path = profiles_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".mineburp-client-assistance.json");
    let mut state = read_json::<ManagedAgentState>(&state_path).unwrap_or_default();
    let previous = state.arguments.remove(&instance.id);
    let updated = update_managed_argument(current, previous.as_deref(), jvm_argument, enabled)?;
    profile.insert("javaArgs".into(), Value::String(updated));
    std::fs::write(
        profiles_path,
        serde_json::to_string_pretty(&document)
            .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?,
    )?;
    if enabled {
        state
            .arguments
            .insert(instance.id.clone(), jvm_argument.to_owned());
    }
    write_agent_state(&state_path, &state)?;
    Ok(managed_outcome(enabled, jvm_argument))
}

fn update_managed_argument(
    current: &str,
    previous: Option<&str>,
    requested: &str,
    enabled: bool,
) -> Result<String, LaunchError> {
    let without_previous = if let Some(previous) = previous {
        current.replace(previous, "")
    } else if current.contains(AGENT_MARKER) {
        if enabled {
            return Ok(current.to_owned());
        }
        return Err(LaunchError::AgentConfiguration(
            "the profile contains an agent argument not managed by MineBurp; remove it in the launcher"
                .into(),
        ));
    } else {
        current.to_owned()
    };
    // Only trim the whitespace directly exposed by removing our own argument.
    // Quoting and intentional spacing elsewhere belongs to the launcher/user.
    let base = without_previous.trim();
    if enabled {
        Ok(if base.is_empty() {
            requested.to_owned()
        } else {
            format!("{base} {requested}")
        })
    } else {
        Ok(base.to_owned())
    }
}

fn set_property(text: &str, key: &str, value: &str) -> String {
    let mut found = false;
    let mut lines = text
        .lines()
        .map(|line| {
            if line
                .split_once('=')
                .is_some_and(|(candidate, _)| candidate.trim() == key)
            {
                found = true;
                format!("{key}={value}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if !found {
        lines.push(format!("{key}={value}"));
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

fn write_agent_state(path: &Path, state: &ManagedAgentState) -> Result<(), LaunchError> {
    if state.arguments.is_empty() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        return Ok(());
    }
    let text = serde_json::to_string_pretty(state)
        .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
    std::fs::write(path, text)?;
    Ok(())
}

fn managed_outcome(enabled: bool, jvm_argument: &str) -> AgentSetupOutcome {
    AgentSetupOutcome {
        kind: AgentSetupKind::Managed,
        configured: enabled,
        jvm_argument: jvm_argument.to_owned(),
        message: if enabled {
            "Client assistance is configured. Fully close and relaunch Minecraft before connecting."
        } else {
            "MineBurp's Java-agent argument was removed from this instance."
        }
        .into(),
    }
}

fn curse_forge_loader(
    metadata: Option<&CurseForgeMetadata>,
    manifest: Option<&CurseForgeManifest>,
) -> LoaderKind {
    if let Some(loader) = metadata.and_then(|value| value.base_mod_loader.as_ref()) {
        if loader.is_vanilla {
            return LoaderKind::Vanilla;
        }
        if let Some(kind) = loader.kind {
            let mapped = match kind {
                1 => LoaderKind::Forge,
                4 => LoaderKind::Fabric,
                5 => LoaderKind::Quilt,
                6 => LoaderKind::NeoForge,
                9_999_999 => LoaderKind::Vanilla,
                _ => LoaderKind::Unknown,
            };
            if mapped != LoaderKind::Unknown {
                return mapped;
            }
        }
        if let Some(name) = &loader.name {
            return infer_loader(name);
        }
    }

    let manifest_loader = manifest
        .and_then(|value| value.minecraft.as_ref())
        .and_then(|value| {
            value
                .mod_loaders
                .iter()
                .find(|loader| loader.primary)
                .or_else(|| value.mod_loaders.first())
        });
    manifest_loader.map_or(LoaderKind::Vanilla, |loader| infer_loader(&loader.id))
}

fn parse_properties(path: &Path) -> Result<HashMap<String, String>, std::io::Error> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect())
}

fn parse_mmc_components(path: &Path) -> (Option<String>, LoaderKind) {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let minecraft_version = component_version(&text, "net.minecraft");
    let loader = if text.contains("net.neoforged") {
        LoaderKind::NeoForge
    } else if text.contains("net.minecraftforge") {
        LoaderKind::Forge
    } else if text.contains("net.fabricmc") {
        LoaderKind::Fabric
    } else if text.contains("org.quiltmc") {
        LoaderKind::Quilt
    } else if minecraft_version.is_some() {
        LoaderKind::Vanilla
    } else {
        LoaderKind::Unknown
    };
    (minecraft_version, loader)
}

fn component_version(text: &str, uid: &str) -> Option<String> {
    let uid_position = text.find(&format!("\"uid\": \"{uid}\""))?;
    json_string(&text[uid_position..], "version")
}

fn infer_loader(text: &str) -> LoaderKind {
    for (needle, loader) in [
        ("neoforge", LoaderKind::NeoForge),
        ("forge", LoaderKind::Forge),
        ("fabric", LoaderKind::Fabric),
        ("quilt", LoaderKind::Quilt),
        ("vanilla", LoaderKind::Vanilla),
    ] {
        if text.to_lowercase().contains(needle) {
            return loader;
        }
    }
    LoaderKind::Unknown
}

fn infer_official_loader(version: &str) -> LoaderKind {
    let inferred = infer_loader(version);
    if inferred == LoaderKind::Unknown {
        LoaderKind::Vanilla
    } else {
        inferred
    }
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let value = text.get(text.find(&marker)? + marker.len()..)?;
    let value = value.get(value.find(':')? + 1..)?.trim_start();
    let value = value.strip_prefix('"')?;
    Some(value.get(..value.find('"')?)?.to_owned())
}

#[allow(dead_code)]
fn is_executable(path: &Path) -> bool {
    path.extension().and_then(OsStr::to_str).is_some() || path.is_file()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn discovers_curse_forge_metadata_and_loader() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let instance = temp.path().join("Instances/All the Mods 10");
        fs::create_dir_all(&instance).expect("instance directory");
        fs::write(
            instance.join("minecraftinstance.json"),
            r#"{
                "guid": "27f92c1b-f8d2-4eca-a900-b7f814212b91",
                "name": "All the Mods 10",
                "gameVersion": "1.21.1",
                "baseModLoader": {
                    "name": "neoforge-21.1.200",
                    "type": 6,
                    "isVanilla": false
                }
            }"#,
        )
        .expect("instance metadata");

        let instances = discover_curse_forge_instances(temp.path()).expect("discovery succeeds");

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].id, "27f92c1b-f8d2-4eca-a900-b7f814212b91");
        assert_eq!(instances[0].name, "All the Mods 10");
        assert_eq!(instances[0].minecraft_version.as_deref(), Some("1.21.1"));
        assert_eq!(instances[0].loader, LoaderKind::NeoForge);
    }

    #[test]
    fn fills_in_loader_details_from_curse_forge_manifest() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let instance = temp.path().join("Manifest Pack");
        fs::create_dir_all(&instance).expect("instance directory");
        fs::write(
            instance.join("minecraftinstance.json"),
            r#"{
                "guid": "9cc7d0ae-c04d-47b1-b99c-8e7eb9740694",
                "name": "Manifest Pack"
            }"#,
        )
        .expect("instance metadata");
        fs::write(
            instance.join("manifest.json"),
            r#"{
                "name": "Manifest Pack",
                "minecraft": {
                    "version": "1.20.1",
                    "modLoaders": [{ "id": "forge-47.4.13", "primary": true }]
                }
            }"#,
        )
        .expect("manifest metadata");

        let instances = discover_curse_forge_instances(temp.path()).expect("discovery succeeds");

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].name, "Manifest Pack");
        assert_eq!(instances[0].minecraft_version.as_deref(), Some("1.20.1"));
        assert_eq!(instances[0].loader, LoaderKind::Forge);
    }

    #[test]
    fn discovers_and_reversibly_configures_an_official_vanilla_profile() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let profiles = temp.path().join("launcher_profiles.json");
        fs::write(
            &profiles,
            r#"{
                "profiles": {
                    "vanilla": {
                        "name": "Vanilla 1.21",
                        "lastVersionId": "1.21.1",
                        "javaArgs": "-Xmx4G  -Dexample=present"
                    }
                }
            }"#,
        )
        .expect("launcher profiles");
        let mut instances = discover_official_instances(temp.path()).expect("official discovery");
        let instance = instances.pop().expect("vanilla profile");
        assert_eq!(instance.loader, LoaderKind::Vanilla);
        assert!(instance.supports_agent_configuration);

        let argument = "-javaagent:/opt/MineBurp/mineburp-agent.jar=config=/tmp/client.properties";
        configure_official_profile(&instance, argument, true).expect("agent configuration");
        let configured = fs::read_to_string(&profiles).expect("configured profiles");
        assert!(configured.contains(argument));
        assert!(configured.contains("-Xmx4G  -Dexample=present"));

        configure_official_profile(&instance, argument, false).expect("agent removal");
        let restored: Value =
            serde_json::from_str(&fs::read_to_string(&profiles).expect("restored profiles"))
                .expect("valid profiles JSON");
        assert_eq!(
            restored["profiles"]["vanilla"]["javaArgs"].as_str(),
            Some("-Xmx4G  -Dexample=present")
        );
        assert!(
            !temp
                .path()
                .join(".mineburp-client-assistance.json")
                .exists()
        );
    }

    #[test]
    fn preserves_existing_multimc_arguments_during_round_trip() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let instance_path = temp.path().join("instances/test");
        fs::create_dir_all(&instance_path).expect("instance directory");
        fs::write(
            instance_path.join("instance.cfg"),
            "name=Test\nJvmArgs=-Xmx6G  -Dquoted=\"a b\"\n",
        )
        .expect("instance config");
        let instance = InstanceDescriptor {
            id: "test".into(),
            launcher: LauncherKind::Prism,
            name: "Test".into(),
            path: instance_path.clone(),
            minecraft_version: Some("1.20.1".into()),
            loader: LoaderKind::Fabric,
            icon_path: None,
            supports_agent_configuration: true,
            client_assist_configured: false,
        };
        let argument = "-javaagent:/opt/mineburp-agent.jar=config=/tmp/client.properties";
        configure_multimc_profile(&instance, argument, true).expect("agent configuration");
        configure_multimc_profile(&instance, argument, false).expect("agent removal");
        let restored = parse_properties(&instance_path.join("instance.cfg"))
            .expect("restored instance config");
        assert_eq!(
            restored.get("JvmArgs").map(String::as_str),
            Some("-Xmx6G  -Dquoted=\"a b\"")
        );
    }

    #[tokio::test]
    async fn service_rediscovery_ignores_a_substituted_profile_path() {
        let real = tempfile::tempdir().expect("real launcher directory");
        let substituted = tempfile::tempdir().expect("substituted launcher directory");
        let profiles_json = r#"{
            "profiles": {
                "vanilla": { "name": "Vanilla", "lastVersionId": "1.21.1" }
            }
        }"#;
        fs::write(real.path().join("launcher_profiles.json"), profiles_json)
            .expect("real launcher profiles");
        fs::write(
            substituted.path().join("launcher_profiles.json"),
            profiles_json,
        )
        .expect("substituted launcher profiles");
        let service = LauncherService::new(LauncherConfig {
            official_root: Some(real.path().to_owned()),
            ..LauncherConfig::default()
        });
        let mut instance = discover_official_instances(real.path())
            .expect("profile discovery")
            .pop()
            .expect("vanilla profile");
        instance.path = substituted.path().join("launcher_profiles.json");
        let argument = "-javaagent:/opt/mineburp-agent.jar=config=/tmp/client.properties";

        service
            .configure_client_assist(&instance, argument, true)
            .await
            .expect("verified configuration");

        assert!(
            fs::read_to_string(real.path().join("launcher_profiles.json"))
                .expect("configured real profile")
                .contains(argument)
        );
        assert!(
            !fs::read_to_string(substituted.path().join("launcher_profiles.json"))
                .expect("untouched substituted profile")
                .contains(argument)
        );
    }
}
