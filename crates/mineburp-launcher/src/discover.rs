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
    LaunchRequest, LauncherAdapter, LauncherKind, LoaderKind,
    fsutil::{backup_once, read_snapshot, write_atomic},
    ini::IniDocument,
    process::spawn_launcher,
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

/// Runs blocking filesystem or process work off the async executor.
///
/// Discovery walks instance directories and reads profile JSON; launching
/// spawns a process and reads `/proc`. None of it belongs on a runtime worker.
async fn off_thread<T, F>(work: F) -> Result<T, LaunchError>
where
    F: FnOnce() -> Result<T, LaunchError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| LaunchError::Io(std::io::Error::other(error.to_string())))?
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
        let Some(root) = self.root.clone() else {
            return Ok(Vec::new());
        };
        off_thread(move || discover_official_instances(&root)).await
    }

    async fn launch(&self, _request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable("Minecraft Launcher"))?;
        off_thread(move || spawn_launcher(Command::new(&executable), executable)).await
    }

    async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        let instance = instance.clone();
        let jvm_argument = jvm_argument.to_owned();
        off_thread(move || configure_official_profile(&instance, &jvm_argument, enabled)).await
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
        let Some(root) = self.root.clone() else {
            return Ok(Vec::new());
        };
        let kind = self.kind;
        off_thread(move || discover_multimc_instances(&root, kind)).await
    }

    async fn launch(&self, request: &LaunchRequest) -> Result<LaunchOutcome, LaunchError> {
        let executable = self
            .executable
            .clone()
            .ok_or(LaunchError::MissingExecutable(self.label()))?;
        let instance_id = request.instance.id.clone();
        let profile_name = request.profile_name.clone();
        off_thread(move || {
            let mut command = Command::new(&executable);
            command.arg("--launch").arg(&instance_id);
            if let Some(profile_name) = profile_name {
                command.arg("--profile").arg(profile_name);
            }
            spawn_launcher(command, executable)
        })
        .await
    }

    async fn configure_client_assist(
        &self,
        instance: &InstanceDescriptor,
        jvm_argument: &str,
        enabled: bool,
    ) -> Result<AgentSetupOutcome, LaunchError> {
        let instance = instance.clone();
        let jvm_argument = jvm_argument.to_owned();
        off_thread(move || configure_multimc_profile(&instance, &jvm_argument, enabled)).await
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
        let Some(root) = self.root.clone() else {
            return Ok(Vec::new());
        };
        off_thread(move || discover_modrinth_instances(&root)).await
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
        off_thread(move || {
            let mut command = Command::new(&executable);
            command.arg(launch_url.as_str());
            spawn_launcher(command, executable)
        })
        .await
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
        let Some(root) = self.root.clone() else {
            return Ok(Vec::new());
        };
        off_thread(move || discover_curse_forge_instances(&root)).await
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
        off_thread(move || {
            let mut command = Command::new(&executable);
            command.arg(launch_url.as_str());
            spawn_launcher(command, executable)
        })
        .await
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
        let config = std::fs::read_to_string(path.join("instance.cfg"))
            .map(|text| IniDocument::parse(&text))
            .ok();
        let property = |key: &str| config.as_ref().and_then(|document| document.get(key));
        let id = entry.file_name().to_string_lossy().into_owned();
        let name = property("name").unwrap_or_else(|| id.clone());
        let (minecraft_version, loader) = parse_mmc_components(&path.join("mmc-pack.json"));
        let icon_path = property("iconKey")
            .filter(|key| is_safe_icon_key(key))
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
            client_assist_configured: property("JvmArgs")
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
        // The metadata names the image; only an image inside the instance's
        // own directory is believed, so a crafted file cannot use discovery
        // to probe for arbitrary paths.
        let icon_path = metadata
            .profile_image_path
            .clone()
            .and_then(|icon| contained_file(&path, &icon));

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
    /// Arguments `MineBurp` wrote earlier that a later edit was replacing when
    /// it was interrupted. They are still removed on the next edit, so a crash
    /// between writing this state and writing the launcher's file never leaves
    /// an argument behind that nothing knows to clean up.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    superseded: HashMap<String, Vec<String>>,
}

impl ManagedAgentState {
    fn is_empty(&self) -> bool {
        self.arguments.is_empty() && self.superseded.is_empty()
    }

    /// Every argument this state says `MineBurp` may have written for `id`.
    fn known(&self, id: &str) -> Vec<String> {
        self.arguments
            .get(id)
            .into_iter()
            .chain(self.superseded.get(id).into_iter().flatten())
            .cloned()
            .collect()
    }

    /// Records the intended argument *before* the launcher file is touched.
    fn begin(&mut self, id: &str, requested: &str, enabled: bool) {
        if let Some(previous) = self.arguments.get(id).cloned()
            && (previous != requested || !enabled)
        {
            let superseded = self.superseded.entry(id.to_owned()).or_default();
            if !superseded.contains(&previous) {
                superseded.push(previous);
            }
        }
        if enabled {
            self.arguments.insert(id.to_owned(), requested.to_owned());
        }
    }

    /// Settles the state once the launcher file holds the new arguments.
    fn finish(&mut self, id: &str, enabled: bool) {
        self.superseded.remove(id);
        if !enabled {
            self.arguments.remove(id);
        }
    }
}

fn configure_multimc_profile(
    instance: &InstanceDescriptor,
    jvm_argument: &str,
    enabled: bool,
) -> Result<AgentSetupOutcome, LaunchError> {
    let config_path = instance.path.join("instance.cfg");
    let state_path = instance.path.join(".mineburp-client-assistance.json");
    let snapshot = read_snapshot(&config_path)?;
    let mut document = IniDocument::parse(&snapshot.text);
    let current = document.get("JvmArgs").unwrap_or_default();
    let mut state = read_json::<ManagedAgentState>(&state_path).unwrap_or_default();
    let updated =
        update_managed_argument(&current, &state.known(&instance.id), jvm_argument, enabled)?;
    document.set("JvmArgs", &updated);
    apply_managed_edit(
        &mut state,
        &state_path,
        &instance.id,
        jvm_argument,
        enabled,
        || {
            backup_once(&config_path)?;
            write_atomic(&config_path, document.render().as_bytes(), Some(&snapshot))
        },
    )?;
    Ok(managed_outcome(enabled, jvm_argument))
}

/// Writes the state file, then the launcher's file, then settles the state.
///
/// The order is what keeps the edit reversible: whichever write a crash
/// interrupts, the state file already names every argument the launcher's file
/// might now contain.
fn apply_managed_edit(
    state: &mut ManagedAgentState,
    state_path: &Path,
    id: &str,
    jvm_argument: &str,
    enabled: bool,
    write_launcher_file: impl FnOnce() -> Result<(), LaunchError>,
) -> Result<(), LaunchError> {
    state.begin(id, jvm_argument, enabled);
    write_agent_state(state_path, state)?;
    write_launcher_file()?;
    state.finish(id, enabled);
    write_agent_state(state_path, state)
}

fn configure_official_profile(
    instance: &InstanceDescriptor,
    jvm_argument: &str,
    enabled: bool,
) -> Result<AgentSetupOutcome, LaunchError> {
    let profiles_path = &instance.path;
    let snapshot = read_snapshot(profiles_path)?;
    // `serde_json` keeps key order here (`preserve_order`), so the launcher's
    // file is rewritten with its keys where they were.
    let mut document: Value = serde_json::from_str(&snapshot.text)
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
        .unwrap_or_default()
        .to_owned();
    let state_path = profiles_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".mineburp-client-assistance.json");
    let mut state = read_json::<ManagedAgentState>(&state_path).unwrap_or_default();
    let updated =
        update_managed_argument(&current, &state.known(&instance.id), jvm_argument, enabled)?;
    profile.insert("javaArgs".into(), Value::String(updated));
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
    apply_managed_edit(
        &mut state,
        &state_path,
        &instance.id,
        jvm_argument,
        enabled,
        || {
            backup_once(profiles_path)?;
            write_atomic(profiles_path, text.as_bytes(), Some(&snapshot))
        },
    )?;
    Ok(managed_outcome(enabled, jvm_argument))
}

fn update_managed_argument(
    current: &str,
    known: &[String],
    requested: &str,
    enabled: bool,
) -> Result<String, LaunchError> {
    let mut without_managed = current.to_owned();
    let mut removed = false;
    for argument in known.iter().map(String::as_str).chain([requested]) {
        if !argument.is_empty() && without_managed.contains(argument) {
            without_managed = without_managed.replace(argument, "");
            removed = true;
        }
    }
    if !removed && known.is_empty() && current.contains(AGENT_MARKER) {
        if enabled {
            return Ok(current.to_owned());
        }
        return Err(LaunchError::AgentConfiguration(
            "the profile contains an agent argument not managed by MineBurp; remove it in the launcher"
                .into(),
        ));
    }
    // Only trim the whitespace directly exposed by removing our own argument.
    // Quoting and intentional spacing elsewhere belongs to the launcher/user.
    let base = without_managed.trim();
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

/// Whether an `iconKey` names a file inside the icons directory.
fn is_safe_icon_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && !key.contains("..")
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
}

/// `candidate` (absolute, or relative to `root`) when it is a file inside
/// `root` after resolving links and `..`.
fn contained_file(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let joined = if candidate.is_absolute() {
        candidate.to_owned()
    } else {
        root.join(candidate)
    };
    let resolved = joined.canonicalize().ok()?;
    let root = root.canonicalize().ok()?;
    (resolved.starts_with(&root) && resolved.is_file()).then_some(resolved)
}

fn write_agent_state(path: &Path, state: &ManagedAgentState) -> Result<(), LaunchError> {
    if state.is_empty() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        return Ok(());
    }
    let text = serde_json::to_string_pretty(state)
        .map_err(|error| LaunchError::InvalidMetadata(error.to_string()))?;
    write_atomic(path, text.as_bytes(), None)
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
        let restored = IniDocument::parse(
            &fs::read_to_string(instance_path.join("instance.cfg")).expect("restored config"),
        );
        assert_eq!(
            restored.get("JvmArgs").as_deref(),
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

    fn prism_instance(root: &Path, config: &str) -> InstanceDescriptor {
        let instance_path = root.join("instances/prism");
        fs::create_dir_all(&instance_path).expect("instance directory");
        fs::write(instance_path.join("instance.cfg"), config).expect("instance config");
        InstanceDescriptor {
            id: "prism".into(),
            launcher: LauncherKind::Prism,
            name: "Prism".into(),
            path: instance_path,
            minecraft_version: None,
            loader: LoaderKind::Fabric,
            icon_path: None,
            supports_agent_configuration: true,
            client_assist_configured: false,
        }
    }

    #[test]
    fn prism_settings_escape_a_quoted_agent_path() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let instance = prism_instance(temp.path(), "[General]\r\nJvmArgs=-Xmx4G\r\nname=Prism\r\n");
        let argument = "-javaagent:\"/home/me/Mine Burp/mineburp-agent.jar\"=config=\"/home/me/a b.properties\"";
        configure_multimc_profile(&instance, argument, true).expect("agent configuration");
        let text = fs::read_to_string(instance.path.join("instance.cfg")).expect("config");
        assert!(
            text.contains("JvmArgs=\"-Xmx4G -javaagent:\\\"/home/me/Mine Burp"),
            "{text}"
        );
        assert!(text.contains("\r\n"), "CRLF endings are kept");
        assert_eq!(
            IniDocument::parse(&text).get("JvmArgs").as_deref(),
            Some(format!("-Xmx4G {argument}").as_str())
        );
        // The pre-edit file is kept once.
        assert_eq!(
            fs::read_to_string(crate::fsutil::backup_path(
                &instance.path.join("instance.cfg")
            ))
            .expect("backup"),
            "[General]\r\nJvmArgs=-Xmx4G\r\nname=Prism\r\n"
        );
        configure_multimc_profile(&instance, argument, false).expect("agent removal");
        let restored = fs::read_to_string(instance.path.join("instance.cfg")).expect("config");
        assert_eq!(
            IniDocument::parse(&restored).get("JvmArgs").as_deref(),
            Some("-Xmx4G")
        );
        assert!(
            !instance
                .path
                .join(".mineburp-client-assistance.json")
                .exists()
        );
    }

    #[test]
    fn an_interrupted_change_of_argument_is_still_removable() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let old = "-javaagent:/old/mineburp-agent.jar=config=/old.properties";
        let new = "-javaagent:/new/mineburp-agent.jar=config=/new.properties";
        let instance = prism_instance(temp.path(), &format!("name=x\nJvmArgs=-Xmx1G {old}\n"));
        // State as a crash would leave it: the new argument recorded, the old
        // one superseded, the launcher file still holding the old one.
        fs::write(
            instance.path.join(".mineburp-client-assistance.json"),
            format!(r#"{{"arguments":{{"prism":"{new}"}},"superseded":{{"prism":["{old}"]}}}}"#),
        )
        .expect("state");
        configure_multimc_profile(&instance, new, false).expect("agent removal");
        let restored = fs::read_to_string(instance.path.join("instance.cfg")).expect("config");
        assert_eq!(
            IniDocument::parse(&restored).get("JvmArgs").as_deref(),
            Some("-Xmx1G")
        );
    }

    #[test]
    fn official_profiles_keep_their_key_order() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let profiles = temp.path().join("launcher_profiles.json");
        fs::write(
            &profiles,
            r#"{"settings":{"z":1,"a":2},"profiles":{"p":{"type":"custom","name":"P","lastVersionId":"1.21.1"}},"version":3}"#,
        )
        .expect("profiles");
        let instance = discover_official_instances(temp.path())
            .expect("discovery")
            .pop()
            .expect("profile");
        configure_official_profile(&instance, "-javaagent:/x/mineburp-agent.jar", true)
            .expect("configuration");
        let text = fs::read_to_string(&profiles).expect("profiles");
        let settings = text.find("\"settings\"").unwrap();
        let profiles_key = text.find("\"profiles\"").unwrap();
        let version = text.find("\"version\"").unwrap();
        assert!(settings < profiles_key && profiles_key < version, "{text}");
        assert!(text.find("\"z\"").unwrap() < text.find("\"a\"").unwrap());
        assert!(text.find("\"type\"").unwrap() < text.find("\"javaArgs\"").unwrap());
    }

    #[test]
    fn icon_lookups_stay_inside_their_directories() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let outside = temp.path().join("secret.png");
        fs::write(&outside, b"x").expect("outside file");
        let root = temp.path().join("multimc");
        fs::create_dir_all(root.join("icons")).expect("icons");
        fs::create_dir_all(root.join("instances/one")).expect("instance");
        fs::write(
            root.join("instances/one/instance.cfg"),
            "name=One\niconKey=../../secret\n",
        )
        .expect("config");
        let instances = discover_multimc_instances(&root, LauncherKind::MultiMc).expect("found");
        assert!(instances[0].icon_path.is_none());
        assert!(is_safe_icon_key("flame"));
        assert!(!is_safe_icon_key("../x"));
        assert!(!is_safe_icon_key("a/b"));

        let instance = temp.path().join("Instances/Pack");
        fs::create_dir_all(instance.join("profileImage")).expect("instance");
        fs::write(instance.join("profileImage/icon.png"), b"x").expect("icon");
        assert!(contained_file(&instance, Path::new("profileImage/icon.png")).is_some());
        assert!(contained_file(&instance, &outside).is_none());
        assert!(contained_file(&instance, Path::new("../../secret.png")).is_none());
    }
}
