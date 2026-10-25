use std::{path::PathBuf, process::Command};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchOutcome {
    pub process_id: u32,
    pub command: PathBuf,
}

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error("launcher executable was not configured for {0}")]
    MissingExecutable(&'static str),
    #[error("instance root does not exist: {0}")]
    MissingRoot(PathBuf),
    #[error("launcher I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("instance {0} was not found")]
    InstanceNotFound(String),
    #[error("invalid launcher metadata: {0}")]
    InvalidMetadata(String),
    #[error("unable to configure client assistance: {0}")]
    AgentConfiguration(String),
    #[error(
        "launching Minecraft as an elevated user is disabled; configure a non-elevated launcher helper"
    )]
    ElevatedLaunchBlocked,
    #[error("{0} does not expose a stable command-line instance launch interface")]
    Unsupported(&'static str),
}

pub(crate) fn spawn_launcher(
    mut command: Command,
    executable: PathBuf,
) -> Result<LaunchOutcome, LaunchError> {
    if is_elevated() {
        command = de_elevated_command(&command)?;
    }
    let mut child = command.spawn()?;
    let process_id = child.id();
    // Launchers outlive the call that started them. Waiting on a background
    // thread reaps the process when it exits, so it does not linger as a
    // zombie for the rest of the session.
    let _ = std::thread::Builder::new()
        .name("mineburp-launcher-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        });
    Ok(LaunchOutcome {
        process_id,
        command: executable,
    })
}

/// Environment variables carried into a de-elevated launch. Everything else
/// in root's environment — `LD_PRELOAD`, `SUDO_*`, root's `PATH` additions,
/// credentials in variables — stays behind.
#[cfg(target_os = "linux")]
const PRESERVED_ENVIRONMENT: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
];

#[cfg(target_os = "linux")]
const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

#[cfg(target_os = "linux")]
fn de_elevated_command(command: &Command) -> Result<Command, LaunchError> {
    let uid = std::env::var("SUDO_UID")
        .or_else(|_| std::env::var("PKEXEC_UID"))
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(LaunchError::ElevatedLaunchBlocked)?;
    let account = account_for_uid(uid).ok_or(LaunchError::ElevatedLaunchBlocked)?;
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(account.gid);
    let mut lowered = Command::new("setpriv");
    lowered.env_clear();
    for key in PRESERVED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(key) {
            lowered.env(key, value);
        }
    }
    lowered
        .env("PATH", SAFE_PATH)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{uid}/bus"),
        )
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={gid}"))
        .arg("--init-groups")
        .arg("--")
        .arg(command.get_program())
        .args(command.get_args())
        .env("HOME", account.home)
        .env("USER", &account.name)
        .env("LOGNAME", account.name)
        .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    if let Some(directory) = command.get_current_dir() {
        lowered.current_dir(directory);
    }
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            lowered.env(key, value);
        } else {
            lowered.env_remove(key);
        }
    }
    Ok(lowered)
}

#[cfg(not(target_os = "linux"))]
fn de_elevated_command(_command: &Command) -> Result<Command, LaunchError> {
    Err(LaunchError::ElevatedLaunchBlocked)
}

#[cfg(target_os = "linux")]
struct Account {
    name: String,
    gid: u32,
    home: String,
}

#[cfg(target_os = "linux")]
fn account_for_uid(uid: u32) -> Option<Account> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.get(2)?.parse::<u32>().ok()? != uid {
                return None;
            }
            Some(Account {
                name: (*fields.first()?).to_owned(),
                gid: fields.get(3)?.parse().ok()?,
                home: (*fields.get(5)?).to_owned(),
            })
        })
}

fn is_elevated() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|value| value.parse::<u32>().ok())
                    })
            })
            .is_some_and(|uid| uid == 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
