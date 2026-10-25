//! Discovery and launch adapters for popular third-party Minecraft launchers.

mod adapter;
mod discover;
mod fsutil;
mod ini;
mod process;

pub use adapter::{
    AgentSetupKind, AgentSetupOutcome, InstanceDescriptor, LaunchRequest, LauncherAdapter,
    LauncherKind, LoaderKind,
};
pub use discover::{LauncherConfig, LauncherService};
pub use process::{LaunchError, LaunchOutcome};
