//! Session-join providers and the local client-assistance broker.
//!
//! The proxy computes both Minecraft server hashes. Providers only decide how
//! to register the active profile with the upstream hash. This keeps Microsoft
//! OAuth, launcher integration, and packet processing independent.

mod broker;
mod hash;

use async_trait::async_trait;

pub use broker::{BrokerError, ClientAssistBroker, ClientAssistServer, ClientAssistStatus};
pub use hash::minecraft_server_hash;

/// A destination supplied by the Java client agent before it is redirected to
/// `MineBurp`'s private, one-use proxy port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentTarget {
    pub host: String,
    pub port: u16,
}

/// Correlates the session call made by the client with the upstream server
/// session call required by the encryption bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionJoinRequest {
    pub client_server_hash: String,
    pub upstream_server_hash: String,
}

#[async_trait]
pub trait SessionJoinProvider: Send + Sync + std::fmt::Debug {
    async fn join_server(&self, request: &SessionJoinRequest) -> Result<(), String>;
}

/// Opens a private interception route for one Minecraft connection. The agent
/// receives only the loopback port; it never receives proxy credentials.
#[async_trait]
pub trait TransparentRouteProvider: Send + Sync + std::fmt::Debug {
    async fn open_transparent_route(&self, target: TransparentTarget) -> Result<u16, String>;
}
