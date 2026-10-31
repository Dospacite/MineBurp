//! Model Context Protocol server for `MineBurp`.
//!
//! One server, two hosts. Inside the desktop app it sees the live proxy,
//! capture, and launchers through [`Host`] and is reached over a private Unix
//! socket; the `mineburp-mcp` binary bridges an MCP client's stdio to that
//! socket. When the app is not running, the same binary serves the same tools
//! against a `.mineburp` file directly ([`OfflineHost`]), and the live tools
//! say they need the app.
//!
//! Output is plain text designed to be cheap to read: one line per packet,
//! short connection ids that every tool accepts back, defaults left unsaid,
//! and explicit cursors instead of large pages.

mod host;
pub mod ops;
mod render;
mod rpc;
mod server;
#[cfg(unix)]
pub mod socket;
mod tools;

pub use host::{DESKTOP_ONLY, Host, OfflineHost};
pub use rpc::serve;
pub use server::McpServer;
