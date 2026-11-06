//! Passive system-capture boundary.
//!
//! The desktop app consumes this trait while the concrete backend delegates raw
//! capture to a privilege-separated helper. Capture stays independent from
//! Minecraft launchers and active proxy sessions.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use mineburp_core::{Direction, FlowMetadata};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{RwLock, broadcast};
use uuid::Uuid;

mod import;
mod minecraft_filter;
mod minecraft_stream;
mod packet;
mod pcap;
mod pipeline;
mod reassembly;
pub mod setup;
mod synthetic;
mod system_backend;

pub use import::{ImportOptions, ImportSummary, import_capture};
pub use minecraft_stream::ImportedPacket;
pub use pcap::{CaptureReader, CaptureRecord, EXPORT_INTERFACE, MAX_RECORD, PcapngWriter};
pub use synthetic::{SYNTHETIC_LINKTYPE, SyntheticEndpoints, SyntheticStreams};
pub use system_backend::SystemCapture;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureCapabilities {
    pub available: bool,
    pub requires_elevation: bool,
    pub process_attribution: bool,
    pub backend: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Whether a capture is running right now; a capture whose dumpcap died
    /// reports `false` with the reason in `last_error`.
    pub running: bool,
    /// Every record dumpcap delivered, attributed or not.
    pub frames_seen: u64,
    pub bytes_seen: u64,
    /// Frames published for Minecraft flows, after reassembly.
    pub frames_emitted: u64,
    pub bytes_emitted: u64,
    /// Minecraft-flow frames that could not be kept.
    pub frames_dropped: u64,
    /// Frames waiting for their flow to be attributed.
    pub frames_held: u64,
    /// Retransmitted segments removed.
    pub retransmissions: u64,
    /// Segments that arrived out of order and were put back in sequence.
    pub reordered: u64,
    /// Sequence holes that never filled and were skipped.
    pub gaps: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelFrame {
    pub id: Uuid,
    pub timestamp_micros: i64,
    pub direction: Direction,
    pub protocol: String,
    pub flow: FlowMetadata,
    pub payload: Bytes,
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("side-channel capture is unavailable: {0}")]
    Unavailable(String),
    #[error("capture backend failed: {0}")]
    Backend(String),
}

#[async_trait]
pub trait SideCapture: Send + Sync + std::fmt::Debug {
    fn capabilities(&self) -> CaptureCapabilities;
    fn subscribe(&self) -> broadcast::Receiver<SideChannelFrame>;
    async fn start(&self) -> Result<(), CaptureError>;
    async fn stop(&self) -> Result<(), CaptureError>;
    async fn stats(&self) -> CaptureStats;
}

#[derive(Debug, Clone)]
pub struct NoopCapture {
    stats: Arc<RwLock<CaptureStats>>,
    sender: broadcast::Sender<SideChannelFrame>,
}

impl Default for NoopCapture {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            stats: Arc::new(RwLock::new(CaptureStats::default())),
            sender,
        }
    }
}

/// Noop backend used on platforms without a native capture implementation.
/// On Windows this would require `WinPcap`/`Npcap` with `GetExtendedTcpTable`;
/// on macOS it would use `lsof`/`proc_pidinfo`. Both remain future work and
/// intentionally report unavailable rather than claiming attribution they cannot prove.
#[async_trait]
#[allow(clippy::doc_markdown)]
impl SideCapture for NoopCapture {
    fn capabilities(&self) -> CaptureCapabilities {
        CaptureCapabilities {
            available: false,
            requires_elevation: false,
            process_attribution: false,
            backend: "disabled".into(),
            reason: Some("no system-capture backend was configured".into()),
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<SideChannelFrame> {
        self.sender.subscribe()
    }

    async fn start(&self) -> Result<(), CaptureError> {
        Err(CaptureError::Unavailable(
            "install a platform capture backend and grant packet-capture permissions".into(),
        ))
    }

    async fn stop(&self) -> Result<(), CaptureError> {
        Ok(())
    }

    async fn stats(&self) -> CaptureStats {
        self.stats.read().await.clone()
    }
}
