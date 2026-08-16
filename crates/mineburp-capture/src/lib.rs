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

mod minecraft_filter;
mod system_backend;

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
    pub frames_seen: u64,
    pub bytes_seen: u64,
    pub frames_emitted: u64,
    pub frames_dropped: u64,
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

#[async_trait]
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
