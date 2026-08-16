use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use mineburp_core::{Direction, FlowMetadata};
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    CaptureCapabilities, CaptureError, CaptureStats, SideCapture, SideChannelFrame,
    minecraft_filter::MinecraftFlowFilter,
};

const MAX_CAPTURED_FRAME: usize = 16 * 1024 * 1024;

/// Minecraft-client TCP/UDP capture through Wireshark's privilege-separated
/// `dumpcap` helper and automatic process/socket attribution.
#[derive(Debug)]
pub struct SystemCapture {
    stats: Arc<RwLock<CaptureStats>>,
    sender: broadcast::Sender<SideChannelFrame>,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    child: Arc<Mutex<Option<Child>>>,
}

impl Default for SystemCapture {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(8_192);
        Self {
            stats: Arc::new(RwLock::new(CaptureStats::default())),
            sender,
            stop: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
            child: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl SideCapture for SystemCapture {
    fn capabilities(&self) -> CaptureCapabilities {
        let dumpcap = dumpcap_available();
        let attribution = MinecraftFlowFilter::supported();
        let available = dumpcap && attribution;
        CaptureCapabilities {
            available,
            requires_elevation: false,
            process_attribution: attribution,
            backend: "dumpcap-minecraft".into(),
            reason: if !attribution {
                Some(
                    "automatic Minecraft process attribution is currently available on Linux"
                        .into(),
                )
            } else if !dumpcap {
                Some(
                    "dumpcap is unavailable or cannot enumerate capture interfaces; install Wireshark/dumpcap and grant capture permission"
                        .into(),
                )
            } else {
                None
            },
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<SideChannelFrame> {
        self.sender.subscribe()
    }

    async fn start(&self) -> Result<(), CaptureError> {
        if self.worker.lock().is_some() {
            return Ok(());
        }
        if !MinecraftFlowFilter::supported() {
            return Err(CaptureError::Unavailable(
                "automatic Minecraft process attribution is not supported on this platform".into(),
            ));
        }
        if !dumpcap_available() {
            return Err(CaptureError::Unavailable(
                "dumpcap could not access a capture interface".into(),
            ));
        }

        let mut child = Command::new("dumpcap")
            .args([
                "-i",
                "any",
                "-F",
                "pcap",
                "-q",
                "-f",
                "tcp or udp",
                "-w",
                "-",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| CaptureError::Backend(error.to_string()))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CaptureError::Backend("dumpcap did not provide its capture stream".into())
        })?;
        self.stop.store(false, Ordering::Release);
        *self.stats.write() = CaptureStats::default();
        *self.child.lock() = Some(child);

        let stats = self.stats.clone();
        let sender = self.sender.clone();
        let stop = self.stop.clone();
        let child = self.child.clone();
        let worker = match std::thread::Builder::new()
            .name("mineburp-system-capture".into())
            .spawn(move || capture_stream(stdout, &stats, &sender, &stop, &child))
        {
            Ok(worker) => worker,
            Err(error) => {
                if let Some(mut process) = self.child.lock().take() {
                    let _ = process.kill();
                    let _ = process.wait();
                }
                return Err(CaptureError::Backend(error.to_string()));
            }
        };
        *self.worker.lock() = Some(worker);
        Ok(())
    }

    async fn stop(&self) -> Result<(), CaptureError> {
        self.stop.store(true, Ordering::Release);
        if let Some(child) = self.child.lock().as_mut() {
            let _ = child.kill();
        }
        let worker = self.worker.lock().take();
        if let Some(worker) = worker {
            tokio::task::spawn_blocking(move || worker.join())
                .await
                .map_err(|error| CaptureError::Backend(error.to_string()))?
                .map_err(|_| CaptureError::Backend("capture thread panicked".into()))?;
        }
        Ok(())
    }

    async fn stats(&self) -> CaptureStats {
        self.stats.read().clone()
    }
}

impl Drop for SystemCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(child) = self.child.lock().as_mut() {
            let _ = child.kill();
        }
    }
}

fn dumpcap_available() -> bool {
    Command::new("dumpcap")
        .arg("-D")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn capture_stream(
    mut input: impl io::Read,
    stats: &RwLock<CaptureStats>,
    sender: &broadcast::Sender<SideChannelFrame>,
    stop: &AtomicBool,
    child: &Mutex<Option<Child>>,
) {
    if let Err(error) = read_pcap(&mut input, stats, sender, stop) {
        record_capture_error(stats, &error);
    }
    if let Some(mut process) = child.lock().take() {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn read_pcap(
    input: &mut impl io::Read,
    stats: &RwLock<CaptureStats>,
    sender: &broadcast::Sender<SideChannelFrame>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut header = [0_u8; 24];
    input.read_exact(&mut header)?;
    let byte_order = ByteOrder::from_magic(header[..4].try_into().expect("four-byte slice"))?;
    let linktype = byte_order.u32(&header[20..24]);
    let mut minecraft_flows = MinecraftFlowFilter::new();

    while !stop.load(Ordering::Acquire) {
        let mut record = [0_u8; 16];
        match input.read_exact(&mut record) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let captured_length = byte_order.u32(&record[8..12]) as usize;
        if captured_length > MAX_CAPTURED_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture frame exceeded the configured limit",
            ));
        }
        let mut frame = vec![0_u8; captured_length];
        input.read_exact(&mut frame)?;
        stats.write().frames_seen += 1;
        let Some(parsed) = parse_frame(linktype, &frame) else {
            continue;
        };
        let outgoing = parsed
            .outgoing
            .unwrap_or(parsed.source_port >= 32_768 && parsed.destination_port < 32_768);
        let direction = if outgoing {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let (local, remote, local_port, remote_port) = if outgoing {
            (
                parsed.source,
                parsed.destination,
                parsed.source_port,
                parsed.destination_port,
            )
        } else {
            (
                parsed.destination,
                parsed.source,
                parsed.destination_port,
                parsed.source_port,
            )
        };
        let Some(process_id) = minecraft_flows.owner(parsed.transport, local_port, remote_port)
        else {
            continue;
        };
        let payload = Bytes::copy_from_slice(parsed.payload);
        {
            let mut current = stats.write();
            current.bytes_seen += payload.len() as u64;
            current.frames_emitted += 1;
        }
        let _ = sender.send(SideChannelFrame {
            id: Uuid::new_v4(),
            timestamp_micros: now_micros(),
            direction,
            protocol: parsed.transport.into(),
            flow: FlowMetadata {
                transport: parsed.transport.into(),
                local_address: local,
                remote_address: remote,
                process_id: Some(process_id),
                stream_id: None,
            },
            payload,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn from_magic(magic: [u8; 4]) -> io::Result<Self> {
        match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => Ok(Self::Little),
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => Ok(Self::Big),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dumpcap returned an unsupported capture stream",
            )),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes: [u8; 4] = bytes.try_into().expect("four-byte field");
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

struct ParsedFrame<'a> {
    source: String,
    destination: String,
    source_port: u16,
    destination_port: u16,
    transport: &'static str,
    payload: &'a [u8],
    outgoing: Option<bool>,
}

fn parse_frame(linktype: u32, frame: &[u8]) -> Option<ParsedFrame<'_>> {
    let (network_offset, ether_type, outgoing) = match linktype {
        1 => (
            14,
            u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]),
            None,
        ),
        113 => (
            16,
            u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]),
            Some(u16::from_be_bytes([*frame.first()?, *frame.get(1)?]) == 4),
        ),
        276 => (
            20,
            u16::from_be_bytes([*frame.first()?, *frame.get(1)?]),
            Some(*frame.get(10)? == 4),
        ),
        _ => return None,
    };
    let mut parsed = match ether_type {
        0x0800 => parse_ipv4(frame.get(network_offset..)?)?,
        0x86dd => parse_ipv6(frame.get(network_offset..)?)?,
        _ => return None,
    };
    parsed.outgoing = outgoing;
    Some(parsed)
}

fn parse_ipv4(packet: &[u8]) -> Option<ParsedFrame<'_>> {
    let header_length = usize::from(packet.first()? & 0x0f) * 4;
    let protocol = *packet.get(9)?;
    let source = Ipv4Addr::new(
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    );
    let destination = Ipv4Addr::new(
        *packet.get(16)?,
        *packet.get(17)?,
        *packet.get(18)?,
        *packet.get(19)?,
    );
    parse_transport(
        packet.get(header_length..)?,
        protocol,
        &source.to_string(),
        &destination.to_string(),
    )
}

fn parse_ipv6(packet: &[u8]) -> Option<ParsedFrame<'_>> {
    let protocol = *packet.get(6)?;
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    parse_transport(
        packet.get(40..)?,
        protocol,
        &source.to_string(),
        &destination.to_string(),
    )
}

fn parse_transport<'a>(
    segment: &'a [u8],
    protocol: u8,
    source: &str,
    destination: &str,
) -> Option<ParsedFrame<'a>> {
    let source_port = u16::from_be_bytes([*segment.first()?, *segment.get(1)?]);
    let destination_port = u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]);
    let (transport, payload_offset) = match protocol {
        6 => ("tcp", usize::from(segment.get(12)? >> 4) * 4),
        17 => ("udp", 8),
        _ => return None,
    };
    Some(ParsedFrame {
        source: format_address(source, source_port),
        destination: format_address(destination, destination_port),
        source_port,
        destination_port,
        transport,
        payload: segment.get(payload_offset..).unwrap_or_default(),
        outgoing: None,
    })
}

fn format_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn record_capture_error(stats: &RwLock<CaptureStats>, _error: &io::Error) {
    stats.write().frames_dropped += 1;
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_sll2_outgoing_ipv4_tcp_payload() {
        let mut frame = vec![0_u8; 20 + 20 + 20 + 3];
        frame[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[10] = 4;
        let ip = 20;
        frame[ip] = 0x45;
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&[127, 0, 0, 1]);
        frame[ip + 16..ip + 20].copy_from_slice(&[1, 2, 3, 4]);
        let tcp = ip + 20;
        frame[tcp..tcp + 2].copy_from_slice(&50_000_u16.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&25565_u16.to_be_bytes());
        frame[tcp + 12] = 5 << 4;
        frame[tcp + 20..].copy_from_slice(b"abc");

        let parsed = parse_frame(276, &frame).expect("parsed frame");
        assert_eq!(parsed.outgoing, Some(true));
        assert_eq!(parsed.source, "127.0.0.1:50000");
        assert_eq!(parsed.destination, "1.2.3.4:25565");
        assert_eq!(parsed.payload, b"abc");
    }

    #[test]
    fn identifies_sll_incoming_ipv4_udp_payload() {
        let mut frame = vec![0_u8; 16 + 20 + 8 + 3];
        frame[0..2].copy_from_slice(&0_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = 16;
        frame[ip] = 0x45;
        frame[ip + 9] = 17;
        frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
        frame[ip + 16..ip + 20].copy_from_slice(&[127, 0, 0, 1]);
        let udp = ip + 20;
        frame[udp..udp + 2].copy_from_slice(&53_u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&50_000_u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&11_u16.to_be_bytes());
        frame[udp + 8..].copy_from_slice(b"dns");

        let parsed = parse_frame(113, &frame).expect("parsed frame");
        assert_eq!(parsed.outgoing, Some(false));
        assert_eq!(parsed.source, "1.2.3.4:53");
        assert_eq!(parsed.destination, "127.0.0.1:50000");
        assert_eq!(parsed.payload, b"dns");
    }

    #[test]
    fn rejects_an_unknown_pcap_magic() {
        assert!(ByteOrder::from_magic([0, 1, 2, 3]).is_err());
    }
}
