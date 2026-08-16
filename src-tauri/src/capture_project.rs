use std::{collections::HashMap, path::PathBuf, sync::Arc};

use mineburp_capture::SideChannelFrame;
use mineburp_core::{
    ConnectionSnapshot, ConnectionStatus, Disposition, PacketDetail, PacketSummary, ProtocolState,
    Target, TrafficSource, WireMetadata,
};
use mineburp_project::ProjectStore;
use mineburp_proxy::ProxyService;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug)]
struct ObservedFlow {
    id: Uuid,
    packet_count: u64,
    byte_count: u64,
}

/// How many frames one database transaction may carry.
const BATCH_LIMIT: usize = 256;

/// Persists passive capture on one blocking worker so `SQLite` and payload
/// compression never stall Tauri's event loop.
///
/// Frames are drained in batches: a busy Minecraft client emits hundreds of TCP
/// segments a second, and committing a transaction per segment made the writer
/// slower than the capture backend, so the channel filled and frames were
/// silently dropped.
pub fn spawn_capture_project_writer(
    project: Arc<RwLock<Option<ProjectStore>>>,
    proxy: ProxyService,
) -> mpsc::Sender<SideChannelFrame> {
    let (sender, mut receiver) = mpsc::channel(16_384);
    tauri::async_runtime::spawn_blocking(move || {
        let mut flows: HashMap<(PathBuf, String), ObservedFlow> = HashMap::new();
        let mut sequence = 0_u64;
        let mut pending = Vec::with_capacity(BATCH_LIMIT);
        while let Some(frame) = receiver.blocking_recv() {
            pending.push(frame);
            while pending.len() < BATCH_LIMIT {
                match receiver.try_recv() {
                    Ok(next) => pending.push(next),
                    Err(_) => break,
                }
            }
            let Some(store) = project.read().clone() else {
                pending.clear();
                continue;
            };
            // Asked once per batch rather than once per frame: the answer only
            // changes when a session starts or stops.
            let proxied_ports = proxy.listener_ports();
            let mut details = Vec::with_capacity(pending.len());
            let mut touched: HashMap<Uuid, ConnectionSnapshot> = HashMap::new();
            for frame in pending.drain(..) {
                if is_proxied_loopback(&frame, &proxied_ports) {
                    continue;
                }
                sequence = sequence.saturating_add(1);
                let (detail, snapshot) = build_detail(&store, &frame, sequence, &mut flows);
                touched.insert(snapshot.id, snapshot);
                details.push(detail);
            }
            // One connection row per flow per batch rather than per frame: the
            // counters are cumulative, so only the last value matters.
            for snapshot in touched.values() {
                let _ = store.save_connection(snapshot);
            }
            let _ = store.insert_packets(&details);
        }
    });
    sender
}

/// Whether this frame is the client's leg of a stream the proxy is decrypting.
///
/// Capture attributes the client's loopback socket to the Minecraft JVM just
/// like any other connection, so without this every decrypted packet also
/// appeared as an unreadable ciphertext row.
fn is_proxied_loopback(frame: &SideChannelFrame, proxied_ports: &[u16]) -> bool {
    if proxied_ports.is_empty() {
        return false;
    }
    [&frame.flow.local_address, &frame.flow.remote_address]
        .into_iter()
        .any(|address| loopback_port(address).is_some_and(|port| proxied_ports.contains(&port)))
}

fn loopback_port(address: &str) -> Option<u16> {
    let (host, port) = address.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.starts_with("127.") || host == "::1" {
        port.parse().ok()
    } else {
        None
    }
}

fn build_detail(
    store: &ProjectStore,
    frame: &SideChannelFrame,
    sequence: u64,
    flows: &mut HashMap<(PathBuf, String), ObservedFlow>,
) -> (PacketDetail, ConnectionSnapshot) {
    let flow_key = format!(
        "{}|{}|{}",
        frame.protocol, frame.flow.local_address, frame.flow.remote_address
    );
    let key = (store.info().path.clone(), flow_key);
    let observed = flows.entry(key).or_insert_with(|| ObservedFlow {
        id: Uuid::new_v4(),
        packet_count: 0,
        byte_count: 0,
    });
    observed.packet_count = observed.packet_count.saturating_add(1);
    observed.byte_count = observed
        .byte_count
        .saturating_add(frame.payload.len() as u64);

    let target = target_from_authority(&frame.flow.remote_address);
    let snapshot = ConnectionSnapshot {
        id: observed.id,
        target,
        listener_address: frame.flow.local_address.clone(),
        status: ConnectionStatus::Active,
        state: ProtocolState::Opaque,
        protocol_version: None,
        minecraft_version: None,
        loader: None,
        compression_threshold: None,
        encrypted_client: false,
        encrypted_server: false,
        packet_count: observed.packet_count,
        byte_count: observed.byte_count,
        last_error: None,
    };
    let size = frame.payload.len();
    let detail = PacketDetail {
        summary: PacketSummary {
            id: 0,
            sequence,
            connection_id: observed.id,
            timestamp_micros: frame.timestamp_micros,
            source: TrafficSource::SideChannel,
            direction: frame.direction,
            state: ProtocolState::Opaque,
            protocol_version: None,
            packet_id: None,
            name: Some(format!("{} payload", frame.protocol.to_uppercase())),
            channel: None,
            loader: None,
            size,
            disposition: Disposition::Observed,
            flow: Some(frame.flow.clone()),
        },
        logical_bytes: frame.payload.clone(),
        decoded: None,
        decode_error: None,
        wire: WireMetadata {
            frame_length: size,
            logical_length: size,
            compressed: false,
            encrypted: false,
            truncated: false,
        },
    };
    (detail, snapshot)
}

fn target_from_authority(authority: &str) -> Target {
    if let Some(ipv6) = authority.strip_prefix('[')
        && let Some((host, port)) = ipv6.rsplit_once("]:")
    {
        return Target {
            host: host.to_owned(),
            port: port.parse().unwrap_or_default(),
        };
    }
    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "0"));
    Target {
        host: host.to_owned(),
        port: port.parse().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use mineburp_core::{Direction, FlowMetadata};

    use super::*;

    fn frame(local: &str, remote: &str) -> SideChannelFrame {
        SideChannelFrame {
            id: Uuid::nil(),
            timestamp_micros: 0,
            direction: Direction::ClientToServer,
            protocol: "tcp".into(),
            flow: FlowMetadata {
                transport: "tcp".into(),
                local_address: local.into(),
                remote_address: remote.into(),
                process_id: None,
                stream_id: None,
            },
            payload: Bytes::from_static(&[0]),
        }
    }

    #[test]
    fn suppresses_only_the_loopback_leg_of_a_proxied_stream() {
        let ports = [39_501_u16];
        assert!(is_proxied_loopback(
            &frame("127.0.0.1:54321", "127.0.0.1:39501"),
            &ports
        ));
        assert!(is_proxied_loopback(
            &frame("[::1]:39501", "[::1]:54321"),
            &ports
        ));
        // A remote server that happens to use the same port number is not ours.
        assert!(!is_proxied_loopback(
            &frame("192.168.1.20:54321", "203.0.113.5:39501"),
            &ports
        ));
        assert!(!is_proxied_loopback(
            &frame("127.0.0.1:54321", "127.0.0.1:25565"),
            &ports
        ));
        assert!(!is_proxied_loopback(
            &frame("127.0.0.1:54321", "127.0.0.1:39501"),
            &[]
        ));
    }

    #[test]
    fn parses_ipv4_and_ipv6_authorities() {
        assert_eq!(
            target_from_authority("127.0.0.1:25565"),
            Target {
                host: "127.0.0.1".into(),
                port: 25_565
            }
        );
        assert_eq!(
            target_from_authority("[::1]:443"),
            Target {
                host: "::1".into(),
                port: 443
            }
        );
    }
}
