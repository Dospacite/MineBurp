use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use mineburp_core::{Direction, PacketSummary, ProtocolState};
use mineburp_protocol::PacketRegistry;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{CompiledFilter, FilterParseError};

/// What the operator has asked Intercept to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct InterceptSettings {
    pub enabled: bool,
    pub client_to_server: bool,
    pub server_to_client: bool,
    /// A filter expression selecting which packets to hold; empty holds all.
    pub expression: String,
    /// Keep-alives and pings pass through untouched — even while another frame
    /// in the same direction is held, because holding one for longer than the
    /// server's timeout (seconds, not minutes) disconnects the player.
    pub forward_keep_alive: bool,
    /// Forward a held frame unchanged once it has waited this long. `None`
    /// holds until the operator decides.
    pub auto_forward_after_ms: Option<u64>,
}

impl Default for InterceptSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            client_to_server: true,
            server_to_client: false,
            expression: String::new(),
            forward_keep_alive: true,
            auto_forward_after_ms: None,
        }
    }
}

/// Packet names that exist only to prove the connection is alive.
const LIVENESS_NAMES: [&str; 5] = [
    "keep_alive",
    "ping",
    "pong",
    "ping_request",
    "pong_response",
];

/// Whether a frame is a keep-alive or ping, judged by its id where the version's
/// table knows it and by its identified name otherwise.
///
/// The id is the better witness: a keep-alive carrying a random id is not
/// always recognisable from its body, and a name *containing* `keep_alive`
/// matched unrelated plugin channels.
#[must_use]
pub fn is_liveness_packet(
    state: ProtocolState,
    direction: Direction,
    packet_id: Option<i32>,
    protocol: Option<i32>,
    name: Option<&str>,
) -> bool {
    let by_name = |name: Option<&str>| name.is_some_and(|name| LIVENESS_NAMES.contains(&name));
    match (state, packet_id) {
        (ProtocolState::Configuration, Some(id)) => by_name(
            PacketRegistry::configuration_packet_name(direction, id, protocol),
        ),
        (ProtocolState::Play, Some(id)) => {
            match PacketRegistry::play_packet_name(direction, id, protocol) {
                Some(table_name) => by_name(Some(table_name)),
                None => by_name(name),
            }
        }
        _ => false,
    }
}

/// One frame waiting for the operator.
#[derive(Debug, Clone)]
pub struct InterceptedPacket {
    pub id: u64,
    pub summary: PacketSummary,
    pub target: String,
    pub logical_bytes: Bytes,
    pub held_at_micros: i64,
    /// When the frame will be forwarded automatically, if ever.
    pub deadline_micros: Option<i64>,
}

/// What happens to a held frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptDecision {
    Forward,
    /// Forward these logical bytes (packet id + body) instead.
    Replace(Bytes),
    Drop,
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    #[error("intercepted packet {0} is no longer held")]
    NotHeld(u64),
}

#[derive(Debug)]
struct Held {
    packet: InterceptedPacket,
    reply: oneshot::Sender<InterceptDecision>,
}

fn is_summary_liveness(summary: &PacketSummary) -> bool {
    is_liveness_packet(
        summary.state,
        summary.direction,
        summary.packet_id,
        summary.protocol_version,
        summary.name.as_deref(),
    )
}

/// The queue of frames Intercept is holding, and the rule for what it holds.
///
/// A held frame blocks only its own direction of its own connection: the
/// reader that produced it awaits the decision, which keeps the stream in
/// order without stalling the other direction or any other session.
#[derive(Debug, Default)]
pub struct Interceptor {
    settings: RwLock<(InterceptSettings, Option<CompiledFilter>)>,
    held: Mutex<BTreeMap<u64, Held>>,
    next_id: AtomicU64,
}

impl Interceptor {
    pub fn settings(&self) -> InterceptSettings {
        self.settings.read().0.clone()
    }

    /// Installs new settings. Turning Intercept off forwards everything held,
    /// so a connection is never left waiting on a queue nobody is looking at.
    pub fn set_settings(&self, settings: InterceptSettings) -> Result<(), FilterParseError> {
        let filter = match settings.expression.trim() {
            "" => None,
            expression => Some(CompiledFilter::parse(expression)?),
        };
        let enabled = settings.enabled;
        *self.settings.write() = (settings, filter);
        if !enabled {
            self.release_all();
        }
        Ok(())
    }

    /// Whether a frame in `state` with this summary should be held.
    ///
    /// Handshake and login frames never are: the proxy rewrites them itself
    /// (target address, encryption bridge, compression), and an operator edit
    /// there would desynchronise the session rather than test the server.
    pub fn should_hold(&self, summary: &PacketSummary) -> bool {
        let guard = self.settings.read();
        let (settings, filter) = &*guard;
        if !settings.enabled
            || !matches!(
                summary.state,
                ProtocolState::Status | ProtocolState::Configuration | ProtocolState::Play
            )
        {
            return false;
        }
        let direction_enabled = match summary.direction {
            mineburp_core::Direction::ClientToServer => settings.client_to_server,
            mineburp_core::Direction::ServerToClient => settings.server_to_client,
        };
        if !direction_enabled {
            return false;
        }
        if settings.forward_keep_alive && is_summary_liveness(summary) {
            return false;
        }
        filter.as_ref().is_none_or(|filter| filter.matches(summary))
    }

    /// Whether a frame read while its direction has a frame held may skip the
    /// queue. Only keep-alives and pings do, and only when the operator lets
    /// them through.
    pub fn bypasses_hold(
        &self,
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
        name: Option<&str>,
    ) -> bool {
        self.settings.read().0.forward_keep_alive
            && is_liveness_packet(state, direction, Some(packet_id), protocol, name)
    }

    /// How long a frame may be held before it is forwarded automatically.
    pub fn auto_forward_after(&self) -> Option<std::time::Duration> {
        self.settings
            .read()
            .0
            .auto_forward_after_ms
            .map(std::time::Duration::from_millis)
    }

    /// Queues a frame and returns the receiver its decision will arrive on.
    pub fn hold(
        &self,
        summary: PacketSummary,
        target: String,
        logical_bytes: Bytes,
        held_at_micros: i64,
        deadline_micros: Option<i64>,
    ) -> (u64, oneshot::Receiver<InterceptDecision>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (reply, receiver) = oneshot::channel();
        self.held.lock().insert(
            id,
            Held {
                packet: InterceptedPacket {
                    id,
                    summary,
                    target,
                    logical_bytes,
                    held_at_micros,
                    deadline_micros,
                },
                reply,
            },
        );
        (id, receiver)
    }

    pub fn resolve(&self, id: u64, decision: InterceptDecision) -> Result<(), InterceptError> {
        let held = self
            .held
            .lock()
            .remove(&id)
            .ok_or(InterceptError::NotHeld(id))?;
        // The reader may have gone away with its session; nothing to tell it.
        let _ = held.reply.send(decision);
        Ok(())
    }

    /// Forwards every held frame unchanged. Returns how many were released.
    pub fn release_all(&self) -> usize {
        let held = std::mem::take(&mut *self.held.lock());
        let count = held.len();
        for (_, entry) in held {
            let _ = entry.reply.send(InterceptDecision::Forward);
        }
        count
    }

    /// Removes a frame whose session ended, or whose deadline passed, while it
    /// was held. Reports whether it was still held.
    pub fn discard(&self, id: u64) -> bool {
        self.held.lock().remove(&id).is_some()
    }

    /// Held frames, oldest first.
    pub fn pending(&self) -> Vec<InterceptedPacket> {
        self.held
            .lock()
            .values()
            .map(|held| held.packet.clone())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.held.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use mineburp_core::{Disposition, TrafficSource};
    use uuid::Uuid;

    use super::*;

    fn summary(state: ProtocolState, direction: Direction, name: &str) -> PacketSummary {
        PacketSummary {
            id: 0,
            sequence: 1,
            connection_id: Uuid::nil(),
            timestamp_micros: 0,
            source: TrafficSource::Minecraft,
            direction,
            state,
            protocol_version: Some(767),
            packet_id: Some(1),
            name: Some(name.into()),
            channel: None,
            loader: None,
            size: 4,
            disposition: Disposition::Forwarded,
            flow: None,
        }
    }

    fn enabled(expression: &str) -> Interceptor {
        let interceptor = Interceptor::default();
        interceptor
            .set_settings(InterceptSettings {
                enabled: true,
                expression: expression.into(),
                ..InterceptSettings::default()
            })
            .unwrap();
        interceptor
    }

    #[test]
    fn holds_only_selected_play_traffic() {
        let interceptor = enabled("name ~ chat");
        let c2s = Direction::ClientToServer;
        assert!(interceptor.should_hold(&summary(ProtocolState::Play, c2s, "chat_message")));
        assert!(!interceptor.should_hold(&summary(ProtocolState::Play, c2s, "move_player")));
        assert!(!interceptor.should_hold(&summary(ProtocolState::Login, c2s, "chat_message")));
        assert!(!interceptor.should_hold(&summary(
            ProtocolState::Play,
            Direction::ServerToClient,
            "chat_message"
        )));
    }

    #[test]
    fn keep_alives_pass_by_default() {
        let interceptor = enabled("");
        let mut keep_alive = summary(ProtocolState::Play, Direction::ClientToServer, "keep_alive");
        // 1.21.1's serverbound keep_alive id.
        keep_alive.packet_id = Some(0x18);
        assert!(!interceptor.should_hold(&keep_alive));
        interceptor
            .set_settings(InterceptSettings {
                enabled: true,
                forward_keep_alive: false,
                ..InterceptSettings::default()
            })
            .unwrap();
        assert!(interceptor.should_hold(&keep_alive));
    }

    #[test]
    fn liveness_is_judged_by_id_where_the_table_knows_it() {
        // 1.21.4: serverbound keep_alive is 0x1a, chat_command is 0x05.
        let c2s = Direction::ClientToServer;
        assert!(is_liveness_packet(
            ProtocolState::Play,
            c2s,
            Some(0x1a),
            Some(769),
            None
        ));
        // A misleading name cannot make a tabulated packet a keep-alive.
        assert!(!is_liveness_packet(
            ProtocolState::Play,
            c2s,
            Some(0x05),
            Some(769),
            Some("keep_alive")
        ));
        // A plugin channel that merely mentions keep_alive is not one.
        assert!(!is_liveness_packet(
            ProtocolState::Play,
            c2s,
            Some(0x05),
            Some(1),
            Some("custom_payload:keep_alive")
        ));
        // Without a table the identified name decides, exactly.
        assert!(is_liveness_packet(
            ProtocolState::Play,
            c2s,
            Some(0x05),
            Some(1),
            Some("keep_alive")
        ));
        assert!(!is_liveness_packet(
            ProtocolState::Status,
            c2s,
            Some(1),
            Some(769),
            Some("ping_request")
        ));
    }

    #[tokio::test]
    async fn disabling_forwards_everything_held() {
        let interceptor = enabled("");
        let packet = summary(ProtocolState::Play, Direction::ClientToServer, "chat");
        let (_, first) = interceptor.hold(packet.clone(), "host:1".into(), Bytes::new(), 0, None);
        let (second_id, second) = interceptor.hold(packet, "host:1".into(), Bytes::new(), 0, None);
        interceptor
            .resolve(second_id, InterceptDecision::Drop)
            .unwrap();
        assert_eq!(second.await.unwrap(), InterceptDecision::Drop);
        assert_eq!(interceptor.pending_count(), 1);

        interceptor
            .set_settings(InterceptSettings::default())
            .unwrap();
        assert_eq!(first.await.unwrap(), InterceptDecision::Forward);
        assert_eq!(interceptor.pending_count(), 0);
        assert!(
            interceptor
                .resolve(second_id, InterceptDecision::Forward)
                .is_err()
        );
    }
}
