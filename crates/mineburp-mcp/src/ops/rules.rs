//! Offline rule verdicts. Uses the same selector and rewrite implementations as the proxy.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mineburp_core::{
    Direction, Disposition, FilterExpression, PacketSummary, ProtocolState, ReplacementAction,
    ReplacementRule, TrafficSource,
};
use mineburp_protocol::{apply_edits, decode_var_i32, inspect_logical};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct RulePreview {
    pub matched: bool,
    pub action: ReplacementAction,
    pub protected: bool,
    pub logical_base64: String,
}
pub fn rule_preview(
    rule: &ReplacementRule,
    bytes: &[u8],
    state: ProtocolState,
    direction: Direction,
    protocol: Option<i32>,
    source: Option<PacketSummary>,
) -> Result<RulePreview, String> {
    let insight = inspect_logical(state, direction, bytes, protocol);
    let mut summary = source.unwrap_or(PacketSummary {
        id: 0,
        sequence: 0,
        connection_id: uuid::Uuid::nil(),
        timestamp_micros: 0,
        source: TrafficSource::Minecraft,
        direction,
        state,
        protocol_version: protocol,
        packet_id: None,
        name: None,
        channel: None,
        loader: None,
        size: bytes.len(),
        disposition: Disposition::Forwarded,
        flow: None,
    });
    summary.state = state;
    summary.direction = direction;
    summary.protocol_version = protocol;
    summary.size = bytes.len();
    summary.packet_id = decode_var_i32(bytes)
        .map_err(|e| e.to_string())?
        .map(|(id, _)| id);
    summary.name = insight.name;
    summary.channel = insight.channel;
    summary.loader = insight.loader;
    let matched = rule.expression.trim().is_empty()
        || FilterExpression::parse(&rule.expression)
            .map_err(|e| e.to_string())?
            .matches(&summary);
    let protected = rule.action == ReplacementAction::Rewrite
        && matches!(state, ProtocolState::Handshake | ProtocolState::Login);
    let output = if matched && !protected && rule.action == ReplacementAction::Rewrite {
        apply_edits(state, direction, protocol, bytes, &rule.edits).map_err(|e| e.to_string())?
    } else {
        bytes.to_vec()
    };
    Ok(RulePreview {
        matched,
        action: rule.action,
        protected,
        logical_base64: STANDARD.encode(output),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_rules_rewrite_and_drop_preview_obeys_the_selector() {
        let old = serde_json::json!({"id":uuid::Uuid::nil(),"name":"old","enabled":true,"expression":"id == 5","edits":[]});
        let mut rule: ReplacementRule = serde_json::from_value(old).unwrap();
        assert_eq!(rule.action, ReplacementAction::Rewrite);
        rule.action = ReplacementAction::Drop;
        let preview = rule_preview(
            &rule,
            &[5, 1],
            ProtocolState::Play,
            Direction::ClientToServer,
            Some(767),
            None,
        )
        .unwrap();
        assert!(preview.matched);
        assert_eq!(preview.action, ReplacementAction::Drop);
        assert_eq!(preview.logical_base64, STANDARD.encode([5, 1]));
        rule.expression = "id == 6".into();
        assert!(
            !rule_preview(
                &rule,
                &[5, 1],
                ProtocolState::Play,
                Direction::ClientToServer,
                Some(767),
                None
            )
            .unwrap()
            .matched
        );
    }
}
