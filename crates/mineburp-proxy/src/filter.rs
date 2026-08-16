use mineburp_core::FilterExpression;
pub use mineburp_core::FilterParseError;

/// A filter expression prepared for repeated matching against live packets.
///
/// The grammar itself lives in `mineburp-core` beside the AST: the proxy
/// evaluates expressions in memory while the project compiles the same
/// expressions to SQL, and a second parser would let the two drift.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    expression: FilterExpression,
}

impl CompiledFilter {
    pub fn parse(input: &str) -> Result<Self, FilterParseError> {
        Ok(Self {
            expression: FilterExpression::parse(input)?,
        })
    }

    #[must_use]
    pub fn matches(&self, packet: &mineburp_core::PacketSummary) -> bool {
        self.expression.matches(packet)
    }
}

#[cfg(test)]
mod tests {
    use mineburp_core::{Direction, Disposition, PacketSummary, ProtocolState, TrafficSource};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn parses_compound_filter() {
        let filter =
            CompiledFilter::parse("direction == client_to_server && name ~ payload").unwrap();
        let packet = PacketSummary {
            id: 0,
            sequence: 1,
            connection_id: Uuid::nil(),
            timestamp_micros: 0,
            source: TrafficSource::Minecraft,
            direction: Direction::ClientToServer,
            state: ProtocolState::Play,
            protocol_version: Some(767),
            packet_id: Some(12),
            name: Some("custom_payload".into()),
            channel: None,
            loader: None,
            size: 4,
            disposition: Disposition::Forwarded,
            flow: None,
        };
        assert!(filter.matches(&packet));
    }
}
