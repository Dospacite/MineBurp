use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Direction, Disposition, PacketSummary, ProtocolState, TrafficSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterField {
    Source,
    Direction,
    State,
    Protocol,
    PacketId,
    Name,
    Channel,
    Loader,
    Size,
    Disposition,
    Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    String(String),
    Integer(i64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FilterExpression {
    MatchAll,
    Predicate {
        field: FilterField,
        comparison: Comparison,
        value: FilterValue,
    },
    Not {
        expression: Box<Self>,
    },
    And {
        expressions: Vec<Self>,
    },
    Or {
        expressions: Vec<Self>,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FilterError {
    #[error("unknown filter field `{0}`")]
    UnknownField(String),
    #[error("invalid filter value `{0}`")]
    InvalidValue(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FilterParseError {
    #[error("empty filter expression")]
    Empty,
    #[error("expected `field operator value`, got `{0}`")]
    InvalidPredicate(String),
    #[error("unknown filter field `{0}`")]
    UnknownField(String),
    #[error("unknown filter operator `{0}`")]
    UnknownOperator(String),
    #[error("`{0}` requires an integer value")]
    ExpectedInteger(String),
}

impl FilterField {
    /// Field names accepted in a filter expression, for help text and hints.
    pub const NAMES: &'static [&'static str] = &[
        "source",
        "direction",
        "state",
        "protocol",
        "id",
        "name",
        "channel",
        "loader",
        "size",
        "disposition",
        "connection",
    ];

    /// Whether this field compares as a number rather than as text.
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        matches!(self, Self::Size | Self::Protocol | Self::PacketId)
    }

    /// Whether the packet may not carry this field at all. An absent field
    /// never matches, including under `!=`.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(
            self,
            Self::Name | Self::Channel | Self::Loader | Self::PacketId | Self::Protocol
        )
    }

    /// Whether values are stored as one of a closed set of enum names.
    #[must_use]
    pub const fn is_enumerated(self) -> bool {
        matches!(
            self,
            Self::Source | Self::Direction | Self::State | Self::Disposition
        )
    }
}

impl FilterExpression {
    /// Parses the operator-style filter language.
    ///
    /// Grammar: `field op value` joined by `&&` and `||`, where `||` binds
    /// loosest. `*` matches everything. Values may be quoted to contain spaces.
    /// Lives here rather than beside either consumer because the proxy matches
    /// expressions in memory while the project compiles the same expressions to
    /// SQL, and both must agree on exactly one grammar.
    pub fn parse(input: &str) -> Result<Self, FilterParseError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(FilterParseError::Empty);
        }
        if input == "*" {
            return Ok(Self::MatchAll);
        }
        let or_groups = split_outside_quotes(input, "||");
        let mut disjunction = Vec::with_capacity(or_groups.len());
        for group in or_groups {
            let predicates = split_outside_quotes(group, "&&")
                .into_iter()
                .map(parse_predicate)
                .collect::<Result<Vec<_>, _>>()?;
            disjunction.push(if predicates.len() == 1 {
                predicates.into_iter().next().expect("one predicate")
            } else {
                Self::And {
                    expressions: predicates,
                }
            });
        }
        Ok(if disjunction.len() == 1 {
            disjunction.into_iter().next().expect("one group")
        } else {
            Self::Or {
                expressions: disjunction,
            }
        })
    }

    #[must_use]
    pub fn matches(&self, packet: &PacketSummary) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Not { expression } => !expression.matches(packet),
            Self::And { expressions } => expressions.iter().all(|item| item.matches(packet)),
            Self::Or { expressions } => expressions.iter().any(|item| item.matches(packet)),
            Self::Predicate {
                field,
                comparison,
                value,
            } => match field {
                FilterField::Size => compare_integer(
                    i64::try_from(packet.size).unwrap_or(i64::MAX),
                    *comparison,
                    value,
                ),
                FilterField::Protocol => compare_optional_integer(
                    packet.protocol_version.map(i64::from),
                    *comparison,
                    value,
                ),
                FilterField::PacketId => {
                    compare_optional_integer(packet.packet_id.map(i64::from), *comparison, value)
                }
                FilterField::Name => {
                    compare_optional_text(packet.name.as_deref(), *comparison, value)
                }
                FilterField::Channel => {
                    compare_optional_text(packet.channel.as_deref(), *comparison, value)
                }
                FilterField::Loader => {
                    compare_optional_text(packet.loader.as_deref(), *comparison, value)
                }
                FilterField::Connection => {
                    compare_text(&packet.connection_id.to_string(), *comparison, value)
                }
                FilterField::Source => compare_text(enum_name(packet.source), *comparison, value),
                FilterField::Direction => {
                    compare_text(enum_name(packet.direction), *comparison, value)
                }
                FilterField::State => compare_text(enum_name(packet.state), *comparison, value),
                FilterField::Disposition => {
                    compare_text(enum_name(packet.disposition), *comparison, value)
                }
            },
        }
    }
}

fn parse_predicate(input: &str) -> Result<FilterExpression, FilterParseError> {
    let input = input.trim();
    let mut parts = input
        .splitn(3, char::is_whitespace)
        .filter(|part| !part.is_empty());
    let field_text = parts
        .next()
        .ok_or_else(|| FilterParseError::InvalidPredicate(input.into()))?;
    let operator_text = parts
        .next()
        .ok_or_else(|| FilterParseError::InvalidPredicate(input.into()))?;
    let value_text = parts
        .next()
        .ok_or_else(|| FilterParseError::InvalidPredicate(input.into()))?
        .trim();
    let field = parse_field(field_text)?;
    let comparison = match operator_text {
        "==" => Comparison::Equal,
        "!=" => Comparison::NotEqual,
        ">" => Comparison::Greater,
        ">=" => Comparison::GreaterOrEqual,
        "<" => Comparison::Less,
        "<=" => Comparison::LessOrEqual,
        "~" => Comparison::Contains,
        other => return Err(FilterParseError::UnknownOperator(other.into())),
    };
    let value = if field.is_numeric() {
        value_text
            .parse::<i64>()
            .map(FilterValue::Integer)
            .map_err(|_| FilterParseError::ExpectedInteger(field_text.into()))?
    } else {
        FilterValue::String(unquote(value_text).to_owned())
    };
    Ok(FilterExpression::Predicate {
        field,
        comparison,
        value,
    })
}

fn parse_field(input: &str) -> Result<FilterField, FilterParseError> {
    match input {
        "source" => Ok(FilterField::Source),
        "direction" | "dir" => Ok(FilterField::Direction),
        "state" | "phase" => Ok(FilterField::State),
        "protocol" | "version" => Ok(FilterField::Protocol),
        "id" | "packet.id" => Ok(FilterField::PacketId),
        "name" | "packet.name" => Ok(FilterField::Name),
        "channel" => Ok(FilterField::Channel),
        "loader" => Ok(FilterField::Loader),
        "size" | "length" => Ok(FilterField::Size),
        "disposition" | "action" => Ok(FilterField::Disposition),
        "connection" => Ok(FilterField::Connection),
        other => Err(FilterParseError::UnknownField(other.into())),
    }
}

fn unquote(input: &str) -> &str {
    if input.len() >= 2
        && ((input.starts_with('"') && input.ends_with('"'))
            || (input.starts_with('\'') && input.ends_with('\'')))
    {
        &input[1..input.len() - 1]
    } else {
        input
    }
}

fn split_outside_quotes<'a>(input: &'a str, separator: &str) -> Vec<&'a str> {
    let mut output = Vec::new();
    let mut quote = None;
    let mut start = 0;
    let bytes = input.as_bytes();
    let separator_bytes = separator.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => {
                quote = if quote == Some(bytes[index]) {
                    None
                } else if quote.is_none() {
                    Some(bytes[index])
                } else {
                    quote
                };
                index += 1;
            }
            _ if quote.is_none() && bytes[index..].starts_with(separator_bytes) => {
                output.push(&input[start..index]);
                index += separator_bytes.len();
                start = index;
            }
            _ => index += 1,
        }
    }
    output.push(&input[start..]);
    output
}

fn compare_optional_integer(
    actual: Option<i64>,
    comparison: Comparison,
    expected: &FilterValue,
) -> bool {
    actual.is_some_and(|value| compare_integer(value, comparison, expected))
}

fn compare_integer(actual: i64, comparison: Comparison, expected: &FilterValue) -> bool {
    let FilterValue::Integer(expected) = expected else {
        return false;
    };
    match comparison {
        Comparison::Equal => actual == *expected,
        Comparison::NotEqual => actual != *expected,
        Comparison::Greater => actual > *expected,
        Comparison::GreaterOrEqual => actual >= *expected,
        Comparison::Less => actual < *expected,
        Comparison::LessOrEqual => actual <= *expected,
        Comparison::Contains => actual.to_string().contains(&expected.to_string()),
    }
}

fn compare_optional_text(
    actual: Option<&str>,
    comparison: Comparison,
    expected: &FilterValue,
) -> bool {
    actual.is_some_and(|value| compare_text(value, comparison, expected))
}

fn compare_text(actual: &str, comparison: Comparison, expected: &FilterValue) -> bool {
    let FilterValue::String(expected) = expected else {
        return false;
    };
    match comparison {
        Comparison::Equal => actual.eq_ignore_ascii_case(expected),
        Comparison::NotEqual => !actual.eq_ignore_ascii_case(expected),
        // ASCII folding only, like `eq_ignore_ascii_case` above and like
        // SQLite's built-in `LOWER`: the project evaluates the same expression
        // in SQL, and a Unicode fold here would select different packets there.
        Comparison::Contains => actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        Comparison::Greater
        | Comparison::GreaterOrEqual
        | Comparison::Less
        | Comparison::LessOrEqual => false,
    }
}

fn enum_name<T>(value: T) -> &'static str
where
    T: EnumName,
{
    value.name()
}

trait EnumName {
    fn name(self) -> &'static str;
}

impl EnumName for Direction {
    fn name(self) -> &'static str {
        match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        }
    }
}

impl EnumName for ProtocolState {
    fn name(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Status => "status",
            Self::Login => "login",
            Self::Configuration => "configuration",
            Self::Play => "play",
            Self::Opaque => "opaque",
            Self::Closed => "closed",
        }
    }
}

impl EnumName for TrafficSource {
    fn name(self) -> &'static str {
        match self {
            Self::Minecraft => "minecraft",
            Self::SideChannel => "side_channel",
        }
    }
}

impl EnumName for Disposition {
    fn name(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Dropped => "dropped",
            Self::Edited => "edited",
            Self::Delayed => "delayed",
            Self::Replayed => "replayed",
            Self::Observed => "observed",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for FilterExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::{Disposition, PacketSummary, ProtocolState, TrafficSource};

    fn packet() -> PacketSummary {
        PacketSummary {
            id: 1,
            sequence: 1,
            connection_id: Uuid::nil(),
            timestamp_micros: 0,
            source: TrafficSource::Minecraft,
            direction: Direction::ClientToServer,
            state: ProtocolState::Play,
            protocol_version: Some(765),
            packet_id: Some(10),
            name: Some("custom_payload".into()),
            channel: Some("fabric:registry/sync".into()),
            loader: Some("fabric".into()),
            size: 128,
            disposition: Disposition::Forwarded,
            flow: None,
        }
    }

    #[test]
    fn evaluates_predicates() {
        let expression = FilterExpression::And {
            expressions: vec![
                FilterExpression::Predicate {
                    field: FilterField::Direction,
                    comparison: Comparison::Equal,
                    value: FilterValue::String("client_to_server".into()),
                },
                FilterExpression::Predicate {
                    field: FilterField::Channel,
                    comparison: Comparison::Contains,
                    value: FilterValue::String("fabric".into()),
                },
            ],
        };
        assert!(expression.matches(&packet()));
    }

    fn parse(input: &str) -> FilterExpression {
        FilterExpression::parse(input).expect("valid expression")
    }

    #[test]
    fn or_binds_looser_than_and() {
        let expression = parse("size > 1000 && state == play || name == custom_payload");
        // (false && true) || true
        assert!(expression.matches(&packet()));
        // Parentheses are not part of the grammar: the text is rejected rather
        // than silently read as a grouping.
        assert!(matches!(
            FilterExpression::parse("size > 1000 && (state == play || name == x)"),
            Err(FilterParseError::UnknownField(_))
        ));
    }

    #[test]
    fn accepts_aliases_quotes_and_match_all() {
        assert_eq!(parse("*"), FilterExpression::MatchAll);
        assert!(parse("dir == client_to_server").matches(&packet()));
        assert!(parse("phase == PLAY").matches(&packet()));
        assert!(parse("packet.id == 10").matches(&packet()));
        assert!(parse("version >= 765").matches(&packet()));
        let quoted = parse("channel == \"fabric:registry/sync\"");
        assert!(quoted.matches(&packet()));
        // A separator inside quotes belongs to the value.
        let expression = parse("name == 'a && b' || size == 128");
        assert!(expression.matches(&packet()));
        let FilterExpression::Or { expressions } = expression else {
            panic!("expected a disjunction");
        };
        assert_eq!(
            expressions[0],
            FilterExpression::Predicate {
                field: FilterField::Name,
                comparison: Comparison::Equal,
                value: FilterValue::String("a && b".into()),
            }
        );
    }

    #[test]
    fn reports_malformed_expressions() {
        assert_eq!(FilterExpression::parse("  "), Err(FilterParseError::Empty));
        assert!(matches!(
            FilterExpression::parse("colour == red"),
            Err(FilterParseError::UnknownField(_))
        ));
        assert!(matches!(
            FilterExpression::parse("size === 3"),
            Err(FilterParseError::UnknownOperator(_))
        ));
        assert!(matches!(
            FilterExpression::parse("size > big"),
            Err(FilterParseError::ExpectedInteger(_))
        ));
        assert!(matches!(
            FilterExpression::parse("size >"),
            Err(FilterParseError::InvalidPredicate(_))
        ));
    }

    #[test]
    fn an_absent_optional_field_never_matches_even_under_not_equal() {
        let mut bare = packet();
        bare.name = None;
        bare.packet_id = None;
        bare.protocol_version = None;
        assert!(!parse("name != chat").matches(&bare));
        assert!(!parse("name ~ ''").matches(&bare));
        assert!(!parse("id != 3").matches(&bare));
        assert!(!parse("id ~ 1").matches(&bare));
        assert!(!parse("protocol < 1000").matches(&bare));
        // Negation is plain boolean negation of that result.
        let negated = FilterExpression::Not {
            expression: Box::new(parse("name != chat")),
        };
        assert!(negated.matches(&bare));
    }

    #[test]
    fn text_comparisons_fold_ascii_only_and_never_order() {
        assert!(parse("name == CUSTOM_PAYLOAD").matches(&packet()));
        assert!(parse("name ~ PAYLOAD").matches(&packet()));
        assert!(!parse("name > a").matches(&packet()));
        assert!(!parse("name <= z").matches(&packet()));
        let mut accented = packet();
        accented.name = Some("Ärger".into());
        // `Ä` and `ä` are different code points to an ASCII fold.
        assert!(!parse("name ~ ärger").matches(&accented));
        assert!(parse("name ~ Ärger").matches(&accented));
        // The ASCII letters still fold around it.
        assert!(parse("name ~ ÄRGER").matches(&accented));
    }

    #[test]
    fn numeric_contains_is_a_digit_match() {
        assert!(parse("size ~ 12").matches(&packet()));
        assert!(parse("size ~ 28").matches(&packet()));
        assert!(!parse("size ~ 9").matches(&packet()));
        assert!(parse("size != 127").matches(&packet()));
    }

    #[test]
    fn empty_groups_follow_iterator_semantics() {
        assert!(
            FilterExpression::And {
                expressions: Vec::new()
            }
            .matches(&packet())
        );
        assert!(
            !FilterExpression::Or {
                expressions: Vec::new()
            }
            .matches(&packet())
        );
    }

    #[test]
    fn a_mistyped_value_never_matches() {
        let expression = FilterExpression::Predicate {
            field: FilterField::Size,
            comparison: Comparison::Equal,
            value: FilterValue::String("128".into()),
        };
        assert!(!expression.matches(&packet()));
        let expression = FilterExpression::Predicate {
            field: FilterField::Name,
            comparison: Comparison::Equal,
            value: FilterValue::Integer(1),
        };
        assert!(!expression.matches(&packet()));
    }
}
