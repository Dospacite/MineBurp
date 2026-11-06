//! Shared domain contracts for `MineBurp`.
//!
//! This crate deliberately contains no networking, persistence, or UI logic. Every
//! boundary crate speaks these types so protocol evolution stays independent from
//! storage and presentation concerns.

mod filter;
mod model;

pub use filter::{
    Comparison, FilterError, FilterExpression, FilterField, FilterParseError, FilterValue,
};
pub use model::{
    ConnectionId, ConnectionSnapshot, ConnectionStatus, Direction, Disposition, FlowMetadata,
    PacketDetail, PacketEdit, PacketId, PacketSummary, ProtocolState, RepeaterAttempt,
    RepeaterEditHistory, RepeaterRevision, RepeaterTab, ReplacementAction, ReplacementRule, Target,
    TrafficSource, WireMetadata,
};

pub mod research;

pub mod scope;
