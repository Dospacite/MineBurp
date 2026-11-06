//! Packet identification and inspection, which run on every relayed packet
//! and on every packet an operator opens.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{identify_packet, inspect_logical, inspect_packet};

#[path = "common.rs"]
mod common;

fuzz_target!(|input: (common::State, bool, u8, i32, u8, &[u8])| {
    let (state, server_to_client, selector, raw, id, body) = input;
    let state = state.into();
    let direction = common::direction(server_to_client);
    let version = common::version(selector, raw);
    let id = i32::from(id);
    let _ = identify_packet(state, direction, id, body, version);
    let _ = inspect_packet(state, direction, id, body, version);
    let _ = inspect_logical(state, direction, body, version);
});
