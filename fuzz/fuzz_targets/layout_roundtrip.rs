//! Field layouts: every span lies inside the frame, and re-encoding a span's
//! own value and splicing it back in yields a frame whose layout reads the
//! same value at the same place — the invariant field edits rely on.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{encode_field, layout_logical};

#[path = "common.rs"]
mod common;

fuzz_target!(|input: (common::State, bool, u8, i32, &[u8])| {
    let (state, server_to_client, selector, raw, logical) = input;
    let state = state.into();
    let direction = common::direction(server_to_client);
    let version = common::version(selector, raw);
    let layout = layout_logical(state, direction, logical, version);
    for span in &layout.fields {
        let end = span
            .offset
            .checked_add(span.length)
            .expect("span end overflows");
        assert!(
            end <= logical.len(),
            "span {span:?} outside a {} byte frame",
            logical.len()
        );
    }
    for span in &layout.fields {
        let Ok(encoded) = encode_field(span.kind, &span.value) else {
            continue;
        };
        let mut spliced = logical[..span.offset].to_vec();
        spliced.extend_from_slice(&encoded);
        spliced.extend_from_slice(&logical[span.offset + span.length..]);
        let relaid = layout_logical(state, direction, &spliced, version);
        if let Some(again) = relaid
            .fields
            .iter()
            .find(|field| field.offset == span.offset && field.name == span.name)
        {
            assert_eq!(
                again.value, span.value,
                "{} did not survive re-encoding",
                span.name
            );
        }
    }
});
