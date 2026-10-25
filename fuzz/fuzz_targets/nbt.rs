//! The network-NBT reader: never panics, never reports more bytes than it was
//! given, and stays inside its node budget (enforced by libFuzzer's
//! `-rss_limit_mb` and `-timeout`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{component_to_text, read_nbt};

fuzz_target!(|bytes: &[u8]| {
    if let Ok((value, consumed)) = read_nbt(bytes) {
        assert!(consumed <= bytes.len());
        let _ = component_to_text(&value);
    }
});
