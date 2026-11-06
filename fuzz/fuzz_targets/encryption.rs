#![no_main]
use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{EncryptionRequest, EncryptionResponse};
#[path = "common.rs"]
mod common;
fuzz_target!(|input: (u8, i32, &[u8])| {
    let (selector, raw, bytes) = input;
    let version = common::version(selector, raw).unwrap_or(raw);
    let _ = EncryptionRequest::decode_for(bytes, version);
    let _ = EncryptionResponse::decode(bytes, version);
});
