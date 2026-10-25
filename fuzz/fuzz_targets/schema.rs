//! Declarative schema packs: an arbitrary (validated) schema over arbitrary
//! bytes decodes or fails within its budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{DecodeContext, SchemaDefinition, decode_schema};

fuzz_target!(|input: (&str, &[u8])| {
    let (definition, bytes) = input;
    let Ok(schema) = serde_json::from_str::<SchemaDefinition>(definition) else {
        return;
    };
    let _ = decode_schema(&schema, bytes, DecodeContext::default());
});
