#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mineburp_protocol::{DecodeContext, SchemaDefinition, decode_schema};
#[derive(Debug, Arbitrary)]
enum Kind {
    Integer,
    String,
    Bytes(Option<u16>, bool),
    Array(Option<u16>, Option<u8>),
}
fuzz_target!(|input: (Vec<Kind>, &[u8])| {
    let (kinds, bytes) = input;
    let fields: Vec<_> = kinds.into_iter().take(128).enumerate().map(|(i, kind)| {
        let mut field = match kind {
            Kind::Integer => serde_json::json!({"type":"var_int"}),
            Kind::String => serde_json::json!({"type":"string"}),
            Kind::Bytes(length, rest) => serde_json::json!({"type":"bytes","length":length,"rest":rest}),
            Kind::Array(count, field) => serde_json::json!({"type":"array","count":count,"count_field":field.map(|n| format!("f{n}")),"item":{"type":"var_int"}}),
        };
        field["name"] = format!("f{i}").into();
        field
    }).collect();
    let schema: SchemaDefinition = serde_json::from_value(serde_json::json!({
        "name":"fuzz", "match":{"state":"play","direction":"client_to_server"}, "fields":fields
    }))
    .unwrap();
    let _ = decode_schema(&schema, bytes, DecodeContext::default());
});
