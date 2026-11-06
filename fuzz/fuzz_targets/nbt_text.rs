#![no_main]
use libfuzzer_sys::fuzz_target;
use mineburp_protocol::decoder::{DecoderOperation, transform};
fuzz_target!(|input: (bool, &[u8])| {
    let (named, bytes) = input;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let operation = if named {
        DecoderOperation::NamedNbtDecode
    } else {
        DecoderOperation::NbtDecode
    };
    if let Ok(result) = transform(operation, &hex) {
        let encoded = transform(
            if named {
                DecoderOperation::NamedNbtEncode
            } else {
                DecoderOperation::NbtEncode
            },
            &result.output,
        )
        .expect("rendered NBT must encode");
        let decoded = transform(
            if named {
                DecoderOperation::NamedNbtDecode
            } else {
                DecoderOperation::NbtDecode
            },
            &encoded.output,
        )
        .expect("encoded NBT must decode");
        assert_eq!(decoded.output, result.output);
    }
});
