#![no_main]
use libfuzzer_sys::fuzz_target;
use mineburp_protocol::decoder::{DecoderOperation::*, transform};
fuzz_target!(|input: (u8, &str)| {
    let (selector, text) = input;
    let operations = [
        HexToText,
        TextToHex,
        Base64ToHex,
        HexToBase64,
        NormalizeHex,
        VarIntDecode,
        VarIntEncode,
        VarLongDecode,
        VarLongEncode,
        StringDecode,
        StringEncode,
        UuidDecode,
        UuidEncode,
        U16BeDecode,
        U16LeDecode,
        U32BeDecode,
        U32LeDecode,
        U64BeDecode,
        U64LeDecode,
        U16BeEncode,
        U16LeEncode,
        U32BeEncode,
        U32LeEncode,
        U64BeEncode,
        U64LeEncode,
        ZlibDecompress,
        ZlibCompress,
        GzipDecompress,
        GzipCompress,
        NbtDecode,
        NbtEncode,
        NamedNbtDecode,
        NamedNbtEncode,
        JsonPretty,
    ];
    let _ = transform(operations[usize::from(selector) % operations.len()], text);
});
