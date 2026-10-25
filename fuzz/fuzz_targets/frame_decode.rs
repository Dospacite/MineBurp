//! The frame codec: arbitrary bytes under an arbitrary threshold must decode
//! or fail cleanly, and feeding them in pieces must agree with feeding them
//! whole.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use mineburp_protocol::FrameCodec;

fuzz_target!(|input: (Option<i16>, u8, &[u8])| {
    let (threshold, chunk, bytes) = input;
    let mut codec = FrameCodec::new(1 << 20);
    codec.set_compression_threshold(threshold.map(i32::from));

    let mut whole = BytesMut::from(bytes);
    let mut expected = Vec::new();
    while let Ok(Some((frame, _))) = codec.try_decode_with_diagnostics(&mut whole) {
        expected.push(frame);
    }

    let chunk = usize::from(chunk.max(1));
    let mut buffer = BytesMut::new();
    let mut actual = Vec::new();
    'feed: for piece in bytes.chunks(chunk) {
        buffer.extend_from_slice(piece);
        loop {
            match codec.try_decode(&mut buffer) {
                Ok(Some(frame)) => actual.push(frame),
                Ok(None) => break,
                Err(_) => break 'feed,
            }
        }
    }
    // Errors depend only on complete prefixes, so both readers stop at the
    // same frame whether it fails or is merely incomplete.
    assert_eq!(expected.len(), actual.len());
    for (left, right) in expected.iter().zip(&actual) {
        assert_eq!((left.id, &left.body), (right.id, &right.body));
    }
});
