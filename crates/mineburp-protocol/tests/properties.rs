//! Property tests for the byte-level primitives a hostile peer can reach.
//!
//! Each property is either a round trip or "never panics, never runs away":
//! the proxy decodes whatever a server sends, so the decoders must hold for
//! inputs nobody would write by hand.

use bytes::{Bytes, BytesMut};
use mineburp_core::{Direction, PacketEdit, ProtocolState};
use mineburp_protocol::{
    FrameCodec, PacketFrame, apply_edits, decode_var_i32, decode_var_i64, encode_var_i32,
    encode_var_i64, identify_packet, inspect_packet, layout_logical, read_nbt,
};
use proptest::prelude::*;

fn threshold() -> impl Strategy<Value = Option<i32>> {
    prop_oneof![Just(None), (-1_i32..300).prop_map(Some)]
}

fn frame() -> impl Strategy<Value = PacketFrame> {
    (any::<i32>(), prop::collection::vec(any::<u8>(), 0..600)).prop_map(|(id, body)| PacketFrame {
        id,
        body: Bytes::from(body),
        compressed: false,
        wire_length: 0,
    })
}

fn state() -> impl Strategy<Value = ProtocolState> {
    prop_oneof![
        Just(ProtocolState::Handshake),
        Just(ProtocolState::Status),
        Just(ProtocolState::Login),
        Just(ProtocolState::Configuration),
        Just(ProtocolState::Play),
    ]
}

fn direction() -> impl Strategy<Value = Direction> {
    prop_oneof![
        Just(Direction::ClientToServer),
        Just(Direction::ServerToClient)
    ]
}

/// Hex-ish text: mostly valid digits, sometimes the separators and junk an
/// operator might type.
fn hexish() -> impl Strategy<Value = String> {
    "[0-9a-fA-F ,:x]{0,16}"
}

fn edit() -> impl Strategy<Value = PacketEdit> {
    prop_oneof![
        hexish().prop_map(|bytes| PacketEdit::Frame { bytes }),
        (0_usize..64, 0_usize..64, hexish()).prop_map(|(offset, length, bytes)| {
            PacketEdit::Range {
                offset,
                length,
                bytes,
            }
        }),
        (hexish(), hexish(), any::<bool>()).prop_map(|(find, replace, all)| PacketEdit::Bytes {
            find,
            replace,
            all
        }),
        (".{0,6}", ".{0,6}", any::<bool>(), any::<bool>()).prop_map(
            |(find, replace, all, case_insensitive)| PacketEdit::Text {
                find,
                replace,
                all,
                case_insensitive,
            }
        ),
        ("[a-z.*+?()\\[\\]$1]{0,8}", ".{0,6}", any::<bool>()).prop_map(
            |(pattern, replace, all)| PacketEdit::Regex {
                pattern,
                replace,
                all,
            }
        ),
        ("[a-z _]{0,16}", ".{0,8}").prop_map(|(name, value)| PacketEdit::Field { name, value }),
        ("[a-z _]{0,16}", ".{0,4}", ".{0,4}", any::<bool>()).prop_map(
            |(name, find, replace, regex)| PacketEdit::FieldReplace {
                name,
                find,
                replace,
                regex,
            }
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn var_i32_round_trips(value in any::<i32>()) {
        let encoded = encode_var_i32(value);
        prop_assert!(encoded.len() <= 5);
        prop_assert_eq!(decode_var_i32(&encoded).unwrap(), Some((value, encoded.len())));
    }

    #[test]
    fn var_i64_round_trips(value in any::<i64>()) {
        let encoded = encode_var_i64(value);
        prop_assert!(encoded.len() <= 10);
        prop_assert_eq!(decode_var_i64(&encoded).unwrap(), Some((value, encoded.len())));
    }

    #[test]
    fn var_int_decoding_never_overreads(bytes in prop::collection::vec(any::<u8>(), 0..12)) {
        if let Ok(Some((_, length))) = decode_var_i32(&bytes) {
            prop_assert!(length <= 5 && length <= bytes.len());
        }
        if let Ok(Some((_, length))) = decode_var_i64(&bytes) {
            prop_assert!(length <= 10 && length <= bytes.len());
        }
    }

    /// Feeding a stream in arbitrary pieces yields the same frames as feeding
    /// it whole, which is what a TCP reader actually does.
    #[test]
    fn chunked_decoding_matches_whole_decoding(
        frames in prop::collection::vec(frame(), 1..6),
        threshold in threshold(),
        cuts in prop::collection::vec(1_usize..64, 0..40),
    ) {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(threshold);
        let mut stream = Vec::new();
        for frame in &frames {
            stream.extend_from_slice(&codec.encode(frame).unwrap());
        }

        let mut whole = BytesMut::from(stream.as_slice());
        let mut expected = Vec::new();
        while let Some(frame) = codec.try_decode(&mut whole).unwrap() {
            expected.push((frame.id, frame.body));
        }
        prop_assert!(whole.is_empty());
        prop_assert_eq!(
            expected.clone(),
            frames.iter().map(|frame| (frame.id, frame.body.clone())).collect::<Vec<_>>()
        );

        let mut buffer = BytesMut::new();
        let mut actual = Vec::new();
        let mut rest = stream.as_slice();
        let mut cuts = cuts.into_iter();
        while !rest.is_empty() {
            let take = cuts.next().unwrap_or(rest.len()).min(rest.len());
            buffer.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            while let Some(frame) = codec.try_decode(&mut buffer).unwrap() {
                actual.push((frame.id, frame.body));
            }
        }
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn frame_decoding_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        threshold in threshold(),
    ) {
        let mut codec = FrameCodec::new(4096);
        codec.set_compression_threshold(threshold);
        let mut buffer = BytesMut::from(bytes.as_slice());
        while let Ok(Some(_)) = codec.try_decode_with_diagnostics(&mut buffer) {}
    }

    #[test]
    fn nbt_reading_never_panics_or_overreads(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok((_, consumed)) = read_nbt(&bytes) {
            prop_assert!(consumed <= bytes.len());
        }
    }

    /// Lists and compounds are where amplification hides, so bias the input
    /// towards their tags.
    #[test]
    fn nested_nbt_stays_bounded(
        bytes in prop::collection::vec(prop_oneof![Just(9_u8), Just(10), Just(0), any::<u8>()], 0..256)
    ) {
        let started = std::time::Instant::now();
        let _ = read_nbt(&bytes);
        prop_assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn edits_never_panic(
        state in state(),
        direction in direction(),
        version in prop::option::of(prop_oneof![Just(47), Just(763), Just(767), Just(769)]),
        frame in prop::collection::vec(any::<u8>(), 0..64),
        edits in prop::collection::vec(edit(), 0..4),
    ) {
        let _ = apply_edits(state, direction, version, &frame, &edits);
    }

    #[test]
    fn inspection_never_panics(
        state in state(),
        direction in direction(),
        version in prop::option::of(prop_oneof![Just(5), Just(47), Just(340), Just(763), Just(767), Just(769)]),
        id in 0_i32..0x80,
        body in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let _ = identify_packet(state, direction, id, &body, version);
        let _ = inspect_packet(state, direction, id, &body, version);
        let mut logical = encode_var_i32(id).to_vec();
        logical.extend_from_slice(&body);
        let layout = layout_logical(state, direction, &logical, version);
        for field in &layout.fields {
            prop_assert!(field.offset + field.length <= logical.len());
        }
    }
}
