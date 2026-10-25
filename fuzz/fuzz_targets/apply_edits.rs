//! Replacement rules: any sequence of edits over any frame either applies or
//! reports an error.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mineburp_core::PacketEdit;
use mineburp_protocol::apply_edits;

#[path = "common.rs"]
mod common;

#[derive(Debug, Arbitrary)]
enum Edit {
    Frame(String),
    Range(u8, u8, String),
    Bytes(String, String, bool),
    Text(String, String, bool, bool),
    Regex(String, String, bool),
    Field(String, String),
    FieldReplace(String, String, String, bool),
}

impl From<Edit> for PacketEdit {
    fn from(edit: Edit) -> Self {
        match edit {
            Edit::Frame(bytes) => Self::Frame { bytes },
            Edit::Range(offset, length, bytes) => Self::Range {
                offset: usize::from(offset),
                length: usize::from(length),
                bytes,
            },
            Edit::Bytes(find, replace, all) => Self::Bytes { find, replace, all },
            Edit::Text(find, replace, all, case_insensitive) => Self::Text {
                find,
                replace,
                all,
                case_insensitive,
            },
            Edit::Regex(pattern, replace, all) => Self::Regex {
                pattern,
                replace,
                all,
            },
            Edit::Field(name, value) => Self::Field { name, value },
            Edit::FieldReplace(name, find, replace, regex) => Self::FieldReplace {
                name,
                find,
                replace,
                regex,
            },
        }
    }
}

fuzz_target!(
    |input: (common::State, bool, u8, i32, Vec<u8>, Vec<Edit>)| {
        let (state, server_to_client, selector, raw, frame, edits) = input;
        if edits.len() > 8 {
            return;
        }
        let edits: Vec<PacketEdit> = edits.into_iter().map(PacketEdit::from).collect();
        let _ = apply_edits(
            state.into(),
            common::direction(server_to_client),
            common::version(selector, raw),
            &frame,
            &edits,
        );
    }
);
