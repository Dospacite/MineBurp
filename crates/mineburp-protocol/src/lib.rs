//! Minecraft Java protocol primitives and declarative decoding.

mod codec;
mod common;
mod crypto;
mod encryption;
mod handshake;
mod inspect;
mod layout;
mod nbt;
mod present;
mod protodef;
mod reader;
mod registry;
mod registry_names;
mod rewrite;
mod schema;
mod varint;

pub use codec::{FrameCodec, FrameDiagnostics, PacketFrame, ProtocolError};
pub use common::{CommonPacketDecode, decode_common_packet};
pub use crypto::MinecraftCipher;
pub use encryption::{EncryptionPacketError, EncryptionRequest, EncryptionResponse};
pub use handshake::{Handshake, HandshakeError, decode_handshake, encode_handshake};
pub use inspect::{
    Identification, PacketInsight, StreamPacket, identify_packet, inspect_logical, inspect_packet,
};
pub use layout::{FieldKind, FieldSpan, PacketLayout, encode_field, layout_logical};
pub use nbt::{NbtError, component_to_text, read_nbt};
pub use protodef::{
    DefinitionDecode, decode_packet as decode_with_definition, definition_protocols, has_definition,
};
pub use reader::Reader;
pub use registry::{PacketRegistry, ProtocolVersion};
pub use registry_names::{
    RegistryEntry, registry_entry, registry_keys, registry_name, registry_name_protocols,
};
pub use rewrite::{RewriteError, apply_edits};
pub use schema::{
    DecodeContext, FieldDefinition, MatchDefinition, SchemaDefinition, SchemaError, SchemaPack,
    SchemaPackManifest, TypeDefinition, decode_schema,
};
pub use varint::{decode_var_i32, decode_var_i64, encode_var_i32, encode_var_i64};
