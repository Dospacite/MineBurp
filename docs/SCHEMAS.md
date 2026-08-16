# Schema packs

Schema packs decode custom payloads without loading plugin or mod code. MineBurp validates each pack before storing or activating it.

```json
{
  "manifest": {
    "id": "example.fabric.audit",
    "name": "Example Fabric audit messages",
    "version": "1.0.0",
    "minecraft_versions": ["1.21.1", "1.21.11", "26.2"],
    "loaders": ["fabric"]
  },
  "schemas": [
    {
      "name": "audit_request",
      "match": {
        "state": "login",
        "direction": "server_to_client",
        "packet_id": 4,
        "channel": "example:audit",
        "protocol_min": 393,
        "protocol_max": null
      },
      "fields": [
        { "name": "request_id", "type": "var_int" },
        { "name": "operation", "type": "string", "max_length": 128 },
        { "name": "body", "type": "bytes", "rest": true }
      ]
    }
  ]
}
```

Supported types are `bool`, `u8`, `i8`, `u16_be`, `i16_be`, `u32_be`, `i32_be`, `i64_be`, `f32_be`, `f64_be`, `var_int`, `var_long`, `uuid`, `string`, `bytes`, `array`, and `struct`.

For a recognized plugin-channel packet, decoding begins after its message/channel envelope. For raw packet-ID matches it begins at the packet body, after the packet ID VarInt. `_remaining_bytes` in the result makes incomplete definitions visible.

Limits are enforced for nesting, strings, byte blocks, and collection sizes. Duplicate schema or field names are rejected. Use narrow protocol ranges where a mod changes its payload between Minecraft releases.

