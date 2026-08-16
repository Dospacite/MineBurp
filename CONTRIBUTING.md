# Contributing

Keep dependencies pointing inward as described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Protocol code must not depend on Tauri, project storage, or launcher behavior.

Before submitting a change, run:

```bash
cargo fmt --all -- --check
cargo test --workspace --exclude mineburp-desktop
cargo check -p mineburp-capture
npm run build
```

On a Linux machine with the Tauri system prerequisites installed, also run `npm run tauri build -- --no-bundle`.

Packet mappings should cite an authoritative artifact in the change description. Add raw fixtures or round-trip tests for framing, encryption, and version-specific layouts. A decoder failure must preserve raw bytes and return a visible error.

Project schema changes require a forward-only migration and tests that open the previous schema. Never rewrite or delete a user's existing `.mineburp` file as part of migration failure handling.
