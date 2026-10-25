# Changelog

All notable changes to MineBurp are documented here. Follows Keep a Changelog and SemVer.

## [Unreleased]

### Added
- **Intercept** view: hold matching packets on decrypted connections, then forward, edit-and-forward, or drop them (Ctrl+Enter / Ctrl+Backspace). Dropped and edited packets are recorded with the `dropped` and `edited` results.
- **Save as** copies the open project — including the temporary session — to a new file (re-keyed with an optional passphrase) and continues recording there.
- Native open/save dialogs for projects and exports, and a recent-projects list.
- Ctrl/⌘+1–6 switches workbench views.

### Changed
- JSON export now runs in the backend, writes every matching packet to a file you choose, and reports how many it wrote.
- The project menu closes on Escape or an outside click and submits on Enter; creating a new project from the temporary session warns that its packets will be discarded.
- Capture status reads as a sentence ("Capture unavailable") instead of the internal state name.
- Messages in the corner dismiss themselves (errors after 10 s, confirmations after 4 s) unless hovered.

### Fixed
- Projects created by this build could not be reopened: migration 4 set `user_version = 4` while the supported schema version was still 3.
- JSON export was silently capped at 500 packets.

## [0.1.0] - 2026-09-02

### Added
- Stateful loopback proxy with VarInt framing, compression, state tracking and encryption bridging (AES-128/CFB8 + RSA).
- Opt-in Decrypt connections mode via Authlib Java agent (loopback-only, capability-protected, one-use routes).
- Automatic Minecraft client capture via dumpcap + procfs socket attribution (Linux) with SideCapture trait.
- SQLCipher + zstd `.mineburp` projects with connections, packets, rules, tabs, schema packs and WAL journaling.
- Repeater with bi-directional hex ↔ decoded field editing and live frame re-encoding.
- Replace rules (frame/range/bytes/text/regex/field) evaluated in order with filter expression language shared with history.
- Decoded fields for handshake/status/login/configuration + shape-based play decoders and declarative schema packs.
- Launcher adapters: Official, Prism, MultiMC, Modrinth, CurseForge with reversible JVM agent injection.
- Microsoft OAuth PKCE → Xbox Live → Minecraft Services (optional distributor-provided client ID).
- Project packet history with DB-side filters, keyset pagination and virtualized rendering.

### Changed
- Polling now visibility-aware (2 s active, 10 s hidden) and uses `Skip` missed-tick behavior to avoid IPC bursts.
- Base64 and hex formatting now chunked for large packets to avoid call-stack limits and O(n²) allocations.
- Added `ErrorBoundary` around each workbench view so a decoder crash no longer white-screens the app.
- Added OS keyring backend (`os-keyring` feature) for refresh tokens.

### Fixed
- Java agent javac `--release 8` warnings silenced via `-Xlint:-options`.
- Biome lint: 47 → 0 warnings via overrides for virtualized grids and correct CSS ordering.
- Frontend tests now pass (17 tests) and CI enforces them.
- Missing `MineBurp/` submodule removed and `libraries/`/`versions/`/`logs/` ignored correctly.

### Security
- `OsCredentialStore` persists refresh tokens in platform keychain instead of plaintext file.
- New indexes on `packets(disposition)` and `packets(size)` for filtered history queries.
- CSP remains `default-src 'self'` with `unsafe-inline` only for dynamic split-pane styles (documented).

[0.1.0]: https://github.com/mineburp/mineburp/releases/tag/v0.1.0
