# Changelog

All notable changes to MineBurp are documented here. Follows Keep a Changelog and SemVer.

## [Unreleased]

### Added

- Project findings with bounded evidence, severity/status tracking, desktop and MCP CRUD, and Markdown/HTML reporting.
- Minecraft Decoder in the right sidebar, with chained hex/text/Base64, VarInt/VarLong, Minecraft string, UUID, integer, compression, NBT, and JSON transforms.
- Channel explorer, Ctrl/Cmd+K command palette, packet selection actions, payload generators, decoded-field history columns, and traffic presets.
- Project-backed Intruder and Sequencer configuration, samples, analysis, and results, with autosave and flush before project changes/exit.
- Repeater edit undo/redo, original comparison, and named revisions stored with saved tabs.
- Automatic drop rules in Replace, including selector preview, history recording, and MCP `behavior="drop"` support.
- **MCP server**: `mineburp-mcp` exposes 19 tools (history, decoding, frame rewriting, rules, annotations, saved filters, schema packs, project import/export, Intercept, Repeater, network shaping, capture, launchers) over stdio. It bridges to the running app through a user-only Unix socket (disable with `MINEBURP_MCP=0`) or works offline on a project file. Changes made through it refresh the UI.
- **Intercept** view: hold matching packets on decrypted connections, then forward, edit-and-forward, or drop them (Ctrl+Enter / Ctrl+Backspace). Dropped and edited packets are recorded with the `dropped` and `edited` results.
- **Save as** copies the open project — including the temporary session — to a new file (re-keyed with an optional passphrase) and continues recording there.
- Native open/save dialogs for projects and exports, and a recent-projects list.
- Ctrl/⌘+1–0 switches workbench views.
- Click the packet list's `#` header to switch between newest first and oldest first. The database orders the whole matching history, so oldest first starts at the first packet ever captured, not the oldest one loaded. "Load newer packets" pages forward, new traffic is appended once the end is loaded, and the choice is remembered with the column settings.
- **Go to packet** (row menu or Ctrl/⌘+G) selects a packet by its `#` number and scrolls to it, loading the rows around it when it is not loaded. Choosing a bookmark does the same.
- Repeater: NBT fields are shown and edited as JSON (`{"text": "hi", "bold": 1}`) instead of raw hex. Values keep the NBT type they had, new ones are inferred, and SNBT suffixes (`5b`, `1.5f`, `[B; 1, 2]`) force a type. NBT over 256 KiB, or NBT that would not survive the round trip, stays hex.

### Changed
- JSON export now runs in the backend, writes every matching packet to a file you choose, and reports how many it wrote.
- The project menu closes on Escape or an outside click and submits on Enter; creating a new project from the temporary session warns that its packets will be discarded.
- Capture status reads as a sentence ("Capture unavailable") instead of the internal state name.
- Messages in the corner dismiss themselves (errors after 10 s, confirmations after 4 s) unless hovered.

### Fixed
- Bound hostile NBT text rendering and use indexed compound/template lookups; packets exceeding the work budget remain hex.
- Reject overflowing registry holder values and safely identify the minimum signed time value.
- Edit modern text components as NBT, including protocol 776; validate legacy JSON components before exposing string spans.
- Look up replacement-rule fields only through the requested span, skipping buffer and NBT presentation for preceding fields.
- Reject invalid characters in Repeater hex field edits using the same strict parser as replacement rules.
- Reject schema packs with missing collection lengths, invalid count references, or reversed protocol ranges.
- Slow project writes no longer stall live proxy traffic or route creation; persistence overflow reports dropped rows.
- Intercept backlogs account for frame overhead and drain without repeated scans.
- Queued compression and login/configuration transitions preserve decoding and packet order.
- Keep-alives overtaking held packets now apply rewrite rules and record edits.
- Disabling Intercept cannot strand a concurrently arriving held packet.
- Upstream connects time out and stop on cancellation; stopped listening routes publish Closed and connecting routes count toward admission limits.
- The client-assistance broker retries accept errors instead of stopping.
- Replacement rules targeting absent fields no longer log a warning per packet.
- Serialize decoded-field edits in Repeater and Intercept, commit multiline fields with Ctrl/Cmd+Enter, and await pending edits before sending.
- Save dirty Repeater tabs before project changes and closing; retain Intercept drafts when held packets leave the queue and offer sending those drafts to Repeater.
- Reload project-scoped rules and annotations after external edits, and guard rule writes with the expected project path.
- Isolate traffic append and connection updates, memoize persistent tools and hex parsing, and stabilize history-table callbacks.
- Scope Repeater shortcuts to its editor, preserve native text undo, coalesce hex typing into undo steps, and support arrow-key tab navigation with tabpanel semantics.
- Preserve connection lists after failed status queries, prevent overlapping status refreshes, and reset packet history on project changes.
- Keep the launcher agent in a stable per-user path across AppImage launches; report stale configured arguments.
- Enable Prism/MultiMC JVM overrides with inherited global flags and restore original launcher settings on removal; preserve official launcher defaults.
- Validate and persist replacement rules before applying them, serialize MCP rule edits, and protect temporary captures and unrestricted history deletion.
- Reconnect MCP desktop calls, bound input and hex output, and provide JSON history output.

- Save As publishes a synced private snapshot and moves the live writer under its lock; passive flow identity survives the change. Abandoned sessions remain recoverable under `sessions/recovered`, listed by `project_current`.
- Compaction uses a sibling SQLCipher export and reopens database handles; bulk history deletion releases the writer between bounded id ranges.
- History cancellation is isolated from export and analysis readers. Exact payload searches filter sizes before decompression; statistics evaluate payload filters once.
- JSON and pcapng exports publish complete files atomically, reject symlinks, and require explicit overwrite for existing targets.
- TCP reassembly bounds metadata and segment counts, avoids shifting all flows, and drains ordered ranges without repeated full-map scans.
- ASCII-insensitive searches preserve non-ASCII exact matches; newer compatible project schemas can open read-only.
- Save as can create a destination after reopening a project; the destination is reserved atomically with private permissions.
- Late full-packet loads cannot overwrite newer Repeater edits.
- Repeater: text components (chat, tab list header and footer, item lore, entity names) and block entity NBT were shown as raw hex. A list of compounds typed every item by its first, so `{"": "text"}` wrappers turned the byte flags of later parts into ints and the round trip failed. Each item is now typed by the item it replaces.
- Repeater: entity metadata lost its `0xff` terminator, and equipment slots lost the "more entries follow" bit when written back. Both rebuilt a frame the game could not read.
- Repeater: a boolean byte other than 0 or 1 was written back as 1, and a field the walker rejected was dropped from the raw tail. Both now keep their bytes.
- Repeater: line breaks in short strings were removed, saved tabs forgot their protocol version, and 64-bit values over 2^53 (timestamps, salts, seeds) were rounded. The Repeater also warns when a frame's state differs from the session's, since it is sent into whatever state the session is in.
- Packets larger than 8 KiB (chunks, inventories, tags) were decoded from their first 8 KiB only. The inspector now decodes and lays out the whole packet and still sends only the first window of bytes.
- Editing the NBT of a `custom_click_action` (dialog and form submissions, 1.21.6+) left its old byte length in place, so the server could not decode the packet. The length is now part of the field and rewritten with it.
- When a frame no longer matches its packet description, for example after editing a count or a type tag, the Repeater keeps the fields before the mismatch and shows only the rest as hex, instead of collapsing the whole body.
- The selected packet stays selected, loaded, and scrolled into view when filters change, even when it is far from the newest rows.
- The Repeater editor fills the window height again while a connection is live.
- Projects created by this build could not be reopened: migration 4 set `user_version = 4` while the supported schema version was still 3.
- JSON export was silently capped at 500 packets.
- Editing the Encryption Request in Intercept or with a rule replaced the proxy's key with the server's, so the client's reply could not be decrypted and the session ended. Edits now apply first and the proxy swaps in only its own key and verify token; an edited `should_authenticate = false` reaches the client and the proxy no longer waits for a join that will not come. The same order applies to the Encryption Response and the handshake, where an unedited host and port still follow the target.
- The packet list's `#` column repeated numbers across connections because it showed each connection's own sequence counter. It now shows the packet's project-wide id, the number Compare, filters, and MCP use.
- Decoded fields listed every value twice for handshake, status, ping, Set Compression, and login plugin packets. The decode stored with each row was passed to the inspector (and the MCP `packet` tool) as if a schema pack had produced it, next to the same fields decoded on open. Only a matching schema pack's decode is added now, and a schema field replaces a built-in field of the same name instead of repeating it.
- Forge 1.20.2+ clients (`\0FORGE` handshake marker) are reported with the Forge loader.
- Control characters in row summaries and decoded string fields are shown as control pictures, so a Forge handshake address reads `host␀FORGE` instead of `hostFORGE`.
- Modern plugin messages (`custom_payload`) were recorded without their channel, so `channel` filters, channel search, the channel explorer, and schema matching could not see 1.20.2+ custom payloads. Live proxy rows and imported captures now read the channel (and loader) from the packet preamble without decoding the payload.
- The MCP `packets` tool and every `filter` object now reject an unknown filter key instead of silently ignoring it. A typo such as `channel=` used to widen the query to the whole history; it is now an error that lists the accepted keys (`channel` is an expression field: `expr="channel == mineburp:batch"`).

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

[0.1.0]: https://github.com/Dospacite/MineBurp/releases/tag/v0.1.0
