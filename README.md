# MineBurp

MineBurp is a Burp Suite-style desktop workbench for authorized Minecraft Java security testing. It automatically discovers Minecraft client JVMs, observes only their TCP/UDP sockets, exposes raw payloads and flows, and stores observations in portable `.mineburp` project files. Its protocol and proxy crates provide the active-inspection foundation for decoding, rewriting, and Repeater workflows.

The current registry covers stable Java releases from 1.7.2 through 26.2. Unknown/newer protocol numbers remain usable in raw mode: framing, compression, encryption bridging, history, rewriting, and Repeater do not depend on a named packet map.

## What is implemented

- **Minecraft Decoder** in a right sidebar, **Channel explorer** across the filtered capture, Ctrl/Cmd+K **command palette**, packet selection actions, bounded payload generators, Repeater undo/redo and named revisions, custom decoded-field history columns, and traffic presets. Intruder and Sequencer work saves in the project. See [workbench tools](docs/WORKBENCH.md).
- **Automatic blockers** in Replace: enabled drop rules discard matched decoded packets before rewriting and Intercept, record the original as `dropped`, and do not advance protocol state.

- **Intruder**: Sniper, Battering ram, Pitchfork, and Cluster bomb attacks over decoded fields or raw byte ranges, with first-attempt preview, sequential pacing, cancellation, and bounded traffic observations.
- **Sequencer**: history/live field collection or pasted samples, duplicate detection, per-byte-position entropy and frequency analysis, and adjacent-sample correlation. See [research tools](docs/RESEARCH_TOOLS.md) for usage and statistical limits.

- Stateful loopback TCP proxy with VarInt framing, compression, connection state tracking, and frame size limits.
- Opt-in **Decrypt connections** mode. A configured Minecraft client receives a one-use, capability-protected private loopback route for each Minecraft network connect; there is no public proxy listener, target field, or PID workflow.
- Online-mode encryption termination with independent client/server AES-128/CFB8 streams. MineBurp uses the signed-in Minecraft session to join the upstream server hash, then continues inspection in plaintext internally.
- **Intercept**: hold handshake, status, login, configuration, and play packets on decrypted connections before they are forwarded, per direction and selected with the filter expression language. Each held packet can be forwarded, edited through its decoded fields or hex and then forwarded, or dropped. A held packet pauses only its own direction of its own connection. Keep-alives and pings overtake a held packet instead of queueing behind it, an optional auto-forward deadline releases held packets with a visible countdown, and turning Intercept off forwards everything still held.
- **Network conditions**: per-direction fixed delay, jitter, and bandwidth limit on decrypted connections, set at runtime from the Intercept view.
- Live Repeater injection in either direction with project-backed tabs. The Repeater decodes the frame it is editing into typed fields; editing a field re-encodes it — length prefixes included — and the hex follows, and editing the hex re-decodes the fields.
- Automatic **Replace** rules that rewrite matching packets in either direction as they pass through: whole frame, byte range, byte sequence, literal text, regular expression, a named decoded field, or a find/replace inside one. Rules are selected with the same filter expression language as the history, are stored in the project, and can be previewed against a captured packet before they are enabled.
- Raw hex inspector plus decoded fields for handshake, status, login, and configuration packets (a version-aware id table confirmed against the body), from a generated per-version id table (see below), and for play packets identified from the shape of their body: chat, commands and tab completion, plugin/custom payloads, client information, movement and vehicle movement, digging, block placement and block use, entity clicks (attack and interact), item use, sneak/sprint and the other player commands, sign edits, hotbar switches, keep alive, health, experience, abilities, time, block updates and block events, mining progress, level events, container screens, entity moves, teleports, velocity and removals, tab-list removals, resource packs, and the play login packet. Fabric, Forge, NeoForge, and legacy plugin channels are recognised by channel.
- Registry ids in decoded fields are named for every release from 1.7 to 26.2: items (with pre-1.13 damage variants), entity types, block states with their properties, sounds, particles, menus, effects, statistics, attributes, data component types, and the other built-in registries. The name sits beside the number (`item_id_name`), so the wire value stays visible and editable.
- Declarative, bounded JSON schema packs for plugin/mod payloads; packs are validated, hashed, stored in the project, and never execute code.
- SQLCipher-backed `.mineburp` projects with optional passphrases, WAL journaling, zstd packet blobs, connections, rules, Repeater tabs, and schema packs.
- Launcher-session assistance for online-mode servers without a MineBurp-owned Entra registration. A loader-independent Java agent asks the already signed-in Minecraft Authlib service to join MineBurp's upstream server hash; its access token never leaves the game process.
- Optional Microsoft OAuth PKCE → Xbox Live → XSTS → Minecraft Services authentication for distributors that provide an approved public-client registration. Access and refresh tokens are redacted from logs and never returned to the webview.
- Official Minecraft Launcher, Prism Launcher, MultiMC, Modrinth, and CurseForge discovery and launch adapters. Official, Prism, and MultiMC JVM configuration is reversible; Modrinth and CurseForge show a copyable manual argument.
- Automatic Minecraft-client TCP/UDP capture through Wireshark's privilege-separated `dumpcap` helper and Linux `procfs` socket ownership. No MineBurp listener, target, or manual PID selection is required, and frames owned by unrelated processes are discarded before publication or persistence.
- Project packet history uses database-side filters and fixed-size pages, so a long capture does not force the desktop UI to reset or render every packet at once.
- Passive capture keeps a connection's first frames: frames of a flow not yet attributed are held until the next socket scan instead of dropped, and every TCP direction is reassembled — retransmissions removed, out-of-order segments put back in sequence, link padding trimmed — with the capture's own timestamps.
- **Annotations and saved filters**: bookmark, colour, and annotate any packet, filter the history to bookmarked rows, and save named filters in the project.
- **Traffic statistics** for any filter: packets and bytes per direction over time, the busiest packet names by count and by bytes, the busiest connections, and a size histogram.
- **pcapng export and import**. Export writes decrypted packets as one synthetic TCP stream per connection, with each packet named in a comment, and `tools/wireshark/mineburp.lua` dissects it in Wireshark. Import reads pcap or pcapng files into a project through the same reassembly as live capture, then splits each TCP stream into Minecraft packets — one row per packet with its state, id and name — following the handshake, compression, login and configuration the way the proxy does. Encrypted traffic (after an online-mode login) cannot be decrypted from a capture and is kept as labelled raw rows; a capture that starts mid-connection is synchronised by searching for frame boundaries, optionally with a protocol version you give it. Re-importing a MineBurp pcapng export restores the packets, states and names it was written with.
- History maintenance: delete the packets a filter matches and compact the project file.
- **MCP server** (`mineburp-mcp`): 19 context-efficient tools that let an MCP client such as Claude Code query and decode history, rewrite frames, manage rules, and drive Intercept and the Repeater. It bridges to the running app over a private Unix socket, or works directly on a `.mineburp` file when the app is closed. See [docs/MCP.md](docs/MCP.md).
- Advanced packet filtering: traffic source, direction, protocol phase, and result sets; packet-name show/hide lists; payload size bounds; free-text search with regex, case-sensitive, and negative options; a filter expression language (`state == play && size > 256 && name ~ chat`) shared with replace rules; and payload content search by literal text, hex byte sequence, or regular expression, scoped to packets that contain the term, are exactly it, start with it, or end with it — each of which can be negated. A content search takes one term per line and matches any of them, and a hex term may be an inclusive range (`0c-0f`, `0100-01ff`), so hiding a handful of frames is one filter rather than one per frame. All of it runs in SQLite against the whole capture, not against the rows on screen.

## Repository layout

```text
crates/
  mineburp-core/       transport-neutral domain models and filters
  mineburp-protocol/   wire framing, encryption, common decoders, schemas
  mineburp-project/    encrypted project repository and migrations
  mineburp-proxy/      sessions, online-mode bridge, Repeater
  mineburp-auth/       Microsoft/Minecraft authentication and secret boundary
  mineburp-session/    session-join contract and capability-protected broker
  mineburp-launcher/   launcher discovery and process isolation
  mineburp-capture/    automatic dumpcap boundary and packet parsing
  mineburp-packet-table/ generates play packet-id tables from a version's own data
  mineburp-mcp/        MCP server and the history operations the desktop shares with it
agent/                 Java 8-compatible, loader-independent Authlib and route agent
src-tauri/             thin desktop command and event adapters
src/                   React workbench; no protocol or persistence logic
design-system/         supplied tokens and visual reference
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for ownership rules and extension points.

## Development

Requirements: the Rust toolchain pinned in `rust-toolchain.toml`, Node.js 22, npm, Wireshark `dumpcap` with capture permission, JDK 21, and the platform prerequisites for Tauri 2. The agent build downloads its pinned ASM dependencies from Maven Central. Linux support requires a graphical desktop, procfs, and a supported Tauri/WebKitGTK environment; capture also depends on local permissions and process visibility. On Arch Linux, install `webkit2gtk-4.1`; for other platforms, use the exact list in the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
npm ci
cargo test --workspace
npm run test:agent
npm run build
npm run tauri dev
```

MineBurp starts `dumpcap` automatically with the `tcp or udp` capture filter, then resolves local sockets against automatically detected Minecraft client JVMs before a frame reaches the UI or project. Use the normal Wireshark group/capability setup; do not run the entire desktop application as root. Automatic process attribution is currently implemented on Linux.

## Generating a packet table

Play packet ids are renumbered nearly every release, so MineBurp identifies play
packets from their body. Some bodies carry no evidence at all — a one-byte body
holding `0` or `1` is an arm swing, a client command, and a movement-input
bitmask at once — and those are named from a per-version id table instead.

Tables are always generated, never written by hand:

```bash
# Fully automatic: resolve the release, download its server jar from Mojang,
# run the data generator inside it, and update the bundled table.
cargo run -p mineburp-packet-table -- --protocol 769

# Or skip whichever steps you already have locally.
cargo run -p mineburp-packet-table -- --protocol 769 --jar server.jar
cargo run -p mineburp-packet-table -- --protocol 769 --report reports/packets.json
cargo run -p mineburp-packet-table -- --protocol 767 --prismarine protocol.json
```

The first three read `reports/packets.json` — the game reporting its own ids —
which exists from 1.20.5 onwards; `--prismarine` reads a `minecraft-data`
`protocol.json` for older releases. Names are mapped onto the names the
inspector already uses, so a packet named from a table and the same packet named
from its shape are one row, not two. Running with no `--protocol` regenerates
every release from the cache (`target/minecraft`), downloading missing
`minecraft-data` descriptions; `--offline` uses only the cache. Results land in
`crates/mineburp-protocol/data/packet-tables.json` (login, configuration and
play ids per protocol, with the release and source) and
`crates/mineburp-protocol/data/protocol-definitions.zst` (field definitions the
inspector decodes with). Requires a JDK the target version accepts (21+ for
modern releases) and network access, unless a report or `minecraft-data` file
is supplied.

The same run rebuilds `crates/mineburp-protocol/data/registry-names.zst`, which
names the numeric registry ids in decoded fields — items, entity types, block
states, sounds, particles, menus and so on — beside the number
(`item_id_name: "minecraft:diamond_sword"`). Its sources are cached under
`target/minecraft/registries/<protocol>/`: the data generator's
`registries.json`, `blocks.json` and `items.json`, cached whenever `--protocol`
runs the generator, and `minecraft-data` registry lists for older releases,
downloaded automatically.

```bash
# Run the data generator for every 1.13+ release whose registry reports are
# not cached yet (downloads each server jar), then rebuild everything.
cargo run -p mineburp-packet-table -- --vanilla-registries

# Write the registry names somewhere else.
cargo run -p mineburp-packet-table -- --offline --names /tmp/registry-names.zst
```

Where a table exists, it names the packet and the body is decoded as that
packet. A body that doesn't fit is reported as a warning on the packet, along
with what it reads as instead, rather than renamed.

## First run

### Passive observation

1. Start MineBurp. The **Traffic** view starts system capture automatically and records into a temporary project, so nothing is lost before you decide where to keep it.
2. Choose **Save as** in the project menu to keep the session: it copies everything captured so far into a `.mineburp` file (with an optional passphrase) and keeps recording there. The temporary project is deleted on exit.
3. Launch Minecraft from its normal launcher or from **Instances**, then connect to any server normally.
4. Pick a connection in **Traffic** and select a packet to inspect its endpoints, decoded fields, and payload bytes. No MineBurp listener, target, PID, Java agent, or Microsoft sign-in is required.

Passive observation cannot modify a connection, and encrypted application payloads remain encrypted.

### Active testing with decryption

1. Save a project for your authorized assessment.
2. Configure client assistance for the instance in **Instances**.
3. Enable **Decrypt connections** in **Traffic**, launch that instance, and connect to your authorized server normally.
4. Find a plugin channel, hold a matching packet in **Intercept**, then edit or send it to **Repeater**. Follow the [active testing tutorial](docs/TUTORIAL.md) for a disposable lab example.

MineBurp keeps this mode off by default. It routes only connections initiated through Minecraft's own network stack and fails open to the original target if the agent or broker is unavailable.

Decrypt mode uses an authenticated client-side route adapter instead of silently changing host `nftables`/TUN rules or requiring the desktop app to run as root. Separate TLS traffic from mods and launchers remains outside that route; modern signed chat and integrity-sensitive mod/plugin packets are marked as unsafe to alter in the inspector.

See [docs/CLIENT_ASSISTANCE.md](docs/CLIENT_ASSISTANCE.md) for launcher-specific setup, the local protocol, and its security boundary.

## Optional direct Microsoft login

MineBurp does **not** bundle a third party's Microsoft client ID. Microsoft login is not required for automatic traffic capture.

Custom distributions may enable direct OAuth at compile time by setting `MINEBURP_MICROSOFT_CLIENT_ID` to their own approved public-client application ID. Its mobile/desktop redirect URI must include `http://localhost:53682/callback`, and public client flows must be enabled.

1. Build with the environment variable set, for example `MINEBURP_MICROSOFT_CLIENT_ID=<your-id> npm run tauri build`.
2. In **Instances**, expand **Advanced: direct Microsoft sign-in** and select **Sign in with Microsoft**.
3. Sign in with the personal Microsoft account that owns Minecraft Java Edition.
4. The final localhost page may be unreachable because MineBurp does not run an HTTP callback server. Copy the complete URL from the browser address bar, including `code` and `state`, paste it into **Callback URL**, and complete sign-in.

MineBurp uses authorization-code flow with PKCE and no client secret. Minecraft Services may still require external approval for a new application. Do not substitute another application's public client ID: ownership and redirect settings remain attached to that registration.

## Security scope

Use MineBurp only on systems you own or have explicit permission to assess. The capture helper can see system traffic, but MineBurp publishes and persists only frames attributed to detected Minecraft client JVM sockets. MineBurp applies payload, collection, nesting, and database limits, does not load native code from schema packs, and redacts authentication secrets from debug output.

Current intentionally bounded areas are documented in [SECURITY.md](SECURITY.md). In particular, the 1.19–1.19.2 signed-nonce response is accepted but its signature is not verified locally, and passive capture does not claim to decrypt encrypted application payloads.

## Verification

The checked-in implementation is covered by unit tests for framing, zlib compression, VarInts, handshake marker preservation, AES stream state, RSA encryption bridging, one-use assisted session routing, reversible launcher configuration, schema limits, common loader-channel decoding, filter parsing, encrypted projects, and project artifact round trips. `npm run test:agent` also launches a real instrumented JVM and exercises both supported Authlib signatures plus the private Netty route hook.

## License

MineBurp is licensed under the [Apache License 2.0](LICENSE). Third-party components have their own licenses.
