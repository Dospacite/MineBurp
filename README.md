# MineBurp

MineBurp is a Burp Suite-style desktop workbench for authorized Minecraft Java security testing. It automatically discovers Minecraft client JVMs, observes only their TCP/UDP sockets, exposes raw payloads and flows, and stores observations in portable `.mineburp` project files. Its protocol and proxy crates provide the active-inspection foundation for decoding, interception, and Repeater workflows.

The current registry covers stable Java releases from 1.7.2 through 26.2. Unknown/newer protocol numbers remain usable in raw mode: framing, compression, encryption bridging, history, interception, and Repeater do not depend on a named packet map.

## What is implemented

- Stateful loopback TCP proxy with VarInt framing, compression, connection state tracking, and frame size limits.
- Opt-in **Decrypt connections** mode. A configured Minecraft client receives a one-use, capability-protected private loopback route for each Minecraft network connect; there is no public proxy listener, target field, or PID workflow.
- Online-mode encryption termination with independent client/server AES-128/CFB8 streams. MineBurp uses the signed-in Minecraft session to join the upstream server hash, then continues inspection in plaintext internally.
- Interactive intercept with forward, drop, delay, hold, and edited-forward decisions.
- Live Repeater injection in either direction with project-backed tabs. The Repeater decodes the frame it is editing into typed fields; editing a field re-encodes it — length prefixes included — and the hex follows, and editing the hex re-decodes the fields.
- Automatic **Replace** rules that rewrite matching packets in either direction as they pass through: whole frame, byte range, byte sequence, literal text, regular expression, a named decoded field, or a find/replace inside one. Rules are selected with the same filter expression language as the history, are stored in the project, and can be previewed against a captured packet before they are enabled.
- Raw hex inspector plus decoded fields for handshake, status, login, and configuration packets (a version-aware id table confirmed against the body), from a generated per-version id table (see below), and for play packets identified from the shape of their body: chat, commands and tab completion, plugin/custom payloads, client information, movement and vehicle movement, digging, block placement and block use, entity clicks (attack and interact), item use, sneak/sprint and the other player commands, sign edits, hotbar switches, keep alive, health, experience, abilities, time, block updates and block events, mining progress, level events, container screens, entity moves, teleports, velocity and removals, tab-list removals, resource packs, and the play login packet. Fabric, Forge, NeoForge, and legacy plugin channels are recognised by channel.
- Declarative, bounded JSON schema packs for plugin/mod payloads; packs are validated, hashed, stored in the project, and never execute code.
- SQLCipher-backed `.mineburp` projects with optional passphrases, WAL journaling, zstd packet blobs, connections, rules, Repeater tabs, and schema packs.
- Launcher-session assistance for online-mode servers without a MineBurp-owned Entra registration. A loader-independent Java agent asks the already signed-in Minecraft Authlib service to join MineBurp's upstream server hash; its access token never leaves the game process.
- Optional Microsoft OAuth PKCE → Xbox Live → XSTS → Minecraft Services authentication for distributors that provide an approved public-client registration. Access and refresh tokens are redacted from logs and never returned to the webview.
- Official Minecraft Launcher, Prism Launcher, MultiMC, Modrinth, and CurseForge discovery and launch adapters. Official, Prism, and MultiMC JVM configuration is reversible; Modrinth and CurseForge show a copyable manual argument.
- Automatic Minecraft-client TCP/UDP capture through Wireshark's privilege-separated `dumpcap` helper and Linux `procfs` socket ownership. No MineBurp listener, target, or manual PID selection is required, and frames owned by unrelated processes are discarded before publication or persistence.
- Project packet history uses database-side filters and fixed-size pages, so a long capture does not force the desktop UI to reset or render every packet at once.
- Advanced packet filtering: traffic source, direction, protocol phase, and result sets; packet-name show/hide lists; payload size bounds; free-text search with regex, case-sensitive, and negative options; a filter expression language (`state == play && size > 256 && name ~ chat`) shared with intercept rules; and payload content search by literal text, hex byte sequence, or regular expression, scoped to packets that contain the term, are exactly it, start with it, or end with it — each of which can be negated. A content search takes one term per line and matches any of them, and a hex term may be an inclusive range (`0c-0f`, `0100-01ff`), so hiding a handful of frames is one filter rather than one per frame. All of it runs in SQLite against the whole capture, not against the rows on screen.

## Repository layout

```text
crates/
  mineburp-core/       transport-neutral domain models and filters
  mineburp-protocol/   wire framing, encryption, common decoders, schemas
  mineburp-project/    encrypted project repository and migrations
  mineburp-proxy/      sessions, interception, online-mode bridge, Repeater
  mineburp-auth/       Microsoft/Minecraft authentication and secret boundary
  mineburp-session/    session-join contract and capability-protected broker
  mineburp-launcher/   launcher discovery and process isolation
  mineburp-capture/    automatic dumpcap boundary and packet parsing
  mineburp-packet-table/ generates play packet-id tables from a version's own data
agent/                 Java 8-compatible, loader-independent Authlib and route agent
src-tauri/             thin desktop command and event adapters
src/                   React workbench; no protocol or persistence logic
design-system/         supplied tokens and visual reference
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for ownership rules and extension points.

## Development

Requirements: Rust 1.97+, Node.js 22+, npm, Wireshark `dumpcap` with capture permission, a JDK with `javac` supporting `--release 8`, and the platform prerequisites for Tauri 2. On Arch Linux, install `webkit2gtk-4.1`; for other platforms, use the exact list in the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
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
from its shape are one row, not two. Results land in
`crates/mineburp-protocol/data/play-packets.json`, one entry per protocol,
carrying the release and the source it came from. Requires a JDK the target
version accepts (21+ for modern releases) and network access, unless a report or
`minecraft-data` file is supplied.

A table names a packet; it never outranks its bytes. The protocol version comes
from a handshake the client wrote, so when a decoder reads the body as a
different packet, the body wins.

## First run

1. Start MineBurp. The **Traffic** view starts system capture automatically and records into a temporary project, so nothing is lost before you decide where to keep it.
2. Create an optional-passphrase `.mineburp` project when you want the session kept — the temporary project is deleted on exit.
3. Launch Minecraft from its normal launcher or from **Instances**, then connect to any server normally.
4. Pick a connection in **Traffic** and select a packet to inspect its endpoints, decoded fields, and payload bytes. No MineBurp listener, target, PID, Java agent, or Microsoft sign-in is required.

Passive observation cannot modify a connection, and encrypted application payloads remain encrypted. To inspect an encrypted Minecraft connection, configure client assistance for the instance in **Instances**, enable **Decrypt connections** in **Traffic**, then launch the instance and connect normally. MineBurp keeps this mode off by default. It routes only connections initiated through Minecraft's own network stack and fails open to the original target if the agent or broker is unavailable.

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

Current intentionally bounded areas are documented in [SECURITY.md](SECURITY.md). In particular, the 1.19–1.19.2 signed-nonce alternative is rejected rather than guessed, and passive capture does not claim to decrypt encrypted application payloads.

## Verification

The checked-in implementation is covered by unit tests for framing, zlib compression, VarInts, handshake marker preservation, AES stream state, RSA encryption bridging, one-use assisted session routing, reversible launcher configuration, schema limits, common loader-channel decoding, filter parsing, encrypted projects, and project artifact round trips. `npm run test:agent` also launches a real instrumented JVM and exercises both supported Authlib signatures plus the private Netty route hook.
