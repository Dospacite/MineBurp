# Architecture

MineBurp is organized around dependency direction. Desktop and UI code depend on application services; application services depend on protocol-neutral domain contracts; no core crate imports Tauri or React concepts.

```text
React UI
   │ invoke/events
Tauri adapters ───────── launcher adapters
   │
   ├── proxy service ─── protocol codecs ─── core models
   ├── project store ──────────────────────── core models
   ├── session join ───── loopback broker ─── Java agent/Authlib
   │             └─────── optional auth client
   └── capture boundary ───────────────────── core models
```

## Crate responsibilities

`mineburp-core` owns stable vocabulary: directions, states, summaries, connection snapshots, interception decisions, Repeater tabs, and the filter AST *and its grammar*. It has no I/O. Parsing lives here rather than beside either consumer because two crates evaluate the same expressions by different means — the proxy matches them against live packets in memory, the project compiles them to SQL — and a second parser would let the two dialects drift.

`mineburp-protocol` owns byte-level rules. The frame codec is incremental and bounded. Compression, CFB8, handshakes, encryption packet layouts, common decoders, protocol releases, declarative schema decoding, network NBT, and on-demand packet inspection live here.

`mineburp-project` is the only crate that knows the SQLite schema. Callers work with typed models, not SQL. Its packet-history query applies the whole filter — connection, source, direction, state and disposition sets, name include/exclude lists, size bounds, free-text search, and a compiled filter expression — in SQLite, and returns bounded pages keyed by id rather than by offset so a page stays stable while capture appends rows. Payloads are read through bounded windows. New migrations must be additive, transactional, and preserve read-only opening of newer-compatible projects.

`mineburp-proxy` coordinates sockets and policies. It owns backpressure queues, connection state, held-packet continuations, Repeater routing, schema selection, and the authenticated RSA/AES bridge. It depends only on the `SessionJoinProvider` contract and does not know where a Minecraft session came from.

`mineburp-auth` owns remote identity endpoints and secret-bearing models. Browser presentation and durable credential backends are adapters, not part of the OAuth client.

`mineburp-session` owns the session-join contract, Minecraft's signed SHA-1 hash formatting, and the capability-authenticated loopback broker. The broker correlates the hash Minecraft joined for the client-facing handshake with the different hash required by the upstream-facing handshake.

`mineburp-launcher` discovers launcher-specific metadata, produces processes, and owns reversible JVM-argument updates. Instance parsing and configuration are separate from process privilege handling so new launchers do not inherit elevation accidentally.

`agent` is a Java 8-compatible `premain` agent with no mod-loader dependency. It instruments Authlib's two known `joinServer` descriptors and Netty's outbound `Bootstrap#connect` seam. The Netty hook verifies a `net.minecraft.*` caller before requesting a one-use private loopback route. It retains a credential reference for at most 60 seconds and fails open so instrumentation or broker failure cannot stop Minecraft's original login or redirect unrelated mod/launcher traffic.

`Bootstrap#connect` is the only seam where both halves of that contract hold. Netty hands the channel's own `doConnect` to the event loop as a task, so the caller is no longer on the stack there and the `net.minecraft.*` check can never pass; which channel class runs also depends on whether a native transport is available, so a client on Linux connects through `EpollSocketChannel` and one on macOS through `KQueueSocketChannel`, neither of which even declares `doConnect`. Every public `connect` overload funnels into `connect(SocketAddress)`, which runs on the thread that asked for the connection.

Instrumentation must read with `ClassReader.EXPAND_FRAMES`: the advice adapter is a `LocalVariablesSorter`, which rejects the compressed stack map frames that every real Netty class carries. The agent's stubs must therefore contain branches — a straight-line stub carries no frames and cannot detect this.

`mineburp-capture` exposes `SideCapture`. `SystemCapture` owns the `dumpcap` child process and parses its bounded classic-PCAP stream. A platform attribution adapter discovers Minecraft client JVMs and maps their socket inodes to local/remote ports before transport-neutral observations are published. It remains independent of proxy sessions and never requires a user-selected process.

`src-tauri` is deliberately thin. Commands translate serializable input, call one service, and translate errors. Long database operations use the blocking pool. Events carry proxy and capture updates to the UI.

It also opens a *temporary project* in the system temporary directory at startup, before capture begins. A project is the only place captured packets live, so without one the proxy's decrypted packets were assigned an id and discarded and passive capture had nowhere to go. Creating or opening a real project replaces the temporary one and deletes it; so does exiting. The temporary state is reported to the UI so it is never presented as saved work.

While a proxy session is running, the desktop capture writer drops passively captured frames on that session's loopback port. Those frames are the ciphertext half of a stream the proxy is already recording in the clear, and keeping them meant every decrypted packet had an unreadable duplicate in the history.

`src` owns interaction state and rendering only. It never parses Minecraft frames, manipulates SQL, or handles access tokens.

## Extending packet support

Use the smallest appropriate layer:

- Add a universally stable packet primitive to `mineburp-protocol`.
- Add version/ID names to `PacketRegistry` when verified against an authoritative release artifact.
- Add a common safe decoder for ubiquitous control packets.
- Use a schema pack for plugin, datapack bridge, mod, Fabric, Forge, or NeoForge payloads.
- Add executable decoding only as a separately sandboxed future subsystem; schema packs must remain data-only.

Raw capture is the compatibility floor. A failed or absent decoder must leave the original logical bytes intact and attach an error, never discard a packet.

## Decoding is on demand

Capture records bytes and cheap metadata. Field-level decoding — common decoders, schema packs, and `mineburp-protocol::inspect` — runs when a packet is opened, never per captured packet. Capture-time work is limited to what a table row and an intercept rule need: state, direction, id, channel, loader, and the *name* of a matching schema.

Identification runs in four tiers. Handshake, status, and login ids have never moved, so the id names the packet. Configuration ids have been renumbered exactly twice since 1.20.2, so `registry` proposes a name from a version table and the body has to agree with it — a mismatch means the protocol version is wrong and the packet falls through rather than being mislabelled. Play ids are renumbered nearly every release, so no id is read without a table generated for that exact protocol, and every decoder validates the body it claims and reports a name only when the parse holds and consumes what it should. `PacketInsight::identification` says which tier a name came from. An unrecognised packet reports no fields rather than inventing structural ones; its bytes are already in the hex view.

Shape identification has a floor that no amount of decoder work raises: a body carries only so much evidence. A one-byte body holding `0` or `1` is byte-for-byte an arm swing, a client command, a container close, and a movement-input bitmask — no validator can separate them, so they stay unnamed. That floor also decides how overlaps are settled between decoders that *do* validate. Two rules apply, and both are about who loses the tie rather than who wins it: a decoder's evidence must be more than the body's length (an eight-byte body is not a keep alive unless the long inside it also reads like a clock or a counter), and where two shapes genuinely coincide, the overlap goes to the packet that is orders of magnitude more common and the rarer one gives up the ambiguous slice. Mining progress and a relative entity move are both a `VarInt` id and nine bytes, separated only by a last byte that is a crack stage in one reading and an on-ground flag in the other, so stages 0 and 1 are simply not claimed. The same reasoning leaves a two-byte item use unnamed, because it cannot be told from a hotbar switch until the sequence number grows past 127.

The play id table is what lifts that floor, and it earns the trust by being *derived rather than written*. `mineburp-packet-table` builds one from the release's own `reports/packets.json` — the game telling you its ids — or, for versions older than that report, from `minecraft-data`. Nobody types a table in, because a hand-written one is indistinguishable from a plausible lie until the day it is wrong. Three rules keep it honest. The protocol match is exact, with no nearest-version fallback: a neighbouring release renumbers rather than approximates, so an untabulated version simply has no table. Generated names are mapped onto the names the shape decoders already use, so one packet is one row whichever tier named it. And the table never outranks the bytes — the protocol version is a claim the client wrote in its handshake, while the body is evidence, so a decoder that reads the body as a different packet wins and the packet is reported as a structural match, which is also exactly what a client lying about its version looks like from the inside. Where the id and the body agree, the packet is reported as a registry match: two independent witnesses to one name.

Naming a row is cheaper than decoding it. `inspect::identify_packet` runs the same identification and throws the fields away, and skips bodies over 4 KiB — chunk, registry, and map payloads are never named by shape, and walking their NBT once per packet is exactly the work capture must not do. A table lookup is a slice index, so where a table exists those oversized packets are still named; the cap skips the shape work, not the identification.

`layout` answers a different question than `inspect`: not what a packet says but *where each value lives*. It walks a frame the inspector has already named into typed spans with byte offsets, which is what lets the Repeater and the replacement rules re-encode one value and splice it back in. `rewrite` builds on it: a field edit rewrites its own length prefix, so resizing a string leaves a frame that still decodes.

The *state* a packet is decoded against is tracked by the proxy, not guessed by the decoder, so the state machine has to follow every phase change. The 1.20.2 configuration boundary is read the same way — by shape, not by an id table: each half of the finish-configuration handshake is the only empty-bodied packet its direction can carry in that state, and re-entering configuration from play requires the server's offer before the client's acknowledgement is believed.

## Filtering

A filter narrows the *query*, never the loaded rows. Every control the operator touches becomes a parameterised `WHERE` clause: filtering a million-packet capture costs one bounded page, and the webview never holds the rows it is not showing.

Two rules keep the two evaluators honest with each other:

- An expression must select the same packets from the project as it does from a live stream. The in-memory evaluator in `mineburp-core` is the specification, including its sharp edges — an absent optional field never matches, even under `!=`, and ordering comparisons on text are false rather than lexicographic. A test runs both against the same corpus.
- Operator text is always bound, never interpolated. A filter expression cannot reach the SQL string.

Case sensitivity is explicit rather than inherited: SQLite's `LIKE` folds ASCII case whatever its operands look like, so case-sensitive search uses `instr`, which also treats `%` and `_` as ordinary characters in a packet name.

Payload search is the one filter that cannot be answered from an index. Payloads are compressed blobs, so a `payload_search` scalar function is registered for the duration of the query with the matcher already compiled, and each surviving row is decompressed and scanned. Three consequences shape the design: the clause is always appended last so indexed terms reject rows first; decompression is capped per packet so one chunk packet cannot decide how long a query takes; and a payload that will not decompress counts as "no match" rather than failing the query, so one corrupt row cannot make a history unreadable.

A search also carries a *scope* — contains, is exactly, starts with, ends with — because "packets that carry this sequence" and "packets that are this sequence" are different questions, and only the second one can be negated into "everything except these frames". The scope is why the function is passed the row's recorded size alongside the blob: the decode stops at the scan cap, so the matcher has to know whether it is holding the whole payload. An exact match is settled by comparing sizes first, which decides almost every row without touching the bytes; a scope anchored at the end reports no match on a payload the scan truncated rather than judging a prefix as if it were the whole.

A search is also a *set*: the term is read one alternative per line and a row matches when any of them does, so "hide these four frames" is one query rather than four. Hex alternatives additionally accept `start-end`, an inclusive range compared byte by byte over sequences of the same length. The dash is safe to give meaning because the hex reader has always treated every other separator as noise and never accepted a dash, so no existing search changes meaning. Ranges are hex-only on purpose: in a text term a dash is an ordinary character, and a regular expression can already say `[\x0c-\x0f]` for itself. Malformed ranges — mismatched widths, a start past its end — are reported as errors rather than compiled into something that quietly matches nothing.

## Rewriting traffic

Replacement rules are separate from intercept decisions on purpose. An intercept decision is one verdict for a packet — forward, drop, delay, hold — and the *first* matching rule owns it. A rewrite is a transformation, so every matching rule applies, in order, each seeing the output of the one before it.

Three invariants hold the feature together:

- A rule that fails is reported and skipped, never fatal. An unknown field name or a bad pattern must not disconnect the game an operator is testing.
- The recorded row is what went on the wire. A rewritten packet is re-derived from the frame that was actually sent and recorded as `edited`, so the history stays a record of the connection rather than of intent.
- Field edits go through `layout`, so a resized value rewrites its own length prefix. Byte-level edits do exactly what they are told; that is what makes them useful where no decoder reaches, and why they can leave a frame the client will reject.

## Volume invariants

Capture rates outrun both the webview and SQLite if either is fed per packet:

- Capture and proxy writers both persist to the project and publish only a coalesced append *count* to the webview. Nothing is mirrored into an in-memory ring: a ring bounded by frame count aged rows out of the operator's reach under real Minecraft load, and payloads travelling over IPC per packet is what made the view unusable in the first place.
- The project writer commits captured frames in batched transactions.
- Packet tables render only the rows on screen; row height is fixed so the window is arithmetic.
- The history appends from a keyset cursor and never replaces loaded rows on a timer.

## Concurrency invariants

- Each accepted client creates one session handle and four tasks: two readers and two writers.
- Socket writers are single-owner tasks behind bounded channels, preserving byte order and applying encryption in one place.
- Client and server links have independent stateful ciphers.
- The upstream encryption response is queued as plaintext before both link ciphers are activated.
- A reader decrypts what is already in its buffer at the moment its cipher activates. Bytes that followed the encryption response in the same read were copied in as ciphertext, and leaving them meant the first encrypted packets framed as garbage.
- Client-assistance routes are one-use and keyed by the client-facing signed server hash.
- Decrypt-mode route requests are capability-protected, loopback-only, and expire after 15 seconds if the client does not connect.
- A route is handed back on the *broker's own* loopback address, never on `InetAddress.getLoopbackAddress()`. Minecraft launches with `-Djava.net.preferIPv6Addresses=system`, under which that returns `::1` while the route listens on the IPv4 loopback: the client's connect is refused outright and the unused route then expires exactly as if the client had never appeared.
- An agent credential is invoked only for the matching upstream hash, is never serialized to Rust, and is cleared after use or expiry.
- SQL work runs off the async executor. Project handles serialize SQLite access internally.
- Parking-lot guards never cross an `.await`.

## Adding a launcher

Implement `LauncherAdapter`, keep discovery side-effect free, and return a typed `InstanceDescriptor`. Put launcher-specific JVM configuration behind `configure_client_assist`; managed changes must record only MineBurp's exact injected value so removal cannot delete unrelated arguments. Launch commands start the selected instance normally and must pass through the privilege-lowering process boundary.

## Adding a capture backend

Implement `SideCapture`, report honest capabilities, publish bounded observations, and keep raw platform handles out of the proxy crate. Capture is independent of launcher and proxy state. Platform implementations must discard unattributed traffic before publication and must not claim decryption they cannot prove.
