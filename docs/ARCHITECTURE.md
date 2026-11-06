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

`mineburp-core` owns stable vocabulary: directions, states, summaries, connection snapshots, rewrite rules, Repeater tabs, and the filter AST *and its grammar*. It has no I/O. Parsing lives here rather than beside either consumer because two crates evaluate the same expressions by different means — the proxy matches them against live packets in memory, the project compiles them to SQL — and a second parser would let the two dialects drift.

`mineburp-protocol` owns byte-level rules. The frame codec is incremental and bounded. Compression, CFB8, handshakes, encryption packet layouts, common decoders, protocol releases, declarative schema decoding, network NBT, and on-demand packet inspection live here.

`mineburp-project` is the only crate that knows the SQLite schema. Callers work with typed models, not SQL. Its packet-history query applies the whole filter — connection, source, direction, state and disposition sets, name include/exclude lists, size bounds, free-text search, and a compiled filter expression — in SQLite, and returns bounded pages keyed by id rather than by offset so a page stays stable while capture appends rows. Payloads are read through bounded windows, and no payload decompresses past the size its row records. Writes go through one connection and history reads through a small pool of read-only connections (WAL lets them run concurrently), so a long search never stalls capture and capture never stalls a page load; every read runs under a time budget and can be interrupted. New migrations must be additive and preserve read-only opening of newer-compatible projects; each step runs in its own transaction with its `user_version` bump, so a failed step rolls back completely. The project also keeps the analyst's own state — packet annotations (bookmark, colour, note) and saved filters — plus statistics over any filter, deletion of matching history, and compaction.

`mineburp-proxy` coordinates sockets and policies. It owns backpressure queues, connection state, batched persistence, Repeater routing, schema selection, and the authenticated RSA/AES bridge. It depends only on the `SessionJoinProvider` contract and does not know where a Minecraft session came from.

`mineburp-auth` owns remote identity endpoints and secret-bearing models. Browser presentation and durable credential backends are adapters, not part of the OAuth client.

`mineburp-session` owns the session-join contract, Minecraft's signed SHA-1 hash formatting, and the capability-authenticated loopback broker. The broker correlates the hash Minecraft joined for the client-facing handshake with the different hash required by the upstream-facing handshake.

`mineburp-launcher` discovers launcher-specific metadata, produces processes, and owns reversible JVM-argument updates. Instance parsing and configuration are separate from process privilege handling so new launchers do not inherit elevation accidentally. An edit to a launcher's file is crash-safe: MineBurp records the argument it is about to write in its own state file first, writes the launcher file to a temporary file that replaces the original with one rename, keeps a one-time backup of the original, and refuses the edit if the launcher saved the file in between. `instance.cfg` is read and written in the dialect the launcher uses — Qt `QSettings` INI for Prism Launcher, MultiMC's own escaping otherwise — so a quoted or Windows path survives the round trip.

`agent` is a Java 8-compatible `premain` agent with no mod-loader dependency. It instruments Authlib's two known `joinServer` descriptors and Netty's outbound `Bootstrap#connect` seam. The Netty hook requires the direct caller of `Bootstrap#connect` to be Minecraft's connection class before requesting a one-use private loopback route; a Minecraft frame elsewhere on the stack is not enough, because a mod's own client started from a tick handler has one too. Every broker connection starts with a mutual HMAC challenge keyed by the capability, so the capability never crosses the socket and the agent will not talk to a listener that cannot prove it holds it. It retains a credential reference for at most 60 seconds and fails open so instrumentation or broker failure cannot stop Minecraft's original login or redirect unrelated mod/launcher traffic.

`Bootstrap#connect` is the only seam where both halves of that contract hold. Netty hands the channel's own `doConnect` to the event loop as a task, so the caller is no longer on the stack there and the caller check can never pass; which channel class runs also depends on whether a native transport is available, so a client on Linux connects through `EpollSocketChannel` and one on macOS through `KQueueSocketChannel`, neither of which even declares `doConnect`. Every public `connect` overload funnels into `connect(SocketAddress)`, which runs on the thread that asked for the connection.

Instrumentation must read with `ClassReader.EXPAND_FRAMES`: the advice adapter is a `LocalVariablesSorter`, which rejects the compressed stack map frames that every real Netty class carries. The agent's stubs must therefore contain branches — a straight-line stub carries no frames and cannot detect this.

`mineburp-capture` exposes `SideCapture`. `SystemCapture` owns the `dumpcap` child process and parses its bounded pcap stream; the same reader takes pcapng, which is how capture files are imported. A platform attribution adapter discovers Minecraft client JVMs and maps their sockets — by full address and port, both ends — to flows before transport-neutral observations are published. It remains independent of proxy sessions and never requires a user-selected process.

Capture is a pipeline of three threads so that no stage can stall the one before it: one reads dumpcap's pipe, one attributes and reassembles, and one rebuilds the socket table from `/proc`. A connection's first frames — its handshake and login — arrive within one round trip of the socket being created, usually before any scan has seen it, so a frame whose flow is not in the table yet is *held*, not dropped, until a scan that started after the frame arrived has finished; only then is the flow declared unrelated, and that verdict is cached. An attributed flow stays attributed until its FIN or RST plus a grace period, because a closing socket leaves the table before its last segments are read. Each TCP direction is then put back in sequence order: retransmissions are released once, out-of-order segments wait for the hole before them, a hole that never fills is skipped after a timeout rather than holding the connection forever, and payloads are trimmed to the IP length so link padding is never stored. Frames carry the capture's own timestamps. dumpcap's exit status and stderr are kept, so a capture that dies says why.

`mineburp-mcp` serves the Model Context Protocol. Its tools are written against a `Host` trait: the desktop app implements it over its live state (proxy, capture, launchers) and serves it on a private Unix socket, and `OfflineHost` implements it over a bare project file for the standalone `mineburp-mcp` binary, which otherwise just bridges stdio to the app's socket. The crate's `ops` module also owns the history operations both front ends need — the UI's filter shape and its translation to a `PacketQuery`, JSON and pcapng export, capture import, export path validation, and schema-pack decoding — so a filter saved in the UI means the same thing when an agent applies it. Tool output is compact text by design; see [MCP.md](MCP.md).

`src-tauri` is deliberately thin. Commands translate serializable input, call one service, and translate errors. Long database operations use the blocking pool. Events carry proxy and capture updates to the UI.

It also opens a *temporary project* at startup, before capture begins, in a `sessions` directory under the app's data directory that only the current user can enter — the file holds decrypted traffic, and the shared system temporary directory would let other local users read it. Each scratch file carries its process id; a later start moves files whose process is gone, together with their WAL sidecars, into the private `sessions/recovered` directory. `project_current` includes a `recovered_projects` array of absolute paths which the UI can offer through the existing project-open flow. Recovery files remain until the operator removes them. A project is the only place captured packets live, so without one the proxy's decrypted packets were assigned an id and discarded and passive capture had nowhere to go. Creating or opening a real project replaces the temporary one and deletes it; so does exiting. The temporary state is reported to the UI so it is never presented as saved work.

While a proxy session is running, the desktop capture writer drops passively captured frames on that session's loopback port. Those frames are the ciphertext half of a stream the proxy is already recording in the clear, and keeping them meant every decrypted packet had an unreadable duplicate in the history.

`src` owns interaction state and rendering only. It never parses Minecraft frames, manipulates SQL, or handles access tokens.

## Extending packet support

Use the smallest appropriate layer:

- Add a universally stable packet primitive to `mineburp-protocol`.
- Regenerate the packet tables and descriptions with `mineburp-packet-table` rather than editing `PacketRegistry` or its data files by hand.
- Add a common safe decoder for ubiquitous control packets.
- Use a schema pack for plugin, datapack bridge, mod, Fabric, Forge, or NeoForge payloads.
- Add executable decoding only as a separately sandboxed future subsystem; schema packs must remain data-only.

Raw capture is the compatibility floor. A failed or absent decoder must leave the original logical bytes intact and attach an error, never discard a packet.

## Decoding is on demand

Capture records bytes and cheap metadata. Field-level decoding — common decoders, schema packs, and `mineburp-protocol::inspect` — runs when a packet is opened, never per captured packet. Capture-time work is limited to what a table row and a replacement rule need: state, direction, id, channel, loader, and the *name* of a matching schema.

Identification runs in three tiers. Handshake, status, and the first four login ids have never moved, so the id names the packet; later login additions (the 1.13 plugin exchange, the 1.20.2 acknowledgement, the 1.20.5 cookies) were appended, so they are stable too but version-gated. Every other login, configuration, and play id is read through a table generated for that exact protocol. Without a table — an unknown protocol, or passive capture that never saw a handshake — play and configuration packets are named from the shape of their body, and every shape decoder validates the body it claims and reports a name only when the parse holds and consumes what it should. `PacketInsight::identification` says which tier a name came from and `decoded_by` says where its fields came from. An unrecognised packet reports no fields rather than inventing structural ones; its bytes are already in the hex view.

The tables earn their trust by being *derived rather than written*. `mineburp-packet-table` builds them from each release's own `reports/packets.json` — the game telling you its ids — and, for releases older than that report, from `minecraft-data`'s `protocol.json`. Nobody types a table in, because a hand-written one is indistinguishable from a plausible lie until the day it is wrong. The two sources name packets differently and neither keeps its names across releases, so the generator *learns* the mapping between them instead of being told it: wherever a protocol has both, the same id in the same state and direction is the same packet; a vanilla name that changes beside a stable `minecraft-data` name is a rename and the newest spelling wins; a `minecraft-data` definition that is byte-for-byte unchanged across a rename carries the new name back through older releases. Only then are names mapped onto the inspector's vocabulary, so one packet is one row whichever tier — or whichever release — named it. The generator refuses to write a table that names two ids alike, which is how a guessed mapping gets caught. The protocol match is exact, with no nearest-version fallback: a neighbouring release renumbers rather than approximates. 1.8 through 26.2 are tabulated; 1.7.2, 1.7.10, and 1.14.2 are not, because neither source describes them.

Where a table exists it is the stronger witness, and the body is decoded *as the packet the table names* — never renamed. A body that does not match is reported in `PacketInsight::warnings`, together with what the bytes read as instead, because that mismatch is exactly what a client lying about its version, a modded server, or a malformed packet looks like from the inside, and it is the operator who should decide which it is.

Fields come from `protodef`, a data-only interpreter for the `minecraft-data` description bundled for the exact protocol (1.8 through 26.1, about 40 KB compressed). Descriptions are data: nothing in one can execute, and a hostile body can only exhaust a budget — a node budget over every value produced, a recursion depth, a span cap, and counts rejected when they exceed the bytes present, so an "array of a million elements" in four bytes allocates nothing. Its byte accounting agrees with the reference implementation, node-minecraft-protocol, on a quarter-million random bodies across every bundled release (`mineburp-packet-table/tools/reference-corpus.js` regenerates that corpus); where it disagrees it is deliberately stricter in the same places vanilla is. `present` then adds readable companions without removing anything: rendered text beside every text component, decoded skin textures beside profile properties, the command syntax a server declares, and an `interactive_events` list of every click action — run or suggest a command, open a URL, copy to the clipboard, open a dialog — wherever it hides. The hand-written decoders remain the decode for releases without a description and the fallback when one fails.

Registry ids are named the same way: derived, never written. Items, entity types, block states, sounds, particles, menus, effects, statistics, data component types and the other built-in registries travel as integers that a release renumbers whenever it adds an entry, so `mineburp-packet-table` builds one id → name list per protocol from the game's own `reports/registries.json` and `reports/blocks.json` (1.14+; 1.13 writes only blocks and items) and fills the rest from `minecraft-data`'s registry lists, back to 1.7. Pre-1.13 items and blocks keep their damage-value variants; block states are stored as each block's first id and property grid, which the generator checks against every explicit id in the report. The bundle (`data/registry-names.zst`, under 100 KB for 51 releases because identical registries are stored once) is decompressed the first time an opened packet needs a name, and `registry_names::annotate` runs inside `inspect_packet` only — never in `identify_packet` — so capture never pays for it. Names are *added*, never substituted: `item_id: 869` gains `item_id_name: "minecraft:diamond_sword"` (`_names` for an id array, `_variant` for a pre-1.13 damage value), so the bytes, the layout spans, and replacement rules all keep addressing the number. Which field means which registry is decided per packet for ambiguous keys (`type` is an entity type in a spawn and a block state in a block update) and by key elsewhere. Registries a server sends during configuration — biomes, damage types, chat types, and from 1.21 enchantments and painting variants — are per connection and stay unnamed: a static table would name them confidently and wrongly.

Shape identification has a floor that no amount of decoder work raises: a body carries only so much evidence. A one-byte body holding `0` or `1` is byte-for-byte an arm swing, a client command, a container close, and a movement-input bitmask — no validator can separate them, so without a table they stay unnamed. That floor also decides how overlaps are settled between decoders that *do* validate. Two rules apply, and both are about who loses the tie rather than who wins it: a decoder's evidence must be more than the body's length (an eight-byte body is not a keep alive unless the long inside it also reads like a clock or a counter), and where two shapes genuinely coincide, the overlap goes to the packet that is orders of magnitude more common and the rarer one gives up the ambiguous slice. Mining progress and a relative entity move are both a `VarInt` id and nine bytes, separated only by a last byte that is a crack stage in one reading and an on-ground flag in the other, so stages 0 and 1 are simply not claimed. Passively captured plaintext frames are always named by shape, because a frame from an unknown state read through the play table would be named as whatever play packet shares its id.

Naming a row is cheaper than decoding it. `inspect::identify_packet` is a table lookup where a table exists — chunk, registry, and map payloads are named for free — and only otherwise runs shape identification, which skips bodies over 4 KiB: walking their NBT once per packet is exactly the work capture must not do. The description interpreter never runs during live capture. The file importer alone uses bounded definition decoding to validate candidate frame boundaries in mid-connection streams; this probe runs in `minecraft_stream`, which is only called by the importer. Its NBT text conversion has byte and template-work limits and falls back to hex.

`layout` answers a different question than `inspect`: not what a packet says but *where each value lives*. It walks a frame the inspector has already named into typed spans with byte offsets, which is what lets the Repeater and the replacement rules re-encode one value and splice it back in. A hand-written walker that accounts for the whole frame is preferred, because replacement rules already refer to its field names; otherwise the description interpreter's spans are used, named by path (`data[0].player.name`), so every field of every described packet is editable. `rewrite` builds on it: a field edit rewrites its own length prefix, so resizing a string leaves a frame that still decodes.

The *state* a packet is decoded against is tracked by the proxy, not guessed by the decoder, so the state machine has to follow every phase change. The 1.20.2 configuration boundary is read the same way — by shape, not by an id table: each half of the finish-configuration handshake is the only empty-bodied packet its direction can carry in that state, and re-entering configuration from play requires the server's offer before the client's acknowledgement is believed.

## Filtering

A filter narrows the *query*, never the loaded rows. Every control the operator touches becomes a parameterised `WHERE` clause: filtering a million-packet capture costs one bounded page, and the webview never holds the rows it is not showing.

Two rules keep the two evaluators honest with each other:

- An expression must select the same packets from the project as it does from a live stream. The in-memory evaluator in `mineburp-core` is the specification, including its sharp edges — an absent optional field never matches, even under `!=`, and ordering comparisons on text are false rather than lexicographic. A test runs both against the same corpus.
- Operator text is always bound, never interpolated. A filter expression cannot reach the SQL string.

Both rules are tested by generation, not only by example: a property test builds random expressions — nested `!`, `&&`, `||`, every field and operator, values with quotes, `%`, `_`, backslashes, and non-ASCII letters — and checks the SQL and in-memory evaluators select the same rows from a corpus with absent fields and mixed case. That is how the two places they used to differ were found: SQLite's `LOWER` folds ASCII only, so the evaluator folds ASCII only too; and a predicate on an absent column must compile to false, never SQL `NULL`, or `NOT` around it disagrees with memory.

Which rows a page reads is part of the design, not left to the planner. One enum value compiles to `column = ?`, which a single-column index — implicitly ordered by rowid — answers newest-first without sorting. Several values compile to `+column IN (…)`, keeping the planner off that index, because a handful of enum values selects much of the table and reading it through the index means sorting every match before the first page. Case-insensitive name and channel tests match expression indexes on `LOWER(column)`. The project runs a bounded `PRAGMA optimize` when it is opened and as it grows, so the planner has statistics.

A live tail (`after_id` with no `before_id`) reads the *oldest* rows past its cursor, not the newest: a tail that fell more than a page behind would otherwise skip every row between its cursor and the newest page, and never see them.

Case sensitivity is explicit rather than inherited: SQLite's `LIKE` folds ASCII case whatever its operands look like, so case-sensitive search uses `instr`, which also treats `%` and `_` as ordinary characters in a packet name.

Payload search is the one filter that cannot be answered from an index. Payloads are compressed blobs, so a `payload_search` scalar function is registered for the duration of the query with the matcher already compiled, and each surviving row is decompressed and scanned. Three consequences shape the design: the clause is always appended last so indexed terms reject rows first; decompression is capped per packet so one chunk packet cannot decide how long a query takes; and a payload that will not decompress counts as "no match" rather than failing the query, so one corrupt row cannot make a history unreadable.

A search also carries a *scope* — contains, is exactly, starts with, ends with — because "packets that carry this sequence" and "packets that are this sequence" are different questions, and only the second one can be negated into "everything except these frames". The scope is why the function is passed the row's recorded size alongside the blob: the decode stops at the scan cap, so the matcher has to know whether it is holding the whole payload. An exact match is settled by comparing sizes first, which decides almost every row without touching the bytes; a scope anchored at the end reports no match on a payload the scan truncated rather than judging a prefix as if it were the whole.

A search is also a *set*: the term is read one alternative per line and a row matches when any of them does, so "hide these four frames" is one query rather than four. Hex alternatives additionally accept `start-end`, an inclusive range compared byte by byte over sequences of the same length. The dash is safe to give meaning because the hex reader has always treated every other separator as noise and never accepted a dash, so no existing search changes meaning. Ranges are hex-only on purpose: in a text term a dash is an ordinary character, and a regular expression can already say `[\x0c-\x0f]` for itself. Malformed ranges — mismatched widths, a start past its end — are reported as errors rather than compiled into something that quietly matches nothing.

## Rewriting traffic

Replacement rules have an action: rewrite or drop, defaulting to rewrite for
older projects. Enabled drop rules evaluate the incoming decoded summary before
replacement edits and Intercept. Any matching blocker records the original frame
as dropped and returns without sending it or advancing the protocol state. This
also applies to liveness packets that bypass an existing Intercept hold. Blockers
can act in every decoded phase. Repeater injection keeps its independent path.

Matching rewrite rules apply in order, each edit seeing the output of the one
before it. A packet that no rewrite changes is forwarded untouched. Rules never
pause traffic; holding a packet for a decision is Intercept's job (below).

Four invariants hold the feature together:

- Rewrite edits never run on handshake or login frames. The proxy rewrites those itself — the handshake address, the key exchange, compression — and a rule there would undo that work or desynchronise the framing.

- A rule that fails is reported and skipped, never fatal. An absent field makes a rule inapplicable without a warning. A bad pattern must not disconnect the game an operator is testing.
- The recorded row is what went on the wire. A rewritten packet is re-derived from the frame that was actually sent and recorded as `edited`, so the history stays a record of the connection rather than of intent.
- Field edits go through `layout`, so a resized value rewrites its own length prefix. Byte-level edits do exactly what they are told; that is what makes them useful where no decoder reaches, and why they can leave a frame the client will reject.

## Intercept

Intercept holds selected handshake, status, login, configuration and play frames for the operator
to forward, edit, or drop. A held frame blocks only its own direction of its own
connection, and three rules stop a hold from costing the session:

- Keep-alives and pings, recognised by id from the version's table, are forwarded at once even while an earlier frame in the same direction is held. The reader keeps draining its socket during a hold; everything else waits behind the held frame in order, up to a bounded backlog. Held backlogs charge 64 bytes per frame in addition to payload bytes and maintain a running byte total. A queued frame that changes protocol state or stream encoding stops further decoding until released. A frame that changes the protocol state is never overtaken, because what follows it is read in the state it moves to.
- An optional deadline forwards a held frame unchanged; the UI shows the countdown.
- A held entry is released however its wait ends — a verdict, the deadline, the session closing, or the task being aborted.

## Network conditions

Every proxied connection can be given a per-direction delay, jitter, and
bandwidth ceiling, applied in the writer just before bytes leave. The proxy
terminates TCP on both sides, so the stream stays reliable and ordered: jitter
delays frames without reordering them, and loss is not simulated. Changes apply
to frames written from then on, on open connections too.

## Volume invariants

Capture rates outrun both the webview and SQLite if either is fed per packet:

- Capture and proxy writers both persist to the project and publish only a coalesced append *count* to the webview. Nothing is mirrored into an in-memory ring: a ring bounded by frame count aged rows out of the operator's reach under real Minecraft load, and payloads travelling over IPC per packet is what made the view unusable in the first place.
- The project writer commits captured frames in batched transactions. Proxy readers enqueue without waiting for SQLite. The persistence queue holds at most 64 frames and 32 MiB, with one bounded batch in flight; overflow drops rows and reports the cumulative drop count. Summary events retain database-assigned row ids after insertion.
- Packet tables render only the rows on screen; row height is fixed so the window is arithmetic.
- The history appends from a keyset cursor and never replaces loaded rows on a timer.
- Statistics, export, and deletion compile the same filter as the history and run in SQLite; export walks matching rows a page at a time, oldest first, and never loads a capture into memory.

## Concurrency invariants

- Each accepted client creates one session handle and four tasks: two readers and two writers.
- Socket writers are single-owner tasks behind channels bounded by frame count and by bytes, preserving byte order and applying encryption in one place.
- When either side closes, the other reader stops and both writers deliver what is already queued — a server's disconnect reason, typically — before a short deadline ends the session. A closed session leaves the live table; its last snapshot is in the project.
- The connection snapshot is saved on the persistence ticker, not per packet, and lifecycle changes are published immediately and saved in the background. A failed save is reported as an error event and never ends the session.
- The proxy's state machine follows the frames it forwarded, not the ones that arrived, and moves between configuration and play only on the four transition packets named by the version's table.
- Repeater injects only in configuration or play, after compression and encryption are settled.
- Client and server links have independent stateful ciphers.
- The upstream encryption response travels as plaintext, but both link ciphers are activated before it is queued, so a fast server's first encrypted reply never meets a link without its cipher. RSA key generation runs on the blocking pool.
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

Implement `SideCapture`, report honest capabilities, publish bounded observations, and keep raw platform handles out of the proxy crate. Reuse the capture pipeline (parsing, holding, reassembly) and supply only attribution: a platform answers "which process owns this 4-tuple" — `GetExtendedTcpTable` on Windows, `proc_pidfdinfo` on macOS — and the rest is shared. Capture is independent of launcher and proxy state. Platform implementations must discard unattributed traffic before publication and must not claim decryption they cannot prove.

## Exchanging captures with other tools

**Export pcapng** writes the packets a filter matches as pcapng, one synthetic TCP stream per connection (`10.1.x.y` → `10.2.x.y` on the connection's real server port, opened with a three-way handshake and closed with FINs). A decoded packet is written as an uncompressed Minecraft frame, so the stream reads like a connection with compression and encryption switched off; a row that was never decoded is written as the raw bytes it holds. Each packet carries a pcapng comment with its name, state, direction, id, and MineBurp row, which `tools/wireshark/mineburp.lua` uses to frame and name packets in Wireshark. **Import capture** reads pcap or pcapng into the open project: with no process to attribute flows to, Minecraft traffic is recognised by server port, and everything up to reassembled bytes is the live capture pipeline.

Imported streams are then split into Minecraft packets (`mineburp-capture::minecraft_stream`). Each direction of a connection runs its own frame codec, and the protocol state is followed from the packets themselves, as the proxy follows it: the handshake names the protocol and next state, Set Compression switches both codecs, login success (before 1.20.2) or the login acknowledgement moves on, and the configuration acknowledgements in each direction are recognised by their id in the version's table, never by an empty body. Rows carry the timestamp of the segment that completed the frame. Three things stop framing, and each leaves bytes as labelled raw rows rather than guessed packets:

- *Encryption.* After the Encryption Request (server) or Response (client) a direction is ciphertext under a secret the capture does not hold.
- *A capture that joined mid-connection.* There is no boundary to start from, so one is searched for: an offset where several consecutive frames parse, inflate, and — when a protocol is known, from the handshake or the import's `protocolVersion` — carry ids from the version's table and decode against its definitions. Compression is guessed the same way, compressed first because an uncompressed reading of a compressed stream also parses. Every offset is probed once; one that runs out of bytes is retried only when enough have arrived, and a search gives up on a window after a bounded wait, so ciphertext costs a few windows and then passes through raw.
- *A hole in the capture.* Reassembly marks the bytes after a skipped gap, and the reader searches again from there. A frame whose length was sound but whose contents are not (a bad zlib stream) is reported as one undecodable row and the stream stays in step.

Everything is bounded: frames by vanilla's 8 MiB, buffered bytes across all connections by a budget that sheds the largest buffer first, tracked connections by count. MineBurp's own exports are recognised by their interface name and read from their per-packet comments, so an exported proxy session — decrypted, decompressed — comes back as the packets it was written from.

The webview may only hand commands paths that fit the command — a project is a `.mineburp` file, an export a `.json` or `.pcapng` file, an import a capture file — and no export may resolve to the open project or its `SQLite` sidecars. Every command is listed in `src-tauri/build.rs`, which generates an `allow-<command>` permission for it, and the main window's capability grants exactly those; a test keeps the handler list, the manifest, and the capability identical.


## Research tools and display decoding

Project migration 6 adds bounded, versioned workbench documents for Intruder and
Sequencer. Document writes capture the expected project path so a delayed write
cannot reach another project. The UI serializes autosaves and flushes editors
before changing project or closing; active research tasks do not resume on load.
Repeater edit history is an optional typed field on existing saved tabs.

The Decoder sidebar delegates bounded conversions to `mineburp-protocol::decoder`.
Payload generation is transport-independent integer/string work in
`mineburp-core::research`. Channel explorer reuses the project's compiled filters
for full-capture SQL aggregation. Custom history columns decode only mounted rows
through bounded batch commands; decoding never moves into capture-time work.

Live Save As uses `ProjectStore::save_as_and_handoff`: the source writer remains locked through export to a private `.partial` file, metadata initialization, sync, publication, and replacement of the shared writer connection. Existing store clones therefore persist subsequent batches to the saved database. Passive flow identity survives the handoff. Ordinary `save_as` remains a snapshot copy. Desktop history pages use `query_history_page`; `interrupt_reads` affects that reader class only, leaving exports and analysis alone. Export ops default to refusing existing targets; `export_json_with_overwrite` and `export_pcapng_with_overwrite` accept an explicit overwrite boolean and still reject symlinks.
