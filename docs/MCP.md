# MCP server

MineBurp ships a [Model Context Protocol](https://modelcontextprotocol.io) server, so an MCP client (Claude Code, Claude Desktop, or any other) can work with the workbench: query and decode history, edit frames, manage rules, and drive Intercept and the Repeater on connections you are authorized to test.

## Running it

```bash
cargo build --release -p mineburp-mcp
# Claude Code
claude mcp add mineburp -- /path/to/MineBurp/target/release/mineburp-mcp
```

Any client that launches stdio servers takes the same command:

```json
{ "mcpServers": { "mineburp": { "command": "/path/to/mineburp-mcp" } } }
```


`mineburp-mcp` picks its mode at startup:

| Situation | Mode | What works |
| --- | --- | --- |
| The desktop app is running | **desktop** — stdio is bridged to the app | everything, including live intercept, Repeater send, network shaping, capture, decrypt mode, launchers |
| The app is not running, or `--offline` | **offline** | history, decoding, rewriting, rules, annotations, saved filters, schema packs, import/export; the `project` tool can open a file |
| `--project FILE.mineburp` | **offline** on that file | as above |

Options: `--project FILE`, `--passphrase-env VAR` (read the passphrase from an environment variable instead of the command line), `--read-only`, `--offline`, `--socket PATH`.

The desktop app listens at `$MINEBURP_MCP_SOCKET`, else `$XDG_RUNTIME_DIR/mineburp/mcp.sock`, else `$TMPDIR/mineburp-$USER/mcp.sock`. Start the app with `MINEBURP_MCP=0` to stop it listening. The desktop transport is Unix-only; on other platforms `mineburp-mcp` runs offline.

When an MCP client changes something the UI shows — intercept settings, rules, the open project, history — the app emits `mcp-change` and the UI refreshes.

## Tools

20 tools. Related actions share one tool through an `action` argument, so the tool list costs a session about 4k tokens.

| Tool | Purpose |
| --- | --- |
| `findings` | Assessment findings: list/get/create/update/delete/add_evidence/remove_evidence/export; `format: "json"` for structured output |
| `status` | One-call overview: mode, project, capture, decrypt mode, live sessions, intercept queue, rules, shaping |
| `packets` | Filtered history, one line per packet, with `before`/`after` cursors; `wait_ms` waits for new traffic; `summaries` adds decoded one-liners |
| `packet` | One packet: metadata, annotation, decode (schema packs too), editable `layout`, hex window; `path` drills into large decodes |
| `connections` | Project connections plus live sessions; `close` ends a live session |
| `stats` | Totals, top names by count/bytes, top connections, size histogram, optional timeline |
| `annotate` | Bookmark/colour/note one or many packets; list annotations |
| `filters` | Filter-language help, validation, saved filters shared with the UI |
| `decode` | Decode arbitrary hex, or a stored packet under another state/direction/protocol |
| `rewrite` | Apply edits to a frame without sending it; returns the new hex and its decode |
| `protocol` | Versions, per-version packet id tables, registry names by id or search |
| `intercept` | Configure Intercept; list, show, forward (optionally edited), drop held frames; wait for one |
| `route` | Create a one-use loopback proxy listener for an authorized protocol test client; expires after 15 seconds |
| `network` | Delay, jitter, and bandwidth per direction |
| `repeater` | Send one frame into a live connection; manage Repeater tabs |
| `capture` | Capture status/start/stop; decrypt mode on/off |
| `launcher` | Launcher instances; launch; add/remove client assistance |
| `project` | Open/create/save-as/checkpoint/compact; export JSON or pcapng; import pcap; delete history |
| `rules` | Replace rules: list/add/update/remove/preview |
| `schemas` | List or install declarative schema packs |

### Conventions

- **Packets** are referred to by row id (`#123` in output, `id`/`packet` in arguments).
- **Connections** print as the first 8 hex characters of their UUID (`c=1a2b3c4d`). Every tool accepts any unique prefix or the full UUID.
- **Frames** are the hex of the *logical* frame: packet-id VarInt followed by the body, with no length prefix, compression, or encryption. This is what the Repeater, Intercept, and rules work on.
- **Filters**: `packets` takes filter keys directly; `stats`, `project` export/delete, and `filters` save take them as a `filter` object. `expr` uses the same expression language as the UI and replace rules (`state == play && name ~ chat && size > 64`). `saved` uses a saved filter as the base.
- **Filter keys are checked**: an unknown key is an error, not an ignored argument. A packet's channel is an expression field (`expr="channel == mineburp:batch"`), not a filter key.
- **Edits** (`rewrite`, `rules`, `repeater`, `intercept` forward) use the replace-rule edit format: `field`, `field_replace`, `text`, `bytes`, `regex`, `range`, `frame`. `set: {"field": value}` is shorthand for field edits.
- Output is plain text: defaults are omitted, long strings and arrays are capped with a note saying how to see more, and a timestamp's date is printed once rather than on every line.

### A typical session

```text
status                                   → what is open and live
packets expr="state == play && name ~ chat" limit=20
packet id=4812 layout=true               → fields with byte offsets
rewrite packet=4812 set={"message":"hi"}  → check the edit offline
repeater action=send packet=4812 set={"message":"hi"}
rules action=add name=rename expr="name ~ chat" edits=[{"kind":"field_replace","name":"message","find":"a","replace":"b"}]
packets after=4900 wait_ms=15000         → watch for the result
```

## Security

The socket's directory is created `0700` and the socket itself `0600`. The app checks every connection's peer credentials and refuses any process not running as the user that owns the socket, and it never replaces a socket that another MineBurp instance is serving. Through the socket a same-user process can read decrypted traffic in the open project and act on live connections, which is also true of the desktop UI; set `MINEBURP_MCP=0` where that is not wanted.

Paths given to `project` are held to the same rules as the UI's: absolute, no `..`, the right extension, and an export can never overwrite the open project. Deleting the whole history requires `confirm=true`. The Repeater sends one frame per call.

### Headless fixture clients

Use `route host="127.0.0.1" port=25565` to create a loopback listener, then point a
protocol client at the returned `listen=` address within 15 seconds. Each route
accepts one client. Close sessions with `connections close=...`. At most 16
explicit routes can wait for clients at once. Offline-mode lab servers need no
Java agent. Online-mode upstream servers still require client assistance.

The optional, local client in `test-projects/runtime-client` (not shipped in this repository) creates this route itself and
handles Fabric configuration pings and teleport acknowledgments. See its README
for the memory limits and interactive request format.

Read-only `status`, `packets`, `packet`, `connections`, and `stats` accept
`format: "json"`. The content text then contains JSON: packet lists and
connections are arrays; packet detail includes summary, annotation, a bounded
hex window, offset and total_bytes. Status and statistics are objects.

`rewrite`, `rules` preview, and `intercept` show accept `hex_limit` in bytes
(default 512, maximum 65536). Long output is capped and reports the bytes shown
and total; increase the limit to inspect more. Rewrites and rule previews also
report changed byte ranges as half-open offsets, capped at 32 ranges.

Replacing a temporary project containing packets through `project` open,
create, or save_as requires `discard: true`. Use Save As to preserve a session.
The stdio server reconnects to the desktop socket per tool call and uses offline
mode when it cannot connect. `passphrase_env` is resolved by the stdio process
before forwarding the value over the private socket.

The desktop `replacement_rules_set` command accepts optional `expectedPath`.
When supplied, it must equal the current project path. Rule expressions are
validated and saved before the live proxy applies them. MCP rule edits hold a
mutex for the project throughout the read, modification, save, and apply steps.

`findings` uses full finding documents for create/update, UUID `id` for get/delete, and `evidence: {kind, id}` for evidence actions. Kinds are `packet`, `connection`, `repeater`, and `rule`. Export takes absolute `path`, `reportFormat: "markdown" | "html"`, optional `pcapPath`, and `overwrite`. Missing history references remain in reports.

### Connection comparison

`connections action="compare" a="<connection id>" b="<connection id>"` aligns
recorded packet sequences per direction. Optional `filter` accepts the same
filter object as `packets` (including `expr`, `dir`, `states`, and content search).
Text returns the row/difference totals and first 20 differences; `limit` bounds
that list to at most 100. `format="json"` returns all bounded alignment rows and
per-name counts, including packet summaries, `kind`, `size_delta` (B minus A),
and `first_difference` (byte offset or null). This action sends no traffic.
The limits are 20,000 packets per side, 1,024 edits per direction and a 30-second
comparison budget. Limit errors suggest narrowing the filter.
