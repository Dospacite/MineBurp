# Workbench tools

## Minecraft Decoder

The binary icon in the top bar opens a collapsible right sidebar alongside any tool. Decoder never sends traffic. Paste input, choose a transformation, and run it. **Use output as input** chains transformations; select a history entry to revisit an earlier stage. Inputs and outputs stay in the current desktop session.

Transformations include hex/UTF-8/Base64, Minecraft VarInt and VarLong, length-prefixed Minecraft strings, UUIDs, unsigned 16/32/64-bit integers in either byte order, zlib/gzip compression, network or named NBT with JSON/SNBT, and JSON formatting. Binary inputs and outputs use whitespace-separated hexadecimal byte pairs. Decimal integers remain strings throughout the UI so 64-bit values retain their precision. Primitive decodes report consumed bytes and preserve trailing bytes separately. NBT conversions require one complete NBT root; standalone JSON-to-NBT infers types unless SNBT specifies them.

Binary and decompressed inputs are bounded to 1 MiB. Text input/output is bounded to 3 MiB. Invalid UTF-8, incomplete values, invalid hex, and decompression limit violations produce errors rather than a partial successful decode.

## Channel explorer

Open **Channels** directly or through the command palette. Its database query groups the entire capture matching the Traffic filter and selected connection by channel, direction, phase, and protocol. The table includes packet counts, bytes, and connection counts. Up to 500 groups are shown; narrow the Traffic filter for larger captures.

Select a group to inspect its latest packet and browse up to 40 matching examples. The inspector shows built-in fields, matching schema-pack fields, and decode errors. **Show matching traffic** opens the corresponding history filter. **Refresh** updates the aggregate after new traffic arrives.

## Command palette

Ctrl/Cmd+K or the search icon opens the palette. Search view names, traffic presets, saved filters, and actions on the selected packet. Use Up/Down and Enter, or click a command. Escape closes it and returns focus. Opening a tool from the palette does not send a packet. Existing view shortcuts remain Ctrl/Cmd+1 through Ctrl/Cmd+9 and Ctrl/Cmd+0 for Sequencer; Channels is available in navigation and the palette.

## Selection actions

In the packet inspector, choose a field in **Structure**, click a decoded field label with a corresponding wire span, or select bytes in the hex view. The selection toolbar can:

- Send the exact selected bytes to Decoder.
- Use the field or raw byte range as an Intruder position.
- Collect a selected field with Sequencer.
- Add the field as a history column, copy its path/value, or search its value in payload history.

Field edits retain typed encoding. Raw Intruder positions retain the exact offset and length and require hexadecimal payloads. Selection actions operate on the captured packet, including when accessed through Channels.

## Payload generators

Each Intruder position has **Generate payloads**. Sources include exact decimal ranges, integer boundaries for signed/unsigned 8/16/32/64-bit types, repeated strings over a length range, manual enum values, and imported text wordlists. Preview before replacing the list. Empty lines are intentional empty payloads. Numeric ranges use integer arithmetic in Rust, including values larger than JavaScript's exact number range.

Boundary lists deliberately include just-outside values. Typed field encoding can reject those values before sending; use raw-byte positions when testing malformed encodings. Generators are bounded to 1,000 single-line values, 4,096 bytes per value, and 4 MiB combined. String length generators repeat the chosen text unit the specified number of times.

## Saved research work

Intruder configuration, seed, payload lists, results, and preview, plus Sequencer's selected field, collected/pasted samples, and analysis, autosave in the current `.mineburp` project. Project encryption applies to these documents too. Each tool has a save/restore status. Work follows **Save as** and is restored when reopening a project. Active sends and live collection are never resumed automatically.

Before switching projects or closing the desktop window, research tasks stop and pending work is flushed. Save failures leave the edits in memory and report the error. A temporary project's work is temporary until **Save as**. Documents are versioned and bounded to 16 MiB each. Intruder result labels are bounded display summaries; full configured payloads remain in the saved position lists, and sent frames remain in packet history.

## Repeater edit history

Undo/redo buttons and Ctrl/Cmd+Z, Ctrl/Cmd+Shift+Z, or Ctrl/Cmd+Y navigate packet hex edits. Editing a decoded field participates in the same history. A new edit after Undo clears the redo branch. Name a revision to keep a candidate and use the revision selector to restore it. The original frame can be displayed alongside the editor or restored as a new edit.

**Save** persists the tab with its history and revisions. Undo/redo keeps up to 100 steps within a 2 MiB hex budget per direction. Named revisions keep up to 20 entries within 2 MiB. Original comparison is unavailable for frames whose hex exceeds 2 MiB. Loading a complete packet replaces a truncated seed's original, and a late load never overwrites newer edits.

## Decoded-field history columns

In **Columns**, add a label and a decoded field path, or choose **Add history column** from the selection toolbar. Dotted keys and array indices such as `data[0].slot` are supported. An exact field name takes precedence over path traversal; matching schema-pack values take precedence over built-in fields.

Up to eight custom columns are stored with the existing local table preferences. Only visible rows request decoding, in batches of at most 32 packets, with a bounded cache scoped to the project and field paths. Missing fields, failed lookups, or packets over 1 MiB show a dash. These display columns do not change capture-time work or provide decoded-value sorting/filtering.

## Traffic presets

The Traffic toolbar and palette offer All, Quiet, Handshake and login, Configuration, Play, Plugin and mod channels, Inventory and containers, Movement, Edited and replayed, and Dropped. A preset replaces packet predicates while preserving the selected connection. Quiet hides common liveness, movement, chunk, and lighting traffic by packet name. Presets filter the display; they do not discard captured packets.

## Automatic blockers

In **Replace**, choose **Drop automatically** as a rule's action, provide the same filter expression used for traffic/replacement rules, then enable the rule. A new rule starts disabled. Drop rules do not require replacement edits.

Enabled blockers run against the incoming decoded packet before replacement edits and Intercept. Any matching blocker drops the packet regardless of rule order; it never reaches the peer, Intercept queue, or protocol-state transition logic. Keep-alives that would otherwise overtake a held packet also pass through blockers. The original frame is recorded with disposition `dropped`. Repeater injection and opaque passive traffic retain their existing independent paths.

Blocking is available during handshake, status, login, configuration, and play. Replacement editing still excludes handshake and login. A blocker can prevent login or completion of a phase. Preview evaluates the selector and shows the drop verdict without affecting live traffic. Rule persistence is backward-compatible: rules without an action continue to rewrite.

The MCP `rules` tool accepts `behavior="drop"` on add/update, and previews drop rules against a stored packet. Existing clients default to rewrite.
