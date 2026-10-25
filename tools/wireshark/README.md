# Wireshark dissector for MineBurp exports

`mineburp.lua` reads the pcapng files written by **Export pcapng** in the
history. Each connection in the export is a synthetic TCP stream
(`10.1.x.y` client, `10.2.x.y` server, on the connection's real server port),
and each packet is an uncompressed, unencrypted Minecraft frame with a comment
naming it:

```text
mineburp: name=chat; state=play; direction=c2s; id=0x07; protocol=767;
          disposition=forwarded; framing=frame; row=42; connection=<uuid>
```

The dissector frames the stream (VarInt length, VarInt packet id, body) and
takes the name, state, and direction from the comment. Rows MineBurp could not
decode — passive capture, or an encrypted stream — are exported with
`framing=raw` and shown as opaque payload.

## Install

1. In Wireshark, open **Help → About Wireshark → Folders** and note
   **Personal Lua Plugins**.
2. Copy `mineburp.lua` there and restart Wireshark (or press
   <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd> to reload Lua plugins).
3. If the server ran on a port other than 25565, add it under
   **Edit → Preferences → Protocols → MineBurp → Server ports**, or use
   **Decode As… → MINEBURP** on the stream.

Useful display filters:

```text
mineburp.name == "chat"
mineburp.direction == "s2c" && mineburp.state == "play"
mineburp.id == 0x07
mineburp.row == "42"
```

Requires Wireshark 3.6 or newer.

## Re-importing

An export can be imported back into a project with **Import capture**. The
server port is the connection's original port, so pass it in the import
options when it is not 25565.
