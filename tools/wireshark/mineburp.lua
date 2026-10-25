-- MineBurp decrypted-export dissector for Wireshark.
--
-- MineBurp's "Export pcapng" writes each connection as a synthetic TCP stream
-- of uncompressed, unencrypted Minecraft frames (VarInt length, VarInt packet
-- id, body), and puts a comment on every packet:
--
--   mineburp: name=chat; state=play; direction=c2s; id=0x07; protocol=767;
--             disposition=forwarded; framing=frame; row=42; connection=<uuid>
--
-- This dissector frames the stream, reads the packet id, and takes the name,
-- protocol state, and direction from that comment — MineBurp identified the
-- packet when it was captured, which a dissector that only sees bytes cannot
-- do for every protocol version. Rows MineBurp could not decode (passive
-- capture, encrypted streams) are exported with `framing=raw` and shown as
-- opaque data.
--
-- Install: copy this file to Wireshark's personal Lua plugins folder
-- (Help → About Wireshark → Folders → Personal Lua Plugins) and restart.
-- The server port(s) to decode are a preference: Edit → Preferences →
-- Protocols → MineBurp. "Decode As… → MINEBURP" works on any stream too.
--
-- Requires Wireshark 3.6 or newer.

local mineburp = Proto("mineburp", "MineBurp Minecraft (decrypted export)")

local fields = {
  length = ProtoField.uint32("mineburp.length", "Frame length", base.DEC),
  packet_id = ProtoField.uint32("mineburp.id", "Packet id", base.HEX),
  name = ProtoField.string("mineburp.name", "Packet"),
  state = ProtoField.string("mineburp.state", "Protocol state"),
  direction = ProtoField.string("mineburp.direction", "Direction"),
  protocol = ProtoField.string("mineburp.protocol", "Protocol version"),
  disposition = ProtoField.string("mineburp.disposition", "Disposition"),
  row = ProtoField.string("mineburp.row", "MineBurp row"),
  connection = ProtoField.string("mineburp.connection", "MineBurp connection"),
  body = ProtoField.bytes("mineburp.body", "Body"),
  raw = ProtoField.bytes("mineburp.raw", "Opaque payload"),
}
mineburp.fields = {
  fields.length, fields.packet_id, fields.name, fields.state, fields.direction,
  fields.protocol, fields.disposition, fields.row, fields.connection, fields.body,
  fields.raw,
}

local expert_bad_varint = ProtoExpert.new(
  "mineburp.bad_varint", "VarInt longer than five bytes",
  expert.group.MALFORMED, expert.severity.ERROR)
mineburp.experts = { expert_bad_varint }

mineburp.prefs.ports = Pref.range("Server ports", "25565",
  "TCP ports carrying exported Minecraft streams", 65535)

-- The frame comment field changed name across Wireshark versions.
local comment_field
for _, name in ipairs({ "frame.comment", "pkt_comment" }) do
  local ok, field = pcall(Field.new, name)
  if ok then
    comment_field = field
    break
  end
end

--- The MineBurp comment on the current frame, parsed into a table.
local function frame_metadata()
  if not comment_field then
    return nil
  end
  for _, value in ipairs({ comment_field() }) do
    local text = tostring(value.value or value)
    local body = text:match("mineburp:%s*(.*)")
    if body then
      local metadata = {}
      for key, item in body:gmatch("(%w+)=([^;]*)") do
        metadata[key] = item
      end
      return metadata
    end
  end
  return nil
end

--- Reads a VarInt at `offset`. Returns value and size, `nil` when the buffer
--- ends inside it, or `false` when it is longer than five bytes.
local function read_varint(tvb, offset)
  local value = 0
  for index = 0, 4 do
    if offset + index >= tvb:len() then
      return nil
    end
    local byte = tvb(offset + index, 1):uint()
    value = value + bit.lshift(bit.band(byte, 0x7f), 7 * index)
    if bit.band(byte, 0x80) == 0 then
      return value, index + 1
    end
  end
  return false
end

local arrows = { c2s = "C→S", s2c = "S→C" }

local function describe(pinfo, metadata, packet_id)
  local parts = {}
  if metadata and metadata.direction then
    parts[#parts + 1] = arrows[metadata.direction] or metadata.direction
  end
  if metadata and metadata.state and metadata.state ~= "" then
    parts[#parts + 1] = metadata.state
  end
  local name = metadata and metadata.name
  if name and name ~= "" then
    parts[#parts + 1] = name
  end
  if packet_id then
    parts[#parts + 1] = string.format("(0x%02x)", packet_id)
  end
  pinfo.cols.info:append(" " .. table.concat(parts, " "))
end

local function add_metadata(subtree, metadata)
  if not metadata then
    return
  end
  local function add(field, key)
    if metadata[key] and metadata[key] ~= "" then
      subtree:add(field, metadata[key])
    end
  end
  add(fields.name, "name")
  add(fields.state, "state")
  add(fields.direction, "direction")
  add(fields.protocol, "protocol")
  add(fields.disposition, "disposition")
  add(fields.row, "row")
  add(fields.connection, "connection")
end

function mineburp.dissector(tvb, pinfo, tree)
  local length = tvb:len()
  if length == 0 then
    return 0
  end
  pinfo.cols.protocol = "MineBurp"
  pinfo.cols.info = ""
  local metadata = frame_metadata()

  if metadata and metadata.framing == "raw" then
    local subtree = tree:add(mineburp, tvb(), "MineBurp opaque payload")
    add_metadata(subtree, metadata)
    subtree:add(fields.raw, tvb())
    describe(pinfo, metadata, nil)
    return length
  end

  local offset = 0
  while offset < length do
    local frame_length, prefix = read_varint(tvb, offset)
    if frame_length == nil then
      -- The length prefix itself continues in the next segment.
      pinfo.desegment_offset = offset
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      return length
    end
    if frame_length == false then
      local subtree = tree:add(mineburp, tvb(offset), "MineBurp frame")
      subtree:add_proto_expert_info(expert_bad_varint)
      return length
    end
    local total = prefix + frame_length
    if offset + total > length then
      pinfo.desegment_offset = offset
      pinfo.desegment_len = offset + total - length
      return length
    end
    local frame = tvb(offset, total)
    local subtree = tree:add(mineburp, frame, "MineBurp frame")
    subtree:add(fields.length, tvb(offset, prefix), frame_length)
    local packet_id, id_size = read_varint(tvb, offset + prefix)
    if packet_id and id_size <= frame_length then
      subtree:add(fields.packet_id, tvb(offset + prefix, id_size), packet_id)
      local body_length = frame_length - id_size
      if body_length > 0 then
        subtree:add(fields.body, tvb(offset + prefix + id_size, body_length))
      end
    end
    add_metadata(subtree, metadata)
    if metadata and metadata.name and metadata.name ~= "" then
      subtree:append_text(": " .. metadata.name)
    end
    describe(pinfo, metadata, packet_id or nil)
    offset = offset + total
  end
  return offset
end

local tcp_port = DissectorTable.get("tcp.port")
local registered_ports

function mineburp.prefs_changed()
  if registered_ports then
    tcp_port:remove(registered_ports, mineburp)
  end
  registered_ports = mineburp.prefs.ports
  tcp_port:add(registered_ports, mineburp)
end

registered_ports = mineburp.prefs.ports
tcp_port:add(registered_ports, mineburp)
tcp_port:add_for_decode_as(mineburp)
