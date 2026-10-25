// Builds a differential corpus for the protocol interpreter.
//
// Random packet bodies are handed to node-minecraft-protocol, the reference
// ProtoDef implementation; each one it parses is written out with the number of
// bytes it read. `mineburp-protocol`'s differential test then decodes the same
// bytes and requires the same count.
//
//   npm install --prefix /tmp/reference minecraft-protocol
//   node crates/mineburp-packet-table/tools/reference-corpus.js \
//     /tmp/reference/node_modules corpus.jsonl 47,340,754,763,767,774 40
//   MINEBURP_DIFF_CORPUS=corpus.jsonl \
//     cargo test -p mineburp-protocol --release differential -- --ignored
//
// The reference is laxer than vanilla in a few places (unknown NBT tags,
// negative counts, reads past the end of the buffer); the generator drops
// over-reads and the test documents the rest.
const path = require('path')
const fs = require('fs')

const [modules, out, protocolList, samplesArg] = process.argv.slice(2)
if (!modules || !out || !protocolList) {
  console.error('usage: reference-corpus.js <node_modules> <out.jsonl> <protocol,...> [samples]')
  process.exit(2)
}
const mc = require(path.join(modules, 'minecraft-protocol'))
const mcData = require(path.join(modules, 'minecraft-data'))
const samples = Number(samplesArg || 40)
const protocols = protocolList.split(',').map(Number)

let seed = 12345
function rand () { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff }
// Mostly zeros and small values, so parses get past their first field.
function byte () {
  const r = rand()
  if (r < 0.55) return 0
  if (r < 0.75) return 1
  if (r < 0.88) return 2 + Math.floor(rand() * 14)
  return Math.floor(rand() * 256)
}
function varint (value) {
  const bytes = []
  do { let b = value & 0x7f; value >>>= 7; if (value) b |= 0x80; bytes.push(b) } while (value)
  return bytes
}

const stream = fs.createWriteStream(out)
const states = ['handshaking', 'status', 'login', 'configuration', 'play']
for (const protocol of protocols) {
  const entry = mcData.versions.pc.find(v => v.version === protocol && mcData.supportedVersions.pc.includes(v.minecraftVersion))
  if (!entry) { console.error('no minecraft-data version for', protocol); continue }
  const version = entry.minecraftVersion
  const data = mcData(version)
  let ok = 0
  let tried = 0
  for (const state of states) {
    for (const isServer of [true, false]) {
      // isServer: the deserializer reads what a server receives (toServer).
      let parser
      try { parser = mc.createDeserializer({ state, isServer, version, noErrorLogging: true }) } catch (e) { continue }
      const side = data.protocol[state] && data.protocol[state][isServer ? 'toServer' : 'toClient']
      if (!side) continue
      const mapper = side.types.packet[1][0].type[1].mappings
      for (const key of Object.keys(mapper)) {
        const id = parseInt(key, 16)
        for (let i = 0; i < samples; i++) {
          tried++
          const length = 1 + Math.floor(rand() * 96)
          const body = []
          for (let j = 0; j < length; j++) body.push(byte())
          const buffer = Buffer.from([...varint(id), ...body])
          let parsed
          try { parsed = parser.parsePacketBuffer(buffer) } catch (e) { continue }
          if (parsed.metadata.size > buffer.length) continue
          ok++
          stream.write(JSON.stringify({ protocol, state, toServer: isServer, id, name: mapper[key], hex: buffer.toString('hex'), size: parsed.metadata.size }) + '\n')
        }
      }
    }
  }
  console.error(protocol, version, 'parsed', ok, 'of', tried)
}
stream.end()
