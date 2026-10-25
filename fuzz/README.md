# Fuzzing

Fuzz targets for the protocol crate — the code a hostile server reaches first.
They live outside the main workspace because cargo-fuzz needs a nightly
toolchain.

| Target | What it exercises |
| --- | --- |
| `frame_decode` | `FrameCodec` framing, compression, chunked-vs-whole agreement |
| `nbt` | network NBT, including list amplification and modified UTF-8 |
| `apply_edits` | replacement rules over arbitrary frames |
| `schema` | declarative schema packs over arbitrary bytes |
| `identify` | packet naming and inspection for every state and version |
| `layout_roundtrip` | field spans are in bounds and survive re-encoding |

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
cd fuzz
cargo +nightly fuzz run nbt -- -rss_limit_mb=512 -timeout=1
```

Always pass `-rss_limit_mb=512 -timeout=1`: an input that allocates
hundreds of megabytes or takes a second is a bug here even when it does not
crash, because the proxy decodes every relayed packet. A crash or slow input is
written to `artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> artifacts/<target>/<file>` and add it as a
regression test in the crate.
