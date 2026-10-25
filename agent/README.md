# MineBurp client-assistance agent

This Java agent observes Authlib's existing `joinServer` call and performs one
additional session join for MineBurp's upstream encryption bridge. When
**Decrypt connections** is enabled, it also rewrites a Minecraft-originated
Netty `Bootstrap#connect` destination to a one-use MineBurp loopback route. It supports
both the `GameProfile` signature used through Minecraft 1.20.1 and the `UUID`
signature used from 1.20.2 onward. It has no mod-loader dependency and leaves
non-Minecraft Netty calls unchanged.

Build it from the repository root with `npm run build:agent`. The build pins and
verifies ASM 9.8, compiles Java 8-compatible bytecode, relocates ASM to
`tools.mineburp.shaded.asm` (with `build-tools/Relocate.java`, which is not
shipped) so it cannot clash with a mod loader's own ASM, and creates
`agent/build/mineburp-agent.jar`.

The agent never serializes the Minecraft access token. Its loopback protocol, a mutual
HMAC challenge keyed by a per-run capability, is documented in `docs/CLIENT_ASSISTANCE.md`.
