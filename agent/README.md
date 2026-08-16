# MineBurp client-assistance agent

This Java agent observes Authlib's existing `joinServer` call and performs one
additional session join for MineBurp's upstream encryption bridge. When
**Decrypt connections** is enabled, it also rewrites a Minecraft-originated
Netty `doConnect` destination to a one-use MineBurp loopback route. It supports
both the `GameProfile` signature used through Minecraft 1.20.1 and the `UUID`
signature used from 1.20.2 onward. It has no mod-loader dependency and leaves
non-Minecraft Netty calls unchanged.

Build it from the repository root with `npm run build:agent`. The build pins and
verifies ASM 9.8, compiles Java 8-compatible bytecode, and creates the shaded
`agent/build/mineburp-agent.jar` resource.

The agent never serializes the Minecraft access token. Its loopback protocol is
documented in `docs/CLIENT_ASSISTANCE.md`.
