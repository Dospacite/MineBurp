# Client assistance

Automatic traffic capture does not require Microsoft login, an Entra application, or a Java agent. Client assistance becomes necessary when the opt-in **Decrypt connections** mode terminates an online-mode Minecraft connection. Minecraft continues to authenticate through its normal launcher. A small Java agent observes Authlib's existing session join and can ask that same in-process Authlib service to join a different upstream server hash.

This works for vanilla and for Fabric, Quilt, Forge, and NeoForge because authentication reaches the same Authlib boundary before loader-specific login and plugin-channel traffic begins.

## Setup by launcher

For normal passive use, start MineBurp and launch any instance normally. Only configure assistance if you are developing or using an active in-path extension.

| Launcher | Optional advanced setup | Normal launch |
| --- | --- | --- |
| Official Minecraft Launcher | Close Minecraft and the launcher, then select **Configure assistance** for the installation. MineBurp updates only that profile's `javaArgs` and records its exact addition for removal. | Open the launcher and start the selected installation normally. |
| Prism Launcher / MultiMC | Select **Configure assistance**. MineBurp updates the instance's `JvmArgs` and records its exact addition for removal. | Select **Launch** or use the launcher normally. |
| Modrinth App | Select **Copy setup argument**, open the instance settings, and paste it into that instance's Java/JVM arguments. | Select **Launch** or use the app normally. |
| CurseForge | Select **Copy setup argument**, open the modpack's **Profile Options**, and paste it under **Additional Arguments**. | Launch the profile normally. |

If assistance is needed, fully stop every running Minecraft process before relaunching it. A client without the displayed `-javaagent` argument cannot assist an active online-mode bridge, but passive capture continues to work. For managed launchers, **Remove assistance** removes only the argument MineBurp previously recorded.

## Decrypt connection mode

1. Configure assistance for the instance, then fully restart Minecraft.
2. In **Traffic**, turn on **Decrypt connections**. It is off by default.
3. Connect to a server normally. The agent recognizes a Minecraft-owned Netty connection, requests a one-use private route, and substitutes only that destination with a loopback port returned by MineBurp.

The desktop app then presents its own RSA key to the client, decrypts the client-side AES stream, re-encrypts a separate stream to the real server, and records decoded frames between the two links. The loopback port is private to that route, bound only on `127.0.0.1`, and is never shown as a user-managed listener. If route setup fails, the agent leaves the original destination untouched.

This client-assisted route adapter avoids silently installing privileged TUN or `nftables` rules. It deliberately ignores any Netty connect whose direct caller is not Minecraft's own connection class — matched by name under Mojang, MCP, intermediary, and Yarn naming, and on obfuscated releases by shape, as a default-package Netty inbound handler — leaving separate launcher/mod TLS traffic — including certificate-pinned traffic — outside MineBurp's decrypt path.

## Authentication sequence

```text
Minecraft/Authlib           Java agent          MineBurp proxy           Mojang session API
       │ join(client hash)       │                    │                         │
       ├────────────────────────►│ READY(client hash) ├                         │
       │──────────────────────────────────────────────────────────────────────►│
       │                         │                    │ upstream hash needed    │
       │                         │◄──── JOIN ─────────┤                         │
       │ join(upstream hash)     │                    │                         │
       │◄────────────────────────┤────────────────────────────────────────────►│
       │                         │──── RESULT ───────►│ continue encryption     │
```

MineBurp terminates the client-facing and upstream-facing RSA handshakes with different public keys, so their signed server hashes differ. The broker uses the client hash only to select the correct short-lived session, then asks Authlib to join the upstream hash.

## Local protocol and security boundary

The desktop app creates a random loopback TCP port and a 256-bit capability on every start. It atomically writes `client-assistance.properties` into the per-user application configuration directory with mode `0600` on Unix. The desktop API exposes the endpoint and JVM argument for setup, but never the capability.

The line protocol is deliberately small. Every connection opens with a mutual challenge, version 2 of the protocol:

```text
agent  → HELLO      2  <agent nonce>
broker → CHALLENGE  <broker nonce>  <broker proof>
agent  → AUTH       <agent proof>
broker → HELLO_OK   <agent id>
agent  → SESSION | ROUTE <host> <port>
```

Nonces are 32 random bytes; nonces and proofs are URL-safe base64 without padding. A proof is HMAC-SHA256 keyed by the capability over a role label (`mineburp-client-assistance-v2 broker` or `… agent`), a zero byte, the agent nonce, and the broker nonce. The capability never crosses the socket. The broker proves itself first: an agent that cannot verify the broker's proof closes the connection without sending `AUTH`, registers no session with it, and follows none of its routes. Because each side contributes a fresh nonce, a recorded `AUTH` or `CHALLENGE` is useless on any other connection. A broker that receives another protocol version answers `ERROR unsupported_protocol 2`, and the agent reports the mismatch once and stays off.

After the handshake:

- `SESSION` keeps the connection open for Authlib joins; `READY` registers a URL-safe-base64 client hash and profile identifier on it.
- `ROUTE` asks for a private port for one original host and port; `ROUTE_OK` returns that port and closes the short-lived route request.
- `JOIN` contains a random request ID plus the client and upstream hashes.
- `RESULT` reports success or a sanitized error.

The handshake and the purpose line must arrive within 5 seconds, and at most 64 broker connections may be open at once. A `READY` session expires after 60 seconds. An agent can only register, replace, and answer its own sessions: a client hash another agent holds is not overwritten, a `RESULT` counts only from the agent its `JOIN` was sent to, and pending joins fail as soon as their agent disconnects.

Access and refresh tokens are not fields in this protocol. The Java agent holds only the objects already passed to Authlib, clears each credential after its one allowed assisted join or after 60 seconds, and never logs token values. Routes are consumed before a `JOIN` is sent and results time out. The agent accepts only a loopback broker address and the Rust broker rejects non-loopback peers.

The Java agent is fail-open: any instrumentation, configuration, or broker error leaves Authlib's original method and the original network destination running. The effect is loss of assisted inspection, not loss of the user's normal Minecraft login. A private route expires if no client connects within 15 seconds. A hostile process already running as the same operating-system user remains inside the local trust boundary and may be able to read other processes or user-owned configuration files.

## Optional direct OAuth

A distributor with its own approved public-client registration may compile with `MINEBURP_MICROSOFT_CLIENT_ID`. That enables an advanced direct sign-in panel and injects `mineburp-auth` as the same `SessionJoinProvider` contract. No client secret is used or bundled. This is optional and is not required for vanilla or modded clients using launcher assistance.
