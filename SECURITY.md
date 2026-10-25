# Security policy and assessment boundaries

MineBurp is intended for authorized testing of Minecraft clients and servers. Do not use it to access, disrupt, or alter systems without permission.

## Design controls

- Automatic capture is delegated to Wireshark's privilege-separated `dumpcap`; MineBurp itself does not request raw-socket privileges.
- Incoming frame lengths, decompressed lengths, strings, schema depth, and collections are bounded.
- Project passphrases are passed to SQLCipher and are not stored in project metadata.
- Authentication tokens — the Microsoft, Xbox, and Minecraft tokens of every step of the sign-in chain — have redacted `Debug` output and are zeroized on drop. `MinecraftSession` implements neither `Serialize` nor `Deserialize`, so no generic serializer can carry its tokens to the webview, a log, or a file. Identity-service requests time out (10 s connect, 30 s total), and quoted error bodies are capped at 512 bytes.
- OAuth uses PKCE and validates the returned state.
- Launcher-assisted access tokens never leave the Minecraft JVM. The agent clears its credential reference after one use or 60 seconds.
- The agent broker accepts only loopback connections. Both sides prove they hold a random per-run capability, stored in a user-only configuration file, with HMAC-SHA256 over a role label and two fresh 32-byte nonces; the capability itself never crosses the socket. The broker proves itself first, and the agent sends nothing derived from the capability, registers no session, and follows no route until that proof checks out — so a program that takes over a stale broker port after MineBurp exits learns nothing and cannot redirect the game. Proofs are compared in constant time. The wire protocol is versioned (currently 2); a mismatched agent and broker refuse each other with a message saying so.
- Broker connections must authenticate and name their purpose within 5 seconds, at most 64 may be open at once, and a `READY` session expires after 60 seconds, matching the agent's credential lifetime. An agent can only register, replace, and answer its own sessions: a session another agent holds is not overwritten, a `RESULT` is accepted only from the agent the join was sent to, and one agent may hold at most 64 ready sessions.
- Decrypt mode is disabled by default. Its client-side route requests are capability-protected, loopback-only, scoped to calls whose direct caller of Netty's `Bootstrap#connect` is Minecraft's own connection class (by name under Mojang, MCP, intermediary, and Yarn naming, and by shape — a default-package Netty inbound handler — on obfuscated releases), and expire before an unused private listener can linger.
- RSA verification tokens use constant-time comparison.
- Schema packs are JSON data. They cannot import code, libraries, URLs, or scripts.
- Minecraft is launched as the desktop user; the whole MineBurp application should not be run with elevated privileges.

## Current boundaries

- Launcher assistance is the default online-mode authentication path and does not require an Entra application. The optional direct Microsoft flow requires a public-client application ID configured by the distributor; no third-party ID is bundled.
- Refresh tokens are held for the process lifetime. `CredentialStore` is the extension boundary for durable storage, and the `os-keyring` feature of `mineburp-auth` provides an OS keyring backend (run on the blocking pool), but the desktop app does not enable it: it keeps no sign-in across restarts. No plaintext credential file is created.
- The agent bundles ASM relocated to `tools.mineburp.shaded.asm`, so it cannot clash with a mod loader's own ASM.
- Authlib instrumentation recognizes the legacy `GameProfile` and modern `UUID` `joinServer` signatures. An unknown future signature is left untouched, which preserves game startup but makes client assistance unavailable until support is added.
- The 1.19–1.19.2 signed-nonce response is accepted so those clients can be inspected. Its profile-key signature authenticates the exchange to Mojang's session service but is not verified by MineBurp, which holds no profile public key; verify-token negotiation is verified and supported across all other bundled releases.
- On Linux, passive capture resolves socket inodes from detected Minecraft client JVMs through `procfs`. Unattributed frames and frames owned by other processes are discarded before desktop events or project persistence. Short-lived sockets may close before ownership can be observed.
- Decrypt mode does not install host TUN or `nftables` rules and does not route arbitrary system traffic. It rewrites only Minecraft-initiated Netty destinations through the configured Java agent. Separate mod/launcher HTTPS and certificate-pinned connections remain out of path.
- Passive capture does not decrypt encrypted payloads, reassemble IP fragments, or currently walk IPv6 extension-header chains.
- Modern play traffic can include signed chat or command data. Mod/plugin payloads can carry independent integrity contracts. The inspector marks these contexts as unsafe to modify; users must forward them unchanged unless they have verified the relevant contract.
- A writable project stores captured payloads. Treat `.mineburp` files as sensitive assessment artifacts and use a passphrase when appropriate.
- Unknown packet versions and formats remain raw. MineBurp never presents guessed fields as decoded facts.

## Reporting vulnerabilities

Do not include access tokens, refresh tokens, project passphrases, or captured private server data in a report. Include the affected crate, a minimal reproduction, and whether the issue crosses the loopback or project trust boundary.
