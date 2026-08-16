# Security policy and assessment boundaries

MineBurp is intended for authorized testing of Minecraft clients and servers. Do not use it to access, disrupt, or alter systems without permission.

## Design controls

- Automatic capture is delegated to Wireshark's privilege-separated `dumpcap`; MineBurp itself does not request raw-socket privileges.
- Incoming frame lengths, decompressed lengths, strings, schema depth, and collections are bounded.
- Project passphrases are passed to SQLCipher and are not stored in project metadata.
- Authentication tokens have redacted `Debug` output, are zeroized on drop, and are not serialized through Tauri commands.
- OAuth uses PKCE and validates the returned state.
- Launcher-assisted access tokens never leave the Minecraft JVM. The agent clears its credential reference after one use or 60 seconds.
- The agent broker accepts only loopback connections authenticated with a random per-run capability stored in a user-only configuration file.
- Decrypt mode is disabled by default. Its client-side route requests are capability-protected, loopback-only, scoped to a Minecraft network call stack, and expire before an unused private listener can linger.
- RSA verification tokens use constant-time comparison.
- Schema packs are JSON data. They cannot import code, libraries, URLs, or scripts.
- Minecraft is launched as the desktop user; the whole MineBurp application should not be run with elevated privileges.

## Current boundaries

- Launcher assistance is the default online-mode authentication path and does not require an Entra application. The optional direct Microsoft flow requires a public-client application ID configured by the distributor; no third-party ID is bundled.
- Refresh tokens are held for the process lifetime. `CredentialStore` is the extension boundary for an OS keyring backend; no plaintext credential file is created.
- Authlib instrumentation recognizes the legacy `GameProfile` and modern `UUID` `joinServer` signatures. An unknown future signature is left untouched, which preserves game startup but makes client assistance unavailable until support is added.
- The signed-nonce branch used by some 1.19–1.19.2 clients is rejected. Verify-token negotiation is supported across the other bundled releases.
- On Linux, passive capture resolves socket inodes from detected Minecraft client JVMs through `procfs`. Unattributed frames and frames owned by other processes are discarded before desktop events or project persistence. Short-lived sockets may close before ownership can be observed.
- Decrypt mode does not install host TUN or `nftables` rules and does not route arbitrary system traffic. It rewrites only Minecraft-initiated Netty destinations through the configured Java agent. Separate mod/launcher HTTPS and certificate-pinned connections remain out of path.
- Passive capture does not decrypt encrypted payloads, reassemble IP fragments, or currently walk IPv6 extension-header chains.
- Modern play traffic can include signed chat or command data. Mod/plugin payloads can carry independent integrity contracts. The inspector marks these contexts as unsafe to modify; users must forward them unchanged unless they have verified the relevant contract.
- A writable project stores captured payloads. Treat `.mineburp` files as sensitive assessment artifacts and use a passphrase when appropriate.
- Unknown packet versions and formats remain raw. MineBurp never presents guessed fields as decoded facts.

## Reporting vulnerabilities

Do not include access tokens, refresh tokens, project passphrases, or captured private server data in a report. Include the affected crate, a minimal reproduction, and whether the issue crosses the loopback or project trust boundary.
