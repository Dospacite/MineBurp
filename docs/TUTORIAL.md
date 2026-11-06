# Active testing in a disposable lab

This walkthrough follows local fixture tests recorded on October 27–28, 2026.
The optional `test-projects/README.md` and `test-projects/TEST-RESULTS.md` in the
owner's checkout contain the setup and evidence. Those local projects are not
shipped or required to build MineBurp. Use your own equivalent lab if they are
unavailable. The reported results below describe those runs, not a verification
of every server or plugin.

## Prepare a connection

Use a disposable private Paper 1.21.6 server with the optional `paper-shop` lab
plugin. Build the local fixtures with JDK 21 and `./gradlew build`; install the
plugin jar and start the server with `-Dmineburp.fixtures.enabled=true` before
`-jar`. The fixtures deliberately change inventories. Give only your trusted
lab player operator access and arm the shop with `/labmenu arm`; the fixture's
arming session expires after five minutes.

Start MineBurp and save the temporary project. For a normal Minecraft client,
configure assistance in Instances, enable Decrypt connections, then launch and
connect. See [client assistance](CLIENT_ASSISTANCE.md).

For an offline-mode headless lab client, connect an MCP client to the running
desktop and call:

```text
route host="127.0.0.1" port=25565
```

Point the protocol client at the returned loopback listener within 15 seconds.
Preserve the intended Minecraft handshake destination. Each route accepts one
client; request another after disconnecting. The optional local
`test-projects/runtime-client` handles routing and teleport acknowledgments.
No agent is needed for this offline-mode route. Online-mode servers still need
client assistance.

## Find and understand the channel

Generate one baseline shop request, then use Channel explorer or:

```text
packets expr="direction == client_to_server && channel == mineburp:batch" limit=10
packet id=PACKET_ID layout=true
```

Substitute the id returned by `packets`. The shop batch body is an operation
byte, declared count byte, and marker bytes. Operation 3, count 1 and three
markers has body `03 01 01 01 01`. Keep the packet id and channel envelope from
the actual captured frame. MCP frames exclude transport length, compression and
encryption. Do not copy packet ids from another Minecraft version.

## Hold and edit one request

Enable Intercept for client-to-server traffic with this selector:

```text
state == play && channel == mineburp:batch
```

Send another baseline request. Inspect the held packet, find the body after its
channel envelope, and edit only the count or markers in hex. Forward once and
check the server inventory and history's `edited` result. In the recorded test,
count 1 with three markers granted three nuggets because the fixture validated
the declared length but processed trailing markers. Drop another held request
and confirm it causes no inventory change. Turn Intercept off afterward.

## Repeat and compare

Send the captured packet to Repeater. Keep its connection, direction and state,
and send one attempt at a time. Compare the baseline and edited history packets
in slots A and B to check the exact bytes changed. Verify inventory effects on
the server, since a successful send alone proves no application outcome.
The recorded inventory fixture also granted a diamond for each replayed claim;
that is a separate `mineburp:inventory` operation, not the shop batch packet.

## Make the edit repeatable

In Replace, add a narrowly scoped rule using the channel selector above. Choose
a byte-range edit at the body offsets observed in your packet, replacing the
baseline body with the edited body. Preview against the original row and confirm
the expected count and hex before enabling it. Disable Intercept, generate one
normal request, and verify the rule's effect. Disable or remove the rule and
repeat the baseline to confirm normal behavior returns.

Save the project, annotate both rows with expected and observed effects, and
export a filtered pcapng. Re-import it to inspect the decoded exchange without
keeping the game running. Stop the lab server and remove its vulnerable plugin
when finished.
