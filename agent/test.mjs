import { execFileSync, spawn } from "node:child_process";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const agentJar = join(root, "build", "mineburp-agent.jar");
const temporary = mkdtempSync(join(tmpdir(), "mineburp-agent-test-"));
const classes = join(temporary, "classes");
const capability = "agent-smoke-test-capability";
const BROKER_LABEL = Buffer.from("mineburp-client-assistance-v2 broker");
const AGENT_LABEL = Buffer.from("mineburp-client-assistance-v2 agent");
const servers = [];
let child;

try {
  mkdirSync(classes, { recursive: true });
  execFileSync(
    "javac",
    ["--release", "8", "-cp", agentJar, "-d", classes, ...collect(join(root, "src", "test", "java"))],
    { stdio: "inherit" },
  );
  // A real listener on the IPv4 loopback: the agent must hand Minecraft an
  // address that actually connects, not merely one that looks like loopback.
  const routeServer = await listen(createServer((socket) => socket.destroy()));
  const routePort = routeServer.address().port;

  // The real broker: proves the capability and checks the agent's proof.
  const honest = await startBroker({ key: capability, routePort });
  await runAgent(honest, "trusted", routePort);
  for (const expected of ["legacy-hash", "modern-hash"]) {
    if (!honest.readyHashes.has(expected)) {
      throw new Error(`Authlib transformer did not capture ${expected}`);
    }
  }
  if (honest.joinResults.filter((result) => result === "OK").length !== 2
    || honest.joinResults.filter((result) => result === "ERR").length !== 2
    || honest.readyHashes.size !== 2) {
    throw new Error("JOIN did not run once per credential or hooked its own join");
  }
  // Exactly two: Minecraft's named and obfuscated connects. Unrelated Netty
  // callers, including a mod client started from Minecraft code, must not
  // even ask for a route.
  const expectedRoute = "203.0.113.5:25565";
  if (honest.routeRequests.length !== 2
    || honest.routeRequests.some((request) => request !== expectedRoute)) {
    throw new Error(`unexpected route requests: ${JSON.stringify(honest.routeRequests)}`);
  }
  if (honest.authFailures > 0) throw new Error("the agent sent an invalid proof");
  expectNoCapability(honest);

  // A listener on a stale broker port that does not hold the capability. The
  // agent must refuse it before revealing anything or following a route.
  const impostor = await startBroker({ key: "not-the-capability", routePort });
  await runAgent(impostor, "refused", routePort);
  expectOnlyHello(impostor, "an impostor broker");

  // A broker speaking another protocol version: the agent fails closed.
  const outdated = await startBroker({ key: capability, routePort, unsupported: true });
  await runAgent(outdated, "refused", routePort);
  expectOnlyHello(outdated, "a broker of another protocol version");

  console.log(
    "Agent transformed Authlib joins and Netty private route requests, "
      + "authenticated the broker, and refused an impostor without blocking Minecraft.",
  );
} finally {
  if (child && child.exitCode === null) child.kill();
  for (const server of servers) server.close();
  rmSync(temporary, { recursive: true, force: true });
}

/** A fake broker speaking protocol 2. `key` is the capability it believes in. */
async function startBroker({ key, routePort, unsupported = false }) {
  const record = {
    received: [],
    readyHashes: new Set(),
    routeRequests: [],
    authFailures: 0,
    joinResults: [],
  };
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    let buffered = "";
    let stage = "hello";
    let agentNonce;
    let brokerNonce;
    socket.on("error", () => {});
    socket.on("data", (chunk) => {
      buffered += chunk;
      let newline;
      while ((newline = buffered.indexOf("\n")) >= 0) {
        const line = buffered.slice(0, newline).replace(/\r$/, "");
        buffered = buffered.slice(newline + 1);
        record.received.push(line);
        const fields = line.split("\t");
        if (stage === "hello" && fields[0] === "HELLO") {
          if (unsupported) {
            socket.end("ERROR\tunsupported_protocol\t3\n");
            return;
          }
          agentNonce = Buffer.from(fields[2] ?? "", "base64url");
          brokerNonce = randomBytes(32);
          const proof = hmac(key, BROKER_LABEL, agentNonce, brokerNonce);
          socket.write(`CHALLENGE\t${brokerNonce.toString("base64url")}\t${proof.toString("base64url")}\n`);
          stage = "auth";
        } else if (stage === "auth" && fields[0] === "AUTH") {
          const supplied = Buffer.from(fields[1] ?? "", "base64url");
          const expected = hmac(key, AGENT_LABEL, agentNonce, brokerNonce);
          if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
            record.authFailures += 1;
            socket.end("ERROR\tauthentication_failed\n");
            return;
          }
          socket.write("HELLO_OK\t00000000-0000-0000-0000-000000000001\n");
          stage = "purpose";
        } else if (stage === "purpose" && fields[0] === "SESSION") {
          stage = "session";
        } else if (stage === "purpose" && fields[0] === "ROUTE" && fields.length === 3) {
          record.routeRequests.push(`${decode(fields[1])}:${fields[2]}`);
          socket.write(`ROUTE_OK\t${routePort}\n`);
        } else if (stage === "session" && fields[0] === "READY" && fields.length === 3) {
          const hash = decode(fields[1]);
          record.readyHashes.add(hash);
          const request = hash === "legacy-hash" ? "00000000-0000-0000-0000-000000000002" : "00000000-0000-0000-0000-000000000003";
          socket.write(`JOIN\t${request}\t${fields[1]}\t${Buffer.from("upstream-" + hash).toString("base64url")}\n`);
          // A credential is one-use. A repeated request must fail.
          socket.write(`JOIN\t00000000-0000-0000-0000-000000000004\t${fields[1]}\t${fields[1]}\n`);
        } else if (stage === "session" && fields[0] === "RESULT") {
          record.joinResults.push(fields[2]);
        }
      }
    });
  });
  await listen(server);
  record.port = server.address().port;
  return record;
}

async function runAgent(broker, mode, routePort) {
  const configuration = join(temporary, `client-assistance-${mode}-${broker.port}.properties`);
  writeFileSync(
    configuration,
    `protocol=2\nhost=127.0.0.1\nport=${broker.port}\ncapability=${capability}\ntransparent_intercept=true\n`,
    { mode: 0o600 },
  );
  child = spawn(
    "java",
    [
      `-javaagent:${agentJar}=config=${configuration}`,
      // Exactly what Minecraft launches with: it makes getLoopbackAddress()
      // return ::1, which is how a route bound to 127.0.0.1 became unreachable.
      "-Djava.net.preferIPv6Addresses=system",
      "-cp",
      classes,
      "tools.mineburp.agent.test.TransformerSmoke",
      String(routePort),
      mode,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const exitCode = await new Promise((resolveExit, rejectExit) => {
    const timeout = setTimeout(
      () => rejectExit(new Error(`agent smoke test (${mode}) timed out\n${output}`)),
      15_000,
    );
    timeout.unref();
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolveExit(code);
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      rejectExit(error);
    });
  });
  if (exitCode !== 0) throw new Error(`agent JVM (${mode}) exited with ${exitCode}\n${output}`);
}

function expectNoCapability(broker) {
  if (broker.received.some((line) => line.includes(capability))) {
    throw new Error("the capability crossed the socket");
  }
}

function expectOnlyHello(broker, who) {
  expectNoCapability(broker);
  const other = broker.received.filter((line) => !line.startsWith("HELLO\t2\t"));
  if (other.length > 0) {
    throw new Error(`the agent sent ${JSON.stringify(other)} to ${who}`);
  }
  if (broker.received.length === 0) {
    throw new Error(`the agent never contacted ${who}; the refusal was not exercised`);
  }
}

function hmac(key, label, agentNonce, brokerNonce) {
  return createHmac("sha256", key)
    .update(label)
    .update(Buffer.from([0]))
    .update(agentNonce)
    .update(brokerNonce)
    .digest();
}

async function listen(server) {
  servers.push(server);
  await new Promise((resolveListening, rejectListening) => {
    server.once("error", rejectListening);
    server.listen(0, "127.0.0.1", resolveListening);
  });
  return server;
}

function collect(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...collect(path));
    else if (path.endsWith(".java")) files.push(path);
  }
  return files;
}

function decode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}
