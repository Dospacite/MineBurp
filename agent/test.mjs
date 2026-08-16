import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const agentJar = join(root, "build", "mineburp-agent.jar");
const temporary = mkdtempSync(join(tmpdir(), "mineburp-agent-test-"));
const classes = join(temporary, "classes");
const configuration = join(temporary, "client-assistance.properties");
const readyHashes = new Set();
const routeRequests = [];
const capability = "agent-smoke-test-capability";
let child;
let routeServer;
let routePort;

try {
  mkdirSync(classes, { recursive: true });
  execFileSync(
    "javac",
    ["--release", "8", "-cp", agentJar, "-d", classes, ...collect(join(root, "src", "test", "java"))],
    { stdio: "inherit" },
  );
  // A real listener on the IPv4 loopback: the agent must hand Minecraft an
  // address that actually connects, not merely one that looks like loopback.
  routeServer = createServer((socket) => socket.destroy());
  await new Promise((resolveListening, rejectListening) => {
    routeServer.once("error", rejectListening);
    routeServer.listen(0, "127.0.0.1", resolveListening);
  });
  routePort = routeServer.address().port;

  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    let buffered = "";
    socket.on("data", (chunk) => {
      buffered += chunk;
      let newline;
      while ((newline = buffered.indexOf("\n")) >= 0) {
        const line = buffered.slice(0, newline).replace(/\r$/, "");
        buffered = buffered.slice(newline + 1);
        const fields = line.split("\t");
        if (fields[0] === "HELLO" && fields[1] === "1" && fields[2] === capability) {
          socket.write("HELLO_OK\t00000000-0000-0000-0000-000000000001\n");
        } else if (fields[0] === "READY" && fields.length === 3) {
          readyHashes.add(decode(fields[1]));
        } else if (fields[0] === "ROUTE" && fields.length === 3) {
          routeRequests.push(`${decode(fields[1])}:${fields[2]}`);
          socket.write(`ROUTE_OK\t${routePort}\n`);
        }
      }
    });
  });
  await new Promise((resolveListening, rejectListening) => {
    server.once("error", rejectListening);
    server.listen(0, "127.0.0.1", resolveListening);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test broker did not bind");
  writeFileSync(
    configuration,
    `protocol=1\nhost=127.0.0.1\nport=${address.port}\ncapability=${capability}\ntransparent_intercept=true\n`,
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
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolveExit, rejectExit) => {
    const timeout = setTimeout(
      () => rejectExit(new Error("agent smoke test timed out")),
      10_000,
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
  server.close();
  routeServer.close();
  if (exitCode !== 0) throw new Error(`agent JVM exited with ${exitCode}\n${stdout}${stderr}`);
  for (const expected of ["legacy-hash", "modern-hash"]) {
    if (!readyHashes.has(expected)) throw new Error(`Authlib transformer did not capture ${expected}`);
  }
  // Exactly one: Minecraft's connect is routed and the unrelated Netty caller
  // in the same JVM must not even ask for a route.
  if (routeRequests.length !== 1 || routeRequests[0] !== "203.0.113.5:25565") {
    throw new Error(`unexpected route requests: ${JSON.stringify(routeRequests)}`);
  }
  console.log("Agent transformed Authlib joins and Netty private route requests without blocking Minecraft.");
} finally {
  if (child && child.exitCode === null) child.kill();
  if (routeServer) routeServer.close();
  rmSync(temporary, { recursive: true, force: true });
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
