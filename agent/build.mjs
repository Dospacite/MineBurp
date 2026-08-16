import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const build = join(root, "build");
const dependencies = join(build, "dependencies");
const classes = join(build, "classes");
const staging = join(build, "staging");
const output = join(build, "mineburp-agent.jar");
const maven = "https://repo.maven.apache.org/maven2/org/ow2/asm";
const artifacts = [
  {
    name: "asm-9.8.jar",
    url: `${maven}/asm/9.8/asm-9.8.jar`,
    sha256: "876eab6a83daecad5ca67eb9fcabb063c97b5aeb8cf1fca7a989ecde17522051",
  },
  {
    name: "asm-commons-9.8.jar",
    url: `${maven}/asm-commons/9.8/asm-commons-9.8.jar`,
    sha256: "3301a1c1cb4c59fcc5292648dac1d7c5aed4c0f067dfbe88873b8cdfe77404f4",
  },
];

mkdirSync(dependencies, { recursive: true });
for (const artifact of artifacts) {
  const path = join(dependencies, artifact.name);
  if (!existsSync(path) || digest(path) !== artifact.sha256) {
    const response = await fetch(artifact.url);
    if (!response.ok) throw new Error(`Unable to download ${artifact.name}: ${response.status}`);
    writeFileSync(path, Buffer.from(await response.arrayBuffer()));
  }
  if (digest(path) !== artifact.sha256) throw new Error(`Checksum mismatch for ${artifact.name}`);
}

rmSync(classes, { recursive: true, force: true });
rmSync(staging, { recursive: true, force: true });
mkdirSync(classes, { recursive: true });
mkdirSync(staging, { recursive: true });

const sources = collect(join(root, "src", "main", "java"), ".java");
const separator = process.platform === "win32" ? ";" : ":";
const classpath = artifacts.map((artifact) => join(dependencies, artifact.name)).join(separator);
execFileSync("javac", ["--release", "8", "-cp", classpath, "-d", classes, ...sources], {
  stdio: "inherit",
});
for (const artifact of artifacts) {
  execFileSync("jar", ["xf", join(dependencies, artifact.name)], {
    cwd: staging,
    stdio: "inherit",
  });
}
rmSync(join(staging, "META-INF", "MANIFEST.MF"), { force: true });
for (const signature of collect(staging).filter((path) =>
  /META-INF[\\/].*\.(SF|RSA|DSA)$/i.test(path))) {
  rmSync(signature, { force: true });
}
cpSync(classes, staging, { recursive: true });
execFileSync("jar", ["cfm", output, join(root, "manifest.mf"), "-C", staging, "."], {
  stdio: "inherit",
});
console.log(`Built ${relative(process.cwd(), output)}`);

function digest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function collect(directory, suffix = "") {
  if (!existsSync(directory)) return [];
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...collect(path, suffix));
    else if (!suffix || path.endsWith(suffix)) files.push(path);
  }
  return files;
}
