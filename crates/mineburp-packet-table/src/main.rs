//! Generates a play-state packet-id table for one protocol version.
//!
//! The default path is fully automatic: name a protocol, and the tool resolves
//! the release, downloads that release's own server jar from Mojang, runs the
//! data generator inside it, and writes the ids the game itself reports. Every
//! step can also be handed in ready-made, which is what makes the tool usable
//! offline and on versions that predate the report.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use mineburp_packet_table::{PlayTable, TableError, from_prismarine, from_vanilla_report, merge};
use mineburp_protocol::PacketRegistry;

const MANIFEST_URL: &str = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";
const DEFAULT_OUTPUT: &str = "crates/mineburp-protocol/data/play-packets.json";
const USAGE: &str = "\
mineburp-packet-table — generate a play packet-id table for one protocol

USAGE:
    mineburp-packet-table --protocol <number> [source] [options]
    mineburp-packet-table --version <release> [source] [options]

SOURCES (the first one given wins; the default downloads the release):
    --report <file>       a vanilla data generator reports/packets.json
    --jar <file>          a server jar to run the data generator in
    --prismarine <file>   a minecraft-data protocol.json (pre-1.20.5 versions)

OPTIONS:
    --output <file>       table file to update (default: {DEFAULT_OUTPUT})
    --stdout              print the table instead of writing it
    --java <path>         java to run the data generator with (default: java)
    --cache <dir>         where downloaded jars are kept (default: target/minecraft)
    --help                show this message
";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug, Default)]
struct Options {
    protocol: Option<i32>,
    version: Option<String>,
    report: Option<PathBuf>,
    jar: Option<PathBuf>,
    prismarine: Option<PathBuf>,
    output: Option<PathBuf>,
    java: Option<String>,
    cache: Option<PathBuf>,
    stdout: bool,
}

fn run() -> Result<(), Failure> {
    let mut options = Options::default();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| Failure(format!("`{argument}` needs a value")))
        };
        match argument.as_str() {
            "--protocol" => {
                let raw = value()?;
                options.protocol = Some(
                    raw.parse()
                        .map_err(|_| Failure(format!("`{raw}` is not a protocol number")))?,
                );
            }
            "--version" => options.version = Some(value()?),
            "--report" => options.report = Some(value()?.into()),
            "--jar" => options.jar = Some(value()?.into()),
            "--prismarine" => options.prismarine = Some(value()?.into()),
            "--output" => options.output = Some(value()?.into()),
            "--java" => options.java = Some(value()?),
            "--cache" => options.cache = Some(value()?.into()),
            "--stdout" => options.stdout = true,
            "--help" | "-h" => {
                println!("{}", USAGE.replace("{DEFAULT_OUTPUT}", DEFAULT_OUTPUT));
                return Ok(());
            }
            other => return Err(Failure(format!("unknown argument `{other}`"))),
        }
    }

    let (protocol, version) = resolve_version(&options)?;
    let table = build(&options, protocol, &version)?;
    eprintln!(
        "{}: {} play packets from the {}",
        version,
        table.packet_count(),
        table.source
    );
    write(&options, table)
}

/// Resolves the protocol number and release name from whichever one was given.
///
/// The bundled version registry already knows both, so naming either is enough
/// — and a protocol the registry does not know is a typo worth reporting rather
/// than a table worth writing.
fn resolve_version(options: &Options) -> Result<(i32, String), Failure> {
    let registry = PacketRegistry::bundled();
    if let Some(protocol) = options.protocol {
        let canonical = registry
            .version(protocol)
            .map(|entry| entry.canonical.clone());
        let version = options.version.clone().or(canonical).ok_or_else(|| {
            Failure(format!(
                "protocol {protocol} is not in the bundled version registry; pass --version too"
            ))
        })?;
        return Ok((protocol, version));
    }
    let name = options
        .version
        .clone()
        .ok_or_else(|| Failure("pass --protocol or --version (see --help)".into()))?;
    let entry = registry
        .supported_protocols()
        .into_iter()
        .find(|entry| entry.canonical == name || entry.releases.contains(&name))
        .ok_or_else(|| {
            Failure(format!(
                "`{name}` is not in the bundled version registry; pass --protocol too"
            ))
        })?;
    Ok((entry.protocol, name))
}

fn build(options: &Options, protocol: i32, version: &str) -> Result<PlayTable, Failure> {
    if let Some(path) = &options.prismarine {
        let json = read(path)?;
        return Ok(from_prismarine(&json, protocol, version)?);
    }
    if let Some(path) = &options.report {
        let json = read(path)?;
        return Ok(from_vanilla_report(&json, protocol, version)?);
    }
    let jar = match &options.jar {
        Some(path) => path.clone(),
        None => download_server(options, version)?,
    };
    let report = generate_report(options, &jar, version)?;
    Ok(from_vanilla_report(&report, protocol, version)?)
}

fn write(options: &Options, table: PlayTable) -> Result<(), Failure> {
    let path = options
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT));
    let existing = if options.stdout || !path.exists() {
        Vec::new()
    } else {
        mineburp_packet_table::parse_existing(&read(&path)?)?
    };
    let rendered = mineburp_packet_table::render(&merge(existing, table))?;
    if options.stdout {
        print!("{rendered}");
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| Failure(format!("{}: {error}", parent.display())))?;
    }
    fs::write(&path, rendered).map_err(|error| Failure(format!("{}: {error}", path.display())))?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

/// Downloads the release's server jar, straight from the manifest Mojang serves.
fn download_server(options: &Options, version: &str) -> Result<PathBuf, Failure> {
    let cache = options
        .cache
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/minecraft"));
    fs::create_dir_all(&cache).map_err(|error| Failure(format!("{}: {error}", cache.display())))?;
    let jar = cache.join(format!("server-{version}.jar"));
    if jar.exists() {
        eprintln!("using cached {}", jar.display());
        return Ok(jar);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_mins(5))
        .user_agent("mineburp-packet-table")
        .build()
        .map_err(|error| Failure(error.to_string()))?;
    eprintln!("resolving {version} in the version manifest");
    let manifest: serde_json::Value = client
        .get(MANIFEST_URL)
        .send()
        .and_then(reqwest::blocking::Response::json)
        .map_err(|error| Failure(format!("version manifest: {error}")))?;
    let entry = manifest
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Failure("the version manifest has no versions".into()))?
        .iter()
        .find(|entry| entry.get("id").and_then(serde_json::Value::as_str) == Some(version))
        .ok_or_else(|| {
            Failure(format!(
                "Mojang does not publish a release called `{version}`"
            ))
        })?;
    let details: serde_json::Value = client
        .get(
            entry
                .get("url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Failure("the manifest entry has no url".into()))?,
        )
        .send()
        .and_then(reqwest::blocking::Response::json)
        .map_err(|error| Failure(format!("version details: {error}")))?;
    let url = details
        .pointer("/downloads/server/url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Failure(format!("{version} publishes no server jar")))?;

    eprintln!("downloading {url}");
    let bytes = client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::bytes)
        .map_err(|error| Failure(format!("server jar: {error}")))?;
    let mut file =
        fs::File::create(&jar).map_err(|error| Failure(format!("{}: {error}", jar.display())))?;
    file.write_all(&bytes)
        .map_err(|error| Failure(format!("{}: {error}", jar.display())))?;
    Ok(jar)
}

/// Runs the data generator inside a server jar and reads the packet report.
///
/// Both entry points are tried because the bundled launcher only exists from
/// 1.18 onwards, and the older jars run the generator directly.
fn generate_report(options: &Options, jar: &Path, version: &str) -> Result<String, Failure> {
    let java = options.java.clone().unwrap_or_else(|| "java".into());
    let output = options
        .cache
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/minecraft"))
        .join(format!("generated-{version}"));
    let report = output.join("reports").join("packets.json");
    if report.exists() {
        eprintln!("using cached {}", report.display());
        return read(&report);
    }

    let jar = jar
        .canonicalize()
        .map_err(|error| Failure(format!("{}: {error}", jar.display())))?;
    let attempts: [Vec<String>; 2] = [
        vec![
            "-DbundlerMainClass=net.minecraft.data.Main".into(),
            "-jar".into(),
            jar.display().to_string(),
        ],
        vec![
            "-cp".into(),
            jar.display().to_string(),
            "net.minecraft.data.Main".into(),
        ],
    ];
    let mut failures = Vec::new();
    for arguments in attempts {
        eprintln!("running the data generator ({java})");
        let result = Command::new(&java)
            .args(&arguments)
            .arg("--reports")
            .arg("--output")
            .arg(&output)
            .output()
            .map_err(|error| Failure(format!("could not run `{java}`: {error}")))?;
        if report.exists() {
            return read(&report);
        }
        failures.push(String::from_utf8_lossy(&result.stderr).trim().to_owned());
    }
    Err(Failure(format!(
        "the data generator produced no packet report for {version}. It only exists from 1.20.5 \
         onwards — use --prismarine for older versions. Java said:\n{}",
        failures.join("\n---\n")
    )))
}

fn read(path: &Path) -> Result<String, Failure> {
    fs::read_to_string(path).map_err(|error| Failure(format!("{}: {error}", path.display())))
}

#[derive(Debug)]
struct Failure(String);

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<TableError> for Failure {
    fn from(error: TableError) -> Self {
        Self(error.to_string())
    }
}
