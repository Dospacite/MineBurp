//! Regenerates the bundled packet tables, field definitions, and registry names.
//!
//! Every run rebuilds the whole set, because naming is learned across releases:
//! the `minecraft-data` → vanilla alignment that names an old release's packets
//! comes from the newer releases that have both descriptions. Sources are kept
//! in a cache directory, so a run is cheap once the cache is warm:
//!
//! * `<cache>/minecraft-data/<protocol>.json` — `minecraft-data` protocol
//!   descriptions, downloaded automatically;
//! * `<cache>/reports/<protocol>/packets.json` — vanilla data generator
//!   reports, produced by running a release's own server jar;
//! * `<cache>/registries/<protocol>/vanilla/{registries,blocks,items}.json` —
//!   the same generator's registry reports, cached whenever it runs;
//! * `<cache>/registries/<protocol>/minecraft-data/<file>.json` —
//!   `minecraft-data` registry lists for releases without vanilla reports,
//!   downloaded automatically.
//!
//! Naming one protocol (`--protocol 769`) adds its vanilla report to the cache
//! first — downloading the server jar and running the data generator unless a
//! `--jar` or `--report` is supplied — and then regenerates everything.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use mineburp_packet_table::{
    PacketTable, RawTable, TableError, build_tables, duplicate_names, minify_definition,
    names::{
        MINECRAFT_DATA_FILES, RegistrySources, build_registries, duplicate_registry_names,
        pack_registries, unpack_registries,
    },
    pack_definitions, parse_existing, raw_from_prismarine, raw_from_vanilla_report, render,
};
use mineburp_protocol::PacketRegistry;

const MANIFEST_URL: &str = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";
const MINECRAFT_DATA: &str =
    "https://raw.githubusercontent.com/PrismarineJS/minecraft-data/master/data";
const DEFAULT_TABLES: &str = "crates/mineburp-protocol/data/packet-tables.json";
const DEFAULT_DEFINITIONS: &str = "crates/mineburp-protocol/data/protocol-definitions.zst";
const DEFAULT_NAMES: &str = "crates/mineburp-protocol/data/registry-names.zst";
/// The first release with a vanilla registry report for blocks and items.
const FIRST_REGISTRY_REPORT: i32 = 393;
const USAGE: &str = "\
mineburp-packet-table — regenerate packet-id tables, field definitions and registry names

USAGE:
    mineburp-packet-table [--protocol <number> | --version <release>] [source] [options]

With no protocol, every release in the bundled registry is regenerated from the
cache, downloading minecraft-data descriptions that are missing. With one, that
release's vanilla report is added to the cache first, along with the registry
reports the same generator run writes.

SOURCES for the named protocol (default: download its server jar and run it):
    --report <file>       a vanilla data generator reports/packets.json
    --jar <file>          a server jar to run the data generator in
    --prismarine <file>   a minecraft-data protocol.json

OPTIONS:
    --cache <dir>         source cache (default: target/minecraft)
    --tables <file>       table file to write (default: {DEFAULT_TABLES})
    --definitions <file>  definition bundle to write (default: {DEFAULT_DEFINITIONS})
    --names <file>        registry-name bundle to write (default: {DEFAULT_NAMES})
    --vanilla-registries  run the data generator for every 1.13+ release whose
                          registry reports are not cached yet (downloads jars)
    --java <path>         java to run the data generator with (default: java)
    --offline             use only what is already in the cache
    --stdout              print the tables instead of writing any file
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
    tables: Option<PathBuf>,
    definitions: Option<PathBuf>,
    names: Option<PathBuf>,
    vanilla_registries: bool,
    java: Option<String>,
    cache: Option<PathBuf>,
    offline: bool,
    stdout: bool,
}

impl Options {
    fn cache(&self) -> PathBuf {
        self.cache
            .clone()
            .unwrap_or_else(|| PathBuf::from("target/minecraft"))
    }
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
            "--tables" | "--output" => options.tables = Some(value()?.into()),
            "--definitions" => options.definitions = Some(value()?.into()),
            "--names" => options.names = Some(value()?.into()),
            "--vanilla-registries" => options.vanilla_registries = true,
            "--java" => options.java = Some(value()?),
            "--cache" => options.cache = Some(value()?.into()),
            "--offline" => options.offline = true,
            "--stdout" => options.stdout = true,
            "--help" | "-h" => {
                println!(
                    "{}",
                    USAGE
                        .replace("{DEFAULT_TABLES}", DEFAULT_TABLES)
                        .replace("{DEFAULT_DEFINITIONS}", DEFAULT_DEFINITIONS)
                        .replace("{DEFAULT_NAMES}", DEFAULT_NAMES)
                );
                return Ok(());
            }
            other => return Err(Failure(format!("unknown argument `{other}`"))),
        }
    }

    let registry = PacketRegistry::bundled();
    if options.protocol.is_some() || options.version.is_some() {
        let (protocol, version) = resolve_version(&registry, &options)?;
        add_named_source(&options, protocol, &version)?;
    }
    if !options.offline {
        if options.vanilla_registries {
            fetch_vanilla_registries(&options, &registry);
        }
        fetch_minecraft_data(&options, &registry)?;
        fetch_minecraft_data_registries(&options, &registry)?;
    }
    regenerate(&options, &registry)?;
    regenerate_names(&options, &registry)
}

/// Resolves the protocol number and release name from whichever one was given.
fn resolve_version(registry: &PacketRegistry, options: &Options) -> Result<(i32, String), Failure> {
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

fn report_path(cache: &Path, protocol: i32) -> PathBuf {
    cache
        .join("reports")
        .join(protocol.to_string())
        .join("packets.json")
}

fn minecraft_data_path(cache: &Path, protocol: i32) -> PathBuf {
    cache
        .join("minecraft-data")
        .join(format!("{protocol}.json"))
}

/// Puts the named protocol's source into the cache.
fn add_named_source(options: &Options, protocol: i32, version: &str) -> Result<(), Failure> {
    let cache = options.cache();
    if let Some(path) = &options.prismarine {
        let json = read(path)?;
        raw_from_prismarine(&json, protocol, version)?;
        return write_file(&minecraft_data_path(&cache, protocol), json.as_bytes());
    }
    let report = if let Some(path) = &options.report {
        read(path)?
    } else {
        let jar = match &options.jar {
            Some(path) => path.clone(),
            None => download_server(options, version)?,
        };
        let reports = run_data_generator(options, &jar, version)?;
        let registries = cache_registry_reports(&cache, protocol, &reports)?;
        let packets = reports.join("packets.json");
        if !packets.exists() {
            // The packet report only exists from 1.20.5 onwards; the registry
            // reports an older generator wrote are still worth keeping.
            if registries {
                eprintln!(
                    "{version} has no packet report (minecraft-data describes its packets); \
                     cached its registry reports"
                );
                return Ok(());
            }
            return Err(Failure(format!(
                "the data generator wrote no packet report for {version}"
            )));
        }
        read(&packets)?
    };
    raw_from_vanilla_report(&report, protocol, version)?;
    write_file(&report_path(&cache, protocol), report.as_bytes())
}

fn http() -> Result<reqwest::blocking::Client, Failure> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_mins(5))
        .user_agent("mineburp-packet-table")
        .build()
        .map_err(|error| Failure(error.to_string()))
}

fn get_json(client: &reqwest::blocking::Client, url: &str) -> Result<serde_json::Value, Failure> {
    client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::json)
        .map_err(|error| Failure(format!("{url}: {error}")))
}

/// Downloads the `minecraft-data` description of every registry protocol that
/// `minecraft-data` describes and the cache does not yet hold.
///
/// The match is by protocol number, never by nearest release: a description of
/// a neighbouring version is a different protocol.
fn fetch_minecraft_data(options: &Options, registry: &PacketRegistry) -> Result<(), Failure> {
    let cache = options.cache();
    let missing: Vec<i32> = registry
        .supported_protocols()
        .into_iter()
        .map(|entry| entry.protocol)
        .filter(|protocol| !minecraft_data_path(&cache, *protocol).exists())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let client = http()?;
    let paths = get_json(&client, &format!("{MINECRAFT_DATA}/dataPaths.json"))?;
    let versions = get_json(
        &client,
        &format!("{MINECRAFT_DATA}/pc/common/protocolVersions.json"),
    )?;
    let pc = paths
        .get("pc")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Failure("dataPaths.json has no pc section".into()))?;
    for protocol in missing {
        let mut names = versions
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.get("version").and_then(serde_json::Value::as_i64)
                    == Some(i64::from(protocol))
                    && entry
                        .get("usesNetty")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true)
            })
            .filter_map(|entry| {
                entry
                    .get("minecraftVersion")
                    .and_then(serde_json::Value::as_str)
            });
        let Some(path) = names
            .find_map(|name| pc.get(name)?.get("protocol")?.as_str())
            .map(str::to_owned)
        else {
            eprintln!("protocol {protocol}: minecraft-data has no description");
            continue;
        };
        let url = format!("{MINECRAFT_DATA}/{path}/protocol.json");
        eprintln!("protocol {protocol}: downloading {url}");
        let text = client
            .get(&url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::text)
            .map_err(|error| Failure(format!("{url}: {error}")))?;
        write_file(&minecraft_data_path(&cache, protocol), text.as_bytes())?;
    }
    Ok(())
}

fn regenerate(options: &Options, registry: &PacketRegistry) -> Result<(), Failure> {
    let cache = options.cache();
    let mut raws: Vec<RawTable> = Vec::new();
    let mut definitions = BTreeMap::new();
    for entry in registry.supported_protocols() {
        let protocol = entry.protocol;
        let version = &entry.canonical;
        let md = minecraft_data_path(&cache, protocol);
        if md.exists() {
            let json = read(&md)?;
            raws.push(raw_from_prismarine(&json, protocol, version)?);
            definitions.insert(protocol, minify_definition(&json)?);
        }
        let report = report_path(&cache, protocol);
        if report.exists() {
            raws.push(raw_from_vanilla_report(&read(&report)?, protocol, version)?);
        }
    }
    let mut tables = build_tables(&raws)?;
    let problems: Vec<String> = tables.iter().flat_map(duplicate_names).collect();
    if !problems.is_empty() {
        return Err(Failure(format!(
            "generated tables are ambiguous:\n{}",
            problems.join("\n")
        )));
    }

    // A protocol with no source in this cache keeps its existing entry rather
    // than silently disappearing from the bundle.
    let tables_path = options
        .tables
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TABLES));
    if tables_path.exists() {
        let existing: Vec<PacketTable> = parse_existing(&read(&tables_path)?)?;
        for table in existing {
            if !tables.iter().any(|entry| entry.protocol == table.protocol) {
                tables.push(table);
            }
        }
    }
    tables.sort_by_key(|table| table.protocol);
    for table in &tables {
        eprintln!(
            "{:>4} {:<8} {:>4} packets  {}",
            table.protocol,
            table.version,
            table.packet_count(),
            table.source
        );
    }
    let rendered = render(&tables)?;
    if options.stdout {
        print!("{rendered}");
        return Ok(());
    }
    write_file(&tables_path, rendered.as_bytes())?;
    eprintln!("wrote {}", tables_path.display());
    if definitions.is_empty() {
        eprintln!("no minecraft-data descriptions in the cache; definitions left untouched");
        return Ok(());
    }
    let packed = pack_definitions(&definitions)?;
    let definitions_path = options
        .definitions
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEFINITIONS));
    write_file(&definitions_path, &packed)?;
    eprintln!(
        "wrote {} ({} protocols, {} bytes)",
        definitions_path.display(),
        definitions.len(),
        packed.len()
    );
    Ok(())
}

/// Downloads the release's server jar, straight from the manifest Mojang serves.
fn download_server(options: &Options, version: &str) -> Result<PathBuf, Failure> {
    let cache = options.cache().join("jars");
    fs::create_dir_all(&cache).map_err(|error| Failure(format!("{}: {error}", cache.display())))?;
    let jar = cache.join(format!("server-{version}.jar"));
    if jar.exists() {
        eprintln!("using cached {}", jar.display());
        return Ok(jar);
    }
    let client = http()?;
    eprintln!("resolving {version} in the version manifest");
    let manifest = get_json(&client, MANIFEST_URL)?;
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
    let details = get_json(
        &client,
        entry
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Failure("the manifest entry has no url".into()))?,
    )?;
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

/// Runs the data generator inside a server jar and returns its reports
/// directory.
///
/// The generator runs in its own working directory under the cache, because
/// the bundled launcher unpacks `libraries/` and `versions/` into whatever
/// directory it is started from. A directory that already holds a registry or
/// packet report is reused rather than generated again.
fn run_data_generator(options: &Options, jar: &Path, version: &str) -> Result<PathBuf, Failure> {
    let java = options.java.clone().unwrap_or_else(|| "java".into());
    let workspace = options.cache().join("generator").join(version);
    fs::create_dir_all(&workspace)
        .map_err(|error| Failure(format!("{}: {error}", workspace.display())))?;
    let reports = workspace.join("generated").join("reports");
    let generated = |reports: &Path| {
        ["packets.json", "registries.json", "blocks.json"]
            .iter()
            .any(|file| reports.join(file).exists())
    };
    if generated(&reports) {
        eprintln!("using cached {}", reports.display());
        return Ok(reports);
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
            .current_dir(&workspace)
            .args(&arguments)
            .arg("--reports")
            .arg("--output")
            .arg("generated")
            .output()
            .map_err(|error| Failure(format!("could not run `{java}`: {error}")))?;
        if generated(&reports) {
            return Ok(reports);
        }
        failures.push(String::from_utf8_lossy(&result.stderr).trim().to_owned());
    }
    Err(Failure(format!(
        "the data generator produced no reports for {version}. Releases before 1.13 have no \
         data generator — minecraft-data describes them instead. Newer releases may need a \
         newer java (--java). Java said:\n{}",
        failures.join("\n---\n")
    )))
}

/// Copies whichever registry reports a generator run wrote into the cache.
/// Returns true when at least one was found.
fn cache_registry_reports(cache: &Path, protocol: i32, reports: &Path) -> Result<bool, Failure> {
    let mut found = false;
    for file in ["registries.json", "blocks.json", "items.json"] {
        let source = reports.join(file);
        if source.exists() {
            let bytes = fs::read(&source)
                .map_err(|error| Failure(format!("{}: {error}", source.display())))?;
            write_file(&vanilla_registry_path(cache, protocol, file), &bytes)?;
            found = true;
        }
    }
    Ok(found)
}

fn vanilla_registry_path(cache: &Path, protocol: i32, file: &str) -> PathBuf {
    cache
        .join("registries")
        .join(protocol.to_string())
        .join("vanilla")
        .join(file)
}

fn minecraft_data_registry_path(cache: &Path, protocol: i32, file: &str) -> PathBuf {
    cache
        .join("registries")
        .join(protocol.to_string())
        .join("minecraft-data")
        .join(format!("{file}.json"))
}

/// Runs the data generator for every 1.13+ release whose registry reports are
/// not cached yet. Each run downloads that release's server jar.
fn fetch_vanilla_registries(options: &Options, registry: &PacketRegistry) {
    let cache = options.cache();
    for entry in registry.supported_protocols() {
        if entry.protocol < FIRST_REGISTRY_REPORT
            || vanilla_registry_path(&cache, entry.protocol, "blocks.json").exists()
        {
            continue;
        }
        let outcome = download_server(options, &entry.canonical)
            .and_then(|jar| run_data_generator(options, &jar, &entry.canonical))
            .and_then(|reports| cache_registry_reports(&cache, entry.protocol, &reports));
        match outcome {
            Ok(true) => eprintln!("protocol {}: cached registry reports", entry.protocol),
            Ok(false) => eprintln!(
                "protocol {}: the generator wrote no registry reports",
                entry.protocol
            ),
            // One release failing (an old jar on a new java, say) should not
            // cost every other release its reports.
            Err(error) => eprintln!("protocol {}: {error}", entry.protocol),
        }
    }
}

/// Downloads `minecraft-data` registry lists for every release the vanilla
/// registry report does not cover. Like the protocol descriptions, the match is
/// by protocol number through `minecraft-data`'s own version list.
fn fetch_minecraft_data_registries(
    options: &Options,
    registry: &PacketRegistry,
) -> Result<(), Failure> {
    let cache = options.cache();
    let needed: Vec<i32> = registry
        .supported_protocols()
        .into_iter()
        .map(|entry| entry.protocol)
        .filter(|protocol| {
            !vanilla_registry_path(&cache, *protocol, "registries.json").exists()
                && MINECRAFT_DATA_FILES
                    .iter()
                    .any(|file| !minecraft_data_registry_path(&cache, *protocol, file).exists())
        })
        .collect();
    if needed.is_empty() {
        return Ok(());
    }
    let client = http()?;
    let paths = get_json(&client, &format!("{MINECRAFT_DATA}/dataPaths.json"))?;
    let versions = get_json(
        &client,
        &format!("{MINECRAFT_DATA}/pc/common/protocolVersions.json"),
    )?;
    let pc = paths
        .get("pc")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Failure("dataPaths.json has no pc section".into()))?;
    for protocol in needed {
        let Some(entry) = versions
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.get("version").and_then(serde_json::Value::as_i64)
                    == Some(i64::from(protocol))
                    && entry
                        .get("usesNetty")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true)
            })
            .filter_map(|entry| entry.get("minecraftVersion")?.as_str())
            .collect::<Vec<_>>()
            .into_iter()
            // `minecraft-data` files 1.7.x under plain "1.7". Unlike packet
            // ids, pre-flattening item and block ids were fixed numbers that
            // did not move within a minor release, so for registries — and
            // only for registries — the minor release is a safe stand-in.
            .find_map(|name| pc.get(name).or_else(|| pc.get(minor_release(name)?)))
        else {
            eprintln!("protocol {protocol}: minecraft-data has no registries");
            continue;
        };
        for file in MINECRAFT_DATA_FILES {
            let target = minecraft_data_registry_path(&cache, protocol, file);
            if target.exists() {
                continue;
            }
            let Some(path) = entry.get(*file).and_then(serde_json::Value::as_str) else {
                continue;
            };
            let url = format!("{MINECRAFT_DATA}/{path}/{file}.json");
            eprintln!("protocol {protocol}: downloading {url}");
            let text = client
                .get(&url)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .and_then(reqwest::blocking::Response::text)
                .map_err(|error| Failure(format!("{url}: {error}")))?;
            write_file(&target, text.as_bytes())?;
        }
    }
    Ok(())
}

/// `1.7.10` → `1.7`; `None` for names without a patch component.
fn minor_release(name: &str) -> Option<&str> {
    let (minor, patch) = name.rsplit_once('.')?;
    (minor.contains('.') && patch.chars().all(|c| c.is_ascii_digit())).then_some(minor)
}

/// Reads one protocol's cached registry sources.
fn registry_sources(cache: &Path, protocol: i32) -> Result<RegistrySources, Failure> {
    let optional = |path: PathBuf| -> Result<Option<String>, Failure> {
        if path.exists() {
            read(&path).map(Some)
        } else {
            Ok(None)
        }
    };
    let mut sources = RegistrySources {
        vanilla_registries: optional(vanilla_registry_path(cache, protocol, "registries.json"))?,
        vanilla_blocks: optional(vanilla_registry_path(cache, protocol, "blocks.json"))?,
        vanilla_items: optional(vanilla_registry_path(cache, protocol, "items.json"))?,
        ..RegistrySources::default()
    };
    for file in MINECRAFT_DATA_FILES {
        if let Some(text) = optional(minecraft_data_registry_path(cache, protocol, file))? {
            sources.minecraft_data.insert((*file).to_owned(), text);
        }
    }
    Ok(sources)
}

fn regenerate_names(options: &Options, registry: &PacketRegistry) -> Result<(), Failure> {
    if options.stdout {
        return Ok(());
    }
    let cache = options.cache();
    let names_path = options
        .names
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_NAMES));
    let mut protocols = BTreeMap::new();
    for entry in registry.supported_protocols() {
        let sources = registry_sources(&cache, entry.protocol)?;
        if sources.is_empty() {
            continue;
        }
        let built = build_registries(entry.protocol, &sources)?;
        if !built.is_empty() {
            protocols.insert(entry.protocol, built);
        }
    }
    if protocols.is_empty() {
        eprintln!("no registry sources in the cache; registry names left untouched");
        return Ok(());
    }
    // A protocol with no source in this cache keeps its bundled registries.
    if names_path.exists() {
        let bytes = fs::read(&names_path)
            .map_err(|error| Failure(format!("{}: {error}", names_path.display())))?;
        for (protocol, registries) in unpack_registries(&bytes)? {
            protocols.entry(protocol).or_insert(registries);
        }
    }
    let problems: Vec<String> = protocols
        .iter()
        .flat_map(|(protocol, registries)| duplicate_registry_names(*protocol, registries))
        .collect();
    if !problems.is_empty() {
        return Err(Failure(format!(
            "generated registries are ambiguous:\n{}",
            problems.join("\n")
        )));
    }
    for (protocol, registries) in &protocols {
        eprintln!("{protocol:>4} {} registries", registries.len());
    }
    let packed = pack_registries(&protocols)?;
    write_file(&names_path, &packed)?;
    eprintln!(
        "wrote {} ({} protocols, {} bytes)",
        names_path.display(),
        protocols.len(),
        packed.len()
    );
    Ok(())
}

fn read(path: &Path) -> Result<String, Failure> {
    fs::read_to_string(path).map_err(|error| Failure(format!("{}: {error}", path.display())))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| Failure(format!("{}: {error}", parent.display())))?;
    }
    fs::write(path, bytes).map_err(|error| Failure(format!("{}: {error}", path.display())))
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
