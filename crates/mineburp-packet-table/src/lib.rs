//! Builds packet-id tables and field definitions from each version's own data.
//!
//! Ids are renumbered nearly every release, which is why a table is only ever
//! used for the exact protocol it was generated from. A table lifts the floor
//! shape identification cannot get past — a one-byte body holding `0` or `1` is
//! an arm swing, a client command, and a movement-input bitmask at once — but
//! only if the table is *derived*, never typed out. Everything here reads a
//! machine-generated description of one version:
//!
//! * the vanilla data generator's `reports/packets.json`, which is the game
//!   telling you its own ids, and
//! * `minecraft-data`'s `protocol.json`, which reaches back to versions that
//!   predate the report and also describes every packet's fields.
//!
//! The two sources name packets differently, and neither keeps its names
//! stable across releases. Rather than hand-maintain a dictionary between them,
//! [`build_tables`] *learns* one: wherever a protocol has both sources, the
//! same id in the same state and direction is the same packet, so each
//! `minecraft-data` name is aligned with the vanilla name it sits beside. A
//! vanilla name that changes while the `minecraft-data` name stays put is a
//! rename, and the newest spelling wins everywhere. Only then are names mapped
//! onto the inspector's vocabulary by [`canonical_name`], so one packet is one
//! row whichever tier — or whichever release — named it.

pub mod names;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write as _,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TableError {
    #[error("{0} is not valid JSON: {1}")]
    Json(&'static str, serde_json::Error),
    #[error("{0}")]
    Shape(String),
    #[error("no packets were found for the play state")]
    Empty,
    #[error("could not compress the definition bundle: {0}")]
    Compress(std::io::Error),
}

/// The states whose ids are tabulated. Handshake and status ids have never
/// moved, so the inspector names those without a table.
pub const STATES: [&str; 3] = ["login", "configuration", "play"];

/// Where a table's ids came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// The vanilla data generator's own report: authoritative.
    Vanilla,
    /// `minecraft-data`'s protocol description.
    MinecraftData,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Self::Vanilla => "vanilla data generator report",
            Self::MinecraftData => "minecraft-data",
        }
    }
}

/// One state's ids before they are named, keyed by id, as the source spelled them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RawState {
    pub serverbound: BTreeMap<i32, String>,
    pub clientbound: BTreeMap<i32, String>,
}

impl RawState {
    fn side(&self, serverbound: bool) -> &BTreeMap<i32, String> {
        if serverbound {
            &self.serverbound
        } else {
            &self.clientbound
        }
    }
}

/// Everything one source says about one protocol version.
#[derive(Debug, Clone)]
pub struct RawTable {
    pub protocol: i32,
    pub version: String,
    pub source: Source,
    /// Keyed by state name (`login`, `configuration`, `play`).
    pub states: BTreeMap<String, RawState>,
    /// `minecraft-data` only: each packet's field definition, minified, keyed
    /// by state, direction (`true` for serverbound), and packet name. Two
    /// releases giving one definition two names is how a rename is recognised.
    pub definitions: BTreeMap<(String, bool, String), String>,
}

/// One state's ids, indexed by packet id. A hole stays `null` rather than
/// shifting everything after it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTable {
    pub serverbound: Vec<Option<String>>,
    pub clientbound: Vec<Option<String>>,
}

impl StateTable {
    #[must_use]
    pub fn packet_count(&self) -> usize {
        self.serverbound.iter().flatten().count() + self.clientbound.iter().flatten().count()
    }

    #[must_use]
    pub fn side(&self, serverbound: bool) -> &[Option<String>] {
        if serverbound {
            &self.serverbound
        } else {
            &self.clientbound
        }
    }
}

/// One protocol version's ids for every tabulated state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketTable {
    pub protocol: i32,
    pub version: String,
    /// Where the ids came from, so a stale or hand-edited entry is obvious.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<StateTable>,
    /// Absent before 1.20.2, which is when the configuration state appeared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<StateTable>,
    pub play: StateTable,
}

impl PacketTable {
    #[must_use]
    pub fn state(&self, state: &str) -> Option<&StateTable> {
        match state {
            "login" => self.login.as_ref(),
            "configuration" => self.configuration.as_ref(),
            "play" => Some(&self.play),
            _ => None,
        }
    }

    #[must_use]
    pub fn packet_count(&self) -> usize {
        STATES
            .iter()
            .filter_map(|state| self.state(state))
            .map(StateTable::packet_count)
            .sum()
    }
}

// --- reading the two sources ---

/// Reads the vanilla data generator's `reports/packets.json`.
///
/// The report is a map of state to direction to packet, each carrying its own
/// `protocol_id`, which is exactly the mapping the running game uses.
pub fn raw_from_vanilla_report(
    json: &str,
    protocol: i32,
    version: &str,
) -> Result<RawTable, TableError> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|error| TableError::Json("the packet report", error))?;
    let mut states = BTreeMap::new();
    for state in STATES {
        let Some(entries) = root.get(state) else {
            continue;
        };
        let mut raw = RawState::default();
        for (key, serverbound) in [("serverbound", true), ("clientbound", false)] {
            let Some(packets) = entries.get(key).and_then(serde_json::Value::as_object) else {
                continue;
            };
            let target = if serverbound {
                &mut raw.serverbound
            } else {
                &mut raw.clientbound
            };
            for (name, value) in packets {
                let id = value
                    .get("protocol_id")
                    .unwrap_or(value)
                    .as_i64()
                    .ok_or_else(|| TableError::Shape(format!("`{name}` has no protocol id")))?;
                let id = i32::try_from(id)
                    .map_err(|_| TableError::Shape(format!("`{name}` has an absurd id {id}")))?;
                target.insert(id, clean_name(strip_namespace(name)));
            }
        }
        states.insert(state.to_owned(), raw);
    }
    if states
        .get("play")
        .is_none_or(|play| play.serverbound.is_empty() && play.clientbound.is_empty())
    {
        return Err(TableError::Empty);
    }
    Ok(RawTable {
        protocol,
        version: version.to_owned(),
        source: Source::Vanilla,
        states,
        definitions: BTreeMap::new(),
    })
}

/// Reads a `minecraft-data` `protocol.json`.
///
/// Each state and direction has a `packet` type: a container whose first field
/// maps ids to names, and whose second switches from those names to the type
/// that describes the packet's fields. Both halves are read, so the field
/// definition travels with its name.
pub fn raw_from_prismarine(
    json: &str,
    protocol: i32,
    version: &str,
) -> Result<RawTable, TableError> {
    let root: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| TableError::Json("the minecraft-data protocol", error))?;
    let mut states = BTreeMap::new();
    let mut definitions = BTreeMap::new();
    for state in STATES {
        let Some(entries) = root.get(state) else {
            continue;
        };
        let mut raw = RawState::default();
        for (key, serverbound) in [("toServer", true), ("toClient", false)] {
            let Some(side) = entries.get(key) else {
                continue;
            };
            let Some(mappings) = find_packet_mappings(side) else {
                continue;
            };
            let types = side.get("types");
            let switch = types
                .and_then(|types| types.get("packet"))
                .and_then(find_packet_switch);
            let target = if serverbound {
                &mut raw.serverbound
            } else {
                &mut raw.clientbound
            };
            for (id, name) in mappings {
                let Some(name) = name.as_str() else { continue };
                let id = parse_id(&id)
                    .ok_or_else(|| TableError::Shape(format!("`{id}` is not a packet id")))?;
                let cleaned = clean_name(strip_prismarine(name));
                let type_name = switch
                    .as_ref()
                    .and_then(|fields| fields.get(name))
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(|| format!("packet_{name}"), str::to_owned);
                if let Some(definition) = types.and_then(|types| types.get(&type_name)) {
                    definitions.insert(
                        (state.to_owned(), serverbound, cleaned.clone()),
                        definition.to_string(),
                    );
                }
                target.insert(id, cleaned);
            }
        }
        if !(raw.serverbound.is_empty() && raw.clientbound.is_empty()) {
            states.insert(state.to_owned(), raw);
        }
    }
    if states
        .get("play")
        .is_none_or(|play| play.serverbound.is_empty() && play.clientbound.is_empty())
    {
        return Err(TableError::Empty);
    }
    Ok(RawTable {
        protocol,
        version: version.to_owned(),
        source: Source::MinecraftData,
        states,
        definitions,
    })
}

/// Finds the packet-name `mappings` object under a subtree.
///
/// Walking rather than indexing a fixed path: the container layout around the
/// mapper has moved between `minecraft-data` releases, the mapper itself has
/// not. The subtree can hold several mapper nodes — the state selector is one
/// too — so every id-keyed candidate is collected and the largest one wins.
fn find_packet_mappings(
    value: &serde_json::Value,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    fn walk(
        value: &serde_json::Value,
        best: &mut Option<serde_json::Map<String, serde_json::Value>>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Object(mappings)) = map.get("mappings")
                    && !mappings.is_empty()
                    && mappings.keys().all(|key| parse_id(key).is_some())
                    && mappings.values().all(serde_json::Value::is_string)
                    && best
                        .as_ref()
                        .is_none_or(|current| mappings.len() > current.len())
                {
                    *best = Some(mappings.clone());
                }
                for child in map.values() {
                    walk(child, best);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, best);
                }
            }
            _ => {}
        }
    }

    let mut best = None;
    walk(value.get("types").unwrap_or(value), &mut best);
    best
}

/// Finds the name-to-type switch in a `packet` container.
fn find_packet_switch(
    value: &serde_json::Value,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Array(items) => {
            if items.first().and_then(serde_json::Value::as_str) == Some("switch")
                && let Some(fields) = items
                    .get(1)
                    .and_then(|options| options.get("fields"))
                    .and_then(serde_json::Value::as_object)
            {
                return Some(fields.clone());
            }
            items.iter().find_map(find_packet_switch)
        }
        serde_json::Value::Object(map) => map.values().find_map(find_packet_switch),
        _ => None,
    }
}

fn parse_id(raw: &str) -> Option<i32> {
    let trimmed = raw.trim();
    trimmed.strip_prefix("0x").map_or_else(
        || trimmed.parse().ok(),
        |hex| i32::from_str_radix(hex, 16).ok(),
    )
}

fn strip_namespace(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, rest)| rest)
}

/// `minecraft-data` prefixes some names with the direction they travel.
fn strip_prismarine(name: &str) -> &str {
    name.strip_prefix("packet_").unwrap_or(name)
}

/// Vanilla's debug packets are namespaced paths (`debug/block_value`); a slash
/// is awkward in a filter expression, so it becomes an underscore.
fn clean_name(name: &str) -> String {
    name.replace(['/', '.', '-'], "_")
}

// --- naming ---

/// Maps a vanilla packet name onto the name the inspector reports.
///
/// Without this a table would name a packet `move_player_pos` while the shape
/// decoder for the same bytes calls it `set_player_position`, and the history
/// would show one packet under two names depending on which tier identified it.
/// Names are state- and direction-aware because vanilla reuses them: `hello` is
/// the login start going up and the encryption request coming down.
#[must_use]
pub fn canonical_name(state: &str, serverbound: bool, name: &str) -> String {
    let mapped = match (state, serverbound, name) {
        // Login: the inspector's names predate the vanilla report.
        ("login", true, "hello") => "login_start",
        ("login", false, "hello") => "encryption_request",
        ("login", true, "key") => "encryption_response",
        ("login", false, "game_profile" | "login_finished") => "login_success",
        ("login", false, "login_compression") => "set_compression",
        ("login", false, "custom_query") => "login_plugin_request",
        ("login", true, "custom_query_answer") => "login_plugin_response",
        // Configuration.
        ("configuration", _, "custom_payload") => "plugin_message",
        ("configuration", true, "finish_configuration") => "finish_configuration_ack",
        ("configuration" | "play", true, "resource_pack") => "resource_pack_response",
        ("configuration", true, "select_known_packs") => "known_packs",
        // `resource_pack_send` is minecraft-data's name from before 1.20.3
        // split the pack packet in two.
        ("configuration" | "play", false, "resource_pack_push" | "resource_pack_send") => {
            "add_resource_pack"
        }
        ("configuration" | "play", false, "resource_pack_pop") => "remove_resource_pack",
        // Serverbound play.
        ("play", true, "move_player_pos") => "set_player_position",
        ("play", true, "move_player_pos_rot") => "set_player_position_and_rotation",
        ("play", true, "move_player_rot") => "set_player_rotation",
        ("play", true, "move_player_status_only") => "set_player_on_ground",
        ("play", true, "chat") => "chat_message",
        ("play", true, "set_carried_item") => "set_held_item",
        ("play", true, "container_click") => "click_container",
        // Clientbound play.
        ("play", false, "set_time") => "update_time",
        ("play", false, "player_position") => "synchronize_player_position",
        ("play", false, "boss_event") => "boss_bar",
        ("play", false, "sound") => "sound_effect",
        ("play", false, "update_mob_effect") => "entity_effect",
        ("play", false, "remove_mob_effect") => "remove_entity_effect",
        ("play", false, "set_objective") => "scoreboard_objective",
        ("play", false, "set_score") => "update_score",
        ("play", false, "player_combat_kill") => "combat_death",
        // `minecraft-data` names from releases older than any vanilla report.
        // Only spellings with a single meaning in every release belong here:
        // the generator rejects a table that names two ids alike, which is how
        // a guess such as `named_sound_effect` → `sound_effect` (the two
        // coexisted until 1.19.3) is caught.
        ("play", true, "update_sign") => "sign_update",
        other => other.2,
    };
    mapped.to_owned()
}

/// What the alignment learned: for each state, direction, and `minecraft-data`
/// name, the vanilla name it corresponds to.
#[derive(Debug, Default)]
struct Vocabulary {
    aliases: HashMap<(String, bool, String), String>,
    /// Vanilla renames, oldest spelling to newest.
    renames: HashMap<(String, bool, String), String>,
}

impl Vocabulary {
    fn learn(raws: &[RawTable]) -> Self {
        let mut vocabulary = Self::default();
        let vanilla: HashMap<i32, &RawTable> = raws
            .iter()
            .filter(|raw| raw.source == Source::Vanilla)
            .map(|raw| (raw.protocol, raw))
            .collect();
        // md name -> vanilla name -> protocols it was seen beside.
        let mut seen: HashMap<(String, bool, String), BTreeMap<String, BTreeSet<i32>>> =
            HashMap::new();
        for md in raws
            .iter()
            .filter(|raw| raw.source == Source::MinecraftData)
        {
            let Some(report) = vanilla.get(&md.protocol) else {
                continue;
            };
            for (state, entries) in &md.states {
                let Some(official) = report.states.get(state) else {
                    continue;
                };
                for serverbound in [true, false] {
                    let official = official.side(serverbound);
                    for (id, md_name) in entries.side(serverbound) {
                        if let Some(name) = official.get(id) {
                            seen.entry((state.clone(), serverbound, md_name.clone()))
                                .or_default()
                                .entry(name.clone())
                                .or_default()
                                .insert(md.protocol);
                        }
                    }
                }
            }
        }

        let coexist = |state: &str, serverbound: bool, a: &str, b: &str| {
            vanilla.values().any(|raw| {
                raw.states.get(state).is_some_and(|entries| {
                    let names = entries.side(serverbound);
                    names.values().any(|name| name == a) && names.values().any(|name| name == b)
                })
            })
        };

        for (key, targets) in &seen {
            // The alias is the majority reading; a single release where the
            // description is wrong is outvoted by the releases where it is right.
            let best = targets
                .iter()
                .max_by_key(|(_, protocols)| (protocols.len(), protocols.last().copied()))
                .map(|(name, _)| name.clone());
            if let Some(best) = best {
                vocabulary.aliases.insert(key.clone(), best);
            }
            // A vanilla name that strictly precedes another beside one stable
            // minecraft-data name, and never appears in the same release as it,
            // is the same packet renamed.
            let mut ordered: Vec<(&String, &BTreeSet<i32>)> = targets.iter().collect();
            ordered.sort_by_key(|(_, protocols)| protocols.first().copied());
            for pair in ordered.windows(2) {
                let ((older, old_protocols), (newer, new_protocols)) = (pair[0], pair[1]);
                if old_protocols.last() < new_protocols.first()
                    && !coexist(&key.0, key.1, older, newer)
                {
                    vocabulary
                        .renames
                        .insert((key.0.clone(), key.1, older.clone()), newer.clone());
                }
            }
        }
        vocabulary
    }

    fn follow_renames(&self, state: &str, serverbound: bool, name: &str) -> String {
        let mut current = name.to_owned();
        for _ in 0..8 {
            match self
                .renames
                .get(&(state.to_owned(), serverbound, current.clone()))
            {
                Some(next) => current.clone_from(next),
                None => break,
            }
        }
        current
    }

    /// Names one packet in the inspector's vocabulary.
    fn name(&self, source: Source, state: &str, serverbound: bool, raw_name: &str) -> String {
        let vanilla = match source {
            Source::Vanilla => raw_name.to_owned(),
            Source::MinecraftData => self
                .aliases
                .get(&(state.to_owned(), serverbound, raw_name.to_owned()))
                .cloned()
                .unwrap_or_else(|| raw_name.to_owned()),
        };
        let vanilla = self.follow_renames(state, serverbound, &vanilla);
        canonical_name(state, serverbound, &vanilla)
    }
}

/// Carries `minecraft-data` renames back through releases that predate any
/// vanilla report: a packet whose definition is byte-for-byte unchanged between
/// two consecutive releases, under a name that disappeared and one that
/// appeared, is one packet renamed.
fn learn_definition_renames(raws: &[RawTable]) -> HashMap<(i32, String, bool, String), String> {
    let mut mds: Vec<&RawTable> = raws
        .iter()
        .filter(|raw| raw.source == Source::MinecraftData)
        .collect();
    mds.sort_by_key(|raw| raw.protocol);
    // (protocol, state, direction, old name) -> name in the next release.
    let mut forward: HashMap<(i32, String, bool, String), String> = HashMap::new();
    for pair in mds.windows(2) {
        let (older, newer) = (pair[0], pair[1]);
        for ((state, serverbound, name), definition) in &older.definitions {
            if newer
                .definitions
                .contains_key(&(state.clone(), *serverbound, name.clone()))
            {
                continue;
            }
            let candidates: Vec<&String> = newer
                .definitions
                .iter()
                .filter(|((new_state, new_side, new_name), new_definition)| {
                    new_state == state
                        && new_side == serverbound
                        && *new_definition == definition
                        && !older.definitions.contains_key(&(
                            state.clone(),
                            *serverbound,
                            new_name.clone(),
                        ))
                })
                .map(|((_, _, new_name), _)| new_name)
                .collect();
            if let [only] = candidates.as_slice() {
                forward.insert(
                    (older.protocol, state.clone(), *serverbound, name.clone()),
                    (*only).clone(),
                );
            }
        }
    }
    // Resolve chains so each old name points at its newest spelling.
    let protocols: Vec<i32> = mds.iter().map(|raw| raw.protocol).collect();
    let mut resolved = HashMap::new();
    for (key, first) in &forward {
        let (protocol, state, serverbound, _) = key;
        let mut name = first.clone();
        let mut index = protocols
            .iter()
            .position(|value| value == protocol)
            .unwrap_or(0)
            + 1;
        while let Some(next_protocol) = protocols.get(index) {
            match forward.get(&(*next_protocol, state.clone(), *serverbound, name.clone())) {
                Some(next) => name.clone_from(next),
                None => break,
            }
            index += 1;
        }
        resolved.insert(key.clone(), name);
    }
    resolved
}

/// Builds one table per protocol from every source given.
///
/// A vanilla report wins over `minecraft-data` for the same protocol; the
/// latter still contributes its field definitions to the bundle.
pub fn build_tables(raws: &[RawTable]) -> Result<Vec<PacketTable>, TableError> {
    let vocabulary = Vocabulary::learn(raws);
    let definition_renames = learn_definition_renames(raws);
    let mut by_protocol: BTreeMap<i32, &RawTable> = BTreeMap::new();
    for raw in raws {
        let keep = by_protocol
            .get(&raw.protocol)
            .is_none_or(|current| raw.source < current.source);
        if keep {
            by_protocol.insert(raw.protocol, raw);
        }
    }
    let mut tables = Vec::new();
    for raw in by_protocol.values() {
        let mut states: BTreeMap<&str, StateTable> = BTreeMap::new();
        for state in STATES {
            let Some(entries) = raw.states.get(state) else {
                continue;
            };
            let mut table = StateTable::default();
            for serverbound in [true, false] {
                let mut named = BTreeMap::new();
                for (id, raw_name) in entries.side(serverbound) {
                    let carried = if raw.source == Source::MinecraftData {
                        definition_renames
                            .get(&(
                                raw.protocol,
                                state.to_owned(),
                                serverbound,
                                raw_name.clone(),
                            ))
                            .cloned()
                            .unwrap_or_else(|| raw_name.clone())
                    } else {
                        raw_name.clone()
                    };
                    named.insert(
                        *id,
                        vocabulary.name(raw.source, state, serverbound, &carried),
                    );
                }
                let slots = lay_out(&named);
                if serverbound {
                    table.serverbound = slots;
                } else {
                    table.clientbound = slots;
                }
            }
            states.insert(state, table);
        }
        let play = states.remove("play").ok_or(TableError::Empty)?;
        tables.push(PacketTable {
            protocol: raw.protocol,
            version: raw.version.clone(),
            source: raw.source.label().to_owned(),
            login: states.remove("login"),
            configuration: states.remove("configuration"),
            play,
        });
    }
    Ok(tables)
}

fn lay_out(entries: &BTreeMap<i32, String>) -> Vec<Option<String>> {
    let highest = entries.keys().copied().max().unwrap_or(-1);
    let mut slots = vec![None; usize::try_from(highest + 1).unwrap_or_default()];
    for (id, name) in entries {
        if let Ok(index) = usize::try_from(*id)
            && let Some(slot) = slots.get_mut(index)
        {
            *slot = Some(name.clone());
        }
    }
    slots
}

/// Problems that make a table untrustworthy: a name used for two ids in one
/// direction means two packets would be indistinguishable in the history.
#[must_use]
pub fn duplicate_names(table: &PacketTable) -> Vec<String> {
    let mut problems = Vec::new();
    for state in STATES {
        let Some(entries) = table.state(state) else {
            continue;
        };
        for serverbound in [true, false] {
            let mut seen = BTreeMap::new();
            for (id, name) in entries.side(serverbound).iter().enumerate() {
                let Some(name) = name else { continue };
                if let Some(first) = seen.insert(name.clone(), id) {
                    problems.push(format!(
                        "{} {state} {}: `{name}` is both {first:#04x} and {id:#04x}",
                        table.version,
                        if serverbound {
                            "serverbound"
                        } else {
                            "clientbound"
                        }
                    ));
                }
            }
        }
    }
    problems
}

pub fn render(tables: &[PacketTable]) -> Result<String, TableError> {
    let mut json = serde_json::to_string_pretty(tables)
        .map_err(|error| TableError::Json("the generated table", error))?;
    json.push('\n');
    Ok(json)
}

pub fn parse_existing(json: &str) -> Result<Vec<PacketTable>, TableError> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json).map_err(|error| TableError::Json("the existing table file", error))
}

// --- field definitions ---

/// Minifies one `minecraft-data` protocol description down to what decoding
/// reads: the shared types and each state's per-direction types.
pub fn minify_definition(json: &str) -> Result<String, TableError> {
    let root: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| TableError::Json("the minecraft-data protocol", error))?;
    let mut kept = serde_json::Map::new();
    for key in [
        "types",
        "handshaking",
        "status",
        "login",
        "configuration",
        "play",
    ] {
        if let Some(value) = root.get(key) {
            kept.insert(key.to_owned(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(kept).to_string())
}

/// Packs minified definitions into the bundle the protocol crate embeds.
///
/// The format is `MBPD1\n`, one line of JSON mapping each protocol to the
/// byte range of its definition, then the definitions back to back — all of it
/// one zstd frame. Identical definitions are stored once, and releases differ
/// so little that the whole history compresses to a few tens of kilobytes. The
/// range index is what lets a reader parse one version without touching the
/// others.
pub fn pack_definitions(definitions: &BTreeMap<i32, String>) -> Result<Vec<u8>, TableError> {
    let mut body = String::new();
    let mut stored: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut index = BTreeMap::new();
    for (protocol, definition) in definitions {
        let range = *stored.entry(definition.as_str()).or_insert_with(|| {
            let start = body.len();
            body.push_str(definition);
            (start, definition.len())
        });
        index.insert(protocol.to_string(), [range.0, range.1]);
    }
    let header = serde_json::json!({ "versions": index }).to_string();
    let mut plain = Vec::with_capacity(body.len() + header.len() + 8);
    plain.extend_from_slice(b"MBPD1\n");
    plain.extend_from_slice(header.as_bytes());
    plain.push(b'\n');
    plain.extend_from_slice(body.as_bytes());

    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 19).map_err(TableError::Compress)?;
    encoder
        .long_distance_matching(true)
        .map_err(TableError::Compress)?;
    encoder.window_log(24).map_err(TableError::Compress)?;
    encoder.write_all(&plain).map_err(TableError::Compress)?;
    encoder.finish().map_err(TableError::Compress)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "handshake": { "serverbound": { "minecraft:intention": { "protocol_id": 0 } } },
      "login": {
        "serverbound": { "minecraft:hello": { "protocol_id": 0 }, "minecraft:key": { "protocol_id": 1 } },
        "clientbound": { "minecraft:hello": { "protocol_id": 1 }, "minecraft:login_finished": { "protocol_id": 2 } }
      },
      "play": {
        "serverbound": {
          "minecraft:swing": { "protocol_id": 54 },
          "minecraft:move_player_pos": { "protocol_id": 26 },
          "minecraft:use_item_on": { "protocol_id": 56 }
        },
        "clientbound": {
          "minecraft:set_time": { "protocol_id": 98 },
          "minecraft:block_update": { "protocol_id": 9 },
          "minecraft:debug/block_value": { "protocol_id": 10 }
        }
      }
    }"#;

    fn prismarine(play_to_server: &[(i32, &str)], play_to_client: &[(i32, &str)]) -> String {
        let side = |entries: &[(i32, &str)]| {
            let mut mappings = serde_json::Map::new();
            let mut fields = serde_json::Map::new();
            let mut types = serde_json::Map::new();
            for (id, name) in entries {
                mappings.insert(format!("0x{id:02x}"), serde_json::json!(name));
                fields.insert(
                    (*name).to_owned(),
                    serde_json::json!(format!("packet_{name}")),
                );
                types.insert(
                    format!("packet_{name}"),
                    serde_json::json!(["container", [{ "name": name, "type": "varint" }]]),
                );
            }
            types.insert(
                "packet".into(),
                serde_json::json!(["container", [
                    { "name": "name", "type": ["mapper", { "type": "varint", "mappings": mappings }] },
                    { "name": "params", "type": ["switch", { "compareTo": "name", "fields": fields }] }
                ]]),
            );
            serde_json::json!({ "types": types })
        };
        serde_json::json!({
            "types": { "varint": "native" },
            "play": { "toServer": side(play_to_server), "toClient": side(play_to_client) }
        })
        .to_string()
    }

    #[test]
    fn reads_every_state_of_the_vanilla_report_and_names_it_canonically() {
        let raw = raw_from_vanilla_report(REPORT, 769, "1.21.4").expect("the report parses");
        let tables = build_tables(&[raw]).expect("tables build");
        let table = &tables[0];
        assert_eq!(table.play.serverbound[54].as_deref(), Some("swing"));
        assert_eq!(
            table.play.serverbound[26].as_deref(),
            Some("set_player_position"),
            "the version's own name is mapped onto the inspector's name"
        );
        assert_eq!(table.play.clientbound[98].as_deref(), Some("update_time"));
        assert_eq!(
            table.play.clientbound[10].as_deref(),
            Some("debug_block_value")
        );
        let login = table.login.as_ref().expect("login is tabulated");
        assert_eq!(login.serverbound[0].as_deref(), Some("login_start"));
        assert_eq!(login.clientbound[1].as_deref(), Some("encryption_request"));
        assert_eq!(login.clientbound[2].as_deref(), Some("login_success"));
        assert!(table.play.serverbound[0].is_none());
    }

    #[test]
    fn minecraft_data_names_are_aligned_with_the_vanilla_name_beside_them() {
        // Protocol 2 has both sources; protocol 1 only minecraft-data. The
        // alignment learned from 2 must name protocol 1's packets.
        let vanilla = r#"{"play":{
            "serverbound":{"minecraft:swing":{"protocol_id":1},"minecraft:move_player_pos":{"protocol_id":2}},
            "clientbound":{"minecraft:set_time":{"protocol_id":0}}}}"#;
        let raws = vec![
            raw_from_vanilla_report(vanilla, 2, "two").unwrap(),
            raw_from_prismarine(
                &prismarine(
                    &[(1, "arm_animation"), (2, "position")],
                    &[(0, "update_time")],
                ),
                2,
                "two",
            )
            .unwrap(),
            raw_from_prismarine(
                &prismarine(
                    &[(5, "position"), (6, "arm_animation")],
                    &[(3, "update_time")],
                ),
                1,
                "one",
            )
            .unwrap(),
        ];
        let tables = build_tables(&raws).unwrap();
        let old = tables.iter().find(|table| table.protocol == 1).unwrap();
        assert_eq!(old.source, "minecraft-data");
        assert_eq!(
            old.play.serverbound[5].as_deref(),
            Some("set_player_position")
        );
        assert_eq!(old.play.serverbound[6].as_deref(), Some("swing"));
        assert_eq!(old.play.clientbound[3].as_deref(), Some("update_time"));
        let new = tables.iter().find(|table| table.protocol == 2).unwrap();
        assert_eq!(new.source, "vanilla data generator report");
    }

    #[test]
    fn a_vanilla_rename_is_followed_back_to_older_releases() {
        // minecraft-data keeps `success`; vanilla renamed game_profile to
        // login_finished between protocols 1 and 2.
        let report = |name: &str| {
            format!(
                r#"{{"login":{{"clientbound":{{"minecraft:{name}":{{"protocol_id":2}}}}}},
                    "play":{{"serverbound":{{"minecraft:swing":{{"protocol_id":0}}}}}}}}"#
            )
        };
        let md = |protocol| {
            let mut root: serde_json::Value =
                serde_json::from_str(&prismarine(&[(0, "arm_animation")], &[])).unwrap();
            root["login"] = serde_json::json!({ "toClient": { "types": { "packet": ["container", [
                { "name": "name", "type": ["mapper", { "type": "varint", "mappings": { "0x02": "success" } }] }
            ]] } } });
            raw_from_prismarine(&root.to_string(), protocol, "v").unwrap()
        };
        let raws = vec![
            raw_from_vanilla_report(&report("game_profile"), 1, "one").unwrap(),
            raw_from_vanilla_report(&report("login_finished"), 2, "two").unwrap(),
            raw_from_vanilla_report(&report("login_finished"), 3, "three").unwrap(),
            md(1),
            md(2),
            md(3),
        ];
        let vocabulary = Vocabulary::learn(&raws);
        assert_eq!(
            vocabulary.follow_renames("login", false, "game_profile"),
            "login_finished"
        );
    }

    #[test]
    fn a_vanilla_report_outranks_minecraft_data_for_the_same_protocol() {
        // minecraft-data lists server_links as serverbound in some releases;
        // vanilla only ever sends it clientbound, and vanilla wins.
        let vanilla = r#"{"play":{"serverbound":{"minecraft:swing":{"protocol_id":0}},
            "clientbound":{"minecraft:server_links":{"protocol_id":0}}}}"#;
        let raws = vec![
            raw_from_prismarine(
                &prismarine(&[(0, "arm_animation"), (1, "server_links")], &[]),
                2,
                "two",
            )
            .unwrap(),
            raw_from_vanilla_report(vanilla, 2, "two").unwrap(),
        ];
        let tables = build_tables(&raws).unwrap();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].play.serverbound, vec![Some("swing".to_owned())]);
        assert_eq!(tables[0].source, "vanilla data generator report");
    }

    #[test]
    fn definition_bundles_store_identical_definitions_once() {
        let mut definitions = BTreeMap::new();
        definitions.insert(1, r#"{"types":{}}"#.to_owned());
        definitions.insert(2, r#"{"types":{}}"#.to_owned());
        definitions.insert(3, r#"{"types":{"x":"native"}}"#.to_owned());
        let packed = pack_definitions(&definitions).unwrap();
        let plain = zstd::decode_all(packed.as_slice()).unwrap();
        let text = String::from_utf8(plain).unwrap();
        let mut lines = text.splitn(3, '\n');
        assert_eq!(lines.next(), Some("MBPD1"));
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["versions"]["1"], header["versions"]["2"]);
        assert_ne!(header["versions"]["1"], header["versions"]["3"]);
    }

    #[test]
    fn the_bundled_tables_are_unambiguous_and_already_canonical() {
        let tables = parse_existing(include_str!(
            "../../mineburp-protocol/data/packet-tables.json"
        ))
        .expect("the bundled tables parse");
        assert!(!tables.is_empty());
        for table in &tables {
            assert_eq!(duplicate_names(table), Vec::<String>::new());
            for state in STATES {
                let Some(entries) = table.state(state) else {
                    continue;
                };
                for serverbound in [true, false] {
                    for name in entries.side(serverbound).iter().flatten() {
                        assert_eq!(
                            &canonical_name(state, serverbound, name),
                            name,
                            "{} {state}: canonicalising the bundled data must change nothing",
                            table.version
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_bundled_definitions_unpack() {
        let packed = include_bytes!("../../mineburp-protocol/data/protocol-definitions.zst");
        let plain = zstd::decode_all(packed.as_slice()).expect("the bundle decompresses");
        assert!(plain.starts_with(b"MBPD1\n"));
    }

    #[test]
    fn a_report_without_play_packets_is_an_error_rather_than_an_empty_table() {
        let error = raw_from_vanilla_report(r#"{"play":{}}"#, 769, "1.21.4")
            .expect_err("an empty state must not be written out as a table");
        assert!(matches!(error, TableError::Empty));
    }
}
