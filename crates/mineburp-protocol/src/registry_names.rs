//! Names for the numeric registry ids decoded fields carry.
//!
//! Items, entity types, block states, sounds, particles and the other built-in
//! registries travel as small integers that are renumbered whenever a release
//! adds an entry. `mineburp-packet-table` derives one id → name list per
//! protocol from the game's own registry reports (1.13+) or `minecraft-data`
//! (back to 1.7), and this module reads that bundle.
//!
//! Decoded fields keep every number exactly as it was on the wire. A name is
//! added *beside* it, under the same key with a `_name` suffix
//! (`item_id: 869` gains `item_id_name: "minecraft:diamond_sword"`), or `_names`
//! for an array of ids. Pre-1.13 items and blocks also carry a damage value or
//! metadata nibble; where `minecraft-data` names that variant it appears as
//! `<key>_variant` (`"Granite"`). A block state is named the way the game
//! prints one: `minecraft:oak_stairs[facing=north,half=top,…]`.
//!
//! Registries a server sends in `registry_data` during configuration — biomes,
//! damage types, chat types, and since 1.21 enchantments and painting variants
//! — are per connection and have no static table, so ids into them stay
//! unnamed rather than guessed.
//!
//! Nothing here runs while capturing: the bundle is decompressed the first time
//! an opened packet asks for a name, and each registry is parsed on first use.

use std::{
    collections::HashMap,
    io::Read as _,
    sync::{Arc, Mutex, OnceLock},
};

use serde_json::{Map, Value};

const BUNDLE: &[u8] = include_bytes!("../data/registry-names.zst");
/// The decompressed bundle is a few megabytes; anything far past that is not
/// the bundle this crate was built with.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
/// Annotation stops descending past this depth; decoded trees are bounded
/// already, this only keeps the walk from trusting that.
const MAX_DEPTH: usize = 64;
/// Ids per array that are named. A chunk-sized list of block states is not
/// worth a name per entry.
const MAX_ARRAY_NAMES: usize = 4_096;

struct Bundle {
    text: String,
    index: HashMap<i32, HashMap<String, (usize, usize)>>,
}

fn bundle() -> Option<&'static Bundle> {
    static CELL: OnceLock<Option<Bundle>> = OnceLock::new();
    CELL.get_or_init(|| load_bundle(BUNDLE)).as_ref()
}

fn load_bundle(bytes: &[u8]) -> Option<Bundle> {
    let decoder = zstd::stream::Decoder::new(bytes).ok()?;
    let mut plain = String::new();
    decoder
        .take(MAX_BUNDLE_BYTES)
        .read_to_string(&mut plain)
        .ok()?;
    let rest = plain.strip_prefix("MBRN1\n")?;
    let (header, body) = rest.split_once('\n')?;
    let header: Value = serde_json::from_str(header).ok()?;
    let mut index = HashMap::new();
    for (protocol, registries) in header.get("protocols")?.as_object()? {
        let protocol: i32 = protocol.parse().ok()?;
        let mut entry = HashMap::new();
        for (key, range) in registries.as_object()? {
            let start = usize::try_from(range.get(0)?.as_u64()?).ok()?;
            let length = usize::try_from(range.get(1)?.as_u64()?).ok()?;
            if start.checked_add(length)? > body.len() {
                return None;
            }
            entry.insert(key.clone(), (start, length));
        }
        index.insert(protocol, entry);
    }
    let offset = plain.len() - body.len();
    let text = plain.split_off(offset);
    Some(Bundle { text, index })
}

/// One parsed registry.
#[derive(Debug)]
enum Registry {
    List(List),
    States(Vec<Block>),
    /// Pre-1.13 block states: a block id over a four-bit metadata nibble.
    LegacyStates(List),
}

#[derive(Debug, Default)]
struct List {
    names: Vec<Option<String>>,
    variants: HashMap<i64, HashMap<i64, String>>,
}

#[derive(Debug)]
struct Block {
    name: String,
    first: i64,
    count: i64,
    grid: Vec<(String, Vec<String>)>,
    explicit: Option<Vec<String>>,
}

/// Parsed registries keyed by their byte range in the bundle, so a registry
/// shared by several releases is parsed once.
type ParsedRegistries = Mutex<HashMap<(usize, usize), Arc<Registry>>>;

fn registry(protocol: i32, key: &str) -> Option<Arc<Registry>> {
    static PARSED: OnceLock<ParsedRegistries> = OnceLock::new();
    let bundle = bundle()?;
    let range = *bundle.index.get(&protocol)?.get(key)?;
    let cache = PARSED.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(found) = cache.lock().ok()?.get(&range) {
        return Some(Arc::clone(found));
    }
    let payload: Value = serde_json::from_str(bundle.text.get(range.0..range.0 + range.1)?).ok()?;
    let parsed = Arc::new(parse_registry(&payload)?);
    cache.lock().ok()?.insert(range, Arc::clone(&parsed));
    Some(parsed)
}

fn parse_registry(payload: &Value) -> Option<Registry> {
    match payload.get("kind")?.as_str()? {
        "list" => Some(Registry::List(parse_list(payload)?)),
        "legacy_states" => Some(Registry::LegacyStates(parse_list(payload)?)),
        "states" => {
            let mut blocks = Vec::new();
            for entry in payload.get("blocks")?.as_array()? {
                let name = entry.get(0)?.as_str()?.to_owned();
                let first = entry.get(1)?.as_i64()?;
                let grid: Vec<(String, Vec<String>)> = entry
                    .get(2)
                    .and_then(Value::as_array)
                    .map(|grid| {
                        grid.iter()
                            .filter_map(|property| {
                                let key = property.get(0)?.as_str()?.to_owned();
                                let values = property
                                    .get(1)?
                                    .as_array()?
                                    .iter()
                                    .filter_map(|value| value.as_str().map(str::to_owned))
                                    .collect();
                                Some((key, values))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let explicit: Option<Vec<String>> =
                    entry.get(3).and_then(Value::as_array).map(|states| {
                        states
                            .iter()
                            .map(|state| state.as_str().unwrap_or_default().to_owned())
                            .collect()
                    });
                let count = match &explicit {
                    Some(states) => i64::try_from(states.len()).ok()?,
                    None => grid.iter().try_fold(1_i64, |count, (_, values)| {
                        count.checked_mul(i64::try_from(values.len().max(1)).ok()?)
                    })?,
                };
                blocks.push(Block {
                    name,
                    first,
                    count,
                    grid,
                    explicit,
                });
            }
            blocks.sort_by_key(|block| block.first);
            Some(Registry::States(blocks))
        }
        _ => None,
    }
}

fn parse_list(payload: &Value) -> Option<List> {
    let names = payload
        .get("names")?
        .as_array()?
        .iter()
        .map(|name| name.as_str().map(str::to_owned))
        .collect();
    let mut variants = HashMap::new();
    if let Some(found) = payload.get("variants").and_then(Value::as_object) {
        for (id, by_meta) in found {
            let Ok(id) = id.parse::<i64>() else { continue };
            let mut entry = HashMap::new();
            for (meta, label) in by_meta.as_object().into_iter().flatten() {
                if let (Ok(meta), Some(label)) = (meta.parse::<i64>(), label.as_str()) {
                    entry.insert(meta, label.to_owned());
                }
            }
            variants.insert(id, entry);
        }
    }
    Some(List { names, variants })
}

impl List {
    fn name(&self, id: i64) -> Option<&str> {
        self.names.get(usize::try_from(id).ok()?)?.as_deref()
    }

    fn variant(&self, id: i64, meta: i64) -> Option<&str> {
        self.variants.get(&id)?.get(&meta).map(String::as_str)
    }
}

/// A resolved name, and the pre-1.13 damage-value variant where one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub name: String,
    pub variant: Option<String>,
}

/// Names one registry id for one protocol.
///
/// `registry` is the vanilla registry key without its namespace — `item`,
/// `entity_type`, `block_state`, `sound_event`, `particle_type`, `menu`, and
/// so on; `legacy_object` is the pre-1.14 table spawned objects (boats,
/// minecarts, projectiles) were numbered from. `meta` is a pre-1.13 item's
/// damage value, used only to name its variant.
#[must_use]
pub fn registry_entry(
    protocol: i32,
    registry_key: &str,
    id: i64,
    meta: Option<i64>,
) -> Option<RegistryEntry> {
    match &*registry(protocol, registry_key)? {
        Registry::List(list) => Some(RegistryEntry {
            name: list.name(id)?.to_owned(),
            variant: meta
                .and_then(|meta| list.variant(id, meta))
                .map(str::to_owned),
        }),
        Registry::LegacyStates(list) => {
            let (block, meta) = (id >> 4, id & 0x0f);
            let name = list.name(block)?;
            let variant = list.variant(block, meta).map(str::to_owned);
            Some(RegistryEntry {
                name: if meta == 0 || variant.is_some() {
                    name.to_owned()
                } else {
                    format!("{name}[metadata={meta}]")
                },
                variant,
            })
        }
        Registry::States(blocks) => {
            let at = blocks
                .partition_point(|block| block.first <= id)
                .checked_sub(1)?;
            let block = &blocks[at];
            let offset = id - block.first;
            if offset >= block.count {
                return None;
            }
            let properties = match &block.explicit {
                Some(states) => states.get(usize::try_from(offset).ok()?)?.clone(),
                None => grid_state(&block.grid, offset),
            };
            Some(RegistryEntry {
                name: if properties.is_empty() {
                    block.name.clone()
                } else {
                    format!("{}[{properties}]", block.name)
                },
                variant: None,
            })
        }
    }
}

/// Names one registry id for one protocol; see [`registry_entry`].
#[must_use]
pub fn registry_name(protocol: i32, registry_key: &str, id: i64) -> Option<String> {
    registry_entry(protocol, registry_key, id, None).map(|entry| entry.name)
}

/// The protocols with bundled registry names.
#[must_use]
pub fn registry_name_protocols() -> Vec<i32> {
    let mut protocols: Vec<i32> = bundle()
        .map(|bundle| bundle.index.keys().copied().collect())
        .unwrap_or_default();
    protocols.sort_unstable();
    protocols
}

/// The registries bundled for one protocol.
#[must_use]
pub fn registry_keys(protocol: i32) -> Vec<String> {
    let mut keys: Vec<String> = bundle()
        .and_then(|bundle| bundle.index.get(&protocol))
        .map(|registries| registries.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

/// The state at `index` within a block, last property varying fastest — the
/// order the game numbers states in.
fn grid_state(grid: &[(String, Vec<String>)], mut index: i64) -> String {
    let mut picked = vec![0_usize; grid.len()];
    for (slot, (_, values)) in grid.iter().enumerate().rev() {
        let count = i64::try_from(values.len().max(1)).unwrap_or(1);
        picked[slot] = usize::try_from(index % count).unwrap_or(0);
        index /= count;
    }
    grid.iter()
        .zip(picked)
        .map(|((key, values), choice)| {
            format!("{key}={}", values.get(choice).map_or("", String::as_str))
        })
        .collect::<Vec<_>>()
        .join(",")
}

// --- annotating decoded fields ---

/// What a numeric field refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// An id into one registry.
    Id(&'static str),
    /// A pre-1.13 item whose damage value sits in a sibling field.
    LegacyItem(&'static str),
    /// A registry holder sent raw: `0` means an inline value follows, and
    /// anything else is the id plus one.
    Holder(&'static str),
    /// A 1.16.2+ section update record: a block state over a 12-bit position.
    PackedState,
    /// A statistic, whose registry depends on its category.
    Statistic,
}

struct Context<'a> {
    packet: &'a str,
    protocol: i32,
}

/// Adds a `_name` companion beside every registry id in `fields` that this
/// protocol's registries can name. Fields that are already names (some
/// descriptions map ids to strings themselves) and ids with no entry are left
/// alone.
pub(crate) fn annotate(packet: &str, protocol: Option<i32>, fields: &mut Value) {
    let Some(protocol) = protocol else { return };
    if bundle().is_none_or(|bundle| !bundle.index.contains_key(&protocol)) {
        return;
    }
    let context = Context { packet, protocol };
    walk(&context, None, fields, 0);
}

fn walk(context: &Context<'_>, parent: Option<&str>, value: &mut Value, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if matches!(child, Value::Object(_) | Value::Array(_)) {
                    walk(context, Some(key), child, depth + 1);
                }
            }
            annotate_object(context, parent, depth, object);
        }
        Value::Array(items) => {
            for item in items {
                walk(context, parent, item, depth + 1);
            }
        }
        _ => {}
    }
}

fn annotate_object(
    context: &Context<'_>,
    parent: Option<&str>,
    depth: usize,
    object: &mut Map<String, Value>,
) {
    let mut additions: Vec<(String, Vec<(String, Value)>)> = Vec::new();
    for (key, value) in object.iter() {
        let Some(target) = target_for(context, parent, depth, object, key, value) else {
            continue;
        };
        let added = match value {
            Value::Number(number) => number
                .as_i64()
                .map(|id| name_one(context, object, key, target, id))
                .unwrap_or_default(),
            Value::Array(items) => name_array(context, key, target, items),
            _ => Vec::new(),
        };
        if !added.is_empty() {
            additions.push((key.clone(), added));
        }
    }
    if additions.is_empty() {
        return;
    }
    // Rebuild so each name sits directly after the id it names.
    let mut rebuilt = Map::new();
    for (key, value) in std::mem::take(object) {
        let after = additions
            .iter()
            .position(|(named, _)| *named == key)
            .map(|at| additions.swap_remove(at).1);
        rebuilt.insert(key, value);
        for (name, value) in after.into_iter().flatten() {
            rebuilt.entry(name).or_insert(value);
        }
    }
    *object = rebuilt;
}

fn name_one(
    context: &Context<'_>,
    object: &Map<String, Value>,
    key: &str,
    target: Target,
    id: i64,
) -> Vec<(String, Value)> {
    let protocol = context.protocol;
    let entry = match target {
        Target::Id(registry_key) => registry_entry(protocol, registry_key, id, None),
        Target::LegacyItem(registry_key) => {
            let meta = object
                .get("item_damage")
                .and_then(Value::as_i64)
                .filter(|_| protocol < 393);
            registry_entry(protocol, registry_key, id, meta)
        }
        Target::Holder(registry_key) => {
            if id <= 0 {
                None
            } else {
                registry_entry(protocol, registry_key, id - 1, None)
            }
        }
        Target::PackedState => registry_entry(protocol, "block_state", id >> 12, None),
        Target::Statistic => object
            .get("category_id")
            .and_then(Value::as_i64)
            .and_then(|category| registry_name(protocol, "stat_type", category))
            .and_then(|category| statistic_registry(&category))
            .and_then(|registry_key| registry_entry(protocol, registry_key, id, None)),
    };
    let Some(entry) = entry else {
        return Vec::new();
    };
    let mut added = vec![(format!("{key}_name"), Value::String(entry.name))];
    if let Some(variant) = entry.variant {
        added.push((format!("{key}_variant"), Value::String(variant)));
    }
    added
}

fn name_array(
    context: &Context<'_>,
    key: &str,
    target: Target,
    items: &[Value],
) -> Vec<(String, Value)> {
    if items.is_empty() || !items.iter().all(Value::is_i64) {
        return Vec::new();
    }
    let names: Vec<Value> = items
        .iter()
        .take(MAX_ARRAY_NAMES)
        .map(|item| {
            let id = item.as_i64().unwrap_or(-1);
            let entry = match target {
                Target::PackedState => {
                    registry_entry(context.protocol, "block_state", id >> 12, None)
                }
                Target::Id(registry_key) => {
                    registry_entry(context.protocol, registry_key, id, None)
                }
                _ => None,
            };
            entry.map_or(Value::Null, |entry| Value::String(entry.name))
        })
        .collect();
    if names.iter().all(Value::is_null) {
        return Vec::new();
    }
    vec![(format!("{key}_names"), Value::Array(names))]
}

/// The registry an entity-metadata value points into, from the entry's type.
///
/// From 1.19.4 the descriptions name each type; before that the type is a
/// number whose meaning moved twice — 1.13 inserted an optional text type, and
/// 1.19.3 a long — so the numbers are read against the release.
fn metadata_target(protocol: i32, kind: &Value) -> Option<&'static str> {
    if let Some(kind) = kind.as_str() {
        return Some(match kind {
            "block_state" | "optional_block_state" => "block_state",
            "cat_variant" => "cat_variant",
            "frog_variant" => "frog_variant",
            "painting_variant" => "painting_variant",
            _ => return None,
        });
    }
    let kind = kind.as_i64()?;
    Some(match (protocol, kind) {
        // Optional block state: 0 is air, which is also how "absent" is sent.
        (107..=392, 12) | (393..=760, 13) | (761, 14) => "block_state",
        (759..=760, 19) | (761, 20) => "cat_variant",
        (759..=760, 20) | (761, 21) => "frog_variant",
        (759..=760, 22) | (761, 23) => "painting_variant",
        _ => return None,
    })
}

/// The registry a statistic's id points into, from its category.
fn statistic_registry(category: &str) -> Option<&'static str> {
    Some(
        match category.strip_prefix("minecraft:").unwrap_or(category) {
            "mined" => "block",
            "crafted" | "used" | "broken" | "picked_up" | "dropped" => "item",
            "killed" | "killed_by" => "entity_type",
            "custom" => "custom_stat",
            _ => return None,
        },
    )
}

/// Rules for a packet's own top-level fields, where a short key such as
/// `type` means something different in every packet.
fn packet_target(context: &Context<'_>, key: &str) -> Option<Target> {
    let protocol = context.protocol;
    match (context.packet, key) {
        ("add_entity", "type") => Some(Target::Id(if protocol < 477 {
            "legacy_object"
        } else {
            "entity_type"
        })),
        ("spawn_entity_living", "type") => Some(Target::Id("entity_type")),
        ("block_update", "type" | "block_state") => Some(Target::Id("block_state")),
        ("section_blocks_update", "records") if protocol >= 751 => Some(Target::PackedState),
        ("block_event", "block_id" | "block_type") => Some(Target::Id("block")),
        ("entity_effect" | "remove_entity_effect", "effect_id" | "effect") => {
            Some(Target::Id("mob_effect"))
        }
        // From 1.19.3 a packet-level sound id is a raw holder; the
        // descriptions that wrap it in a holder object decode the id
        // already, and those sit one level down.
        ("sound_effect" | "sound_entity" | "named_sound_effect", "sound_id") => {
            Some(if protocol >= 761 {
                Target::Holder("sound_event")
            } else {
                Target::Id("sound_event")
            })
        }
        ("level_particles", "particle_id" | "particle" | "type") => {
            Some(Target::Id("particle_type"))
        }
        ("open_screen", "inventory_type" | "type" | "window_type") if protocol >= 477 => {
            Some(Target::Id("menu"))
        }
        ("block_entity_data", "action") if protocol >= 757 => Some(Target::Id("block_entity_type")),
        ("spawn_entity_painting", "title" | "motive") => Some(Target::Id(
            if registry(protocol, "painting_variant").is_some() {
                "painting_variant"
            } else {
                "motive"
            },
        )),
        ("cooldown", "item_id") => Some(Target::Id("item")),
        _ => None,
    }
}

/// Decides what one field refers to. Packet-specific rules come first because
/// short keys like `type` mean different things in different packets; the
/// generic rules after them match keys that only ever hold one kind of id.
fn target_for(
    context: &Context<'_>,
    parent: Option<&str>,
    depth: usize,
    object: &Map<String, Value>,
    key: &str,
    value: &Value,
) -> Option<Target> {
    let top = depth == 0;
    let protocol = context.protocol;
    let is_array = value.is_array();
    if !(value.is_i64() || is_array) {
        return None;
    }

    if top && let Some(target) = packet_target(context, key) {
        return Some(target);
    }

    // Pre-1.16.2 section updates list their records as objects.
    if context.packet == "section_blocks_update" && key == "block_id" && parent == Some("records") {
        return Some(Target::Id("block_state"));
    }
    if context.packet == "award_stats" {
        match key {
            "category_id" => return Some(Target::Id("stat_type")),
            "statistic_id" => return Some(Target::Statistic),
            _ => {}
        }
    }
    if context.packet == "update_attributes" && key == "key" && parent == Some("properties") {
        return Some(Target::Id("attribute"));
    }
    // Entity metadata: the value's meaning is the entry's type.
    if key == "value"
        && let Some(kind) = object.get("type")
    {
        return metadata_target(protocol, kind).map(Target::Id);
    }
    // A hand-decoded stack (`{id, count}`) and the component lists around it.
    if context.packet == "click_container" {
        match (parent, key) {
            (Some("item" | "carried_item"), "id") => return Some(Target::Id("item")),
            (Some("component_hashes"), "type") | (_, "removed_components") => {
                return Some(Target::Id("data_component_type"));
            }
            _ => {}
        }
    }
    // Item components: an added component's type, and the removed list.
    if key == "type" && matches!(parent, Some("components" | "remove_components")) {
        return Some(Target::Id("data_component_type"));
    }
    // A particle object (`{type, …data}`) wherever it is embedded.
    if key == "type"
        && parent.is_some_and(|parent| parent == "particle" || parent.ends_with("_particle"))
    {
        return Some(Target::Id("particle_type"));
    }

    match (parent, key) {
        // A chunk's block entities.
        (Some("block_entities"), "type") => return Some(Target::Id("block_entity_type")),
        // Attribute modifiers on an item, and the effects a stew or potion
        // carries.
        (Some("attributes"), "type_id") => return Some(Target::Id("attribute")),
        (Some("effects"), "effect") => return Some(Target::Id("mob_effect")),
        (_, "id") if object.contains_key("details") => return Some(Target::Id("mob_effect")),
        (Some("icons" | "decorations"), "type") if context.packet == "map_item_data" => {
            return Some(Target::Id("map_decoration_type"));
        }
        _ => {}
    }

    match key {
        "item_id" => Some(Target::LegacyItem("item")),
        "ingredient_id" | "template_item_id" => Some(Target::Id("item")),
        // Before 1.13 a stack's item id was spelled `blockId`.
        "block_id" if object.contains_key("item_count") || object.contains_key("item_damage") => {
            Some(Target::LegacyItem("item"))
        }
        "block_state" => Some(Target::Id("block_state")),
        "villager_type" => Some(Target::Id("villager_type")),
        "villager_profession" => Some(Target::Id("villager_profession")),
        "particle_id" => Some(Target::Id("particle_type")),
        "effect_id" | "primary_effect" | "secondary_effect" => Some(Target::Id("mob_effect")),
        "potion_id" => Some(Target::Id("potion")),
        "entity_type" => Some(Target::Id("entity_type")),
        // Inside a holder object the description has already removed the
        // holder's offset.
        "sound_id" if !top => Some(Target::Id("sound_event")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diamond_sword_across_releases() {
        for (protocol, id) in [(47, 276), (340, 276), (765, 834), (769, 869)] {
            assert_eq!(
                registry_name(protocol, "item", id).as_deref(),
                Some("minecraft:diamond_sword"),
                "protocol {protocol}"
            );
        }
    }

    #[test]
    fn every_supported_release_has_items_and_block_states() {
        let protocols = registry_name_protocols();
        assert!(protocols.len() >= 49, "{protocols:?}");
        for protocol in protocols {
            let keys = registry_keys(protocol);
            for key in ["item", "block_state", "entity_type"] {
                assert!(
                    keys.iter().any(|found| found == key),
                    "{protocol} lacks {key}"
                );
            }
        }
    }

    #[test]
    fn names_are_unique_within_each_registry() {
        for protocol in registry_name_protocols() {
            for key in registry_keys(protocol) {
                if key == "legacy_object" {
                    continue;
                }
                let Some(found) = registry(protocol, &key) else {
                    panic!("{protocol} {key} does not parse");
                };
                if let Registry::List(list) | Registry::LegacyStates(list) = &*found {
                    let mut seen = std::collections::HashSet::new();
                    for name in list.names.iter().flatten() {
                        assert!(seen.insert(name), "{protocol} {key}: {name} twice");
                    }
                }
            }
        }
    }

    #[test]
    fn block_states_name_their_properties() {
        assert_eq!(
            registry_name(769, "block_state", 0).as_deref(),
            Some("minecraft:air")
        );
        assert_eq!(
            registry_name(769, "block_state", 1).as_deref(),
            Some("minecraft:stone")
        );
        let stairs = registry_name(769, "block_state", 2929).unwrap();
        assert!(
            stairs.starts_with("minecraft:oak_stairs[facing=north,half=top,"),
            "{stairs}"
        );
        // Pre-1.13: block id 1, metadata 1 is granite.
        let granite = registry_entry(47, "block_state", (1 << 4) | 1, None).unwrap();
        assert_eq!(granite.name, "minecraft:stone");
        assert_eq!(granite.variant.as_deref(), Some("Granite"));
        assert_eq!(
            registry_name(47, "block_state", 3 << 4).as_deref(),
            Some("minecraft:dirt")
        );
    }

    #[test]
    fn legacy_items_and_objects() {
        let granite = registry_entry(47, "item", 1, Some(1)).unwrap();
        assert_eq!(granite.name, "minecraft:stone");
        assert_eq!(granite.variant.as_deref(), Some("Granite"));
        assert_eq!(
            registry_name(47, "entity_type", 50).as_deref(),
            Some("Creeper")
        );
        assert_eq!(
            registry_name(340, "entity_type", 50).as_deref(),
            Some("minecraft:creeper")
        );
        assert_eq!(
            registry_name(47, "legacy_object", 1).as_deref(),
            Some("Boat")
        );
        assert_eq!(
            registry_name(47, "mob_effect", 1).as_deref(),
            Some("minecraft:speed")
        );
    }

    #[test]
    fn unknown_ids_and_protocols_stay_unnamed() {
        assert_eq!(registry_name(769, "item", 1_000_000), None);
        assert_eq!(registry_name(769, "item", -1), None);
        assert_eq!(registry_name(769, "block_state", i64::MAX), None);
        assert_eq!(registry_name(1, "item", 1), None);
        assert_eq!(registry_name(769, "biome", 1), None);
    }

    #[test]
    fn annotation_adds_names_beside_ids() {
        let mut fields = json!({
            "entity_id": 7,
            "type": 0,
            "equipment": [{ "slot": 0, "item": { "item_count": 1, "item_id": 869 } }],
        });
        annotate("add_entity", Some(769), &mut fields);
        let keys: Vec<&str> = fields
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["entity_id", "type", "type_name", "equipment"]);
        assert_eq!(fields["type_name"], "minecraft:acacia_boat");
        assert_eq!(
            fields["equipment"][0]["item"]["item_id_name"],
            "minecraft:diamond_sword"
        );
        assert_eq!(fields["type"], 0, "the number is kept");
    }

    #[test]
    fn holders_statistics_and_packed_states() {
        let mut sound = json!({ "sound_id": 1 });
        annotate("sound_effect", Some(769), &mut sound);
        assert_eq!(
            sound["sound_id_name"],
            registry_name(769, "sound_event", 0).unwrap()
        );

        let mut nested = json!({ "sound": { "sound_id": 0 } });
        annotate("sound_effect", Some(769), &mut nested);
        assert_eq!(
            nested["sound"]["sound_id_name"],
            registry_name(769, "sound_event", 0).unwrap()
        );

        let mined = (0..40)
            .find(|id| registry_name(769, "stat_type", *id).as_deref() == Some("minecraft:mined"))
            .unwrap();
        let mut stats =
            json!({ "entries": [{ "category_id": mined, "statistic_id": 1, "value": 3 }] });
        annotate("award_stats", Some(769), &mut stats);
        assert_eq!(stats["entries"][0]["category_id_name"], "minecraft:mined");
        assert_eq!(stats["entries"][0]["statistic_id_name"], "minecraft:stone");

        let mut section = json!({ "records": [(1_i64 << 12) | 5, 5] });
        annotate("section_blocks_update", Some(769), &mut section);
        assert_eq!(
            section["records_names"],
            json!(["minecraft:stone", "minecraft:air"])
        );
    }

    #[test]
    fn legacy_slots_name_their_damage_variant() {
        let mut fields = json!({ "item": { "block_id": 1, "item_count": 1, "item_damage": 1 } });
        annotate("set_equipment", Some(47), &mut fields);
        assert_eq!(fields["item"]["block_id_name"], "minecraft:stone");
        assert_eq!(fields["item"]["block_id_variant"], "Granite");
    }

    #[test]
    fn hand_decoded_click_stacks_and_components() {
        let component = (0..200)
            .find(|id| registry_name(770, "data_component_type", *id).is_some())
            .unwrap();
        let mut fields = json!({
            "changed_slots": [{ "slot": 1, "item": { "id": 1, "count": 1 } }],
            "carried_item": {
                "id": 1,
                "count": 2,
                "component_hashes": [{ "type": component, "hash": "00000000" }],
                "removed_components": [component],
            },
        });
        annotate("click_container", Some(770), &mut fields);
        assert_eq!(
            fields["changed_slots"][0]["item"]["id_name"],
            "minecraft:stone"
        );
        assert_eq!(fields["carried_item"]["id_name"], "minecraft:stone");
        let component_name = registry_name(770, "data_component_type", component).unwrap();
        assert_eq!(
            fields["carried_item"]["component_hashes"][0]["type_name"],
            component_name
        );
        assert_eq!(
            fields["carried_item"]["removed_components_names"][0],
            component_name
        );
    }

    #[test]
    fn numbered_metadata_types_follow_the_release() {
        assert_eq!(metadata_target(340, &json!(12)), Some("block_state"));
        assert_eq!(metadata_target(578, &json!(13)), Some("block_state"));
        assert_eq!(metadata_target(761, &json!(14)), Some("block_state"));
        assert_eq!(metadata_target(761, &json!(13)), None);
        assert_eq!(metadata_target(47, &json!(12)), None);
        assert_eq!(
            metadata_target(769, &json!("optional_block_state")),
            Some("block_state")
        );
    }

    #[test]
    fn strings_and_unknown_protocols_are_left_alone() {
        let mut fields = json!({ "particle": { "type": "dust" } });
        annotate("level_particles", Some(769), &mut fields);
        assert_eq!(fields, json!({ "particle": { "type": "dust" } }));
        let mut fields = json!({ "item_id": 1 });
        annotate("anything", None, &mut fields);
        annotate("anything", Some(1), &mut fields);
        assert_eq!(fields, json!({ "item_id": 1 }));
    }
}
