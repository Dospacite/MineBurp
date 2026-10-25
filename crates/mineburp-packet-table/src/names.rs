//! Builds the registry-name bundle: per protocol, what each numeric registry id
//! on the wire is called.
//!
//! Items, entity types, block states, sounds and the rest of the built-in
//! registries are sent as small integers, and those integers are renumbered
//! whenever a release adds an entry. As with packet ids, nothing here is typed
//! out by hand. Two machine-generated sources describe a release:
//!
//! * the vanilla data generator's `reports/registries.json` (1.14+) and
//!   `reports/blocks.json` / `reports/items.json` (1.13+) — the game listing
//!   its own protocol ids, and
//! * `minecraft-data`'s `items.json`, `blocks.json`, `entities.json`,
//!   `effects.json`, `enchantments.json`, `particles.json` and `sounds.json`,
//!   which reach back past the flattening to 1.7.
//!
//! A vanilla report always wins over `minecraft-data` for the same registry.
//!
//! Registries that a server sends in `registry_data` during configuration
//! (biomes, damage types, chat types, and since 1.21 enchantments and painting
//! variants) are per connection and deliberately absent: a static table would
//! name them confidently and wrongly.

use std::{
    collections::{BTreeMap, HashMap},
    io::Write as _,
};

use serde_json::{Map, Value, json};

use crate::TableError;

/// Built-in vanilla registries whose protocol ids appear on the wire, keyed
/// without the `minecraft:` namespace.
pub const VANILLA_REGISTRIES: &[&str] = &[
    "item",
    "block",
    "entity_type",
    "mob_effect",
    "enchantment",
    "particle_type",
    "sound_event",
    "menu",
    "data_component_type",
    "attribute",
    "villager_type",
    "villager_profession",
    "custom_stat",
    "stat_type",
    "potion",
    "block_entity_type",
    "fluid",
    "game_event",
    "command_argument_type",
    "recipe_serializer",
    "recipe_type",
    "cat_variant",
    "frog_variant",
    "painting_variant",
    "motive",
    "instrument",
    "banner_pattern",
    "position_source_type",
    "consume_effect_type",
    "slot_display",
    "recipe_display",
    "recipe_book_category",
    "map_decoration_type",
    "number_format_type",
    "armor_material",
    "entity_sub_predicate_type",
];

/// `minecraft-data` files read for releases the vanilla reports do not cover.
pub const MINECRAFT_DATA_FILES: &[&str] = &[
    "items",
    "blocks",
    "entities",
    "effects",
    "enchantments",
    "particles",
    "sounds",
];

/// Everything known about one protocol's registries, as source text.
#[derive(Debug, Default, Clone)]
pub struct RegistrySources {
    /// `reports/registries.json`.
    pub vanilla_registries: Option<String>,
    /// `reports/blocks.json`.
    pub vanilla_blocks: Option<String>,
    /// `reports/items.json` (1.13 only writes items this way).
    pub vanilla_items: Option<String>,
    /// `minecraft-data` files keyed by [`MINECRAFT_DATA_FILES`] name.
    pub minecraft_data: BTreeMap<String, String>,
}

impl RegistrySources {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vanilla_registries.is_none()
            && self.vanilla_blocks.is_none()
            && self.vanilla_items.is_none()
            && self.minecraft_data.is_empty()
    }
}

/// Builds one protocol's registries: registry key → payload.
///
/// Payloads take one of three shapes, all plain JSON:
///
/// * `{"kind":"list","names":[…],"variants":{id:{meta:label}}}` — a dense
///   id → name list (`null` for holes). `variants` only appears for the
///   pre-flattening item and block damage values.
/// * `{"kind":"states","blocks":[[name, first_id, [[property,[values…]],…]]…]}`
///   — block states as each block's first state id and its property grid. A
///   state id inside a block indexes the grid with the *last* property varying
///   fastest, which is how the game numbers them; the generator checks every
///   block against the report's explicit ids and stores the explicit list
///   (`[name, first_id, null, ["a=b,c=d", …]]`) for any block that does not
///   follow the grid.
/// * `{"kind":"legacy_states", …list fields…}` — a pre-1.13 block state, which
///   is a block id shifted left four bits over a metadata nibble.
pub fn build_registries(
    protocol: i32,
    sources: &RegistrySources,
) -> Result<BTreeMap<String, Value>, TableError> {
    let mut out = BTreeMap::new();
    add_vanilla(&mut out, sources)?;
    add_minecraft_data(&mut out, protocol, sources)?;
    if protocol < 393 {
        borrow_block_variants(&mut out);
    }
    Ok(out)
}

/// Adds every registry a vanilla report describes.
fn add_vanilla(
    out: &mut BTreeMap<String, Value>,
    sources: &RegistrySources,
) -> Result<(), TableError> {
    if let Some(text) = &sources.vanilla_registries {
        let root = parse(text, "a vanilla registries report")?;
        for (key, registry) in object(&root, "a vanilla registries report")? {
            let short = key.strip_prefix("minecraft:").unwrap_or(key);
            if !VANILLA_REGISTRIES.contains(&short) {
                continue;
            }
            let Some(entries) = registry.get("entries").and_then(Value::as_object) else {
                continue;
            };
            let pairs = entries.iter().filter_map(|(name, entry)| {
                let id = entry.get("protocol_id")?.as_i64()?;
                Some((id, name.clone()))
            });
            if let Some(list) = dense_list(pairs) {
                out.insert(short.to_owned(), list);
            }
        }
    }
    if let Some(text) = &sources.vanilla_items
        && !out.contains_key("item")
    {
        let root = parse(text, "a vanilla items report")?;
        let pairs = object(&root, "a vanilla items report")?
            .iter()
            .filter_map(|(name, entry)| Some((entry.get("protocol_id")?.as_i64()?, name.clone())));
        if let Some(list) = dense_list(pairs) {
            out.insert("item".to_owned(), list);
        }
    }
    if let Some(text) = &sources.vanilla_blocks {
        let root = parse(text, "a vanilla blocks report")?;
        out.insert("block_state".to_owned(), vanilla_states(&root)?);
    }
    Ok(())
}

/// Fills in, from `minecraft-data`, whatever the vanilla reports did not cover.
fn add_minecraft_data(
    out: &mut BTreeMap<String, Value>,
    protocol: i32,
    sources: &RegistrySources,
) -> Result<(), TableError> {
    for (file, text) in &sources.minecraft_data {
        let root = parse(text, "a minecraft-data registry")?;
        let Some(entries) = root.as_array() else {
            continue;
        };
        match file.as_str() {
            "items" if !out.contains_key("item") => {
                if let Some(list) = legacy_list(entries, "item", protocol) {
                    out.insert("item".into(), list);
                }
            }
            "blocks" => {
                if !out.contains_key("block")
                    && let Some(list) = legacy_list(entries, "block", protocol)
                {
                    out.insert("block".into(), list);
                }
                if !out.contains_key("block_state") {
                    let states = if protocol < 393 {
                        legacy_list(entries, "block", protocol).map(|mut list| {
                            list["kind"] = json!("legacy_states");
                            list
                        })
                    } else {
                        minecraft_data_states(entries)
                    };
                    if let Some(states) = states {
                        out.insert("block_state".into(), states);
                    }
                }
            }
            "entities" => {
                // Before 1.14 a spawned object and a spawned mob are numbered
                // from two different tables.
                let mobs = entries.iter().filter(|entry| {
                    protocol >= 477 || entry.get("type").and_then(Value::as_str) != Some("object")
                });
                if !out.contains_key("entity_type")
                    && let Some(list) = dense_list(mobs.filter_map(|entry| {
                        Some((
                            entry.get("id")?.as_i64()?,
                            md_name("entities", entry, protocol)?,
                        ))
                    }))
                {
                    out.insert("entity_type".into(), list);
                }
                if protocol < 477 {
                    let objects = entries.iter().filter(|entry| {
                        entry.get("type").and_then(Value::as_str) == Some("object")
                    });
                    if let Some(list) = dense_list(objects.filter_map(|entry| {
                        Some((
                            entry.get("id")?.as_i64()?,
                            md_name("entities", entry, protocol)?,
                        ))
                    })) {
                        out.insert("legacy_object".into(), list);
                    }
                }
            }
            "effects" | "enchantments" | "particles" | "sounds" => {
                let key = match file.as_str() {
                    "effects" => "mob_effect",
                    "enchantments" => "enchantment",
                    "particles" => "particle_type",
                    _ => "sound_event",
                };
                if !out.contains_key(key)
                    && let Some(list) = dense_list(entries.iter().filter_map(|entry| {
                        Some((entry.get("id")?.as_i64()?, md_name(file, entry, protocol)?))
                    }))
                {
                    out.insert(key.into(), list);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Before the flattening an item id under 256 *is* a block id, and its damage
/// value is that block's metadata. Some `minecraft-data` releases list damage
/// variants only on the block, so a block item without its own borrows them.
fn borrow_block_variants(registries: &mut BTreeMap<String, Value>) {
    let Some(block_variants) = registries
        .get("block_state")
        .and_then(|states| states.get("variants"))
        .and_then(Value::as_object)
        .cloned()
    else {
        return;
    };
    let Some(item) = registries.get_mut("item") else {
        return;
    };
    let mut variants = item
        .get("variants")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (id, by_meta) in block_variants {
        if id.parse::<u32>().is_ok_and(|id| id < 256) && !variants.contains_key(&id) {
            variants.insert(id, by_meta);
        }
    }
    if !variants.is_empty() {
        item["variants"] = Value::Object(variants);
    }
}

/// Ids at or past this are treated as corrupt rather than allocated for.
const MAX_REGISTRY_ID: i64 = 1 << 20;

fn dense_list(pairs: impl Iterator<Item = (i64, String)>) -> Option<Value> {
    let mut by_id: BTreeMap<i64, String> = BTreeMap::new();
    for (id, name) in pairs {
        if (0..MAX_REGISTRY_ID).contains(&id) {
            // The first name for an id wins; `minecraft-data` repeats a few
            // legacy object ids (the minecart family) under several names.
            by_id.entry(id).or_insert(name);
        }
    }
    let last = *by_id.keys().next_back()?;
    let mut names = vec![Value::Null; usize::try_from(last + 1).ok()?];
    for (id, name) in by_id {
        names[usize::try_from(id).ok()?] = Value::String(name);
    }
    Some(json!({ "kind": "list", "names": names }))
}

/// A `minecraft-data` item or block list, with damage-value variants.
fn legacy_list(entries: &[Value], file: &str, protocol: i32) -> Option<Value> {
    let mut list = dense_list(entries.iter().filter_map(|entry| {
        Some((
            entry.get("id")?.as_i64()?,
            md_name(&format!("{file}s"), entry, protocol)?,
        ))
    }))?;
    let mut variants = Map::new();
    for entry in entries {
        let (Some(id), Some(found)) = (
            entry.get("id").and_then(Value::as_i64),
            entry.get("variations").and_then(Value::as_array),
        ) else {
            continue;
        };
        let mut by_meta = Map::new();
        for variation in found {
            if let (Some(meta), Some(label)) = (
                variation.get("metadata").and_then(Value::as_i64),
                variation.get("displayName").and_then(Value::as_str),
            ) {
                by_meta.insert(meta.to_string(), json!(label));
            }
        }
        if !by_meta.is_empty() {
            variants.insert(id.to_string(), Value::Object(by_meta));
        }
    }
    if !variants.is_empty() {
        list["variants"] = Value::Object(variants);
    }
    Some(list)
}

/// Names a `minecraft-data` entry the way the game spelled it in that release.
///
/// Lower-case names gain the `minecraft:` namespace; legacy capitalised entity
/// names (`PigZombie`, before 1.11) are kept verbatim because that is what the
/// game called them. Effect names are display-cased in `minecraft-data` in
/// every release, so they are converted to the registry's snake case.
fn md_name(file: &str, entry: &Value, _protocol: i32) -> Option<String> {
    let raw = entry.get("name")?.as_str()?;
    if raw.is_empty() {
        return None;
    }
    let raw = if file == "effects" {
        snake_case(raw)
    } else {
        raw.to_owned()
    };
    let lower = raw
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '/'));
    Some(if lower && !raw.contains(':') {
        format!("minecraft:{raw}")
    } else {
        raw
    })
}

fn snake_case(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 4);
    for (index, c) in raw.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Block states from the vanilla blocks report.
fn vanilla_states(root: &Value) -> Result<Value, TableError> {
    let mut blocks: Vec<(i64, Value)> = Vec::new();
    for (name, block) in object(root, "a vanilla blocks report")? {
        let Some(states) = block.get("states").and_then(Value::as_array) else {
            continue;
        };
        let mut ids: Vec<(i64, &Map<String, Value>)> = states
            .iter()
            .filter_map(|state| {
                let id = state.get("id")?.as_i64()?;
                let properties = state
                    .get("properties")
                    .and_then(Value::as_object)
                    .unwrap_or(empty_map());
                Some((id, properties))
            })
            .collect();
        ids.sort_by_key(|(id, _)| *id);
        let Some(first) = ids.first().map(|(id, _)| *id) else {
            continue;
        };
        let grid: Vec<(String, Vec<String>)> = block
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| {
                properties
                    .iter()
                    .map(|(key, values)| {
                        let values = values
                            .as_array()
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(|value| value.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default();
                        (key.clone(), values)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let follows_grid = ids.len() == grid_size(&grid)
            && ids.iter().enumerate().all(|(index, (id, properties))| {
                Some(*id) == offset_id(first, index) && grid_state(&grid, index) == **properties
            });
        let entry = if follows_grid {
            json!([name, first, grid_json(&grid)])
        } else {
            let explicit: Vec<String> = ids
                .iter()
                .map(|(_, properties)| {
                    properties
                        .iter()
                        .map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .collect();
            // Explicit lists are only valid for contiguous ids.
            if ids
                .iter()
                .enumerate()
                .any(|(index, (id, _))| Some(*id) != offset_id(first, index))
            {
                return Err(TableError::Shape(format!(
                    "block {name} has non-contiguous state ids"
                )));
            }
            json!([name, first, null, explicit])
        };
        blocks.push((first, entry));
    }
    blocks.sort_by_key(|(first, _)| *first);
    Ok(json!({
        "kind": "states",
        "blocks": blocks.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>(),
    }))
}

/// Block states from a `minecraft-data` blocks list that carries them (1.13+).
fn minecraft_data_states(entries: &[Value]) -> Option<Value> {
    let mut blocks = Vec::new();
    for entry in entries {
        let name = md_name("blocks", entry, 393)?;
        let first = entry.get("minStateId")?.as_i64()?;
        let grid: Vec<(String, Vec<String>)> = entry
            .get("states")
            .and_then(Value::as_array)
            .map(|states| {
                states
                    .iter()
                    .filter_map(|state| {
                        let key = state.get("name")?.as_str()?.to_owned();
                        let values = match state.get("type").and_then(Value::as_str) {
                            Some("bool") => vec!["true".to_owned(), "false".to_owned()],
                            _ => state
                                .get("values")?
                                .as_array()?
                                .iter()
                                .map(|value| match value {
                                    Value::String(text) => text.clone(),
                                    other => other.to_string(),
                                })
                                .collect(),
                        };
                        Some((key, values))
                    })
                    .collect()
            })
            .unwrap_or_default();
        blocks.push((first, json!([name, first, grid_json(&grid)])));
    }
    blocks.sort_by_key(|(first, _)| *first);
    if blocks.is_empty() {
        return None;
    }
    Some(json!({
        "kind": "states",
        "blocks": blocks.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>(),
    }))
}

fn offset_id(first: i64, index: usize) -> Option<i64> {
    first.checked_add(i64::try_from(index).ok()?)
}

fn grid_size(grid: &[(String, Vec<String>)]) -> usize {
    grid.iter().map(|(_, values)| values.len().max(1)).product()
}

/// The properties of the state at `index` within a block, last property
/// varying fastest.
fn grid_state(grid: &[(String, Vec<String>)], mut index: usize) -> Map<String, Value> {
    let mut picked = vec![0; grid.len()];
    for (slot, (_, values)) in grid.iter().enumerate().rev() {
        let count = values.len().max(1);
        picked[slot] = index % count;
        index /= count;
    }
    grid.iter()
        .zip(picked)
        .map(|((key, values), choice)| {
            (
                key.clone(),
                json!(values.get(choice).cloned().unwrap_or_default()),
            )
        })
        .collect()
}

fn grid_json(grid: &[(String, Vec<String>)]) -> Value {
    Value::Array(
        grid.iter()
            .map(|(key, values)| json!([key, values]))
            .collect(),
    )
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn parse(text: &str, what: &'static str) -> Result<Value, TableError> {
    serde_json::from_str(text).map_err(|error| TableError::Json(what, error))
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, TableError> {
    value
        .as_object()
        .ok_or_else(|| TableError::Shape(format!("{what} is not a JSON object")))
}

/// Names that appear for more than one id within a registry, which would make
/// the bundle ambiguous. `legacy_object` is exempt: the pre-1.14 object table
/// genuinely reuses one name for several minecart ids.
#[must_use]
pub fn duplicate_registry_names(
    protocol: i32,
    registries: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (key, registry) in registries {
        if key == "legacy_object" {
            continue;
        }
        let Some(names) = registry.get("names").and_then(Value::as_array) else {
            continue;
        };
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for (id, name) in names.iter().enumerate() {
            if let Some(name) = name.as_str()
                && let Some(previous) = seen.insert(name, id)
            {
                problems.push(format!(
                    "protocol {protocol} {key}: `{name}` is both {previous} and {id}"
                ));
            }
        }
    }
    problems
}

/// Packs every protocol's registries into the bundle the protocol crate
/// embeds.
///
/// The format mirrors the definition bundle: `MBRN1\n`, one line of JSON
/// mapping each protocol and registry to the byte range of its payload, then
/// the payloads back to back, all one zstd frame. Identical payloads are stored
/// once — most registries change only every few releases — and the range index
/// lets a reader parse just the registry it needs.
pub fn pack_registries(
    protocols: &BTreeMap<i32, BTreeMap<String, Value>>,
) -> Result<Vec<u8>, TableError> {
    let mut body = String::new();
    let mut stored: HashMap<String, (usize, usize)> = HashMap::new();
    let mut index = BTreeMap::new();
    for (protocol, registries) in protocols {
        let mut entry = BTreeMap::new();
        for (key, payload) in registries {
            let text = payload.to_string();
            let range = *stored.entry(text).or_insert_with_key(|text| {
                let start = body.len();
                body.push_str(text);
                (start, text.len())
            });
            entry.insert(key.clone(), [range.0, range.1]);
        }
        index.insert(protocol.to_string(), entry);
    }
    let header = json!({ "protocols": index }).to_string();
    let mut plain = Vec::with_capacity(body.len() + header.len() + 8);
    plain.extend_from_slice(b"MBRN1\n");
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

/// Reads a bundle written by [`pack_registries`] back into its registries.
pub fn unpack_registries(
    bytes: &[u8],
) -> Result<BTreeMap<i32, BTreeMap<String, Value>>, TableError> {
    let shape = |what: &str| TableError::Shape(format!("registry bundle: {what}"));
    let plain = zstd::decode_all(bytes).map_err(TableError::Compress)?;
    let text = String::from_utf8(plain).map_err(|_| shape("not UTF-8"))?;
    let rest = text
        .strip_prefix("MBRN1\n")
        .ok_or_else(|| shape("bad magic"))?;
    let (header, body) = rest.split_once('\n').ok_or_else(|| shape("no header"))?;
    let header = parse(header, "the registry bundle header")?;
    let mut out = BTreeMap::new();
    for (protocol, registries) in header
        .get("protocols")
        .and_then(Value::as_object)
        .ok_or_else(|| shape("no protocols"))?
    {
        let protocol: i32 = protocol.parse().map_err(|_| shape("bad protocol"))?;
        let mut entry = BTreeMap::new();
        for (key, range) in registries.as_object().ok_or_else(|| shape("bad index"))? {
            let start = range
                .get(0)
                .and_then(Value::as_u64)
                .ok_or_else(|| shape("bad range"))?;
            let length = range
                .get(1)
                .and_then(Value::as_u64)
                .ok_or_else(|| shape("bad range"))?;
            let (start, length) = (
                usize::try_from(start).map_err(|_| shape("bad range"))?,
                usize::try_from(length).map_err(|_| shape("bad range"))?,
            );
            let payload = body
                .get(start..start + length)
                .ok_or_else(|| shape("range past the end"))?;
            entry.insert(key.clone(), parse(payload, "a registry payload")?);
        }
        out.insert(protocol, entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRIES: &str = r#"{
      "minecraft:item": { "protocol_id": 7, "entries": {
        "minecraft:air": { "protocol_id": 0 },
        "minecraft:stone": { "protocol_id": 1 },
        "minecraft:diamond_sword": { "protocol_id": 3 }
      } },
      "minecraft:worldgen/feature": { "protocol_id": 9, "entries": { "minecraft:x": { "protocol_id": 0 } } }
    }"#;

    const BLOCKS: &str = r#"{
      "minecraft:air": { "states": [ { "id": 0, "default": true } ] },
      "minecraft:lever": {
        "properties": { "face": ["floor", "wall"], "powered": ["true", "false"] },
        "states": [
          { "id": 5, "properties": { "face": "floor", "powered": "true" } },
          { "id": 6, "properties": { "face": "floor", "powered": "false" } },
          { "id": 7, "properties": { "face": "wall", "powered": "true" } },
          { "id": 8, "properties": { "face": "wall", "powered": "false" } }
        ]
      },
      "minecraft:odd": {
        "properties": { "a": ["x", "y"] },
        "states": [
          { "id": 9, "properties": { "a": "y" } },
          { "id": 10, "properties": { "a": "x" } }
        ]
      }
    }"#;

    #[test]
    fn vanilla_reports_become_dense_lists_and_state_grids() {
        let sources = RegistrySources {
            vanilla_registries: Some(REGISTRIES.into()),
            vanilla_blocks: Some(BLOCKS.into()),
            ..RegistrySources::default()
        };
        let built = build_registries(769, &sources).unwrap();
        assert_eq!(
            built["item"]["names"],
            json!([
                "minecraft:air",
                "minecraft:stone",
                null,
                "minecraft:diamond_sword"
            ])
        );
        assert!(!built.contains_key("worldgen/feature"));
        let blocks = built["block_state"]["blocks"].as_array().unwrap();
        assert_eq!(
            blocks[1],
            json!([
                "minecraft:lever",
                5,
                [["face", ["floor", "wall"]], ["powered", ["true", "false"]]]
            ])
        );
        // A block whose ids do not follow the grid keeps them explicitly.
        assert_eq!(blocks[2], json!(["minecraft:odd", 9, null, ["a=y", "a=x"]]));
    }

    #[test]
    fn legacy_data_keeps_variants_and_splits_objects_from_mobs() {
        let mut sources = RegistrySources::default();
        sources.minecraft_data.insert(
            "items".into(),
            r#"[{"id":1,"name":"stone","variations":[{"metadata":1,"displayName":"Granite"}]},{"id":276,"name":"diamond_sword"}]"#.into(),
        );
        sources.minecraft_data.insert(
            "entities".into(),
            r#"[{"id":50,"name":"Creeper","type":"mob"},{"id":1,"name":"Boat","type":"object"},{"id":10,"name":"MinecartRideable","type":"object"},{"id":11,"name":"MinecartRideable","type":"object"}]"#.into(),
        );
        sources.minecraft_data.insert(
            "effects".into(),
            r#"[{"id":1,"name":"Speed"},{"id":8,"name":"JumpBoost"}]"#.into(),
        );
        let built = build_registries(47, &sources).unwrap();
        assert_eq!(built["item"]["names"][276], "minecraft:diamond_sword");
        assert_eq!(built["item"]["variants"]["1"]["1"], "Granite");
        assert_eq!(built["entity_type"]["names"][50], "Creeper");
        assert_eq!(built["legacy_object"]["names"][1], "Boat");
        assert_eq!(built["mob_effect"]["names"][8], "minecraft:jump_boost");
        assert!(duplicate_registry_names(47, &built).is_empty());
    }

    #[test]
    fn duplicates_are_reported() {
        let mut registries = BTreeMap::new();
        registries.insert(
            "item".to_owned(),
            json!({"kind":"list","names":["minecraft:a","minecraft:a"]}),
        );
        assert_eq!(duplicate_registry_names(1, &registries).len(), 1);
    }

    #[test]
    fn packing_is_deterministic_and_shares_payloads() {
        let sources = RegistrySources {
            vanilla_registries: Some(REGISTRIES.into()),
            ..RegistrySources::default()
        };
        let built = build_registries(1, &sources).unwrap();
        let mut protocols = BTreeMap::new();
        protocols.insert(1, built.clone());
        protocols.insert(2, built);
        let first = pack_registries(&protocols).unwrap();
        assert_eq!(first, pack_registries(&protocols).unwrap());
        let plain = zstd::decode_all(first.as_slice()).unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert_eq!(text.matches("diamond_sword").count(), 1);
        assert_eq!(unpack_registries(&first).unwrap(), protocols);
    }
}
