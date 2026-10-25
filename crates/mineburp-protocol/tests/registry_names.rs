//! Registry names reach the decoded fields of real packet bodies.

use mineburp_core::{Direction, ProtocolState};
use mineburp_protocol::{PacketRegistry, encode_var_i32, encode_var_i64, inspect_packet};
use serde_json::Value;

fn var(value: i32) -> Vec<u8> {
    encode_var_i32(value).to_vec()
}

fn fields(protocol: i32, name: &str, body: &[u8]) -> Value {
    let direction = Direction::ServerToClient;
    let id = PacketRegistry::packet_id(ProtocolState::Play, direction, name, Some(protocol))
        .unwrap_or_else(|| panic!("{name} has no id in {protocol}"));
    let insight = inspect_packet(ProtocolState::Play, direction, id, body, Some(protocol));
    assert_eq!(insight.name.as_deref(), Some(name));
    insight.fields.expect("decoded fields")
}

fn position() -> [u8; 8] {
    0_i64.to_be_bytes()
}

#[test]
fn spawned_entities_are_named_by_release() {
    // 1.21.4: one entity-type registry.
    let mut body = var(5);
    body.extend([0; 16]);
    body.extend(var(10));
    body.extend([0; 24]);
    body.extend([0, 0, 0]);
    body.extend(var(0));
    body.extend([0; 6]);
    let spawned = fields(769, "add_entity", &body);
    assert_eq!(spawned["type"], 10);
    assert_eq!(spawned["type_name"], "minecraft:bat");

    // 1.8: objects and mobs are numbered from separate tables.
    let mut boat = var(1);
    boat.push(1);
    boat.extend([0; 14]);
    boat.extend(0_i32.to_be_bytes());
    assert_eq!(fields(47, "add_entity", &boat)["type_name"], "Boat");
    let mut creeper = var(1);
    creeper.push(50);
    creeper.extend([0; 15]);
    creeper.extend([0; 6]);
    creeper.push(0x7f);
    assert_eq!(
        fields(47, "spawn_entity_living", &creeper)["type_name"],
        "Creeper"
    );
}

#[test]
fn items_are_named_in_every_slot_format() {
    // 1.21.4: count, id, then component counts.
    let mut body = var(0);
    body.extend(var(1));
    body.extend(5_i16.to_be_bytes());
    body.extend(var(1));
    body.extend(var(869));
    body.extend(var(0));
    body.extend(var(0));
    let slot = fields(769, "container_set_slot", &body);
    assert_eq!(slot["item"]["item_id_name"], "minecraft:diamond_sword");

    // 1.20.4: presence, id, count, NBT.
    let mut body = var(0);
    body.extend(var(1));
    body.extend(5_i16.to_be_bytes());
    body.push(1);
    body.extend(var(834));
    body.push(1);
    body.push(0);
    let slot = fields(765, "container_set_slot", &body);
    assert_eq!(slot["item"]["item_id_name"], "minecraft:diamond_sword");

    // 1.8 and 1.12.2: a short id (spelled `blockId`) and a damage value. In
    // 1.12.2 the variant is borrowed from the block of the same id.
    for (protocol, id, name, variant) in [
        (47, 1, "minecraft:stone", "Granite"),
        (340, 3, "minecraft:dirt", "Coarse Dirt"),
    ] {
        let mut body = vec![0];
        body.extend(5_i16.to_be_bytes());
        body.extend(i16::try_from(id).unwrap().to_be_bytes());
        body.push(1);
        body.extend(1_i16.to_be_bytes());
        body.push(0);
        let slot = fields(protocol, "container_set_slot", &body);
        assert_eq!(slot["item"]["block_id_name"], name, "{protocol}");
        assert_eq!(slot["item"]["block_id_variant"], variant, "{protocol}");
    }
}

#[test]
fn block_states_carry_their_properties() {
    let mut body = position().to_vec();
    body.extend(var(2929));
    let update = fields(769, "block_update", &body);
    assert_eq!(
        update["type_name"],
        "minecraft:oak_stairs[facing=north,half=top,shape=straight,waterlogged=true]"
    );

    let mut legacy = position().to_vec();
    legacy.extend(var((1 << 4) | 1));
    let update = fields(47, "block_update", &legacy);
    assert_eq!(update["type_name"], "minecraft:stone");
    assert_eq!(update["type_variant"], "Granite");

    let mut section = position().to_vec();
    section.extend(var(1));
    section.extend(encode_var_i64((1 << 12) | 5).to_vec());
    let records = fields(769, "section_blocks_update", &section);
    assert_eq!(records["records_names"][0], "minecraft:stone");
}

#[test]
fn metadata_sounds_effects_particles_and_statistics() {
    let mut metadata = var(3);
    metadata.extend([8]);
    metadata.extend(var(14));
    metadata.extend(var(1));
    metadata.push(0xff);
    let entity = fields(769, "set_entity_data", &metadata);
    assert_eq!(entity["metadata"][0]["value_name"], "minecraft:stone");

    // 1.12.2 numbers its metadata types; 12 is an optional block state.
    let mut metadata = var(3);
    metadata.extend([8, 12]);
    metadata.extend(var(1 << 4));
    metadata.push(0xff);
    let entity = fields(340, "set_entity_data", &metadata);
    assert_eq!(entity["metadata"][0]["value_name"], "minecraft:stone");

    // A sound holder: id 4 is sent as 5.
    let mut sound = var(5);
    sound.extend(var(0));
    sound.extend([0; 12]);
    sound.extend(1_f32.to_be_bytes());
    sound.extend(1_f32.to_be_bytes());
    sound.extend(0_i64.to_be_bytes());
    let sound = fields(769, "sound_effect", &sound);
    assert_eq!(sound["sound"]["sound_id"], 4);
    assert!(
        sound["sound"]["sound_id_name"]
            .as_str()
            .unwrap()
            .starts_with("minecraft:")
    );

    let mut effect = var(1);
    effect.extend(var(0));
    effect.extend(var(0));
    effect.extend(var(100));
    effect.push(0);
    assert_eq!(
        fields(769, "entity_effect", &effect)["effect_id_name"],
        "minecraft:speed"
    );

    let mut particles = var(1);
    particles.push(0);
    particles.extend([0; 40]);
    particles.extend(1_i32.to_be_bytes());
    let particles = fields(765, "level_particles", &particles);
    assert!(
        particles["particle_id_name"]
            .as_str()
            .unwrap()
            .starts_with("minecraft:")
    );

    let mut stats = var(1);
    stats.extend(var(0));
    stats.extend(var(1));
    stats.extend(var(3));
    let stats = fields(769, "award_stats", &stats);
    assert_eq!(stats["entries"][0]["category_id_name"], "minecraft:mined");
    assert_eq!(stats["entries"][0]["statistic_id_name"], "minecraft:stone");
}
