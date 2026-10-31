import { EMPTY_FILTER, type PacketFilter } from "../domain/types";
export const TRAFFIC_PRESETS = [
  "all",
  "quiet",
  "login",
  "configuration",
  "play",
  "channels",
  "inventory",
  "movement",
  "changed",
  "dropped",
] as const;
export type TrafficPreset = (typeof TRAFFIC_PRESETS)[number];
/** Presets replace packet predicates, while the selected connection stays scoped. */
export function trafficPreset(preset: TrafficPreset): PacketFilter {
  const filter: PacketFilter = { ...EMPTY_FILTER };
  switch (preset) {
    case "quiet":
      filter.expression =
        "!(name ~ keep_alive || name ~ ping || name ~ pong || name == move_entity_pos || name == move_entity_pos_rot || name == move_entity_rot || name == move_vehicle || name == set_player_position || name == set_player_position_and_rotation || name == set_player_rotation || name ~ chunk || name ~ light_update || name ~ update_light)";
      break;
    case "login":
      filter.states = ["handshake", "status", "login"];
      break;
    case "configuration":
      filter.states = ["configuration"];
      break;
    case "play":
      filter.states = ["play"];
      break;
    case "channels":
      filter.expression = 'channel != ""';
      break;
    case "inventory":
      filter.expression = "name ~ container || name ~ inventory || name ~ slot || name ~ carried_item";
      break;
    case "movement":
      filter.expression =
        "name == move_entity_pos || name == move_entity_pos_rot || name == move_entity_rot || name == move_vehicle || name ~ position || name ~ rotation || name ~ movement || name ~ teleport || name ~ velocity";
      break;
    case "changed":
      filter.dispositions = ["edited", "replayed"];
      break;
    case "dropped":
      filter.dispositions = ["dropped"];
      break;
  }
  return filter;
}
