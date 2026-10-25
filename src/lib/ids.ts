/**
 * A random RFC 4122 version-4 UUID.
 *
 * Tabs and rules are sent to the backend as `Uuid`, which rejects anything
 * else. The old fallback — a timestamp and some hex — failed to deserialise,
 * so this one builds a real v4 UUID from whatever randomness is available.
 */
export function newId(): string {
  try {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  } catch {
    // Not a secure context; fall through.
  }
  const bytes = new Uint8Array(16);
  try {
    crypto.getRandomValues(bytes);
  } catch {
    for (let index = 0; index < bytes.length; index++) bytes[index] = Math.floor(Math.random() * 256);
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
