import { afterEach, describe, expect, it, vi } from "vitest";

import {
  base64ToBytes,
  desktop,
  formatCArray,
  formatHex,
  formatHexInput,
  formatRawHex,
  HexParseError,
  parseHex,
  readPayload,
  subscription,
  tryParseHex,
} from "./desktop";

describe("base64ToBytes", () => {
  it("round-trips bytes through base64", () => {
    const original = new Uint8Array([0, 1, 255, 128, 42]);
    const b64 = btoa(String.fromCharCode(...original));
    expect(base64ToBytes(b64)).toEqual(original);
  });

  it("handles empty input", () => {
    expect(base64ToBytes(btoa(""))).toEqual(new Uint8Array([]));
  });
});

describe("parseHex", () => {
  it("parses space separated hex", () => {
    expect(parseHex("00 0f 6d")).toEqual(new Uint8Array([0x00, 0x0f, 0x6d]));
  });

  it("handles 0x prefixes and mixed case", () => {
    expect(parseHex("0x0A 0xFF, 0b")).toEqual(new Uint8Array([0x0a, 0xff, 0x0b]));
  });

  it("throws on odd nibble", () => {
    expect(() => parseHex("0a 0")).toThrow();
  });

  it("handles newlines and varied separators", () => {
    expect(parseHex("00\n0f\t6d\r\n01")).toEqual(new Uint8Array([0, 0x0f, 0x6d, 0x01]));
  });

  it("rejects characters that are not hex instead of dropping them", () => {
    expect(() => parseHex("41 gg 42")).toThrow(HexParseError);
    expect(() => parseHex("41 gg 42")).toThrow("“g” in “gg” is not a hex digit.");
    expect(tryParseHex("41 zz").error).toMatch(/not a hex digit/);
  });

  it("strips 0x only at the start of a token", () => {
    expect(parseHex("10 0x20")).toEqual(new Uint8Array([0x10, 0x20]));
    // `0x` in the middle of a run is not a prefix: the `x` is an error.
    expect(() => parseHex("100x20")).toThrow(HexParseError);
  });

  it("accepts C escapes and colon or semicolon separators", () => {
    expect(parseHex("\\x41\\x42")).toEqual(new Uint8Array([0x41, 0x42]));
    expect(parseHex("de:ad;be:ef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("returns no bytes for empty input", () => {
    expect(parseHex("   ")).toEqual(new Uint8Array());
  });
});

describe("formatCArray", () => {
  it("emits a sized C literal", () => {
    expect(formatCArray(new Uint8Array([1, 255]), "x")).toBe(
      "const unsigned char x[2] = {\n  0x01, 0xff\n};",
    );
  });
});

describe("readPayload", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reads past the backend window in chunks", async () => {
    const total = 600 * 1024;
    const spy = vi.spyOn(desktop, "packetBytes").mockImplementation(async (_id, offset, limit) => {
      const size = Math.min(limit, 256 * 1024, total - offset);
      const chunk = new Uint8Array(size).fill(offset / 1024);
      let binary = "";
      for (const byte of chunk) binary += String.fromCharCode(byte);
      return { offset, total, base64: btoa(binary) };
    });
    const result = await readPayload(1);
    expect(result.complete).toBe(true);
    expect(result.bytes).toHaveLength(total);
    expect(spy).toHaveBeenCalledTimes(3);
  });

  it("stops at a limit and says the result is partial", async () => {
    vi.spyOn(desktop, "packetBytes").mockResolvedValue({ offset: 0, total: 10, base64: btoa("abcd") });
    const result = await readPayload(1, 4);
    expect(result).toMatchObject({ total: 10, complete: false });
    expect(result.bytes).toHaveLength(4);
  });
});

describe("subscription", () => {
  it("unlistens a listener that resolves after cleanup", async () => {
    const unlisten = vi.fn();
    let resolve: (fn: () => void) => void = () => undefined;
    const stop = subscription(
      new Promise((done) => {
        resolve = done;
      }),
    );
    stop();
    resolve(unlisten);
    await Promise.resolve();
    await Promise.resolve();
    expect(unlisten).toHaveBeenCalledTimes(1);
  });
});

describe("formatHex", () => {
  it("formats with address and ascii", () => {
    const out = formatHex(new Uint8Array([0x48, 0x69]), 16, 0);
    expect(out).toContain("000000");
    expect(out).toContain("48 69");
    expect(out).toContain("Hi");
  });

  it("respects startOffset", () => {
    const out = formatHex(new Uint8Array([0xff]), 16, 0x10);
    expect(out.startsWith("000010")).toBe(true);
  });

  it("handles non-printable as dot", () => {
    const out = formatHex(new Uint8Array([0x00, 0x1f, 0x7f]), 16, 0);
    expect(out).toContain("...");
  });
});

describe("formatRawHex", () => {
  it("joins with single space without addresses", () => {
    expect(formatRawHex(new Uint8Array([0x0a, 0xff]))).toBe("0a ff");
  });
});

describe("formatHexInput", () => {
  it("wraps at column boundary", () => {
    const bytes = new Uint8Array(20).fill(0xab);
    const out = formatHexInput(bytes, 16);
    const lines = out.split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]!.split(" ")).toHaveLength(16);
  });
});
