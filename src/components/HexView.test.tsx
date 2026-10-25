import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { ByteWindow } from "../domain/types";
import { findAll, HEX_PAGE_BYTES, HexView, parseOffset } from "./HexView";

function windowOf(offset: number, fill: number): ByteWindow {
  const bytes = new Uint8Array(HEX_PAGE_BYTES).fill(fill);
  return { offset, total: HEX_PAGE_BYTES * 3, base64: btoa(String.fromCharCode(...bytes)) };
}

function firstByte(container: HTMLElement): string | null {
  return container.querySelector(".hex-bytes span")?.textContent ?? null;
}

describe("HexView", () => {
  it("pages forward", async () => {
    const loadWindow = vi.fn(async (offset: number) => windowOf(offset, 0xbb));
    const user = userEvent.setup();
    const { container } = render(
      <HexView
        sourceKey={1}
        total={HEX_PAGE_BYTES * 3}
        initial={{ offset: 0, bytes: new Uint8Array(HEX_PAGE_BYTES).fill(0xaa) }}
        loadWindow={loadWindow}
      />,
    );
    expect(firstByte(container)).toBe("aa");
    await user.click(screen.getByRole("button", { name: "Next byte range" }));
    expect(loadWindow).toHaveBeenCalledWith(HEX_PAGE_BYTES, HEX_PAGE_BYTES);
    expect(firstByte(container)).toBe("bb");
    expect(container.querySelector(".hex-address")?.textContent).toBe("001000");
  });

  it("ignores a page that resolves after the payload changed", async () => {
    let resolve: (window: ByteWindow) => void = () => undefined;
    const loadWindow = vi.fn(
      () =>
        new Promise<ByteWindow>((done) => {
          resolve = done;
        }),
    );
    const user = userEvent.setup();
    const { container, rerender } = render(
      <HexView
        sourceKey={1}
        total={HEX_PAGE_BYTES * 3}
        initial={{ offset: 0, bytes: new Uint8Array(16).fill(0xaa) }}
        loadWindow={loadWindow}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Next byte range" }));
    rerender(
      <HexView
        sourceKey={2}
        total={HEX_PAGE_BYTES * 3}
        initial={{ offset: 0, bytes: new Uint8Array(16).fill(0xcc) }}
        loadWindow={loadWindow}
      />,
    );
    expect(firstByte(container)).toBe("cc");
    await act(async () => resolve(windowOf(HEX_PAGE_BYTES, 0xbb)));
    // The stale page for packet 1 must not land under packet 2.
    expect(firstByte(container)).toBe("cc");
    expect(container.querySelector(".hex-address")?.textContent).toBe("000000");
  });

  it("reports the selected range and marks a highlight", async () => {
    const onSelectionChange = vi.fn();
    const user = userEvent.setup();
    const { container } = render(
      <HexView
        sourceKey={1}
        total={4}
        initial={{ offset: 0, bytes: new Uint8Array([1, 2, 3, 4]) }}
        loadWindow={vi.fn()}
        highlight={{ offset: 1, length: 2 }}
        onSelectionChange={onSelectionChange}
      />,
    );
    expect(container.querySelectorAll(".hex-bytes .hl")).toHaveLength(2);
    const bytes = container.querySelectorAll<HTMLElement>(".hex-bytes span");
    await user.pointer([{ keys: "[MouseLeft>]", target: bytes[0] as HTMLElement }, { keys: "[/MouseLeft]" }]);
    await user.keyboard("{Shift>}{ArrowRight}{ArrowRight}{/Shift}");
    expect(onSelectionChange).toHaveBeenLastCalledWith({ offset: 0, length: 3 });
    expect(screen.getByText(/0x0–0x2 · 3 bytes/)).toBeInTheDocument();
  });
});

describe("findAll", () => {
  it("finds overlapping and repeated matches", () => {
    expect(findAll(new Uint8Array([1, 1, 1, 2, 1, 1]), new Uint8Array([1, 1]))).toEqual([0, 1, 4]);
    expect(findAll(new Uint8Array([1, 2, 3]), new Uint8Array([4]))).toEqual([]);
  });
});

describe("parseOffset", () => {
  it("reads hex and decimal", () => {
    expect(parseOffset("0x1a")).toBe(26);
    expect(parseOffset("1ah")).toBe(26);
    expect(parseOffset("26")).toBe(26);
    expect(parseOffset("zz")).toBeNull();
  });
});
