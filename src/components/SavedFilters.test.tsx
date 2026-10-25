import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EMPTY_FILTER, type PacketFilter, type SavedFilter } from "../domain/types";
import { desktop } from "../lib/desktop";
import { fromSavedPayload, toSavedPayload } from "../lib/savedFilters";
import { SavedFilters } from "./SavedFilters";

const busy: PacketFilter = {
  ...EMPTY_FILTER,
  search: "brand",
  searchRegex: true,
  directions: ["client_to_server"],
  states: ["play", "configuration"],
  dispositions: ["edited"],
  includeNames: ["chat", "custom_payload"],
  excludeNames: ["keep_alive"],
  minSize: 16,
  maxSize: 4_096,
  expression: "size > 64",
  content: "0a 00\n0c-0f",
  contentMode: "hex",
  contentScope: "prefix",
  contentNegate: true,
  bookmarked: true,
};

describe("saved filter payloads", () => {
  it("round-trip every control", () => {
    expect(fromSavedPayload(toSavedPayload(busy))).toEqual(busy);
    expect(fromSavedPayload(toSavedPayload(EMPTY_FILTER))).toEqual(EMPTY_FILTER);
  });

  it("leave out where the operator is", () => {
    const payload = toSavedPayload(busy);
    for (const key of ["connectionId", "offset", "limit", "beforeId", "afterId"]) {
      expect(payload).not.toHaveProperty(key);
    }
  });

  it("never stores an unset bookmark filter as 'only unbookmarked'", () => {
    expect(toSavedPayload(EMPTY_FILTER).bookmarked).toBeNull();
  });

  it("fall back to no filter for unreadable fields", () => {
    expect(fromSavedPayload({ states: "play", minSize: -1, contentMode: "base64" })).toEqual(EMPTY_FILTER);
  });
});

describe("SavedFilters", () => {
  let stored: SavedFilter[];

  beforeEach(() => {
    vi.restoreAllMocks();
    stored = [];
    vi.spyOn(desktop, "savedFilters").mockImplementation(async () => stored);
    vi.spyOn(desktop, "savedFilterSave").mockImplementation(async ({ id, name, filter }) => {
      const entry: SavedFilter = {
        id: id ?? `id-${stored.length + 1}`,
        name,
        filter,
        createdAtMicros: 1,
        updatedAtMicros: 1,
      };
      stored = [...stored.filter((item) => item.id !== entry.id), entry];
      return entry;
    });
  });

  it("saves the current filter and applies it again", async () => {
    const onApply = vi.fn();
    render(<SavedFilters filter={busy} onApply={onApply} onError={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: /saved/i }));
    fireEvent.click(await screen.findByRole("menuitem", { name: /save the current filter/i }));
    fireEvent.change(screen.getByPlaceholderText(/chat from the client/i), {
      target: { value: "client chat" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(desktop.savedFilterSave).toHaveBeenCalledTimes(1));
    expect(desktop.savedFilterSave).toHaveBeenCalledWith({
      id: null,
      name: "client chat",
      filter: toSavedPayload(busy),
    });

    fireEvent.click(screen.getByRole("button", { name: /saved/i }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "client chat" }));
    expect(onApply).toHaveBeenCalledWith(busy);
  });
});
