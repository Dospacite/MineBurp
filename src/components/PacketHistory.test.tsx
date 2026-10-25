import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EMPTY_FILTER, type PacketHistoryQuery, type PacketSummary, type ProjectInfo } from "../domain/types";
import { annotationStore } from "../lib/annotations";
import { desktop } from "../lib/desktop";
import { fetchNewer, PAGE_SIZE, PacketHistory, RETAINED_ROWS } from "./PacketHistory";

function packet(id: number): PacketSummary {
  return {
    id,
    sequence: id,
    connection_id: "c",
    timestamp_micros: id * 1_000,
    source: "minecraft",
    direction: id % 2 ? "client_to_server" : "server_to_client",
    state: "play",
    protocol_version: 767,
    packet_id: 1,
    name: "keep_alive",
    channel: null,
    loader: null,
    size: 9,
    disposition: "forwarded",
    flow: null,
  };
}

/**
 * The store's semantics: both cursors apply; with only `afterId` set the page
 * is the oldest `limit` rows past it, and every page is returned newest first.
 */
function store(rows: () => PacketSummary[]) {
  return async (query: PacketHistoryQuery = {}) => {
    const matching = rows().filter(
      (row) =>
        (query.afterId == null || row.id > query.afterId) &&
        (query.beforeId == null || row.id < query.beforeId),
    );
    const ascending = query.afterId != null && query.beforeId == null;
    const page = matching
      .sort((a, b) => (ascending ? a.id - b.id : b.id - a.id))
      .slice(0, query.limit ?? 251);
    return ascending ? page.reverse() : page;
  };
}

const project: ProjectInfo = {
  path: "/tmp/p.mineburp",
  name: "p",
  encrypted: false,
  schema_version: 1,
  temporary: true,
};

describe("fetchNewer", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("closes the gap when more than a page arrived since the cursor", async () => {
    const rows = Array.from({ length: 1_000 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const result = await fetchNewer({}, 10);
    expect(result?.complete).toBe(true);
    const ids = result?.rows.map((row) => row.id) ?? [];
    expect(ids).toHaveLength(990);
    expect(ids[0]).toBe(1_000);
    expect(ids.at(-1)).toBe(11);
    // Strictly descending with no hole.
    expect(ids.every((id, index) => index === 0 || ids[index - 1] === id + 1)).toBe(true);
  });

  it("reads a single page when it was not full", async () => {
    const rows = Array.from({ length: 20 }, (_, index) => packet(index + 1));
    const spy = vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const result = await fetchNewer({}, 10);
    expect(result?.rows).toHaveLength(10);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("walks forward from the cursor one page at a time", async () => {
    const rows = Array.from({ length: 700 }, (_, index) => packet(index + 1));
    const spy = vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    await fetchNewer({}, 0);
    const cursors = spy.mock.calls.map(([query]) => query?.afterId);
    expect(cursors).toEqual([0, PAGE_SIZE, 2 * PAGE_SIZE]);
  });

  it("stops past what the history keeps and reports it incomplete", async () => {
    const rows = Array.from({ length: RETAINED_ROWS + 600 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const result = await fetchNewer({}, 0);
    expect(result?.complete).toBe(false);
    expect(result?.rows.length).toBeGreaterThanOrEqual(RETAINED_ROWS);
  });

  it("abandons a read the caller no longer wants", async () => {
    const rows = Array.from({ length: 2 * PAGE_SIZE }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    expect(await fetchNewer({}, 0, () => false)).toBeNull();
  });
});

describe("PacketHistory live tail", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    annotationStore.reset();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "packetAnnotationsGet").mockResolvedValue([]);
  });

  it("loads every packet of a burst larger than one page", async () => {
    let rows = Array.from({ length: 10 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const props = {
      project,
      connectionId: null,
      filter: { ...EMPTY_FILTER },
      onFilterChange: vi.fn(),
      selectedId: null,
      onSelect: vi.fn(),
      onError: vi.fn(),
    };
    const { rerender } = render(<PacketHistory {...props} appendSignal={0} />);
    expect(await screen.findByText("10 loaded", {}, { timeout: 2_000 })).toBeInTheDocument();

    rows = Array.from({ length: 610 }, (_, index) => packet(index + 1));
    rerender(<PacketHistory {...props} appendSignal={1} />);
    await waitFor(() => expect(screen.getByText("610 loaded")).toBeInTheDocument(), { timeout: 3_000 });
    expect(props.onError).not.toHaveBeenCalled();
  });
});
