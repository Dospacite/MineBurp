import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EMPTY_FILTER, type PacketHistoryQuery, type PacketSummary, type ProjectInfo } from "../domain/types";
import { annotationStore } from "../lib/annotations";
import { desktop } from "../lib/desktop";
import {
  AROUND_ROWS,
  fetchAround,
  fetchNewer,
  PAGE_SIZE,
  PacketHistory,
  RETAINED_ROWS,
} from "./PacketHistory";

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
 * `oldestFirst` orders the whole result ascending and returns it that way.
 */
function store(rows: () => PacketSummary[]) {
  return async (query: PacketHistoryQuery = {}) => {
    const matching = rows().filter(
      (row) =>
        (query.afterId == null || row.id > query.afterId) &&
        (query.beforeId == null || row.id < query.beforeId),
    );
    const ascending = query.oldestFirst || (query.afterId != null && query.beforeId == null);
    const page = matching
      .sort((a, b) => (ascending ? a.id - b.id : b.id - a.id))
      .slice(0, query.limit ?? 251);
    return ascending && !query.oldestFirst ? page.reverse() : page;
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

describe("PacketHistory order", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    annotationStore.reset();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "packetAnnotationsGet").mockResolvedValue([]);
  });

  const props = {
    project,
    connectionId: null,
    filter: { ...EMPTY_FILTER },
    onFilterChange: vi.fn(),
    selectedId: null,
    onSelect: vi.fn(),
    onError: vi.fn(),
    appendSignal: 0,
  };
  const firstRowNumber = () =>
    within(screen.getAllByRole("row")[1] as HTMLElement).getAllByRole("gridcell")[0];

  it("re-reads the whole history in the new order instead of sorting the loaded rows", async () => {
    const rows = Array.from({ length: 600 }, (_, index) => packet(index + 1));
    const spy = vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    render(<PacketHistory {...props} />);
    await waitFor(() => expect(firstRowNumber()).toHaveTextContent("600"), { timeout: 2_000 });

    fireEvent.click(screen.getByRole("button", { name: /#/ }));
    // Packet 1 was never loaded newest first; it can only come from the database.
    await waitFor(() => expect(firstRowNumber()).toHaveTextContent(/^1$/), { timeout: 2_000 });
    const reread = spy.mock.lastCall?.[0];
    expect(reread?.oldestFirst).toBe(true);
    expect(reread?.afterId ?? null).toBeNull();
    expect(reread?.beforeId ?? null).toBeNull();
    expect(screen.getByRole("columnheader", { name: /#/ })).toHaveAttribute("aria-sort", "ascending");

    fireEvent.click(screen.getByRole("button", { name: "Load newer packets" }));
    await waitFor(() => expect(screen.getByText(`${2 * PAGE_SIZE} loaded`)).toBeInTheDocument());
    expect(spy).toHaveBeenLastCalledWith(
      expect.objectContaining({ oldestFirst: true, afterId: PAGE_SIZE, beforeId: null }),
    );
  });

  it("appends new traffic after the last row once the end is loaded", async () => {
    localStorage.setItem("mineburp.table", JSON.stringify({ oldestFirst: true }));
    let rows = Array.from({ length: 10 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const { rerender } = render(<PacketHistory {...props} />);
    expect(await screen.findByText("10 loaded", {}, { timeout: 2_000 })).toBeInTheDocument();
    expect(firstRowNumber()).toHaveTextContent(/^1$/);

    rows = Array.from({ length: 15 }, (_, index) => packet(index + 1));
    rerender(<PacketHistory {...props} appendSignal={1} />);
    await waitFor(() => expect(screen.getByText("15 loaded")).toBeInTheDocument(), { timeout: 3_000 });
    expect(firstRowNumber()).toHaveTextContent(/^1$/);
    expect(props.onError).not.toHaveBeenCalled();
  });
});

/** Like `store`, but honours the direction filter, so a filter change can drop rows. */
function filteredStore(rows: () => PacketSummary[]) {
  return (query: PacketHistoryQuery = {}) =>
    store(() =>
      rows().filter((row) => !query.directions?.length || query.directions.includes(row.direction)),
    )(query);
}

describe("fetchAround", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("reads the rows on both sides of a packet, newest first", async () => {
    const rows = Array.from({ length: 600 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const around = await fetchAround({}, 300);
    expect(around?.rows[0]?.id).toBe(300 + AROUND_ROWS);
    expect(around?.rows.at(-1)?.id).toBe(300 - AROUND_ROWS);
    expect(around?.rows).toHaveLength(2 * AROUND_ROWS + 1);
    expect(around?.olderMore).toBe(true);
    expect(around?.newerMore).toBe(true);
  });

  it("returns rows oldest first when the history runs that way", async () => {
    const rows = Array.from({ length: 20 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const around = await fetchAround({ oldestFirst: true }, 10);
    expect(around?.rows.map((row) => row.id)).toEqual(rows.map((row) => row.id));
    expect(around?.olderMore).toBe(false);
    expect(around?.newerMore).toBe(false);
  });

  it("reports a packet the query does not match", async () => {
    const rows = Array.from({ length: 20 }, (_, index) => packet(index + 1));
    vi.spyOn(desktop, "packets").mockImplementation(filteredStore(() => rows));
    expect(await fetchAround({ directions: ["client_to_server"] }, 10)).toBeNull();
  });
});

describe("PacketHistory selection", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    annotationStore.reset();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "packetAnnotationsGet").mockResolvedValue([]);
  });

  const rows = Array.from({ length: 600 }, (_, index) => packet(index + 1));
  const props = {
    project,
    connectionId: null,
    filter: { ...EMPTY_FILTER },
    onFilterChange: vi.fn(),
    onError: vi.fn(),
    appendSignal: 0,
  };
  const selectedRow = () => screen.queryByRole("row", { selected: true });

  it("keeps a selected packet loaded and highlighted when the filter changes", async () => {
    vi.spyOn(desktop, "packets").mockImplementation(filteredStore(() => rows));
    const { rerender } = render(<PacketHistory {...props} selectedId={null} onSelect={vi.fn()} />);
    await screen.findByText("250 loaded", {}, { timeout: 2_000 });
    // Packet 51 is below the newest filtered page (599 down to 101), and passes the filter.
    rerender(
      <PacketHistory
        {...props}
        filter={{ ...EMPTY_FILTER, directions: ["client_to_server"] }}
        selectedId={51}
        onSelect={vi.fn()}
      />,
    );
    // Odd ids only: the 26 at or below 51, and the 125 above it.
    await screen.findByText("151 loaded", {}, { timeout: 2_000 });
    // The reveal set the scroll position; jsdom does not fire the event itself.
    fireEvent.scroll(document.querySelector(".virtual-viewport") as HTMLElement);
    await waitFor(() => expect(selectedRow()).not.toBeNull());
    expect(within(selectedRow() as HTMLElement).getAllByRole("gridcell")[0]).toHaveTextContent(/^51$/);
    expect(props.onError).not.toHaveBeenCalled();
  });

  it("goes to a packet number from the row menu", async () => {
    vi.spyOn(desktop, "packets").mockImplementation(store(() => rows));
    const onSelect = vi.fn();
    const { rerender } = render(<PacketHistory {...props} selectedId={null} onSelect={onSelect} />);
    await screen.findByText("250 loaded", {}, { timeout: 2_000 });

    fireEvent.contextMenu(screen.getAllByRole("row")[1] as HTMLElement);
    fireEvent.click(screen.getByRole("menuitem", { name: /Go to packet/ }));
    fireEvent.change(screen.getByLabelText("Packet number"), { target: { value: "#42" } });
    fireEvent.click(screen.getByRole("button", { name: "Go" }));

    await waitFor(() => expect(onSelect).toHaveBeenLastCalledWith(42), { timeout: 2_000 });
    rerender(<PacketHistory {...props} selectedId={42} onSelect={onSelect} />);
    // 42 and the 41 below it, and the 125 above.
    expect(screen.getByText("167 loaded")).toBeInTheDocument();
    fireEvent.scroll(document.querySelector(".virtual-viewport") as HTMLElement);
    await waitFor(() =>
      expect(within(selectedRow() as HTMLElement).getAllByRole("gridcell")[0]).toHaveTextContent(/^42$/),
    );
    expect(screen.getByRole("button", { name: "jump to newest" })).toBeInTheDocument();
  });
});
