import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PacketTable } from "./PacketTable";

// Mock VirtualRows to keep table test simple - we only test row rendering
vi.mock("./VirtualRows", async () => {
  const actual = await vi.importActual<typeof import("./VirtualRows")>("./VirtualRows");
  return {
    ...actual,
    VirtualRows: ({
      items,
      renderRow,
      header,
    }: {
      items: unknown[];
      renderRow: (i: unknown, idx: number) => React.ReactNode;
      header: React.ReactNode;
    }) => (
      <div role="grid">
        {header}
        {items.map((item, idx) => (
          <div key={(item as { id: number }).id}>{renderRow(item as never, idx)}</div>
        ))}
      </div>
    ),
  };
});

describe("PacketTable", () => {
  it("renders rows and highlights selected", () => {
    const packets = [
      {
        id: 7,
        sequence: 0,
        direction: "client_to_server",
        state: "play",
        name: "chat",
        packet_id: 3,
        size: 42,
        disposition: "forwarded",
      },
      {
        id: 8,
        sequence: 0,
        direction: "server_to_client",
        state: "play",
        name: null,
        packet_id: 10,
        size: 12,
        disposition: "observed",
      },
    ] as never;
    const onSelect = vi.fn();
    render(<PacketTable packets={packets} selectedId={7} onSelect={onSelect} />);
    expect(screen.getByText("chat")).toBeInTheDocument();
    expect(screen.getByText("0xa")).toBeInTheDocument();
  });

  it("numbers rows by their unique id, not the per-connection sequence", () => {
    const packets = [
      { id: 7, sequence: 0, direction: "client_to_server", state: "play", name: "a", packet_id: 1, size: 1 },
      { id: 8, sequence: 0, direction: "client_to_server", state: "play", name: "b", packet_id: 2, size: 1 },
    ] as never;
    render(<PacketTable packets={packets} selectedId={null} onSelect={vi.fn()} />);
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
  });
});
