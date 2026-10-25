import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EMPTY_FILTER, type ProjectInfo, type TrafficStats } from "../domain/types";
import { desktop } from "../lib/desktop";
import { STATS_OPTIONS, StatsView } from "./StatsView";

const project: ProjectInfo = {
  path: "/tmp/p.mineburp",
  name: "p",
  encrypted: false,
  schema_version: 5,
  temporary: true,
};

const fixture: TrafficStats = {
  totalPackets: 1_500,
  totalBytes: 90_000,
  clientToServerPackets: 600,
  clientToServerBytes: 20_000,
  serverToClientPackets: 900,
  serverToClientBytes: 70_000,
  firstTimestampMicros: 1_000_000,
  lastTimestampMicros: 61_000_000,
  bucketMicros: 30_000_000,
  buckets: [
    {
      startMicros: 1_000_000,
      clientToServerPackets: 400,
      clientToServerBytes: 12_000,
      serverToClientPackets: 500,
      serverToClientBytes: 40_000,
    },
    {
      startMicros: 31_000_000,
      clientToServerPackets: 200,
      clientToServerBytes: 8_000,
      serverToClientPackets: 400,
      serverToClientBytes: 30_000,
    },
  ],
  topByCount: [
    { name: "keep_alive", packets: 700, bytes: 6_300 },
    { name: null, packets: 20, bytes: 400 },
  ],
  topByBytes: [{ name: "level_chunk_with_light", packets: 40, bytes: 60_000 }],
  topConnections: [{ connectionId: "11111111-2222-3333-4444-555555555555", packets: 1_500, bytes: 90_000 }],
  sizeHistogram: [
    { min: 0, max: 63, packets: 1_200 },
    { min: 64, max: null, packets: 300 },
  ],
};

describe("StatsView", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "trafficStats").mockResolvedValue(fixture);
  });

  function view(overrides: Partial<Parameters<typeof StatsView>[0]> = {}) {
    const props = {
      project,
      filter: { ...EMPTY_FILTER, states: ["play" as const] },
      connectionId: null,
      connections: [
        {
          id: "11111111-2222-3333-4444-555555555555",
          target: { host: "play.example.net", port: 25565 },
          listener_address: "",
          status: "active" as const,
          state: "play" as const,
          protocol_version: 767,
          minecraft_version: "1.21.1",
          loader: null,
          compression_threshold: 256,
          encrypted_client: true,
          encrypted_server: true,
          packet_count: 1_500,
          byte_count: 90_000,
          last_error: null,
        },
      ],
      appendSignal: 0,
      onApplyName: vi.fn(),
      onApplyConnection: vi.fn(),
      onError: vi.fn(),
      ...overrides,
    };
    render(<StatsView {...props} />);
    return props;
  }

  it("renders totals, rankings, and the histogram for the current filter", async () => {
    const props = view();
    expect(await screen.findByText("1,500")).toBeInTheDocument();
    expect(desktop.trafficStats).toHaveBeenCalledWith(
      expect.objectContaining({ states: ["play"], connectionId: null }),
      STATS_OPTIONS,
    );
    expect(screen.getByText("600")).toBeInTheDocument();
    expect(screen.getByText("900")).toBeInTheDocument();
    expect(screen.getByText("keep_alive")).toBeInTheDocument();
    expect(screen.getByText("level_chunk_with_light")).toBeInTheDocument();
    expect(screen.getByText("play.example.net:25565")).toBeInTheDocument();
    expect(screen.getByText("≥ 64 B")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /2 buckets/ })).toBeInTheDocument();
    expect(props.onError).not.toHaveBeenCalled();
  });

  it("applies a name or a connection when one is chosen", async () => {
    const props = view();
    fireEvent.click(await screen.findByTitle("Show only keep_alive in Traffic"));
    expect(props.onApplyName).toHaveBeenCalledWith("keep_alive");
    fireEvent.click(screen.getByTitle("Show only this connection in Traffic"));
    expect(props.onApplyConnection).toHaveBeenCalledWith("11111111-2222-3333-4444-555555555555");
    // An unnamed row cannot become a name filter.
    expect(screen.getByText("(unnamed)").closest("button")).toBeNull();
  });

  it("says so when nothing matches", async () => {
    vi.spyOn(desktop, "trafficStats").mockResolvedValue({
      ...fixture,
      totalPackets: 0,
      buckets: [],
      topByCount: [],
      topByBytes: [],
      topConnections: [],
      sizeHistogram: [],
    });
    view();
    expect(await screen.findByText("No packets match the current filter.")).toBeInTheDocument();
  });
});
