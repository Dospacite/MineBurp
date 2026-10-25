import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TrafficStats } from "../domain/types";
import { backendErrorText } from "../hooks/useMineBurp";
import { desktop } from "../lib/desktop";
import { DeleteHistoryDialog } from "./DeleteHistoryDialog";
import { importResultRows, parsePorts, parseProtocol } from "./ImportCaptureDialog";

function stats(totalPackets: number, totalBytes: number): TrafficStats {
  return {
    totalPackets,
    totalBytes,
    clientToServerPackets: 0,
    clientToServerBytes: 0,
    serverToClientPackets: 0,
    serverToClientBytes: 0,
    firstTimestampMicros: null,
    lastTimestampMicros: null,
    bucketMicros: 0,
    buckets: [],
    topByCount: [],
    topByBytes: [],
    topConnections: [],
    sizeHistogram: [],
  };
}

describe("DeleteHistoryDialog", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "trafficStats").mockResolvedValue(stats(42, 2_048));
    vi.spyOn(desktop, "packetsDelete").mockResolvedValue({ packets: 42, connections: 1 });
  });

  const query = { states: ["play" as const], connectionId: "c-1" };

  it("shows what will go and deletes exactly that", async () => {
    const onDeleted = vi.fn();
    const onClose = vi.fn();
    render(
      <DeleteHistoryDialog
        query={query}
        scope="play · host:25565"
        narrowed
        onDeleted={onDeleted}
        onClose={onClose}
        onError={vi.fn()}
      />,
    );
    expect(await screen.findByText(/42 packets \(2\.0 KiB\) will be removed/)).toBeInTheDocument();
    expect(screen.getByText("Packets matching: play · host:25565")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();

    fireEvent.click(screen.getByRole("checkbox", { name: /connections left without packets/i }));
    fireEvent.click(screen.getByRole("button", { name: "Delete 42 packets" }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalledWith({ packets: 42, connections: 1 }));
    expect(desktop.packetsDelete).toHaveBeenCalledWith(query, false);
    expect(onClose).toHaveBeenCalled();
  });

  it("warns when nothing narrows the delete", async () => {
    render(
      <DeleteHistoryDialog
        query={{}}
        scope="All packets"
        narrowed={false}
        onDeleted={vi.fn()}
        onClose={vi.fn()}
        onError={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/every packet in the project/);
    expect(await screen.findByRole("button", { name: "Delete 42 packets" })).toBeEnabled();
  });

  it("cannot delete before the count is known, or when nothing matches", async () => {
    vi.spyOn(desktop, "trafficStats").mockResolvedValue(stats(0, 0));
    render(
      <DeleteHistoryDialog
        query={query}
        scope="play"
        narrowed
        onDeleted={vi.fn()}
        onClose={vi.fn()}
        onError={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled();
    expect(await screen.findByText(/nothing to delete/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete 0 packets" })).toBeDisabled();
    expect(desktop.packetsDelete).not.toHaveBeenCalled();
  });
});

describe("small helpers", () => {
  it("reads server ports", () => {
    expect(parsePorts("25565, 25566 19132")).toEqual([25565, 25566, 19132]);
    expect(parsePorts("25565, abc")).toBeNull();
    expect(parsePorts("70000")).toBeNull();
  });

  it("reads an optional protocol version", () => {
    expect(parseProtocol("")).toBeUndefined();
    expect(parseProtocol(" 767 ")).toBe(767);
    expect(parseProtocol("1.21")).toBeNull();
    expect(parseProtocol("-4")).toBeNull();
  });

  it("summarises an import, leaving out counts that are zero", () => {
    const rows = importResultRows({
      recordsRead: 120,
      framesImported: 90,
      bytesImported: 4_096,
      duplicatesRemoved: 0,
      segmentsReordered: 0,
      gaps: 0,
      packetsDecoded: 86,
      rawRows: 4,
      connections: 2,
      encryptedConnections: 1,
      midstreamConnections: 0,
      unsynchronisedStreams: 0,
      desyncs: 0,
      resyncs: 0,
      frameErrors: 0,
      exportedPackets: 0,
      truncated: false,
      error: null,
    });
    const labels = rows.map(([label]) => label);
    expect(labels).toContain("Minecraft packets");
    expect(labels).toContain("Raw rows");
    expect(labels).toContain("Encrypted connections");
    expect(labels).not.toContain("Gaps skipped");
    expect(rows.find(([label]) => label === "Minecraft packets")?.[1]).toBe("86");
  });

  it("formats backend errors for the log", () => {
    expect(backendErrorText({ source: "capture", message: "disk full", repeated: 1 })).toBe(
      "capture: disk full",
    );
    expect(backendErrorText({ source: "capture", message: "disk full", repeated: 5 })).toBe(
      "capture: disk full (×5)",
    );
  });
});
