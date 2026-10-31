import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionSnapshot, PacketView } from "../domain/types";
import { desktop } from "../lib/desktop";
import { EMPTY_INTRUDER } from "../lib/researchDocuments";
import { IntruderView } from "./IntruderView";
import { SequencerView } from "./SequencerView";

const session = {
  id: "c1",
  target: { host: "play.example.test", port: 25565 },
  listener_address: "127.0.0.1:1",
  status: "active",
  state: "play",
  protocol_version: 767,
  minecraft_version: null,
  loader: null,
  compression_threshold: null,
  encrypted_client: true,
  encrypted_server: true,
  packet_count: 1,
  byte_count: 1,
  last_error: null,
} satisfies ConnectionSnapshot;

function view(bytes: number[], total = bytes.length): PacketView {
  return {
    summary: {
      id: 42,
      sequence: 1,
      connection_id: "c1",
      timestamp_micros: 0,
      source: "minecraft",
      direction: "client_to_server",
      state: "play",
      protocol_version: 767,
      packet_id: 5,
      name: "chat_command",
      channel: null,
      loader: null,
      size: total,
      disposition: "forwarded",
      flow: null,
    },
    wire: {
      frame_length: total,
      logical_length: total,
      compressed: false,
      encrypted: true,
      truncated: false,
    },
    insight: {
      name: "chat_command",
      label: null,
      summary: null,
      fields: null,
      channel: null,
      loader: null,
      identification: "registry",
      error: null,
      stream: [],
    },
    schema_decoded: null,
    schema_decode_error: null,
    total_bytes: total,
    bytes_offset: 0,
    bytes_base64: btoa(String.fromCharCode(...bytes)),
  };
}

const layout = {
  name: "test",
  complete: true,
  fields: [{ name: "token", kind: "string" as const, offset: 1, length: 2, value: "a" }],
};
beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(desktop, "packetLayoutStored").mockResolvedValue(layout);
  vi.spyOn(desktop, "intruderPlan").mockResolvedValue([[0]]);
  vi.spyOn(desktop, "packetBytes").mockResolvedValue({ offset: 0, total: 3, base64: btoa("abc") });
  vi.spyOn(desktop, "replacementPreview").mockResolvedValue(new Uint8Array([1, 2, 3]));
  vi.spyOn(desktop, "repeaterSend").mockResolvedValue();
  vi.spyOn(desktop, "proxySessions").mockResolvedValue([session]);
  vi.spyOn(desktop, "packets").mockResolvedValue([]);
});
describe("research workflows", () => {
  it("previews encoded bytes without sending a packet", async () => {
    render(
      <IntruderView
        request={{ packet: view([1, 2, 3]), nonce: 1 }}
        sessions={[session]}
        projectKey="one"
        onError={vi.fn()}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: /Preview first/ })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: /Preview first/ }));
    await screen.findByDisplayValue("01 02 03");
    expect(desktop.repeaterSend).not.toHaveBeenCalled();
  });
  it("does not send after stop while an edit is still pending", async () => {
    let finish: (frame: Uint8Array) => void = () => {};
    vi.mocked(desktop.replacementPreview).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    render(
      <IntruderView
        request={{ packet: view([1, 2, 3]), nonce: 1 }}
        sessions={[session]}
        projectKey="one"
        onError={vi.fn()}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Start attack" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Start attack" }));
    await waitFor(() => expect(desktop.replacementPreview).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Stop" }));
    finish(new Uint8Array([1, 2, 3]));
    await waitFor(() => expect(screen.getByRole("button", { name: "Start attack" })).toBeEnabled());
    expect(desktop.repeaterSend).not.toHaveBeenCalled();
  });
  it("keeps the sent attempt when observation is stopped", async () => {
    vi.mocked(desktop.intruderPlan).mockResolvedValue([[0], [0]]);
    render(
      <IntruderView
        request={{ packet: view([1, 2, 3]), nonce: 1 }}
        sessions={[session]}
        projectKey="one"
        onError={vi.fn()}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Start attack" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Start attack" }));
    await waitFor(() => expect(desktop.repeaterSend).toHaveBeenCalledTimes(1));
    await userEvent.click(screen.getByRole("button", { name: "Stop" }));
    await screen.findByText("Sent; observation stopped");
    expect(desktop.repeaterSend).toHaveBeenCalledTimes(1);
  });
  it("rejects a connection that has changed protocol state", async () => {
    vi.mocked(desktop.proxySessions).mockResolvedValue([{ ...session, state: "configuration" }]);
    const error = vi.fn();
    render(
      <IntruderView
        request={{ packet: view([1, 2, 3]), nonce: 1 }}
        sessions={[session]}
        projectKey="one"
        onError={error}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Start attack" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Start attack" }));
    await waitFor(() =>
      expect(error).toHaveBeenCalledWith(expect.stringContaining("protocol version and state")),
    );
    expect(desktop.repeaterSend).not.toHaveBeenCalled();
  });
  it("collects only matching packet fields in history order", async () => {
    const seed = view([1, 2, 3]);
    vi.mocked(desktop.packets).mockResolvedValue([
      { ...seed.summary, id: 1 },
      { ...seed.summary, id: 2, packet_id: 99 },
      { ...seed.summary, id: 3 },
    ]);
    vi.mocked(desktop.packetLayoutStored).mockImplementation(async (id) => ({
      ...layout,
      fields: [{ ...layout.fields[0]!, value: id === 1 ? "first" : "last" }],
    }));
    render(<SequencerView request={{ packet: seed, nonce: 1 }} projectKey="one" onError={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Collect existing history" })).toBeEnabled(),
    );
    await userEvent.click(screen.getByRole("button", { name: "Collect existing history" }));
    await waitFor(() => expect(screen.getByRole("textbox")).toHaveValue("first\nlast"));
    expect(desktop.packetLayoutStored).not.toHaveBeenCalledWith(2);
  });
});

it("uses selected raw bytes as an Intruder position", async () => {
  render(
    <IntruderView
      request={{ packet: view([1, 2, 3]), nonce: 1, selection: { offset: 1, length: 2 } }}
      sessions={[session]}
      projectKey="one"
      onError={vi.fn()}
    />,
  );
  await screen.findByDisplayValue("Raw byte range, hex payloads");
  expect(screen.getByRole("spinbutton", { name: "Byte offset, including packet ID" })).toHaveValue(1);
  expect(screen.getByRole("spinbutton", { name: "Bytes to replace" })).toHaveValue(2);
});

it("does not replay an old selection request into a different project", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  vi.spyOn(desktop, "workbenchDocumentGet").mockResolvedValue({ version: 1, data: EMPTY_INTRUDER });
  vi.spyOn(desktop, "workbenchDocumentSave").mockResolvedValue();
  const request = { packet: view([1, 2, 3]), nonce: 1 };
  const onError = vi.fn();
  const { rerender } = render(
    <IntruderView request={request} sessions={[session]} projectKey="one" onError={onError} />,
  );
  await waitFor(() => expect(screen.getByRole("button", { name: "Start attack" })).toBeEnabled());
  rerender(<IntruderView request={request} sessions={[session]} projectKey="two" onError={onError} />);
  await screen.findByText("Send a captured packet to Intruder from its history context menu.");
  expect(screen.queryByRole("button", { name: "Start attack" })).not.toBeInTheDocument();
});
