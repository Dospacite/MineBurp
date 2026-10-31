import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectionSnapshot, PacketView, RepeaterTab } from "../domain/types";
import { desktop } from "../lib/desktop";
import { RepeaterView } from "./RepeaterView";

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

const saved: RepeaterTab = {
  id: "00000000-0000-4000-8000-000000000001",
  name: "Saved tab",
  connection_id: "c1",
  direction: "server_to_client",
  state: "play",
  logical_bytes: [0x01, 0x02],
  decoded: null,
};

describe("RepeaterView", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "packetLayout").mockRejectedValue(new Error("no layout in tests"));
  });

  it("keeps a sent packet when saved tabs load afterwards", async () => {
    let finish: (tabs: RepeaterTab[]) => void = () => undefined;
    vi.spyOn(desktop, "repeaterTabs").mockReturnValue(
      new Promise((done) => {
        finish = done;
      }),
    );
    const onRequestHandled = vi.fn();
    render(
      <RepeaterView
        sessions={[session]}
        request={{ packet: view([0x05, 0x68, 0x69]), nonce: 1 }}
        onRequestHandled={onRequestHandled}
        onError={vi.fn()}
      />,
    );
    const editor = await screen.findByRole("textbox", { name: "Bytes" });
    expect(editor).toHaveValue("05 68 69");
    expect(onRequestHandled).toHaveBeenCalledWith(1);

    finish([saved]);
    expect(await screen.findByRole("tab", { name: "Saved tab" })).toBeInTheDocument();
    // The saved tab joins the strip; it does not take over the editor.
    expect(screen.getByRole("textbox", { name: "Bytes" })).toHaveValue("05 68 69");
    expect(screen.getByRole("tab", { name: /chat_command/ })).toHaveAttribute("aria-selected", "true");
  });

  it("loads the whole payload when the packet arrived truncated", async () => {
    vi.spyOn(desktop, "repeaterTabs").mockResolvedValue([]);
    const full = [0x05, 0x68, 0x69, 0x21, 0x21];
    const bytes = vi.spyOn(desktop, "packetBytes").mockResolvedValue({
      offset: 0,
      total: full.length,
      base64: btoa(String.fromCharCode(...full)),
    });
    render(
      <RepeaterView
        sessions={[session]}
        request={{ packet: view([0x05, 0x68], full.length), nonce: 2 }}
        onRequestHandled={vi.fn()}
        onError={vi.fn()}
      />,
    );
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Bytes" })).toHaveValue("05 68 69 21 21"));
    expect(bytes).toHaveBeenCalledWith(42, 0, 256 * 1024);
  });

  it("shows an invalid hex character instead of dropping it", async () => {
    vi.spyOn(desktop, "repeaterTabs").mockResolvedValue([]);
    const user = userEvent.setup();
    render(<RepeaterView sessions={[session]} request={null} onRequestHandled={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "New tab" }));
    await user.type(screen.getByRole("textbox", { name: "Bytes" }), "41 gg 42");
    expect(screen.getByRole("alert")).toHaveTextContent("“g” in “gg” is not a hex digit.");
    expect(screen.getByRole("button", { name: /Send/ })).toBeDisabled();
  });
});

describe("Repeater edit history", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(false);
    vi.spyOn(desktop, "repeaterTabSave").mockResolvedValue();
  });
  it("undoes packet edits, restores named revisions, and saves history with the tab", async () => {
    render(
      <RepeaterView
        sessions={[session]}
        request={{ packet: view([5, 104]), nonce: 1 }}
        onRequestHandled={vi.fn()}
        onError={vi.fn()}
      />,
    );
    const editor = await screen.findByRole("textbox", { name: "Bytes" });
    fireEvent.change(editor, { target: { value: "05 69" } });
    await userEvent.click(screen.getByRole("button", { name: "Undo edit" }));
    expect(editor).toHaveValue("05 68");
    await userEvent.click(screen.getByRole("button", { name: "Redo edit" }));
    expect(editor).toHaveValue("05 69");
    await userEvent.type(screen.getByRole("textbox", { name: "Revision name" }), "candidate");
    await userEvent.click(screen.getByRole("button", { name: "Create revision" }));
    fireEvent.change(editor, { target: { value: "05 70" } });
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Restore a revision" }), "candidate");
    expect(editor).toHaveValue("05 69");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(desktop.repeaterTabSave).toHaveBeenCalled());
    expect(vi.mocked(desktop.repeaterTabSave).mock.calls[0]?.[0].edit_history).toMatchObject({
      original: "05 68",
      revisions: [{ name: "candidate", hex: "05 69" }],
    });
  });
});
