import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { InterceptedPacket, InterceptSettings } from "../domain/types";
import { desktop } from "../lib/desktop";
import { InterceptView, parseSeconds } from "./InterceptView";

const settings: InterceptSettings = {
  enabled: true,
  client_to_server: true,
  server_to_client: false,
  expression: "",
  forward_keep_alive: true,
  auto_forward_after_ms: null,
};

const held: InterceptedPacket = {
  id: 7,
  target: "play.example.test:25565",
  held_at_micros: 0,
  deadline_micros: null,
  bytes_base64: btoa(String.fromCharCode(0x05, 0x68, 0x69)),
  summary: {
    id: 0,
    sequence: 1,
    connection_id: "c",
    timestamp_micros: 0,
    source: "minecraft",
    direction: "client_to_server",
    state: "play",
    protocol_version: 767,
    packet_id: 5,
    name: "chat_command",
    channel: null,
    loader: null,
    size: 3,
    disposition: "forwarded",
    flow: null,
  } as never,
};

function renderView(
  decryptEnabled = true,
  onSettingsPatch = vi.fn(async (patch: Partial<InterceptSettings>) => ({ ...settings, ...patch })),
) {
  return render(
    <InterceptView
      settings={settings}
      onSettingsPatch={onSettingsPatch}
      pendingSignal={1}
      decryptEnabled={decryptEnabled}
      onError={vi.fn()}
    />,
  );
}

describe("InterceptView", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "interceptPending").mockResolvedValue([held]);
    vi.spyOn(desktop, "packetLayout").mockRejectedValue(new Error("no layout in tests"));
    vi.spyOn(desktop, "networkConditions").mockResolvedValue({
      client_to_server: { delay_ms: 0, jitter_ms: 0, bandwidth_bytes_per_second: null },
      server_to_client: { delay_ms: 0, jitter_ms: 0, bandwidth_bytes_per_second: null },
    });
  });

  it("forwards an unedited packet without replacement bytes", async () => {
    const resolve = vi.spyOn(desktop, "interceptResolve").mockResolvedValue();
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole("button", { name: /^Forward$/ }));
    expect(resolve).toHaveBeenCalledWith(7, "forward", undefined);
  });

  it("forwards edited hex as the replacement, from the keyboard", async () => {
    const resolve = vi.spyOn(desktop, "interceptResolve").mockResolvedValue();
    const user = userEvent.setup();
    renderView();
    const editor = await screen.findByRole("textbox", { name: "Bytes" });
    await waitFor(() => expect(editor).toHaveValue("05 68 69"));
    await user.clear(editor);
    await user.type(editor, "05 68 6f");
    expect(screen.getByRole("button", { name: /Forward edited/ })).toBeInTheDocument();
    await user.keyboard("{Control>}{Enter}{/Control}");
    expect(resolve).toHaveBeenCalledWith(7, "forward", new Uint8Array([0x05, 0x68, 0x6f]));
  });

  it("drops the selected packet", async () => {
    const resolve = vi.spyOn(desktop, "interceptResolve").mockResolvedValue();
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole("button", { name: /Drop/ }));
    expect(resolve).toHaveBeenCalledWith(7, "drop", undefined);
  });

  it("explains that Intercept needs decrypted connections", async () => {
    renderView(false);
    expect(await screen.findByText(/Turn on Decrypt connections/)).toBeInTheDocument();
  });

  it("shows how long a held packet has before it is forwarded", async () => {
    vi.spyOn(desktop, "interceptPending").mockResolvedValue([
      { ...held, deadline_micros: (Date.now() + 9_500) * 1000 },
    ]);
    renderView();
    expect((await screen.findAllByRole("timer"))[0]).toHaveTextContent(/forwards in (9|10)s/);
  });

  it("applies an auto-forward delay in milliseconds", async () => {
    const patch = vi.fn(async (next: Partial<InterceptSettings>) => ({ ...settings, ...next }));
    const user = userEvent.setup();
    renderView(true, patch);
    const field = await screen.findByLabelText(/Auto-forward after/);
    await user.type(field, "2.5{Enter}");
    expect(patch).toHaveBeenCalledWith({ auto_forward_after_ms: 2500 });
  });

  it("sends network conditions in bytes per second", async () => {
    const set = vi
      .spyOn(desktop, "setNetworkConditions")
      .mockImplementation(async (conditions) => conditions);
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole("button", { name: /Network/ }));
    const [, serverDelay] = await screen.findAllByLabelText("Delay (ms)");
    const [clientBandwidth] = screen.getAllByLabelText("Bandwidth (KiB/s)");
    if (!serverDelay || !clientBandwidth) throw new Error("both directions are editable");
    await user.clear(serverDelay);
    await user.type(serverDelay, "250");
    await user.type(clientBandwidth, "64");
    await user.click(screen.getByRole("button", { name: /Apply/ }));
    expect(set).toHaveBeenCalledWith({
      client_to_server: { delay_ms: 0, jitter_ms: 0, bandwidth_bytes_per_second: 65_536 },
      server_to_client: { delay_ms: 250, jitter_ms: 0, bandwidth_bytes_per_second: null },
    });
  });
});

describe("parseSeconds", () => {
  it("reads empty as waiting, numbers as milliseconds, and rejects the rest", () => {
    expect(parseSeconds("")).toBeNull();
    expect(parseSeconds("1.5")).toBe(1500);
    expect(parseSeconds("0")).toBeUndefined();
    expect(parseSeconds("soon")).toBeUndefined();
  });
});

it("retains an expired frame draft and never forwards the next unseen frame", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  const pending = vi.spyOn(desktop, "interceptPending").mockResolvedValue([held]);
  vi.spyOn(desktop, "packetLayout").mockRejectedValue(new Error("raw"));
  vi.spyOn(desktop, "networkConditions").mockRejectedValue(new Error("offline"));
  const resolve = vi.spyOn(desktop, "interceptResolve").mockResolvedValue();
  const props = {
    settings,
    onSettingsPatch: vi.fn(),
    pendingSignal: 1,
    decryptEnabled: true,
    onError: vi.fn(),
  };
  const ui = render(<InterceptView {...props} />);
  const input = await screen.findByRole("textbox", { name: "Bytes" });
  const { fireEvent } = await import("@testing-library/react");
  fireEvent.change(input, { target: { value: "01 02" } });
  pending.mockResolvedValue([{ ...held, id: 8 }]);
  ui.rerender(<InterceptView {...props} pendingSignal={2} />);
  await screen.findByText(/forwarded without these edits/);
  expect(input).toHaveValue("01 02");
  fireEvent.keyDown(window, { key: "Enter", ctrlKey: true });
  expect(resolve).not.toHaveBeenCalled();
});
