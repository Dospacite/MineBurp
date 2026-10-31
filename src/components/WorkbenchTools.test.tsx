import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { ReplaceView } from "../views/ReplaceView";
import { CommandPalette } from "./CommandPalette";
import { DecoderSidebar } from "./DecoderSidebar";
import { PayloadGeneratorDialog } from "./PayloadGeneratorDialog";

beforeEach(() => vi.restoreAllMocks());
describe("workbench tools", () => {
  it("searches and runs palette commands from the keyboard", async () => {
    const run = vi.fn(),
      close = vi.fn();
    render(
      <CommandPalette
        commands={[
          { id: "decoder", label: "Minecraft Decoder", run },
          { id: "channels", label: "Channel explorer", run: vi.fn() },
        ]}
        onClose={close}
      />,
    );
    const input = screen.getByRole("combobox");
    await userEvent.type(input, "decoder");
    expect(screen.getAllByRole("option")).toHaveLength(1);
    await userEvent.keyboard("{Enter}");
    expect(run).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });
  it("chains Decoder output while keeping consumed and trailing bytes visible", async () => {
    vi.spyOn(desktop, "decoderTransform").mockResolvedValue({
      output: "300",
      consumed: 2,
      trailing_hex: "ff",
    });
    render(
      <DecoderSidebar open request={{ input: "ac 02 ff", nonce: 1 }} onClose={vi.fn()} onError={vi.fn()} />,
    );
    await userEvent.selectOptions(screen.getByRole("combobox"), "var_int_decode");
    await userEvent.click(screen.getByRole("button", { name: "Transform" }));
    await screen.findByDisplayValue("300");
    expect(screen.getByDisplayValue("ff")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Consumed 2 bytes");
    await userEvent.click(screen.getByRole("button", { name: "Use output as input" }));
    expect(screen.getByRole("textbox", { name: "Input" })).toHaveValue("300");
    expect(screen.getByRole("heading", { name: "Transformation history" })).toBeInTheDocument();
  });
  it("generates a payload preview and only applies it explicitly", async () => {
    const apply = vi.fn();
    vi.spyOn(desktop, "payloadGenerate").mockResolvedValue(["0", "1", "2"]);
    render(<PayloadGeneratorDialog onApply={apply} onClose={vi.fn()} onError={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Generate preview" }));
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "Generated payload preview" })).toHaveValue("0\n1\n2"),
    );
    expect(apply).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Replace payload list" }));
    expect(apply).toHaveBeenCalledWith("0\n1\n2");
  });
  it("previews a drop rule with no replacement edits", async () => {
    vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
    vi.spyOn(desktop, "replacementRules").mockResolvedValue([
      {
        id: "00000000-0000-4000-8000-000000000001",
        name: "Block channel",
        enabled: false,
        action: "drop",
        expression: 'channel == "test:channel"',
        edits: [],
      },
    ]);
    vi.spyOn(desktop, "filterValidate").mockResolvedValue();
    vi.spyOn(desktop, "replacementRulePreview").mockResolvedValue({
      matched: true,
      action: "drop",
      protected: false,
      logical_base64: "AA==",
    });
    render(<ReplaceView seed={null} onError={vi.fn()} />);
    await screen.findByDisplayValue("Block channel");
    expect(screen.queryByText(t("replace.add-edit"))).not.toBeInTheDocument();
    await userEvent.type(screen.getByRole("textbox", { name: t("replace.input") }), "00");
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: t("replace.result") })).toHaveValue(
        t("replace.preview.drop"),
      ),
    );
  });
});
