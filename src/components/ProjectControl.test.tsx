import { save } from "@tauri-apps/plugin-dialog";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectInfo } from "../domain/types";
import { desktop } from "../lib/desktop";
import { ProjectControl } from "./ProjectControl";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

const temporary: ProjectInfo = {
  path: "/tmp/mineburp-session.mineburp",
  name: "Temporary session",
  encrypted: false,
  schema_version: 4,
  temporary: true,
};

const saved: ProjectInfo = { ...temporary, path: "/work/kept.mineburp", name: "Kept", temporary: false };

describe("ProjectControl", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(desktop, "projectRecoveredList").mockResolvedValue([]);
    vi.spyOn(desktop, "projectScopeGet").mockResolvedValue([]);
  });

  it("saves the temporary session instead of starting an empty project", async () => {
    const saveAs = vi.spyOn(desktop, "projectSaveAs").mockResolvedValue(saved);
    const create = vi.spyOn(desktop, "projectCreate");
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={onChange} onError={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    expect(screen.getByRole("tab", { name: "Save as" })).toHaveAttribute("aria-selected", "true");
    await user.type(screen.getByPlaceholderText("/path/to/assessment.mineburp"), "/work/kept{Enter}");

    expect(saveAs).toHaveBeenCalledWith("/work/kept.mineburp", "Minecraft assessment", "");
    expect(create).not.toHaveBeenCalled();
    expect(onChange).toHaveBeenCalledWith(saved);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("warns that a new project discards the temporary session", async () => {
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.click(screen.getByRole("tab", { name: "New" }));
    expect(screen.getByText(/packets are discarded/)).toBeInTheDocument();
  });

  it("closes on Escape and on a click outside", async () => {
    const user = userEvent.setup();
    render(
      <>
        <ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />
        <p>outside</p>
      </>,
    );
    const toggle = screen.getByRole("button", { name: /Temporary session/ });
    await user.click(toggle);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(toggle);
    await user.click(screen.getByText("outside"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("reopens a recent unencrypted project in one click", async () => {
    vi.spyOn(desktop, "projectSaveAs").mockResolvedValue(saved);
    const openProject = vi.spyOn(desktop, "projectOpen").mockResolvedValue(saved);
    const user = userEvent.setup();
    const { rerender } = render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.type(screen.getByPlaceholderText("/path/to/assessment.mineburp"), "/work/kept{Enter}");

    // Now on a different project, "Kept" is offered under Open.
    rerender(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.click(screen.getByRole("tab", { name: "Open" }));
    await user.click(screen.getByRole("button", { name: /^Kept/ }));
    expect(openProject).toHaveBeenCalledWith("/work/kept.mineburp");
  });
  it("lists recovered packet counts and dates and opens a session", async () => {
    vi.spyOn(desktop, "projectRecoveredList").mockResolvedValue([
      { path: "/sessions/recovered/old.mineburp", packets: 42, modified_millis: 1700000000000 },
    ]);
    const open = vi.spyOn(desktop, "projectOpen").mockResolvedValue(saved);
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    expect(await screen.findByText(/42 packets/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open" }));
    expect(open).toHaveBeenCalledWith("/sessions/recovered/old.mineburp");
  });

  it("requires confirmation before deleting a recovered session", async () => {
    vi.spyOn(desktop, "projectRecoveredList").mockResolvedValue([
      { path: "/sessions/recovered/old.mineburp", packets: 42, modified_millis: 1700000000000 },
    ]);
    const remove = vi.spyOn(desktop, "projectRecoveredDelete").mockResolvedValue();
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(remove).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(remove).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.click(screen.getByRole("button", { name: "Delete permanently" }));
    expect(remove).toHaveBeenCalledWith("/sessions/recovered/old.mineburp");
    expect(screen.queryByText("old.mineburp")).not.toBeInTheDocument();
  });
  it("saves the authorized scope as trimmed nonempty patterns", async () => {
    const save = vi.spyOn(desktop, "projectScopeSet").mockResolvedValue();
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.type(screen.getByLabelText("Target scope"), "*.example.com:25565{Enter}10.0.0.0/8");
    await user.click(screen.getByRole("button", { name: "Save scope" }));
    expect(save).toHaveBeenCalledWith(["*.example.com:25565", "10.0.0.0/8"]);
  });
  it("saves a recovered copy without first replacing the current session", async () => {
    vi.spyOn(desktop, "projectRecoveredList").mockResolvedValue([
      { path: "/sessions/recovered/old.mineburp", packets: 42, modified_millis: 1700000000000 },
    ]);
    vi.mocked(save).mockResolvedValue("/work/recovered.mineburp");
    const saveCopy = vi.spyOn(desktop, "projectRecoveredSaveAs").mockResolvedValue(saved);
    const open = vi.spyOn(desktop, "projectOpen");
    const user = userEvent.setup();
    render(<ProjectControl project={temporary} onChange={vi.fn()} onError={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /Temporary session/ }));
    await user.click(await screen.findByRole("button", { name: "Save as…" }));
    expect(saveCopy).toHaveBeenCalledWith("/sessions/recovered/old.mineburp", "/work/recovered.mineburp");
    expect(open).not.toHaveBeenCalled();
  });
});
