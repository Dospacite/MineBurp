import { FolderOpen, LockKeyhole, Plus } from "lucide-react";
import { useState } from "react";

import type { ProjectInfo } from "../domain/types";
import { desktop } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";

export function ProjectControl({
  project,
  onChange,
  onError,
}: {
  project: ProjectInfo | null;
  onChange: (project: ProjectInfo) => void;
  onError: (error: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"create" | "open">("create");
  const [path, setPath] = useState("");
  const [name, setName] = useState("Minecraft assessment");
  const [passphrase, setPassphrase] = useState("");

  async function submit() {
    try {
      const next =
        mode === "create"
          ? await desktop.projectCreate(path, name, passphrase)
          : await desktop.projectOpen(path, passphrase);
      onChange(next);
      setOpen(false);
    } catch (reason) {
      onError(message(reason));
    }
  }

  return (
    <div className="project-control">
      <button
        className={`project-button ${project?.temporary ? "temporary" : ""}`}
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        title={project?.temporary ? "Temporary project" : project?.path}
      >
        <FolderOpen size={15} aria-hidden="true" />
        <span>{project?.name ?? "Open project"}</span>
        {project?.temporary && <span className="project-tag">temp</span>}
        {project?.encrypted && <LockKeyhole size={13} aria-label="Encrypted" />}
      </button>
      {open && (
        <div className="project-popover">
          {project?.temporary && (
            <p className="project-note">Temporary project — deleted when MineBurp exits.</p>
          )}
          <div className="segmented" aria-label="Project action">
            <button className={mode === "create" ? "active" : ""} onClick={() => setMode("create")}>New</button>
            <button className={mode === "open" ? "active" : ""} onClick={() => setMode("open")}>Open</button>
          </div>
          {mode === "create" && (
            <label>
              Project name
              <input value={name} onChange={(event) => setName(event.target.value)} />
            </label>
          )}
          <label>
            Project path
            <input
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="/path/to/assessment.mineburp"
            />
          </label>
          <label>
            Passphrase <span className="optional">optional</span>
            <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} />
          </label>
          <button className="button primary" disabled={!path || (mode === "create" && !name)} onClick={submit}>
            {mode === "create" ? <Plus size={14} /> : <FolderOpen size={14} />}
            {mode === "create" ? "Create project" : "Open project"}
          </button>
        </div>
      )}
    </div>
  );
}
