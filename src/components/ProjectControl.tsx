import { Clock, FolderOpen, Loader2, LockKeyhole, Plus, Save, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";

import type { ProjectInfo } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { chooseProjectDestination, chooseProjectToOpen, withExtension } from "../lib/files";
import { forgetProject, type RecentProject, recentProjects, rememberProject } from "../lib/recentProjects";

type Mode = "save" | "create" | "open";

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
  const [mode, setMode] = useState<Mode>("save");
  const [path, setPath] = useState("");
  const [name, setName] = useState("Minecraft assessment");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>(recentProjects);
  const root = useRef<HTMLDivElement>(null);
  const passphraseInput = useRef<HTMLInputElement>(null);
  const temporary = project?.temporary ?? false;

  // A popover that only its own button could close stayed open over the
  // traffic table; Escape and a click anywhere else dismiss it now.
  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event: PointerEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function toggle() {
    if (!open) {
      // Saving is the useful default while the session is still temporary.
      setMode(project ? "save" : "open");
      setName(temporary ? "Minecraft assessment" : (project?.name ?? "Minecraft assessment"));
      setPath("");
      setPassphrase("");
      setRecent(recentProjects());
    }
    setOpen(!open);
  }

  async function browse() {
    try {
      const picked = mode === "open" ? await chooseProjectToOpen() : await chooseProjectDestination(name);
      if (picked) setPath(picked);
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function run(action: () => Promise<ProjectInfo>) {
    setBusy(true);
    try {
      const next = await action();
      setRecent(rememberProject(next));
      onChange(next);
      setOpen(false);
      setPassphrase("");
    } catch (reason) {
      onError(message(reason));
    } finally {
      setBusy(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    const target = mode === "open" ? path : withExtension(path.trim(), ".mineburp");
    void run(() =>
      mode === "save"
        ? desktop.projectSaveAs(target, name, passphrase)
        : mode === "create"
          ? desktop.projectCreate(target, name, passphrase)
          : desktop.projectOpen(target, passphrase),
    );
  }

  function openRecent(entry: RecentProject) {
    if (entry.encrypted) {
      setMode("open");
      setPath(entry.path);
      passphraseInput.current?.focus();
      return;
    }
    void run(() => desktop.projectOpen(entry.path));
  }

  const canSubmit = !busy && path.trim() !== "" && (mode === "open" || name.trim() !== "");
  const modes: Mode[] = project ? ["save", "create", "open"] : ["create", "open"];
  const otherRecent = recent.filter((entry) => entry.path !== project?.path);

  return (
    <div className="project-control" ref={root}>
      <button
        type="button"
        className={`project-button ${temporary ? "temporary" : ""}`}
        onClick={toggle}
        aria-expanded={open}
        aria-haspopup="dialog"
        title={temporary ? t("project.temporary.title") : project?.path}
      >
        <FolderOpen size={15} aria-hidden="true" />
        <span>{project?.name ?? t("project.open")}</span>
        {temporary && <span className="project-tag">{t("project.temporary.tag")}</span>}
        {project?.encrypted && <LockKeyhole size={13} aria-label={t("project.encrypted")} />}
      </button>
      {open && (
        <form
          className="project-popover"
          role="dialog"
          aria-label={t("project.action.label")}
          onSubmit={submit}
        >
          {temporary ? (
            <p className="project-note">{t("project.temporary.note")}</p>
          ) : (
            project && (
              <p className="project-current" title={project.path}>
                {project.path}
              </p>
            )
          )}
          <div className="segmented" role="tablist" aria-label={t("project.action.label")}>
            {modes.map((option) => (
              <button
                type="button"
                role="tab"
                key={option}
                aria-selected={mode === option}
                className={mode === option ? "active" : ""}
                onClick={() => {
                  setMode(option);
                  setPath("");
                }}
              >
                {t(`project.action.${option}`)}
              </button>
            ))}
          </div>
          {mode === "create" && temporary && <p className="project-hint">{t("project.create.discards")}</p>}
          {mode === "save" && (
            <p className="project-hint">
              {t(temporary ? "project.save.keeps-session" : "project.save.copies-project")}
            </p>
          )}
          {mode !== "open" && (
            <label>
              {t("project.name")}
              <input value={name} onChange={(event) => setName(event.target.value)} />
            </label>
          )}
          <label>
            {t(mode === "open" ? "project.path" : "project.destination")}
            <span className="path-field">
              <input
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder={t("project.path.placeholder")}
                spellCheck={false}
              />
              <button type="button" className="button" onClick={() => void browse()}>
                {t("project.browse")}
              </button>
            </span>
          </label>
          <label>
            {t("project.passphrase")} <span className="optional">{t("project.optional")}</span>
            <input
              ref={passphraseInput}
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              autoComplete={mode === "open" ? "current-password" : "new-password"}
            />
          </label>
          <button type="submit" className="button primary" disabled={!canSubmit}>
            {busy ? (
              <Loader2 className="spin" size={14} aria-hidden="true" />
            ) : mode === "save" ? (
              <Save size={14} aria-hidden="true" />
            ) : mode === "create" ? (
              <Plus size={14} aria-hidden="true" />
            ) : (
              <FolderOpen size={14} aria-hidden="true" />
            )}
            {t(`project.${mode}.button`)}
          </button>
          {mode === "open" && otherRecent.length > 0 && (
            <div className="recent-projects">
              <span className="recent-heading">
                <Clock size={11} aria-hidden="true" />
                {t("project.recent")}
              </span>
              <ul>
                {otherRecent.map((entry) => (
                  <li key={entry.path}>
                    <button
                      type="button"
                      className="recent-open"
                      title={entry.path}
                      disabled={busy}
                      onClick={() => openRecent(entry)}
                    >
                      <strong>{entry.name}</strong>
                      <small>{entry.path}</small>
                      {entry.encrypted && <LockKeyhole size={11} aria-label={t("project.encrypted")} />}
                    </button>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label={t("project.recent.forget", { name: entry.name })}
                      title={t("project.recent.forget", { name: entry.name })}
                      onClick={() => setRecent(forgetProject(entry.path))}
                    >
                      <X size={12} aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </form>
      )}
    </div>
  );
}
