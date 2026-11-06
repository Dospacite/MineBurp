import { save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { Split } from "../components/Split";
import type { Finding, FindingSeverity, FindingStatus } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
export const emptyFinding = (): Finding => ({
  id: "00000000-0000-0000-0000-000000000000",
  title: "New finding",
  severity: "info",
  status: "open",
  description: "",
  reproductionSteps: "",
  createdAtMicros: 0,
  updatedAtMicros: 0,
  evidence: [],
  tags: [],
});
export function FindingsView({
  projectKey,
  onError,
  onPacket,
}: {
  projectKey: string | null;
  onError: (s: string) => void;
  onPacket: (id: number) => void;
}) {
  const [rows, setRows] = useState<Finding[]>([]);
  const [draft, setDraft] = useState<Finding | null>(null);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [pcap, setPcap] = useState(false);
  const [missing, setMissing] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    setMissing([]);
    if (projectKey && draft && rows.some((f) => f.id === draft.id))
      void desktop
        .findings<Array<{ evidence: Finding["evidence"][number]; missing: boolean }>>(
          projectKey,
          "evidence_status",
          { id: draft.id },
        )
        .then((states) => {
          if (active)
            setMissing(states.filter((s) => s.missing).map((s) => `${s.evidence.kind}:${s.evidence.id}`));
        })
        .catch((e) => onError(String(e)));
    return () => {
      active = false;
    };
  }, [projectKey, draft, rows, onError]);
  useEffect(() => {
    let active = true;
    if (projectKey)
      desktop
        .findings(projectKey, "list")
        .then((r) => {
          if (active) setRows(r);
        })
        .catch((e) => onError(String(e)));
    return () => {
      active = false;
    };
  }, [projectKey, onError]);
  async function run(action: string, args: Record<string, unknown>) {
    if (!projectKey || busy) return;
    setBusy(true);
    try {
      const result = await desktop.findings<Finding>(projectKey, action, args);
      setRows(await desktop.findings(projectKey, "list"));
      setDraft(action === "delete" ? null : result);
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function exportReport(html: boolean) {
    if (!projectKey) return;
    try {
      const path = await save({
        filters: [{ name: html ? "HTML" : "Markdown", extensions: [html ? "html" : "md"] }],
      });
      const pcapPath =
        path && pcap ? await save({ filters: [{ name: "pcapng", extensions: ["pcapng"] }] }) : null;
      if (path)
        await desktop.findings(projectKey, "export", {
          pcapPath,
          path,
          reportFormat: html ? "html" : "markdown",
          overwrite: true,
        });
    } catch (e) {
      onError(String(e));
    }
  }
  const filtered = rows.filter(
    (f) => (!severity || f.severity === severity) && (!status || f.status === status),
  );
  return (
    <section className="tool-view">
      <div className="toolbar">
        <h2>{t("app.view.findings")}</h2>
        <button type="button" disabled={!projectKey || busy} onClick={() => setDraft(emptyFinding())}>
          {t("findings.new")}
        </button>
        <button type="button" onClick={() => void exportReport(false)}>
          {t("findings.markdown")}
        </button>
        <button type="button" onClick={() => void exportReport(true)}>
          {t("findings.html")}
        </button>
      </div>
      <label>
        {t("findings.severity")}
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">{t("findings.all")}</option>
          {["info", "low", "medium", "high", "critical"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>
      <label>
        {t("findings.status")}
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">{t("findings.all")}</option>
          {["open", "confirmed", "false_positive", "fixed"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>
      <label>
        <input type="checkbox" checked={pcap} onChange={(e) => setPcap(e.target.checked)} />
        {t("findings.pcap")}
      </label>
      <p>
        {filtered.length} / {rows.length}
      </p>
      <Split orientation="columns" className="findings-layout" initial={[0.35, 0.65]} storageKey="findings">
        <div>
          {filtered.map((f) => (
            <button type="button" key={f.id} onClick={() => setDraft(f)}>
              {f.severity} · {f.status} · {f.title}
            </button>
          ))}
        </div>
        {draft && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run(rows.some((f) => f.id === draft.id) ? "update" : "create", { finding: draft });
            }}
          >
            <label>
              {t("findings.title")}
              <input
                required
                maxLength={200}
                value={draft.title}
                onChange={(e) => setDraft({ ...draft, title: e.target.value })}
              />
            </label>
            <label>
              {t("findings.severity")}
              <select
                value={draft.severity}
                onChange={(e) => setDraft({ ...draft, severity: e.target.value as FindingSeverity })}
              >
                {["info", "low", "medium", "high", "critical"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              {t("findings.status")}
              <select
                value={draft.status}
                onChange={(e) => setDraft({ ...draft, status: e.target.value as FindingStatus })}
              >
                {["open", "confirmed", "false_positive", "fixed"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              {t("findings.description")}
              <textarea
                maxLength={65536}
                value={draft.description}
                onChange={(e) => setDraft({ ...draft, description: e.target.value })}
              />
            </label>
            <label>
              {t("findings.steps")}
              <textarea
                maxLength={65536}
                value={draft.reproductionSteps}
                onChange={(e) => setDraft({ ...draft, reproductionSteps: e.target.value })}
              />
            </label>
            <label>
              {t("findings.tags")}
              <input
                value={draft.tags.join(",")}
                onChange={(e) => setDraft({ ...draft, tags: e.target.value.split(",") })}
              />
            </label>
            <button disabled={busy} type="submit">
              {t("findings.save")}
            </button>
            <button disabled={busy} type="button" onClick={() => void run("delete", { id: draft.id })}>
              {t("findings.delete")}
            </button>
            <h3>{t("findings.evidence")}</h3>
            {draft.evidence.map((e) => (
              <div key={`${e.kind}:${e.id}`}>
                {e.kind} #{e.id} {missing.includes(`${e.kind}:${e.id}`) && t("findings.missing")}
                {e.kind === "repeater" && (
                  <button
                    type="button"
                    onClick={() =>
                      window.dispatchEvent(new CustomEvent("finding-open-repeater", { detail: e.id }))
                    }
                  >
                    {t("findings.repeater")}
                  </button>
                )}
                {e.kind === "packet" && (
                  <button type="button" onClick={() => onPacket(e.id)}>
                    {t("findings.traffic")}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void run("remove_evidence", { id: draft.id, evidence: e })}
                >
                  {t("findings.remove")}
                </button>
              </div>
            ))}
          </form>
        )}
      </Split>
    </section>
  );
}
