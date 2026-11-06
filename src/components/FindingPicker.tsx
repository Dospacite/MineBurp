import { useEffect, useState } from "react";
import type { Finding, FindingEvidence } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { emptyFinding } from "../views/FindingsView";
import { Modal } from "./Modal";
export function addToFinding(evidence: FindingEvidence[]) {
  window.dispatchEvent(new CustomEvent("finding-picker", { detail: evidence }));
}
export function FindingPicker({
  projectKey,
  onError,
}: {
  projectKey: string | null;
  onError: (s: string) => void;
}) {
  const [evidence, setEvidence] = useState<FindingEvidence[] | null>(null);
  const [rows, setRows] = useState<Finding[]>([]);
  const [id, setId] = useState("");
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const open = (event: Event) => {
      setEvidence((event as CustomEvent<FindingEvidence[]>).detail);
      setId("");
      if (projectKey)
        void desktop
          .findings(projectKey, "list")
          .then(setRows)
          .catch((e) => onError(String(e)));
    };
    window.addEventListener("finding-picker", open);
    return () => window.removeEventListener("finding-picker", open);
  }, [projectKey, onError]);
  async function submit() {
    if (!projectKey || !evidence) return;
    setBusy(true);
    try {
      if (!id)
        await desktop.findings(projectKey, "create", { finding: { ...emptyFinding(), title, evidence } });
      else
        for (const link of evidence)
          await desktop.findings(projectKey, "add_evidence", { id, evidence: link });
      setEvidence(null);
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    evidence && (
      <Modal
        title={t("findings.add")}
        onClose={() => {
          if (!busy) setEvidence(null);
        }}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <label>
            {t("app.view.findings")}
            <select value={id} onChange={(e) => setId(e.target.value)}>
              <option value="">{t("findings.new")}</option>
              {rows.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.title}
                </option>
              ))}
            </select>
          </label>
          {!id && (
            <label>
              {t("findings.title")}
              <input required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
            </label>
          )}
          <button type="submit" disabled={busy || !projectKey}>
            {t("findings.save")}
          </button>
        </form>
      </Modal>
    )
  );
}
