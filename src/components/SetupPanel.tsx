import { useCallback, useEffect, useState } from "react";
import type { SetupCheck } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { desktop } from "../lib/desktop";
import { Modal } from "./Modal";

export function openSetup() {
  window.dispatchEvent(new Event("mineburp:setup"));
}

export function SetupPanel({ banner = false }: { banner?: boolean }) {
  const [checks, setChecks] = useState<SetupCheck[]>([]);
  const [expanded, setExpanded] = useState(!banner);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      setChecks(await desktop.setupCheck());
      setError("");
    } catch (reason) {
      setError(message(reason));
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    const show = () => setExpanded(true);
    window.addEventListener("mineburp:setup", show);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("mineburp:setup", show);
    };
  }, [refresh]);
  const failing = checks.some((check) => check.required && check.status === "fail");
  if (banner && !expanded && !failing && !error) return null;
  return (
    <section className="client-assist-card" aria-label="Setup">
      <button type="button" className="button" onClick={() => setExpanded(!expanded)}>
        Setup{failing ? " · Action required" : ""}
      </button>
      {expanded && (
        <Modal title="Setup" onClose={() => setExpanded(false)}>
          <button type="button" className="button" disabled={busy} onClick={() => void refresh()}>
            {busy ? "Checking…" : "Run checks"}
          </button>
          {error && <p role="alert">{error}</p>}
          <ul>
            {checks.map((check) => (
              <li key={check.id}>
                <strong>
                  {check.status.toUpperCase()} · {check.id.replaceAll("_", " ")}
                </strong>
                : {check.detail}
                {check.status !== "pass" && <p>{check.hint}</p>}
              </li>
            ))}
          </ul>
        </Modal>
      )}
    </section>
  );
}
