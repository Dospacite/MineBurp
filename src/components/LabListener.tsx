import { useCallback, useEffect, useState } from "react";
import { message } from "../hooks/useMineBurp";
import { desktop } from "../lib/desktop";

// Survives the panel unmounting with its view, so switching tabs does not
// lose the address of a listener that is still armed in the backend.
let remembered: [string, string] | null = null;

export function LabListener({ onError }: { onError: (error: string) => void }) {
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("25565");
  const [armed, setArmed] = useState(false);
  const [listener, setListenerState] = useState<[string, string] | null>(remembered);
  const setListener = useCallback((next: [string, string] | null) => {
    remembered = next;
    setListenerState(next);
  }, []);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!listener) return;
    const timer = window.setInterval(() => {
      void desktop
        .labListenerActive(listener[0])
        .then((active) => {
          if (!active) setListener(null);
        })
        .catch((error) => onError(message(error)));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [listener, onError, setListener]);
  async function toggle() {
    setBusy(true);
    try {
      if (listener) {
        await desktop.labListenerStop(listener[0]);
        setListener(null);
      } else {
        setListener(await desktop.labListenerStart(host, Number(port), armed));
      }
    } catch (error) {
      onError(message(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <details className="lab-listener">
      <summary>Lab listener</summary>
      <fieldset disabled={busy}>
        <label>
          Target host
          <input
            disabled={listener !== null}
            value={host}
            onChange={(event) => setHost(event.target.value)}
          />
        </label>
        <label>
          Target port
          <input
            disabled={listener !== null}
            type="number"
            min="1"
            max="65535"
            value={port}
            onChange={(event) => setPort(event.target.value)}
          />
        </label>
        <label className="checkbox-row">
          <input
            disabled={listener !== null}
            type="checkbox"
            checked={armed}
            onChange={(event) => setArmed(event.target.checked)}
          />
          Stay armed
        </label>
        <p className="project-hint">
          Loopback only. Up to 8 concurrent clients. Stops after 60 seconds without a new connection.
        </p>
        <button
          type="button"
          className="button"
          disabled={
            !host.trim() || !Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535
          }
          onClick={() => void toggle()}
        >
          {listener ? "Stop listener" : "Create listener"}
        </button>
        {listener && (
          <label>
            Loopback address
            <input readOnly value={listener[1]} onFocus={(event) => event.target.select()} />
            <button
              type="button"
              onClick={() =>
                void navigator.clipboard.writeText(listener[1]).catch((error) => onError(message(error)))
              }
            >
              Copy address
            </button>
          </label>
        )}
      </fieldset>
    </details>
  );
}
