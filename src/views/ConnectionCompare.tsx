import { useEffect, useMemo, useRef, useState } from "react";
import { VirtualRows, type VirtualRowsHandle } from "../components/VirtualRows";
import type {
  ConnectionComparison,
  ConnectionSnapshot,
  PacketHistoryQuery,
  PacketSummary,
} from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { PacketCompareView } from "./CompareView";

export function ConnectionCompare({
  filter,
  onError,
  onTraffic,
}: {
  filter: PacketHistoryQuery;
  onError: (error: string) => void;
  onTraffic?: (packet: PacketSummary) => void;
}) {
  const [connections, setConnections] = useState<ConnectionSnapshot[]>([]);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [scoped, setScoped] = useState(false);
  const [hide, setHide] = useState(false);
  const [direction, setDirection] = useState("");
  const [result, setResult] = useState<ConnectionComparison | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(-1);
  const [swapped, setSwapped] = useState(false);
  const handle = useRef<VirtualRowsHandle | null>(null);
  useEffect(() => {
    if (!desktop.isAvailable()) return;
    let live = true;
    void desktop
      .connections(true)
      .then((rows) => {
        if (live) {
          setConnections(rows);
          setA(rows[0]?.id ?? "");
          setB(rows[1]?.id ?? "");
        }
      })
      .catch((e) => onError(message(e)));
    return () => {
      live = false;
    };
  }, [onError]);
  const rows = useMemo(
    () =>
      result?.rows.filter(
        (r) => (!hide || r.kind !== "identical") && (!direction || (r.a ?? r.b)?.direction === direction),
      ) ?? [],
    [result, hide, direction],
  );
  const counts = useMemo(
    () =>
      Object.fromEntries(
        ["identical", "changed", "only_a", "only_b"].map((kind) => [
          kind,
          result?.rows.filter((r) => r.kind === kind).length ?? 0,
        ]),
      ),
    [result],
  );
  const run = async () => {
    setBusy(true);
    setResult(null);
    setSelected(-1);
    try {
      setResult(await desktop.compareConnections(a, b, scoped ? filter : {}));
    } catch (e) {
      onError(message(e));
    } finally {
      setBusy(false);
    }
  };
  const next = (step: number) => {
    for (let n = 1; n <= rows.length; n++) {
      const start = selected < 0 ? (step > 0 ? -1 : 0) : selected;
      const i = (((start + step * n) % rows.length) + rows.length) % rows.length;
      if (rows[i]?.kind !== "identical") {
        setSelected(i);
        handle.current?.revealRow(i, "center")?.focus();
        break;
      }
    }
  };
  const current = rows[selected];
  return (
    <section
      aria-label={t("compare.connections")}
      className="connection-compare"
      onKeyDown={(event) => {
        if ((event.target as HTMLElement).matches("input,select,textarea")) return;
        if (event.key === "F7" || event.key === "n" || event.key === "p") {
          event.preventDefault();
          next(event.shiftKey || event.key === "p" ? -1 : 1);
        }
      }}
    >
      <div className="compare-header">
        {([a, b] as const).map((value, i) => (
          <label key={i === 0 ? "A" : "B"}>
            {i === 0 ? "A" : "B"}
            <select
              aria-label={`Connection ${i === 0 ? "A" : "B"}`}
              value={value}
              onChange={(e) => (i === 0 ? setA : setB)(e.target.value)}
            >
              {connections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.target.host}:{c.target.port} · {c.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
        ))}
        <label>
          <input type="checkbox" checked={scoped} onChange={(e) => setScoped(e.target.checked)} />
          {t("compare.traffic-filter")}
        </label>
        <button type="button" className="button" disabled={!a || !b || busy} onClick={() => void run()}>
          {busy ? t("compare.loading") : t("compare.run")}
        </button>
      </div>
      <div className="compare-header">
        <label>
          <input
            type="checkbox"
            checked={hide}
            onChange={(e) => {
              setHide(e.target.checked);
              setSelected(-1);
            }}
          />
          {t("compare.hide-identical")}
        </label>
        <select
          aria-label={t("compare.direction")}
          value={direction}
          onChange={(e) => {
            setDirection(e.target.value);
            setSelected(-1);
          }}
        >
          <option value="">{t("compare.all-directions")}</option>
          <option value="client_to_server">{t("flow.c2s")}</option>
          <option value="server_to_client">{t("flow.s2c")}</option>
        </select>
        <button type="button" className="button" onClick={() => next(-1)}>
          {t("compare.previous")}
        </button>
        <button type="button" className="button" onClick={() => next(1)}>
          {t("compare.next")}
        </button>
      </div>
      {result && (
        <>
          <p role="status">{t("compare.connection-summary", counts)}</p>
          <VirtualRows
            items={rows}
            rowHeight={38}
            activeIndex={Math.max(0, selected)}
            handleRef={(value) => {
              handle.current = value;
            }}
            style={{ height: 380 }}
            ariaLabel={t("compare.connections")}
            renderRow={(row, index) => (
              <button
                type="button"
                tabIndex={index === Math.max(0, selected) ? 0 : -1}
                aria-pressed={index === selected}
                className={`connection-compare-row compare-${row.kind}`}
                onClick={() => setSelected(index)}
              >
                <span>{t(`compare.kind.${row.kind}`)}</span>
                <span>{row.a ? `#${row.a.id} ${row.a.state} ${row.a.name ?? "?"}` : "—"}</span>
                <span>{row.b ? `#${row.b.id} ${row.b.state} ${row.b.name ?? "?"}` : "—"}</span>
                <span>
                  {row.size_delta > 0 ? "+" : ""}
                  {row.size_delta} B {row.first_difference !== null ? `@${row.first_difference}` : ""}
                </span>
              </button>
            )}
          />
          {current && (
            <div className="compare-header">
              {[current.a, current.b].map(
                (packet, i) =>
                  packet && (
                    <button
                      type="button"
                      className="button"
                      key={i === 0 ? "A" : "B"}
                      onClick={() => onTraffic?.(packet)}
                    >
                      {t("compare.show-traffic")} {i === 0 ? "A" : "B"} #{packet.id}
                    </button>
                  ),
              )}
            </div>
          )}
          {current?.kind === "changed" && (
            <PacketCompareView
              slots={{
                a: (swapped ? current.b : current.a)?.id ?? null,
                b: (swapped ? current.a : current.b)?.id ?? null,
              }}
              onSwap={() => setSwapped((value) => !value)}
              onClear={() => setSelected(-1)}
              onError={onError}
            />
          )}
          <table className="compare-fields">
            <thead>
              <tr>
                <th>{t("compare.name")}</th>
                <th>A</th>
                <th>B</th>
                <th>{t("compare.differ")}</th>
              </tr>
            </thead>
            <tbody>
              {result.names.map((r) => (
                <tr key={r.name}>
                  <th>{r.name}</th>
                  <td>{r.a}</td>
                  <td>{r.b}</td>
                  <td>{r.differ}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
