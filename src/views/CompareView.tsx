import { ArrowLeftRight, Loader2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { EmptyState } from "../components/EmptyState";
import type { PacketView } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop, readPayload } from "../lib/desktop";
import { changedBytes, type DiffRun, diffBytes, diffFields, SEQUENCE_DIFF_LIMIT } from "../lib/diff";

/** Bytes compared at most; larger packets compare their leading part. */
const COMPARE_LIMIT = 1024 * 1024;
/** Equal bytes kept around each change before the rest is folded away. */
const CONTEXT = 8;

export interface CompareSlots {
  a: number | null;
  b: number | null;
}

interface Side {
  packet: PacketView;
  bytes: Uint8Array;
  complete: boolean;
}

/**
 * Two packets side by side: what changed in the bytes, and what changed in
 * the decode. The byte diff aligns insertions — a longer string, a grown
 * VarInt — instead of reporting every byte after them as different.
 */
export function CompareView({
  slots,
  onSwap,
  onClear,
  onError,
}: {
  slots: CompareSlots;
  onSwap: () => void;
  onClear: () => void;
  onError: (error: string) => void;
}) {
  const [a, setA] = useState<Side | null>(null);
  const [b, setB] = useState<Side | null>(null);
  const [loading, setLoading] = useState(false);
  const [onlyChanged, setOnlyChanged] = useState(true);

  useEffect(() => {
    let live = true;
    const load = async (id: number | null): Promise<Side | null> => {
      if (id === null || !desktop.isAvailable()) return null;
      const packet = await desktop.packet(id);
      if (!packet) return null;
      const { bytes, complete } = await readPayload(id, COMPARE_LIMIT);
      return { packet, bytes, complete };
    };
    setLoading(true);
    void Promise.all([load(slots.a), load(slots.b)])
      .then(([left, right]) => {
        if (!live) return;
        setA(left);
        setB(right);
      })
      .catch((reason) => live && onError(message(reason)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [onError, slots.a, slots.b]);

  const diff = useMemo(() => (a && b ? diffBytes(a.bytes, b.bytes) : null), [a, b]);
  const fields = useMemo(
    () => (a && b ? diffFields(a.packet.insight.fields, b.packet.insight.fields) : []),
    [a, b],
  );

  if (slots.a === null && slots.b === null) {
    return <EmptyState title={t("compare.empty.title")} detail={t("compare.empty.detail")} />;
  }

  const shownFields = onlyChanged ? fields.filter((row) => row.changed) : fields;

  return (
    <section className="compare-view">
      <header className="compare-header">
        <SideCard label="A" side={a} id={slots.a} />
        <button
          type="button"
          className="icon-button"
          aria-label={t("compare.swap")}
          title={t("compare.swap")}
          onClick={onSwap}
        >
          <ArrowLeftRight size={15} aria-hidden="true" />
        </button>
        <SideCard label="B" side={b} id={slots.b} />
        <button type="button" className="button" onClick={onClear}>
          {t("compare.clear")}
        </button>
      </header>
      {loading && (
        <p className="compare-status">
          <Loader2 className="spin" size={13} aria-hidden="true" /> {t("compare.loading")}
        </p>
      )}
      {a && b && diff ? (
        <div className="compare-body">
          <section className="compare-section">
            <h3>
              {t("compare.bytes")}
              <small>
                {changedBytes(diff.runs) === 0
                  ? t("compare.identical")
                  : t("compare.bytes.summary", {
                      changed: changedBytes(diff.runs),
                      a: a.packet.total_bytes,
                      b: b.packet.total_bytes,
                    })}
                {diff.positional && ` · ${t("compare.positional", { limit: SEQUENCE_DIFF_LIMIT / 1024 })}`}
                {(!a.complete || !b.complete) &&
                  ` · ${t("compare.truncated", { limit: (COMPARE_LIMIT / 1024).toLocaleString() })}`}
              </small>
            </h3>
            <ByteDiff runs={diff.runs} a={a.bytes} b={b.bytes} />
          </section>
          <section className="compare-section">
            <h3>
              {t("compare.fields")}
              <label className="check">
                <input
                  type="checkbox"
                  checked={onlyChanged}
                  onChange={(event) => setOnlyChanged(event.target.checked)}
                />
                {t("compare.only-changed")}
              </label>
            </h3>
            {shownFields.length === 0 ? (
              <p className="decoded-empty">
                {fields.length === 0 ? t("fields.none") : t("compare.fields.same")}
              </p>
            ) : (
              <table className="compare-fields">
                <thead>
                  <tr>
                    <th scope="col">{t("compare.field")}</th>
                    <th scope="col">A</th>
                    <th scope="col">B</th>
                  </tr>
                </thead>
                <tbody>
                  {shownFields.map((row) => (
                    <tr key={row.path} className={row.changed ? "changed" : ""}>
                      <th scope="row">{row.path}</th>
                      <td>{row.a ?? <em>{t("compare.absent")}</em>}</td>
                      <td>{row.b ?? <em>{t("compare.absent")}</em>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>
      ) : (
        !loading && <EmptyState title={t("compare.need-both.title")} detail={t("compare.need-both.detail")} />
      )}
    </section>
  );
}

function SideCard({ label, side, id }: { label: string; side: Side | null; id: number | null }) {
  if (id === null) {
    return (
      <div className="compare-side empty">
        <strong>{label}</strong>
        <small>{t("compare.unset")}</small>
      </div>
    );
  }
  const summary = side?.packet.summary;
  return (
    <div className="compare-side">
      <strong>{label}</strong>
      <span>
        {summary
          ? (summary.name ??
            (summary.packet_id === null ? t("table.raw-stream") : `0x${summary.packet_id.toString(16)}`))
          : `#${id}`}
      </span>
      {summary && (
        <small>
          #{summary.id} · {summary.direction === "client_to_server" ? t("flow.c2s") : t("flow.s2c")} ·{" "}
          {summary.state} · {side?.packet.total_bytes.toLocaleString()} B
        </small>
      )}
    </div>
  );
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

/**
 * The diff as hunks: each change with the offsets it sits at on both sides,
 * and long equal stretches folded down to a little context.
 */
function ByteDiff({ runs, a, b }: { runs: DiffRun[]; a: Uint8Array; b: Uint8Array }) {
  const lines: Array<{
    key: string;
    kind: "equal" | "delete" | "insert" | "fold";
    at: string;
    text: string;
  }> = [];
  runs.forEach((run, index) => {
    if (run.kind === "equal") {
      const first = index === 0;
      const last = index === runs.length - 1;
      const keepHead = first ? 0 : CONTEXT;
      const keepTail = last ? 0 : CONTEXT;
      if (run.length <= keepHead + keepTail + 4) {
        lines.push({
          key: `e${index}`,
          kind: "equal",
          at: `0x${run.aOffset.toString(16)}`,
          text: hexOf(a.subarray(run.aOffset, run.aOffset + run.length)),
        });
        return;
      }
      if (keepHead) {
        lines.push({
          key: `eh${index}`,
          kind: "equal",
          at: `0x${run.aOffset.toString(16)}`,
          text: hexOf(a.subarray(run.aOffset, run.aOffset + keepHead)),
        });
      }
      lines.push({
        key: `f${index}`,
        kind: "fold",
        at: "",
        text: t("compare.folded", { count: run.length - keepHead - keepTail }),
      });
      if (keepTail) {
        const start = run.aOffset + run.length - keepTail;
        lines.push({
          key: `et${index}`,
          kind: "equal",
          at: `0x${start.toString(16)}`,
          text: hexOf(a.subarray(start, start + keepTail)),
        });
      }
    } else if (run.kind === "delete") {
      lines.push({
        key: `d${index}`,
        kind: "delete",
        at: `A 0x${run.aOffset.toString(16)}`,
        text: hexOf(a.subarray(run.aOffset, run.aOffset + run.length)),
      });
    } else {
      lines.push({
        key: `i${index}`,
        kind: "insert",
        at: `B 0x${run.bOffset.toString(16)}`,
        text: hexOf(b.subarray(run.bOffset, run.bOffset + run.length)),
      });
    }
  });
  return (
    <ol className="byte-diff">
      {lines.map((line) => (
        <li key={line.key} className={`byte-diff-${line.kind}`}>
          <span className="byte-diff-mark" aria-hidden="true">
            {line.kind === "delete" ? "−" : line.kind === "insert" ? "+" : " "}
          </span>
          <span className="byte-diff-at">{line.at}</span>
          <span className="byte-diff-text">
            {line.kind === "delete" && <span className="visually-hidden">{t("compare.only-a")} </span>}
            {line.kind === "insert" && <span className="visually-hidden">{t("compare.only-b")} </span>}
            {line.text}
          </span>
        </li>
      ))}
    </ol>
  );
}
