import { Loader2, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { describe } from "../components/PacketFilterBar";
import type {
  ConnectionSnapshot,
  NameStat,
  PacketFilter,
  ProjectInfo,
  SizeBucket,
  TrafficBucket,
  TrafficStats,
} from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { formatBytes } from "../lib/format";
import { formatAbsolute, formatSeconds } from "../lib/time";
import { useTrafficAppend, useTrafficConnections } from "../lib/trafficStore";

/** How often new traffic may re-run the statistics while the view is open. */
const AUTO_REFRESH_MS = 5_000;
export const STATS_OPTIONS = { maxBuckets: 120, top: 15 } as const;

type Metric = "packets" | "bytes";

/**
 * Counts, a timeline, rankings, and a size histogram for the history's current
 * filter. Every number comes from one backend aggregate over the whole
 * capture, not from the rows the table happens to have loaded.
 */
export function StatsView({
  project,
  filter,
  connectionId,
  connections: providedConnections,
  appendSignal: providedAppendSignal,
  onApplyName,
  onApplyConnection,
  onError,
}: {
  project: ProjectInfo | null;
  filter: PacketFilter;
  connectionId: string | null;
  connections?: ConnectionSnapshot[];
  appendSignal?: number;
  /** Narrows the history to one packet name and shows it. */
  onApplyName: (name: string) => void;
  /** Narrows the history to one connection and shows it. */
  onApplyConnection: (connectionId: string) => void;
  onError: (error: string) => void;
}) {
  const storedConnections = useTrafficConnections();
  const connections = providedConnections ?? storedConnections;
  const storeSignal = useTrafficAppend();
  const appendSignal = providedAppendSignal ?? storeSignal;
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [metric, setMetric] = useState<Metric>("packets");
  const [live, setLive] = useState(true);
  const request = useRef(0);
  const lastRun = useRef(0);

  const query = useMemo(
    () => ({ ...filter, search: filter.search.trim(), connectionId }),
    [filter, connectionId],
  );
  const queryKey = JSON.stringify(query);

  const load = useCallback(async () => {
    if (!project || !desktop.isAvailable()) return;
    const requestId = ++request.current;
    lastRun.current = Date.now();
    setLoading(true);
    try {
      const next = await desktop.trafficStats(JSON.parse(queryKey), STATS_OPTIONS);
      if (requestId === request.current) setStats(next);
    } catch (reason) {
      if (requestId === request.current) onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (requestId === request.current) setLoading(false);
    }
  }, [onError, project, queryKey]);

  useEffect(() => {
    void load();
  }, [load]);

  // New traffic re-runs the aggregate, at most every few seconds.
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    if (!live || appendSignal === 0) return undefined;
    const wait = Math.max(0, AUTO_REFRESH_MS - (Date.now() - lastRun.current));
    const timer = window.setTimeout(() => void loadRef.current(), wait);
    return () => window.clearTimeout(timer);
  }, [appendSignal, live]);

  const connectionLabels = useMemo(
    () => new Map(connections.map((c) => [c.id, `${c.target.host}:${c.target.port}`])),
    [connections],
  );

  if (!project) {
    return (
      <section className="stats-view empty">
        <p className="decoded-empty">{t("traffic.no-project.detail")}</p>
      </section>
    );
  }

  const scope = [
    describe(filter) ?? t("filter.all-packets"),
    connectionId ? (connectionLabels.get(connectionId) ?? connectionId.slice(0, 8)) : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <section className="stats-view" aria-label={t("stats.title")} aria-busy={loading}>
      <header className="stats-header">
        <div>
          <h2>{t("stats.title")}</h2>
          <p className="stats-scope">{t("stats.scope", { scope })}</p>
        </div>
        <div className="button-row">
          <fieldset className="segmented stats-metric">
            <legend className="visually-hidden">{t("stats.metric")}</legend>
            {(["packets", "bytes"] as const).map((value) => (
              <button
                type="button"
                key={value}
                className={metric === value ? "active" : ""}
                aria-pressed={metric === value}
                onClick={() => setMetric(value)}
              >
                {t(`stats.metric.${value}`)}
              </button>
            ))}
          </fieldset>
          <label className="stats-live">
            <input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />
            {t("stats.live")}
          </label>
          <button type="button" className="button" onClick={() => void load()} disabled={loading}>
            {loading ? (
              <Loader2 className="spin" size={13} aria-hidden="true" />
            ) : (
              <RefreshCw size={13} aria-hidden="true" />
            )}{" "}
            {t("stats.refresh")}
          </button>
        </div>
      </header>

      {!stats ? (
        <p className="decoded-empty">{t("stats.loading")}</p>
      ) : stats.totalPackets === 0 ? (
        <p className="decoded-empty">{t("stats.empty")}</p>
      ) : (
        <div className="stats-grid">
          <Totals stats={stats} />
          <section className="stats-card wide">
            <h3>{t("stats.timeline")}</h3>
            <Timeline buckets={stats.buckets} bucketMicros={stats.bucketMicros} metric={metric} />
          </section>
          <section className="stats-card">
            <h3>{t("stats.top-count")}</h3>
            <Ranking entries={stats.topByCount} metric="packets" onApply={onApplyName} />
          </section>
          <section className="stats-card">
            <h3>{t("stats.top-bytes")}</h3>
            <Ranking entries={stats.topByBytes} metric="bytes" onApply={onApplyName} />
          </section>
          <section className="stats-card">
            <h3>{t("stats.top-connections")}</h3>
            <BarList
              entries={stats.topConnections.map((entry) => ({
                key: entry.connectionId,
                label: connectionLabels.get(entry.connectionId) ?? entry.connectionId.slice(0, 8),
                value: metric === "bytes" ? entry.bytes : entry.packets,
                detail: `${entry.packets.toLocaleString()} · ${formatBytes(entry.bytes)}`,
                onSelect: () => onApplyConnection(entry.connectionId),
                title: t("stats.apply-connection"),
              }))}
            />
          </section>
          <section className="stats-card">
            <h3>{t("stats.sizes")}</h3>
            <Histogram buckets={stats.sizeHistogram} />
          </section>
        </div>
      )}
    </section>
  );
}

function Totals({ stats }: { stats: TrafficStats }) {
  const span =
    stats.firstTimestampMicros !== null && stats.lastTimestampMicros !== null
      ? stats.lastTimestampMicros - stats.firstTimestampMicros
      : null;
  const tiles = [
    {
      label: t("stats.total"),
      value: stats.totalPackets.toLocaleString(),
      detail: formatBytes(stats.totalBytes),
    },
    {
      label: t("flow.c2s"),
      value: stats.clientToServerPackets.toLocaleString(),
      detail: formatBytes(stats.clientToServerBytes),
      className: "client_to_server",
    },
    {
      label: t("flow.s2c"),
      value: stats.serverToClientPackets.toLocaleString(),
      detail: formatBytes(stats.serverToClientBytes),
      className: "server_to_client",
    },
    {
      label: t("stats.duration"),
      value: span === null ? "—" : formatSeconds(span),
      detail:
        stats.firstTimestampMicros === null
          ? ""
          : t("stats.since", { time: formatAbsolute(stats.firstTimestampMicros) }),
    },
  ];
  return (
    <dl className="stats-totals">
      {tiles.map((tile) => (
        <div key={tile.label} className={`stats-tile ${tile.className ?? ""}`}>
          <dt>{tile.label}</dt>
          <dd>
            <strong>{tile.value}</strong>
            <small>{tile.detail}</small>
          </dd>
        </div>
      ))}
    </dl>
  );
}

const CHART_HEIGHT = 140;

/** Stacked bars per time bucket: client to server below, server to client on top. */
function Timeline({
  buckets,
  bucketMicros,
  metric,
}: {
  buckets: TrafficBucket[];
  bucketMicros: number;
  metric: Metric;
}) {
  const values = buckets.map((bucket) =>
    metric === "bytes"
      ? { c2s: bucket.clientToServerBytes, s2c: bucket.serverToClientBytes }
      : { c2s: bucket.clientToServerPackets, s2c: bucket.serverToClientPackets },
  );
  const peak = Math.max(1, ...values.map((value) => value.c2s + value.s2c));
  const width = Math.max(1, buckets.length);
  const format = (value: number) => (metric === "bytes" ? formatBytes(value) : value.toLocaleString());
  const first = buckets[0];
  const last = buckets.at(-1);
  return (
    <figure className="stats-timeline">
      <svg
        viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={t("stats.timeline.aria", {
          buckets: buckets.length,
          width: formatSeconds(bucketMicros),
          peak: format(peak),
        })}
      >
        {values.map((value, index) => {
          const bucket = buckets[index];
          if (!bucket) return null;
          const c2s = (value.c2s / peak) * CHART_HEIGHT;
          const s2c = (value.s2c / peak) * CHART_HEIGHT;
          return (
            <g key={bucket.startMicros}>
              <title>
                {`${formatAbsolute(bucket.startMicros)} — ${t("flow.c2s")} ${format(value.c2s)}, ${t("flow.s2c")} ${format(value.s2c)}`}
              </title>
              <rect
                className="bar client_to_server"
                x={index + 0.08}
                width={0.84}
                y={CHART_HEIGHT - c2s}
                height={c2s}
              />
              <rect
                className="bar server_to_client"
                x={index + 0.08}
                width={0.84}
                y={CHART_HEIGHT - c2s - s2c}
                height={s2c}
              />
            </g>
          );
        })}
      </svg>
      <figcaption>
        <span>{first ? formatAbsolute(first.startMicros) : ""}</span>
        <span className="stats-legend">
          <i className="swatch client_to_server" aria-hidden="true" /> {t("flow.c2s")}
          <i className="swatch server_to_client" aria-hidden="true" /> {t("flow.s2c")}
          <span>· {t("stats.peak", { peak: format(peak), width: formatSeconds(bucketMicros) })}</span>
        </span>
        <span>{last ? formatAbsolute(last.startMicros + bucketMicros) : ""}</span>
      </figcaption>
    </figure>
  );
}

function Ranking({
  entries,
  metric,
  onApply,
}: {
  entries: NameStat[];
  metric: Metric;
  onApply: (name: string) => void;
}) {
  return (
    <BarList
      entries={entries.map((entry, index) => ({
        key: entry.name ?? `unnamed-${index}`,
        label: entry.name ?? t("stats.unnamed"),
        value: metric === "bytes" ? entry.bytes : entry.packets,
        detail: `${entry.packets.toLocaleString()} · ${formatBytes(entry.bytes)}`,
        onSelect: entry.name ? () => onApply(entry.name as string) : undefined,
        title: entry.name ? t("stats.apply-name", { name: entry.name }) : undefined,
      }))}
    />
  );
}

interface BarEntry {
  key: string;
  label: string;
  value: number;
  detail: string;
  onSelect?: () => void;
  title?: string;
}

/** A ranked list with each value drawn as a bar relative to the largest. */
function BarList({ entries }: { entries: BarEntry[] }) {
  if (entries.length === 0) return <p className="decoded-empty">{t("stats.none")}</p>;
  const peak = Math.max(1, ...entries.map((entry) => entry.value));
  return (
    <ol className="stats-bars">
      {entries.map((entry) => {
        const content = (
          <>
            <span className="stats-bar-label">{entry.label}</span>
            <span className="stats-bar-track" aria-hidden="true">
              <span className="stats-bar-fill" style={{ width: `${(entry.value / peak) * 100}%` }} />
            </span>
            <span className="stats-bar-value">{entry.detail}</span>
          </>
        );
        return (
          <li key={entry.key}>
            {entry.onSelect ? (
              <button type="button" className="stats-bar" title={entry.title} onClick={entry.onSelect}>
                {content}
              </button>
            ) : (
              <span className="stats-bar">{content}</span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function Histogram({ buckets }: { buckets: SizeBucket[] }) {
  return (
    <BarList
      entries={buckets.map((bucket) => ({
        key: String(bucket.min),
        label:
          bucket.max === null
            ? `≥ ${formatBytes(bucket.min)}`
            : `${formatBytes(bucket.min)} – ${formatBytes(bucket.max)}`,
        value: bucket.packets,
        detail: bucket.packets.toLocaleString(),
      }))}
    />
  );
}
