import { useEffect, useRef, useState } from "react";
import type { FieldSpan } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { useDocumentField, useProjectDocument } from "../hooks/useProjectDocument";
import { t } from "../i18n";
import { copyText, desktop } from "../lib/desktop";
import { delay } from "../lib/intruder";
import { registerProjectPreparation } from "../lib/projectWrites";
import { EMPTY_SEQUENCER, isSequencerDocument } from "../lib/researchDocuments";
import type { ResearchRequest } from "./IntruderView";

export function SequencerView({
  request,
  projectKey,
  onError,
}: {
  request: ResearchRequest | null;
  projectKey: string | null;
  onError: (error: string) => void;
}) {
  const document = useProjectDocument(projectKey, "sequencer", EMPTY_SEQUENCER, isSequencerDocument, onError);
  const [seed, setSeed] = useDocumentField(document.value, document.setValue, "seed");
  const [field, setField] = useDocumentField(document.value, document.setValue, "field");
  const [samples, setSamples] = useDocumentField(document.value, document.setValue, "samples");
  const [analysis, setAnalysis] = useDocumentField(document.value, document.setValue, "analysis");
  const [status, setStatus] = useDocumentField(document.value, document.setValue, "status");
  const [fields, setFields] = useState<FieldSpan[]>([]);
  const [running, setRunning] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const handledRequest = useRef<number | null>(null);
  const collected = useRef<string[] | null>(null);
  useEffect(
    () =>
      registerProjectPreparation(() => {
        controller.current?.abort();
        if (collected.current) setSamples(collected.current.join("\n"));
      }),
    [setSamples],
  );
  const analysisVersion = useRef(0);
  useEffect(() => {
    void projectKey;
    generation.current++;
    controller.current?.abort();
    setFields([]);
  }, [projectKey]);
  useEffect(
    () => () => {
      generation.current++;
      controller.current?.abort();
    },
    [],
  );
  useEffect(() => {
    if (!request || handledRequest.current === request.nonce) return;
    handledRequest.current = request.nonce;
    controller.current?.abort();
    const version = ++generation.current;
    setSeed(request.packet);
    setFields([]);
    setField("");
    setSamples("");
    setAnalysis(null);
    void desktop
      .packetLayoutStored(request.packet.summary.id)
      .then((layout) => {
        if (generation.current !== version) return;
        setFields(layout?.fields ?? []);
        setField(request.selection?.field ?? layout?.fields[0]?.name ?? "");
      })
      .catch((error) => {
        if (generation.current === version) onError(message(error));
      });
  }, [request, onError, setSeed, setField, setSamples, setAnalysis]);
  useEffect(() => {
    let live = true;
    if (seed)
      void desktop
        .packetLayoutStored(seed.summary.id)
        .then((layout) => {
          if (live) setFields(layout?.fields ?? []);
        })
        .catch((error) => {
          if (live) onError(message(error));
        });
    return () => {
      live = false;
    };
  }, [seed, onError]);
  const analyze = async () => {
    const version = generation.current;
    const analysisId = ++analysisVersion.current;
    setAnalysis(null);
    try {
      const result = await desktop.sequencerAnalyze(
        samples
          .replace(/\r/g, "")
          .split("\n")
          .filter((s) => s.length > 0),
      );
      if (generation.current === version && analysisVersion.current === analysisId) setAnalysis(result);
    } catch (error) {
      if (generation.current === version && analysisVersion.current === analysisId) onError(message(error));
    }
  };
  const collect = async (live: boolean) => {
    if (!seed || running || !field) return;
    analysisVersion.current++;
    const abort = new AbortController();
    controller.current = abort;
    setRunning(true);
    setAnalysis(null);
    setSamples("");
    const version = generation.current;
    const valid = () => !abort.signal.aborted && version === generation.current;
    const values: string[] = [];
    collected.current = values;
    let scanned = 0;
    let skipped = 0;
    let size = 0;
    try {
      let cursor = 0;
      if (live) {
        const latest = await desktop.packets({ connectionId: seed.summary.connection_id, limit: 1 });
        cursor = latest[0]?.id ?? 0;
      }
      while (valid() && scanned < 10_000) {
        const page = await desktop.packets({
          connectionId: seed.summary.connection_id,
          directions: [seed.summary.direction],
          states: [seed.summary.state],
          afterId: cursor,
          oldestFirst: true,
          limit: Math.min(250, 10_000 - scanned),
        });
        for (const packet of page) {
          if (!valid()) break;
          cursor = packet.id;
          scanned++;
          if (
            packet.packet_id !== seed.summary.packet_id ||
            packet.channel !== seed.summary.channel ||
            packet.protocol_version !== seed.summary.protocol_version
          ) {
            skipped++;
            continue;
          }
          const layout = await desktop.packetLayoutStored(packet.id);
          if (!valid()) break;
          const value = layout?.fields.find((f) => f.name === field)?.value;
          if (
            value === null ||
            value === undefined ||
            String(value).length === 0 ||
            String(value).includes("\n") ||
            String(value).includes("\r")
          ) {
            skipped++;
            continue;
          }
          const text = String(value);
          const bytes = new TextEncoder().encode(text).length;
          if (bytes > 4096 || size + bytes > 4 * 1024 * 1024) throw new Error(t("sequencer.limit"));
          size += bytes;
          values.push(text);
        }
        if (!valid()) break;
        setSamples(values.join("\n"));
        setStatus(t("sequencer.progress", { count: values.length, scanned, skipped }));
        if (!live && page.length < 250) break;
        if (live && page.length < 250) await delay(500, abort.signal);
      }
    } catch (error) {
      if (valid()) onError(message(error));
    } finally {
      if (controller.current === abort) {
        if (generation.current === version) {
          setSamples(values.join("\n"));
          setStatus(t("sequencer.progress", { count: values.length, scanned, skipped }));
        }
        setRunning(false);
        controller.current = null;
        collected.current = null;
      }
    }
  };
  return (
    <section className="research-view">
      <header>
        <h2>{t("app.view.sequencer")}</h2>
        <p>{t("sequencer.description")}</p>
        <p role="status">
          {projectKey ? t(`research.storage.${document.status}`) : t("research.storage.none")}
        </p>
      </header>
      {seed ? (
        <fieldset disabled={running} className="research-controls">
          <legend>{t("sequencer.source")}</legend>
          <p>
            {seed.summary.name ?? seed.summary.id} · {seed.summary.direction} ·{" "}
            {seed.summary.connection_id.slice(0, 8)}
          </p>
          <label>
            {t("sequencer.field")}
            <select value={field} onChange={(e) => setField(e.target.value)}>
              {fields.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name}
                </option>
              ))}
            </select>
          </label>
          <div className="research-toolbar">
            <button type="button" className="button" disabled={!field} onClick={() => void collect(false)}>
              {t("sequencer.history")}
            </button>
            <button type="button" className="button" disabled={!field} onClick={() => void collect(true)}>
              {t("sequencer.live")}
            </button>
          </div>
        </fieldset>
      ) : (
        <p>{t("sequencer.empty")}</p>
      )}
      <div className="research-toolbar">
        <button
          type="button"
          className="button"
          disabled={!running}
          onClick={() => controller.current?.abort()}
        >
          {t("research.stop")}
        </button>
        <span role="status">{status}</span>
      </div>
      <label>
        {t("sequencer.samples")}
        <textarea
          className="research-samples"
          rows={8}
          disabled={running}
          value={samples}
          onChange={(e) => {
            analysisVersion.current++;
            setSamples(e.target.value);
            setAnalysis(null);
          }}
        />
      </label>
      <button type="button" className="button" disabled={running || !samples} onClick={() => void analyze()}>
        {t("sequencer.analyze")}
      </button>
      <p>{t("sequencer.caveat")}</p>
      {analysis && (
        <>
          <button
            type="button"
            className="button"
            onClick={() =>
              void copyText(
                JSON.stringify(
                  {
                    field,
                    seedPacketId: seed?.summary.id ?? null,
                    analysis,
                    samples: samples.split("\n").filter(Boolean),
                  },
                  null,
                  2,
                ),
              ).catch((error) => onError(message(error)))
            }
          >
            {t("research.copy")}
          </button>
          <dl className="research-summary">
            <div>
              <dt>{t("sequencer.count")}</dt>
              <dd>{analysis.samples}</dd>
            </div>
            <div>
              <dt>{t("sequencer.unique")}</dt>
              <dd>{analysis.unique}</dd>
            </div>
            <div>
              <dt>{t("sequencer.duplicates")}</dt>
              <dd>{analysis.duplicates}</dd>
            </div>
            <div>
              <dt>{t("sequencer.lengths")}</dt>
              <dd>
                {analysis.min_length}–{analysis.max_length}
              </dd>
            </div>
            <div>
              <dt>{t("sequencer.adjacent")}</dt>
              <dd>{analysis.adjacent_equal}</dd>
            </div>
            <div>
              <dt>{t("sequencer.correlation")}</dt>
              <dd>{analysis.serial_correlation?.toFixed(4) ?? t("sequencer.undefined")}</dd>
            </div>
          </dl>
          <div className="research-results">
            <table>
              <thead>
                <tr>
                  {["offset", "count", "distinct", "entropy", "common"].map((k) => (
                    <th key={k}>{t(`sequencer.${k}` as Parameters<typeof t>[0])}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.positions.map((p) => (
                  <tr key={p.offset}>
                    <td>{p.offset}</td>
                    <td>{p.samples}</td>
                    <td>{p.distinct}</td>
                    <td>{p.entropy_bits.toFixed(4)}</td>
                    <td>{(p.most_common_fraction * 100).toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
