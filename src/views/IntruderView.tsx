import { memo, useEffect, useRef, useState } from "react";
import { PayloadGeneratorDialog } from "../components/PayloadGeneratorDialog";
import type { AttackMode, ConnectionSnapshot, FieldSpan, PacketView } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { useDocumentField, useProjectDocument } from "../hooks/useProjectDocument";
import { t } from "../i18n";
import { copyText, desktop, formatHexInput, readPayload } from "../lib/desktop";
import { newId } from "../lib/ids";
import { caseEdits, delay, payloadLists, validatePositions } from "../lib/intruder";
import { registerProjectPreparation } from "../lib/projectWrites";
import {
  type IntruderAttempt as Attempt,
  EMPTY_INTRUDER,
  isIntruderDocument,
} from "../lib/researchDocuments";
import { useTrafficConnections } from "../lib/trafficStore";

export interface ResearchRequest {
  packet: PacketView;
  nonce: number;
  selection?: { field?: string; offset: number; length: number; value?: string | number | boolean | null };
}
interface Props {
  request: ResearchRequest | null;
  sessions?: ConnectionSnapshot[];
  projectKey: string | null;
  onError: (error: string) => void;
}

function IntruderViewImpl({ request, sessions: providedConnections, projectKey, onError }: Props) {
  const storedConnections = useTrafficConnections();
  const sessions = providedConnections ?? storedConnections;
  const document = useProjectDocument(projectKey, "intruder", EMPTY_INTRUDER, isIntruderDocument, onError);
  const [seed, setSeed] = useDocumentField(document.value, document.setValue, "seed");
  const [positions, setPositions] = useDocumentField(document.value, document.setValue, "positions");
  const [mode, setMode] = useDocumentField(document.value, document.setValue, "mode");
  const [connection, setConnection] = useDocumentField(document.value, document.setValue, "connection");
  const [windowMs, setWindowMs] = useDocumentField(document.value, document.setValue, "windowMs");
  const [fields, setFields] = useState<FieldSpan[]>([]);
  const [generatorIndex, setGeneratorIndex] = useState<number | null>(null);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useDocumentField(document.value, document.setValue, "results");
  const [previewHex, setPreviewHex] = useDocumentField(document.value, document.setValue, "previewHex");
  const [progress, setProgress] = useDocumentField(document.value, document.setValue, "progress");
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const handledRequest = useRef<number | null>(null);
  useEffect(
    () =>
      registerProjectPreparation(() => {
        controller.current?.abort();
      }),
    [],
  );
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
    setConnection(request.packet.summary.connection_id);
    setResults([]);
    setPreviewHex("");
    setFields([]);
    setPositions([]);
    void desktop
      .packetLayoutStored(request.packet.summary.id)
      .then((layout) => {
        if (generation.current !== version) return;
        const editable = layout?.fields ?? [];
        setFields(editable);
        const selection = request.selection;
        const chosen = selection?.field
          ? editable.find((field) => field.name === selection.field)
          : editable[0];
        setPositions(
          selection && !selection.field
            ? [
                {
                  id: newId(),
                  field: "@raw",
                  offset: selection.offset,
                  length: selection.length,
                  payloads: "00",
                },
              ]
            : chosen
              ? [{ id: newId(), field: chosen.name, payloads: String(chosen.value ?? "") }]
              : [],
        );
      })
      .catch((error) => {
        if (generation.current === version) onError(message(error));
      });
  }, [request, onError, setSeed, setConnection, setResults, setPreviewHex, setPositions]);

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

  const execute = async (preview: boolean) => {
    if (!seed || running) return;
    const version = generation.current;
    const abort = new AbortController();
    controller.current = abort;
    setRunning(true);
    setResults([]);
    const valid = () => !abort.signal.aborted && version === generation.current;
    let pending: Attempt | null = null;
    try {
      if (!validatePositions(positions)) throw new Error(t("intruder.positions-error"));
      const lists = payloadLists(positions);
      if (
        lists.some((list) => list.length > 1000 || list.some((value) => value.length > 4096)) ||
        lists.flat().reduce((sum, value) => sum + value.length, 0) > 4 * 1024 * 1024
      )
        throw new Error(t("intruder.payload-error"));
      const plan = await desktop.intruderPlan(
        mode,
        lists.map((list) => list.length),
      );
      const { bytes, complete } = await readPayload(seed.summary.id, 1024 * 1024);
      if (!complete) throw new Error(t("intruder.large"));
      const cases = preview ? plan.slice(0, 1) : plan;
      for (const [index, row] of cases.entries()) {
        if (!valid()) break;
        const edits = caseEdits(mode, positions, lists, row);
        const started = performance.now();
        pending = {
          index: index + 1,
          payloads: edits
            .map((e) => JSON.stringify(e))
            .join(", ")
            .slice(0, 2048),
          bytes: 0,
          elapsed: 0,
          result: "",
          observed: 0,
          observedBytes: 0,
        };
        const frame = await desktop.replacementPreview(
          bytes,
          seed.summary.state,
          seed.summary.direction,
          edits,
          seed.summary.protocol_version,
        );
        if (!valid()) break;
        if (preview) setPreviewHex(formatHexInput(frame));
        let observed = 0;
        let observedBytes = 0;
        if (!preview) {
          const active = await desktop.proxySessions();
          if (!valid()) break;
          const session = active.find((s) => s.id === connection && s.status === "active");
          if (
            !session ||
            session.state !== seed.summary.state ||
            session.protocol_version !== seed.summary.protocol_version
          )
            throw new Error(t("intruder.session-error"));
          const latest = await desktop.packets({ connectionId: connection, limit: 1 });
          if (!valid()) break;
          await desktop.repeaterSend(connection, seed.summary.direction, frame);
          await delay(windowMs, abort.signal);
          if (!valid()) {
            if (version === generation.current)
              setResults((old) => [
                ...old,
                {
                  index: index + 1,
                  payloads: edits.map((e) => JSON.stringify(e)).join(", "),
                  bytes: frame.length,
                  elapsed: Math.round(performance.now() - started),
                  result: t("intruder.sent-stopped"),
                  observed: 0,
                  observedBytes: 0,
                },
              ]);
            break;
          }
          const traffic = await desktop.packets({
            connectionId: connection,
            afterId: latest[0]?.id ?? 0,
            oldestFirst: true,
            directions: [
              seed.summary.direction === "client_to_server" ? "server_to_client" : "client_to_server",
            ],
            limit: 251,
          });
          observed = traffic.length;
          observedBytes = traffic.reduce((sum, p) => sum + p.size, 0);
        }
        if (!valid()) break;
        setResults((old) => [
          ...old,
          {
            index: index + 1,
            payloads: edits
              .map((e) =>
                e.kind === "field"
                  ? `${e.name}=${e.value}`
                  : e.kind === "range"
                    ? `@${e.offset}:${e.length}=${e.bytes}`
                    : "",
              )
              .join(", ")
              .slice(0, 2048),
            bytes: frame.length,
            elapsed: Math.round(performance.now() - started),
            result: t(preview ? "intruder.previewed" : "intruder.sent"),
            observed,
            observedBytes,
          },
        ]);
        pending = null;
        setProgress(`${index + 1} / ${cases.length}`);
      }
      if (!abort.signal.aborted && version === generation.current) setProgress(t("intruder.complete"));
    } catch (error) {
      if (valid()) {
        const failure = pending;
        if (failure) setResults((old) => [...old, { ...failure, result: message(error) }]);
        setProgress(t("intruder.stopped-error"));
        onError(message(error));
      }
    } finally {
      if (controller.current === abort) {
        setRunning(false);
        controller.current = null;
      }
    }
  };
  return (
    <section className="research-view">
      <header>
        <h2>{t("app.view.intruder")}</h2>
        <p>{t("intruder.description")}</p>
        <p role="status">
          {projectKey ? t(`research.storage.${document.status}`) : t("research.storage.none")}
        </p>
      </header>
      {!seed ? (
        <p>{t("research.empty")}</p>
      ) : (
        <>
          <p>
            {seed.summary.name ?? seed.summary.id} · {seed.summary.direction} · {seed.summary.state}
          </p>
          <fieldset disabled={running} className="research-controls">
            <legend>{t("intruder.configuration")}</legend>
            <label>
              {t("intruder.mode")}
              <select value={mode} onChange={(e) => setMode(e.target.value as AttackMode)}>
                <option value="sniper">Sniper</option>
                <option value="battering_ram">Battering ram</option>
                <option value="pitchfork">Pitchfork</option>
                <option value="cluster_bomb">Cluster bomb</option>
              </select>
            </label>
            <p>{t(`intruder.mode.${mode}`)}</p>
            <label>
              {t("intruder.connection")}
              <select value={connection} onChange={(e) => setConnection(e.target.value)}>
                <option value="">{t("intruder.choose")}</option>
                {sessions
                  .filter((s) => s.status === "active")
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target.host}:{s.target.port} · {s.id.slice(0, 8)}
                    </option>
                  ))}
              </select>
            </label>
            <label>
              {t("intruder.window")}
              <input
                type="number"
                min={50}
                max={60000}
                value={windowMs}
                onChange={(e) => setWindowMs(Math.max(50, Math.min(60000, Number(e.target.value) || 250)))}
              />
            </label>
            {positions.map((p, i) => (
              <div className="research-position" key={p.id ?? p.field}>
                <label>
                  {t("intruder.field", { index: i + 1 })}
                  <select
                    value={p.field}
                    onChange={(e) =>
                      setPositions((old) =>
                        old.map((v, j) =>
                          j === i ? { ...v, field: e.target.value, offset: 0, length: 1 } : v,
                        ),
                      )
                    }
                  >
                    <option value="@raw">{t("intruder.raw")}</option>
                    {fields.map((f) => (
                      <option key={f.name} value={f.name}>
                        {f.name} · {f.kind}
                      </option>
                    ))}
                  </select>
                </label>
                {p.field === "@raw" && (
                  <div className="research-toolbar">
                    <label>
                      {t("intruder.offset")}
                      <input
                        type="number"
                        min={0}
                        value={p.offset ?? 0}
                        onChange={(e) =>
                          setPositions((old) =>
                            old.map((v, j) => (j === i ? { ...v, offset: Number(e.target.value) } : v)),
                          )
                        }
                      />
                    </label>
                    <label>
                      {t("intruder.length")}
                      <input
                        type="number"
                        min={1}
                        value={p.length ?? 1}
                        onChange={(e) =>
                          setPositions((old) =>
                            old.map((v, j) => (j === i ? { ...v, length: Number(e.target.value) } : v)),
                          )
                        }
                      />
                    </label>
                  </div>
                )}
                {mode !== "battering_ram" || i === 0 ? (
                  <label>
                    {t("intruder.payloads")}
                    <textarea
                      rows={4}
                      value={p.payloads}
                      onChange={(e) =>
                        setPositions((old) =>
                          old.map((v, j) => (j === i ? { ...v, payloads: e.target.value } : v)),
                        )
                      }
                    />
                  </label>
                ) : null}
                <button
                  type="button"
                  className="button"
                  disabled={running}
                  onClick={() => setGeneratorIndex(i)}
                >
                  {t("payload.open")}
                </button>
                <button
                  type="button"
                  className="button"
                  onClick={() => setPositions((old) => old.filter((_, j) => j !== i))}
                >
                  {t("research.remove")}
                </button>
              </div>
            ))}
            <button
              type="button"
              className="button"
              disabled={positions.length >= 16}
              onClick={() => {
                const f = fields.find((f) => !positions.some((p) => p.field === f.name));
                setPositions([
                  ...positions,
                  f
                    ? { id: newId(), field: f.name, payloads: String(f.value ?? "") }
                    : { id: newId(), field: "@raw", offset: 0, length: 1, payloads: "00" },
                ]);
              }}
            >
              {t("intruder.add")}
            </button>
          </fieldset>
          <div className="research-toolbar">
            <button
              type="button"
              className="button"
              disabled={running || !document.loaded || !positions.length}
              onClick={() => void execute(true)}
            >
              {t("intruder.preview")}
            </button>
            <button
              type="button"
              className="button"
              disabled={running || !document.loaded || !positions.length || !connection}
              onClick={() => void execute(false)}
            >
              {t("intruder.start")}
            </button>
            <button
              type="button"
              className="button"
              disabled={!running}
              onClick={() => {
                controller.current?.abort();
                setProgress(t("intruder.cancelled"));
              }}
            >
              {t("research.stop")}
            </button>
            <button
              type="button"
              className="button"
              disabled={running || !results.length}
              onClick={() =>
                void copyText(
                  JSON.stringify(
                    {
                      mode,
                      positions,
                      connection,
                      observationWindowMs: windowMs,
                      seedPacketId: seed.summary.id,
                      results,
                    },
                    null,
                    2,
                  ),
                ).catch((error) => onError(message(error)))
              }
            >
              {t("research.copy")}
            </button>
            <span role="status">{progress}</span>
          </div>
          <p>{t("intruder.observation-note")}</p>
          {previewHex && (
            <label>
              {t("intruder.preview-hex")}
              <textarea rows={4} readOnly value={previewHex} />
            </label>
          )}
          <div className="research-results">
            <table>
              <thead>
                <tr>
                  {["attempt", "payload", "bytes", "elapsed", "result", "observed", "observed-bytes"].map(
                    (k) => (
                      <th key={k}>{t(`research.${k}` as Parameters<typeof t>[0])}</th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {results.map((r) => (
                  <tr key={r.index}>
                    <td>{r.index}</td>
                    <td>{r.payloads}</td>
                    <td>{r.bytes}</td>
                    <td>{r.elapsed}</td>
                    <td>{r.result}</td>
                    <td>{r.observed >= 251 ? "251+" : r.observed}</td>
                    <td>{r.observedBytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {generatorIndex !== null && (
        <PayloadGeneratorDialog
          onClose={() => setGeneratorIndex(null)}
          onApply={(payloads) => {
            setPositions((old) => old.map((p, i) => (i === generatorIndex ? { ...p, payloads } : p)));
            setGeneratorIndex(null);
          }}
          onError={onError}
        />
      )}
    </section>
  );
}

export const IntruderView = memo(IntruderViewImpl);
