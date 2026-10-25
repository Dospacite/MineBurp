import { FileUp, Loader2 } from "lucide-react";
import { useState } from "react";

import type { ImportSummary } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { chooseCaptureToImport } from "../lib/files";
import { formatBytes } from "../lib/format";
import { Modal } from "./Modal";

/** Reads "25565, 25566" into ports, or null when any entry is not a port. */
export function parsePorts(text: string): number[] | null {
  const entries = text
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const ports = entries.map((entry) => Number(entry));
  if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535)) return null;
  return ports;
}

/** Reads an optional protocol number: undefined when blank, null when invalid. */
export function parseProtocol(text: string): number | null | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const value = Number(trimmed);
  return Number.isInteger(value) && value >= 0 && value <= 0x7fff_ffff ? value : null;
}

/**
 * Imports a pcap or pcapng file. An imported file has no process to attribute
 * its flows to, so Minecraft traffic is recognised by the server's port. Each
 * TCP stream is split into Minecraft packets; what cannot be framed
 * (encrypted or unsynchronised data) is kept as labelled raw rows.
 */
export function ImportCaptureDialog({
  onImported,
  onClose,
  onError,
}: {
  onImported: (summary: ImportSummary) => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [ports, setPorts] = useState("25565");
  const [split, setSplit] = useState(true);
  const [protocol, setProtocol] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ path: string; summary: ImportSummary } | null>(null);
  const parsed = parsePorts(ports);
  const protocolVersion = parseProtocol(protocol);
  const valid = parsed !== null && protocolVersion !== null;

  async function run() {
    if (!valid || !parsed || busy) return;
    try {
      const path = await chooseCaptureToImport();
      if (!path) return;
      setBusy(true);
      const summary = await desktop.captureImport(path, {
        serverPorts: parsed,
        splitPackets: split,
        protocolVersion: protocolVersion ?? null,
      });
      setResult({ path, summary });
      if (summary.framesImported > 0) onImported(summary);
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={t("import.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={onClose}>
            {result ? t("filter.done") : t("form.cancel")}
          </button>
          <button
            type="button"
            className="button primary"
            disabled={!valid || busy}
            onClick={() => void run()}
          >
            {busy ? (
              <Loader2 className="spin" size={13} aria-hidden="true" />
            ) : (
              <FileUp size={13} aria-hidden="true" />
            )}{" "}
            {result ? t("import.another") : t("import.choose")}
          </button>
        </>
      }
    >
      <div className="import-capture">
        <label className="filter-field">
          {t("import.ports")}
          <input
            value={ports}
            onChange={(event) => setPorts(event.target.value)}
            aria-invalid={parsed === null || undefined}
            placeholder="25565"
          />
        </label>
        <p className="filter-hint">{parsed === null ? t("import.ports.invalid") : t("import.ports.hint")}</p>
        <label className="filter-field inline">
          <input type="checkbox" checked={split} onChange={(event) => setSplit(event.target.checked)} />
          {t("import.split")}
        </label>
        <p className="filter-hint">{t("import.split.hint")}</p>
        {split && (
          <>
            <label className="filter-field">
              {t("import.protocol")}
              <input
                value={protocol}
                inputMode="numeric"
                onChange={(event) => setProtocol(event.target.value)}
                aria-invalid={protocolVersion === null || undefined}
                placeholder="767"
              />
            </label>
            <p className="filter-hint">
              {protocolVersion === null ? t("import.protocol.invalid") : t("import.protocol.hint")}
            </p>
          </>
        )}
        {result && <ImportResult path={result.path} summary={result.summary} />}
      </div>
    </Modal>
  );
}

/** The summary lines worth showing: counts that are zero are left out. */
export function importResultRows(summary: ImportSummary): Array<[string, string]> {
  const count = (value: number) => value.toLocaleString();
  const always: Array<[string, string]> = [
    [t("import.result.records"), count(summary.recordsRead)],
    [t("import.result.frames"), count(summary.framesImported)],
    [t("import.result.packets"), count(summary.packetsDecoded)],
    [t("import.result.bytes"), formatBytes(summary.bytesImported)],
    [t("import.result.connections"), count(summary.connections)],
  ];
  const whenPresent: Array<[string, number]> = [
    [t("import.result.raw"), summary.rawRows],
    [t("import.result.exported"), summary.exportedPackets],
    [t("import.result.encrypted"), summary.encryptedConnections],
    [t("import.result.midstream"), summary.midstreamConnections],
    [t("import.result.unsynchronised"), summary.unsynchronisedStreams],
    [t("import.result.resyncs"), summary.resyncs],
    [t("import.result.desyncs"), summary.desyncs],
    [t("import.result.frameErrors"), summary.frameErrors],
    [t("import.result.duplicates"), summary.duplicatesRemoved],
    [t("import.result.reordered"), summary.segmentsReordered],
    [t("import.result.gaps"), summary.gaps],
  ];
  return [
    ...always,
    ...whenPresent
      .filter(([, value]) => value > 0)
      .map(([label, value]): [string, string] => [label, count(value)]),
  ];
}

function ImportResult({ path, summary }: { path: string; summary: ImportSummary }) {
  const rows = importResultRows(summary);
  return (
    <section className="import-result" aria-live="polite">
      <p>{t("import.result.from", { path })}</p>
      <dl className="inspector-facts">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      {summary.encryptedConnections > 0 && <p className="filter-hint">{t("import.result.encryptedHint")}</p>}
      {summary.midstreamConnections > 0 && <p className="filter-hint">{t("import.result.midstreamHint")}</p>}
      {summary.truncated && <p className="filter-hint">{t("import.result.truncated")}</p>}
      {summary.error && (
        <p className="filter-error" role="alert">
          {summary.error}
        </p>
      )}
    </section>
  );
}
