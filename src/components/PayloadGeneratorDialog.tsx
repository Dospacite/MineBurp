import { useState } from "react";
import type { PayloadGenerator } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { Modal } from "./Modal";

export function PayloadGeneratorDialog({
  onApply,
  onClose,
  onError,
}: {
  onApply: (text: string) => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [kind, setKind] = useState<PayloadGenerator["kind"]>("numbers");
  const [start, setStart] = useState("0");
  const [end, setEnd] = useState("10");
  const [step, setStep] = useState("1");
  const [bits, setBits] = useState(32);
  const [signed, setSigned] = useState(true);
  const [unit, setUnit] = useState("A");
  const [values, setValues] = useState("false\ntrue");
  const [preview, setPreview] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  function changed() {
    setPreview(null);
  }
  async function generate() {
    setBusy(true);
    setPreview(null);
    try {
      const generator: PayloadGenerator =
        kind === "numbers"
          ? { kind, start, end, step }
          : kind === "boundaries"
            ? { kind, bits, signed }
            : kind === "lengths"
              ? { kind, start: Number(start), end: Number(end), step: Number(step), unit }
              : { kind, values: values.replace(/\r/g, "").split("\n") };
      setPreview(await desktop.payloadGenerate(generator));
    } catch (error) {
      onError(message(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={t("payload.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" disabled={busy} onClick={() => void generate()}>
            {t("payload.generate")}
          </button>
          <button
            type="button"
            className="button primary"
            disabled={!preview || busy}
            onClick={() => preview && onApply(preview.join("\n"))}
          >
            {t("payload.apply")}
          </button>
        </>
      }
    >
      <fieldset disabled={busy} className="research-controls">
        <legend>{t("payload.configuration")}</legend>
        <label>
          {t("payload.kind")}
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as PayloadGenerator["kind"]);
              changed();
            }}
          >
            {(["numbers", "boundaries", "lengths", "values"] as const).map((k) => (
              <option key={k} value={k}>
                {t(`payload.kind.${k}`)}
              </option>
            ))}
          </select>
        </label>
        {(kind === "numbers" || kind === "lengths") && (
          <div className="research-toolbar">
            {(
              [
                ["start", start, setStart],
                ["end", end, setEnd],
                ["step", step, setStep],
              ] as const
            ).map(([key, value, set]) => (
              <label key={key}>
                {t(`payload.${key}`)}
                <input
                  value={value}
                  onChange={(e) => {
                    set(e.target.value);
                    changed();
                  }}
                  inputMode="numeric"
                />
              </label>
            ))}
          </div>
        )}
        {kind === "boundaries" && (
          <>
            <label>
              {t("payload.bits")}
              <select
                value={bits}
                onChange={(e) => {
                  setBits(Number(e.target.value));
                  changed();
                }}
              >
                {[8, 16, 32, 64].map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={signed}
                onChange={(e) => {
                  setSigned(e.target.checked);
                  changed();
                }}
              />
              {t("payload.signed")}
            </label>
            <p>{t("payload.boundary-note")}</p>
          </>
        )}
        {kind === "lengths" && (
          <label>
            {t("payload.unit")}
            <input
              value={unit}
              onChange={(e) => {
                setUnit(e.target.value);
                changed();
              }}
            />
          </label>
        )}
        {kind === "values" && (
          <>
            <label>
              {t("payload.values")}
              <textarea
                rows={8}
                value={values}
                onChange={(e) => {
                  setValues(e.target.value);
                  changed();
                }}
              />
            </label>
            <label>
              {t("payload.import")}
              <input
                type="file"
                accept=".txt,.csv,.list"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  if (file.size > 4 * 1024 * 1024) {
                    onError(t("payload.file-limit"));
                    return;
                  }
                  void file
                    .text()
                    .then((text) => {
                      setValues(text.replace(/\r\n/g, "\n").replace(/\n$/, ""));
                      changed();
                    })
                    .catch((error) => onError(message(error)));
                }}
              />
            </label>
          </>
        )}
      </fieldset>
      {preview && (
        <>
          <p role="status">{t("payload.count", { count: preview.length })}</p>
          <textarea rows={8} readOnly value={preview.join("\n")} aria-label={t("payload.preview")} />
        </>
      )}
    </Modal>
  );
}
