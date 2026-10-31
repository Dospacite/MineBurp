import { ArrowDown, Copy, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { copyText, desktop } from "../lib/desktop";
import { newId } from "../lib/ids";

export interface DecoderRequest {
  input: string;
  nonce: number;
}
const OPERATIONS = [
  "normalize_hex",
  "hex_to_text",
  "text_to_hex",
  "base64_to_hex",
  "hex_to_base64",
  "var_int_decode",
  "var_int_encode",
  "var_long_decode",
  "var_long_encode",
  "string_decode",
  "string_encode",
  "uuid_decode",
  "uuid_encode",
  "u16_be_decode",
  "u16_le_decode",
  "u32_be_decode",
  "u32_le_decode",
  "u64_be_decode",
  "u64_le_decode",
  "u16_be_encode",
  "u16_le_encode",
  "u32_be_encode",
  "u32_le_encode",
  "u64_be_encode",
  "u64_le_encode",
  "zlib_decompress",
  "zlib_compress",
  "gzip_decompress",
  "gzip_compress",
  "nbt_decode",
  "nbt_encode",
  "named_nbt_decode",
  "named_nbt_encode",
  "json_pretty",
] as const;
interface Stage {
  id: string;
  operation: string;
  input: string;
  output: string;
  consumed: number | null;
  trailing_hex: string;
}
export function DecoderSidebar({
  request,
  open,
  onClose,
  onError,
}: {
  request: DecoderRequest | null;
  open: boolean;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [input, setInput] = useState("");
  const [operation, setOperation] = useState<string>("hex_to_text");
  const [result, setResult] = useState<Stage | null>(null);
  const [history, setHistory] = useState<Stage[]>([]);
  const [busy, setBusy] = useState(false);
  const version = useRef(0);
  useEffect(() => {
    if (request) {
      version.current++;
      setBusy(false);
      setInput(request.input);
      setResult(null);
      setHistory([]);
    }
  }, [request]);
  async function run() {
    const id = ++version.current;
    setBusy(true);
    try {
      const output = await desktop.decoderTransform(operation, input);
      if (id === version.current) setResult({ id: newId(), operation, input, ...output });
    } catch (error) {
      if (id === version.current) {
        setResult(null);
        onError(message(error));
      }
    } finally {
      if (id === version.current) setBusy(false);
    }
  }
  return (
    <aside className="decoder-sidebar" hidden={!open} aria-label={t("decoder.title")}>
      <header className="section-header">
        <h2>{t("decoder.title")}</h2>
        <button type="button" className="icon-button" aria-label={t("decoder.close")} onClick={onClose}>
          <X size={15} />
        </button>
      </header>
      <div className="decoder-content">
        <p>{t("decoder.description")}</p>
        <label>
          {t("decoder.input")}
          <textarea
            rows={8}
            value={input}
            spellCheck={false}
            onChange={(e) => {
              version.current++;
              setBusy(false);
              setInput(e.target.value);
              setResult(null);
            }}
          />
        </label>
        <label>
          {t("decoder.operation")}
          <select
            value={operation}
            onChange={(e) => {
              version.current++;
              setBusy(false);
              setOperation(e.target.value);
              setResult(null);
            }}
          >
            {OPERATIONS.map((op) => (
              <option key={op} value={op}>
                {t(`decoder.op.${op}`)}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="button" disabled={busy} onClick={() => void run()}>
          {t(busy ? "decoder.working" : "decoder.transform")}
        </button>
        {result && (
          <>
            <label>
              {t("decoder.output")}
              <textarea rows={8} readOnly value={result.output} />
            </label>
            <p role="status">
              {result.consumed !== null
                ? t("decoder.consumed", { count: result.consumed })
                : t("decoder.complete")}
            </p>
            {result.trailing_hex && (
              <label>
                {t("decoder.trailing")}
                <textarea rows={2} readOnly value={result.trailing_hex} />
              </label>
            )}
            <div className="research-toolbar">
              <button
                type="button"
                className="button"
                onClick={() => {
                  setHistory((old) => [...old, result].slice(-20));
                  setInput(result.output);
                  setResult(null);
                }}
              >
                <ArrowDown size={13} />
                {t("decoder.chain")}
              </button>
              <button
                type="button"
                className="button"
                onClick={() => void copyText(result.output).catch((error) => onError(message(error)))}
              >
                <Copy size={13} />
                {t("decoder.copy")}
              </button>
            </div>
          </>
        )}
        {history.length > 0 && (
          <section>
            <h3>{t("decoder.history")}</h3>
            {history.map((stage, i) => (
              <button
                type="button"
                className="decoder-stage"
                key={stage.id}
                onClick={() => {
                  version.current++;
                  setBusy(false);
                  setInput(stage.input);
                  setOperation(stage.operation);
                  setResult(stage);
                  setHistory(history.slice(0, i));
                }}
              >
                {i + 1}. {t(`decoder.op.${stage.operation}` as Parameters<typeof t>[0])}
              </button>
            ))}
          </section>
        )}
      </div>
    </aside>
  );
}
