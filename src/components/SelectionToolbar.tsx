import type { FieldSpan, PacketView } from "../domain/types";
import { t } from "../i18n";
import { copyText } from "../lib/desktop";
import { useSelectionActions } from "../lib/selectionActions";
import type { ByteRange } from "./HexView";
export function SelectionToolbar({
  packet,
  range,
  field,
  onError,
}: {
  packet: PacketView;
  range: ByteRange | null;
  field: FieldSpan | null;
  onError: (error: string) => void;
}) {
  const actions = useSelectionActions();
  if (!actions || !range) return null;
  const copy = (text: string) =>
    void copyText(text).catch((error) => onError(error instanceof Error ? error.message : String(error)));
  return (
    <section className="selection-toolbar" aria-label={t("selection.title")}>
      <span className="selection-label">
        {field?.name ?? `0x${range.offset.toString(16)} + ${range.length} B`}
      </span>
      <button type="button" className="link-button" onClick={() => actions.decoder(packet, range)}>
        {t("selection.decoder")}
      </button>
      <button type="button" className="link-button" onClick={() => actions.intruder(packet, range, field)}>
        {t("selection.intruder")}
      </button>
      {field && (
        <>
          <button type="button" className="link-button" onClick={() => actions.sequencer(packet, field)}>
            {t("selection.sequencer")}
          </button>
          <button type="button" className="link-button" onClick={() => actions.column(field.name)}>
            {t("selection.column")}
          </button>
          <button type="button" className="link-button" onClick={() => copy(field.name)}>
            {t("selection.path")}
          </button>
          {field.value !== null && (
            <>
              <button type="button" className="link-button" onClick={() => copy(String(field.value))}>
                {t("selection.value")}
              </button>
              <button type="button" className="link-button" onClick={() => actions.find(String(field.value))}>
                {t("selection.find")}
              </button>
            </>
          )}
        </>
      )}
    </section>
  );
}
