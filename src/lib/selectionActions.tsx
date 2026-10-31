import { createContext, useContext } from "react";
import type { ByteRange } from "../components/HexView";
import type { FieldSpan, PacketView } from "../domain/types";
export interface SelectionActions {
  intruder: (packet: PacketView, range: ByteRange, field: FieldSpan | null) => void;
  sequencer: (packet: PacketView, field: FieldSpan) => void;
  decoder: (packet: PacketView, range: ByteRange) => void;
  column: (field: string) => void;
  find: (value: string) => void;
}
export const SelectionActionsContext = createContext<SelectionActions | null>(null);
export function useSelectionActions() {
  return useContext(SelectionActionsContext);
}
