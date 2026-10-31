/** Flush registered project editors before changing the current project or closing. */
const editors = new Set<() => Promise<void>>();
const preparations = new Set<() => void | Promise<void>>();
export function registerProjectPreparation(prepare: () => void | Promise<void>): () => void {
  preparations.add(prepare);
  return () => {
    preparations.delete(prepare);
  };
}
export function registerProjectEditor(flush: () => Promise<void>): () => void {
  editors.add(flush);
  return () => {
    editors.delete(flush);
  };
}
export async function flushProjectEditors(): Promise<void> {
  await Promise.all([...preparations].map((prepare) => prepare()));
  await Promise.all([...editors].map((flush) => flush()));
}
