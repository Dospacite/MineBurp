/** A byte count in the largest binary unit that keeps it readable. */
export function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KiB`;
  if (bytes < 1_073_741_824) return `${(bytes / 1_048_576).toFixed(1)} MiB`;
  return `${(bytes / 1_073_741_824).toFixed(2)} GiB`;
}
