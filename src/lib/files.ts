import { open, save } from "@tauri-apps/plugin-dialog";

const PROJECT_FILTER = [{ name: "MineBurp project", extensions: ["mineburp"] }];

/** Asks for an existing project file. Resolves to null when the dialog is cancelled. */
export async function chooseProjectToOpen(): Promise<string | null> {
  const picked = await open({ multiple: false, directory: false, filters: PROJECT_FILTER });
  return typeof picked === "string" ? picked : null;
}

/** Asks where a new project file should go, suggesting a name derived from the project's. */
export async function chooseProjectDestination(projectName: string): Promise<string | null> {
  const picked = await save({ defaultPath: `${fileStem(projectName)}.mineburp`, filters: PROJECT_FILTER });
  return picked ? withExtension(picked, ".mineburp") : null;
}

export async function chooseExportDestination(): Promise<string | null> {
  const picked = await save({
    defaultPath: `mineburp-export-${new Date().toISOString().slice(0, 10)}.json`,
    filters: [{ name: "JSON", extensions: ["json"] }],
  });
  return picked ? withExtension(picked, ".json") : null;
}

/** Asks where a pcapng export should go. */
export async function choosePcapngDestination(): Promise<string | null> {
  const picked = await save({
    defaultPath: `mineburp-export-${new Date().toISOString().slice(0, 10)}.pcapng`,
    filters: [{ name: "pcapng", extensions: ["pcapng"] }],
  });
  return picked ? withExtension(picked, ".pcapng") : null;
}

/** Asks for a packet capture to import. */
export async function chooseCaptureToImport(): Promise<string | null> {
  const picked = await open({
    multiple: false,
    directory: false,
    filters: [{ name: "Packet capture", extensions: ["pcapng", "pcap", "cap"] }],
  });
  return typeof picked === "string" ? picked : null;
}

/** Appends `extension` unless the path already ends with it (GTK save dialogs do not). */
export function withExtension(path: string, extension: string): string {
  return path.toLowerCase().endsWith(extension) ? path : `${path}${extension}`;
}

function fileStem(name: string): string {
  const stem = name
    .trim()
    .replace(/[\\/:*?"<>|]+/g, "-")
    .replace(/\s+/g, "-")
    .toLowerCase();
  return stem || "assessment";
}
