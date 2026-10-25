import type { ProjectInfo } from "../domain/types";

const KEY = "mineburp.recent-projects";
const LIMIT = 8;

export interface RecentProject {
  path: string;
  name: string;
  encrypted: boolean;
}

/**
 * Projects opened or created on this machine, most recent first.
 *
 * Browser storage can be unavailable or hold anything, so reads never throw
 * and drop entries that do not have the expected shape.
 */
export function recentProjects(): RecentProject[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(KEY) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (entry): entry is RecentProject =>
        typeof entry?.path === "string" &&
        typeof entry?.name === "string" &&
        typeof entry?.encrypted === "boolean",
    );
  } catch {
    return [];
  }
}

export function rememberProject(project: ProjectInfo): RecentProject[] {
  if (project.temporary) return recentProjects();
  const entry = { path: project.path, name: project.name, encrypted: project.encrypted };
  return store([entry, ...recentProjects().filter((recent) => recent.path !== project.path)]);
}

export function forgetProject(path: string): RecentProject[] {
  return store(recentProjects().filter((recent) => recent.path !== path));
}

function store(entries: RecentProject[]): RecentProject[] {
  const kept = entries.slice(0, LIMIT);
  try {
    localStorage.setItem(KEY, JSON.stringify(kept));
  } catch {
    // Storage is a convenience; the project itself is unaffected.
  }
  return kept;
}
