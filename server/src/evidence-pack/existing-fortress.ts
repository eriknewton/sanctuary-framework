/** Read-only initialization marker predicate shared by server boot, the MCP child and evidence export. */
import type { Stats } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { join } from "node:path";
import { FORTRESS_INITIALIZATION_KEYS, FORTRESS_STATE_DIRECTORY } from "../core/custody-markers.js";

/** Marker presence admits an existing fortress; custody authentication still belongs to boot. */
export async function initializedFortressExists(
  fortressPath: string,
  followRootSymlink = true,
): Promise<boolean> {
  const fortressStats = await (followRootSymlink ? statOrMissing(fortressPath) : lstatOrMissing(fortressPath));
  if (!fortressStats?.isDirectory()) return false;

  // Must match FORTRESS_INITIALIZATION_KEYS in ../core/custody-markers.ts; admission uses the complete custody marker registry.
  for (const key of Object.values(FORTRESS_INITIALIZATION_KEYS)) {
    const markerStats = await lstatOrMissing(join(fortressPath, FORTRESS_STATE_DIRECTORY, "_meta", `${key}.enc`));
    if (markerStats?.isFile()) return true;
  }
  return false;
}

async function statOrMissing(path: string): Promise<Stats | null> {
  try {
    return await stat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw err;
  }
}

async function lstatOrMissing(path: string): Promise<Stats | null> {
  try {
    return await lstat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw err;
  }
}

