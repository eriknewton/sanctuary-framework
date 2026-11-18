/** Read-only initialization marker predicate shared by the MCP child and evidence export. */
import type { Stats } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { join } from "node:path";

/** Marker presence admits an existing fortress; custody authentication still belongs to boot. */
export async function initializedFortressExists(
  fortressPath: string,
  followRootSymlink = true,
): Promise<boolean> {
  const fortressStats = await (followRootSymlink ? statOrMissing(fortressPath) : lstatOrMissing(fortressPath));
  if (!fortressStats?.isDirectory()) return false;

  for (const marker of FORTRESS_INITIALIZATION_MARKERS) {
    const markerStats = await lstatOrMissing(join(fortressPath, ...marker));
    if (markerStats?.isFile()) return true;
  }
  return false;
}

// Must match mcpChildFortressExists in ../mcp-child-fortress-refusal.ts; both consumers share this marker set.
const FORTRESS_INITIALIZATION_MARKERS = [
  ["state", "_meta", "custody-envelope.enc"],
  ["state", "_meta", "custody-sentinel.enc"],
  ["state", "_meta", "key-params.enc"],
  ["state", "_meta", "recovery-key-hash.enc"],
] as const;

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

