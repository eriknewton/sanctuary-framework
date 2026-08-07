import type { Stats } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import { loadConfig } from "./config.js";

export const FORTRESS_NOT_FOUND_EXIT_CODE = 78;
export const FORTRESS_LIFECYCLE_DOCS_URL =
  "https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/fortress-lifecycle.md";

export interface FortressNotFoundErrorLine {
  level: "error";
  code: "FORTRESS_NOT_FOUND";
  fortress_path: string;
  message: string;
  docs_url: string;
  caller_kind: "mcp_child";
}

export function buildFortressNotFoundErrorLine(
  fortressPath: string,
): FortressNotFoundErrorLine {
  return {
    level: "error",
    code: "FORTRESS_NOT_FOUND",
    fortress_path: fortressPath,
    message:
      "Sanctuary fortress not found at the resolved path. The MCP child refuses to silently initialize a fortress. Run sanctuary init to create one explicitly, or set SANCTUARY_FORTRESS_PATH to point at an existing fortress.",
    docs_url: FORTRESS_LIFECYCLE_DOCS_URL,
    caller_kind: "mcp_child",
  };
}

export async function resolveMcpChildFortressPath(): Promise<string> {
  const config = await loadConfig();
  return isAbsolute(config.storage_path)
    ? config.storage_path
    : resolve(process.cwd(), config.storage_path);
}

export async function mcpChildFortressExists(
  fortressPath: string,
): Promise<boolean> {
  const fortressStats = await statOrMissing(fortressPath);
  if (!fortressStats?.isDirectory()) return false;

  for (const marker of FORTRESS_INITIALIZATION_MARKERS) {
    const markerStats = await lstatOrMissing(join(fortressPath, ...marker));
    if (markerStats?.isFile()) return true;
  }
  return false;
}

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

export async function refuseMissingMcpChildFortressOrExit(): Promise<void> {
  const fortressPath = await resolveMcpChildFortressPath();
  if (await mcpChildFortressExists(fortressPath)) return;

  process.stderr.write(
    `${JSON.stringify(buildFortressNotFoundErrorLine(fortressPath))}\n`,
  );
  process.exit(FORTRESS_NOT_FOUND_EXIT_CODE);
}
