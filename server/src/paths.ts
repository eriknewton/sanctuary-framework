/**
 * Sanctuary MCP Server — Shared path resolution
 *
 * Resolves per-tenant storage paths and network ports from environment
 * variables, with sensible defaults for single-tenant installations.
 *
 * Multi-tenancy contract: every Sanctuary artifact that used to live under a
 * hardcoded `~/.sanctuary/*` location must now route through one of these
 * helpers so two instances on the same host can pick distinct locations.
 */

import { homedir } from "node:os";
import { join } from "node:path";

/** Default top-level storage directory when no env override is set. */
export const DEFAULT_STORAGE_DIR = ".sanctuary";

/** Default dashboard port — matched by config.ts default. */
export const DEFAULT_DASHBOARD_PORT = 3501;

/**
 * Resolve the storage path for a Sanctuary instance.
 *
 * Precedence (highest wins):
 *   1. `SANCTUARY_STORAGE_PATH` env var
 *   2. `~/.sanctuary`
 *
 * @param env Optional env object (for tests). Defaults to `process.env`.
 * @param home Optional home directory override (for tests). Defaults to `os.homedir()`.
 */
export function resolveStoragePath(
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir()
): string {
  const override = env.SANCTUARY_STORAGE_PATH;
  if (override && override.length > 0) return override;
  return join(home, DEFAULT_STORAGE_DIR);
}

/**
 * Resolve the dashboard starting port.
 *
 * Precedence (highest wins):
 *   1. Explicit port argument (e.g. `--port` CLI flag)
 *   2. `SANCTUARY_DASHBOARD_PORT` env var
 *   3. Default 3501
 *
 * Auto-fallback (3501→3510) is handled downstream once a port is chosen.
 */
export function resolveDashboardPort(
  explicitPort?: number,
  env: NodeJS.ProcessEnv = process.env
): number {
  if (typeof explicitPort === "number" && !Number.isNaN(explicitPort)) {
    return explicitPort;
  }
  const envPort = env.SANCTUARY_DASHBOARD_PORT;
  if (envPort) {
    const parsed = parseInt(envPort, 10);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return DEFAULT_DASHBOARD_PORT;
}
