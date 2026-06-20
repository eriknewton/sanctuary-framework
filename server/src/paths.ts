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
 * Strictly parse a whole-string TCP port from an env var.
 *
 * `parseInt("80abc", 10)` returns `80`: it stops at the first non-digit and
 * silently TRUNCATES, which would bind the dashboard to a port the operator
 * never typed. This matches the strict env parse in `config.ts` (the
 * `loadConfig` reader) byte-for-byte on the regex: both accept ASCII digits
 * only (no leading sign), so the same env value never resolves to two different
 * ports across the two readers. After the digit-only screen, enforce the valid
 * TCP range 1..65535. Any non-clean-integer, signed, or out-of-range value
 * yields `undefined` so the caller falls back to the documented default rather
 * than binding a truncated or out-of-spec port.
 *
 * Returns `undefined` for "", "+8443", "-1", "80abc", "0x10", "3501 5",
 * "70000", "0", or any value that is not a clean in-range unsigned integer.
 */
function parseStrictPortEnv(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    return undefined;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return undefined;
  }
  return parsed;
}

/**
 * Resolve the dashboard starting port.
 *
 * Precedence (highest wins):
 *   1. Explicit port argument (e.g. `--port` CLI flag)
 *   2. `SANCTUARY_DASHBOARD_PORT` env var (strict whole-string parse,
 *      validated to the 1..65535 TCP range)
 *   3. Default 3501
 *
 * The env-var read is strict and range-checked so an invalid value (e.g.
 * "80abc", which the old lenient `parseInt` truncated to 80, or "70000",
 * which is out of the TCP range) does NOT silently bind a wrong port. Such
 * values fall back to the default: the same invalid-port hole that the
 * `loadConfig` reader closes by failing closed, closed here on the wrap
 * (Protect) boot path by ignoring the bad value.
 *
 * Auto-fallback (chosen port, then the next PORT_FALLBACK_ATTEMPTS-1
 * consecutive ports) is handled downstream once a port is chosen.
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
    const parsed = parseStrictPortEnv(envPort);
    if (parsed !== undefined) return parsed;
  }
  return DEFAULT_DASHBOARD_PORT;
}
