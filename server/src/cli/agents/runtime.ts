/**
 * Sanctuary MCP Server — per-tenant runtime state
 *
 * A live Sanctuary process writes `runtime.json` into its storage path on
 * start and deletes it on clean shutdown. The file is plaintext (no secrets)
 * and gives the `sanctuary agents` CLI + multi-agent dashboard enough
 * information to reach the running instance: the actual dashboard port, the
 * webhook callback port, the PID, and the start time.
 *
 * The file is best-effort: a process that crashes will leave a stale file.
 * Consumers must probe the dashboard HTTP health endpoint before treating a
 * tenant as running.
 */

import { readFile, writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";

export const RUNTIME_FILE_NAME = "runtime.json";

export interface TenantRuntimeState {
  /** Package version the running process was booted from. */
  version: string;
  /** OS process id. */
  pid: number;
  /** ISO 8601 UTC start timestamp. */
  started_at: string;
  /** Dashboard HTTP host (typically 127.0.0.1). */
  dashboard_host: string;
  /** Dashboard HTTP port the process actually bound (after any auto-fallback). */
  dashboard_port: number;
  /** Webhook callback port when the webhook approval channel is enabled. */
  webhook_callback_port?: number;
  /** Webhook callback host. */
  webhook_callback_host?: string;
  /** Process mode — which CLI entry started the dashboard. */
  mode: "wrap" | "standalone" | "co-located";
}

function runtimePath(storagePath: string): string {
  return join(storagePath, RUNTIME_FILE_NAME);
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (
      !!err &&
      typeof err === "object" &&
      (err as NodeJS.ErrnoException).code === "EPERM"
    );
  }
}

/**
 * Persist live runtime state for a tenant. Overwrites any existing file.
 * Never throws for I/O reasons — the caller should not fail to start the
 * dashboard just because the runtime hint file could not be written.
 */
export async function writeTenantRuntime(
  storagePath: string,
  state: TenantRuntimeState
): Promise<void> {
  try {
    await writeFile(
      runtimePath(storagePath),
      JSON.stringify(state, null, 2),
      { mode: 0o600 }
    );
  } catch {
    // Best-effort — never break dashboard startup on runtime-hint write failure.
  }
}

/**
 * Remove the runtime hint file. Called on graceful shutdown.
 * Swallows errors — missing file is fine.
 */
export async function clearTenantRuntime(storagePath: string): Promise<void> {
  try {
    await unlink(runtimePath(storagePath));
  } catch {
    // Missing / permission → caller does not care.
  }
}

/**
 * Read runtime state for a tenant. Returns null if the file is missing or
 * malformed, or if the writer process is no longer alive. Callers still probe
 * the dashboard via HTTP before treating a tenant as reachable.
 */
export async function readTenantRuntime(
  storagePath: string
): Promise<TenantRuntimeState | null> {
  try {
    const raw = await readFile(runtimePath(storagePath), "utf-8");
    const parsed = JSON.parse(raw) as Partial<TenantRuntimeState>;
    if (
      typeof parsed.dashboard_port !== "number" ||
      typeof parsed.pid !== "number" ||
      typeof parsed.started_at !== "string" ||
      typeof parsed.version !== "string" ||
      typeof parsed.dashboard_host !== "string" ||
      typeof parsed.mode !== "string"
    ) {
      return null;
    }
    const state: TenantRuntimeState = {
      version: parsed.version,
      pid: parsed.pid,
      started_at: parsed.started_at,
      dashboard_host: parsed.dashboard_host,
      dashboard_port: parsed.dashboard_port,
      mode: parsed.mode as TenantRuntimeState["mode"],
    };
    if (typeof parsed.webhook_callback_port === "number") {
      state.webhook_callback_port = parsed.webhook_callback_port;
    }
    if (typeof parsed.webhook_callback_host === "string") {
      state.webhook_callback_host = parsed.webhook_callback_host;
    }
    if (!isProcessAlive(state.pid)) return null;
    return state;
  } catch {
    return null;
  }
}
