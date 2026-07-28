/**
 * Sanctuary v1.1.5 — Hub Agent Registry Persistence (Finding Z)
 *
 * v1.1.1 shipped the hub API surface (`/api/hub/agents`) backed by an
 * in-memory `InMemoryLocalAgentRegistry` constructed empty on every boot
 * (`server/src/dashboard/v1_1/wiring.ts:12-15` documents the deferral:
 * "v1.2 will populate it from `discoverTenants()` and the wrapped harness
 * manifest. v1.1.1 ships the API surface so existing operator scripts can
 * hit it; the data plane is the next conversation."). The 2026-04-27
 * acceptance drill arrested at Phase 1.3 because wrap reported success
 * while the v1.1 dashboard's Agents view stayed empty: wrap had no
 * write-side path into the registry, and the registry had no read-side
 * path off disk.
 *
 * v1.1.5 closes the gap with the smallest hotfix shape that holds:
 * `sanctuary wrap` persists a `LocalAgentRecord` to a single hub-layer
 * file under the fortress's storage path; `buildV11Bindings()` reads the
 * file as the registry seed at construction. Persistence and rehydration
 * cover the two operator paths the drill exercises (wrap-auto dashboard
 * + standalone `sanctuary dashboard`).
 *
 * Layer boundary preserved: this is the v1.1 hub registry only. The L1
 * cognitive identity layer at `~/.sanctuary/state/_identities/` stays
 * lazy by design (created on first fortress-unlock; see `cli.ts:588-593`).
 * The two layers describe different concerns: hub registry tracks what
 * wrap registered; L1 identity tracks the master-key-derived Ed25519 keys.
 *
 * File: `<storagePath>/state/_hub/local-agents.json`, mode 0600,
 * atomic write via `.tmp` rename. Best-effort read on rehydrate (parse
 * errors fall back to an empty list; the file is operator-local and a
 * corrupted file degrades the dashboard's agent list rather than
 * blocking the fortress).
 */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";

const PERSISTED_VERSION = "1.1" as const;

interface PersistedHubAgents {
  version: typeof PERSISTED_VERSION;
  agents: LocalAgentRecord[];
}

/**
 * Resolve the canonical local-agents.json path for a given fortress
 * storage root. Callers should not assemble this path by hand; route
 * through here so a future move (e.g. to a sub-directory per harness
 * kind under v1.2) only updates one site.
 */
export function localAgentsFilePath(storagePath: string): string {
  return join(storagePath, "state", "_hub", "local-agents.json");
}

/**
 * Read the persisted hub agent records. Best-effort: a missing file
 * returns an empty list; parse errors return an empty list (the fortress
 * is still functional, just without prior wrap-state restored). The
 * caller is responsible for any logging/diagnostic surfacing.
 *
 * CONSUMER BOUND (F-1, dry-bar sweep 2026-07-27): best-effort is correct for
 * the hub-restore consumer ONLY (a corrupted file degrades the dashboard's
 * agent list rather than blocking the fortress). It is WRONG for any consumer
 * that turns "zero records" into an attestation: an empty return here cannot
 * distinguish "read to completion, genuinely empty" from "corrupt file". An
 * attesting consumer (the evidence pack's inventory census) MUST use
 * {@link readPersistedLocalAgentsStrict} instead.
 */
export function readPersistedLocalAgents(
  storagePath: string,
): LocalAgentRecord[] {
  const filePath = localAgentsFilePath(storagePath);
  if (!existsSync(filePath)) return [];
  try {
    const raw = readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedHubAgents;
    if (!parsed || !Array.isArray(parsed.agents)) return [];
    return parsed.agents;
  } catch {
    return [];
  }
}

/**
 * The strict read outcome for an ATTESTING consumer (F-1). Three states,
 * deliberately not collapsible into each other:
 *  - `absent`: the registry file does not exist. An honest empty candidate
 *    (nothing has ever been wrapped, or the fortress is fresh).
 *  - `ok`: the file exists, parsed, and matched the persisted shape; `agents`
 *    are the records (possibly an empty array, which IS a verified empty).
 *  - `unreadable`: the file exists but could not be read, did not parse, or
 *    did not match the persisted shape. `reason` is a FIXED, host-independent
 *    classification safe for a signed artifact; `cause` (when present) is the
 *    raw error for operator-console diagnostics ONLY and must never reach a
 *    delivered pack.
 */
export type StrictLocalAgentsRead =
  | { status: "absent" }
  | { status: "ok"; agents: LocalAgentRecord[] }
  | { status: "unreadable"; reason: string; cause?: unknown };

/** Fixed, host-independent unreadable classifications (safe for signed prose). */
const UNREADABLE_IO = "the registry file exists but could not be read";
const UNREADABLE_JSON = "the registry file is not valid JSON";
const UNREADABLE_SHAPE =
  "the registry file does not match the persisted hub registry shape";

/**
 * Validate the fields of a persisted record that an attesting consumer
 * actually renders and sorts on (agent_id, harness, wrapped_at, status, and
 * the optional model_provider vendor/model_id). Deliberately NOT a full
 * `LocalAgentRecord` validation: over-validating fields the census never
 * touches would turn a benign writer evolution into a false read-failure
 * disclosure on a healthy fortress (the mirror defect).
 */
function isRenderableLocalAgentRecord(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (typeof r.agent_id !== "string" || r.agent_id.length === 0) return false;
  if (typeof r.harness !== "string") return false;
  if (typeof r.wrapped_at !== "string") return false;
  if (typeof r.status !== "string") return false;
  if (r.model_provider !== undefined) {
    const mp = r.model_provider as Record<string, unknown> | null;
    if (!mp || typeof mp !== "object" || Array.isArray(mp)) return false;
    if (typeof mp.vendor !== "string" || typeof mp.model_id !== "string") {
      return false;
    }
  }
  return true;
}

/**
 * STRICT read of the persisted hub agent records, for consumers that turn the
 * result into an attestation (F-1, dry-bar sweep 2026-07-27). Unlike the
 * best-effort {@link readPersistedLocalAgents}, this never conflates "could
 * not read or parse" with "verified empty": a corrupt, truncated, or
 * wrong-shape file is reported as `unreadable`, so an evidence artifact can
 * disclose a read failure instead of signing a definitive "none recorded"
 * census over a file it could not actually use. Never throws.
 */
export function readPersistedLocalAgentsStrict(
  storagePath: string,
): StrictLocalAgentsRead {
  const filePath = localAgentsFilePath(storagePath);
  if (!existsSync(filePath)) return { status: "absent" };
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (cause) {
    return { status: "unreadable", reason: UNREADABLE_IO, cause };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    return { status: "unreadable", reason: UNREADABLE_JSON, cause };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    (parsed as Record<string, unknown>).version !== PERSISTED_VERSION ||
    !Array.isArray((parsed as Record<string, unknown>).agents)
  ) {
    return { status: "unreadable", reason: UNREADABLE_SHAPE };
  }
  const agents = (parsed as { agents: unknown[] }).agents;
  if (!agents.every(isRenderableLocalAgentRecord)) {
    return { status: "unreadable", reason: UNREADABLE_SHAPE };
  }
  return { status: "ok", agents: agents as LocalAgentRecord[] };
}

/**
 * Atomically replace the persisted record set. Writes a `.tmp` file with
 * mode 0600 and renames over the canonical path; the caller's process
 * crashing mid-write leaves the prior file intact rather than producing
 * a half-written replacement. Creates the parent directory chain with
 * mode 0700 if missing.
 */
export function writePersistedLocalAgents(
  storagePath: string,
  agents: LocalAgentRecord[],
): void {
  const filePath = localAgentsFilePath(storagePath);
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const payload: PersistedHubAgents = {
    version: PERSISTED_VERSION,
    agents,
  };
  const tmpPath = `${filePath}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, {
    mode: 0o600,
  });
  renameSync(tmpPath, filePath);
  chmodSync(filePath, 0o600);
}

/**
 * Insert or update a record by `agent_id`. Re-wrapping the same harness
 * preserves the original `wrapped_at` and bumps `last_activity_at`;
 * other fields take the new record's values. New records append.
 *
 * Returns the updated record list so callers that need to mirror the
 * persisted state into an in-memory registry (e.g. wrap setting up the
 * v1.1 hub bindings on the wrap-auto dashboard) avoid a re-read race.
 */
export function upsertPersistedLocalAgent(
  storagePath: string,
  record: LocalAgentRecord,
): LocalAgentRecord[] {
  const existing = readPersistedLocalAgents(storagePath);
  const idx = existing.findIndex((r) => r.agent_id === record.agent_id);
  let next: LocalAgentRecord[];
  if (idx >= 0) {
    const prior = existing[idx];
    if (prior === undefined) {
      next = [...existing, record];
    } else {
      const updated: LocalAgentRecord = {
        ...record,
        wrapped_at: prior.wrapped_at,
        last_activity_at: new Date().toISOString(),
      };
      next = [...existing];
      next[idx] = updated;
    }
  } else {
    next = [...existing, record];
  }
  writePersistedLocalAgents(storagePath, next);
  return next;
}
