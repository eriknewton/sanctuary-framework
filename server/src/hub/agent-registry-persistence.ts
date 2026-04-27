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
 * lazy by design (created on first cocoon-unlock; see `cli.ts:588-593`).
 * The two layers describe different concerns: hub registry tracks what
 * wrap registered; L1 identity tracks the cocoon-derived Ed25519 keys.
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
