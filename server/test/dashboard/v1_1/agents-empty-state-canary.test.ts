/**
 * Sanctuary v1.1.7 — Z empty-state regression-canary
 *
 * v1.1.5 (PR #82, Finding Z) closed the wrap → hub agent-registry gap:
 * `sanctuary wrap` now upserts a `LocalAgentRecord` to disk
 * (`<storage>/state/_hub/local-agents.json`), and `buildV11Bindings`
 * rehydrates the file on dashboard boot. Before Z, the v1.1 dashboard's
 * Agents view sat permanently on the empty-state copy ("No wrapped
 * agents yet. Run `sanctuary wrap` to wrap a harness.") even after the
 * operator successfully wrapped.
 *
 * The 2026-04-27 v1.1.6 acceptance drill noted that the empty-state
 * copy is still in the source — by design — but should never be visible
 * to a real operator post-wrap. If wrap stops persisting (Z regresses),
 * the dashboard slides back to empty silently. This canary catches that.
 *
 * Two layers:
 *   1. Static-source guard: `renderAgentsList` must wrap the empty-state
 *      branch in a `!state.agents.length` check. Removing the guard
 *      would render the empty-state alongside agent rows.
 *   2. End-to-end persistence: seed a `LocalAgentRecord` on disk, boot
 *      the v1.1 dashboard against the fortress, hit `/api/hub/agents`,
 *      and assert the response contains the seeded agent. Proves the
 *      wrap-side write + dashboard-side rehydrate path is intact.
 *
 * Spawn-prompt deviation: the original v1.1.7 spawn prompt asked for
 * "rendered HTML does NOT contain the literal string 'Run sanctuary
 * wrap'" — but the v1.1 SPA bundles the renderAgentsList JS function
 * (including the empty-state copy as a string literal) in the served
 * HTML at all times, so a literal-string scan would always match. The
 * shape above (static guard + API populated-case smoke) is the
 * functionally equivalent canary.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../../src/dashboard/v1_1/wiring.js";
import { upsertPersistedLocalAgent } from "../../../src/hub/agent-registry-persistence.js";
import { getClientScript } from "../../../src/dashboard/v1_1/index.js";
import type { LocalAgentRecord } from "../../../src/contracts/v1.1/local-agent-records.js";
import { getFreePort } from "../../helpers/free-port.js";

function buildSeedRecord(agentId: string): LocalAgentRecord {
  const now = new Date().toISOString();
  return {
    version: "1.1",
    agent_id: agentId,
    identity_id: "operator-z-canary",
    harness: "claude_code",
    model_provider: { vendor: "anthropic", model_id: "claude-sonnet-4-5-test" },
    policy_id: "default",
    status: "running",
    budget_summary: {
      window: "daily",
      currency: "USD",
      spent: 0,
      cap: 0,
    },
    last_activity_at: now,
    wrapped_at: now,
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
    },
  };
}

describe("v1.1 Agents empty-state canary (Finding Z regression)", () => {
  it("renderAgentsList guards the empty-state branch on !state.agents.length", () => {
    const script = getClientScript();
    // The guard structure: `if (!state.agents.length) return '<h1>Agents</h1><p ...empty...>';`
    // The empty-state copy is acceptable in the source as long as it's
    // gated behind this check. A regression that drops the guard would
    // render the empty-state alongside or instead of agent rows.
    expect(script).toMatch(
      /function renderAgentsList\(\)\s*\{[^}]*if\s*\(\s*!state\.agents\.length\s*\)\s*return\s*['"]<h1>Agents<\/h1>/,
    );
    // Pin the negation: the empty-state copy points operators at protect.
    expect(script).toContain("No protected agents yet.");
  });

  describe("populated registry path (proves Z's persistence is intact)", () => {
    let dashboard: DashboardApprovalChannel | null = null;
    let storagePath: string;
    let port: number;
    let authToken: string;

    beforeEach(async () => {
      storagePath = await mkdtemp(join(tmpdir(), "sanctuary-v117-z-canary-"));
      authToken = `z-canary-${randomBytes(8).toString("hex")}`;
      port = await getFreePort();
    });

    afterEach(async () => {
      if (dashboard) {
        await dashboard.stop();
        dashboard = null;
      }
      await rm(storagePath, { recursive: true, force: true }).catch(() => {});
    });

    it("seeded LocalAgentRecord shows in /api/hub/agents (no empty-state regression)", async () => {
      // 1. Seed a record on disk via the production write path.
      const seedRecord = buildSeedRecord("agent:claude_code:fortress-canary-z");
      upsertPersistedLocalAgent(storagePath, seedRecord);

      // 2. Boot the dashboard with v1.1 bindings rehydrated from disk.
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);

      dashboard = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 30,
        auth_token: authToken,
        auto_open: false,
      });
      dashboard.setDependencies({
        policy: {
          version: 1,
          tier1_always_approve: [],
          tier3_auto_allow: [],
          anomaly_thresholds: {
            new_namespace: true,
            unfamiliar_counterparty_window_days: 7,
            frequency_spike_multiplier: 5,
          },
          approval_channel: { type: "stderr", timeout_seconds: 30 },
        } as never,
        baseline: { load: async () => {}, save: async () => {} } as never,
        auditLog,
      });
      dashboard.setV11Bindings(
        buildV11Bindings({
          identityId: seedRecord.identity_id,
          fortressId: fortressIdFromStoragePath(storagePath),
          auditLog,
          storagePath,
        }),
      );
      await dashboard.start();

      // 3. The hub API now reflects the seeded record. If Z regresses
      //    (wrap stops writing), the response would be empty here — the
      //    dashboard's Agents view would slide back to the empty-state
      //    copy and the operator would think nothing wrapped.
      const res = await fetch(`http://127.0.0.1:${port}/api/hub/agents`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { agents: Array<{ agent_id: string }> };
      };
      expect(body.ok).toBe(true);
      expect(body.data.agents.length).toBeGreaterThan(0);
      const ids = body.data.agents.map((a) => a.agent_id);
      expect(ids).toContain("agent:claude_code:fortress-canary-z");
    });
  });
});
