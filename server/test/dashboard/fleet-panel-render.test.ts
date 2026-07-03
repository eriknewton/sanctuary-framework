/**
 * Wrap ("Protect") dashboard fleet panel - read-only render + end-to-end wiring.
 *
 * The wrap dashboard serves `renderPostureHomeHTML()`, which already carries the
 * read-only fleet-roster panel (`#fleet-section`, fetching `GET
 * /api/posture/fleet`). These pin finding #2's guarantees for that panel:
 *
 *   MARKUP (the served page):
 *     - the fleet panel is present and uses the SHARED posture tokens (exactly
 *       one `:root` block, no duplicate token block bolted on);
 *     - copy is SEE / MONITOR, never manage;
 *     - there are NO mutation controls (no admit / revoke / rotate button,
 *       form, or POST) anywhere in the panel - it is view-only.
 *
 *   BEHAVIOUR (end-to-end over the real wrap dashboard server):
 *     - ABSENCE: with no fleet provider wired, `GET /api/posture/fleet` 404s
 *       within the namespace, so the panel's fetch fails and the section stays
 *       hidden (`display:none`) - the honest empty state, never a fabricated
 *       row or a greyed-green "armed" shell;
 *     - PRESENCE: with a provider wired to a REAL provisioned roster, the route
 *       serves `available:true` with the real rows the panel renders.
 */

import { afterEach, describe, expect, it } from "vitest";

import {
  renderPostureHomeHTML,
} from "../../src/principal-policy/posture-home-html.js";
import { POSTURE_ROOT_TOKENS_CSS } from "../../src/principal-policy/posture-html-shared.js";
import { startDashboardServer } from "../../src/dashboard/server.js";
import type { DashboardHandle } from "../../src/dashboard/server.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { randomBytes } from "node:crypto";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";

describe("wrap dashboard fleet panel - read-only markup", () => {
  const html = renderPostureHomeHTML();

  it("renders the fleet panel and reuses the SHARED posture tokens (single :root)", () => {
    // The panel exists and fetches the read-only posture fleet route.
    expect(html).toContain('id="fleet-section"');
    expect(html).toContain('id="fleet"');
    expect(html).toContain("/api/posture/fleet");
    // Shared tokens: the page embeds the shared token block, and there is
    // exactly ONE `:root {` in the document (no duplicate token block).
    expect(html).toContain(POSTURE_ROOT_TOKENS_CSS);
    const rootBlocks = html.split(":root {").length - 1;
    expect(rootBlocks).toBe(1);
  });

  it("uses SEE / MONITOR copy, not manage", () => {
    // Scope to the fleet section's documentation + heading region.
    const seeMonitor = /SEE\s*\/\s*MONITOR only/i.test(html);
    expect(seeMonitor).toBe(true);
    // The panel must not describe itself as a management surface.
    expect(/manage (the |your )?fleet/i.test(html)).toBe(false);
  });

  it("exposes NO mutation controls in the fleet panel (view-only)", () => {
    // Isolate the fleet section markup so an admit/revoke control elsewhere on
    // the page (there are none today, but be precise) cannot mask a regression.
    const start = html.indexOf('id="fleet-section"');
    expect(start).toBeGreaterThan(-1);
    // Take a generous window covering the section markup.
    const sectionEnd = html.indexOf("</section>", start);
    const section = html.slice(start, sectionEnd === -1 ? undefined : sectionEnd);

    // No trust-mutation verbs rendered as controls in the panel.
    for (const verb of ["admit", "revoke", "rotate", "kill", "evict"]) {
      expect(section.toLowerCase()).not.toContain(verb);
    }
    // No form / button / POST-ish control in the fleet section markup.
    expect(section.toLowerCase()).not.toContain("<button");
    expect(section.toLowerCase()).not.toContain("<form");
    expect(section.toLowerCase()).not.toContain("<input");
  });
});

// ── End-to-end over the real wrap dashboard server ──────────────────────────

async function testAuditLog(): Promise<AuditLog> {
  const storage = new MemoryStorage();
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `fleet-panel-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return new AuditLog(storage, masterKey);
}

async function startForTest(overrides: {
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
} = {}): Promise<DashboardHandle> {
  const auditLog = await testAuditLog();
  const sources: AggregatorSources = {
    mode: "co-located",
    server_version: "0.9.0-test",
    activity: [],
    pendingApprovals: [],
    auditLog,
  };
  return startDashboardServer({
    mode: "co-located",
    port: 0,
    sources,
    ...(overrides.fleetRoster ? { fleetRoster: overrides.fleetRoster } : {}),
  });
}

/** A present, provisioned 1-node roster the panel renders as a row. */
function presentRoster(): FleetRoster {
  return {
    available: true,
    enabled: true,
    fortress_id: "fortress:test",
    node_id: "home-mac",
    eviction_serial: 0,
    nodes: [
      {
        node_id: "node-1",
        label: "linux-box",
        trust_state: "admitted",
        trust_evaluable: true,
        reach: "recent",
        node_mode: "local",
        provider_in_trust_boundary: false,
        last_sync_received_at: "2026-06-24T11:59:00.000Z",
        policy: {
          version: null,
          hash: null,
          hash_algorithm: null,
          applied_at: null,
          source_event_id: null,
          drift_state: "unknown",
        },
        first_seen: "2026-06-24T11:00:00.000Z",
        last_seen: "2026-06-24T11:59:00.000Z",
      },
    ],
    summary: { total: 1, admitted: 1, revoked: 0, untrusted: 0 },
    sync_health: {
      reachable: 1,
      stale: 0,
      never: 0,
      oldest_last_sync: "2026-06-24T11:59:00.000Z",
      freshness_window_ms: 600000,
    },
    policy_distribution: {
      available: true,
      operator_policy: null,
      summary: { in_sync: 0, drifted: 0, unknown: 1 },
    },
  };
}

describe("wrap dashboard fleet panel - end-to-end /api/posture/fleet", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.stop();
      handle = null;
    }
  });

  it("ABSENCE: 404s within the namespace when no provider is wired (panel stays hidden)", async () => {
    handle = await startForTest();
    const res = await fetch(`${handle.url}/api/posture/fleet`);
    // 404 -> the panel's fetch fails and #fleet-section stays display:none. The
    // honest empty state: no fabricated rows, no greyed-green armed shell.
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe("fleet_unavailable");
  });

  it("PRESENCE: serves the real roster the panel renders when a provider is wired", async () => {
    const roster = presentRoster();
    handle = await startForTest({ fleetRoster: () => roster });
    const res = await fetch(`${handle.url}/api/posture/fleet`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as FleetRoster;
    expect(body.available).toBe(true);
    expect(body.nodes.map((n) => [n.node_id, n.trust_state])).toEqual([
      ["node-1", "admitted"],
    ]);
  });
});
