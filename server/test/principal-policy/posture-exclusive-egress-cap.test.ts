/**
 * Unified Protect Slice 5 S5-P: every surface renders coarse-only NON-GREEN
 * (design rev3 §6 acceptance: "every surface renders coarse-only non-green").
 *
 * The surfaces all earn wall-green from ONE builder
 * (`buildCastleWallPosture.arm_state === "armed"`), so the load-bearing tests
 * are: (1) the builder caps a would-be `armed` to the DISTINCT non-green
 * `coarse_only` when a fine-grained-provisioned agent's exclusive stack is not
 * live; (2) the `castle_wall_egress` feature-health row caps `active` to the
 * distinct `coarse_only` status; (3) each renderer maps the new state/status
 * to a NON-GREEN, DISTINCTLY-LABELED presentation (pill mappers, the CLI
 * status table, the posture-home page source, the v1.1 console source, the
 * fortress-view source).
 */

import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildCastleWallPosture,
  failedExclusiveEgressStatus,
  type ExclusiveEgressStatus,
} from "../../src/principal-policy/posture.js";
import {
  buildFeatureHealthPanel,
  SLICE1_FEATURE_REGISTRY,
} from "../../src/principal-policy/feature-health.js";
import {
  featureHealthPill,
  renderPostureHomeHTML,
} from "../../src/principal-policy/posture-home-html.js";
import { renderTable } from "../../src/cli/status.js";
import {
  buildExclusiveEgressPosture,
  summarizeExclusiveEgressStatus,
} from "../../src/egress-gate/posture.js";

const FORTRESS = "fortress:test";

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

async function appendCW(
  log: AuditLog,
  operation: string,
  timestamp: string,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: FORTRESS,
    result: "success",
    details: { cw_source: "castle_wall_audit_consumer" },
    timestamp,
  });
}

/** A summary in which the one fine-grained agent's exclusive stack is DOWN. */
function coarseOnlyStatus(): ExclusiveEgressStatus {
  return summarizeExclusiveEgressStatus([
    buildExclusiveEgressPosture({
      agent_uid: 601,
      fine_grained_declared: true,
      coarse_wall_armed: true,
      registry_entry: { agent_uid: 601, gate_port: 49152, generation_id: 7 },
      staging_record_present: false,
      registry_dirty: false,
      pf_pass_port: 49152,
      manifest: null, // gate policy gone => generation mismatch => not live
      pf_liveness: { live: false, reasons: ["anchor flushed"] },
      gate_process: { up: false, port_owner_verified: false, reasons: [] },
    }),
  ]);
}

/** A summary in which the fine-grained agent is fully exclusive-live. */
function exclusiveLiveStatus(): ExclusiveEgressStatus {
  return summarizeExclusiveEgressStatus([
    buildExclusiveEgressPosture({
      agent_uid: 601,
      fine_grained_declared: true,
      coarse_wall_armed: true,
      registry_entry: { agent_uid: 601, gate_port: 49152, generation_id: 7 },
      staging_record_present: false,
      registry_dirty: false,
      pf_pass_port: 49152,
      manifest: { gate_port: 49152, generation_id: 7 },
      pf_liveness: { live: true, reasons: [] },
      gate_process: { up: true, port_owner_verified: true, reasons: [] },
    }),
  ]);
}

describe("S5-P: buildCastleWallPosture aggregate-green cap (the one chokepoint)", () => {
  it("caps a would-be ARMED to the distinct non-green coarse_only when the exclusive stack is down", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
      exclusiveEgress: coarseOnlyStatus(),
    });
    expect(posture.arm_state).toBe("coarse_only");
    expect(posture.arm_state).not.toBe("armed");
    // The full posture object is attached, queryably (design §6).
    expect(posture.exclusive_egress?.fine_grained_declared).toBe(true);
    expect(posture.exclusive_egress?.exclusive_egress_live).toBe(false);
    expect(posture.exclusive_egress?.mode).toBe("coarse-only");
    expect(posture.exclusive_egress?.agents[0]?.pf_liveness.reasons).toContain(
      "anchor flushed",
    );
  });

  it("stays ARMED when every fine-grained agent is exclusive-live (block still attached)", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
      exclusiveEgress: exclusiveLiveStatus(),
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.exclusive_egress?.exclusive_egress_live).toBe(true);
  });

  it("no exclusive-egress input (no producer wired) => behavior byte-identical, no block attached", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.exclusive_egress).toBeUndefined();
  });

  it("a NON-armed wall keeps its more specific state (never relabeled) but still attaches the block", async () => {
    const log = newAuditLog();
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: Date.now(),
      exclusiveEgress: coarseOnlyStatus(),
    });
    // No evidence at all: unknown, not coarse_only (the wall itself is unproven).
    expect(posture.arm_state).toBe("unknown");
    expect(posture.exclusive_egress?.mode).toBe("coarse-only");
  });

  it("a FAILED provider read (failedExclusiveEgressStatus) caps green - never the stronger claim", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
      exclusiveEgress: failedExclusiveEgressStatus("provider exploded"),
    });
    expect(posture.arm_state).toBe("coarse_only");
    expect(posture.exclusive_egress?.reasons.join(" ")).toContain(
      "provider exploded",
    );
  });
});

describe("S5-P: castle_wall_egress feature-health row caps to the distinct coarse_only status", () => {
  it("a would-be ACTIVE row reads coarse_only / exclusive_egress_not_live when capped", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now,
      exclusiveEgress: coarseOnlyStatus(),
    });
    const wallRow = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(wallRow?.status).toBe("coarse_only");
    expect(wallRow?.basis).toBe("exclusive_egress_not_live");
    // Every OTHER row is untouched by the cap.
    for (const row of panel.rows) {
      if (row.feature_id === "castle_wall_egress") continue;
      expect(row.status).not.toBe("coarse_only");
    }
  });

  it("stays ACTIVE when the exclusive stack is live", async () => {
    const log = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now,
      exclusiveEgress: exclusiveLiveStatus(),
    });
    const wallRow = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(wallRow?.status).toBe("active");
  });

  it("a NON-active wall row keeps its more specific story (a stale/quiet wall is not relabeled)", async () => {
    const log = newAuditLog();
    // No evidence at all: the row is unknown, and must NOT be relabeled to
    // coarse_only (which would falsely assert "the coarse wall is enforcing").
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
      exclusiveEgress: coarseOnlyStatus(),
    });
    const wallRow = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(wallRow?.status).not.toBe("coarse_only");
    expect(wallRow?.status).not.toBe("active");
  });

  it("registry sanity: the capped row id exists in the Slice-1 registry", () => {
    expect(
      SLICE1_FEATURE_REGISTRY.some((f) => f.id === "castle_wall_egress"),
    ).toBe(true);
  });
});

describe("S5-P: every surface renders coarse-only NON-GREEN and DISTINCT", () => {
  it("featureHealthPill maps coarse_only to a non-green pill with its own label", () => {
    const pill = featureHealthPill("coarse_only");
    expect(pill.cls).not.toBe("green");
    expect(pill.label).toBe("coarse-only");
    // Distinct from every other non-green label on this surface.
    expect(pill.label).not.toBe(featureHealthPill("unknown").label);
    expect(pill.label).not.toBe(featureHealthPill("unconfirmed").label);
  });

  it("the posture-home page source renders coarse_only as a distinct AMBER pill, never the green class", () => {
    const html = renderPostureHomeHTML();
    // Client-side wall pill: an explicit coarse_only branch with an amber pill.
    expect(html).toContain('state === "coarse_only"');
    expect(html).toContain('<span class="pill amber">COARSE-ONLY</span>');
    expect(html).not.toContain('<span class="pill green">COARSE-ONLY</span>');
    // Client-side feature pill: distinct coarse-only chip, amber.
    expect(html).toContain('<span class="pill amber">coarse-only</span>');
    // The reason copy for the capped feature row.
    expect(html).toContain("exclusive_egress_not_live");
    // The wall panel renders the exclusive-egress reasons block.
    expect(html).toContain("Exclusive egress:");
  });

  it("the CLI status table renders the distinct arm-state AND the exclusive-egress line", () => {
    const table = renderTable({
      ok: true,
      version: "1.6.1",
      daemon: { mode: "standalone", pid: 1 },
      listener: { host: "127.0.0.1", port: 3502, tls: false },
      federation: { enabled: false },
      identity: null,
      castle_wall: {
        arm_state: "coarse_only",
        exclusive_egress: {
          fine_grained_declared: true,
          exclusive_egress_live: false,
          mode: "coarse-only",
          agents: [],
          reasons: ["uid 601: coarse-only (pf: anchor flushed)"],
        },
      },
    });
    expect(table).toContain("castle wall:  coarse_only");
    expect(table).toContain("exclusive egress: NOT live (coarse-only)");
    expect(table).toContain("anchor flushed");
  });

  it("the CLI status table omits the exclusive line when no fine-grained agent is declared", () => {
    const table = renderTable({
      ok: true,
      castle_wall: { arm_state: "armed" },
    });
    expect(table).toContain("castle wall:  armed");
    expect(table).not.toContain("exclusive egress:");
  });

  it("the CLI status table renders 'live' when the exclusive stack is up", () => {
    const table = renderTable({
      ok: true,
      castle_wall: {
        arm_state: "armed",
        exclusive_egress: {
          fine_grained_declared: true,
          exclusive_egress_live: true,
          mode: "exclusive",
          agents: [],
          reasons: [],
        },
      },
    });
    expect(table).toContain("exclusive egress: live");
  });

  it("the v1.1 console client maps coarse_only to a distinct non-verified pill", async () => {
    const { getClientScript } = await import("../../src/dashboard/v1_1/client.js");
    const js = getClientScript();
    expect(js).toContain(
      'if (armState === "coarse_only") return { cls: "pill tone-degraded", text: "Coarse-only" };',
    );
    // Never mapped to the green/verified tone.
    expect(js).not.toContain('coarse_only") return { cls: "pill tone-verified"');
    // The layer-lines popover names the state honestly.
    expect(js).toContain("coarse-only (exclusive egress not live)");
  });

  it("the fortress-view (Protect) page maps coarse_only to a distinct amber state, never green", async () => {
    const { generateFortressViewHTML } = await import("../../src/wrap/fortress-view.js");
    const html = generateFortressViewHTML({
      serverVersion: "1.6.1",
      upstreamServerCount: 1,
    });
    expect(html).toContain("wallArmState === 'coarse_only'");
    expect(html).toContain("Coarse protection only");
    // The coarse-only branch sets the amber indicator, not the green one.
    const branch = html.slice(
      html.indexOf("} else if (wallCoarseOnly) {"),
      html.indexOf("} else if (hasPending) {"),
    );
    expect(branch).toContain("status-indicator amber");
    expect(branch).not.toContain("status-indicator green");
  });
});
