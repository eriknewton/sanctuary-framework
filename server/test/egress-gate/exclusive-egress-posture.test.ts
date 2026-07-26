/**
 * Unified Protect Slice 5 S5-P: the exclusive-egress posture object (design
 * rev3 §6), unit-tested from mocked probe results per the PR table's own
 * acceptance line ("Unit: posture states from mocked probes").
 *
 * The load-bearing invariants:
 *  - `mode: "exclusive"` (the only green-contributing state) requires the
 *    declared fine-grained intent AND the coarse wall AND every component
 *    (generation match, pf liveness, gate up + owner-verified) live;
 *  - every component failure surfaces in the reasons vector (never a silent
 *    boolean collapse);
 *  - the posture consumes the REAL S5-2 committed-generation semantics: a
 *    staging record, a tombstone, or a dirty registry mean NOT committed,
 *    never live;
 *  - the S5-3 liveness-oracle verify output drops in as the pf probe, so an
 *    expired/absent/forged token reads not-live with its reason;
 *  - the summary + capping rule fire iff a fine-grained-declared agent is not
 *    exclusive, and the failed-provider stand-in always caps (fail-closed).
 */

import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";

import {
  buildExclusiveEgressPosture,
  summarizeExclusiveEgressStatus,
  exclusiveEgressCapsAggregateGreen,
  failedExclusiveEgressStatus,
  type ExclusiveEgressPostureInput,
} from "../../src/egress-gate/posture.js";
import {
  GateLivenessOracle,
  createOracleLivenessProbe,
  type LivenessTokenSource,
} from "../../src/egress-gate/liveness-oracle.js";
import type { PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";

const LIVE_PF: PfLivenessResult = { live: true, reasons: [] };

/** A fully-live, fine-grained-declared baseline input; tests override fields. */
function liveInput(
  overrides: Partial<ExclusiveEgressPostureInput> = {},
): ExclusiveEgressPostureInput {
  return {
    agent_uid: 601,
    fine_grained_declared: true,
    coarse_wall_armed: true,
    registry_entry: { agent_uid: 601, gate_port: 49152, generation_id: 7 },
    staging_record_present: false,
    registry_dirty: false,
    pf_pass_port: 49152,
    manifest: { gate_port: 49152, generation_id: 7 },
    pf_liveness: LIVE_PF,
    gate_process: { up: true, port_owner_verified: true, reasons: [] },
    ...overrides,
  };
}

describe("S5-P exclusive-egress posture object (mocked probes)", () => {
  it("reads EXCLUSIVE (live) only when everything is live: declared + wall + generation + pf + gate", () => {
    const posture = buildExclusiveEgressPosture(liveInput());
    expect(posture.mode).toBe("exclusive");
    expect(posture.exclusive_egress_live).toBe(true);
    expect(posture.reasons).toEqual([]);
    expect(posture.generation_match.serve).toBe(true);
    expect(posture.manifest_gate_rule_generation).toBe(7);
  });

  it("a staging record in flight means NOT committed => never exclusive (S5-2 resolveCommittedGeneration semantics)", () => {
    const posture = buildExclusiveEgressPosture(
      liveInput({ staging_record_present: true }),
    );
    expect(posture.mode).toBe("coarse-only");
    expect(posture.exclusive_egress_live).toBe(false);
    expect(posture.generation_match.serve).toBe(false);
    expect(posture.reasons.join(" ")).toContain("no committed generation");
  });

  it("a tombstoned uid is never live (the gate pass was dropped)", () => {
    const posture = buildExclusiveEgressPosture(
      liveInput({
        registry_entry: {
          agent_uid: 601,
          gate_port: 49152,
          generation_id: 7,
          tombstone: true,
        },
      }),
    );
    expect(posture.mode).toBe("coarse-only");
    expect(posture.exclusive_egress_live).toBe(false);
  });

  it("a dirty (needs-repair) registry is never live", () => {
    const posture = buildExclusiveEgressPosture(liveInput({ registry_dirty: true }));
    expect(posture.exclusive_egress_live).toBe(false);
    expect(posture.mode).toBe("coarse-only");
  });

  it("no registry entry at all => not live", () => {
    const posture = buildExclusiveEgressPosture(liveInput({ registry_entry: null }));
    expect(posture.exclusive_egress_live).toBe(false);
  });

  it("pf pass-rule port disagreeing with the committed port refuses (three-surface generation match)", () => {
    const posture = buildExclusiveEgressPosture(liveInput({ pf_pass_port: 50000 }));
    expect(posture.exclusive_egress_live).toBe(false);
    expect(posture.reasons.join(" ")).toContain("pf pass port");
  });

  it("manifest port / generation mismatches refuse", () => {
    const wrongPort = buildExclusiveEgressPosture(
      liveInput({ manifest: { gate_port: 50001, generation_id: 7 } }),
    );
    expect(wrongPort.exclusive_egress_live).toBe(false);
    expect(wrongPort.reasons.join(" ")).toContain("manifest port");

    const wrongGen = buildExclusiveEgressPosture(
      liveInput({ manifest: { gate_port: 49152, generation_id: 6 } }),
    );
    expect(wrongGen.exclusive_egress_live).toBe(false);
    expect(wrongGen.reasons.join(" ")).toContain("manifest generation");
  });

  it("an absent manifest reads null generation and refuses", () => {
    const posture = buildExclusiveEgressPosture(liveInput({ manifest: null }));
    expect(posture.manifest_gate_rule_generation).toBeNull();
    expect(posture.exclusive_egress_live).toBe(false);
  });

  it("pf not-live carries the FULL reasons vector through (never collapsed)", () => {
    const posture = buildExclusiveEgressPosture(
      liveInput({
        pf_liveness: {
          live: false,
          reasons: ["anchor rules missing", "hook not installed"],
        },
      }),
    );
    expect(posture.exclusive_egress_live).toBe(false);
    expect(posture.pf_liveness.live).toBe(false);
    expect(posture.pf_liveness.reasons).toEqual([
      "anchor rules missing",
      "hook not installed",
    ]);
    expect(posture.reasons).toContain("pf: anchor rules missing");
    expect(posture.reasons).toContain("pf: hook not installed");
  });

  it("gate down / owner-unverified each refuse with a named reason", () => {
    const down = buildExclusiveEgressPosture(
      liveInput({ gate_process: { up: false, port_owner_verified: false, reasons: [] } }),
    );
    expect(down.exclusive_egress_live).toBe(false);
    expect(down.reasons).toContain("gate: process not up");

    const squatted = buildExclusiveEgressPosture(
      liveInput({
        gate_process: {
          up: true,
          port_owner_verified: false,
          reasons: ["listener start-time mismatch"],
        },
      }),
    );
    expect(squatted.exclusive_egress_live).toBe(false);
    expect(squatted.reasons).toContain("gate: port owner not verified");
    expect(squatted.reasons).toContain("gate: listener start-time mismatch");
  });

  it("a live stack WITHOUT the declared fine-grained intent never reads exclusive", () => {
    const posture = buildExclusiveEgressPosture(
      liveInput({ fine_grained_declared: false }),
    );
    expect(posture.mode).toBe("coarse-only");
    expect(posture.exclusive_egress_live).toBe(true);
  });

  it("a fine-grained agent with the coarse wall DOWN reads unprotected (never exclusive, never coarse-only)", () => {
    const posture = buildExclusiveEgressPosture(
      liveInput({ coarse_wall_armed: false }),
    );
    expect(posture.mode).toBe("unprotected");
    expect(posture.reasons).toContain(
      "wall: coarse Castle Wall enforcement not confirmed for this fortress",
    );
  });

  it("S5-3 integration: an EXPIRED oracle token read through the real probe reads pf-not-live with the expiry reason", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    let stored: string | null = null;
    let clock = 1_000_000;
    const oracle = new GateLivenessOracle(
      privateKey,
      {
        writeToken: async (_uid, payload) => {
          stored = payload;
        },
        removeToken: async () => {
          stored = null;
        },
        probe: async () => ({ live: true, reasons: [] }),
        now: () => clock,
      },
      { ttlMs: 2_000 },
    );
    const binding = { agentUid: 601, gatePort: 49152, generationId: 7 };
    await oracle.refresh(binding);
    const source: LivenessTokenSource = {
      read: async () => stored,
    };
    const probe = createOracleLivenessProbe({
      source,
      publicKey,
      binding,
      now: () => clock,
    });
    // Fresh token: live.
    const fresh = await probe.check();
    expect(fresh.live).toBe(true);
    expect(
      buildExclusiveEgressPosture(liveInput({ pf_liveness: fresh }))
        .exclusive_egress_live,
    ).toBe(true);

    // Let the token expire: the SAME posture input flips not-live with the
    // oracle's own reason - no parallel bookkeeping, the S5-3 verdict IS the
    // posture's pf verdict.
    clock += 10_000;
    const expired = await probe.check();
    expect(expired.live).toBe(false);
    const posture = buildExclusiveEgressPosture(liveInput({ pf_liveness: expired }));
    expect(posture.exclusive_egress_live).toBe(false);
    expect(posture.mode).toBe("coarse-only");
    expect(posture.reasons.join(" ")).toContain("expired");
  });
});

describe("S5-P summary + aggregate-green capping rule", () => {
  it("no fine-grained agent declared => vacuously live, cap never fires", () => {
    const coarseAgent = buildExclusiveEgressPosture(
      liveInput({ fine_grained_declared: false, registry_entry: null, manifest: null }),
    );
    const summary = summarizeExclusiveEgressStatus([coarseAgent]);
    expect(summary.fine_grained_declared).toBe(false);
    expect(summary.exclusive_egress_live).toBe(true);
    expect(summary.mode).toBeNull();
    expect(exclusiveEgressCapsAggregateGreen(summary)).toBe(false);
    expect(exclusiveEgressCapsAggregateGreen(null)).toBe(false);
    expect(exclusiveEgressCapsAggregateGreen(undefined)).toBe(false);
  });

  it("one fine-grained agent not exclusive => cap fires with per-uid reasons", () => {
    const dead = buildExclusiveEgressPosture(liveInput({ manifest: null }));
    const summary = summarizeExclusiveEgressStatus([dead]);
    expect(summary.fine_grained_declared).toBe(true);
    expect(summary.exclusive_egress_live).toBe(false);
    expect(summary.mode).toBe("coarse-only");
    expect(summary.reasons.join(" ")).toContain("uid 601");
    expect(exclusiveEgressCapsAggregateGreen(summary)).toBe(true);
  });

  it("every fine-grained agent exclusive => no cap", () => {
    const a = buildExclusiveEgressPosture(liveInput());
    const b = buildExclusiveEgressPosture(
      liveInput({
        agent_uid: 602,
        registry_entry: { agent_uid: 602, gate_port: 49200, generation_id: 3 },
        pf_pass_port: 49200,
        manifest: { gate_port: 49200, generation_id: 3 },
      }),
    );
    const summary = summarizeExclusiveEgressStatus([a, b]);
    expect(summary.exclusive_egress_live).toBe(true);
    expect(summary.mode).toBe("exclusive");
    expect(exclusiveEgressCapsAggregateGreen(summary)).toBe(false);
  });

  it("worst-mode fold: unprotected < coarse-only < exclusive", () => {
    const ok = buildExclusiveEgressPosture(liveInput());
    const unprotectedAgent = buildExclusiveEgressPosture(
      liveInput({ agent_uid: 603, coarse_wall_armed: false }),
    );
    const summary = summarizeExclusiveEgressStatus([ok, unprotectedAgent]);
    expect(summary.mode).toBe("unprotected");
    expect(exclusiveEgressCapsAggregateGreen(summary)).toBe(true);
  });

  it("the failed-provider stand-in ALWAYS caps green (fail-closed)", () => {
    const failed = failedExclusiveEgressStatus("boom");
    expect(failed.fine_grained_declared).toBe(true);
    expect(failed.exclusive_egress_live).toBe(false);
    expect(exclusiveEgressCapsAggregateGreen(failed)).toBe(true);
    expect(failed.reasons.join(" ")).toContain("boom");
  });
});
