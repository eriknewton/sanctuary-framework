/**
 * Unified Protect Slice 5 S5-7: the per-agent unprotect sequence
 * (`runEgressGateUnprotect`). Host-free: every side effect is an injected
 * recorder op. Pins the design's S5-7 row semantics -- two-agent remove-one
 * (sibling confinement preserved, no flush), last-agent flush, idempotent
 * re-run -- plus the ordering + fail-closed contract: park FIRST, registry
 * remove LAST, every failure leaves remaining protection intact and reports
 * an honest staged outcome with a verified parked claim.
 */

import { describe, it, expect } from "vitest";

import {
  EGRESS_GATE_UNPROTECT_AUDIT_OP,
  EGRESS_GATE_UNPROTECT_FAILED_AUDIT_OP,
  runEgressGateUnprotect,
  type EgressGateUnprotectOps,
} from "../../../src/castle-wall/provision/exclusive-unprotect.js";

interface Recorder {
  ops: EgressGateUnprotectOps;
  calls: string[];
  audits: { operation: string; details: Record<string, unknown> }[];
  prints: string[];
}

function makeOps(overrides: Partial<EgressGateUnprotectOps> = {}): Recorder {
  const calls: string[] = [];
  const audits: { operation: string; details: Record<string, unknown> }[] = [];
  const prints: string[] = [];
  const ops: EgressGateUnprotectOps = {
    async parkHarness() {
      calls.push("park");
    },
    async verifyParkedPersistent() {
      calls.push("verify-parked");
      return { ok: true };
    },
    async recoverGeneration() {
      calls.push("recover");
    },
    async bootoutGateDaemon() {
      calls.push("bootout-gate");
    },
    async invalidateOracleToken() {
      calls.push("invalidate-token");
    },
    async revokeCredential() {
      calls.push("revoke-credential");
    },
    async removeGateSurfaces() {
      calls.push("remove-surfaces");
    },
    async scrubProvisionedRules() {
      calls.push("scrub");
      return { removedRuleIds: ["provisioned-hermes-api"], reloadOk: true };
    },
    async removeRegistryEntry() {
      calls.push("registry-remove");
      return { remainingUids: [602], flushed: false, dirty: false };
    },
    async audit(operation, details) {
      audits.push({ operation, details });
    },
    print(line) {
      prints.push(line);
    },
    ...overrides,
  };
  return { ops, calls, audits, prints };
}

const ctx = { agentUid: 601 };

describe("castle-wall/provision/exclusive-unprotect: happy paths", () => {
  it("two-agent remove-one: unprotects, preserves the sibling (no flush), audits", async () => {
    const r = makeOps();
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toEqual({
      kind: "unprotected",
      remainingUids: [602],
      flushed: false,
      registryDirty: false,
    });
    expect(r.audits).toHaveLength(1);
    expect(r.audits[0]?.operation).toBe(EGRESS_GATE_UNPROTECT_AUDIT_OP);
    expect(r.audits[0]?.details).toMatchObject({
      agent_uid: 601,
      remaining_uids: [602],
      anchor_flushed: false,
      registry_dirty: false,
      scrubbed_rule_ids: ["provisioned-hermes-api"],
      reload_confirmed: true,
    });
    expect(r.prints.some((l) => l.includes("re-verified live"))).toBe(true);
    expect(r.prints.some((l) => l.includes("602"))).toBe(true);
  });

  it("runs the teardown in the contract order: park -> recover -> gate daemon -> credential -> scrub -> policy -> registry LAST", async () => {
    const r = makeOps();
    await runEgressGateUnprotect(ctx, r.ops);
    // Fix-round LOW-2: the manifest scrub runs BEFORE the policy-surface
    // (routing-marker) removal so a crash + external reload composes
    // marker-present-no-rules (fail-closed), never marker-gone-rules-present.
    expect(r.calls).toEqual([
      "park",
      "recover",
      "bootout-gate",
      "invalidate-token",
      "revoke-credential",
      "scrub",
      "remove-surfaces",
      "registry-remove",
    ]);
  });

  it("last-agent flush: reports flushed and says so", async () => {
    const r = makeOps({
      async removeRegistryEntry() {
        return { remainingUids: [], flushed: true, dirty: false };
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotected", remainingUids: [], flushed: true });
    expect(r.prints.some((l) => l.includes("flushed"))).toBe(true);
    expect(r.audits[0]?.details).toMatchObject({ anchor_flushed: true });
  });

  it("idempotent re-run converges: a second run over already-torn-down ops unprotects again", async () => {
    // Every op tolerates already-gone by contract; the registry's remove of an
    // absent uid is a reconciling no-op returning the (empty) remaining set.
    const r = makeOps({
      async removeRegistryEntry() {
        return { remainingUids: [], flushed: true, dirty: false };
      },
    });
    const first = await runEgressGateUnprotect(ctx, r.ops);
    const second = await runEgressGateUnprotect(ctx, r.ops);
    expect(first.kind).toBe("unprotected");
    expect(second).toEqual(first);
  });

  it("registry dirty after remove: still unprotected, but LOUD + flagged (repair owed)", async () => {
    const r = makeOps({
      async removeRegistryEntry() {
        return { remainingUids: [602], flushed: false, dirty: true };
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotected", registryDirty: true });
    expect(r.prints.some((l) => l.includes("--repair-egress-gate"))).toBe(true);
    expect(r.audits[0]?.details).toMatchObject({ registry_dirty: true });
  });

  it("an unconfirmed policy reload after the scrub is loud but not fatal (rules already gone from the signing source)", async () => {
    const r = makeOps({
      async scrubProvisionedRules() {
        return { removedRuleIds: ["provisioned-hermes-api"], reloadOk: false };
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome.kind).toBe("unprotected");
    expect(r.prints.some((l) => l.includes("reload could not be confirmed"))).toBe(true);
    expect(r.audits[0]?.details).toMatchObject({ reload_confirmed: false });
  });
});

describe("castle-wall/provision/exclusive-unprotect: fail-closed staged failures", () => {
  it("park failure: honest 'park' stage, NOTHING dismantled (no later op ran)", async () => {
    const r = makeOps({
      async parkHarness() {
        throw new Error("launchctl disable exited 1");
      },
      async verifyParkedPersistent() {
        return { ok: false, problems: ["the harness job reports RUNNING (pid 4242)"] };
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({
      kind: "unprotect-failed",
      stage: "park",
      parkedStateVerified: false,
    });
    if (outcome.kind !== "unprotect-failed") throw new Error("unreachable");
    expect(outcome.parkedStateProblems).toEqual(["the harness job reports RUNNING (pid 4242)"]);
    // No teardown op ran: the leaving uid's confinement is fully intact.
    expect(r.calls.filter((c) => c !== "verify-parked")).toEqual([]);
    expect(r.audits[0]?.operation).toBe(EGRESS_GATE_UNPROTECT_FAILED_AUDIT_OP);
    expect(r.audits[0]?.details).toMatchObject({ stage: "park", parked_state_verified: false });
  });

  it("recover failure: 'recover' stage, gate daemon and registry untouched", async () => {
    const r = makeOps({
      async recoverGeneration() {
        throw new Error("staging record unreadable");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "recover", parkedStateVerified: true });
    expect(r.calls).not.toContain("bootout-gate");
    expect(r.calls).not.toContain("registry-remove");
  });

  it("a genuine gate-daemon bootout failure is LOUD and stops the teardown (never .catch(() => undefined))", async () => {
    const r = makeOps({
      async bootoutGateDaemon() {
        throw new Error("launchctl bootout ai.sanctuaryprotocol.egress-gate.601 exited 5: Input/output error");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "gate-daemon" });
    if (outcome.kind !== "unprotect-failed") throw new Error("unreachable");
    expect(outcome.reason).toContain("possibly-live gate");
    expect(outcome.reason).toContain("exited 5");
    expect(r.calls).not.toContain("invalidate-token");
    expect(r.calls).not.toContain("remove-surfaces");
    expect(r.calls).not.toContain("registry-remove");
  });

  it("credential teardown failure: 'credential' stage, policy + registry untouched", async () => {
    const r = makeOps({
      async revokeCredential() {
        throw new Error("EACCES: /var/db/sanctuary/gate-cred/601.accept");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "credential" });
    expect(r.calls).toContain("invalidate-token");
    expect(r.calls).not.toContain("remove-surfaces");
    expect(r.calls).not.toContain("registry-remove");
  });

  it("scrub failure (a rule survived the verified read-back): 'manifest-scrub' stage, policy + registry untouched", async () => {
    const r = makeOps({
      async scrubProvisionedRules() {
        throw new Error("egress rule scrub left 1 provisioned rule file(s) behind");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "manifest-scrub" });
    // Scrub now runs BEFORE the policy-surface removal (LOW-2), so a scrub
    // failure leaves the routing marker + registry untouched.
    expect(r.calls).not.toContain("remove-surfaces");
    expect(r.calls).not.toContain("registry-remove");
  });

  it("policy-surface removal failure: 'policy' stage, registry untouched (scrub already ran)", async () => {
    const r = makeOps({
      async removeGateSurfaces() {
        throw new Error("EPERM: exclusive-routing.json");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "policy" });
    // The scrub ran first (LOW-2 ordering); only the registry remove is skipped.
    expect(r.calls).toContain("scrub");
    expect(r.calls).not.toContain("registry-remove");
  });

  it("registry-remove failure: 'registry' stage, reason names the journaled-transaction rollback", async () => {
    const r = makeOps({
      async removeRegistryEntry() {
        throw new Error("union liveness verification failed for uid 602");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", stage: "registry" });
    if (outcome.kind !== "unprotect-failed") throw new Error("unreachable");
    expect(outcome.reason).toContain("remaining uids stay confined");
    expect(outcome.reason).toContain("union liveness verification failed for uid 602");
    // No success audit; exactly one failure audit.
    expect(r.audits).toHaveLength(1);
    expect(r.audits[0]?.operation).toBe(EGRESS_GATE_UNPROTECT_FAILED_AUDIT_OP);
  });

  it("a THROWING parked-state probe on the failure path reads as not-verified (never green by default)", async () => {
    const r = makeOps({
      async parkHarness() {
        throw new Error("bootout hung");
      },
      async verifyParkedPersistent() {
        throw new Error("launchctl print timed out");
      },
    });
    const outcome = await runEgressGateUnprotect(ctx, r.ops);
    expect(outcome).toMatchObject({ kind: "unprotect-failed", parkedStateVerified: false });
    if (outcome.kind !== "unprotect-failed") throw new Error("unreachable");
    expect(outcome.parkedStateProblems[0]).toContain("parked-state verify probe threw");
  });
});
