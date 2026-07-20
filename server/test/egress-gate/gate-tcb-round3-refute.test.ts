/**
 * INDEPENDENT round-3 refute suite (Family-A final pass). Attacks the two
 * round-3 fixes:
 *   (1) createOracleLivenessProbe freezes the advertised `probe.binding` AND the
 *       whole probe, so the construction-time cross-check and the runtime verify
 *       read the SAME immutable snapshot (no divergence bypass);
 *   (2) gate-account makes `agentUid` REQUIRED and ALWAYS excluded from the gate
 *       uid (create plans refuse on it, skip plans refuse, non-positive
 *       agentUid rejected).
 * Every test is an ATTACK; the assertion is that the bypass FAILS.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";

import {
  createExclusiveEgressGate,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import {
  createOracleLivenessProbe,
  type LivenessTokenSource,
  type LivenessProbeBinding,
} from "../../src/egress-gate/liveness-oracle.js";
import {
  planGateAccountProvision,
  planAndCreateGateAccount,
  GateUidCollisionError,
  type GateAccountProvisionOptions,
} from "../../src/egress-gate/gate-account.js";
import type { GateAccountProvisionOps } from "../../src/egress-gate/gate-account.js";
import type { ExclusiveEgressGatePolicy } from "../../src/castle-wall/allowlist/gate-derivation.js";

const AGENT_UID = 502;
const GATE_PORT = 47311;
const GATE_HOME = "/var/sanctuary-agents/sanctuary-gate-hermes";
const policy: ExclusiveEgressGatePolicy = { agent_uid: AGENT_UID, gate_port: GATE_PORT };

// ---------------------------------------------------------------------------
// Round-3 fix (1): probe binding divergence.
// ---------------------------------------------------------------------------
describe("round-3 fix (1) refute: probe binding cannot be diverged after construction", () => {
  const source: LivenessTokenSource = { read: () => Promise.resolve(null) };
  const { publicKey } = generateKeyPairSync("ed25519");

  function matchingProbe(): GateLivenessProbe {
    return createOracleLivenessProbe({
      source,
      publicKey,
      binding: { agentUid: AGENT_UID, gatePort: GATE_PORT, generationId: 7 },
    });
  }

  it("REASSIGNING probe.binding to a foreign binding does NOT change what the gate cross-checks", () => {
    const probe = matchingProbe();
    // Attack: try to swap the advertised binding to a foreign one AFTER
    // construction so the gate is built against the ORIGINAL (matching) binding
    // but check() would enforce the foreign one. The whole probe is frozen, so
    // the reassignment must not take.
    try {
      (probe as unknown as { binding: unknown }).binding = { agentUid: 999, gatePort: GATE_PORT };
    } catch {
      // strict-mode ESM throws on writing a frozen prop; both outcomes are fine.
    }
    expect(probe.binding).toEqual({ agentUid: AGENT_UID, gatePort: GATE_PORT });
    // The gate still builds (binding still matches policy) -- the reassignment
    // never diverged the advertised binding.
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: probe })).not.toThrow();
  });

  it("MUTATING probe.binding.agentUid does NOT change the advertised binding", () => {
    const probe = matchingProbe();
    try {
      (probe.binding as unknown as { agentUid: number }).agentUid = 999;
    } catch {
      // frozen -> throws in strict mode; fine.
    }
    expect(probe.binding?.agentUid).toBe(AGENT_UID);
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: probe })).not.toThrow();
  });

  it("MUTATING the caller-owned input.binding object after construction has no effect (snapshot copied)", async () => {
    const mutableBinding: LivenessProbeBinding = { agentUid: AGENT_UID, gatePort: GATE_PORT, generationId: 7 };
    const probe = createOracleLivenessProbe({ source, publicKey, binding: mutableBinding });
    // Attack: mutate the caller-owned object to a foreign agent/port. Neither the
    // advertised binding (cross-checked at construction) nor the enforced binding
    // (read by check()) may follow it.
    mutableBinding.agentUid = 999;
    mutableBinding.gatePort = GATE_PORT + 1;
    mutableBinding.generationId = 42;
    expect(probe.binding).toEqual({ agentUid: AGENT_UID, gatePort: GATE_PORT });
    // Gate still builds against the immutable snapshot (matches policy).
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: probe })).not.toThrow();
    // And check() reads null token (source) -> fail-closed not-live, proving it
    // ran against the frozen bound copy, not the mutated foreign object.
    const res = await probe.check();
    expect(res.live).toBe(false);
  });

  it("a foreign advertised binding built from the START is still refused at construction (control)", () => {
    const foreign = createOracleLivenessProbe({
      source,
      publicKey,
      binding: { agentUid: 999, gatePort: GATE_PORT, generationId: 7 },
    });
    expect(() => createExclusiveEgressGate({ policy, rules: [], livenessProbe: foreign })).toThrow(/must match policy/);
  });

  it("the probe object itself is frozen (no method/binding swap is possible)", () => {
    const probe = matchingProbe();
    expect(Object.isFrozen(probe)).toBe(true);
    expect(Object.isFrozen(probe.binding)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Round-3 fix (2): required + always-excluded agentUid.
// ---------------------------------------------------------------------------
describe("round-3 fix (2) refute: gate uid can never collide with the agent uid", () => {
  const base = (over: Partial<GateAccountProvisionOptions> = {}): GateAccountProvisionOptions => ({
    agentId: "hermes",
    agentUid: AGENT_UID,
    ceiling: 400,
    homeDirectory: GATE_HOME,
    ...over,
  });

  it("REFUSES a create plan whose computed uid lands on the agent uid, excludeUids OMITTED", () => {
    // ceiling 502, highest 501 => create uid = max(502, 502) = 502 = AGENT_UID.
    expect(() =>
      planGateAccountProvision(base({ ceiling: AGENT_UID }), {
        existingUid: undefined,
        highestAssignedUid: AGENT_UID - 1,
      }),
    ).toThrow(GateUidCollisionError);
  });

  it("REFUSES a skip plan sitting on the agent uid, excludeUids OMITTED", () => {
    expect(() =>
      planGateAccountProvision(base(), { existingUid: AGENT_UID, highestAssignedUid: 600 }),
    ).toThrow(GateUidCollisionError);
  });

  it("REJECTS a non-positive agentUid (0 / negative / non-integer) before any planning", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() =>
        planGateAccountProvision(base({ agentUid: bad }), { existingUid: undefined, highestAssignedUid: 700 }),
      ).toThrow(/agentUid must be a positive integer/);
    }
  });

  it("does NOT break a legitimate provision (agent uid distinct from a valid dedicated gate uid)", () => {
    const plan = planGateAccountProvision(base({ ceiling: 400 }), { existingUid: undefined, highestAssignedUid: 700 });
    expect(plan.action).toBe("create");
    expect(plan.uid).toBe(701);
    expect(plan.uid).not.toBe(AGENT_UID);
  });

  it("the create exclusion refuses before any create side effect runs", async () => {
    let record:
      | { uid: number; homeDirectory: string; isHidden?: boolean; userShell: string }
      | undefined;
    let createdUid: number | undefined;
    let lookupCalls = 0;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: () => Promise.resolve(undefined),
      lookupAccountRecord: () => {
        lookupCalls += 1;
        return Promise.resolve(lookupCalls === 1 ? undefined : record);
      },
      canonicalizeHomeDirectory: (path) => Promise.resolve(path),
      // highest is one below the agent uid so the computed create uid == agent uid.
      highestAssignedUid: () => Promise.resolve(AGENT_UID - 1),
      createUser: (_accountName, uid, _comment, homeDirectory) => {
        createdUid = uid;
        record = { uid, homeDirectory, userShell: "/usr/bin/false" };
        return Promise.resolve();
      },
      hardenCreatedUser: () => {
        if (record !== undefined) record = { ...record, isHidden: true };
        return Promise.resolve();
      },
    };
    await expect(planAndCreateGateAccount(base({ ceiling: AGENT_UID }), ops)).rejects.toThrow(GateUidCollisionError);
    expect(createdUid).toBeUndefined();
  });

  it("still excludes the agent uid even when excludeUids lists only OPERATOR uids (agent uid is structural)", () => {
    expect(() =>
      planGateAccountProvision(base({ ceiling: AGENT_UID, excludeUids: [501, 0] }), {
        existingUid: undefined,
        highestAssignedUid: AGENT_UID - 1,
      }),
    ).toThrow(GateUidCollisionError);
  });
});
