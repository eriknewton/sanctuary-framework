/**
 * Undeclared-workload detection + signed finding + seal (thin prototype, rung c).
 *
 * Cross-checks a synthetic LIVE supervised set (the supervisor `status()` shape)
 * against a DECLARED set projected from a #504 workload-lifecycle audit chain,
 * flags live workloads with no matching declared record, signs the finding
 * (reusing the #513 Ed25519 + canonical-JSON pattern), and seals it chain-bound.
 *
 * Asserts (mapping to the spawn-prompt test list):
 *   - live agent_1, registry empty → undeclared:[agent_1];
 *   - live & declared in sync (by workload_id) → none;
 *   - declared via instance_id match (workload_id != agent_id but instance_ids
 *     includes agent_id) → NOT flagged (the SEAM rule prevents the false alarm);
 *   - 3 live, 2 declared → exactly 1 undeclared;
 *   - the signed finding verifies offline; an envelope-only signer_kid swap is
 *     rejected (FIX-3 binding); the sealed entry is found by a chain walk;
 *   - the registry fold IGNORES workload_undeclared_detected;
 *   - the scope text disclaims host-wide completeness + the custom-mapping limit.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { generateKeypair } from "../../src/core/identity.js";
import type { SupervisedAgentState } from "../../src/supervisor/protocol.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_SCHEMA,
} from "../../src/workload-lifecycle/constants.js";
import {
  emitWorkloadLifecycle,
  type WorkloadLifecyclePayload,
} from "../../src/workload-lifecycle/payload.js";
import { WorkloadRegistry } from "../../src/workload-lifecycle/registry.js";
import type { WorkloadAttestationSigner } from "../../src/workload-lifecycle/host-attestation.js";
import {
  detectUndeclaredWorkloads,
  UNDECLARED_REASON,
  UNDECLARED_REASON_TERMINAL_DECLARATION,
  type LiveSupervisedWorkload,
} from "../../src/workload-lifecycle/undeclared-detection.js";
import {
  buildUndeclaredFinding,
  undeclaredFindingBundleHash,
  verifyUndeclaredFinding,
  WORKLOAD_UNDECLARED_FINDING_SCOPE_TEXT,
} from "../../src/workload-lifecycle/undeclared-finding.js";
import { sealUndeclaredFinding } from "../../src/workload-lifecycle/undeclared-finding-seal.js";

// ── Test signer: the opaque-bytes Ed25519 handle the builder consumes. ──────
// The SAME `WorkloadAttestationSigner` abstraction the #513 host attestation
// consumes (no second signer type). Production custody is the Castle Wall root
// signer; this carries a raw keypair only in-test.
function makeTestSigner(): WorkloadAttestationSigner & { privateKey: Uint8Array } {
  const { publicKey, privateKey } = generateKeypair();
  return {
    signer_kid: "test-fortress-signer",
    publicKey,
    privateKey,
    async sign(bytes: Uint8Array): Promise<Uint8Array> {
      return ed25519.sign(bytes, privateKey);
    },
  };
}

function live(
  agent_id: string,
  over: Partial<LiveSupervisedWorkload> = {},
): LiveSupervisedWorkload {
  return {
    agent_id,
    harness: "claude_code",
    state: "protected" as SupervisedAgentState,
    ...over,
  };
}

function base(
  over: Partial<WorkloadLifecyclePayload> = {},
): WorkloadLifecyclePayload {
  return {
    lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
    workload_id: "wl-1",
    instance_id: "wli-1",
    workload_class: "stateful-agent",
    class_definition: "sanctuary.workload-class.v1",
    initiator: { kind: "operator", identity_id: "op-1" },
    consent_ref: null,
    consent_status: "present",
    state_disposition: "running",
    manufactured_preference_caveat: true,
    ...over,
  };
}

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

/** Declare one workload via the sanctioned writer, keyed by the given ids. */
async function declare(
  auditLog: AuditLog,
  workload_id: string,
  instance_id: string,
  ts: number,
): Promise<void> {
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
    identity_id: "fortress-1",
    payload: base({ workload_id, instance_id, consent_ref: `consent://${workload_id}` }),
    timestamp: new Date(1_700_000_000_000 + ts * 1000).toISOString(),
  });
}

/** Declare one workload with an EXPLICIT lifecycle op (so the registry record's
 * folded `state` is e.g. `deleted` or `slept`), keyed by the given ids. */
async function declareOp(
  auditLog: AuditLog,
  operation: (typeof WORKLOAD_LIFECYCLE_OPS)[keyof typeof WORKLOAD_LIFECYCLE_OPS],
  workload_id: string,
  instance_id: string,
  ts: number,
): Promise<void> {
  // A workload_deleted record must record state_disposition "destroyed" (the
  // op↔payload internal-consistency check); other ops preserve state ("running").
  const isDelete = operation === WORKLOAD_LIFECYCLE_OPS.DELETED;
  await emitWorkloadLifecycle({
    auditLog,
    operation,
    identity_id: "fortress-1",
    payload: base({
      workload_id,
      instance_id,
      consent_ref: `consent://${workload_id}`,
      ...(isDelete ? { state_disposition: "destroyed" as const } : {}),
    }),
    timestamp: new Date(1_700_000_000_000 + ts * 1000).toISOString(),
  });
}

describe("detectUndeclaredWorkloads — live vs declared cross-check", () => {
  it("flags a live agent with NO declared record (undeclared:[agent_1])", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog); // empty
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual(["agent_1"]);
    expect(detection.undeclared[0]!.reason).toBe(UNDECLARED_REASON);
    expect(detection.undeclared[0]!.harness).toBe("claude_code");
    expect(detection.undeclared[0]!.supervisor_state).toBe("protected");
    expect(detection.live_count).toBe(1);
    expect(detection.declared_count).toBe(0);
  });

  it("flags NOTHING when live and declared are in sync (by workload_id)", async () => {
    const auditLog = newAuditLog();
    // Default wiring: workload_id === instance_id === agent_id.
    await declare(auditLog, "agent_1", "agent_1", 0);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    expect(detection.undeclared).toEqual([]);
    expect(detection.live_count).toBe(1);
    expect(detection.declared_count).toBe(1);
  });

  it("does NOT flag a custom-mapped workload declared via instance_id (THE SEAM RULE — no false alarm)", async () => {
    const auditLog = newAuditLog();
    // Custom adapter: workload_id differs from agent_id, but the agent_id is
    // carried as the instance_id. A naive workload_id-only diff would FALSE-FLAG
    // this as undeclared. The seam rule (match by workload_id OR instance_id)
    // resolves it correctly.
    await declare(auditLog, "custom-workload-name", "agent_1", 0);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    // The live agent_1 IS declared (via instance_id) — must NOT be flagged.
    expect(detection.undeclared).toEqual([]);
    expect(detection.declared_count).toBe(1);
  });

  it("3 live, 2 declared → exactly 1 undeclared (deterministic ordering)", async () => {
    const auditLog = newAuditLog();
    await declare(auditLog, "agent_a", "agent_a", 0); // declared by workload_id
    await declare(auditLog, "wl-custom", "agent_b", 1); // declared by instance_id
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      // Out-of-order live input to prove the sort.
      liveStatuses: [live("agent_b"), live("agent_c"), live("agent_a")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual(["agent_c"]);
    expect(detection.live_count).toBe(3);
    expect(detection.declared_count).toBe(2);
  });

  it("sorts the undeclared list by agent_id deterministically", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog); // empty
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("zeta"), live("alpha"), live("mike")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual([
      "alpha",
      "mike",
      "zeta",
    ]);
  });
});

describe("detectUndeclaredWorkloads — only ACTIVE declared records clear (codex follow-up)", () => {
  it("FLAGS a live workload matching only a workload_deleted record (deleted id reuse — codex repro)", async () => {
    const auditLog = newAuditLog();
    // The exact codex repro: agent_x was deleted, then a NEW live agent_x is
    // running with no fresh declaration. The old flat-union code (every declared
    // id clears, regardless of state) silently CLEARED this — a missed detection.
    // Only-active-records-clear must FLAG it with the terminal-record reason.
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.DELETED,
      "agent_x",
      "agent_x",
      0,
    );
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    // Sanity: the record exists but in terminal `deleted` state.
    expect(
      registry.listDeclared().map((r) => [r.workload_id, r.state]),
    ).toEqual([["agent_x", "deleted"]]);

    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_x")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual(["agent_x"]);
    expect(detection.undeclared[0]!.reason).toBe(
      UNDECLARED_REASON_TERMINAL_DECLARATION,
    );
    expect(detection.declared_count).toBe(1);
  });

  it("FLAGS a live workload matching only a workload_slept (dormant) record", async () => {
    const auditLog = newAuditLog();
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.SLEPT,
      "agent_y",
      "agent_y",
      0,
    );
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry.listDeclared()[0]!.state).toBe("slept");

    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_y")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual(["agent_y"]);
    expect(detection.undeclared[0]!.reason).toBe(
      UNDECLARED_REASON_TERMINAL_DECLARATION,
    );
  });

  it("does NOT flag a live workload matching an ACTIVE (instantiated/resumed) record (still cleared)", async () => {
    const auditLog = newAuditLog();
    // instantiated (active), then resumed (also active) — last state is `resumed`.
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      "agent_z",
      "agent_z",
      0,
    );
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.RESUMED,
      "agent_z",
      "agent_z",
      1,
    );
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry.listDeclared()[0]!.state).toBe("resumed");

    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_z")],
      registry,
    });
    expect(detection.undeclared).toEqual([]);
  });

  it("an ACTIVE record carrying agent_id as an instance_id still clears (no regression to the false-alarm fix)", async () => {
    const auditLog = newAuditLog();
    // Active record whose workload_id != agent_id, but instance_id == agent_id.
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      "custom-workload-name",
      "agent_inst",
      0,
    );
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_inst")],
      registry,
    });
    expect(detection.undeclared).toEqual([]);
    expect(detection.declared_count).toBe(1);
  });

  it("an ACTIVE record for a reused id wins over a terminal record sharing that id (cleared)", async () => {
    const auditLog = newAuditLog();
    // Same id appears on two distinct workload_ids: one terminal (deleted), one
    // active (instantiated). The active match must clear the live workload.
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.DELETED,
      "wl-old",
      "shared-inst",
      0,
    );
    await declareOp(
      auditLog,
      WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      "wl-new",
      "shared-inst",
      1,
    );
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("shared-inst")],
      registry,
    });
    expect(detection.undeclared).toEqual([]);
  });
});

describe("buildUndeclaredFinding — signed, offline-verifiable, tamper-evident", () => {
  it("signs a finding that verifies offline against the signer public key", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    const signer = makeTestSigner();
    const finding = await buildUndeclaredFinding({
      detection,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    expect(verifyUndeclaredFinding(finding, signer.publicKey)).toBe(true);
    expect(verifyUndeclaredFinding(finding, finding.public_key)).toBe(true);
    expect(finding.body.undeclared_count).toBe(1);
    expect(finding.body.undeclared[0]!.agent_id).toBe("agent_1");
  });

  it("fails verification when the undeclared list is tampered", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    const signer = makeTestSigner();
    const finding = await buildUndeclaredFinding({
      detection,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    // Drop the flagged workload (the exact laundering an auditor must catch).
    const tampered = {
      ...finding,
      body: { ...finding.body, undeclared: [], undeclared_count: 0 },
    };
    expect(verifyUndeclaredFinding(tampered, signer.publicKey)).toBe(false);
  });

  it("binds signer_kid into the signed body and rejects an envelope-only signer_kid swap (FIX-3)", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    const signer = makeTestSigner();
    const finding = await buildUndeclaredFinding({
      detection,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    expect(finding.body.signer_kid).toBe("test-fortress-signer");
    expect(finding.signer_kid).toBe(finding.body.signer_kid);
    expect(finding.body.signature_algorithm).toBe("Ed25519");
    expect(finding.body.payload_encoding).toBe(
      "domain-separated-canonical-json-v1",
    );
    // Swap ONLY the envelope's signer_kid (no re-sign). The body copy is under
    // signature, so the cross-check rejects it.
    const swapped = { ...finding, signer_kid: "attacker-controlled-kid" };
    expect(verifyUndeclaredFinding(swapped, signer.publicKey)).toBe(false);
    // Likewise an unexpected envelope algorithm/encoding is rejected.
    const badAlg = { ...finding, signature_algorithm: "RSA" as never };
    expect(verifyUndeclaredFinding(badAlg, signer.publicKey)).toBe(false);
    const badEnc = { ...finding, payload_encoding: "raw-json" as never };
    expect(verifyUndeclaredFinding(badEnc, signer.publicKey)).toBe(false);
  });
});

describe("sealUndeclaredFinding — chain-bound critical entry", () => {
  it("appends a workload_undeclared_detected entry a chain walk finds, bound by bundle hash", async () => {
    const auditLog = newAuditLog();
    await declare(auditLog, "agent_a", "agent_a", 0);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_a"), live("agent_b")],
      registry,
    });
    const signer = makeTestSigner();
    const finding = await buildUndeclaredFinding({
      detection,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    const boundHash = await sealUndeclaredFinding(auditLog, finding, {
      recording_identity_id: "fortress-1",
    });

    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED,
    });
    expect(entries).toHaveLength(1);
    const details = entries[0]!.details!;
    expect(details.finding_bundle_sha256).toBe(boundHash);
    expect(details.finding_bundle_sha256).toBe(
      undeclaredFindingBundleHash(finding),
    );
    expect(details.undeclared_count).toBe(1);
    expect(details.live_count).toBe(2);
    expect(details.declared_count).toBe(1);
    expect(details.undeclared_agent_ids).toEqual(["agent_b"]);
    expect(details.signer_kid).toBe("test-fortress-signer");
    expect(details.scope).toBe(WORKLOAD_UNDECLARED_FINDING_SCOPE_TEXT);
  });

  it("a chain integrity check passes after the finding is sealed", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    const finding = await buildUndeclaredFinding({
      detection,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    await sealUndeclaredFinding(auditLog, finding, {
      recording_identity_id: "fortress-1",
    });
    const res = await auditLog.query({ limit: 100 });
    expect(res.integrity_findings).toEqual([]);
  });
});

describe("registry fold ignores the undeclared-detection op", () => {
  it("a sealed workload_undeclared_detected entry adds NO declared workload", async () => {
    const auditLog = newAuditLog();
    // One genuine declared workload.
    await declare(auditLog, "agent_a", "agent_a", 0);
    const registry0 = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry0.listDeclared().map((r) => r.workload_id)).toEqual([
      "agent_a",
    ]);

    // Seal an undeclared-detection finding (a host-level summary event).
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_a"), live("agent_b")],
      registry: registry0,
    });
    const finding = await buildUndeclaredFinding({
      detection,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    await sealUndeclaredFinding(auditLog, finding, {
      recording_identity_id: "fortress-1",
    });

    // Rebuild: the detection entry must NOT add or mutate a declared workload
    // (it is NOT a per-workload state transition — excluded from OP_TO_STATE).
    const registry1 = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry1.listDeclared().map((r) => r.workload_id)).toEqual([
      "agent_a",
    ]);
  });
});

describe("honesty scoping — supervisor-view + custom-mapping disclaimer", () => {
  it("the finding scope disclaims host-wide completeness AND the custom-mapping limitation (regression guard)", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_1")],
      registry,
    });
    const finding = await buildUndeclaredFinding({
      detection,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    // Exact disclaimer text present.
    expect(finding.body.scope).toBe(WORKLOAD_UNDECLARED_FINDING_SCOPE_TEXT);
    // Compares LIVE supervised vs DECLARED, by workload_id OR instance_id.
    expect(finding.body.scope).toMatch(/LIVE supervised/);
    expect(finding.body.scope).toMatch(/DECLARED/);
    expect(finding.body.scope).toMatch(/workload_id OR by instance_id/i);
    // Disclaims host-wide process enumeration (rung d, out of scope).
    expect(finding.body.scope).toMatch(/does NOT enumerate all host processes/i);
    expect(finding.body.scope).toMatch(/out of scope/i);
    // Documents the custom-mapping limitation (both ids overridden).
    expect(finding.body.scope).toMatch(
      /overrode BOTH its workload_id AND its instance_id/i,
    );
    expect(finding.body.scope).toMatch(/not\s+definitive/i);
    // Discloses that ONLY active records clear, and a deleted/slept-only match
    // is flagged as running without a current declaration (FIX 1 disclosure).
    expect(finding.body.scope).toMatch(/Only ACTIVE declared records clear/i);
    expect(finding.body.scope).toMatch(
      /running without a current declaration/i,
    );
    // Discloses the false-CLEAR residual: ids not guaranteed unique/non-reused,
    // so an unrelated active record sharing an id could clear a live workload;
    // full precision needs per-instance identity disambiguation (FIX 2).
    expect(finding.body.scope).toMatch(/unique or non-reused/i);
    expect(finding.body.scope).toMatch(
      /UNRELATED active declared record that happens to share/i,
    );
    expect(finding.body.scope).toMatch(
      /per-instance identity disambiguation/i,
    );
    // No consciousness/sentience/welfare verdict.
    expect(finding.body.scope).toMatch(
      /NOT a consciousness, sentience, or welfare verdict/i,
    );
  });
});
