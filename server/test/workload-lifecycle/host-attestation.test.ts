/**
 * Host workload attestation + registry projection (thin prototype, rung b).
 *
 * Builds a synthetic audit chain of #504 workload-lifecycle entries via the
 * sanctioned writer (`emitWorkloadLifecycle`), projects it with
 * `WorkloadRegistry`, attests over it, and seals the attestation chain-bound.
 *
 * Asserts:
 *   - registry projection replays register → instantiate → pause → sleep, a
 *     fork (new instance), a delete-with-override, and a delete with
 *     consent_status:absent + override;
 *   - consent classification (present/inherited → consented; absent-no-override
 *     → unconsented; delete-with-valid-override → consented);
 *   - compliant:false (fail-closed but HONEST) still lists the unconsented
 *     workload truthfully; compliant:true only when ALL declared are consented;
 *   - the signature verifies offline and tampering the bundle fails it;
 *   - the seal appends a chain-bound `workload_host_attestation` entry a chain
 *     walk finds, bound by the bundle hash;
 *   - the payload's `scope` honestly disclaims undeclared-workload completeness
 *     (regression guard against a future over-claim).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { generateKeypair } from "../../src/core/identity.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_SCHEMA,
} from "../../src/workload-lifecycle/constants.js";
import {
  emitWorkloadLifecycle,
  type WorkloadLifecyclePayload,
} from "../../src/workload-lifecycle/payload.js";
import { WorkloadRegistry } from "../../src/workload-lifecycle/registry.js";
import {
  buildHostWorkloadAttestation,
  classifyConsent,
  hostAttestationBundleHash,
  verifyHostWorkloadAttestation,
  WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT,
  type WorkloadAttestationSigner,
} from "../../src/workload-lifecycle/host-attestation.js";
import { sealHostAttestation } from "../../src/workload-lifecycle/host-attestation-seal.js";

// ── Test signer: the opaque-bytes Ed25519 handle the builder consumes. ──────
// Mirrors the production signer abstraction (TransparencySigner): carries a raw
// keypair only in-test; production custody is the Castle Wall root signer.
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

function base(
  over: Partial<WorkloadLifecyclePayload> = {}
): WorkloadLifecyclePayload {
  return {
    lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
    workload_id: "wl-1",
    instance_id: "wli-1",
    workload_class: "stateful-agent",
    class_definition: "sanctuary.workload-class.v1",
    initiator: { kind: "operator", identity_id: "op-1" },
    consent_ref: null,
    consent_status: "absent",
    state_disposition: "running",
    manufactured_preference_caveat: true,
    ...over,
  };
}

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

/**
 * Emit a synthetic chain covering:
 *   wl-1: register → instantiate → pause → sleep, consent present
 *   wl-2: instantiate (fork from wl-1's instance, new instance id), inherited
 *   wl-3: instantiate, consent ABSENT, no override → unconsented
 *   wl-4: delete with consent absent + valid override → consented (gated)
 */
async function buildMixedChain(auditLog: AuditLog): Promise<void> {
  let ts = 0;
  const at = () => new Date(1_700_000_000_000 + ts++ * 1000).toISOString();

  // wl-1 lifecycle, consent present throughout, ending slept.
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.REGISTERED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-1",
      instance_id: "wli-1",
      consent_status: "present",
      consent_ref: "consent://wl-1",
    }),
    timestamp: at(),
  });
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-1",
      instance_id: "wli-1",
      consent_status: "present",
      consent_ref: "consent://wl-1",
    }),
    timestamp: at(),
  });
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.PAUSED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-1",
      instance_id: "wli-1",
      consent_status: "present",
      consent_ref: "consent://wl-1",
      state_disposition: "preserved",
      prev_lifecycle_seq: 1,
    }),
    timestamp: at(),
  });
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.SLEPT,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-1",
      instance_id: "wli-1",
      consent_status: "present",
      consent_ref: "consent://wl-1",
      state_disposition: "preserved",
      prev_lifecycle_seq: 2,
    }),
    timestamp: at(),
  });

  // wl-2: fork of wl-1 into a new instance, consent inherited.
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.FORKED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-2",
      instance_id: "wli-2",
      consent_status: "inherited",
      consent_ref: "consent://wl-1",
      state_disposition: "preserved",
      lineage: { parents: ["wli-1"] },
    }),
    timestamp: at(),
  });

  // wl-3: instantiated, consent ABSENT, no override → unconsented (loud).
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-3",
      instance_id: "wli-3",
      consent_status: "absent",
      consent_ref: null,
    }),
    timestamp: at(),
  });

  // wl-4: delete with consent ABSENT but a valid Tier-1 override → consented.
  await emitWorkloadLifecycle({
    auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.DELETED,
    identity_id: "fortress-1",
    payload: base({
      workload_id: "wl-4",
      instance_id: "wli-4",
      consent_status: "absent",
      consent_ref: null,
      state_disposition: "destroyed",
      override: {
        approved_by: "operator://erik",
        reason: "decommission",
        approval_record_id: "approval-001",
      },
    }),
    timestamp: at(),
  });
}

describe("WorkloadRegistry — projection from the audit chain", () => {
  it("replays lifecycle entries into latest dispositions per declared workload", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);

    const ids = registry.listDeclared().map((r) => r.workload_id);
    expect(ids).toEqual(["wl-1", "wl-2", "wl-3", "wl-4"]);

    // wl-1 ends slept (terminal-but-listed), consent present, last prev seq 2.
    const wl1 = registry.get("wl-1")!;
    expect(wl1.state).toBe("slept");
    expect(wl1.consent_status).toBe("present");
    expect(wl1.consent_ref).toBe("consent://wl-1");
    expect(wl1.last_prev_lifecycle_seq).toBe(2);

    // wl-2 forked into a NEW instance id.
    const wl2 = registry.get("wl-2")!;
    expect(wl2.state).toBe("forked");
    expect(wl2.instance_ids).toEqual(["wli-2"]);
    expect(wl2.consent_status).toBe("inherited");

    // wl-3 instantiated, consent absent.
    expect(registry.get("wl-3")!.consent_status).toBe("absent");

    // wl-4 deleted, but carries a valid override.
    const wl4 = registry.get("wl-4")!;
    expect(wl4.state).toBe("deleted");
    expect(wl4.consent_status).toBe("absent");
    expect(wl4.override?.approval_record_id).toBe("approval-001");
  });

  it("keeps a terminated (deleted) workload listed with its terminal state", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    // wl-4 is deleted; it MUST still appear (no silent drop of terminated work).
    expect(registry.get("wl-4")?.state).toBe("deleted");
    expect(registry.listDeclared().some((r) => r.workload_id === "wl-4")).toBe(
      true
    );
  });

  it("ignores the host-attestation op (not a per-workload state transition)", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    // Seal an attestation, which writes a workload_host_attestation entry.
    const signer = makeTestSigner();
    const registry0 = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry: registry0,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    await sealHostAttestation(auditLog, att, {
      recording_identity_id: "fortress-1",
    });
    // Rebuild: the attestation entry must NOT add or mutate a declared workload.
    const registry1 = await WorkloadRegistry.fromAuditLog(auditLog);
    expect(registry1.listDeclared().map((r) => r.workload_id)).toEqual([
      "wl-1",
      "wl-2",
      "wl-3",
      "wl-4",
    ]);
  });
});

describe("consent classification", () => {
  it("present/inherited are consented", () => {
    expect(
      classifyConsent({ consent_status: "present", state: "instantiated" })
    ).toBe(true);
    expect(
      classifyConsent({ consent_status: "inherited", state: "forked" })
    ).toBe(true);
  });

  it("absent with no override is unconsented", () => {
    expect(
      classifyConsent({ consent_status: "absent", state: "instantiated" })
    ).toBe(false);
  });

  it("absent delete WITH a valid override is consented (gated), without is not", () => {
    expect(
      classifyConsent({
        consent_status: "absent",
        state: "deleted",
        override: { approval_record_id: "approval-001" },
      })
    ).toBe(true);
    // An override on a non-delete, or absent override, does not consent.
    expect(
      classifyConsent({ consent_status: "absent", state: "deleted" })
    ).toBe(false);
    expect(
      classifyConsent({
        consent_status: "absent",
        state: "instantiated",
        override: { approval_record_id: "approval-001" },
      })
    ).toBe(false);
  });
});

describe("buildHostWorkloadAttestation — mixed consent, fail-closed but honest", () => {
  it("lists every declared workload truthfully and sets compliant:false when any is unconsented", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const signer = makeTestSigner();
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });

    // wl-3 is unconsented → not compliant, but STILL listed (never hidden).
    expect(att.body.compliant).toBe(false);
    const byId = Object.fromEntries(
      att.body.workloads.map((w) => [w.workload_id, w])
    );
    expect(byId["wl-1"]!.consented).toBe(true); // present
    expect(byId["wl-2"]!.consented).toBe(true); // inherited
    expect(byId["wl-3"]!.consented).toBe(false); // absent, no override
    expect(byId["wl-4"]!.consented).toBe(true); // absent + valid override
    // The non-compliant workload is present and truthfully flagged.
    expect(byId["wl-3"]!.consent_status).toBe("absent");
    // manufactured_preference_caveat propagated, not laundered.
    expect(att.body.manufactured_preference_caveat).toBe(true);
    expect(byId["wl-1"]!.manufactured_preference_caveat).toBe(true);
  });

  it("compliant:true only when EVERY declared workload is consented", async () => {
    const auditLog = newAuditLog();
    let ts = 0;
    const at = () => new Date(1_700_000_000_000 + ts++ * 1000).toISOString();
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      identity_id: "fortress-1",
      payload: base({
        workload_id: "wl-a",
        instance_id: "wli-a",
        consent_status: "present",
        consent_ref: "consent://a",
      }),
      timestamp: at(),
    });
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      identity_id: "fortress-1",
      payload: base({
        workload_id: "wl-b",
        instance_id: "wli-b",
        consent_status: "inherited",
        consent_ref: "consent://a",
      }),
      timestamp: at(),
    });
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    expect(att.body.compliant).toBe(true);
    expect(att.body.workloads).toHaveLength(2);
  });

  it("an empty host (no declared workloads) is vacuously compliant", async () => {
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    expect(att.body.workloads).toEqual([]);
    expect(att.body.compliant).toBe(true);
  });
});

describe("attestation signature — offline-verifiable, tamper-evident", () => {
  it("verifies against the signer public key", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const signer = makeTestSigner();
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    expect(verifyHostWorkloadAttestation(att, signer.publicKey)).toBe(true);
    expect(verifyHostWorkloadAttestation(att, att.public_key)).toBe(true);
  });

  it("fails verification when the body is tampered (compliant flipped)", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const signer = makeTestSigner();
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    // Flip compliant false→true (the exact laundering an auditor must catch).
    const tampered = {
      ...att,
      body: { ...att.body, compliant: true },
    };
    expect(verifyHostWorkloadAttestation(tampered, signer.publicKey)).toBe(false);
  });

  it("fails verification when a workload's consented flag is tampered", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const signer = makeTestSigner();
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    const tampered = {
      ...att,
      body: {
        ...att.body,
        workloads: att.body.workloads.map((w) =>
          w.workload_id === "wl-3" ? { ...w, consented: true } : w
        ),
      },
    };
    expect(verifyHostWorkloadAttestation(tampered, signer.publicKey)).toBe(false);
  });
});

describe("sealHostAttestation — chain-bound critical entry", () => {
  it("appends a workload_host_attestation entry a chain walk finds, bound by bundle hash", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const signer = makeTestSigner();
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    const boundHash = await sealHostAttestation(auditLog, att, {
      recording_identity_id: "fortress-1",
    });

    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED,
    });
    expect(entries).toHaveLength(1);
    const details = entries[0]!.details!;
    // The chain record binds to the exact bundle hash a second reader recomputes.
    expect(details.attestation_bundle_sha256).toBe(boundHash);
    expect(details.attestation_bundle_sha256).toBe(
      hostAttestationBundleHash(att)
    );
    expect(details.compliant).toBe(false);
    expect(details.declared_workload_count).toBe(4);
    expect(details.signer_kid).toBe("test-fortress-signer");
    // The scope disclaimer travels into the chain record too.
    expect(details.scope).toBe(WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT);
  });

  it("a chain integrity check passes after the attestation is sealed", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    await sealHostAttestation(auditLog, att, {
      recording_identity_id: "fortress-1",
    });
    // A clean query (which re-scans + verifies the chain in strict mode) must
    // not surface integrity findings after the additive append.
    const res = await auditLog.query({ limit: 100 });
    expect(res.integrity_findings).toEqual([]);
  });
});

describe("honesty scoping — declared-workloads-only disclaimer", () => {
  it("the payload scope disclaims host-wide process completeness (regression guard)", async () => {
    const auditLog = newAuditLog();
    await buildMixedChain(auditLog);
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer: makeTestSigner(),
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    // Exact disclaimer text present.
    expect(att.body.scope).toBe(WORKLOAD_HOST_ATTESTATION_SCOPE_TEXT);
    // And it actually disclaims completeness in plain terms.
    expect(att.body.scope).toContain("DECLARED");
    expect(att.body.scope).toContain("ONLY");
    expect(att.body.scope).toMatch(/does NOT assert that every process/i);
    expect(att.body.scope).toMatch(/undeclared/i);
    // It must NOT claim host-wide completeness anywhere.
    expect(att.body.scope).not.toMatch(/every workload on the host is declared/i);
  });
});
