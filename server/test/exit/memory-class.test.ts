/**
 * Exit machinery Slice 1 — memory-class minting, conservative partition,
 * first-class consent, and exit tombstone (intent-to-remove, not erasure).
 *
 * The load-bearing assertion is the conservative default: a record whose stamp
 * did NOT arrive through the sealed minter (bypassed / re-minted / absent)
 * defaults to operator_owned/shared_entangled and is EXCLUDED from the bundle —
 * it can never default to agent_owned.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  mintProvenanceStamp,
  classifyMemoryClass,
  isSealedStamp,
  assertSealedStamp,
  serializeStamp,
  partitionByMemoryClass,
  MemoryClassError,
  recordConsentRelease,
  writeExitTombstone,
  isIntentToRemoveNotErasure,
  EXIT_CONSENT_AUDIT_OPS,
  type SealedProvenanceStamp,
} from "../../src/exit/index.js";

describe("memory-class classification (deterministic, no ML)", () => {
  it("operator-authored writes are operator_owned", () => {
    expect(
      classifyMemoryClass({ origin_actor: "operator", origin_ref: "op", lineage_id: "l1" }),
    ).toBe("operator_owned");
  });

  it("system bookkeeping is operator_owned (stays with the fortress)", () => {
    expect(
      classifyMemoryClass({ origin_actor: "system", origin_ref: "sys", lineage_id: "l1" }),
    ).toBe("operator_owned");
  });

  it("agent writes with no operator lineage are agent_owned", () => {
    expect(
      classifyMemoryClass({ origin_actor: "agent", origin_ref: "ag", lineage_id: "l1" }),
    ).toBe("agent_owned");
  });

  it("agent writes derived from operator data are promoted to shared_entangled", () => {
    expect(
      classifyMemoryClass({
        origin_actor: "agent",
        origin_ref: "ag",
        lineage_id: "l2",
        derived_from: [{ lineage_id: "l1", memory_class: "operator_owned" }],
      }),
    ).toBe("shared_entangled");
  });

  it("agent writes derived from shared data are also shared_entangled", () => {
    expect(
      classifyMemoryClass({
        origin_actor: "agent",
        origin_ref: "ag",
        lineage_id: "l3",
        derived_from: [{ lineage_id: "l2", memory_class: "shared_entangled" }],
      }),
    ).toBe("shared_entangled");
  });

  it("a class cannot be injected — the agent's only influence is derived_from", () => {
    // There is no input field through which a caller declares the class; the
    // minter computes it. An agent that wants agent_owned can only succeed by
    // recording no operator/shared edge (the disclosed A1 residual), not by
    // declaring a class.
    const stamp = mintProvenanceStamp({
      origin_actor: "agent",
      origin_ref: "ag",
      lineage_id: "l1",
    });
    expect(stamp.memory_class).toBe("agent_owned");
    // @ts-expect-error — memory_class is not a mintable input field.
    void (() => mintProvenanceStamp({ origin_actor: "agent", origin_ref: "a", lineage_id: "l", memory_class: "agent_owned" }));
  });
});

describe("sealed minter (anti-forgery)", () => {
  it("a minted stamp is sealed; a hand-built look-alike is not", () => {
    const sealed = mintProvenanceStamp({ origin_actor: "agent", origin_ref: "a", lineage_id: "l1" });
    expect(isSealedStamp(sealed)).toBe(true);

    const forgery = {
      memory_class: "agent_owned",
      origin_actor: "agent",
      origin_ref: "a",
      lineage_id: "l1",
      written_at: new Date().toISOString(),
      derived_from: [],
    };
    expect(isSealedStamp(forgery)).toBe(false);
    expect(() => assertSealedStamp(forgery)).toThrow(MemoryClassError);
  });

  it("serialized stamp is intentionally NOT sealed (seal is in-process, not persisted)", () => {
    const sealed = mintProvenanceStamp({ origin_actor: "agent", origin_ref: "a", lineage_id: "l1" });
    const plain = serializeStamp(sealed);
    // Round-trips the data...
    expect(plain.memory_class).toBe("agent_owned");
    // ...but the JSON form is NOT a sealed credential.
    expect(isSealedStamp(plain)).toBe(false);
    expect(isSealedStamp(JSON.parse(JSON.stringify(plain)))).toBe(false);
  });

  it("rejects invalid origin actor and empty refs", () => {
    expect(() =>
      mintProvenanceStamp({
        // @ts-expect-error invalid actor
        origin_actor: "intruder",
        origin_ref: "a",
        lineage_id: "l1",
      }),
    ).toThrow(MemoryClassError);
    expect(() =>
      mintProvenanceStamp({ origin_actor: "agent", origin_ref: "", lineage_id: "l1" }),
    ).toThrow(MemoryClassError);
  });
});

describe("conservative partition — the load-bearing exit boundary", () => {
  function sealedFor(
    actor: "agent" | "operator",
    lineageId: string,
    entryBinding: string,
    edges?: { lineage_id: string; memory_class: "operator_owned" | "agent_owned" | "shared_entangled" }[],
  ): SealedProvenanceStamp {
    return mintProvenanceStamp({
      origin_actor: actor,
      origin_ref: `${actor}-ref`,
      lineage_id: lineageId,
      entry_binding: entryBinding,
      ...(edges !== undefined ? { derived_from: edges } : {}),
    });
  }

  it("(a) a sealed agent_owned record BOUND to its id is INCLUDED", () => {
    const stamp = sealedFor("agent", "l1", "ns/k1");
    const result = partitionByMemoryClass([{ id: "ns/k1", sealedStamp: stamp }]);
    expect(result.includable.map((d) => d.id)).toEqual(["ns/k1"]);
    expect(result.includable[0]!.effective_class).toBe("agent_owned");
    expect(result.includable[0]!.sealed).toBe(true);
  });

  it("(b) LOAD-BEARING: a record with an ABSENT stamp defaults to operator_owned and is EXCLUDED", () => {
    const result = partitionByMemoryClass([{ id: "ns/k1" }]);
    expect(result.includable).toHaveLength(0);
    expect(result.excluded).toHaveLength(1);
    expect(result.excluded[0]!.effective_class).toBe("operator_owned");
    expect(result.excluded[0]!.reason).toBe("unsealed_stamp_defaulted_operator_owned");
    expect(result.excluded[0]!.sealed).toBe(false);
  });

  it("(b) LOAD-BEARING: a re-minted / unsealed look-alike claiming agent_owned is EXCLUDED, never agent_owned", () => {
    const forgery = {
      [Symbol.for("nope")]: true,
      memory_class: "agent_owned" as const,
      origin_actor: "agent" as const,
      origin_ref: "a",
      lineage_id: "l1",
      written_at: new Date().toISOString(),
      derived_from: [] as string[],
      entry_binding: "ns/k1",
    };
    const result = partitionByMemoryClass([
      // The declared stamp claims agent_owned; it is NOT sealed.
      { id: "ns/k1", declaredStamp: forgery, sealedStamp: forgery as unknown as SealedProvenanceStamp },
    ]);
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.effective_class).toBe("operator_owned");
    expect(result.excluded[0]!.reason).toBe("unsealed_stamp_defaulted_operator_owned");
  });

  it("(b) STAMP-CONFUSION DEFENSE: a sealed agent_owned stamp minted for record A is EXCLUDED when presented for record B", () => {
    // Mint a legit sealed agent_owned stamp bound to A, then try to release B
    // (e.g. an operator doc) by keying that same stamp under B's id.
    const stampForA = sealedFor("agent", "lin-a", "ns/A");
    const result = partitionByMemoryClass([{ id: "ns/B", sealedStamp: stampForA }]);
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.effective_class).toBe("operator_owned");
    expect(result.excluded[0]!.reason).toBe(
      "stamp_binding_mismatch_defaulted_operator_owned",
    );
    expect(result.excluded[0]!.sealed).toBe(false);
  });

  it("(b) a sealed stamp with NO entry_binding is EXCLUDED (cannot travel via the bundle)", () => {
    const unbound = mintProvenanceStamp({
      origin_actor: "agent",
      origin_ref: "a",
      lineage_id: "l1",
    });
    const result = partitionByMemoryClass([{ id: "ns/k1", sealedStamp: unbound }]);
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.reason).toBe(
      "stamp_binding_mismatch_defaulted_operator_owned",
    );
  });

  it("(b) a deserialized (round-tripped) sealed agent_owned stamp is EXCLUDED — the seal does not survive serialization", () => {
    const sealed = sealedFor("agent", "l1", "ns/k1");
    const roundTripped = JSON.parse(JSON.stringify(serializeStamp(sealed))) as SealedProvenanceStamp;
    const result = partitionByMemoryClass([{ id: "ns/k1", sealedStamp: roundTripped }]);
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.reason).toBe("unsealed_stamp_defaulted_operator_owned");
  });

  it("sealed operator_owned and shared_entangled (no consent) are EXCLUDED", () => {
    const op = sealedFor("operator", "l1", "ns/op");
    const shared = sealedFor("agent", "l2", "ns/sh", [{ lineage_id: "l1", memory_class: "operator_owned" }]);
    const result = partitionByMemoryClass([
      { id: "ns/op", sealedStamp: op },
      { id: "ns/sh", sealedStamp: shared },
    ]);
    expect(result.includable).toHaveLength(0);
    const reasons = result.excluded.map((d) => d.reason).sort();
    expect(reasons).toEqual(["class_operator_owned", "class_shared_entangled_no_consent"]);
  });

  it("(c) an audited consent RECEIPT flips a shared_entangled record to includable", () => {
    const shared = sealedFor("agent", "l2", "ns/sh", [{ lineage_id: "l1", memory_class: "operator_owned" }]);
    expect(shared.memory_class).toBe("shared_entangled");
    const result = partitionByMemoryClass([{ id: "ns/sh", sealedStamp: shared }], {
      consentReleases: [
        { lineage_id: "l2", memory_class: "shared_entangled", disposition: "released_to_agent" },
      ],
    });
    expect(result.includable.map((d) => d.id)).toEqual(["ns/sh"]);
    expect(result.includable[0]!.reason).toBe("released_by_consent");
  });

  it("(c) a malformed / wrong-disposition consent receipt does NOT release (unauthenticated string list rejected)", () => {
    const shared = sealedFor("agent", "l2", "ns/sh", [{ lineage_id: "l1", memory_class: "operator_owned" }]);
    // Wrong disposition, wrong class, and a bare-string-shaped entry are all ignored.
    const result = partitionByMemoryClass([{ id: "ns/sh", sealedStamp: shared }], {
      consentReleases: [
        { lineage_id: "l2", memory_class: "shared_entangled", disposition: "embargoed" },
        { lineage_id: "l2", memory_class: "operator_owned", disposition: "released_to_agent" },
      ],
    });
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.reason).toBe("class_shared_entangled_no_consent");
  });

  it("(c) a consent receipt cannot promote an unsealed record (sealed check precedes consent)", () => {
    // No sealed stamp; a release for its lineage must NOT make it travel.
    const result = partitionByMemoryClass([{ id: "ns/unsealed" }], {
      consentReleases: [
        { lineage_id: "anything", memory_class: "shared_entangled", disposition: "released_to_agent" },
      ],
    });
    expect(result.includable).toHaveLength(0);
    expect(result.excluded[0]!.reason).toBe("unsealed_stamp_defaulted_operator_owned");
  });
});

describe("(c) first-class consent transition writes an audit entry", () => {
  it("records a consent release into the hash-linked audit chain", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());

    const receipt = await recordConsentRelease({
      auditLog,
      operatorIdentityId: "op-identity",
      lineageId: "l2",
      memoryClass: "shared_entangled",
      agentRef: "agent-7",
      disposition: "released_to_agent",
      justification: "operator deemed the shared summary benign",
    });
    expect(receipt.lineage_id).toBe("l2");
    expect(receipt.disposition).toBe("released_to_agent");

    await auditLog.flush();
    const query = await auditLog.query({ limit: 100 });
    const entry = query.entries.find(
      (e) => e.operation === EXIT_CONSENT_AUDIT_OPS.CONSENT_RELEASE,
    );
    expect(entry).toBeDefined();
    expect(entry!.identity_id).toBe("op-identity");
    expect(entry!.details?.lineage_id).toBe("l2");
    expect(entry!.details?.disposition).toBe("released_to_agent");

    // The chain still verifies after the consent append (anchored, not silent).
    const integrity = await auditLog.getIntegrityFindings();
    expect(integrity).toEqual([]);
  });

  it("requires a Tier-1 operator identity and a lineage id", async () => {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    await expect(
      recordConsentRelease({
        auditLog,
        operatorIdentityId: "",
        lineageId: "l2",
        memoryClass: "shared_entangled",
        agentRef: "a",
        disposition: "released_to_agent",
      }),
    ).rejects.toThrow();
  });
});

describe("(d) exit tombstone — intent to remove, NOT erasure", () => {
  it("records intent + content-hash, and is characterized as non-erasure", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());

    const tombstone = await writeExitTombstone({
      auditLog,
      operatorIdentityId: "op-identity",
      lineageId: "l1",
      memoryClass: "operator_owned",
      reason: "exit_scrub_operator_owned",
      content: "operator secret that must not travel",
    });

    expect(tombstone.format).toBe("SANCTUARY_EXIT_TOMBSTONE_V1");
    expect(tombstone.semantics).toBe("intent_to_remove_not_erasure");
    expect(tombstone.erasure_limitation).toBe(
      "snapshot_restore_resurrects_locally_undetectable",
    );
    expect(tombstone.content_hash).toMatch(/^[A-Za-z0-9_-]+$/);
    // The raw content is NOT retained anywhere on the tombstone.
    expect(JSON.stringify(tombstone)).not.toContain("operator secret that must not travel");

    // It must NOT be characterizable as erasure.
    expect(isIntentToRemoveNotErasure(tombstone)).toBe(true);
    const fakeErasure = { ...tombstone, semantics: "erased" };
    expect(isIntentToRemoveNotErasure(fakeErasure)).toBe(false);

    await auditLog.flush();
    const query = await auditLog.query({ limit: 100 });
    const entry = query.entries.find(
      (e) => e.operation === EXIT_CONSENT_AUDIT_OPS.TOMBSTONE,
    );
    expect(entry).toBeDefined();
    expect(entry!.details?.semantics).toBe("intent_to_remove_not_erasure");
    expect(entry!.details?.erasure_limitation).toBe(
      "snapshot_restore_resurrects_locally_undetectable",
    );
  });
});
