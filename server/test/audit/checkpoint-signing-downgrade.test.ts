/**
 * IC-05-DG planted-divergence proofs, part 1 (design §f-1/2/3/5) plus the
 * false-positive guards (§f-8).
 *
 * Every detector assertion here is mutation-proven per the design's baseline
 * discipline: knocking out the named enforcement (see the PR body's mutation
 * table) turns the probe red, so none of these tests can pass vacuously.
 * The deletion-shaped probes (§f-4b) live in
 * checkpoint-signing-deletion.test.ts; enumeration/fault schedules in their
 * own suites.
 */
import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import {
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
  CHECKPOINT_NAMESPACE,
  appendCriticalEntries,
  buildSignedFortress,
  corruptIdentityRecord,
  deleteControlRecord,
  deleteIdentity,
  findingsOfKind,
  hardFindings,
  lenientFindings,
  readCheckpointRecord,
  seedStoredIdentity,
  strictReadError,
  stripCheckpoint,
} from "../helpers/signing-fixture.js";

describe("IC-05-DG §f-1: strip probe (D1)", () => {
  it("a stripped signed checkpoint raises checkpoint_signing_downgrade on a strict reader", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    await stripCheckpoint(storage, 2);

    const error = await strictReadError(storage, masterKey);
    expect(error?.name).toBe("AuditIntegrityError");
    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    expect(downgrades.some((finding) => finding.sequence === 2)).toBe(true);
    expect(downgrades.every((finding) => finding.severity !== "warn")).toBe(true);
  });

  it("stripping EVERY signed checkpoint still fires (the #1243 gate's zero-findings shape)", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    for (const sequence of [1, 2, 3]) await stripCheckpoint(storage, sequence);

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    // All three stripped records are at/above the armed floor.
    for (const sequence of [1, 2, 3]) {
      expect(downgrades.some((finding) => finding.sequence === sequence)).toBe(true);
    }
  });
});

describe("IC-05-DG §f-2: decapitate-forward probe (D2)", () => {
  it("checkpoints written after the identity vanished read as downgrades at/above the floor", async () => {
    const { storage, masterKey, storedIdentity } = await buildSignedFortress(2);
    await deleteIdentity(storage, storedIdentity.identity_id);

    // Drive further intervals: the signer now sees proven absence, so the
    // checkpoints write honest-unsigned-SHAPED records; the armed floor is
    // what makes them findings.
    const writer2 = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 2, "post-decapitation");

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    // The post-decapitation unsigned checkpoints (sequences 3 and 4) are
    // strip-variant downgrades at/above the floor...
    for (const sequence of [3, 4]) {
      expect(
        downgrades.some(
          (finding) => finding.variant === "strip" && finding.sequence === sequence
        )
      ).toBe(true);
    }
    // ...and the committed tip/floor witnesses ALSO fire (the deleted
    // identity makes the previously verified checkpoints unverifiable, and
    // "gone or no longer verifies" is exactly what those witnesses attest),
    // plus the per-record unverifiable-signer findings. Monotone: deletion
    // of identity material only ever ADDS findings.
    expect(downgrades.some((finding) => finding.variant === "deleted-tail")).toBe(true);
    expect(
      findingsOfKind(findings, "checkpoint_signature_embedded_key_untrusted")
        .length
    ).toBeGreaterThanOrEqual(2);
  });
});

describe("IC-05-DG §f-3: reason-spoof probe (D3 / R3-d regression)", () => {
  it("armed store: rewriting unsigned_reason to the honest-absence string still raises checkpoint_signing_error from the ring", async () => {
    const { storage, masterKey, storedIdentity } = await buildSignedFortress(1);
    // Induce a signer failure: corrupt the identity record IN PLACE.
    await corruptIdentityRecord(storage, storedIdentity.identity_id);
    const writer2 = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 1, storedIdentity.identity_id);

    // Find the incident checkpoint and spoof its reason to honest absence.
    let incidentSequence: number | null = null;
    for (const meta of await storage.list(CHECKPOINT_NAMESPACE, "audit-checkpoint-")) {
      const record = JSON.parse(
        bytesToString((await storage.read(CHECKPOINT_NAMESPACE, meta.key))!)
      );
      if (record.unsigned === true) {
        incidentSequence = record.checkpoint_sequence;
        record.unsigned_reason = "no signing identity available at checkpoint time";
        await storage.write(
          CHECKPOINT_NAMESPACE,
          meta.key,
          stringToBytes(JSON.stringify(record))
        );
      }
    }
    expect(incidentSequence).not.toBeNull();

    const findings = await lenientFindings(storage, masterKey);
    const errors = findingsOfKind(findings, "checkpoint_signing_error");
    // The finding fires from the signing head's MAC'd incident ring — the
    // plaintext reason carries zero trust weight in either direction.
    expect(errors.some((finding) => finding.sequence === incidentSequence)).toBe(
      true
    );
  });

  it("NEVER-armed store (the exact R3-d gap): the spoof still cannot silence the incident", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    // Corrupt BEFORE the first interval ever signs: the fortress never arms.
    await corruptIdentityRecord(storage, storedIdentity.identity_id);
    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);

    // Spoof the at-rest reason to the honest-absence string.
    for (const meta of await storage.list(CHECKPOINT_NAMESPACE, "audit-checkpoint-")) {
      const record = JSON.parse(
        bytesToString((await storage.read(CHECKPOINT_NAMESPACE, meta.key))!)
      );
      record.unsigned_reason = "no signing identity available at checkpoint time";
      await storage.write(
        CHECKPOINT_NAMESPACE,
        meta.key,
        stringToBytes(JSON.stringify(record))
      );
    }

    const findings = await lenientFindings(storage, masterKey);
    expect(findingsOfKind(findings, "checkpoint_signing_error").length)
      .toBeGreaterThanOrEqual(1);
  });

  it("planting the signer-error reason on an honest below-floor record creates findings, never silence (loud in both directions)", async () => {
    // Migration shape: unsigned pre-bootstrap checkpoint, then signing
    // starts. Planting the SIGNER_ERROR reason string on the pre-bootstrap
    // record must not fire checkpoint_signing_error (no ring attestation)
    // and must not suppress anything.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 1, "pre-bootstrap");
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    const writer2 = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 1, storedIdentity.identity_id);

    const preBoot = (await readCheckpointRecord(storage, 1))!;
    expect(preBoot.unsigned).toBe(true);
    preBoot.unsigned_reason =
      "checkpoint signer failed: identity material unreadable or signing error";
    await storage.write(
      CHECKPOINT_NAMESPACE,
      "audit-checkpoint-" + String(1).padStart(20, "0"),
      stringToBytes(JSON.stringify(preBoot))
    );

    const findings = await lenientFindings(storage, masterKey);
    // The plaintext reason is cosmetic: no ring attestation, no error
    // finding; and the below-floor record stays clean.
    expect(findingsOfKind(findings, "checkpoint_signing_error")).toEqual([]);
    expect(findingsOfKind(findings, "checkpoint_signing_downgrade")).toEqual([]);
  });
});

describe("IC-05-DG §f-5: day-one corruption (the window pure floor logic can never see)", () => {
  it("a never-armed fortress with corrupt identity material still raises checkpoint_signing_error", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    await corruptIdentityRecord(storage, storedIdentity.identity_id);

    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 2, storedIdentity.identity_id);

    const findings = await lenientFindings(storage, masterKey);
    const errors = findingsOfKind(findings, "checkpoint_signing_error");
    expect(errors.length).toBeGreaterThanOrEqual(2);
    // Never armed: no latch was written, and no downgrade fires (floor
    // logic is blind here; the incident ring is the only witness).
    expect(await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY)).toBeNull();
    expect(findingsOfKind(findings, "checkpoint_signing_downgrade")).toEqual([]);
    // Strict instances fail closed on their next load.
    const error = await strictReadError(storage, masterKey);
    expect(error?.name).toBe("AuditIntegrityError");
  });
});

describe("IC-05-DG: latch tamper (state_TAMPERED)", () => {
  it("a latch that fails authentication is a loud finding and never silently disables the other memories", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    const raw = (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!;
    const record = JSON.parse(bytesToString(raw));
    record.data.armed_at_sequence = 999; // breaks the MAC
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY,
      stringToBytes(JSON.stringify(record))
    );
    await stripCheckpoint(storage, 2);

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    expect(downgrades.some((finding) => finding.variant === "latch-tamper")).toBe(true);
    // The strip is still caught: the head floor witness + in-store memory
    // keep the floor while the latch is tamper-evidence.
    expect(downgrades.some((finding) => finding.sequence === 2)).toBe(true);
  });
});

describe("IC-05-DG §f-8: false-positive guards (the detector must NOT fire)", () => {
  it("a pre-bootstrap store (no identity, no latch) is fully clean", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 2, "no-identity-fortress");

    expect(await lenientFindings(storage, masterKey)).toEqual([]);
    expect(await strictReadError(storage, masterKey)).toBeNull();
  });

  it("the migration shape (unsigned prefix, then signing starts) stays clean below the floor, including the first signed record's reference to an unsigned predecessor", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer, 2, "pre-bootstrap");

    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    const writer2 = new AuditLog(storage, masterKey, { checkpointInterval: 1 });
    await appendCriticalEntries(writer2, 2, storedIdentity.identity_id);

    // The first SIGNED checkpoint chains to the last unsigned one; the
    // predecessor-existence predicate demands bound existence, never
    // signedness, so this must stay finding-free.
    const first = await readCheckpointRecord(storage, 3);
    expect(first?.unsigned).toBe(false);
    expect(first?.previous_checkpoint_sequence).toBe(2);
    expect(await lenientFindings(storage, masterKey)).toEqual([]);
  });

  it("a clean signed fortress stays finding-free across repeated loads (no stamp churn, no self-inflicted findings)", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    expect(await lenientFindings(storage, masterKey)).toEqual([]);
    expect(await lenientFindings(storage, masterKey)).toEqual([]);
    expect(await strictReadError(storage, masterKey)).toBeNull();
  });

  it("carve-out counter-probe (review finding 2 regression): a REAL fortress with corrupt _identities + corrupt latch + stripped checkpoints raises the full loud set, never a degraded shrug", async () => {
    const { storage, masterKey, storedIdentity } = await buildSignedFortress(2);
    await corruptIdentityRecord(storage, storedIdentity.identity_id);
    const latchRaw = (await storage.read(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY
    ))!;
    const latch = JSON.parse(bytesToString(latchRaw));
    latch.data.armed_at_sequence = 7; // MAC now fails
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY,
      stringToBytes(JSON.stringify(latch))
    );
    for (const sequence of [1, 2]) await stripCheckpoint(storage, sequence);

    const findings = await lenientFindings(storage, masterKey);
    const downgrades = findingsOfKind(findings, "checkpoint_signing_downgrade");
    // TAMPERED latch + strip downgrades, with hard severity throughout: the
    // review's manufactured composition (corrupt identities to blank the
    // resolver, corrupt the latch, strip) must buy MORE findings, not a
    // degraded verdict.
    expect(downgrades.some((finding) => finding.variant === "latch-tamper")).toBe(true);
    expect(downgrades.some((finding) => finding.sequence === 1)).toBe(true);
    expect(downgrades.some((finding) => finding.sequence === 2)).toBe(true);
    expect(hardFindings(downgrades).length).toBe(downgrades.length);
  });

  it("a constructionally non-fortress instance raises no downgrade findings on a store it cannot authenticate", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    await stripCheckpoint(storage, 1);
    // A DIFFERENT master (the wrong-key transitional shape) + the
    // construction-time declaration: no signing findings, because the
    // instance said so at new — never because storage looked degraded.
    const otherMaster = generateRandomKey();
    const reader = new AuditLog(storage, otherMaster, {
      integrityMode: "lenient",
      signingDetectionMode: "non-fortress",
    });
    const result = await reader.query({ limit: 100 });
    const signingKinds = (result.integrity_findings as Array<{ kind: string }>).filter(
      (finding) =>
        finding.kind.startsWith("checkpoint_signing_")
    );
    expect(signingKinds).toEqual([]);
  });

  it("the SAME wrong-key store in FORTRESS mode is loud (the declaration, not the key mismatch, is what softens)", async () => {
    const { storage } = await buildSignedFortress(2);
    const otherMaster = generateRandomKey();
    const reader = new AuditLog(storage, otherMaster, { integrityMode: "lenient" });
    const result = await reader.query({ limit: 100 });
    const signingFindings = (result.integrity_findings as Array<{ kind: string }>).filter(
      (finding) => finding.kind.startsWith("checkpoint_signing_")
    );
    expect(signingFindings.length).toBeGreaterThan(0);
  });

  it("the arm-then-crash shape (valid latch, zeroed head, no checkpoints ≥ floor... none at all) is fully clean", async () => {
    // Simulate the §d after-(2) crash: latch + head exist, the first signed
    // checkpoint never persisted. Under v2 FORWARD-commitment semantics the
    // latch promises "everything ≥ N that exists is signed" — vacuous over
    // an empty set — so the shape must be clean by construction.
    const storage = new MemoryStorage();
    const faulty = new (await import("../helpers/signing-fixture.js")).FaultInjectingStorage(
      storage
    );
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(faulty, masterKey);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: "audit-checkpoint-",
      calls: [1],
    };
    const writer = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id).catch(() => {
      // The injected checkpoint-write failure may surface; the entry append
      // itself is what we care about having happened.
    });
    faulty.failWriteOnCall = null;

    // Latch and head exist; no checkpoint record does.
    expect(await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY)).not.toBeNull();
    expect(await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY)).not.toBeNull();
    expect(await storage.list(CHECKPOINT_NAMESPACE, "audit-checkpoint-")).toEqual([]);

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findings.filter((finding) => finding.kind.startsWith("checkpoint_signing_"))
    ).toEqual([]);
  });

  it("the crash-between-persist-and-commit shape is clean and self-heals both endpoints, never ROLLED_FLOOR", async () => {
    // §d sign-then-commit: signed checkpoint persisted, head commit failed
    // (head write #2: the ensure is call #1). Reload must be clean with the
    // floor predicate vacuous, then self-heal tip AND floor.
    const storage = new MemoryStorage();
    const { FaultInjectingStorage } = await import("../helpers/signing-fixture.js");
    const faulty = new FaultInjectingStorage(storage);
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(faulty, masterKey);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [2],
    };
    const writer = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    const headBefore = JSON.parse(
      bytesToString((await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!)
    );
    expect(headBefore.data.highest_signed_checkpoint_sequence).toBe(0);
    expect(headBefore.data.lowest_signed_checkpoint_sequence).toBeNull();

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findings.filter((finding) => finding.kind.startsWith("checkpoint_signing_"))
    ).toEqual([]);

    // The clean load self-healed both endpoints in one write.
    const headAfter = JSON.parse(
      bytesToString((await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!)
    );
    expect(headAfter.data.highest_signed_checkpoint_sequence).toBe(1);
    expect(headAfter.data.lowest_signed_checkpoint_sequence).toBe(1);
    // And a second load is still clean (no ROLLED_FLOOR from the heal).
    expect(await lenientFindings(storage, masterKey)).toEqual([]);
  });
});

describe("IC-05-DG §f-4 latch deletion (D4)", () => {
  it("latch deletion alone: floor recovered from the surviving memories, strict-closed once, permanent warn after, strip still fires afterwards", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);

    // Recovery pass: hard recovery finding, strict fails closed.
    const findings = await lenientFindings(storage, masterKey);
    const recovered = findingsOfKind(findings, "checkpoint_signing_floor_recovered");
    expect(recovered.length).toBeGreaterThanOrEqual(1);
    expect(hardFindings(recovered).length).toBeGreaterThanOrEqual(1);

    // Re-armed at the true earliest.
    const latchRaw = await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY);
    expect(latchRaw).not.toBeNull();
    expect(JSON.parse(bytesToString(latchRaw!)).data.armed_at_sequence).toBe(1);

    // Later loads: warn-grade latched re-emission only — strict-visible,
    // non-fatal, permanent.
    const later = await lenientFindings(storage, masterKey);
    const laterRecovery = findingsOfKind(later, "checkpoint_signing_floor_recovered");
    expect(laterRecovery.length).toBeGreaterThanOrEqual(1);
    expect(laterRecovery.every((finding) => finding.severity === "warn")).toBe(true);
    expect(await strictReadError(storage, masterKey)).toBeNull();

    // The strip probe still fires after recovery.
    await stripCheckpoint(storage, 2);
    const afterStrip = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(afterStrip, "checkpoint_signing_downgrade").some(
        (finding) => finding.sequence === 2
      )
    ).toBe(true);
  });

  it("latch + head deleted together: strip and incident records all escalate to downgrade and both recoveries fire", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    await stripCheckpoint(storage, 2);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_head_recovered").length
    ).toBeGreaterThanOrEqual(1);
    expect(
      findingsOfKind(findings, "checkpoint_signing_floor_recovered").length
    ).toBeGreaterThanOrEqual(1);
    // The stripped record reads as downgrade from the surviving in-store
    // verified memory (three-memory MIN: c1 still verifies).
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.sequence === 2
      )
    ).toBe(true);
  });
});
