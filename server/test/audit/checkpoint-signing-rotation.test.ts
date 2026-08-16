/**
 * IC-05-DG §f-12: master-rotation schedule over the signing control records.
 *
 * Both MAC'd records restamp via `MAC_ANCHORS` (fixed count, O(1) rotation
 * work); rotation atop a TAMPERED record aborts loudly (restamping would
 * launder tamper evidence into validity); and the rotation-crash interleave
 * (kill between each adjacent `_audit_checkpoints` restamp) must leave every
 * mixed-epoch state recoverable by the supported resume path into a
 * finding-free (or loud-correct) load, never wrongly-TAMPERED and never
 * silently-clean-on-tamper.
 */
import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AuditIntegrityFinding } from "../../src/operational/audit-log.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  rotateMaster,
  resumeRotation,
  type RotateMasterOptions,
} from "../../src/core/master-rotation.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import {
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
  CHECKPOINT_NAMESPACE,
  appendCriticalEntries,
  corruptIdentityRecord,
  findingsOfKind,
  seedStoredIdentity,
} from "../helpers/signing-fixture.js";

const PASSPHRASE = "ic05dg-rotation-passphrase";
const FORTRESS_ID = "fortress-ic05dg-rotation";

async function buildArmedFortress() {
  const storage = new MemoryStorage();
  const est = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
  });
  const master = est.masterKey;
  const { storedIdentity } = await seedStoredIdentity(storage, master);
  const writer = new AuditLog(storage, master, { checkpointInterval: 1 });
  await appendCriticalEntries(writer, 2, storedIdentity.identity_id);
  // One signer INCIDENT so the head carries ring evidence across rotation:
  // corrupt the identity, drive an interval, then the incident-bearing store
  // is what rotates.
  const identityRaw = await storage.read("_identities", storedIdentity.identity_id);
  await corruptIdentityRecord(storage, storedIdentity.identity_id);
  const writer2 = new AuditLog(storage, master, {
    checkpointInterval: 1,
    integrityMode: "lenient",
  });
  await appendCriticalEntries(writer2, 1, storedIdentity.identity_id);
  // Restore the identity so the fortress stays signable after rotation.
  await storage.write("_identities", storedIdentity.identity_id, identityRaw!);
  return { storage, master, storedIdentity };
}

function rotateOpts(
  storage: MemoryStorage,
  overrides?: Partial<RotateMasterOptions>
): RotateMasterOptions {
  return {
    storage,
    fortressId: FORTRESS_ID,
    passphrase: PASSPHRASE,
    approve: async () => true,
    captureRecoveryKey: async (recoveryKey, verify) => verify(recoveryKey),
    ...overrides,
  };
}

async function lenientSigningFindings(
  storage: MemoryStorage,
  master: Uint8Array
): Promise<AuditIntegrityFinding[]> {
  const reader = new AuditLog(storage, master, { integrityMode: "lenient" });
  const result = await reader.query({ limit: 1000 });
  return (result.integrity_findings as AuditIntegrityFinding[]).filter(
    (finding) => finding.kind.startsWith("checkpoint_signing_")
  );
}

describe("IC-05-DG §f-12: rotation schedule", () => {
  it("rotation on an armed store with incidents: both records restamp and the findings are preserved across rotation", async () => {
    const { storage, master } = await buildArmedFortress();
    // Pre-rotation: the incident fires under the old master.
    const before = await lenientSigningFindings(storage, master);
    expect(
      findingsOfKind(before, "checkpoint_signing_error").length
    ).toBeGreaterThanOrEqual(1);
    const latchBefore = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
    );

    await rotateMaster(rotateOpts(storage));
    const est = await establishMaster({ storage, passphrase: PASSPHRASE });
    const newMaster = est.masterKey;

    // Both records now authenticate under the NEW master: same incident
    // finding, no tamper findings, no recovery findings (nothing was lost).
    const after = await lenientSigningFindings(storage, newMaster);
    expect(
      findingsOfKind(after, "checkpoint_signing_error").length
    ).toBeGreaterThanOrEqual(1);
    expect(findingsOfKind(after, "checkpoint_signing_downgrade")).toEqual([]);
    expect(findingsOfKind(after, "checkpoint_signing_head_recovered")).toEqual([]);
    expect(findingsOfKind(after, "checkpoint_signing_floor_recovered")).toEqual([]);
    // The latch bytes changed (restamped MAC) but the data did not.
    const latchAfter = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
    );
    expect(JSON.parse(latchAfter).data).toEqual(JSON.parse(latchBefore).data);
    expect(latchAfter).not.toBe(latchBefore);
  }, 30_000);

  it("rotation atop a TAMPERED latch aborts loudly and restamps nothing (tamper is never laundered into validity)", async () => {
    const { storage } = await buildArmedFortress();
    const raw = (await storage.read(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY
    ))!;
    const record = JSON.parse(bytesToString(raw));
    record.data.armed_at_sequence = 41; // MAC now fails under BOTH masters
    const tampered = JSON.stringify(record);
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY,
      stringToBytes(tampered)
    );

    await expect(rotateMaster(rotateOpts(storage))).rejects.toThrow(
      /failed authentication under both/
    );
    // The tamper evidence survives byte-for-byte for the next load to
    // report.
    expect(
      bytesToString(
        (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
      )
    ).toBe(tampered);
  }, 30_000);

  it("rotation atop a TAMPERED signing head aborts loudly", async () => {
    const { storage } = await buildArmedFortress();
    const raw = (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!;
    const record = JSON.parse(bytesToString(raw));
    record.data.incident_count = (record.data.incident_count as number) + 7;
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_HEAD_KEY,
      stringToBytes(JSON.stringify(record))
    );
    await expect(rotateMaster(rotateOpts(storage))).rejects.toThrow(
      /failed authentication under both/
    );
  }, 30_000);

  it("rotation-crash interleave: a kill after EACH _audit_checkpoints restamp resumes to a finding-free load under the new master", async () => {
    // The four MAC'd records' restamp points; the rotation anchor is absent
    // on this fixture (no prune has run), so the interleave drives the three
    // that exist. Every crash point must resume (the supported recovery for
    // a mid-rotation crash — the same transitional mechanism the existing
    // anchors use) into a store whose control records all authenticate.
    const crashPoints = [
      `converted:_audit_checkpoints/__head_anchor`,
      `converted:_audit_checkpoints/${AUDIT_SIGNING_LATCH_V2_KEY}`,
      `converted:_audit_checkpoints/${AUDIT_SIGNING_HEAD_KEY}`,
    ];
    for (const point of crashPoints) {
      const { storage } = await buildArmedFortress();
      await expect(
        rotateMaster(
          rotateOpts(storage, {
            failpoint: (p) => {
              if (p === point) throw new Error(`simulated crash at ${p}`);
            },
          })
        )
      ).rejects.toThrow(/simulated crash/);

      const resumed = await resumeRotation({
        storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      });
      expect(resumed.rotation_id).toBeTruthy();

      const est = await establishMaster({ storage, passphrase: PASSPHRASE });
      const findings = await lenientSigningFindings(storage, est.masterKey);
      // Finding-free except the incident evidence this fixture carries on
      // purpose: never wrongly-TAMPERED, never a recovery (nothing lost),
      // and the incident ring still attests across the interrupted
      // rotation.
      expect(findingsOfKind(findings, "checkpoint_signing_downgrade")).toEqual([]);
      expect(findingsOfKind(findings, "checkpoint_signing_head_recovered")).toEqual([]);
      expect(findingsOfKind(findings, "checkpoint_signing_floor_recovered")).toEqual([]);
      expect(
        findingsOfKind(findings, "checkpoint_signing_state_indeterminate")
      ).toEqual([]);
      expect(
        findingsOfKind(findings, "checkpoint_signing_error").length
      ).toBeGreaterThanOrEqual(1);
    }
  }, 120_000);
});
