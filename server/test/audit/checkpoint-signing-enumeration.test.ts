/**
 * IC-05-DG §f-6 (partial enumeration / D5 / R3-e regression) and §f-7 (the
 * monotone-loudness sweep over design §c's matrix).
 */
import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AuditIntegrityFinding } from "../../src/operational/audit-log.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import {
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
  CHECKPOINT_NAMESPACE,
  FaultInjectingStorage,
  buildSignedFortress,
  checkpointKey,
  deleteCheckpoint,
  deleteControlRecord,
  findingsOfKind,
  hardFindings,
  lenientFindings,
  readCheckpointRecord,
  strictReadError,
  stripCheckpoint,
  writeCheckpointRecordRaw,
} from "../helpers/signing-fixture.js";

async function lenientFindingsVia(
  storage: StorageBackend,
  masterKey: Uint8Array
): Promise<AuditIntegrityFinding[]> {
  const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
  const result = await reader.query({ limit: 1000 });
  return result.integrity_findings as AuditIntegrityFinding[];
}

describe("IC-05-DG §f-6: partial enumeration (D5 / R3-e regression)", () => {
  it("unreadable checkpoint + deleted latch: state_INDETERMINATE, strict fails closed, and NO latch record is written", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    const faulty = new FaultInjectingStorage(storage);
    faulty.readFaults = [
      { namespace: CHECKPOINT_NAMESPACE, key: checkpointKey(2) },
    ];

    const findings = await lenientFindingsVia(faulty, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_state_indeterminate").length
    ).toBeGreaterThanOrEqual(1);
    // The per-record finding carries the failing key; the scoped
    // indeterminate finding names the blindness (fail-closed-must-be-
    // diagnosable, taken together an operator can locate the starved file).
    expect(
      findingsOfKind(findings, "storage_unavailable").some(
        (finding) => finding.key === checkpointKey(2)
      )
    ).toBe(true);
    // The R3-e load-bearing assertion: no floor was stamped from the
    // partial view.
    expect(
      await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY)
    ).toBeNull();
    // Strict fails closed on the blindness.
    const strictReader = new AuditLog(faulty, masterKey);
    await expect(strictReader.query({ limit: 100 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
    });
  });

  it("ARMED_PARTIAL (latch present, one record unreadable): verdicts for readable records only, NO durable head write, scoped indeterminate finding", async () => {
    // Build a fortress whose head endpoints are UNCOMMITTED (every head
    // write after the ensure failed), so the load would want to self-heal;
    // the partial enumeration must veto that stamp.
    const base = await buildSignedFortress(1);
    const { storage, masterKey, storedIdentity } = base;
    const faultyWriter = new FaultInjectingStorage(storage);
    faultyWriter.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [1, 2, 3, 4, 5, 6],
    };
    const writer2 = new AuditLog(faultyWriter, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    const { appendCriticalEntries } = await import("../helpers/signing-fixture.js");
    await appendCriticalEntries(writer2, 2, storedIdentity.identity_id);

    const headBefore = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!
    );
    // The head tip is behind the store (writes failed), so a CLEAN load
    // would raise it; a PARTIAL load must not.
    const faultyReader = new FaultInjectingStorage(storage);
    faultyReader.readFaults = [
      { namespace: CHECKPOINT_NAMESPACE, key: checkpointKey(2) },
    ];
    const findings = await lenientFindingsVia(faultyReader, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_state_indeterminate").length
    ).toBeGreaterThanOrEqual(1);
    const headAfter = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!
    );
    expect(headAfter).toBe(headBefore);

    // Remove the fault: the next COMPLETE clean pass self-heals the head.
    const healed = await lenientFindingsVia(storage, masterKey);
    expect(
      healed.filter((finding) => finding.kind.startsWith("checkpoint_signing_"))
    ).toEqual([]);
    const headHealed = JSON.parse(
      bytesToString((await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!)
    );
    expect(headHealed.data.highest_signed_checkpoint_sequence).toBe(3);
  });

  it("the LATCH itself unreadable: state_INDETERMINATE (never UNARMED-clean, never TAMPERED), carrying key and error class", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    // Strip everything too: treat-error-as-absent would read this store as
    // UNARMED-clean, which is exactly the exploit the absence rule blocks.
    await stripCheckpoint(storage, 1);
    await stripCheckpoint(storage, 2);
    const faulty = new FaultInjectingStorage(storage);
    faulty.readFaults = [
      { namespace: CHECKPOINT_NAMESPACE, key: AUDIT_SIGNING_LATCH_V2_KEY },
    ];

    const findings = await lenientFindingsVia(faulty, masterKey);
    const indeterminate = findingsOfKind(
      findings,
      "checkpoint_signing_state_indeterminate"
    );
    expect(
      indeterminate.some(
        (finding) =>
          finding.key === AUDIT_SIGNING_LATCH_V2_KEY &&
          finding.message.includes("EACCES")
      )
    ).toBe(true);
    // Not TAMPERED: an EACCES proves nothing about the bytes.
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "latch-tamper"
      )
    ).toBe(false);
    // The strip is still caught from the surviving head witness (three-
    // memory MIN): indeterminate suppresses stamping, not verdicts.
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").length
    ).toBeGreaterThanOrEqual(1);
  });
});

describe("IC-05-DG §f-7: monotone-loudness sweep (§c's matrix, delete column now real cells)", () => {
  type Expectation = "hard-forever" | "recovery-warn-after" | "clean";
  const scenarios: Array<{
    name: string;
    op: (storage: StorageBackend) => Promise<void>;
    expectation: Expectation;
  }> = [
    {
      name: "latch delete (clean store)",
      op: (storage) => deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY),
      expectation: "recovery-warn-after",
    },
    {
      name: "latch corrupt (MAC break)",
      op: async (storage) => {
        const raw = (await storage.read(
          CHECKPOINT_NAMESPACE,
          AUDIT_SIGNING_LATCH_V2_KEY
        ))!;
        const record = JSON.parse(bytesToString(raw));
        record.data.armed_at_sequence = 40;
        await storage.write(
          CHECKPOINT_NAMESPACE,
          AUDIT_SIGNING_LATCH_V2_KEY,
          stringToBytes(JSON.stringify(record))
        );
      },
      expectation: "hard-forever",
    },
    {
      name: "head delete (clean store)",
      op: (storage) => deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY),
      expectation: "recovery-warn-after",
    },
    {
      name: "head corrupt (marker strip)",
      op: async (storage) => {
        const raw = (await storage.read(
          CHECKPOINT_NAMESPACE,
          AUDIT_SIGNING_HEAD_KEY
        ))!;
        const record = JSON.parse(bytesToString(raw));
        delete record.__sanctuary_audit_signing_head_v1;
        await storage.write(
          CHECKPOINT_NAMESPACE,
          AUDIT_SIGNING_HEAD_KEY,
          stringToBytes(JSON.stringify(record))
        );
      },
      expectation: "hard-forever",
    },
    {
      name: "checkpoint whole-record deletion (interior)",
      op: (storage) => deleteCheckpoint(storage, 2),
      expectation: "hard-forever",
    },
    {
      name: "checkpoint whole-record deletion (committed tail)",
      op: (storage) => deleteCheckpoint(storage, 4),
      expectation: "hard-forever",
    },
    {
      name: "checkpoint strip (field rewrite)",
      op: (storage) => stripCheckpoint(storage, 3),
      expectation: "hard-forever",
    },
    {
      name: "unsigned_reason spoof alone (no trust weight, no effect)",
      op: async (storage) => {
        const record = (await readCheckpointRecord(storage, 3))!;
        // A SIGNED record's unsigned_reason is not even part of the signed
        // payload; planting one changes nothing.
        (record as { unsigned_reason?: string }).unsigned_reason =
          "checkpoint signer failed: identity material unreadable or signing error";
        await writeCheckpointRecordRaw(storage, 3, record);
      },
      expectation: "clean",
    },
    {
      name: "previous_checkpoint_sequence rewrite (signed field breaks)",
      op: async (storage) => {
        const record = (await readCheckpointRecord(storage, 3))!;
        record.previous_checkpoint_sequence = 1;
        await writeCheckpointRecordRaw(storage, 3, record);
      },
      expectation: "hard-forever",
    },
  ];

  for (const scenario of scenarios) {
    it(`${scenario.name}: findings(tampered) ⊇ findings(clean), and a second load never heals below the pinned re-grade`, async () => {
      const { storage, masterKey } = await buildSignedFortress(4);
      expect(await lenientFindings(storage, masterKey)).toEqual([]);
      await scenario.op(storage);

      const first = await lenientFindings(storage, masterKey);
      const second = await lenientFindings(storage, masterKey);
      switch (scenario.expectation) {
        case "clean":
          expect(first).toEqual([]);
          expect(second).toEqual([]);
          break;
        case "hard-forever":
          expect(hardFindings(first).length).toBeGreaterThanOrEqual(1);
          expect(hardFindings(second).length).toBeGreaterThanOrEqual(1);
          break;
        case "recovery-warn-after":
          expect(hardFindings(first).length).toBeGreaterThanOrEqual(1);
          // The ONLY sanctioned softening: the pinned recovery-warn
          // re-grade. Never silence.
          expect(second.length).toBeGreaterThanOrEqual(1);
          expect(second.every((finding) => finding.severity === "warn")).toBe(true);
          break;
      }
    });
  }

  it("composite: unreadable-latch (chmod) on a stripped+latch-deleted store never reads UNARMED-clean", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    await stripCheckpoint(storage, 1);
    await stripCheckpoint(storage, 2);
    await deleteControlRecord(storage, AUDIT_SIGNING_HEAD_KEY);
    const faulty = new FaultInjectingStorage(storage);
    faulty.readFaults = [
      { namespace: CHECKPOINT_NAMESPACE, key: AUDIT_SIGNING_LATCH_V2_KEY },
    ];
    const findings = await lenientFindingsVia(faulty, masterKey);
    expect(hardFindings(findings).length).toBeGreaterThanOrEqual(1);
    expect(
      findingsOfKind(findings, "checkpoint_signing_state_indeterminate").length
    ).toBeGreaterThanOrEqual(1);
  });

  it("strict-mode gate: the warn re-grade is visible in query results while strict loads succeed", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    await deleteControlRecord(storage, AUDIT_SIGNING_LATCH_V2_KEY);
    await lenientFindings(storage, masterKey); // the recovery pass

    // Strict reader now loads (warn is non-fatal)...
    expect(await strictReadError(storage, masterKey)).toBeNull();
    // ...and the finding is still VISIBLE to it (no mode drops a finding).
    const strictReader = new AuditLog(storage, masterKey);
    const result = await strictReader.query({ limit: 100 });
    const warns = (result.integrity_findings as AuditIntegrityFinding[]).filter(
      (finding) => finding.severity === "warn"
    );
    expect(warns.length).toBeGreaterThanOrEqual(1);
  });
});
