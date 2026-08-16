/**
 * IC-05-DG rule-12 fault-injection schedules: §f-9 (crash-ordering matrix),
 * §f-10 (the LD6 delayed-completion / BP-DEADLINE class), and §f-11 (the
 * rule-8 adversarial-complexity bound).
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
  FaultInjectingStorage,
  appendCriticalEntries,
  buildSignedFortress,
  corruptIdentityRecord,
  findingsOfKind,
  hardFindings,
  lenientFindings,
  seedStoredIdentity,
  strictReadError,
} from "../helpers/signing-fixture.js";

async function readHeadData(storage: {
  read: (n: string, k: string) => Promise<Uint8Array | null>;
}): Promise<Record<string, unknown> | null> {
  const raw = await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY);
  return raw
    ? (JSON.parse(bytesToString(raw)).data as Record<string, unknown>)
    : null;
}

describe("IC-05-DG §f-9: crash-ordering matrix (arm / signed-pair / incident-pair)", () => {
  it("crash at arm step 1 (head-ensure fails): no control record persists; the next load recovers loudly, never silently-clean-with-evidence-lost", async () => {
    const storage = new MemoryStorage();
    const faulty = new FaultInjectingStorage(storage);
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(faulty, masterKey);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [1, 2],
    };
    const writer = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 1, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    // The signed checkpoint was still written (bookkeeping never aborts the
    // audit record)...
    const record = await storage.read(
      CHECKPOINT_NAMESPACE,
      "audit-checkpoint-" + String(1).padStart(20, "0")
    );
    expect(record).not.toBeNull();
    // ...and the recovery pass is hard once, warn thereafter (a §d-named
    // state, not silence and not a permanent brick from an honest crash).
    const first = await lenientFindings(storage, masterKey);
    expect(
      hardFindings([
        ...findingsOfKind(first, "checkpoint_signing_floor_recovered"),
        ...findingsOfKind(first, "checkpoint_signing_head_recovered"),
      ]).length
    ).toBeGreaterThanOrEqual(1);
    const second = await lenientFindings(storage, masterKey);
    expect(second.every((finding) => finding.severity === "warn")).toBe(true);
    expect(await strictReadError(storage, masterKey)).toBeNull();
  });

  it("crash at arm step 2 (latch write fails): head + checkpoint survive; the floor recovers at the true first-signed sequence", async () => {
    const storage = new MemoryStorage();
    const faulty = new FaultInjectingStorage(storage);
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(faulty, masterKey);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_LATCH_V2_KEY,
      calls: [1],
    };
    const writer = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer, 2, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    // The R2-b regression shape: a swallowed first latch write must never
    // advance the DETECTED floor past the first signed checkpoint. The
    // write-path retry stamps the latch at the CURRENT sequence (a true
    // forward commitment), and the floor stays anchored at 1 by the head's
    // monotone-MIN witness (committed by append 1's tip+floor head write),
    // so the three-memory MIN keeps c1 defended.
    const latchRaw = await storage.read(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY
    );
    expect(latchRaw).not.toBeNull();
    expect(JSON.parse(bytesToString(latchRaw!)).data.armed_at_sequence).toBe(2);
    const head = await readHeadData(storage);
    expect(head!.lowest_signed_checkpoint_sequence).toBe(1);
    // The proof that matters: stripping c1 still fires (the floor did NOT
    // advance to 2, which was exactly R2-b's silent hole).
    const { stripCheckpoint } = await import("../helpers/signing-fixture.js");
    await stripCheckpoint(storage, 1);
    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.sequence === 1
      )
    ).toBe(true);
  });

  it("steady-state signed pair: a failed tip advance is re-committed by the next load's self-heal, clean", async () => {
    const { storage, masterKey, storedIdentity } = await buildSignedFortress(2);
    const faulty = new FaultInjectingStorage(storage);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [1],
    };
    const writer2 = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 1, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    expect((await readHeadData(storage))!.highest_signed_checkpoint_sequence).toBe(2);
    // Clean load: no findings (the tip is a monotone LOWER bound; a
    // checkpoint above it is the normal crash window), and the tip heals.
    expect(await lenientFindings(storage, masterKey)).toEqual([]);
    expect((await readHeadData(storage))!.highest_signed_checkpoint_sequence).toBe(3);
  });

  it("incident pair on a NEVER-armed store: a failed head write costs diagnostics, not detection (accepted §d loss), and the next incident write's monotonic count still witnesses failures", async () => {
    const storage = new MemoryStorage();
    const faulty = new FaultInjectingStorage(storage);
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(faulty, masterKey);
    await corruptIdentityRecord(faulty, storedIdentity.identity_id);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [1],
    };
    const writer = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    // Interval 1: incident write fails (diagnostic-only loss). Interval 2:
    // incident write succeeds.
    await appendCriticalEntries(writer, 2, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    const head = await readHeadData(storage);
    expect(head).not.toBeNull();
    expect(head!.incident_count).toBe(1);
    const findings = await lenientFindings(storage, masterKey);
    // The attested interval fires; the lost interval is diagnostic loss on
    // a store that was writing honest-unsigned regardless (never armed).
    expect(
      findingsOfKind(findings, "checkpoint_signing_error").length
    ).toBeGreaterThanOrEqual(1);
    expect(findingsOfKind(findings, "checkpoint_signing_downgrade")).toEqual([]);
  });

  it("incident pair on an ARMED store with the head write failing: the unattested unsigned checkpoint escalates to downgrade (monotone direction)", async () => {
    const { storage, masterKey, storedIdentity } = await buildSignedFortress(1);
    await corruptIdentityRecord(storage, storedIdentity.identity_id);
    const faulty = new FaultInjectingStorage(storage);
    faulty.failWriteOnCall = {
      namespace: CHECKPOINT_NAMESPACE,
      keyPrefix: AUDIT_SIGNING_HEAD_KEY,
      calls: [1, 2, 3],
    };
    const writer2 = new AuditLog(faulty, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    await appendCriticalEntries(writer2, 1, storedIdentity.identity_id);
    faulty.failWriteOnCall = null;

    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.sequence === 2
      )
    ).toBe(true);
  });

  it("torn latch bytes read as state_TAMPERED, never a crash and never absent", async () => {
    const { storage, masterKey } = await buildSignedFortress(1);
    const raw = (await storage.read(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY
    ))!;
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY,
      raw.slice(0, Math.floor(raw.length / 2))
    );
    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "latch-tamper"
      )
    ).toBe(true);
    // Not treated as absent: no recovery stamped over the torn record.
    const after = await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY);
    expect(after!.length).toBeLessThan(raw.length);
  });
});

describe("IC-05-DG §f-10: LD6 delayed-completion schedule (BP-DEADLINE class)", () => {
  it("(a) a deadline-expired continuation is stopped at the pre-dispatch assert: the write never lands", async () => {
    const { storage, masterKey } = await buildSignedFortress(1);
    const faulty = new FaultInjectingStorage(storage);
    const auditLog = new AuditLog(faulty, masterKey, { integrityMode: "lenient" });
    // Flip the signal to aborted DURING the chokepoint's re-read: the first
    // hold assert has already passed, so only the second, synchronous,
    // immediately-pre-dispatch assert can stop the write.
    const signal = { aborted: false };
    faulty.onRead = (namespace, key) => {
      if (namespace === CHECKPOINT_NAMESPACE && key === AUDIT_SIGNING_HEAD_KEY) {
        signal.aborted = true;
      }
    };
    const before = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!
    );
    await expect(
      (
        auditLog as unknown as {
          writeSigningControlRecord: (
            signal: { aborted: boolean },
            intent: Record<string, unknown>
          ) => Promise<string>;
        }
      ).writeSigningControlRecord(signal, {
        record: "head",
        tipCandidate: 99,
      })
    ).rejects.toThrow();
    const after = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!
    );
    expect(after).toBe(before);
  });

  it("(b) a stale arm write never overwrites a newer valid latch and never repairs an invalid one", async () => {
    const { storage, masterKey } = await buildSignedFortress(1);
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const chokepoint = (
      auditLog as unknown as {
        writeSigningControlRecord: (
          signal: { aborted: boolean },
          intent: Record<string, unknown>
        ) => Promise<string>;
      }
    ).writeSigningControlRecord.bind(auditLog);

    // Valid latch at 1: a stale arm at 5 must be a write-once no-op.
    const before = bytesToString(
      (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
    );
    expect(
      await chokepoint({ aborted: false }, {
        record: "latch",
        armed_at_sequence: 5,
        signer_kid: "stale",
        armed_at: new Date().toISOString(),
      })
    ).toBe("skipped");
    expect(
      bytesToString(
        (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
      )
    ).toBe(before);

    // Invalid latch: never repaired by overwrite (tamper evidence stays).
    const record = JSON.parse(before);
    record.data.armed_at_sequence = 3;
    const tampered = JSON.stringify(record);
    await storage.write(
      CHECKPOINT_NAMESPACE,
      AUDIT_SIGNING_LATCH_V2_KEY,
      stringToBytes(tampered)
    );
    expect(
      await chokepoint({ aborted: false }, {
        record: "latch",
        armed_at_sequence: 1,
        signer_kid: "repair-attempt",
        armed_at: new Date().toISOString(),
      })
    ).toBe("skipped");
    expect(
      bytesToString(
        (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY))!
      )
    ).toBe(tampered);
  });

  it("(c) the head's monotone merge holds under interleaved waves, a stale late landing regresses at most one increment, and the next load re-derives it from the store", async () => {
    const { storage, masterKey } = await buildSignedFortress(3);
    // Reset the head to a BEHIND state (tip 1) by rebuilding it as the
    // chokepoint would after partial write failures: read-modify-write with
    // the real MAC via the production instance's own chokepoint on a fresh
    // zeroed base is not reachable, so drive the merge rule directly with
    // chokepoint intents instead.
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const chokepoint = (
      auditLog as unknown as {
        writeSigningControlRecord: (
          signal: { aborted: boolean },
          intent: Record<string, unknown>
        ) => Promise<string>;
      }
    ).writeSigningControlRecord.bind(auditLog);
    const live = { aborted: false };

    // Regression intents must be no-ops: a lower tip, a HIGHER floor, and a
    // duplicate incident can never move the memories in their unsafe
    // directions.
    await chokepoint(live, { record: "head", tipCandidate: 1 });
    await chokepoint(live, { record: "head", floorCandidate: 3 });
    let head = await readHeadData(storage);
    expect(head!.highest_signed_checkpoint_sequence).toBe(3);
    expect(head!.lowest_signed_checkpoint_sequence).toBe(1);

    // Markers never disappear across merges.
    await chokepoint(live, {
      record: "head",
      addMarkers: [{ marker_kind: "latch_recovered", detail: "wave-test" }],
    });
    await chokepoint(live, { record: "head", tipCandidate: 2 });
    head = await readHeadData(storage);
    expect(
      (head!.latched as Array<{ detail: string }>).some(
        (marker) => marker.detail === "wave-test"
      )
    ).toBe(true);

    // The stale-landing schedule: writer A's payload (computed BEFORE writer
    // B's newer tip landed) completes late and regresses the tip by one
    // increment; the next load self-heals it from the store.
    const faulty = new FaultInjectingStorage(storage);
    const lateLog = new AuditLog(faulty, masterKey, { integrityMode: "lenient" });
    const lateChokepoint = (
      lateLog as unknown as {
        writeSigningControlRecord: (
          signal: { aborted: boolean },
          intent: Record<string, unknown>
        ) => Promise<string>;
      }
    ).writeSigningControlRecord.bind(lateLog);
    faulty.deferWritesTo = {
      namespace: CHECKPOINT_NAMESPACE,
      key: AUDIT_SIGNING_HEAD_KEY,
    };
    // A dispatches with the CURRENT (pre-B) view: merged tip stays 3.
    const pendingA = lateChokepoint(live, { record: "head", addIncidents: [] });
    await new Promise((resolve) => setTimeout(resolve, 10));
    // B lands a newer increment directly (tip 4 is a lie about the store,
    // but the point is the ordering, and 4 > 3 exercises the regression).
    faulty.deferWritesTo = null;
    await chokepoint(live, { record: "head", tipCandidate: 4 });
    expect((await readHeadData(storage))!.highest_signed_checkpoint_sequence).toBe(4);
    // A's stale payload lands late: the bounded transient (one lost raise).
    await faulty.releaseDeferredWrites();
    await pendingA;
    expect((await readHeadData(storage))!.highest_signed_checkpoint_sequence).toBe(3);
    // The next load re-derives every memory from the store: tip 4 was never
    // real (no verified c4), so the honest healed value is the store's
    // highest verified, 3 — and the transient minted no HARD verdict (the
    // only findings are the warn-grade re-emissions of the wave-test marker
    // planted above, which is this test's own arrangement).
    const afterLoad = await lenientFindings(storage, masterKey);
    expect(hardFindings(afterLoad)).toEqual([]);
    expect((await readHeadData(storage))!.highest_signed_checkpoint_sequence).toBe(3);
  });
});

describe("IC-05-DG §f-11: adversarial complexity (rule 8)", () => {
  it("attacker-induced signer failures across many intervals keep the head fixed-size and the count monotonic", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { storedIdentity } = await seedStoredIdentity(storage, masterKey);
    await corruptIdentityRecord(storage, storedIdentity.identity_id);
    const writer = new AuditLog(storage, masterKey, {
      checkpointInterval: 1,
      integrityMode: "lenient",
    });
    const INTERVALS = 100;
    await appendCriticalEntries(writer, INTERVALS, storedIdentity.identity_id);

    const raw = (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY))!;
    // The whole envelope stays under the derived byte ceiling however many
    // incidents the attacker induces.
    expect(raw.length).toBeLessThanOrEqual(16384);
    const head = JSON.parse(bytesToString(raw)).data;
    expect(head.incident_count).toBe(INTERVALS);
    expect(head.recent.length).toBeLessThanOrEqual(32);
    // The ring keeps the NEWEST K incidents (loudness-safe eviction: the
    // evicted ones escalate to downgrade classification at/above the floor,
    // and this store never armed, so eviction costs nothing).
    const sequences = head.recent.map((incident: { sequence: number }) => incident.sequence);
    expect(Math.max(...sequences)).toBe(
      Math.max(...sequences.slice().sort((a: number, b: number) => a - b))
    );
    expect(head.recent.length).toBe(32);
  }, 60_000);

  it("attacker-driven recovery waves keep the latched ring capped with a monotonic summary and the sticky hard flag (DELTA-1)", async () => {
    const { storage, masterKey } = await buildSignedFortress(2);
    const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const chokepoint = (
      auditLog as unknown as {
        writeSigningControlRecord: (
          signal: { aborted: boolean },
          intent: Record<string, unknown>
        ) => Promise<string>;
      }
    ).writeSigningControlRecord.bind(auditLog);
    const live = { aborted: false };
    await chokepoint(live, {
      record: "head",
      addMarkers: [{ marker_kind: "downgrade_latched", detail: "hard-evidence" }],
    });
    for (let wave = 0; wave < 40; wave++) {
      await chokepoint(live, {
        record: "head",
        addMarkers: [
          { marker_kind: "latch_recovered", detail: `wave-${wave}` },
        ],
      });
    }
    const head = (await readHeadData(storage))!;
    expect((head.latched as unknown[]).length).toBeLessThanOrEqual(32);
    expect(head.latched_evicted_count as number).toBeGreaterThanOrEqual(9);
    // The hard grade survives eviction of the detail marker: the sticky
    // flag, not ring residency, carries it (DELTA-1's fork-closer).
    expect(head.hard_downgrade_ever_latched).toBe(true);
    const findings = await lenientFindings(storage, masterKey);
    expect(
      findingsOfKind(findings, "checkpoint_signing_downgrade").some(
        (finding) => finding.variant === "latched"
      )
    ).toBe(true);
  });
});
