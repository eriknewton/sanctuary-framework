/**
 * Anti-Rollback Stage 2 — external Rekor counter-floor cross-check.
 *
 * The threat Stage 2 closes (above Stage 1): a FULL-SNAPSHOT rollback of an
 * ANCHORED fortress. Stage 1's witnesses all live under the restored tree, so
 * a self-consistent full-tree restore is invisible to it. The external Rekor
 * log is outside the attacker's disk: the highest counter the fortress
 * anchored there is a freshness witness the snapshot cannot roll back. If the
 * on-disk transparency counter floor is BELOW that highest anchored counter,
 * the checkpoint store has been rolled back to before an anchoring the public
 * log still remembers.
 *
 * Posture under regression matches Stage 1 EXACTLY: warn-loud + the same
 * `custody_rollback_suspected` finding class + FREEZE via the SAME marker /
 * `enforceCustodyFloor` chokepoint, NEVER refuse boot, `restore-attest` clears
 * it. A fortress with transparency NOT enabled is a clean PASS (Stage 2 does
 * not apply); missing/tampered receipts WITH transparency on fail toward
 * FREEZE, never silent PASS.
 *
 * Pure-verdict tests cover every fail direction deterministically; the
 * integration tests run the REAL anchoring pipeline (emit → anchor through the
 * real Rekor client against the synthetic log fixture → roll the floor back)
 * so the offline witness resolution is exercised end to end. No test touches
 * the network (synthetic-fixture rule).
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toBase64url, stringToBytes, bytesToString } from "../../src/core/encoding.js";
import { randomBytes, generateRandomKey } from "../../src/core/random.js";
import {
  evaluateRekorCounterFloor,
  evaluateAndEnforceRekorCounterFloor,
  isRollbackFrozen,
  restoreAttest,
  REKOR_COUNTER_FLOOR_WITNESS_SOURCE,
  ROLLBACK_FREEZE_META_KEY,
  type RekorFloorInputs,
} from "../../src/core/anti-rollback.js";
import { CustodyRollbackFrozenError } from "../../src/core/master-custody.js";
import {
  emitEnforcementCheckpoint,
  readTransparencyCounterFloor,
  TRANSPARENCY_FLOOR_META_KEY,
  type TransparencySigner,
} from "../../src/transparency/emitter.js";
import {
  anchorCheckpoint,
  computeHighestVerifiedAnchoredCounter,
  enableAnchoring,
  disableAnchoring,
  readAnchorReceipts,
  TRANSPARENCY_ANCHOR_NAMESPACE,
  anchorReceiptStorageKey,
} from "../../src/transparency/anchoring.js";
import type { EnforcementCheckpointRecord } from "../../src/transparency/checkpoint.js";
import { FakeRekorLog } from "../transparency/fake-rekor-log.js";

const FORTRESS_ID = "fortress-stage2-test";
const REKOR_URL = "https://rekor.fixture.test";

// ---- pure verdict ----------------------------------------------------------

function inputs(over: Partial<RekorFloorInputs> = {}): RekorFloorInputs {
  return {
    stage2Applies: true,
    onDiskFloor: { status: "valid", highest_counter: 3 },
    highestAnchoredCounter: 3,
    unverifiableAnchorPresent: false,
    notes: [],
    ...over,
  };
}

describe("evaluateRekorCounterFloor (pure verdict)", () => {
  it("is NOT-APPLICABLE when Stage 2 does not apply (no receipts + config not enabled): clean, never freeze", () => {
    const v = evaluateRekorCounterFloor(inputs({ stage2Applies: false }));
    expect(v.kind).toBe("not-applicable");
  });

  it("is CONSISTENT when the on-disk floor equals the highest anchored counter", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "valid", highest_counter: 5 }, highestAnchoredCounter: 5 })
    );
    expect(v.kind).toBe("consistent");
  });

  it("is CONSISTENT when the on-disk floor is ABOVE the highest anchored counter", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "valid", highest_counter: 9 }, highestAnchoredCounter: 5 })
    );
    expect(v.kind).toBe("consistent");
  });

  it("is CONSISTENT when transparency is on but nothing is anchored yet (no external witness)", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "absent" }, highestAnchoredCounter: 0 })
    );
    expect(v.kind).toBe("consistent");
  });

  it("is SUSPECTED-ROLLBACK when the on-disk floor is BELOW the highest anchored counter", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "valid", highest_counter: 2 }, highestAnchoredCounter: 5 })
    );
    expect(v.kind).toBe("rollback-suspected");
    if (v.kind === "rollback-suspected") {
      expect(v.onDiskFloor).toBe(2);
      expect(v.highestAnchoredCounter).toBe(5);
      expect(v.notes[0]).toMatch(/BELOW the/);
    }
  });

  it("is SUSPECTED when the floor is ABSENT but something IS anchored (floor 0 < anchored)", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "absent" }, highestAnchoredCounter: 4 })
    );
    expect(v.kind).toBe("rollback-suspected");
    if (v.kind === "rollback-suspected") expect(v.onDiskFloor).toBe(0);
  });

  it("fails toward FREEZE when the on-disk floor is INVALID (tampered), regardless of numbers", () => {
    const v = evaluateRekorCounterFloor(
      inputs({ onDiskFloor: { status: "invalid" }, highestAnchoredCounter: 0 })
    );
    expect(v.kind).toBe("rollback-suspected");
    if (v.kind === "rollback-suspected") {
      expect(v.notes[0]).toMatch(/failed.*authentication/i);
    }
  });

  it("fails toward FREEZE when an anchored receipt is unverifiable, even if floor >= anchored", () => {
    const v = evaluateRekorCounterFloor(
      inputs({
        onDiskFloor: { status: "valid", highest_counter: 9 },
        highestAnchoredCounter: 3,
        unverifiableAnchorPresent: true,
        notes: ["receipt 3 did not verify offline"],
      })
    );
    expect(v.kind).toBe("rollback-suspected");
  });
});

// ---- integration: real anchoring pipeline ----------------------------------

function testSigner(privateKey = randomBytes(32)): TransparencySigner {
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    publicKey,
    sign: async (bytes) => ed25519.sign(bytes, privateKey),
  };
}

let fortressPath: string;
let binaryPath: string;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-stage2-"));
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  await mkdir(rulesDir, { recursive: true });
  await writeFile(
    join(rulesDir, "allow-github.json"),
    JSON.stringify({ rule_id: "allow-github", host: "github.com" })
  );
  binaryPath = join(fortressPath, "fake-binary.js");
  await writeFile(binaryPath, "console.log('sanctuary');");
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

interface Anchored {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  records: EnforcementCheckpointRecord[];
  log: FakeRekorLog;
}

/** Emit + anchor n checkpoints through the REAL pipeline against the fixture. */
async function anchorN(n: number): Promise<Anchored> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const signer = testSigner();
  const log = new FakeRekorLog();
  log.appendNoise("pre-existing");
  await enableAnchoring({ storage, masterKey, auditLog, fortressId: FORTRESS_ID, rekorUrl: REKOR_URL });
  const records: EnforcementCheckpointRecord[] = [];
  for (let i = 0; i < n; i++) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: i % 2 === 0 ? "egress_blocked" : "egress_allowed",
      identity_id: FORTRESS_ID,
      result: "success",
      details: { rule_id: `rule-${i}` },
    });
    const record = await emitEnforcementCheckpoint({
      storage,
      auditLog,
      fortressId: FORTRESS_ID,
      fortressPath,
      masterKey,
      signer,
      binaryPath,
      version: "0.0.0-test",
    });
    records.push(record);
    const outcome = await anchorCheckpoint({
      storage,
      masterKey,
      auditLog,
      record,
      fetchFn: log.fetchLike(),
    });
    expect(outcome.status).toBe("anchored");
    log.appendNoise(`foreign-${i}`);
  }
  return { storage, masterKey, auditLog, records, log };
}

/** Re-write the MAC'd on-disk transparency floor to a LOWER counter under the
 * REAL master (simulating a restored snapshot whose floor is older than the
 * external anchors). Done by re-deriving the floor MAC exactly as the emitter. */
async function forceFloorTo(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  counter: number
): Promise<void> {
  const { derivePurposeKey } = await import("../../src/core/key-derivation.js");
  const { hmacSha256 } = await import("../../src/core/hashing.js");
  const { canonicalJson } = await import("../../src/audit/chain.js");
  const macKey = derivePurposeKey(masterKey, "transparency-counter-floor");
  const data = { highest_counter: counter };
  const mac = hmacSha256(
    macKey,
    stringToBytes("sanctuary.transparency-counter-floor.v1\n" + canonicalJson(data))
  );
  macKey.fill(0);
  const envelope = {
    ["__sanctuary_transparency_counter_floor_v1"]: true,
    data,
    mac: toBase64url(mac),
  };
  await storage.write("_meta", TRANSPARENCY_FLOOR_META_KEY, stringToBytes(JSON.stringify(envelope)));
}

describe("computeHighestVerifiedAnchoredCounter (offline witness resolution)", () => {
  it("resolves the highest anchored counter from local receipts, no network", async () => {
    const a = await anchorN(3);
    const result = await computeHighestVerifiedAnchoredCounter({
      storage: a.storage,
      masterKey: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(result.highestAnchoredCounter).toBe(3);
    expect(result.verifiedAnchorCount).toBe(3);
    expect(result.unverifiableAnchorPresent).toBe(false);
  });

  it("flags a tampered receipt as unverifiable (never a silent witness)", async () => {
    const a = await anchorN(2);
    // Corrupt the commitment digest of receipt 2 → its offline checks fail.
    const key = anchorReceiptStorageKey(2);
    const raw = await a.storage.read(TRANSPARENCY_ANCHOR_NAMESPACE, key);
    const obj = JSON.parse(bytesToString(raw!)) as { commitment_digest: string };
    obj.commitment_digest = "f".repeat(64);
    await a.storage.write(TRANSPARENCY_ANCHOR_NAMESPACE, key, stringToBytes(JSON.stringify(obj)));
    const result = await computeHighestVerifiedAnchoredCounter({
      storage: a.storage,
      masterKey: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(result.unverifiableAnchorPresent).toBe(true);
  });
});

describe("evaluateAndEnforceRekorCounterFloor (boot / on-demand)", () => {
  it("PASSES clean when the floor matches the highest anchored counter (no freeze)", async () => {
    const a = await anchorN(3);
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("consistent");
    expect(r.frozen).toBe(false);
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(false);
  });

  it("FREEZES (suspected) when the on-disk floor is rolled back below the anchored counter, NEVER refusing boot", async () => {
    const a = await anchorN(3);
    // Snapshot rollback: the on-disk floor reverts to 1; the external log still
    // remembers anchor 3.
    await forceFloorTo(a.storage, a.masterKey, 1);
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("rollback-suspected");
    if (r.verdict.kind === "rollback-suspected") {
      expect(r.verdict.onDiskFloor).toBe(1);
      expect(r.verdict.highestAnchoredCounter).toBe(3);
    }
    expect(r.frozen).toBe(true);
    expect(r.banner).toMatch(/SUSPECTED CUSTODY ROLLBACK/);
    // No exception was thrown — boot is never refused.
  });

  it("freezes via the SAME Stage-1 marker, with the Rekor witness source", async () => {
    const a = await anchorN(2);
    // Roll the on-disk floor back to 1 while the external log remembers 2.
    await forceFloorTo(a.storage, a.masterKey, 1);
    await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    const frozen = await isRollbackFrozen(a.storage, a.masterKey);
    expect(frozen.frozen).toBe(true);
    expect(frozen.data?.witness_source).toBe(REKOR_COUNTER_FLOOR_WITNESS_SOURCE);
    expect(frozen.data?.witnessed_epoch).toBe(2);
    expect(frozen.data?.observed_epoch).toBe(1);
    // The marker lives at the SAME key Stage 1 uses.
    expect(await a.storage.read("_meta", ROLLBACK_FREEZE_META_KEY)).not.toBeNull();
  });

  it("the Stage-2 freeze gates enforceCustodyFloor (the same chokepoint Stage 1 uses)", async () => {
    const a = await anchorN(2);
    await forceFloorTo(a.storage, a.masterKey, 1);
    await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    const { enforceCustodyFloor } = await import("../../src/core/master-custody.js");
    await expect(
      enforceCustodyFloor(a.storage, "identity_create", a.masterKey)
    ).rejects.toBeInstanceOf(CustodyRollbackFrozenError);
  });

  it("restore-attest clears the Stage-2 freeze exactly as it clears Stage 1's", async () => {
    const a = await anchorN(2);
    await forceFloorTo(a.storage, a.masterKey, 1);
    await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(true);
    const res = await restoreAttest({
      storage: a.storage,
      master: a.masterKey,
      currentEpoch: 0,
      epochId: "stage2-restore",
      recordAttestation: async () => {},
    });
    expect(res.unfroze).toBe(true);
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(false);
    // And enforceCustodyFloor no longer throws.
    const { enforceCustodyFloor } = await import("../../src/core/master-custody.js");
    await expect(
      enforceCustodyFloor(a.storage, "identity_create", a.masterKey)
    ).resolves.toBeUndefined();
  });

  it("FIX 1: disabled-after-anchoring WITH a rolled-back floor + receipts on disk is SUSPECTED (the spoof), not not-applicable", async () => {
    const a = await anchorN(2);
    // Disable anchoring after the fact (config status=disabled, receipts +
    // floor preserved). A disk-write attacker dodging Stage 2 by flipping the
    // config off must NOT escape: receipts on disk prove anchoring happened, so
    // Stage 2 still applies and a rolled-back floor (0 < anchored 2) freezes.
    await disableAnchoring({
      storage: a.storage,
      masterKey: a.masterKey,
      auditLog: a.auditLog,
      fortressId: FORTRESS_ID,
    });
    await forceFloorTo(a.storage, a.masterKey, 0);
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("rollback-suspected");
    if (r.verdict.kind === "rollback-suspected") {
      expect(r.verdict.onDiskFloor).toBe(0);
      expect(r.verdict.highestAnchoredCounter).toBe(2);
    }
    expect(r.frozen).toBe(true);
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(true);
  });

  it("FIX 1: disabled-after-anchoring WITH a current (un-rolled-back) floor is CONSISTENT, no false positive", async () => {
    const a = await anchorN(2);
    // Legitimate disable-after-anchoring: the floor is still >= the highest
    // anchored counter, so even though Stage 2 now APPLIES (receipts present),
    // the verdict is CONSISTENT — no freeze. This is the case FIX 1 must NOT
    // false-positive on.
    await disableAnchoring({
      storage: a.storage,
      masterKey: a.masterKey,
      auditLog: a.auditLog,
      fortressId: FORTRESS_ID,
    });
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("consistent");
    expect(r.frozen).toBe(false);
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(false);
  });

  it("never freezes a fortress that NEVER enabled transparency (clean not-applicable)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage,
      master: masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("not-applicable");
    expect(r.frozen).toBe(false);
  });

  it("fails toward FREEZE when an anchored receipt is tampered with transparency ON", async () => {
    const a = await anchorN(2);
    const key = anchorReceiptStorageKey(2);
    const raw = await a.storage.read(TRANSPARENCY_ANCHOR_NAMESPACE, key);
    const obj = JSON.parse(bytesToString(raw!)) as { commitment_digest: string };
    obj.commitment_digest = "0".repeat(64);
    await a.storage.write(TRANSPARENCY_ANCHOR_NAMESPACE, key, stringToBytes(JSON.stringify(obj)));
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("rollback-suspected");
    expect(r.frozen).toBe(true);
  });

  it("fails toward FREEZE when the on-disk floor is tampered with transparency ON", async () => {
    const a = await anchorN(2);
    // Corrupt the floor MAC: flip a byte in the stored envelope.
    const raw = await a.storage.read("_meta", TRANSPARENCY_FLOOR_META_KEY);
    const obj = JSON.parse(bytesToString(raw!)) as { data: { highest_counter: number } };
    obj.data.highest_counter = 999; // forge higher → MAC now fails → invalid
    await a.storage.write(
      "_meta",
      TRANSPARENCY_FLOOR_META_KEY,
      stringToBytes(JSON.stringify(obj))
    );
    expect((await readTransparencyCounterFloor(a.storage, a.masterKey)).status).toBe("invalid");
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("rollback-suspected");
    expect(r.frozen).toBe(true);
  });

  it("FIX 2: an EXISTING-but-corrupt receipt store FREEZES (suspected), boot not refused", async () => {
    const a = await anchorN(2);
    // Replace receipt 2 with non-JSON garbage: the store is PRESENT but
    // unreadable/malformed. readAnchorReceipts throws on it; the Stage-2
    // orchestrator must catch that → unverifiableAnchorPresent → suspected +
    // freeze, NOT let the exception escape and silently skip the check.
    const key = anchorReceiptStorageKey(2);
    await a.storage.write(
      TRANSPARENCY_ANCHOR_NAMESPACE,
      key,
      stringToBytes("{ this is not valid receipt json")
    );
    // Sanity: the store is genuinely unreadable now.
    await expect(readAnchorReceipts(a.storage)).rejects.toThrow();
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("rollback-suspected");
    expect(r.frozen).toBe(true);
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(true);
    // No exception thrown out of the orchestrator — boot is never refused.
  });

  it("FIX 2: a genuinely-ABSENT receipt store with transparency on is CONSISTENT (nothing anchored), never a freeze", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    // Enable anchoring but anchor NOTHING (no receipts dir / empty store).
    await enableAnchoring({
      storage,
      masterKey,
      auditLog,
      fortressId: FORTRESS_ID,
      rekorUrl: REKOR_URL,
    });
    const r = await evaluateAndEnforceRekorCounterFloor({
      storage,
      master: masterKey,
      fortressId: FORTRESS_ID,
    });
    expect(r.verdict.kind).toBe("consistent");
    expect(r.frozen).toBe(false);
  });

  it("FIX 4: deleting the Stage-2 freeze marker STILL blocks enforceCustodyFloor (recompute re-derives the suspected verdict)", async () => {
    const a = await anchorN(3);
    // Detect a Stage-2 rollback: floor reverts to 1, external receipts remember 3.
    await forceFloorTo(a.storage, a.masterKey, 1);
    await evaluateAndEnforceRekorCounterFloor({
      storage: a.storage,
      master: a.masterKey,
      fortressId: FORTRESS_ID,
    });
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(true);

    // The attacker deletes ONLY the Stage-2 freeze marker (the cache), trying to
    // lift the freeze mid-session without a boot.
    await a.storage.delete("_meta", ROLLBACK_FREEZE_META_KEY);
    expect(await a.storage.read("_meta", ROLLBACK_FREEZE_META_KEY)).toBeNull();

    // enforceCustodyFloor must STILL block: the marker-absent recompute now
    // re-derives the Stage-2 verdict (parity with Stage 1) and re-freezes.
    const { enforceCustodyFloor } = await import("../../src/core/master-custody.js");
    await expect(
      enforceCustodyFloor(a.storage, "identity_create", a.masterKey)
    ).rejects.toBeInstanceOf(CustodyRollbackFrozenError);
    // The recompute re-established the marker.
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(true);
  });

  it("FIX 4: the legitimate CONSISTENT case still allows writes after a marker delete (no false freeze in recompute)", async () => {
    const a = await anchorN(2);
    // No rollback: floor matches anchored. Even with no freeze marker present,
    // the Stage-2 recompute must return consistent and allow the write.
    await a.storage.delete("_meta", ROLLBACK_FREEZE_META_KEY); // no-op (none set)
    const { enforceCustodyFloor } = await import("../../src/core/master-custody.js");
    await expect(
      enforceCustodyFloor(a.storage, "identity_create", a.masterKey)
    ).resolves.toBeUndefined();
    expect((await isRollbackFrozen(a.storage, a.masterKey)).frozen).toBe(false);
  });
});
