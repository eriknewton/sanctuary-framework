/**
 * Anti-Rollback Epoch Anchoring — Stage 1 tests.
 *
 * The threat under regression: an attacker with disk write but WITHOUT the
 * current master restores an older, internally-valid snapshot to resurrect a
 * rotated-away credential. Stage 1 maintains a monotonic epoch witness and
 * cross-checks it at boot; a regression freezes trust-bearing writes (never
 * bricks boot) until an audited, passphrase-gated restore-attest.
 *
 * Each test closes one leg: witness monotonicity, the boot detector verdicts,
 * the fail-CLOSED-toward-freeze direction on tampered/missing witnesses, the
 * enforceCustodyFloor freeze chokepoint, restore-attest as the only sanctioned
 * way down, and the envelope-epoch MAC binding (an attacker cannot lower the
 * on-disk epoch without the master).
 */

import { describe, it, expect } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";
import {
  readEpochWitness,
  writeEpochWitness,
  isRollbackFrozen,
  observeWitnessEpoch,
  evaluateRollback,
  evaluateAndEnforceRollback,
  restoreAttest,
  EPOCH_WITNESS_META_KEY,
  ROLLBACK_FREEZE_META_KEY,
  type WitnessObservation,
} from "../../src/core/anti-rollback.js";
import {
  writeCustodyEnvelope,
  readCustodyEnvelope,
  enforceCustodyFloor,
  verifyEnvelopeMac,
  envelopeEpochOf,
  readEnvelopeEpoch,
  wrapMasterWithPassphrase,
  wrapMasterWithRecoveryKey,
  CustodyRollbackFrozenError,
  CustodyEnvelopeIntegrityError,
  type CustodyEnvelope,
} from "../../src/core/master-custody.js";

function okObservation(highestEpoch: number, source = "test"): WitnessObservation {
  return { highestEpoch, source, suspect: false, notes: [] };
}

/** A no-op durable-audit callback for tests that don't assert on the record. */
const noopRecord = async (): Promise<void> => {};

describe("epoch witness", () => {
  it("round-trips and authenticates under the master", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 3,
      epoch_id: "rot-3",
      witnessed_at: "2026-06-12T00:00:00.000Z",
    });
    const read = await readEpochWitness(storage, master);
    expect(read.status).toBe("valid");
    if (read.status === "valid") expect(read.data.epoch).toBe(3);
  });

  it("reads absent when there is no record", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    expect((await readEpochWitness(storage, master)).status).toBe("absent");
  });

  it("reads invalid (suspected) under the wrong master — fail closed", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const other = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 2,
      epoch_id: "rot-2",
      witnessed_at: "2026-06-12T00:00:00.000Z",
    });
    expect((await readEpochWitness(storage, other)).status).toBe("invalid");
  });

  it("reads invalid when the record bytes are tampered", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 2,
      epoch_id: "rot-2",
      witnessed_at: "2026-06-12T00:00:00.000Z",
    });
    const raw = await storage.read("_meta", EPOCH_WITNESS_META_KEY);
    const obj = JSON.parse(bytesToString(raw!)) as { data: { epoch: number } };
    obj.data.epoch = 99; // lower? no — forge higher; MAC must now fail
    await storage.write(
      "_meta",
      EPOCH_WITNESS_META_KEY,
      stringToBytes(JSON.stringify(obj))
    );
    expect((await readEpochWitness(storage, master)).status).toBe("invalid");
  });

  it("is monotonic: refuses to lower the epoch without force", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 5,
      epoch_id: "rot-5",
      witnessed_at: "t",
    });
    await expect(
      writeEpochWitness(storage, master, {
        epoch: 2,
        epoch_id: "rot-2",
        witnessed_at: "t",
      })
    ).rejects.toThrow(/refusing to lower the custody epoch witness/);
    // force re-baselines lower (restore-attest only)
    await writeEpochWitness(
      storage,
      master,
      { epoch: 2, epoch_id: "rot-2", witnessed_at: "t" },
      { force: true }
    );
    const read = await readEpochWitness(storage, master);
    if (read.status === "valid") expect(read.data.epoch).toBe(2);
  });
});

describe("rollback freeze marker", () => {
  it("reads NOT frozen when absent", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(false);
  });

  it("fails CLOSED (frozen) on a tampered freeze marker", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    // Plant a garbage record at the freeze key — an attacker corrupting their
    // own marker must NOT thereby clear the freeze.
    await storage.write(
      "_meta",
      ROLLBACK_FREEZE_META_KEY,
      stringToBytes(JSON.stringify({ garbage: true }))
    );
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
  });

  it("fails CLOSED (frozen) on a freeze marker MAC'd under the wrong master", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const other = generateRandomKey();
    // Detect under `master`, then read under `other` (the spliced-in master) —
    // must stay frozen.
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(4),
    });
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
    expect((await isRollbackFrozen(storage, other)).frozen).toBe(true);
  });
});

describe("evaluateRollback (pure verdict)", () => {
  it("ok when the on-disk epoch matches the witness", () => {
    expect(
      evaluateRollback({ envelopeEpoch: 3, observation: okObservation(3) }).kind
    ).toBe("ok");
  });

  it("ok when the on-disk epoch EXCEEDS the witness (rolled forward)", () => {
    expect(
      evaluateRollback({ envelopeEpoch: 4, observation: okObservation(3) }).kind
    ).toBe("ok");
  });

  it("suspected when the on-disk epoch is older than the witness", () => {
    const v = evaluateRollback({
      envelopeEpoch: 1,
      observation: okObservation(3),
    });
    expect(v.kind).toBe("rollback-suspected");
    if (v.kind === "rollback-suspected") {
      expect(v.observedEpoch).toBe(1);
      expect(v.witnessedEpoch).toBe(3);
    }
  });

  it("suspected when a witness is tampered, regardless of the numbers", () => {
    const v = evaluateRollback({
      envelopeEpoch: 5,
      observation: { highestEpoch: 0, source: "x", suspect: true, notes: ["t"] },
    });
    expect(v.kind).toBe("rollback-suspected");
  });
});

describe("observeWitnessEpoch", () => {
  it("takes the rotation epoch count as the floor", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const obs = await observeWitnessEpoch({
      storage,
      master,
      rotationEpochCount: 2,
      rotationEpochTampered: false,
    });
    expect(obs.highestEpoch).toBe(2);
    expect(obs.suspect).toBe(false);
  });

  it("marks suspect when the rotation epoch record is tampered", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const obs = await observeWitnessEpoch({
      storage,
      master,
      rotationEpochCount: -1,
      rotationEpochTampered: true,
    });
    expect(obs.suspect).toBe(true);
  });

  it("takes the higher of the rotation count and the witness record", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 7,
      epoch_id: "rot-7",
      witnessed_at: "t",
    });
    const obs = await observeWitnessEpoch({
      storage,
      master,
      rotationEpochCount: 2,
      rotationEpochTampered: false,
    });
    expect(obs.highestEpoch).toBe(7);
  });

  it("marks suspect when the witness record is tampered (wrong master)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const other = generateRandomKey();
    await writeEpochWitness(storage, master, {
      epoch: 1,
      epoch_id: "rot-1",
      witnessed_at: "t",
    });
    const obs = await observeWitnessEpoch({
      storage,
      master: other,
      rotationEpochCount: 0,
      rotationEpochTampered: false,
    });
    expect(obs.suspect).toBe(true);
  });

  it("marks suspect on a SPLICE head anchor even when both epoch witnesses are deleted (codex r1)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    // No epoch witness, no rotation record (the attacker deleted both), epoch 0
    // on disk — but the audit head anchor survives the custody-only splice and
    // does not authenticate under the swapped-in (old) master.
    const obs = await observeWitnessEpoch({
      storage,
      master,
      rotationEpochCount: 0,
      rotationEpochTampered: false,
      headAnchor: { status: "tampered" },
    });
    expect(obs.suspect).toBe(true);
    expect(
      evaluateRollback({ envelopeEpoch: 0, observation: obs }).kind
    ).toBe("rollback-suspected");
  });

  it("does NOT mark suspect on a valid head anchor for a genuine never-rotated fortress", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const obs = await observeWitnessEpoch({
      storage,
      master,
      rotationEpochCount: 0,
      rotationEpochTampered: false,
      headAnchor: { status: "valid" },
    });
    expect(obs.suspect).toBe(false);
    expect(evaluateRollback({ envelopeEpoch: 0, observation: obs }).kind).toBe(
      "ok"
    );
  });
});

describe("evaluateAndEnforceRollback (boot detector)", () => {
  it("advances the monotonic witness on an OK verdict and does not freeze", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const res = await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 2,
      observation: okObservation(2),
    });
    expect(res.frozen).toBe(false);
    const witness = await readEpochWitness(storage, master);
    expect(witness.status).toBe("valid");
    if (witness.status === "valid") expect(witness.data.epoch).toBe(2);
  });

  it("freezes + banners on a rollback verdict, but the caller (not this) refuses boot", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const res = await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(3),
    });
    expect(res.frozen).toBe(true);
    expect(res.banner).toMatch(/SUSPECTED CUSTODY ROLLBACK/);
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
  });

  it("keeps a prior freeze in effect across an OK re-boot (no auto-clear)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    // First boot: rollback detected, freeze set.
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(3),
    });
    // Operator rolls forward to epoch 3 WITHOUT attesting; re-boot sees OK
    // numbers but the freeze must persist until restore-attest.
    const res = await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 3,
      observation: okObservation(3),
    });
    expect(res.frozen).toBe(true);
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
  });

  it("preserves the original detection timestamp across repeated suspected boots", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    let t = 0;
    const now = () => new Date(1_000_000 + t++ * 60_000);
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(3),
      now,
    });
    const first = await isRollbackFrozen(storage, master);
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(3),
      now,
    });
    const second = await isRollbackFrozen(storage, master);
    expect(second.data?.frozen_at).toBe(first.data?.frozen_at);
  });
});

describe("restoreAttest (the only sanctioned way down)", () => {
  it("re-baselines the witness to the current epoch and clears the freeze", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    // Detect a rollback (witness floor 5, on-disk 1) → frozen.
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 1,
      observation: okObservation(5),
    });
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
    const result = await restoreAttest({
      storage,
      master,
      currentEpoch: 1,
      epochId: "attested-1",
      recordAttestation: noopRecord,
    });
    expect(result.unfroze).toBe(true);
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(false);
    const witness = await readEpochWitness(storage, master);
    if (witness.status === "valid") expect(witness.data.epoch).toBe(1);
  });

  it("cannot be invoked without the master (the attacker cannot clear the freeze)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const attacker = generateRandomKey();
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(4),
    });
    // The attacker can CALL restoreAttest with a wrong master, but it writes a
    // witness/clears a freeze keyed to THAT master — it does not clear the
    // freeze the real master sees, and the real master still reads frozen.
    await restoreAttest({
      storage,
      master: attacker,
      currentEpoch: 0,
      epochId: "forged",
      recordAttestation: noopRecord,
    });
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
  });

  it("aborts WITHOUT mutating when the durable audit fails (atomicity, codex r2)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 1,
      observation: okObservation(5),
    });
    // Seed a high witness so we can prove it was NOT lowered on the failed path.
    await writeEpochWitness(
      storage,
      master,
      { epoch: 5, epoch_id: "rot-5", witnessed_at: "t" },
      { force: true }
    );
    await expect(
      restoreAttest({
        storage,
        master,
        currentEpoch: 1,
        epochId: "attested-1",
        recordAttestation: async () => {
          throw new Error("audit append failed");
        },
      })
    ).rejects.toThrow(/audit append failed/);
    // Freeze still in effect; witness NOT lowered to 1.
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
    const witness = await readEpochWitness(storage, master);
    if (witness.status === "valid") expect(witness.data.epoch).toBe(5);
  });
});

describe("enforceCustodyFloor freeze chokepoint", () => {
  async function twoFactorEnvelope(
    storage: MemoryStorage,
    master: Uint8Array
  ): Promise<CustodyEnvelope> {
    const pass = await wrapMasterWithPassphrase(master, "pw", { verified: true });
    const rk = wrapMasterWithRecoveryKey(master, generateRandomKey(), {
      verified: true,
    });
    return writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "interactive",
        wraps: [pass, rk],
        created_at: "t",
      },
      master
    );
  }

  it("passes when not frozen and the floor is met", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await twoFactorEnvelope(storage, master);
    await expect(
      enforceCustodyFloor(storage, "identity_create", master)
    ).resolves.toBeUndefined();
  });

  it("refuses trust-bearing writes while frozen (even with the floor met)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await twoFactorEnvelope(storage, master);
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(2),
    });
    await expect(
      enforceCustodyFloor(storage, "identity_create", master)
    ).rejects.toBeInstanceOf(CustodyRollbackFrozenError);
  });

  it("passes again after restore-attest clears the freeze", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await twoFactorEnvelope(storage, master);
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(2),
    });
    await restoreAttest({
      storage,
      master,
      currentEpoch: 0,
      epochId: "attested",
      recordAttestation: noopRecord,
    });
    await expect(
      enforceCustodyFloor(storage, "identity_create", master)
    ).resolves.toBeUndefined();
  });

  it("re-freezes via recompute when an attacker DELETES the freeze marker (codex r2 MEDIUM)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    // Two-factor envelope at epoch 0, but a higher epoch witness exists (a real
    // rotation happened) — so the on-disk epoch (0) is a rollback vs witness 3.
    await twoFactorEnvelope(storage, master);
    await writeEpochWitness(
      storage,
      master,
      { epoch: 3, epoch_id: "rot-3", witnessed_at: "t" },
      { force: true }
    );
    // Boot detects the rollback and freezes.
    await evaluateAndEnforceRollback({
      storage,
      master,
      envelopeEpoch: 0,
      observation: okObservation(3),
    });
    // Attacker deletes the freeze CACHE to try to bypass the chokepoint.
    await storage.delete("_meta", ROLLBACK_FREEZE_META_KEY);
    // enforceCustodyFloor recomputes from the witness (epoch 3) vs envelope (0)
    // and re-freezes — the write still refuses.
    await expect(
      enforceCustodyFloor(storage, "identity_create", master)
    ).rejects.toBeInstanceOf(CustodyRollbackFrozenError);
    // And the freeze marker has been re-established.
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);
  });
});

describe("envelope epoch MAC binding", () => {
  it("absent epoch reads as 0 and verifies under the existing MAC", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const wrap = await wrapMasterWithPassphrase(master, "pw", { verified: true });
    const env = await writeCustodyEnvelope(
      storage,
      { v: 1, install_mode: "interactive", wraps: [wrap], created_at: "t" },
      master
    );
    expect(env.epoch).toBeUndefined();
    expect(envelopeEpochOf(env)).toBe(0);
    expect(await readEnvelopeEpoch(storage)).toBe(0);
    verifyEnvelopeMac(env, master); // must not throw
  });

  it("binds the epoch into the MAC: lowering it on disk fails verification", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const wrap = await wrapMasterWithPassphrase(master, "pw", { verified: true });
    await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "interactive",
        wraps: [wrap],
        created_at: "t",
        epoch: 3,
        epoch_id: "rot-3",
      },
      master
    );
    // Attacker lowers the epoch on disk WITHOUT the master.
    const env = (await readCustodyEnvelope(storage)) as CustodyEnvelope;
    expect(env.epoch).toBe(3);
    const forged: CustodyEnvelope = { ...env, epoch: 0, epoch_id: "rot-0" };
    expect(() => verifyEnvelopeMac(forged, master)).toThrow(
      CustodyEnvelopeIntegrityError
    );
  });

  it("an epoch-bearing envelope round-trips its epoch through read", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    const wrap = await wrapMasterWithPassphrase(master, "pw", { verified: true });
    await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "interactive",
        wraps: [wrap],
        created_at: "t",
        epoch: 4,
        epoch_id: "rot-4",
      },
      master
    );
    expect(await readEnvelopeEpoch(storage)).toBe(4);
  });
});
