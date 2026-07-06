/**
 * Fleet control plane PR-3 fix: EXTERNAL revocation-version anti-rollback anchor.
 *
 * Defect: a corrupt stored revocation list reads as version 0, and both push
 * paths took the stored version as their monotonic floor - so a disk attacker who
 * trashes the list file could roll the floor back to 0 and re-apply an OLD,
 * genuinely-issuer-signed (lower-version) list to UN-REVOKE licenses.
 *
 * Definition-of-Done:
 *  1. read/write anchor: master-MAC'd, tri-state (valid/absent/invalid), monotonic
 *     (refuses to lower a valid anchor), wrong-master reads invalid.
 *  2. effectiveRevocationVersionFloor = max(storedListVersion, anchorVersion):
 *     a VALID list + anchor -> their max; a CORRUPT list (reads 0) + a valid
 *     anchor -> the ANCHOR (NOT 0); absent both -> 0.
 *  3. THE ROLLBACK REJECTION: with a corrupt stored list but an anchor at N, an
 *     older genuinely-signed list at version <= N is refused (not_newer) because
 *     the floor comes from the anchor, not the unreadable list.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import {
  REVOCATION_LIST_META_KEY,
  readRevocationList,
  signRevocationList,
  verifyPushedRevocationList,
  writeRevocationList,
  type RevocationListPayload,
} from "../../src/entitlement/revocation-list.js";
import {
  REVOCATION_VERSION_ANCHOR_META_KEY,
  readRevocationVersionAnchor,
  writeRevocationVersionAnchor,
  effectiveRevocationVersionFloor,
  revocationVerifiability,
  persistPushedRevocationListSerialized,
} from "../../src/entitlement/revocation-antirollback.js";
import {
  EPOCH_WITNESS_META_KEY,
  raiseRevocationFloorLatch,
  readRevocationFloorLatch,
} from "../../src/core/anti-rollback.js";

const issuer = generateKeypair();
const master = randomBytes(32);
const wrongMaster = randomBytes(32);

function payload(overrides: Partial<RevocationListPayload> = {}): RevocationListPayload {
  return {
    version: 1,
    revokedLicenseIds: ["lic-a"],
    issuer: "issuer-fp",
    issuedAt: "2026-07-06T00:00:00.000Z",
    ...overrides,
  };
}

/** Corrupt the stored list bytes so its MAC fails (reads invalid -> version 0). */
async function corruptStoredList(storage: MemoryStorage): Promise<void> {
  const raw = await storage.read("_meta", REVOCATION_LIST_META_KEY);
  const obj = JSON.parse(new TextDecoder().decode(raw!));
  obj.data.payload.version = 99999; // flip a MAC'd field without re-MAC'ing
  await storage.write(
    "_meta",
    REVOCATION_LIST_META_KEY,
    stringToBytes(JSON.stringify(obj)),
  );
}

// ── anchor persistence ────────────────────────────────────────────────────────

describe("revocation-version anchor - persistence", () => {
  it("round-trips a valid anchor under the master", async () => {
    const storage = new MemoryStorage();
    await writeRevocationVersionAnchor(storage, master, 7);
    const read = await readRevocationVersionAnchor(storage, master);
    expect(read.status).toBe("valid");
    if (read.status === "valid") expect(read.data.version).toBe(7);
  });

  it("reads absent when never written", async () => {
    expect((await readRevocationVersionAnchor(new MemoryStorage(), master)).status).toBe(
      "absent",
    );
  });

  it("reads invalid under the WRONG master (never silently trusted)", async () => {
    const storage = new MemoryStorage();
    await writeRevocationVersionAnchor(storage, master, 4);
    expect((await readRevocationVersionAnchor(storage, wrongMaster)).status).toBe("invalid");
  });

  it("reads invalid when the stored anchor bytes are tampered", async () => {
    const storage = new MemoryStorage();
    await writeRevocationVersionAnchor(storage, master, 4);
    const raw = await storage.read("_meta", REVOCATION_VERSION_ANCHOR_META_KEY);
    const obj = JSON.parse(new TextDecoder().decode(raw!));
    obj.data.version = 999;
    await storage.write(
      "_meta",
      REVOCATION_VERSION_ANCHOR_META_KEY,
      stringToBytes(JSON.stringify(obj)),
    );
    expect((await readRevocationVersionAnchor(storage, master)).status).toBe("invalid");
  });

  it("is MONOTONIC: refuses to lower a valid anchor; accepts equal/higher", async () => {
    const storage = new MemoryStorage();
    await writeRevocationVersionAnchor(storage, master, 7);
    await expect(writeRevocationVersionAnchor(storage, master, 3)).rejects.toThrow(/lower/i);
    await writeRevocationVersionAnchor(storage, master, 7); // equal ok
    await writeRevocationVersionAnchor(storage, master, 9); // advance ok
    const read = await readRevocationVersionAnchor(storage, master);
    expect(read.status === "valid" && read.data.version).toBe(9);
  });
});

// ── effective floor = max(list, anchor) ───────────────────────────────────────

describe("effectiveRevocationVersionFloor", () => {
  it("is 0 when both list and anchor are absent", async () => {
    expect(await effectiveRevocationVersionFloor(new MemoryStorage(), master)).toBe(0);
  });

  it("is the max of a valid list version and a valid anchor version", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 5 }));
    await writeRevocationVersionAnchor(storage, master, 8);
    expect(await effectiveRevocationVersionFloor(storage, master)).toBe(8);
  });

  it("falls back to the ANCHOR (not 0) when the stored list is CORRUPT", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 5 }));
    await writeRevocationVersionAnchor(storage, master, 5);
    await corruptStoredList(storage);
    // The corrupt list reads as version 0, but the anchor holds the true floor.
    expect(await effectiveRevocationVersionFloor(storage, master)).toBe(5);
  });
});

// ── THE ROLLBACK REJECTION (the whole point) ─────────────────────────────────

describe("corrupt stored list must NOT enable an old-version rollback", () => {
  it("refuses an OLDER genuinely-signed list when the anchor holds the floor", async () => {
    const storage = new MemoryStorage();
    // Push v5 (real), and advance the anchor to 5, then a disk attacker corrupts
    // the stored list so it reads version 0.
    await writeRevocationList(storage, master, payload({ version: 5, revokedLicenseIds: ["lic-killed"] }));
    await writeRevocationVersionAnchor(storage, master, 5);
    await corruptStoredList(storage);

    // The attacker now replays an OLD, genuinely-issuer-signed v2 list (which does
    // NOT contain lic-killed - an un-revoke). WITHOUT the anchor, the floor would
    // read 0 from the corrupt list and this stale list would verify as "newer".
    const oldSigned = signRevocationList(
      payload({ version: 2, revokedLicenseIds: [] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    const floor = await effectiveRevocationVersionFloor(storage, master);
    const v = verifyPushedRevocationList(oldSigned, issuer.publicKey, floor);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("not_newer");
  });

  it("still ACCEPTS a genuinely-newer list above the anchored floor (progress not blocked)", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 5 }));
    await writeRevocationVersionAnchor(storage, master, 5);
    await corruptStoredList(storage);

    const newSigned = signRevocationList(
      payload({ version: 6, revokedLicenseIds: ["lic-killed", "lic-2"] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    const floor = await effectiveRevocationVersionFloor(storage, master);
    expect(verifyPushedRevocationList(newSigned, issuer.publicKey, floor).ok).toBe(true);
  });
});

// ── THE CHOKEPOINT: revocationVerifiability (the single enforcement signal) ────

/** Delete the stored list file outright (the delete-not-corrupt bypass). */
async function deleteStoredList(storage: MemoryStorage): Promise<void> {
  await storage.delete("_meta", REVOCATION_LIST_META_KEY);
}

describe("revocationVerifiability - single fail-closed chokepoint", () => {
  it("CLEAN when nothing was ever pushed and the list is absent (the legit never-revoked fleet)", async () => {
    const storage = new MemoryStorage();
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("clean");
    if (v.status === "clean") expect(v.floor).toBe(0);
  });

  it("CLEAN when a valid list is present at/above the floor", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 3 }));
    await writeRevocationVersionAnchor(storage, master, 3);
    await raiseRevocationFloorLatch(storage, master, 3);
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("clean");
    if (v.status === "clean") expect(v.listVersion).toBe(3);
  });

  it("THE DELETE BYPASS: an ABSENT list after a push (floor established) is UNVERIFIABLE (absent_below_floor)", async () => {
    // push v5 (list + anchor + witness latch), then DELETE only the list file.
    const storage = new MemoryStorage();
    await writeRevocationList(
      storage,
      master,
      payload({ version: 5, revokedLicenseIds: ["lic-killed"] }),
    );
    await writeRevocationVersionAnchor(storage, master, 5);
    await raiseRevocationFloorLatch(storage, master, 5);

    await deleteStoredList(storage);

    // Even with the list file gone, the anchor + witness latch prove a version-5
    // revocation existed, so the chokepoint fails closed - the delete cannot
    // un-revoke lic-killed.
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("absent_below_floor");
  });

  it("DELETE BYPASS survives deletion of the standalone ANCHOR too (witness latch remains)", async () => {
    // The round-1 anchor was itself deletable; delete BOTH the list AND the
    // standalone anchor. The custody-MAC'd witness latch (in the epoch witness, a
    // separate record) still proves the version-5 revocation existed.
    const storage = new MemoryStorage();
    await writeRevocationList(
      storage,
      master,
      payload({ version: 5, revokedLicenseIds: ["lic-killed"] }),
    );
    await writeRevocationVersionAnchor(storage, master, 5);
    await raiseRevocationFloorLatch(storage, master, 5);

    await deleteStoredList(storage);
    await storage.delete("_meta", REVOCATION_VERSION_ANCHOR_META_KEY);

    // The witness latch alone still holds the floor at 5.
    expect((await readRevocationFloorLatch(storage, master)).floor).toBe(5);
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("absent_below_floor");
  });

  it("CORRUPT list (present, MAC fail) is UNVERIFIABLE (corrupt) - regression guard from round 1", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 5 }));
    await writeRevocationVersionAnchor(storage, master, 5);
    await raiseRevocationFloorLatch(storage, master, 5);
    await corruptStoredList(storage);
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("corrupt");
  });

  it("ROLLED-BACK: a valid list below the established floor is UNVERIFIABLE (rolled_back)", async () => {
    // A genuinely-signed OLD list (v2) is written over the floor-5 state (the
    // witness latch + anchor still say 5). Its version < floor -> rolled_back.
    const storage = new MemoryStorage();
    await writeRevocationVersionAnchor(storage, master, 5);
    await raiseRevocationFloorLatch(storage, master, 5);
    // Directly persist a valid-but-old list at version 2 (writeRevocationList
    // refuses to LOWER a stored list, but there is no stored list here yet).
    await writeRevocationList(storage, master, payload({ version: 2 }));
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("rolled_back");
  });
});

// ── Transient-read grace (defect #5: don't launder an EIO into corrupt) ───────

/** A MemoryStorage that throws a controllable error on the FIRST N reads of a key. */
class FlakyStorage extends MemoryStorage {
  constructor(
    private readonly targetKey: string,
    private failCount: number,
    private readonly code: string,
  ) {
    super();
  }
  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (key === this.targetKey && this.failCount > 0) {
      this.failCount -= 1;
      const err = new Error(`injected ${this.code}`) as NodeJS.ErrnoException;
      err.code = this.code;
      throw err;
    }
    return super.read(namespace, key);
  }
}

describe("revocationVerifiability - transient-read grace", () => {
  it("a TRANSIENT IO error (EIO) is retried and does NOT drop a legit fleet (grace)", async () => {
    // Seed a valid list, then make the list-key read throw EIO on every attempt so
    // the bounded retry is exhausted -> `transient`, NOT `corrupt` (no drop).
    const base = new MemoryStorage();
    await writeRevocationList(base, master, payload({ version: 4 }));
    await writeRevocationVersionAnchor(base, master, 4);
    await raiseRevocationFloorLatch(base, master, 4);
    // Copy the seeded bytes into a flaky store that fails the list read forever.
    const flaky = new FlakyStorage(REVOCATION_LIST_META_KEY, 999, "EIO");
    for (const key of [
      REVOCATION_LIST_META_KEY,
      REVOCATION_VERSION_ANCHOR_META_KEY,
      EPOCH_WITNESS_META_KEY,
    ]) {
      const raw = await base.read("_meta", key);
      if (raw) await flaky.write("_meta", key, raw);
    }
    const v = await revocationVerifiability(flaky, master);
    // A genuine transient must NOT be laundered into an authoritative corrupt drop.
    expect(v.status).toBe("transient");
  });

  it("a transient that CLEARS within the retry budget resolves to the real verdict", async () => {
    const base = new MemoryStorage();
    await writeRevocationList(base, master, payload({ version: 4 }));
    await writeRevocationVersionAnchor(base, master, 4);
    await raiseRevocationFloorLatch(base, master, 4);
    // Fail the list read TWICE (budget is 3), then succeed -> the seeded valid list
    // is read and the verdict is clean.
    const flaky = new FlakyStorage(REVOCATION_LIST_META_KEY, 2, "EAGAIN");
    for (const key of [
      REVOCATION_LIST_META_KEY,
      REVOCATION_VERSION_ANCHOR_META_KEY,
      EPOCH_WITNESS_META_KEY,
    ]) {
      const raw = await base.read("_meta", key);
      if (raw) await flaky.write("_meta", key, raw);
    }
    const v = await revocationVerifiability(flaky, master);
    expect(v.status).toBe("clean");
  });
});

// ── Concurrent push serialization (defect #3: no interleave / lost revocation) ─

describe("persistPushedRevocationListSerialized - concurrent pushes stay monotonic", () => {
  it("two overlapping pushes (v6 + v7) do not interleave; final state is monotonic, v7 wins", async () => {
    const storage = new MemoryStorage();
    // Establish a v5 floor first.
    await writeRevocationList(storage, master, payload({ version: 5 }));
    await writeRevocationVersionAnchor(storage, master, 5);
    await raiseRevocationFloorLatch(storage, master, 5);

    const v6 = signRevocationList(
      payload({ version: 6, revokedLicenseIds: ["lic-6"] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    const v7 = signRevocationList(
      payload({ version: 7, revokedLicenseIds: ["lic-6", "lic-7"] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );

    // Fire both concurrently. The serialized path re-reads the floor INSIDE the
    // (in-process, on MemoryStorage) critical section and re-verifies monotonicity,
    // so whichever runs second cannot regress the floor; the final stored version
    // is the max (7) and v7's revocations are present.
    const results = await Promise.all([
      persistPushedRevocationListSerialized({
        storage,
        master,
        signed: v6,
        issuerPublicKey: issuer.publicKey,
      }),
      persistPushedRevocationListSerialized({
        storage,
        master,
        signed: v7,
        issuerPublicKey: issuer.publicKey,
      }),
    ]);

    // At least one push succeeds; whichever ran after the other-if-it-won may be
    // refused not_newer, but the FINAL state must be the highest version pushed.
    expect(results.some((r) => r.ok)).toBe(true);
    const list = await readRevocationList(storage, master);
    expect(list.status).toBe("valid");
    if (list.status === "valid") {
      expect(list.payload.version).toBe(7);
      expect(list.payload.revokedLicenseIds).toContain("lic-7");
    }
    // The floor (anchor + witness latch) never regressed below 7.
    expect(await effectiveRevocationVersionFloor(storage, master)).toBe(7);
    expect((await readRevocationFloorLatch(storage, master)).floor).toBe(7);
  });
});
