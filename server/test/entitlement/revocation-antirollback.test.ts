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
  writableRevocationVersionFloor,
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
      const err = new Error(`injected ${this.code || "no-code"}`) as NodeJS.ErrnoException;
      // An empty code simulates an error with NO `code` property (unclassifiable).
      if (this.code) err.code = this.code;
      throw err;
    }
    return super.read(namespace, key);
  }
}

describe("revocationVerifiability - transient-read grace", () => {
  it("a TRANSIENT IO error (EIO) with NO established floor (floor 0) is grace (does NOT drop the legit never-revoked fleet)", async () => {
    // No revocation ever pushed (floor 0). A persistent EIO on the list read must
    // be grace -> `transient`, NOT a drop: there is nothing to un-revoke, so a
    // benign IO blip must not knock a legit never-revoked fleet off paid.
    const flaky = new FlakyStorage(REVOCATION_LIST_META_KEY, 999, "EIO");
    const v = await revocationVerifiability(flaky, master);
    expect(v.status).toBe("transient");
  });

  it("FIX 1(b): a genuine TRANSIENT (EIO) on an ESTABLISHED floor (>0) FAILS CLOSED (unverifiable, not indefinite grace)", async () => {
    // Seed a valid list at v4 (floor 4 established: list + anchor + witness latch),
    // then make the list-key read throw EIO on every attempt. Pre-fix this returned
    // `transient` (grace) and a killed license could be held paid FOREVER by making
    // the read keep throwing a transient code. Post-fix: floor > 0 + unresolved
    // transient -> `unverifiable` (transient_below_floor) -> the caller drops.
    const base = new MemoryStorage();
    await writeRevocationList(base, master, payload({ version: 4 }));
    await writeRevocationVersionAnchor(base, master, 4);
    await raiseRevocationFloorLatch(base, master, 4);
    // Copy the seeded bytes into a flaky store that fails the LIST read forever, but
    // leaves the anchor + witness readable so the floor still resolves to 4 (> 0).
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
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") {
      expect(v.reason).toBe("transient_below_floor");
      expect(v.floor).toBe(4);
    }
  });

  it("FIX 1(a): a NON-transient read throw (EACCES - a chmod-000/symlink swap) is UNVERIFIABLE (corrupt), NEVER laundered as transient", async () => {
    // The un-revoke bypass this closes: replace the list file with a symlink /
    // directory / chmod-000 file so the read throws a code NOT in TRANSIENT_IO_CODES
    // (EACCES / EPERM / EISDIR / ELOOP). Pre-fix this was mislabeled `transient`
    // (grace) and a killed license stayed paid. Post-fix: it is `unverifiable`
    // (corrupt) -> fail closed, exactly like a corrupt list. Floor 4 established.
    const base = new MemoryStorage();
    await writeRevocationList(base, master, payload({ version: 4 }));
    await writeRevocationVersionAnchor(base, master, 4);
    await raiseRevocationFloorLatch(base, master, 4);
    const flaky = new FlakyStorage(REVOCATION_LIST_META_KEY, 999, "EACCES");
    for (const key of [
      REVOCATION_LIST_META_KEY,
      REVOCATION_VERSION_ANCHOR_META_KEY,
      EPOCH_WITNESS_META_KEY,
    ]) {
      const raw = await base.read("_meta", key);
      if (raw) await flaky.write("_meta", key, raw);
    }
    const v = await revocationVerifiability(flaky, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("corrupt");
  });

  it("FIX 1(a): a NON-transient read throw with NO code (unclassifiable) is UNVERIFIABLE (corrupt), not transient", async () => {
    // An error carrying no `code` at all is unclassifiable -> must fail closed, not
    // launder as transient grace. Floor established so the drop is meaningful.
    const base = new MemoryStorage();
    await writeRevocationList(base, master, payload({ version: 4 }));
    await writeRevocationVersionAnchor(base, master, 4);
    await raiseRevocationFloorLatch(base, master, 4);
    const flaky = new FlakyStorage(REVOCATION_LIST_META_KEY, 999, "");
    for (const key of [
      REVOCATION_LIST_META_KEY,
      REVOCATION_VERSION_ANCHOR_META_KEY,
      EPOCH_WITNESS_META_KEY,
    ]) {
      const raw = await base.read("_meta", key);
      if (raw) await flaky.write("_meta", key, raw);
    }
    const v = await revocationVerifiability(flaky, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("corrupt");
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

// ── FIX 2: crash before the latch must not leave the custody floor at 0 ────────

/** A MemoryStorage that throws on the FIRST write to a given key (simulating a
 *  crash mid-push) exactly once, then behaves normally. */
class CrashOnWriteStorage extends MemoryStorage {
  constructor(
    private readonly targetKey: string,
    private crashesLeft: number,
  ) {
    super();
  }
  override async write(namespace: string, key: string, value: Uint8Array): Promise<void> {
    if (key === this.targetKey && this.crashesLeft > 0) {
      this.crashesLeft -= 1;
      throw new Error(`simulated crash writing ${key}`);
    }
    return super.write(namespace, key, value);
  }
}

describe("persistPushedRevocationListSerialized - LATCH-FIRST crash ordering (fix #2)", () => {
  it("raises the custody latch BEFORE the list, so a crash before the list keeps the floor established (>0, not 0)", async () => {
    // Crash on the FIRST list write. With LATCH-FIRST ordering, the custody floor
    // latch is already raised to the pushed version when the crash hits the list
    // write - so the durable floor is AHEAD of the (unwritten) list, NOT 0.
    const storage = new CrashOnWriteStorage(REVOCATION_LIST_META_KEY, 1);
    const v5 = signRevocationList(
      payload({ version: 5, revokedLicenseIds: ["lic-killed"] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    await expect(
      persistPushedRevocationListSerialized({
        storage,
        master,
        signed: v5,
        issuerPublicKey: issuer.publicKey,
      }),
    ).rejects.toThrow(/simulated crash/);

    // The list never got written (the crash was on its write); pre-fix (latch LAST)
    // the latch would ALSO be unwritten -> floor 0 -> a later state reads `clean` ->
    // un-revoke. Post-fix the latch was raised FIRST -> floor is 5.
    expect((await readRevocationFloorLatch(storage, master)).floor).toBe(5);
    expect(await effectiveRevocationVersionFloor(storage, master)).toBe(5);

    // Enforcement therefore FAILS CLOSED on the crash-interrupted state (list
    // absent while floor 5) - the conservative, never-un-revoke direction.
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("unverifiable");
    if (v.status === "unverifiable") expect(v.reason).toBe("absent_below_floor");
  });

  it("a RETRY of the same version after a latch-first crash COMPLETES the list write (not refused not_newer by its own latch)", async () => {
    // Crash once on the first list write (latch already raised to 5), then a retry
    // of the SAME v5 must succeed: the re-verify uses the WRITABLE floor (list ∪
    // anchor = 0 here, NOT the latch = 5), so v5 is strictly-newer-than-0 and the
    // list/anchor write completes. Pre-fix, verifying against a floor that included
    // the latch (5) would refuse v5 as not_newer and the list would never land.
    const storage = new CrashOnWriteStorage(REVOCATION_LIST_META_KEY, 1);
    const v5 = signRevocationList(
      payload({ version: 5, revokedLicenseIds: ["lic-killed"] }),
      (m) => ed25519.sign(m, issuer.privateKey),
    );
    await expect(
      persistPushedRevocationListSerialized({
        storage,
        master,
        signed: v5,
        issuerPublicKey: issuer.publicKey,
      }),
    ).rejects.toThrow(/simulated crash/);

    // Confirm the writable floor (list ∪ anchor) is still 0 (neither landed), while
    // the latch is 5 - the exact state that pre-fix bricked the retry.
    expect(await writableRevocationVersionFloor(storage, master)).toBe(0);
    expect((await readRevocationFloorLatch(storage, master)).floor).toBe(5);

    // Retry (no more crashes) - it must COMPLETE.
    const retry = await persistPushedRevocationListSerialized({
      storage,
      master,
      signed: v5,
      issuerPublicKey: issuer.publicKey,
    });
    expect(retry.ok).toBe(true);
    if (retry.ok) expect(retry.version).toBe(5);

    // Now fully consistent: list present at 5, floor 5, enforcement clean, and the
    // killed license is on the list (the revocation survived the crash+retry).
    const v = await revocationVerifiability(storage, master);
    expect(v.status).toBe("clean");
    const list = await readRevocationList(storage, master);
    expect(list.status).toBe("valid");
    if (list.status === "valid") {
      expect(list.payload.version).toBe(5);
      expect(list.payload.revokedLicenseIds).toContain("lic-killed");
    }
  });
});
