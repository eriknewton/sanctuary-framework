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
} from "../../src/entitlement/revocation-antirollback.js";

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
