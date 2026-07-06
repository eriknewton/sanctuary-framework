/**
 * Fleet control plane PR-3: the SIGNED, DISTRIBUTED REVOCATION LIST tests.
 *
 * Definition-of-Done:
 *  1. signRevocationList + verifyPushedRevocationList round-trip under the pinned
 *     issuer key; a list signed by the WRONG key is rejected (bad_signature).
 *  2. REPLAY/ROLLBACK: a list whose version is not STRICTLY greater than the
 *     stored/current version is rejected (not_newer) BEFORE the signature check,
 *     so even a genuinely-signed OLD list cannot un-revoke a license.
 *  3. TAMPER: editing the ids / version / issuer after signing flips the
 *     signature to bad_signature.
 *  4. Persistence: writeRevocationList is master-MAC'd + monotonic (refuses a
 *     lower version); readRevocationList is tri-state (valid/absent/invalid);
 *     a wrong-master read is invalid, never silently trusted.
 *  5. isLicenseRevoked: revoked id -> revoked; absent list -> not revoked;
 *     CORRUPT list -> not revoked + listReadable:false (never a DoS strip).
 *
 * A real Ed25519 issuer key signs the fixtures so a dropped verify fails here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import {
  REVOCATION_LIST_META_KEY,
  buildRevocationListMessage,
  signRevocationList,
  verifyPushedRevocationList,
  readRevocationList,
  writeRevocationList,
  isLicenseRevoked,
  type RevocationListPayload,
  type SignedRevocationList,
} from "../../src/entitlement/revocation-list.js";

const issuer = generateKeypair();
const wrongIssuer = generateKeypair();
const master = randomBytes(32);
const wrongMaster = randomBytes(32);

/** A signer that Ed25519-signs a raw message with the issuer private key. */
function issuerSigner(privateKey: Uint8Array = issuer.privateKey) {
  return (message: Uint8Array): Uint8Array => ed25519.sign(message, privateKey);
}

function payload(overrides: Partial<RevocationListPayload> = {}): RevocationListPayload {
  return {
    version: 1,
    revokedLicenseIds: ["lic-a", "lic-b"],
    issuer: "issuer-fingerprint",
    issuedAt: "2026-07-06T00:00:00.000Z",
    ...overrides,
  };
}

// ── sign + verify round-trip ─────────────────────────────────────────────────

describe("signRevocationList + verifyPushedRevocationList", () => {
  it("round-trips under the pinned issuer key", () => {
    const signed = signRevocationList(payload(), issuerSigner());
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 0);
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.payload.version).toBe(1);
      expect(v.payload.revokedLicenseIds).toEqual(["lic-a", "lic-b"]);
    }
  });

  it("canonicalizes the id set: order + dupes do not change the signature", () => {
    const a = signRevocationList(
      payload({ revokedLicenseIds: ["lic-b", "lic-a", "lic-a"] }),
      issuerSigner(),
    );
    const b = signRevocationList(
      payload({ revokedLicenseIds: ["lic-a", "lic-b"] }),
      issuerSigner(),
    );
    expect(a.signature).toBe(b.signature);
    expect(a.payload.revokedLicenseIds).toEqual(["lic-a", "lic-b"]);
  });

  it("REJECTS a list signed by the WRONG issuer key (bad_signature)", () => {
    const signed = signRevocationList(payload(), issuerSigner(wrongIssuer.privateKey));
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 0);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("bad_signature");
  });

  it("verifies against the PINNED key, not a payload-claimed key", () => {
    // The payload names one issuer fingerprint but is signed by `issuer`; verify
    // against `issuer.publicKey` (pinned) passes, against wrongIssuer fails.
    const signed = signRevocationList(payload({ issuer: "claims-anything" }), issuerSigner());
    expect(verifyPushedRevocationList(signed, issuer.publicKey, 0).ok).toBe(true);
    expect(verifyPushedRevocationList(signed, wrongIssuer.publicKey, 0).ok).toBe(false);
  });
});

// ── replay / rollback (monotonic version) ────────────────────────────────────

describe("verifyPushedRevocationList - monotonic version guard", () => {
  it("REJECTS a version equal to the current (not_newer)", () => {
    const signed = signRevocationList(payload({ version: 5 }), issuerSigner());
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 5);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("not_newer");
  });

  it("REJECTS a version below the current, even if genuinely signed (replay)", () => {
    const signed = signRevocationList(payload({ version: 2 }), issuerSigner());
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 9);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("not_newer");
  });

  it("ACCEPTS a strictly-greater version", () => {
    const signed = signRevocationList(payload({ version: 10 }), issuerSigner());
    expect(verifyPushedRevocationList(signed, issuer.publicKey, 9).ok).toBe(true);
  });

  it("checks monotonicity BEFORE the signature (an old wrong-key list is not_newer)", () => {
    const signed = signRevocationList(
      payload({ version: 1 }),
      issuerSigner(wrongIssuer.privateKey),
    );
    const v = verifyPushedRevocationList(signed, issuer.publicKey, 5);
    expect(v.ok).toBe(false);
    // not_newer wins because monotonicity is checked first (defense in depth:
    // we never even reach the sig check on a stale version).
    if (!v.ok) expect(v.reason).toBe("not_newer");
  });
});

// ── tamper ───────────────────────────────────────────────────────────────────

describe("verifyPushedRevocationList - tamper rejection", () => {
  function tamper(
    signed: SignedRevocationList,
    mutate: (p: RevocationListPayload) => RevocationListPayload,
  ): SignedRevocationList {
    return { payload: mutate(signed.payload), signature: signed.signature };
  }

  it("rejects an added revoked id (bad_signature)", () => {
    const signed = signRevocationList(payload({ version: 3 }), issuerSigner());
    const t = tamper(signed, (p) => ({
      ...p,
      revokedLicenseIds: [...p.revokedLicenseIds, "lic-injected"],
    }));
    const v = verifyPushedRevocationList(t, issuer.publicKey, 0);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("bad_signature");
  });

  it("rejects a removed revoked id (bad_signature)", () => {
    const signed = signRevocationList(payload({ version: 3 }), issuerSigner());
    const t = tamper(signed, (p) => ({ ...p, revokedLicenseIds: ["lic-a"] }));
    expect(verifyPushedRevocationList(t, issuer.publicKey, 0).ok).toBe(false);
  });

  it("rejects a bumped version without re-signing (bad_signature)", () => {
    const signed = signRevocationList(payload({ version: 3 }), issuerSigner());
    const t = tamper(signed, (p) => ({ ...p, version: 99 }));
    const v = verifyPushedRevocationList(t, issuer.publicKey, 0);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("bad_signature");
  });

  it("rejects a re-attributed issuer (bad_signature)", () => {
    const signed = signRevocationList(payload({ version: 3 }), issuerSigner());
    const t = tamper(signed, (p) => ({ ...p, issuer: "someone-else" }));
    expect(verifyPushedRevocationList(t, issuer.publicKey, 0).ok).toBe(false);
  });

  it("rejects a malformed envelope (malformed)", () => {
    expect(verifyPushedRevocationList(null, issuer.publicKey, 0).ok).toBe(false);
    expect(verifyPushedRevocationList({}, issuer.publicKey, 0).ok).toBe(false);
    expect(
      verifyPushedRevocationList({ payload: {}, signature: 1 }, issuer.publicKey, 0).ok,
    ).toBe(false);
    const bad = verifyPushedRevocationList(
      { payload: { version: "x", revokedLicenseIds: [], issuer: "i", issuedAt: "t" }, signature: "s" },
      issuer.publicKey,
      0,
    );
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toBe("malformed");
  });

  it("rejects a non-string id in the set (malformed)", () => {
    const bad = verifyPushedRevocationList(
      {
        payload: { version: 1, revokedLicenseIds: ["ok", 42], issuer: "i", issuedAt: "t" },
        signature: "s",
      },
      issuer.publicKey,
      0,
    );
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toBe("malformed");
  });
});

// ── persistence (master-MAC'd, monotonic, tri-state) ──────────────────────────

describe("writeRevocationList + readRevocationList - persistence", () => {
  it("round-trips a valid record under the master", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 4 }));
    const read = await readRevocationList(storage, master);
    expect(read.status).toBe("valid");
    if (read.status === "valid") {
      expect(read.payload.version).toBe(4);
      expect(read.payload.revokedLicenseIds).toEqual(["lic-a", "lic-b"]);
    }
  });

  it("reads absent when no record was ever written", async () => {
    const storage = new MemoryStorage();
    expect((await readRevocationList(storage, master)).status).toBe("absent");
  });

  it("reads invalid under the WRONG master (never silently trusted)", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 4 }));
    expect((await readRevocationList(storage, wrongMaster)).status).toBe("invalid");
  });

  it("reads invalid when the stored bytes are tampered", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 4 }));
    // Flip the persisted version without re-MAC'ing.
    const raw = await storage.read("_meta", REVOCATION_LIST_META_KEY);
    const obj = JSON.parse(new TextDecoder().decode(raw!));
    obj.data.payload.version = 999;
    await storage.write(
      "_meta",
      REVOCATION_LIST_META_KEY,
      stringToBytes(JSON.stringify(obj)),
    );
    expect((await readRevocationList(storage, master)).status).toBe("invalid");
  });

  it("is MONOTONIC: refuses to lower the stored version", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 7 }));
    await expect(
      writeRevocationList(storage, master, payload({ version: 3 })),
    ).rejects.toThrow(/lower/i);
    // The stored version is unchanged.
    const read = await readRevocationList(storage, master);
    expect(read.status === "valid" && read.payload.version).toBe(7);
  });

  it("accepts an equal or higher version write (idempotent re-stamp / advance)", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 7 }));
    await writeRevocationList(storage, master, payload({ version: 7 })); // equal ok
    await writeRevocationList(storage, master, payload({ version: 8 })); // advance ok
    const read = await readRevocationList(storage, master);
    expect(read.status === "valid" && read.payload.version).toBe(8);
  });
});

// ── isLicenseRevoked ──────────────────────────────────────────────────────────

describe("isLicenseRevoked - fail-closed lookup", () => {
  it("reports revoked for an id on a valid list", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(
      storage,
      master,
      payload({ version: 1, revokedLicenseIds: ["lic-killed"] }),
    );
    const status = await isLicenseRevoked(storage, master, "lic-killed");
    expect(status).toEqual({ revoked: true, listReadable: true, version: 1 });
  });

  it("reports NOT revoked for an id absent from the list", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(
      storage,
      master,
      payload({ version: 1, revokedLicenseIds: ["lic-killed"] }),
    );
    const status = await isLicenseRevoked(storage, master, "lic-fine");
    expect(status.revoked).toBe(false);
    expect(status.listReadable).toBe(true);
  });

  it("reports NOT revoked when no list exists (nothing revoked yet)", async () => {
    const storage = new MemoryStorage();
    const status = await isLicenseRevoked(storage, master, "lic-any");
    expect(status).toEqual({ revoked: false, listReadable: true, version: 0 });
  });

  it("a CORRUPT list reports NOT revoked + listReadable:false (never a DoS strip)", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(storage, master, payload({ version: 1 }));
    // Read under the WRONG master: the list is invalid/unreadable.
    const status = await isLicenseRevoked(storage, wrongMaster, "lic-a");
    expect(status.revoked).toBe(false);
    expect(status.listReadable).toBe(false);
  });

  it("a null / empty license id is never revoked", async () => {
    const storage = new MemoryStorage();
    await writeRevocationList(
      storage,
      master,
      payload({ version: 1, revokedLicenseIds: ["lic-a"] }),
    );
    expect((await isLicenseRevoked(storage, master, null)).revoked).toBe(false);
    expect((await isLicenseRevoked(storage, master, "")).revoked).toBe(false);
  });
});

// ── buildRevocationListMessage sanity ─────────────────────────────────────────

describe("buildRevocationListMessage", () => {
  it("throws on a malformed id set (a malformed set must never be signed)", () => {
    expect(() =>
      buildRevocationListMessage({
        version: 1,
        // @ts-expect-error deliberately malformed
        revokedLicenseIds: "not-an-array",
        issuer: "i",
        issuedAt: "t",
      }),
    ).toThrow();
  });

  it("produces a stable, base64url-verifiable signature end to end", () => {
    const signed = signRevocationList(payload({ version: 2 }), issuerSigner());
    // The signature is base64url and verifies against the exact built message.
    const msg = buildRevocationListMessage(signed.payload);
    const ok = ed25519.verify(
      Buffer.from(signed.signature.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
      msg,
      issuer.publicKey,
    );
    expect(ok).toBe(true);
    expect(toBase64url(new Uint8Array([1, 2, 3]))).toBeTypeOf("string");
  });
});
