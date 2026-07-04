/**
 * Fleet license ledger (PR-1) — tamper-evident, append-only issuance record.
 *
 * DoD: issue/list round-trips, revoke marks + surfaces, and the ledger is
 * tamper-EVIDENT — any on-disk edit (a flipped revoked bit, an edited claim, a
 * reordered/spliced chain) makes `verifyLedgerIntegrity` report `tampered`,
 * and it NEVER silently trusts a broken chain. The pure core is exercised with
 * a real Ed25519 issuer key so a dropped signature check fails here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair, generateIdentityId } from "../../src/core/identity.js";
import { resolveEntitlement } from "../../src/entitlement/index.js";
import {
  appendRow,
  emptyLedger,
  issueLicense,
  listLicenses,
  revokeLicense,
  verifyLedgerIntegrity,
  type IssueLicenseParams,
  type IssuerSigner,
  type Ledger,
} from "../../src/entitlement/ledger.js";

const issuer = generateKeypair();
const wrongIssuer = generateKeypair();
const NOW = 1_800_000_000;
// The signed `claims.issuer` MUST be the fingerprint of the issuer public key:
// verifyLedgerIntegrity cross-checks it against the pinned key, and every row's
// token signature covers it. A fake string here would (correctly) read as tampered.
const ISSUER_ID = generateIdentityId(issuer.publicKey);

/** A raw-key issuer signer (the CLI supplies an encrypted-key one). */
const sign: IssuerSigner = (message) => ed25519.sign(message, issuer.privateKey);

function params(overrides: Partial<IssueLicenseParams> = {}): IssueLicenseParams {
  return {
    licenseId: `lic-${Math.random().toString(36).slice(2, 10)}`,
    subject: "fleet-op-1",
    tier: "fleet",
    pricingUnit: "node",
    entitledCount: 10,
    period: "monthly",
    notBefore: NOW,
    notAfter: NOW + 30 * 86_400,
    graceUntil: NOW + 44 * 86_400,
    featureFlags: ["roster", "policy-dist"],
    issuer: ISSUER_ID,
    ...overrides,
  };
}

/** Issue N licenses into a fresh ledger; return {ledger, ids}. */
function seed(n: number): { ledger: Ledger; ids: string[] } {
  let ledger = emptyLedger();
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const p = params({ licenseId: `lic-${i}` });
    const { row } = issueLicense(p, sign, NOW + i);
    ledger = appendRow(ledger, row, sign, issuer.publicKey);
    ids.push(p.licenseId);
  }
  return { ledger, ids };
}

describe("ledger — issue/list round-trip", () => {
  it("issues a signed license whose token independently resolves granted", () => {
    const { token } = issueLicense(params({ licenseId: "lic-x" }), sign, NOW);
    const result = resolveEntitlement({
      token,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.tier).toBe("fleet");
    expect(result.licenseId).toBe("lic-x");
    expect(result.entitledCount).toBe(10);
  });

  it("lists every issued license with its fields", () => {
    const { ledger, ids } = seed(3);
    const entries = listLicenses(ledger);
    expect(entries.map((e) => e.licenseId)).toEqual(ids);
    expect(entries[0]!.revoked).toBe(false);
    expect(entries[0]!.entitledCount).toBe(10);
    expect(entries[0]!.featureFlags).toEqual(["policy-dist", "roster"]);
  });

  it("a fresh ledger verifies as intact", () => {
    const { ledger } = seed(3);
    expect(verifyLedgerIntegrity(ledger, issuer.publicKey).ok).toBe(true);
  });

  it("rejects a duplicate licenseId on append", () => {
    let ledger = emptyLedger();
    const { row } = issueLicense(params({ licenseId: "dup" }), sign, NOW);
    ledger = appendRow(ledger, row, sign, issuer.publicKey);
    const { row: row2 } = issueLicense(params({ licenseId: "dup" }), sign, NOW + 1);
    expect(() => appendRow(ledger, row2, sign, issuer.publicKey)).toThrow(/duplicate/);
  });
});

describe("ledger — revoke", () => {
  it("marks the row revoked, surfaces in list, and stays intact", () => {
    const { ledger, ids } = seed(3);
    const revoked = revokeLicense(ledger, ids[1]!, NOW + 500, "chargeback", sign, issuer.publicKey);
    const entries = listLicenses(revoked);
    expect(entries[1]!.revoked).toBe(true);
    expect(entries[1]!.revokedAt).toBe(NOW + 500);
    expect(entries[1]!.revokeReason).toBe("chargeback");
    // The other rows are untouched.
    expect(entries[0]!.revoked).toBe(false);
    expect(entries[2]!.revoked).toBe(false);
    // The chain is re-linked and still verifies.
    expect(verifyLedgerIntegrity(revoked, issuer.publicKey).ok).toBe(true);
  });

  it("fails closed on an unknown licenseId", () => {
    const { ledger } = seed(2);
    expect(() => revokeLicense(ledger, "nope", NOW, null, sign, issuer.publicKey)).toThrow(/unknown/);
  });

  it("refuses to double-revoke", () => {
    const { ledger, ids } = seed(2);
    const once = revokeLicense(ledger, ids[0]!, NOW, null, sign, issuer.publicKey);
    expect(() => revokeLicense(once, ids[0]!, NOW + 1, null, sign, issuer.publicKey)).toThrow(/already revoked/);
  });

  it("does not mutate the input ledger (pure)", () => {
    const { ledger, ids } = seed(2);
    revokeLicense(ledger, ids[0]!, NOW, null, sign, issuer.publicKey);
    expect(listLicenses(ledger)[0]!.revoked).toBe(false);
  });
});

describe("ledger — tamper-evidence (fail-closed)", () => {
  it("detects a flipped revoked bit on disk (revocation status un-does without a valid re-sign)", () => {
    const { ledger, ids } = seed(2);
    const revoked = revokeLicense(ledger, ids[0]!, NOW + 10, "x", sign, issuer.publicKey);
    // Simulate a disk edit: flip revoked back to false WITHOUT re-signing. The
    // row-hash check catches the metadata edit; even if an attacker also fixed
    // the rowHash to match, the per-row revocation signature — which is signed
    // over (licenseId, revoked, revokedAt) — would no longer verify. Either way
    // the flip is detected and reported as tampered (fail-closed).
    const tampered: Ledger = structuredClone(revoked);
    tampered.rows[0]!.metadata.revoked = false;
    tampered.rows[0]!.metadata.revokedAt = null;
    const verdict = verifyLedgerIntegrity(tampered, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("detects a revocation-signature swapped for a matching-hash but wrong-status one", () => {
    // Directly exercise the revocation-signature guard in isolation. Sign a
    // "revoked=true" status for row 0's licenseId with the real key, then craft
    // a row whose metadata says revoked=FALSE but carries that revoked=true
    // signature, and re-derive a rowHash that matches the false metadata. The
    // hash-chain check passes (hash matches the false metadata) but the
    // revocation signature — made over revoked=true — cannot validate the
    // revoked=false status: the module reports tampered. We recompute the
    // rowHash by re-appending the edited row via the same code path.
    const { ledger, ids } = seed(1);
    // A signature asserting the OPPOSITE status than the metadata will carry.
    const oppositeStatusSig = revokeLicense(ledger, ids[0]!, NOW + 10, null, sign, issuer.publicKey)
      .rows[0]!.revocationSignature;
    // Rebuild a clean single-row ledger, then swap only the revocation signature
    // for the opposite-status one and repair the rowHash to match by re-running
    // append on a reconstructed row.
    const clean = structuredClone(ledger);
    const row0 = clean.rows[0]!;
    const rebuilt = appendRow(
      emptyLedger(),
      {
        token: row0.token,
        metadata: row0.metadata, // revoked=false
        revocationSignature: oppositeStatusSig, // says revoked=true
      },
      sign,
      issuer.publicKey,
    );
    const verdict = verifyLedgerIntegrity(rebuilt, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.tampered).toBe(true);
      expect(verdict.reason).toContain("revocation signature");
    }
  });

  it("detects an edited claim on disk (row hash mismatch)", () => {
    const { ledger } = seed(2);
    const tampered: Ledger = structuredClone(ledger);
    // Raise entitledCount on disk without re-hashing/re-signing.
    tampered.rows[0]!.token.claims.entitledCount = 9999;
    const verdict = verifyLedgerIntegrity(tampered, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.tampered).toBe(true);
      expect(verdict.rowIndex).toBe(0);
    }
  });

  it("detects a reordered (spliced) chain", () => {
    const { ledger } = seed(3);
    const spliced: Ledger = structuredClone(ledger);
    // Swap rows 1 and 2 — prevHash links no longer match.
    const tmp = spliced.rows[1]!;
    spliced.rows[1] = spliced.rows[2]!;
    spliced.rows[2] = tmp;
    const verdict = verifyLedgerIntegrity(spliced, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("detects a dropped row (chain break)", () => {
    const { ledger } = seed(3);
    const dropped: Ledger = structuredClone(ledger);
    dropped.rows.splice(1, 1); // remove the middle row
    const verdict = verifyLedgerIntegrity(dropped, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("detects an appended forged row (revocation signature from wrong key)", () => {
    const { ledger } = seed(1);
    const forgedSign: IssuerSigner = (m) => ed25519.sign(m, wrongIssuer.privateKey);
    const { row } = issueLicense(params({ licenseId: "forged" }), forgedSign, NOW);
    const withForged = appendRow(ledger, row, sign, issuer.publicKey);
    // The genuine issuer key is pinned; the forged row's token + revocation
    // signatures were made with the WRONG key and will not verify against it.
    const verdict = verifyLedgerIntegrity(withForged, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("reports tampered on a malformed ledger object", () => {
    const verdict = verifyLedgerIntegrity({} as unknown as Ledger, issuer.publicKey);
    expect(verdict.ok).toBe(false);
  });

  it("an empty ledger is intact", () => {
    expect(verifyLedgerIntegrity(emptyLedger(), issuer.publicKey).ok).toBe(true);
  });
});

describe("ledger — no key material ever appears in a row", () => {
  it("a serialized ledger never contains the issuer private key", () => {
    const { ledger } = seed(2);
    const serialized = JSON.stringify(ledger);
    const privHex = Buffer.from(issuer.privateKey).toString("hex");
    const privB64 = Buffer.from(issuer.privateKey).toString("base64");
    expect(serialized).not.toContain(privHex);
    expect(serialized).not.toContain(privB64);
  });
});
