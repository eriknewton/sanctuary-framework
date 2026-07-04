/**
 * Fleet license ledger (PR-1) — adversarial tamper-evidence tests for the
 * fix-round hardening (token-signature re-verify + signed head anchor +
 * issuer-fingerprint pin).
 *
 * The spec requires: "a ledger row must be tamper-evident" and "a ledger that
 * fails its integrity check is reported as tampered, never silently trusted."
 * Two gaps the two-family gate found in the first cut are closed here and
 * proven by these tests:
 *
 *   (A) CLAIM-EDIT-PLUS-REHASH: an attacker with write access edits a signed
 *       claim (entitledCount / featureFlags / tier) AND repairs the public,
 *       unkeyed rowHash + the whole prevHash chain. The bare chain used to
 *       return ok:true. Now the per-row LICENSE TOKEN signature (which covers
 *       every claim field) is re-verified, so the stale token signature is
 *       rejected -> tampered.
 *   (B) TRUNCATION / SUBSTITUTION TO A SHORTER CHAIN: dropping the newest
 *       row(s) leaves a still-valid shorter chain with no anchor. The bare chain
 *       used to return ok:true. Now the signed HEAD ANCHOR over
 *       (rowCount, finalRowHash) no longer verifies -> tampered.
 *
 * Every attack that fabricates or hides a paid grant must be REFUTED (verdict
 * ok:false, tampered:true). A raw-key issuer signer is used so a dropped check
 * fails loudly here.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair, generateIdentityId } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  appendRow,
  emptyLedger,
  issueLicense,
  revokeLicense,
  verifyLedgerIntegrity,
  type IssueLicenseParams,
  type IssuerSigner,
  type Ledger,
} from "../../src/entitlement/ledger.js";

const issuer = generateKeypair();
const attacker = generateKeypair();
const NOW = 1_800_000_000;
// The signed `claims.issuer` is the fingerprint of the issuer public key.
const ISSUER_ID = generateIdentityId(issuer.publicKey);

const sign: IssuerSigner = (m) => ed25519.sign(m, issuer.privateKey);
const attackerSign: IssuerSigner = (m) => ed25519.sign(m, attacker.privateKey);

function params(overrides: Partial<IssueLicenseParams> = {}): IssueLicenseParams {
  return {
    licenseId: `lic-${Math.random().toString(36).slice(2, 10)}`,
    subject: "fleet-op",
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

/** Issue n rows signed by the real issuer (generation bumped 1..n). */
function seed(n: number): { ledger: Ledger; ids: string[] } {
  let ledger = emptyLedger();
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const p = params({ licenseId: `lic-${i}` });
    const { row } = issueLicense(p, sign, NOW + i);
    ledger = appendRow(ledger, row, sign, issuer.publicKey, (ledger.generation ?? 0) + 1);
    ids.push(p.licenseId);
  }
  return { ledger, ids };
}

/**
 * Model an attacker who repairs the hash chain after a content edit: recompute
 * every prevHash + rowHash via the module's own append path so the chain is
 * internally consistent. This does NOT re-sign the tokens (the attacker has no
 * issuer key) and re-signs the head with WHOEVER `headSign` is (the real issuer
 * cannot be impersonated; the attacker can only self-sign the head).
 */
function rebuildChain(
  ledger: Ledger,
  headSign: IssuerSigner,
  headPub: Uint8Array,
): Ledger {
  let rebuilt = emptyLedger();
  for (const r of ledger.rows) {
    rebuilt = appendRow(
      rebuilt,
      {
        token: r.token,
        metadata: r.metadata,
        revocationSignature: r.revocationSignature,
      },
      headSign,
      headPub,
      (rebuilt.generation ?? 0) + 1,
    );
  }
  return rebuilt;
}

describe("ledger fix-round — (A) claim edit + rowHash/chain repaired is caught by the token signature", () => {
  it("raise entitledCount and FULLY repair the chain -> token signature invalid -> tampered", () => {
    const { ledger } = seed(2);
    const t: Ledger = structuredClone(ledger);
    // Inflate the signed entitlement and rebuild the chain so the hash check
    // would pass. The attacker cannot re-sign the token (no issuer key), so they
    // re-sign only the head with the real issuer key in this hostile model
    // (worst case: assume they somehow re-signed the head; the TOKEN sig still
    // fails). We use the real signer for the head to make the test strictly
    // about the token-signature guard.
    t.rows[0]!.token.claims.entitledCount = 9999;
    const rebuilt = rebuildChain(t, sign, issuer.publicKey);
    const verdict = verifyLedgerIntegrity(rebuilt, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.tampered).toBe(true);
      expect(verdict.reason).toMatch(/token signature/);
      expect(verdict.rowIndex).toBe(0);
    }
  });

  it("add a featureFlag and repair the chain -> token signature invalid -> tampered", () => {
    const { ledger } = seed(1);
    const t: Ledger = structuredClone(ledger);
    t.rows[0]!.token.claims.featureFlags = ["roster", "policy-dist", "console"];
    const rebuilt = rebuildChain(t, sign, issuer.publicKey);
    const verdict = verifyLedgerIntegrity(rebuilt, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/token signature/);
  });

  it("upgrade tier and repair the chain -> token signature invalid -> tampered", () => {
    const { ledger } = seed(1);
    const t: Ledger = structuredClone(ledger);
    t.rows[0]!.token.claims.tier = "enterprise";
    const rebuilt = rebuildChain(t, sign, issuer.publicKey);
    const verdict = verifyLedgerIntegrity(rebuilt, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/token signature/);
  });
});

describe("ledger fix-round — (B) truncation / substitution to a shorter chain is caught by the head anchor", () => {
  it("drop the newest row (tail truncation) -> head anchor invalid -> tampered", () => {
    const { ledger } = seed(3);
    const truncated: Ledger = structuredClone(ledger);
    // Attacker drops the newest row. The remaining chain is internally valid,
    // but the signed head is over rowCount=3; the on-disk count is now 2.
    truncated.rows.pop();
    const verdict = verifyLedgerIntegrity(truncated, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.tampered).toBe(true);
      expect(verdict.reason).toMatch(/head anchor/);
    }
  });

  it("drop several trailing rows -> head anchor invalid -> tampered", () => {
    const { ledger } = seed(4);
    const truncated: Ledger = structuredClone(ledger);
    truncated.rows.splice(2); // keep rows 0,1; drop 2,3
    const verdict = verifyLedgerIntegrity(truncated, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/head anchor/);
  });

  it("strip the head signature off a non-empty ledger -> tampered (fail-closed)", () => {
    const { ledger } = seed(2);
    const t: Ledger = structuredClone(ledger);
    delete t.headSignature;
    const verdict = verifyLedgerIntegrity(t, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/head anchor/);
  });

  it("whole-ledger substitution to a shorter attacker-built chain -> tampered", () => {
    // The attacker replaces the file with a brand-new SHORTER ledger they built
    // themselves. They cannot sign tokens or the head with the issuer key, so
    // they self-sign with their own key. Pinned to the real issuer key, the
    // token signature on their forged row fails first.
    const forged = appendRow(
      emptyLedger(),
      issueLicense(
        params({ licenseId: "attacker-1", tier: "enterprise", entitledCount: null, issuer: ISSUER_ID }),
        attackerSign,
        NOW,
      ).row,
      attackerSign,
      attacker.publicKey,
      1,
    );
    const verdict = verifyLedgerIntegrity(forged, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("attacker rebuilds a shorter chain of the REAL rows and self-signs the head -> head anchor invalid -> tampered", () => {
    // Rows are genuinely issuer-signed tokens (token sigs pass), but the chain
    // is shorter than the original and the head is signed by the attacker's key.
    const { ledger } = seed(3);
    const shorter: Ledger = structuredClone(ledger);
    shorter.rows.pop();
    // Rebuild the chain + re-sign the head with the ATTACKER key (they lack the
    // issuer key). Every real token sig still verifies, so the head anchor is
    // the guard that must fire.
    const rebuilt = rebuildChain(shorter, attackerSign, attacker.publicKey);
    const verdict = verifyLedgerIntegrity(rebuilt, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.tampered).toBe(true);
      // The attacker's head signature does not verify under the pinned issuer key.
      expect(verdict.reason).toMatch(/head anchor/);
    }
  });
});

describe("ledger fix-round — reorder still caught, and the issuer anchor is pinned", () => {
  it("reordered chain -> tampered", () => {
    const { ledger } = seed(3);
    const t: Ledger = structuredClone(ledger);
    const tmp = t.rows[1]!;
    t.rows[1] = t.rows[2]!;
    t.rows[2] = tmp;
    expect(verifyLedgerIntegrity(t, issuer.publicKey).ok).toBe(false);
  });

  it("a row whose signed claims.issuer does not match the pinned key -> tampered", () => {
    // Craft a row signed by the attacker whose claims name a DIFFERENT issuer
    // fingerprint. Verified under the real issuer key, the fingerprint cross-
    // check (and the token signature) both reject it.
    const wrongIssuerId = generateIdentityId(attacker.publicKey);
    const forged = appendRow(
      emptyLedger(),
      issueLicense(params({ licenseId: "mismatch", issuer: wrongIssuerId }), attackerSign, NOW).row,
      attackerSign,
      attacker.publicKey,
      1,
    );
    const verdict = verifyLedgerIntegrity(forged, issuer.publicKey);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.tampered).toBe(true);
  });

  it("a legitimately built ledger verifies ok, and re-signing after revoke keeps it ok", () => {
    const { ledger, ids } = seed(3);
    expect(verifyLedgerIntegrity(ledger, issuer.publicKey).ok).toBe(true);
    const revoked = revokeLicense(ledger, ids[1]!, NOW + 500, "chargeback", sign, issuer.publicKey, (ledger.generation ?? 0) + 1);
    expect(verifyLedgerIntegrity(revoked, issuer.publicKey).ok).toBe(true);
  });

  it("an empty ledger needs no head anchor and verifies ok", () => {
    expect(verifyLedgerIntegrity(emptyLedger(), issuer.publicKey).ok).toBe(true);
  });
});

describe("ledger fix-round — no issuer secret-key material leaks via the head anchor", () => {
  it("the serialized ledger (rows + head) never contains the issuer private key", () => {
    const { ledger } = seed(2);
    const blob = JSON.stringify(ledger);
    const privHex = Buffer.from(issuer.privateKey).toString("hex");
    const privB64 = Buffer.from(issuer.privateKey).toString("base64");
    const privB64url = toBase64url(issuer.privateKey);
    expect(blob).not.toContain(privHex);
    expect(blob).not.toContain(privB64);
    expect(blob).not.toContain(privB64url);
    // The stored anchor is the PUBLIC key (safe to persist).
    expect(ledger.issuerPublicKey).toBe(toBase64url(issuer.publicKey));
  });
});
