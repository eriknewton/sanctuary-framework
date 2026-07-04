/**
 * Fleet license issuance ledger (PR-1)  -  the ISSUER's tamper-evident,
 * append-only record of every v2 license it has signed.
 *
 * One row per issued license: the full signed v2 token (claims + signature)
 * plus mutable issuance metadata (revocation status). The license TERMS are
 * already Ed25519-signed by the issuer, so a row's terms cannot be forged
 * without the issuer key. This module makes that tamper-EVIDENT end to end:
 *
 *  1. Append-only hash chain  -  each row commits to the prior row's `rowHash`
 *     (genesis for the first). Reordering, splicing, or dropping a row breaks
 *     the chain, so the ORDER and COMPLETENESS of the log are tamper-evident.
 *     Reuses the audit-chain `sha256Hex` + canonical-JSON hashing primitive
 *     (the same shape as `computeAuditEntryHash`) rather than inventing one.
 *  2. Per-row LICENSE TOKEN signature  -  `verifyLedgerIntegrity` re-verifies
 *     each row's v2 token signature against the pinned issuer key. Because that
 *     signature covers every claim field, editing a claim (entitledCount,
 *     featureFlags, tier, ...) and repairing the (public, unkeyed) rowHash + the
 *     chain STILL fails here: the stale token signature no longer verifies. The
 *     pinned key's fingerprint must also equal the row's signed `claims.issuer`.
 *  3. Per-row revocation signature  -  the revocation status `(licenseId ||
 *     revoked || revokedAt)` is Ed25519-signed by the issuer, so a
 *     revoked→active flip (or vice versa) on disk cannot pass verification
 *     without the issuer key.
 *  4. Signed HEAD ANCHOR  -  the issuer signs `(rowCount, finalRowHash)` (see
 *     {@link LEDGER_HEAD_DOMAIN}), re-signed on every mutation. Truncating
 *     trailing rows, reordering, or substituting a shorter/rewritten chain
 *     changes the head, so the stored signature no longer verifies. This closes
 *     the "drop the newest row leaves a still-valid shorter chain" gap that a
 *     bare hash chain (no external anchor) cannot detect on its own.
 *
 * FAIL-CLOSED: `verifyLedgerIntegrity` returns `tampered` on the FIRST chain
 * break, bad token/revocation signature, or bad/absent head anchor; a ledger
 * that fails its integrity check is reported as tampered and MUST NOT be
 * silently trusted.
 *
 * SCOPE BOUND (do not exceed in this module): `revokeLicense` is LOCAL ledger
 * bookkeeping only  -  it marks the row revoked in this issuer-local record. The
 * DISTRIBUTED signed revocation list that is pushed to fleets is PR-3; the push
 * rail is NOT built here.
 *
 * The core functions below are PURE (no I/O, deterministic given `now` and the
 * injected signer) so they are exhaustively unit-testable. Load/save is a thin
 * separate layer at the bottom, and the CLI (`cli/license.ts`) wires the
 * encrypted-key issuer signer into these pure functions.
 */

import { sha256Hex, canonicalJson } from "../audit/chain.js";
import { toBase64url } from "../core/encoding.js";
import { verify, generateIdentityId } from "../core/identity.js";
import { fromBase64urlStrict } from "../core/encoding.js";
import {
  ENTITLEMENT_TOKEN_VERSION_V2,
  buildEntitlementMessageV2,
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "./token.js";

/**
 * A v2 (license) token: an {@link EntitlementToken} whose claims are narrowed
 * to {@link EntitlementClaimsV2}. Every ledger row holds one of these  -  the
 * ledger only ever records v2 licenses.
 */
export interface LicenseToken extends EntitlementToken {
  claims: EntitlementClaimsV2;
}

/** Ledger persistence schema version (independent of the token version). */
export const LEDGER_SCHEMA_VERSION = 1 as const;

/** Genesis prev-hash for the first appended row. */
export const LEDGER_GENESIS = "GENESIS";

/**
 * Domain separator for a per-row revocation-status signature. Distinct from the
 * token domain so a token signature can never be replayed as a revocation
 * signature or vice versa.
 */
export const LEDGER_REVOCATION_DOMAIN = "sanctuary.fleet.ledger.revocation.v1";

/**
 * Domain separator for the signed ledger HEAD ANCHOR (mirrors the #805 /
 * guardian anti-rollback pattern). The issuer signs a canonical head over the
 * final row hash + the row count, so truncation, row-drop, reordering, or
 * whole-ledger substitution to a shorter/rewritten chain is detected: the
 * recomputed head no longer matches the signed one. Distinct domain so a head
 * signature can never be replayed as a token or revocation signature.
 */
export const LEDGER_HEAD_DOMAIN = "sanctuary.fleet.ledger.head.v1";

/**
 * Signs a message with the issuer key. Injected (never a raw secret key passed
 * by value) so the pure core never holds key material: the CLI supplies a
 * closure over the encrypted-key `sign()` path (which zeroes the decrypted key
 * in a `finally`, NEVER #6). Returns the raw 64-byte Ed25519 signature.
 */
export type IssuerSigner = (message: Uint8Array) => Uint8Array;

/** The mutable issuance metadata tracked per row (outside the signed token). */
export interface LedgerRowMetadata {
  /** Unix seconds the license was issued/appended. */
  issuedAt: number;
  /** The issuer identity id that signed the license (== claims.issuer). */
  issuedBy: string;
  /** Whether this license has been locally revoked. */
  revoked: boolean;
  /** Unix seconds of revocation, or null if not revoked. */
  revokedAt: number | null;
  /** Free-text revocation reason, or null. */
  revokeReason: string | null;
}

/**
 * One ledger row: the full signed v2 token plus mutable metadata, the
 * hash-chain link to the prior row, and a per-row signature over the
 * revocation status.
 */
export interface LedgerRow {
  /** The full signed v2 license token (claims + signature). Immutable terms. */
  token: LicenseToken;
  /** Mutable issuance/revocation metadata. */
  metadata: LedgerRowMetadata;
  /** Hash of the prior row (LEDGER_GENESIS for the first row). */
  prevHash: string;
  /** sha256 over this row's chained content (see computeRowHash). */
  rowHash: string;
  /** base64url Ed25519 signature over the revocation status (see revStatusMessage). */
  revocationSignature: string;
}

/** The persisted ledger document. */
export interface Ledger {
  schemaVersion: typeof LEDGER_SCHEMA_VERSION;
  rows: LedgerRow[];
  /**
   * The raw issuer Ed25519 public key (base64url, 32 bytes) this ledger is
   * anchored to. Present on any ledger that has ever been mutated by an issuer.
   * It is NOT a secret (public key only, NEVER #6). It is a self-verification
   * anchor, not an unchecked root of trust: `verifyLedgerIntegrity` cross-checks
   * that its fingerprint (`generateIdentityId`) equals each row's signed
   * `claims.issuer`, so an attacker cannot swap in their own key without
   * breaking the token signature that covers `claims.issuer`.
   */
  issuerPublicKey?: string;
  /**
   * base64url Ed25519 signature over the canonical ledger head (see
   * {@link headMessage}). Present on any non-empty issuer-signed ledger; absent
   * on a fresh/empty ledger (nothing to anchor). Anchors the row count + final
   * row hash so truncation/reorder/substitution to a shorter or rewritten chain
   * is detected.
   */
  headSignature?: string;
}

/** A fresh empty ledger. */
export function emptyLedger(): Ledger {
  return { schemaVersion: LEDGER_SCHEMA_VERSION, rows: [] };
}

/**
 * The canonical byte string signed for a row's revocation status. Domain
 * separated + canonical-JSON of exactly `(licenseId, revoked, revokedAt)`.
 * Changing any of those on disk changes this message, so the stored
 * `revocationSignature` no longer verifies  -  the flip is detected.
 */
function revStatusMessage(
  licenseId: string,
  revoked: boolean,
  revokedAt: number | null,
): Uint8Array {
  const body = canonicalJson({ licenseId, revoked, revokedAt });
  return new TextEncoder().encode(`${LEDGER_REVOCATION_DOMAIN}\n${body}`);
}

/**
 * The hash-chain link for a row. Commits to the prior row's hash, the full
 * signed token, the mutable metadata, AND the revocation signature, so ANY
 * on-disk edit to a row (terms, metadata, order, or the revocation signature
 * itself) changes this hash and breaks the chain at that point. Mirrors the
 * audit-chain `computeAuditEntryHash` construction (sha256 over canonical-JSON).
 */
function computeRowHash(input: {
  prevHash: string;
  token: LicenseToken;
  metadata: LedgerRowMetadata;
  revocationSignature: string;
}): string {
  return sha256Hex(
    canonicalJson({
      schema_version: LEDGER_SCHEMA_VERSION,
      prevHash: input.prevHash,
      token: input.token,
      metadata: input.metadata,
      revocationSignature: input.revocationSignature,
    }),
  );
}

/**
 * The canonical byte string the issuer signs for the ledger HEAD ANCHOR. Domain
 * separated + canonical-JSON of exactly `(rowCount, finalRowHash)`. `finalRowHash`
 * is the last row's `rowHash`, or {@link LEDGER_GENESIS} for a zero-row head.
 * Because the row count is signed, dropping/adding rows (truncation, splicing a
 * shorter chain) changes this message and the stored `headSignature` no longer
 * verifies. Because the final row hash chains back to genesis, rewriting any row
 * also changes it.
 */
function headMessage(rowCount: number, finalRowHash: string): Uint8Array {
  const body = canonicalJson({ rowCount, finalRowHash });
  return new TextEncoder().encode(`${LEDGER_HEAD_DOMAIN}\n${body}`);
}

/** The final row's hash (chain tip), or GENESIS for an empty ledger. */
function finalRowHash(rows: readonly LedgerRow[]): string {
  return rows.length === 0 ? LEDGER_GENESIS : rows[rows.length - 1]!.rowHash;
}

/**
 * Re-sign the ledger HEAD ANCHOR over the current `(rowCount, finalRowHash)` and
 * return a NEW ledger carrying the fresh `headSignature` and the pinned
 * `issuerPublicKey`. Called after every mutation (append/revoke) so the anchor
 * always matches the current chain tip + length. PURE: does not mutate `ledger`.
 * `sign` is the injected issuer signer (the pure core never holds a raw secret
 * key); `issuerPublicKey` is the matching public key stored as the anchor.
 */
function signLedgerHead(
  ledger: Ledger,
  sign: IssuerSigner,
  issuerPublicKey: Uint8Array,
): Ledger {
  const message = headMessage(ledger.rows.length, finalRowHash(ledger.rows));
  return {
    ...ledger,
    issuerPublicKey: toBase64url(issuerPublicKey),
    headSignature: toBase64url(sign(message)),
  };
}

/** Parameters for issuing a license (the signed claim fields, issuer-supplied). */
export interface IssueLicenseParams {
  licenseId: string;
  subject: string;
  tier: EntitlementClaimsV2["tier"];
  pricingUnit: EntitlementClaimsV2["pricingUnit"];
  entitledCount: number | null;
  period: EntitlementClaimsV2["period"];
  notBefore: number;
  notAfter: number;
  graceUntil: number | null;
  featureFlags: string[];
  /** The issuer identity id (fingerprint verifiers pin)  -  also stored as claims.issuer. */
  issuer: string;
}

/**
 * Build and sign a v2 license token + its ledger row. PURE: no I/O; the caller
 * appends the returned `row` with {@link appendRow}. `sign` is the injected
 * issuer signer (the pure core never receives a raw secret key). `now` is the
 * issuance timestamp (Unix seconds), injected for deterministic tests.
 *
 * The row's revocation signature covers `(licenseId, false, null)` at issuance;
 * {@link revokeLicense} re-signs it when the status flips.
 */
export function issueLicense(
  params: IssueLicenseParams,
  sign: IssuerSigner,
  now: number,
): { token: LicenseToken; row: Omit<LedgerRow, "prevHash" | "rowHash"> } {
  const claims: EntitlementClaimsV2 = {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: params.licenseId,
    subject: params.subject,
    tier: params.tier,
    pricingUnit: params.pricingUnit,
    entitledCount: params.entitledCount,
    period: params.period,
    notBefore: params.notBefore,
    notAfter: params.notAfter,
    graceUntil: params.graceUntil,
    // buildEntitlementMessageV2 canonicalizes featureFlags (sort+dedupe) before
    // signing; persist that SAME canonical form in the token so the stored
    // claims and the signed message agree byte-for-byte.
    featureFlags: canonicalizeForToken(params.featureFlags),
    issuer: params.issuer,
  };
  const tokenMessage = buildEntitlementMessageV2(claims);
  const tokenSig = sign(tokenMessage);
  const token: LicenseToken = {
    claims,
    signature: toBase64url(tokenSig),
  };

  const metadata: LedgerRowMetadata = {
    issuedAt: now,
    issuedBy: params.issuer,
    revoked: false,
    revokedAt: null,
    revokeReason: null,
  };
  const revSig = sign(revStatusMessage(params.licenseId, false, null));
  return {
    token,
    row: {
      token,
      metadata,
      revocationSignature: toBase64url(revSig),
    },
  };
}

/** Canonicalize a feature-flag list the same way the signed message does. */
function canonicalizeForToken(flags: string[]): string[] {
  const seen = new Set<string>();
  for (const f of flags) {
    if (typeof f === "string" && f.length > 0) seen.add(f);
  }
  return Array.from(seen).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Append a freshly-issued row to the ledger, linking it into the hash chain and
 * re-signing the HEAD ANCHOR over the new `(rowCount, finalRowHash)`. PURE:
 * returns a NEW ledger (does not mutate the input). Rejects a duplicate
 * licenseId (a re-issue of the same id would make the ledger ambiguous).
 *
 * `sign` is the injected issuer signer and `issuerPublicKey` its matching public
 * key (stored as the ledger's self-verification anchor). Re-signing the head on
 * every append is what makes truncation of the newest row(s) detectable: the
 * signed row count no longer matches the on-disk count.
 */
export function appendRow(
  ledger: Ledger,
  row: Omit<LedgerRow, "prevHash" | "rowHash">,
  sign: IssuerSigner,
  issuerPublicKey: Uint8Array,
): Ledger {
  const licenseId = row.token.claims.licenseId;
  if (typeof licenseId !== "string" || licenseId.length === 0) {
    throw new Error("appendRow: row token is missing a licenseId");
  }
  if (ledger.rows.some((r) => r.token.claims.licenseId === licenseId)) {
    throw new Error(`appendRow: duplicate licenseId ${licenseId}`);
  }
  const prevHash = finalRowHash(ledger.rows);
  const full: LedgerRow = {
    token: row.token,
    metadata: row.metadata,
    prevHash,
    revocationSignature: row.revocationSignature,
    rowHash: computeRowHash({
      prevHash,
      token: row.token,
      metadata: row.metadata,
      revocationSignature: row.revocationSignature,
    }),
  };
  const appended: Ledger = { ...ledger, rows: [...ledger.rows, full] };
  return signLedgerHead(appended, sign, issuerPublicKey);
}

/** A read-only view of a ledger row for listing (no secret material exists here). */
export interface LicenseListEntry {
  licenseId: string;
  subject: string;
  tier: EntitlementClaimsV2["tier"];
  pricingUnit: EntitlementClaimsV2["pricingUnit"];
  entitledCount: number | null;
  period: EntitlementClaimsV2["period"];
  notBefore: number;
  notAfter: number;
  graceUntil: number | null;
  featureFlags: string[];
  issuedAt: number;
  revoked: boolean;
  revokedAt: number | null;
  revokeReason: string | null;
}

/** Project the ledger to a listing (read-only, no I/O, no custody). */
export function listLicenses(ledger: Ledger): LicenseListEntry[] {
  return ledger.rows.map((r) => {
    const c = r.token.claims;
    return {
      licenseId: c.licenseId,
      subject: c.subject,
      tier: c.tier,
      pricingUnit: c.pricingUnit,
      entitledCount: c.entitledCount,
      period: c.period,
      notBefore: c.notBefore,
      notAfter: c.notAfter,
      graceUntil: c.graceUntil,
      featureFlags: [...c.featureFlags],
      issuedAt: r.metadata.issuedAt,
      revoked: r.metadata.revoked,
      revokedAt: r.metadata.revokedAt,
      revokeReason: r.metadata.revokeReason,
    };
  });
}

/**
 * Mark a license revoked in the ledger. PURE: returns a NEW ledger.
 *
 * This re-signs the row's revocation status (so the flip is tamper-evident),
 * re-derives EVERY subsequent row's hash chain from the mutated row forward (the
 * chain commits to metadata, so a metadata change must re-link the tail), and
 * re-signs the HEAD ANCHOR over the new chain tip. Throws if `licenseId` is
 * unknown (fail-closed: the CLI maps this to a non-zero exit) or already revoked.
 *
 * `issuerPublicKey` is the matching public key stored as the ledger's anchor.
 *
 * SCOPE: local bookkeeping ONLY. The distributed signed revocation list pushed
 * to fleets is PR-3; this does not build that push rail.
 */
export function revokeLicense(
  ledger: Ledger,
  licenseId: string,
  now: number,
  reason: string | null,
  sign: IssuerSigner,
  issuerPublicKey: Uint8Array,
): Ledger {
  const idx = ledger.rows.findIndex(
    (r) => r.token.claims.licenseId === licenseId,
  );
  if (idx === -1) {
    throw new Error(`revokeLicense: unknown licenseId ${licenseId}`);
  }
  if (ledger.rows[idx]!.metadata.revoked) {
    throw new Error(`revokeLicense: license ${licenseId} already revoked`);
  }

  const rows = ledger.rows.slice();
  const target = rows[idx]!;
  const newMetadata: LedgerRowMetadata = {
    ...target.metadata,
    revoked: true,
    revokedAt: now,
    revokeReason: reason,
  };
  const newRevSig = toBase64url(
    sign(revStatusMessage(licenseId, true, now)),
  );

  // Re-link the chain from the mutated row forward: each row's hash commits to
  // metadata + prevHash, so a metadata edit changes this row's hash and every
  // subsequent prevHash/rowHash.
  let prevHash = idx === 0 ? LEDGER_GENESIS : rows[idx - 1]!.rowHash;
  for (let i = idx; i < rows.length; i++) {
    const r = rows[i]!;
    const metadata = i === idx ? newMetadata : r.metadata;
    const revocationSignature = i === idx ? newRevSig : r.revocationSignature;
    const rowHash = computeRowHash({
      prevHash,
      token: r.token,
      metadata,
      revocationSignature,
    });
    rows[i] = { ...r, metadata, revocationSignature, prevHash, rowHash };
    prevHash = rowHash;
  }
  return signLedgerHead({ ...ledger, rows }, sign, issuerPublicKey);
}

/** The outcome of a ledger integrity check. */
export type LedgerIntegrity =
  | { ok: true }
  | { ok: false; tampered: true; reason: string; rowIndex?: number };

/**
 * Verify the ledger is intact and untampered. FAIL-CLOSED: returns
 * `{ ok:false, tampered:true }` on the FIRST anomaly; a ledger that fails ANY
 * check is reported tampered and MUST NOT be silently trusted.
 *
 * Checks, per row in order:
 *  1. the hash chain links correctly (prevHash matches the prior rowHash, or
 *     GENESIS for row 0) and the stored rowHash equals the recomputed hash  -
 *     catches reordering, splicing, dropped rows, and any content edit;
 *  2. the LICENSE TOKEN signature verifies against `issuerPublicKey` over the
 *     v2 signing message rebuilt from the stored claims  -  catches a claim edit
 *     (e.g. raising entitledCount or adding a featureFlag) even when the attacker
 *     also repairs the rowHash + hash chain, because the token signature covers
 *     every claim field and cannot be re-forged without the issuer key. The
 *     pinned `issuerPublicKey`'s fingerprint must also equal the row's signed
 *     `claims.issuer`, so a swapped anchor key is rejected;
 *  3. the per-row revocation signature verifies against `issuerPublicKey` over
 *     `(licenseId, revoked, revokedAt)`  -  catches a revoked-bit flip on disk.
 *
 * Then, if the ledger has any rows, the signed HEAD ANCHOR is verified: the
 * issuer's `headSignature` over `(rowCount, finalRowHash)` must be present and
 * validate  -  catches truncation of trailing rows, whole-ledger substitution to
 * a shorter chain, and reorder/drop that a per-row chain alone might tolerate at
 * the tail. `issuerPublicKey` pins the single issuer this ledger was signed by.
 */
export function verifyLedgerIntegrity(
  ledger: Ledger,
  issuerPublicKey: Uint8Array,
): LedgerIntegrity {
  if (
    typeof ledger !== "object" ||
    ledger === null ||
    !Array.isArray((ledger as Ledger).rows)
  ) {
    return { ok: false, tampered: true, reason: "malformed ledger" };
  }
  // The fingerprint of the pinned key, cross-checked against each row's signed
  // `claims.issuer`. Computing it once here binds the anchor to the signed
  // claims: an attacker who swaps in their own public key gets a different
  // fingerprint, which no longer matches the `claims.issuer` the (still
  // issuer-signed) token covers  -  so either this check or the token-signature
  // check fails.
  const pinnedFingerprint = generateIdentityId(issuerPublicKey);
  let expectedPrev = LEDGER_GENESIS;
  for (let i = 0; i < ledger.rows.length; i++) {
    const r = ledger.rows[i]!;
    if (r.prevHash !== expectedPrev) {
      return {
        ok: false,
        tampered: true,
        reason: "hash-chain link broken",
        rowIndex: i,
      };
    }
    const recomputed = computeRowHash({
      prevHash: r.prevHash,
      token: r.token,
      metadata: r.metadata,
      revocationSignature: r.revocationSignature,
    });
    if (recomputed !== r.rowHash) {
      return {
        ok: false,
        tampered: true,
        reason: "row hash mismatch (content edited)",
        rowIndex: i,
      };
    }
    // The pinned key must be the issuer this row's claims name. (Defense in
    // depth: also enforced by the token-signature check below, since
    // `claims.issuer` is a signed field.)
    if (r.token.claims.issuer !== pinnedFingerprint) {
      return {
        ok: false,
        tampered: true,
        reason: "row issuer does not match pinned issuer key",
        rowIndex: i,
      };
    }
    // License TOKEN signature: rebuild the v2 signing message from the STORED
    // claims and verify it against the pinned issuer key. This is what closes
    // claim-tampering: editing entitledCount/featureFlags/tier and repairing the
    // rowHash + chain leaves the token signature (over the ORIGINAL claims)
    // stale, so it no longer verifies here.
    let tokenSig: Uint8Array;
    try {
      tokenSig = fromBase64urlStrict(r.token.signature);
    } catch {
      return {
        ok: false,
        tampered: true,
        reason: "token signature not canonical base64url",
        rowIndex: i,
      };
    }
    let tokenMessage: Uint8Array;
    try {
      tokenMessage = buildEntitlementMessageV2(r.token.claims);
    } catch {
      // Malformed claims (e.g. bad featureFlags) cannot yield a signable
      // message; treat as tampered rather than trusting the row.
      return {
        ok: false,
        tampered: true,
        reason: "token claims malformed (unsignable)",
        rowIndex: i,
      };
    }
    if (!verify(tokenMessage, tokenSig, issuerPublicKey)) {
      return {
        ok: false,
        tampered: true,
        reason: "token signature invalid (claims edited)",
        rowIndex: i,
      };
    }
    // Revocation-status signature: strict-decode then verify over the exact
    // (licenseId, revoked, revokedAt) that this row now claims.
    let revSig: Uint8Array;
    try {
      revSig = fromBase64urlStrict(r.revocationSignature);
    } catch {
      return {
        ok: false,
        tampered: true,
        reason: "revocation signature not canonical base64url",
        rowIndex: i,
      };
    }
    const message = revStatusMessage(
      r.token.claims.licenseId,
      r.metadata.revoked,
      r.metadata.revokedAt,
    );
    if (!verify(message, revSig, issuerPublicKey)) {
      return {
        ok: false,
        tampered: true,
        reason: "revocation signature invalid (status flipped?)",
        rowIndex: i,
      };
    }
    expectedPrev = r.rowHash;
  }

  // HEAD ANCHOR: a non-empty ledger MUST carry a valid signed head over its
  // current row count + chain tip. This is the anti-rollback / anti-truncation
  // guarantee: dropping trailing rows or substituting a shorter (even fully
  // self-consistent) chain changes `(rowCount, finalRowHash)`, so the stored
  // signature no longer verifies. An empty ledger has no head to anchor (the
  // well-defined genesis floor).
  if (ledger.rows.length > 0) {
    if (
      typeof ledger.headSignature !== "string" ||
      ledger.headSignature.length === 0
    ) {
      return {
        ok: false,
        tampered: true,
        reason: "missing signed head anchor (truncated or unsigned ledger)",
      };
    }
    let headSig: Uint8Array;
    try {
      headSig = fromBase64urlStrict(ledger.headSignature);
    } catch {
      return {
        ok: false,
        tampered: true,
        reason: "head signature not canonical base64url",
      };
    }
    const headMsg = headMessage(ledger.rows.length, finalRowHash(ledger.rows));
    if (!verify(headMsg, headSig, issuerPublicKey)) {
      return {
        ok: false,
        tampered: true,
        reason: "head anchor invalid (truncated/reordered/substituted chain)",
      };
    }
  }
  return { ok: true };
}
