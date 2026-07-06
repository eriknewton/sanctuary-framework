/**
 * Fleet control plane PR-3: the SIGNED, DISTRIBUTED license REVOCATION LIST.
 *
 * The issuer (Erik) can compromise/refund/kill a specific license AFTER it has
 * been activated on a fleet. `ledger.revokeLicense` (PR-1) only flips the row in
 * the issuer-LOCAL ledger; it does not reach an operator's already-activated
 * fortress. This module is the rail that DOES: a small, Ed25519-signed list of
 * revoked `licenseId`s that the issuer pushes to a fortress, which the fortress
 * verifies and then consults on every license re-resolve so a revoked license
 * fails CLOSED to Community.
 *
 * ── SHAPE (mirrors the shipped #789 policy-push rail + #859 token signing) ──────
 * The list is a versioned payload signed with the SAME operator-signed message
 * construction the rest of the admin surface uses (domain separator +
 * length-prefixed canonical JSON), under a DEDICATED action domain so a
 * revocation-list signature can never be replayed as any other operator-signed
 * request and vice versa. The list is:
 *   - VERIFIED against the PINNED issuer public key (the fortress's own operator
 *     identity, exactly the key `resolveActivation` pins). We NEVER trust a key
 *     the pushed list claims for itself.
 *   - REPLAY/ROLLBACK-protected by a MONOTONIC `version` (mirror the proven
 *     `ledger-antirollback` generation anchor): a push whose version is not
 *     STRICTLY greater than the stored version is refused, so an attacker cannot
 *     replay an OLD (shorter) list to un-revoke a license.
 *   - TAMPER-rejected: any edit to the ids/version/issuer flips the signature.
 *
 * ── FAIL-CLOSED DIRECTION (coordinator-adjudicated 2026-07-06) ──────────────
 * This module can only ever ADD a license to the revoked set (drop it to
 * Community); it can never grant a paid tier. The subtle rule is the ABSENT vs.
 * CORRUPT distinction:
 *   - ABSENT list (never pushed): nothing has been revoked -> every license is
 *     fine. Failing closed here would brick every normal fleet, so absent is
 *     treated as "not revoked" ({@link isLicenseRevoked} returns
 *     `revoked:false, listReadable:true`).
 *   - PRESENT-but-INVALID list (corrupt bytes / failed master-MAC / unparseable):
 *     revocation state is INDETERMINATE. A stored list that WAS pushed but no
 *     longer authenticates cannot be relied on to say a revoked license is still
 *     paid. This module's {@link isLicenseRevoked} still returns
 *     `revoked:false, listReadable:false` (it does not, by itself, know WHICH
 *     license was revoked), but the `listReadable:false` signal is a HARD
 *     fail-closed trigger the ENFORCEMENT callers MUST honor: a paid grant is
 *     dropped toward Community with a loud, specific "revocation state
 *     unverifiable" banner + downgrade-log entry until a fresh signed list is
 *     re-pushed. The earlier DoS counter-argument is void: corrupting the record
 *     already strips paid capacity via the activation MAC, so failing closed on a
 *     corrupt revocation list grants the attacker no new capability, while
 *     failing open would hand a disk attacker a targeted un-revoke primitive.
 * The revocation SET only ever grows on an AUTHENTICATED push, and the version is
 * externally anchored ({@link readRevocationVersionAnchor}) so a corrupt file
 * cannot roll the monotonic floor back to 0 and let an old signed list re-apply.
 *
 * Persistence is the SAME master-MAC'd `_meta` discipline as
 * {@link FLEET_ACTIVATION_META_KEY}: `derivePurposeKey` -> `hmacSha256`, marker +
 * base64url MAC, tri-state valid/absent/invalid read. No new cryptography.
 */

import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { canonicalJson } from "../audit/chain.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "../core/encoding.js";
import { verify } from "../core/identity.js";
import { buildOperatorSignedMessage } from "../v1/operator-signed.js";

/**
 * The dedicated action domain the revocation-list signature is bound to. FROZEN:
 * this is a signing-crypto label; changing it invalidates every already-signed
 * revocation list. Distinct from every other operator-signed action so a
 * revocation-list signature can never be replayed as another request.
 */
export const REVOCATION_LIST_SIGN_ACTION = "sanctuary.fleet.revocation-list.v1";

/** `_meta` key holding the master-MAC'd, verified revocation-list record. */
export const REVOCATION_LIST_META_KEY = "fleet-revocation-list-v1";

const REVOCATION_LIST_MARKER = "__sanctuary_fleet_revocation_list_v1";
/** Fresh MAC domain for the stored record (distinct from every other MAC domain). */
const REVOCATION_LIST_MAC_DOMAIN = "sanctuary.fleet.revocation-list.record.v1\n";
/** HKDF purpose label for the record MAC key (distinct from all others). */
const REVOCATION_LIST_MAC_PURPOSE = "fleet-revocation-list-mac";

/**
 * The SIGNED payload the issuer pushes. `revokedLicenseIds` is the full,
 * absolute set of revoked license ids at this version (NOT a delta): a list is a
 * complete snapshot, so applying a newer list simply REPLACES the older set. The
 * `issuer` fingerprint is bound into the signature so a list cannot be re-attributed.
 */
export interface RevocationListPayload {
  /**
   * Monotonic list version. STRICTLY increases on every issuer push. The stored
   * record refuses a push whose version is not greater than the current, which
   * defeats replay of an older (shorter) list.
   */
  version: number;
  /**
   * The COMPLETE set of revoked license ids at this version. Order-independent
   * (canonicalized before signing). Duplicates are collapsed.
   */
  revokedLicenseIds: string[];
  /** The issuer identity fingerprint this list is attributed to (bound into the sig). */
  issuer: string;
  /** ISO-8601 issuance time (advisory provenance for the operator log). */
  issuedAt: string;
}

/** A signed revocation list: the payload plus a base64url Ed25519 signature. */
export interface SignedRevocationList {
  payload: RevocationListPayload;
  /** base64url Ed25519 signature over {@link buildRevocationListMessage}. */
  signature: string;
}

/**
 * Canonicalize the revoked-id set: reject a non-array or any non-string /
 * empty-string element (a malformed set must never be signed or trusted), then
 * sort + dedupe so two logically-equal sets produce byte-identical signed
 * messages. Returns null on a malformed set. This is the SINGLE place the id set
 * is ordered, so the sign side and the verify side always agree byte-for-byte.
 */
function canonicalizeRevokedIds(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0) return null;
    seen.add(item);
  }
  return Array.from(seen).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * PUBLIC canonicalizer for a revoked-id set: the SAME sort+dedupe the sign and
 * verify sides use. A caller (the CLI `revoke-push`) that assembles the id set
 * from raw, operator-supplied, argv-ORDER ids MUST canonicalize them INTO the
 * payload BEFORE signing - otherwise the signed bytes are over the raw order while
 * {@link verifyPushedRevocationList} recomputes the message over the CANONICAL
 * order, producing a spurious `bad_signature` on any unsorted or duplicated set.
 * Returns null on a malformed set (non-array / non-string / empty-string element)
 * so the caller can reject it up front rather than sign a set that can never verify.
 */
export function canonicalizeRevocationListIds(value: unknown): string[] | null {
  return canonicalizeRevokedIds(value);
}

/**
 * Build the byte string the issuer signs for a revocation-list payload. Reuses
 * the shipped {@link buildOperatorSignedMessage} envelope (domain +
 * length-prefixed action + length-prefixed canonical JSON) under the dedicated
 * {@link REVOCATION_LIST_SIGN_ACTION}, with `revokedLicenseIds` canonicalized
 * FIRST so ordering/dupes cannot change the signed bytes. Throws if the id set is
 * malformed (a malformed set must never be signed).
 */
export function buildRevocationListMessage(payload: RevocationListPayload): Uint8Array {
  const canonicalIds = canonicalizeRevokedIds(payload.revokedLicenseIds);
  if (canonicalIds === null) {
    throw new TypeError("buildRevocationListMessage: malformed revokedLicenseIds");
  }
  const normalized: RevocationListPayload = {
    ...payload,
    revokedLicenseIds: canonicalIds,
  };
  return buildOperatorSignedMessage(REVOCATION_LIST_SIGN_ACTION, normalized);
}

/** An injected Ed25519 signer over a raw message (mirror {@link IssuerSigner}). */
export type RevocationListSigner = (message: Uint8Array) => Uint8Array;

/**
 * Sign a revocation-list payload with the injected issuer signer. PURE (no I/O).
 * `revokedLicenseIds` are canonicalized so the stored payload and the signed
 * message agree byte-for-byte.
 */
export function signRevocationList(
  payload: RevocationListPayload,
  sign: RevocationListSigner,
): SignedRevocationList {
  const canonicalIds = canonicalizeRevokedIds(payload.revokedLicenseIds);
  if (canonicalIds === null) {
    throw new TypeError("signRevocationList: malformed revokedLicenseIds");
  }
  const normalized: RevocationListPayload = {
    ...payload,
    revokedLicenseIds: canonicalIds,
  };
  const message = buildRevocationListMessage(normalized);
  return { payload: normalized, signature: toBase64url(sign(message)) };
}

/** Why a revocation-list verification failed (operator-facing; never a secret). */
export type RevocationListVerifyReason =
  | "malformed" // shape is not a signed revocation list
  | "bad_signature" // signature does not verify against the pinned issuer key
  | "not_newer"; // version is not strictly greater than the stored version (replay/rollback)

/** The result of verifying a pushed signed revocation list. */
export type RevocationListVerification =
  | { ok: true; payload: RevocationListPayload }
  | { ok: false; reason: RevocationListVerifyReason };

/**
 * Verify a PUSHED signed revocation list, FAIL-CLOSED. Checks, in order:
 *   1. structural shape (a payload with a numeric version, a string-array id set,
 *      a string issuer, and a base64url signature);
 *   2. MONOTONICITY: `payload.version` MUST be strictly greater than
 *      `currentVersion` (the version already stored, or 0 when none). This is the
 *      replay/rollback guard: an old list cannot un-revoke a license.
 *   3. SIGNATURE against the PINNED issuer public key (never the payload's
 *      self-claimed key). Any tamper to the ids/version/issuer flips this.
 *
 * NEVER throws. On any failure returns `{ ok: false, reason }` and the caller
 * persists NOTHING (the currently-stored list stands).
 */
export function verifyPushedRevocationList(
  signed: unknown,
  issuerPublicKey: Uint8Array,
  currentVersion: number,
): RevocationListVerification {
  if (typeof signed !== "object" || signed === null) {
    return { ok: false, reason: "malformed" };
  }
  const s = signed as Record<string, unknown>;
  const payload = s.payload;
  const signature = s.signature;
  if (
    typeof payload !== "object" ||
    payload === null ||
    typeof signature !== "string"
  ) {
    return { ok: false, reason: "malformed" };
  }
  const p = payload as Record<string, unknown>;
  const version = p.version;
  const issuer = p.issuer;
  const issuedAt = p.issuedAt;
  const canonicalIds = canonicalizeRevokedIds(p.revokedLicenseIds);
  if (
    typeof version !== "number" ||
    !Number.isSafeInteger(version) ||
    version < 0 ||
    typeof issuer !== "string" ||
    issuer.length === 0 ||
    typeof issuedAt !== "string" ||
    canonicalIds === null
  ) {
    return { ok: false, reason: "malformed" };
  }

  // MONOTONICITY (replay/rollback guard) BEFORE the signature check: even a
  // genuinely issuer-signed OLD list must be refused if it is not strictly newer.
  const baseline =
    Number.isSafeInteger(currentVersion) && currentVersion >= 0 ? currentVersion : 0;
  if (version <= baseline) {
    return { ok: false, reason: "not_newer" };
  }

  const normalized: RevocationListPayload = {
    version,
    revokedLicenseIds: canonicalIds,
    issuer,
    issuedAt,
  };
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64url(signature);
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  // Verify against the PINNED key. A list that claims a different issuer than the
  // fortress pins simply fails the signature (the pinned key did not sign it).
  if (!verify(buildRevocationListMessage(normalized), sigBytes, issuerPublicKey)) {
    return { ok: false, reason: "bad_signature" };
  }
  return { ok: true, payload: normalized };
}

// ── Persistence: master-MAC'd `_meta` record (mirror activation.ts) ───────────

/** The MAC'd payload of the stored record: the verified list payload only. */
interface StoredRevocationListData {
  payload: RevocationListPayload;
}

function revocationListMac(
  master: Uint8Array,
  data: StoredRevocationListData,
): Uint8Array {
  const macKey = derivePurposeKey(master, REVOCATION_LIST_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(REVOCATION_LIST_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return mac;
}

/**
 * Read + authenticate the stored revocation list. Tri-state, mirror of
 * {@link readFleetActivation}:
 *  - "valid": authenticates under the master -> a trustworthy revoked set.
 *  - "absent": no record -> nothing has ever been revoked on this fortress
 *    (the empty set; every license is un-revoked). Reads as version 0.
 *  - "invalid": present but tampered / malformed / wrong-key / unreadable ->
 *    SUSPECT. The caller surfaces the corruption loudly but does NOT brick a paid
 *    fleet (see the module note): a corrupt LOCAL list is not evidence a specific
 *    license was revoked.
 */
export async function readRevocationList(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<
  | { status: "valid"; payload: RevocationListPayload }
  | { status: "absent" }
  | { status: "invalid" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", REVOCATION_LIST_META_KEY);
  } catch {
    return { status: "invalid" };
  }
  if (!raw) return { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { status: "invalid" };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[REVOCATION_LIST_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as { payload?: unknown } | undefined;
  const mac = obj.mac;
  if (!data || typeof data !== "object" || typeof mac !== "string") {
    return { status: "invalid" };
  }
  const p = data.payload;
  if (typeof p !== "object" || p === null) {
    return { status: "invalid" };
  }
  const pr = p as Record<string, unknown>;
  const canonicalIds = canonicalizeRevokedIds(pr.revokedLicenseIds);
  if (
    typeof pr.version !== "number" ||
    !Number.isSafeInteger(pr.version) ||
    pr.version < 0 ||
    typeof pr.issuer !== "string" ||
    typeof pr.issuedAt !== "string" ||
    canonicalIds === null
  ) {
    return { status: "invalid" };
  }
  // Reconstruct the EXACT payload that was MAC'd (canonicalized ids, same field
  // set) so a shape mismatch fails the MAC rather than being silently trusted.
  const fullPayload: RevocationListPayload = {
    version: pr.version,
    revokedLicenseIds: canonicalIds,
    issuer: pr.issuer,
    issuedAt: pr.issuedAt,
  };
  const fullData: StoredRevocationListData = { payload: fullPayload };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (!constantTimeEqual(provided, revocationListMac(master, fullData))) {
    return { status: "invalid" };
  }
  return { status: "valid", payload: fullPayload };
}

/**
 * Persist a VERIFIED revocation-list payload as a master-MAC'd record. The caller
 * MUST have already verified the pushed list (see {@link verifyPushedRevocationList})
 * against the pinned issuer key AND confirmed monotonicity. This only writes the
 * authenticated payload. MONOTONIC: refuses to LOWER the stored version (a lower
 * version is a rollback-laundering write), mirror of the ledger-generation anchor.
 */
export async function writeRevocationList(
  storage: StorageBackend,
  master: Uint8Array,
  payload: RevocationListPayload,
): Promise<void> {
  const canonicalIds = canonicalizeRevokedIds(payload.revokedLicenseIds);
  if (
    canonicalIds === null ||
    !Number.isSafeInteger(payload.version) ||
    payload.version < 0
  ) {
    throw new Error("writeRevocationList: refusing to persist a malformed payload");
  }
  const current = await readRevocationList(storage, master);
  if (current.status === "valid" && payload.version < current.payload.version) {
    throw new Error(
      "Sanctuary: refusing to lower the fleet revocation-list version " +
        `(${current.payload.version} -> ${payload.version}); a lower version is a ` +
        "rollback-laundering write.",
    );
  }
  const fullPayload: RevocationListPayload = {
    version: payload.version,
    revokedLicenseIds: canonicalIds,
    issuer: payload.issuer,
    issuedAt: payload.issuedAt,
  };
  const data: StoredRevocationListData = { payload: fullPayload };
  const record = {
    [REVOCATION_LIST_MARKER]: true,
    data,
    mac: toBase64url(revocationListMac(master, data)),
  };
  await storage.write(
    "_meta",
    REVOCATION_LIST_META_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}

/**
 * The revocation status of a license against the stored list. `revoked` is true
 * ONLY when an AUTHENTICATED list contains the id. `listReadable` is:
 *   - true for an ABSENT list (nothing revoked yet) or a VALID list;
 *   - false ONLY for a PRESENT-but-INVALID (corrupt / tamper-failed) list.
 * `listReadable:false` is the ENFORCEMENT fail-closed trigger: a caller resolving a
 * paid grant against a corrupt list must NOT keep the paid tier on the basis of an
 * unverifiable list; it drops toward Community and surfaces the corruption loudly.
 * (Distinguish from absent, which is `listReadable:true` and keeps the grant.)
 * `version` is the authenticated list version (0 when absent/invalid).
 */
export interface RevocationStatus {
  revoked: boolean;
  listReadable: boolean;
  version: number;
}

/**
 * Consult the stored revocation list for a license id, FAIL-CLOSED and never
 * throwing.
 *
 *  - absent list -> `{ revoked: false, listReadable: true, version: 0 }` (nothing
 *    revoked yet).
 *  - valid list containing the id -> `{ revoked: true, ... }` (the license is
 *    revoked; the caller drops it to Community).
 *  - valid list NOT containing the id -> `{ revoked: false, ... }`.
 *  - INVALID (tampered/unreadable) list -> `{ revoked: false, listReadable: false,
 *    version: 0 }`. This function does not itself know WHICH license the corrupt
 *    list revoked, so it does not assert `revoked: true`; instead it flags
 *    `listReadable: false`, which the enforcement callers treat as a HARD
 *    fail-closed trigger (drop a paid grant toward Community with a loud banner
 *    until a fresh signed list is re-pushed). See the module note on the
 *    absent-vs-corrupt distinction.
 */
export async function isLicenseRevoked(
  storage: StorageBackend,
  master: Uint8Array,
  licenseId: string | null | undefined,
): Promise<RevocationStatus> {
  const record = await readRevocationList(storage, master);
  if (record.status === "absent") {
    return { revoked: false, listReadable: true, version: 0 };
  }
  if (record.status === "invalid") {
    return { revoked: false, listReadable: false, version: 0 };
  }
  const revoked =
    typeof licenseId === "string" &&
    licenseId.length > 0 &&
    record.payload.revokedLicenseIds.includes(licenseId);
  return { revoked, listReadable: true, version: record.payload.version };
}
