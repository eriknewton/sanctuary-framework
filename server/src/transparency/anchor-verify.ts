/**
 * sanctuary verify-transparency --check-anchors: auditor-side verification
 * of external anchors (PR-3 of the verifiable-transparency design).
 *
 * PR-2 published salted commitments to checkpoints in a public Sigstore
 * Rekor log. This module closes the loop on the VERIFIER side: given an
 * operator-exported anchors file (the salt, the derived anchoring public
 * key, and the local anchor receipts; never anything from the wire), it
 * checks for each anchored checkpoint that:
 *
 *   1. COMMITMENT BINDING: the receipt's commitment digest recomputes from
 *      the salt + counter + the hash of the checkpoint actually in the
 *      bundle, so an anchor cannot be re-pointed at a different history.
 *   2. ENTRY BINDING: the Rekor entry body (receipt-embedded, or freshly
 *      fetched by the caller) is a hashedrekord over exactly that digest,
 *      signed by the fortress's anchoring key (P-256, verified), and the
 *      entry UUID's leaf hash recomputes from the body bytes (RFC 6962).
 *   3. INCLUSION: the proof's leaf index equals the entry's signed log
 *      index and lies inside the claimed tree (RFC 6962 trees allow
 *      duplicate leaves, so a proof for a DIFFERENT index with the same
 *      leaf must not satisfy an entry signed for this index), the Merkle
 *      inclusion proof recomputes from the leaf to the proof's root, and
 *      the embedded signed checkpoint note agrees with that root and tree
 *      size.
 *   4. LOG SIGNATURES (only with a pinned Rekor log key, obtained
 *      out-of-band): the signed entry timestamp and the checkpoint note
 *      signature verify under the log key, and the entry's logID matches
 *      that key. Without the pinned key these checks are honestly listed
 *      under not_checked; they are never silently skipped as passed, and
 *      an anchor that passes everything else is reported "consistent",
 *      never "verified": every remaining input (salt, anchoring key, entry
 *      body, proof, root, note, timestamp) is operator-supplied and could
 *      have been fabricated together.
 *
 * Plus anchor-coverage reporting (which checkpoints are anchored, which
 * are not, stated plainly) and the --expect-fresh staleness policy.
 *
 * STANDALONE PROPERTY (mirrors verify.ts): this module imports only
 * @noble/curves, @noble/hashes, Node builtins, and verify.ts (itself
 * standalone), so it ships inside the offline verifier artifact. Format
 * constants are duplicated from anchor.ts for the same reason verify.ts
 * duplicates checkpoint.ts constants; the integration tests run real
 * receipts produced by anchoring.ts through this verifier so the
 * duplication cannot drift silently.
 *
 * HONESTY DISCIPLINE: a check that cannot run (missing body, missing
 * proof, no log key) leaves the anchor in the "unverified" coverage state
 * with a stated reason. A check that runs and fails is a FINDING. An
 * anchor whose checks all pass WITHOUT a pinned log key is "consistent",
 * not "verified". There is no state in which missing evidence or
 * operator-supplied-only evidence reads as verified.
 */

import { Buffer } from "node:buffer";

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

import {
  checkpointPayloadHash,
  type TransparencyFinding,
  type VerifierCheckpointRecord,
} from "./verify.js";

// ---- Format constants (duplicated from anchor.ts for standalone use) --------

export const TRANSPARENCY_ANCHORS_EXPORT_FORMAT =
  "SANCTUARY_TRANSPARENCY_ANCHORS_V1";
const ANCHOR_SCHEMA_VERSION = 1;
const ANCHOR_COMMITMENT_DOMAIN = "sanctuary.transparency.anchor-commitment.v1";
/** SPKI DER prefix for an uncompressed P-256 public point (65 bytes). */
const SPKI_P256_PREFIX_HEX =
  "3059301306072a8648ce3d020106082a8648ce3d030107034200";
/** Signed-note signature-line prefix (EM DASH, space) per the note format. */
const NOTE_SIG_PREFIX = "\u2014 ";

const HEX64 = /^[0-9a-f]{64}$/;

// ---- Exported anchors-file shapes (structural mirrors of anchor.ts) ---------

export interface ExportedRekorEntry {
  uuid: string;
  log_index: number;
  log_id: string;
  integrated_time: number;
  body_b64?: string;
  verification?: Record<string, unknown>;
}

export interface ExportedAnchorReceiptBase {
  anchor_kind: "transparency-anchor-receipt";
  schema_version: number;
  counter: number;
  checkpoint_hash: string;
  commitment_digest: string;
  rekor_url: string;
}

export interface ExportedAnchoredReceipt extends ExportedAnchorReceiptBase {
  status: "anchored";
  anchored_at: string;
  rekor: ExportedRekorEntry;
}

export interface ExportedFailedAnchorReceipt extends ExportedAnchorReceiptBase {
  status: "failed";
  failed_at: string;
  error: string;
}

export type ExportedAnchorReceipt =
  | ExportedAnchoredReceipt
  | ExportedFailedAnchorReceipt;

/**
 * The operator-exported anchors evidence file. Everything in it comes from
 * the operator's LOCAL receipt store and config (PR-2 invariant: the salt
 * and receipt material never travel over the wire to the log; they travel
 * only when the operator deliberately hands this file to an auditor).
 * Handing the file out links the pseudonymous public anchors to this
 * fortress's checkpoint history for whoever holds it; that is its purpose.
 */
export interface TransparencyAnchorsExport {
  format: typeof TRANSPARENCY_ANCHORS_EXPORT_FORMAT;
  exported_at: string;
  fortress_id: string;
  /** 64-hex per-fortress commitment salt (local secret until exported). */
  salt: string;
  /** SPKI PEM of the derived anchoring public key (the log pseudonym). */
  anchor_public_key_pem: string;
  rekor_url: string;
  receipts: ExportedAnchorReceipt[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isExportedRekorEntry(value: unknown): value is ExportedRekorEntry {
  if (!isObject(value)) return false;
  return (
    typeof value.uuid === "string" &&
    typeof value.log_index === "number" &&
    Number.isSafeInteger(value.log_index) &&
    value.log_index >= 0 &&
    typeof value.log_id === "string" &&
    typeof value.integrated_time === "number" &&
    Number.isSafeInteger(value.integrated_time) &&
    (value.body_b64 === undefined || typeof value.body_b64 === "string") &&
    (value.verification === undefined || isObject(value.verification))
  );
}

export function isExportedAnchorReceipt(
  value: unknown
): value is ExportedAnchorReceipt {
  if (!isObject(value)) return false;
  if (
    value.anchor_kind !== "transparency-anchor-receipt" ||
    value.schema_version !== ANCHOR_SCHEMA_VERSION ||
    typeof value.counter !== "number" ||
    !Number.isSafeInteger(value.counter) ||
    value.counter <= 0 ||
    typeof value.checkpoint_hash !== "string" ||
    !HEX64.test(value.checkpoint_hash) ||
    typeof value.commitment_digest !== "string" ||
    !HEX64.test(value.commitment_digest) ||
    typeof value.rekor_url !== "string"
  ) {
    return false;
  }
  if (value.status === "anchored") {
    return (
      typeof value.anchored_at === "string" && isExportedRekorEntry(value.rekor)
    );
  }
  if (value.status === "failed") {
    return typeof value.failed_at === "string" && typeof value.error === "string";
  }
  return false;
}

export function isTransparencyAnchorsExport(
  value: unknown
): value is TransparencyAnchorsExport {
  return (
    isObject(value) &&
    value.format === TRANSPARENCY_ANCHORS_EXPORT_FORMAT &&
    typeof value.exported_at === "string" &&
    typeof value.fortress_id === "string" &&
    typeof value.salt === "string" &&
    HEX64.test(value.salt) &&
    typeof value.anchor_public_key_pem === "string" &&
    value.anchor_public_key_pem.includes("BEGIN PUBLIC KEY") &&
    typeof value.rekor_url === "string" &&
    Array.isArray(value.receipts) &&
    value.receipts.every((receipt) => isExportedAnchorReceipt(receipt))
  );
}

// ---- Small crypto / encoding helpers (no server imports) ---------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function b64ToBytes(b64: string): Uint8Array {
  const bytes = Buffer.from(b64, "base64");
  // Buffer.from silently tolerates garbage; round-trip to refuse it.
  if (Buffer.from(bytes).toString("base64").replace(/=+$/, "") !==
      b64.replace(/\s+/g, "").replace(/=+$/, "")) {
    throw new Error("invalid base64");
  }
  return new Uint8Array(bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Minimal canonical JSON (sorted keys), mirroring audit/chain.ts. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

/**
 * Parse an SPKI PEM carrying an uncompressed P-256 point. Returns the DER
 * bytes (for logID computation) and the 65-byte point (for verification).
 */
export function parseSpkiP256Pem(pem: string): {
  der: Uint8Array;
  point: Uint8Array;
} {
  const body = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = b64ToBytes(body);
  const prefix = hexToBytes(SPKI_P256_PREFIX_HEX);
  if (der.length !== prefix.length + 65) {
    throw new Error(
      `public key is not an uncompressed P-256 SPKI (${der.length} DER bytes)`
    );
  }
  for (let i = 0; i < prefix.length; i++) {
    if (der[i] !== prefix[i]) {
      throw new Error("public key is not an uncompressed P-256 SPKI");
    }
  }
  const point = der.slice(prefix.length);
  if (point[0] !== 0x04) {
    throw new Error("public key point is not in uncompressed form");
  }
  return { der, point };
}

function verifyP256Der(
  signatureDer: Uint8Array,
  messageHash: Uint8Array,
  publicPoint: Uint8Array
): boolean {
  try {
    const signature = p256.Signature.fromDER(signatureDer);
    return p256.verify(signature.toCompactRawBytes(), messageHash, publicPoint, {
      lowS: false,
    });
  } catch {
    return false;
  }
}

// ---- RFC 6962 Merkle math -----------------------------------------------------

export function rfc6962LeafHash(body: Uint8Array): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x00]), body));
}

function rfc6962NodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

/**
 * Recompute the tree root from a leaf hash and an inclusion proof, per
 * RFC 9162 section 2.1.3.2. Returns null when the proof shape is
 * impossible for the claimed index/size (too short, too long, index out of
 * range): an impossible proof is a failed check, never a pass.
 */
export function rootFromInclusionProof(input: {
  leafHash: Uint8Array;
  leafIndex: number;
  treeSize: number;
  proofHashes: Uint8Array[];
}): Uint8Array | null {
  const { leafHash, leafIndex, treeSize, proofHashes } = input;
  if (
    !Number.isSafeInteger(leafIndex) ||
    !Number.isSafeInteger(treeSize) ||
    leafIndex < 0 ||
    treeSize <= 0 ||
    leafIndex >= treeSize
  ) {
    return null;
  }
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;
  for (const hash of proofHashes) {
    if (sn === 0) return null; // proof longer than the path
    if (fn % 2 === 1 || fn === sn) {
      r = rfc6962NodeHash(hash, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = rfc6962NodeHash(r, hash);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) return null; // proof shorter than the path
  return r;
}

// ---- Signed checkpoint note (the log's signed tree head) ----------------------

interface ParsedSignedNote {
  origin: string;
  treeSize: number;
  rootHash: Uint8Array;
  /** The exact bytes the note signatures cover. */
  signedBytes: Uint8Array;
  /** Raw signature blobs (4-byte key hint + DER signature). */
  signatureBlobs: Uint8Array[];
}

/**
 * Parse a signed note ("<origin>\n<size>\n<root b64>\n[ext...]\n\n<sig
 * lines>"). The 4-byte key hint inside each signature blob is NOT used for
 * selection (its derivation is signer-specific); every signature is tried
 * against the pinned key instead, which is strictly stronger.
 */
export function parseSignedNote(note: string): ParsedSignedNote | null {
  const separator = note.indexOf("\n\n");
  if (separator < 0) return null;
  const text = note.slice(0, separator + 1); // includes trailing newline
  const lines = text.split("\n");
  if (lines.length < 4) return null; // origin, size, root, "" (from trailing \n)
  const origin = lines[0]!;
  const treeSize = Number(lines[1]!);
  if (!Number.isSafeInteger(treeSize) || treeSize <= 0 || origin.length === 0) {
    return null;
  }
  let rootHash: Uint8Array;
  try {
    rootHash = b64ToBytes(lines[2]!);
  } catch {
    return null;
  }
  if (rootHash.length !== 32) return null;
  const signatureBlobs: Uint8Array[] = [];
  for (const line of note.slice(separator + 2).split("\n")) {
    if (!line.startsWith(NOTE_SIG_PREFIX)) continue;
    const parts = line.slice(NOTE_SIG_PREFIX.length).split(" ");
    const blobB64 = parts.at(-1);
    if (!blobB64) continue;
    try {
      const blob = b64ToBytes(blobB64);
      if (blob.length > 4) signatureBlobs.push(blob);
    } catch {
      // a malformed signature line is simply not a usable signature
    }
  }
  return {
    origin,
    treeSize,
    rootHash,
    signedBytes: new TextEncoder().encode(text),
    signatureBlobs,
  };
}

// ---- Anchor evidence verification ---------------------------------------------

/** Entry material fetched live from the log by the caller (--fetch-anchors). */
export interface FetchedAnchorEntry {
  uuid: string;
  log_index: number;
  log_id: string;
  integrated_time: number;
  body_b64?: string;
  verification?: Record<string, unknown>;
}

export interface AnchorVerifyOptions {
  /**
   * SPKI PEM of the Rekor log's public key, obtained OUT-OF-BAND (for the
   * public-good instance: GET /api/v1/log/publicKey, pinned by the
   * auditor). Without it, log-signature checks are listed under
   * not_checked and freshness cannot be asserted.
   */
  rekorPublicKeyPem?: string;
  /** --expect-fresh window in milliseconds. */
  expectFreshMs?: number;
  now?: () => Date;
  /** Live-fetched entries keyed by checkpoint counter (--fetch-anchors). */
  fetchedEntries?: Map<number, FetchedAnchorEntry>;
}

export type AnchorCounterState =
  /** Every check passed INCLUDING log signatures under a pinned log key. */
  | "verified"
  /**
   * Every runnable check passed, but no log key was pinned: only
   * commitment and entry-shape arithmetic was checked, against
   * operator-supplied data that could have been fabricated together.
   * Internal consistency, not log-attested verification.
   */
  | "consistent"
  | "unverified"
  | "invalid"
  | "anchor_failed"
  | "unanchored";

export interface AnchorCounterStatus {
  counter: number;
  status: AnchorCounterState;
  detail: string;
  integrated_time: number | null;
}

export interface AnchorCoverage {
  checkpoints: number;
  verified: number;
  /** Anchors whose runnable checks passed without a pinned log key. */
  consistent: number;
  unverified: number;
  invalid: number;
  anchor_failed: number;
  unanchored: number;
  statuses: AnchorCounterStatus[];
  newest_verified_integrated_time: number | null;
  /**
   * "pinned-rekor-key": signed entry timestamps and note signatures were
   * verified under a caller-pinned log key; anchors can reach "verified".
   * "none": only commitment binding, entry binding, and Merkle arithmetic
   * against receipt-embedded roots were checked, all of which an operator
   * could fabricate together; anchors top out at "consistent", never
   * "verified". Stated, never silently upgraded.
   */
  log_signature_basis: "pinned-rekor-key" | "none";
}

export interface AnchorVerifyResult {
  findings: TransparencyFinding[];
  not_checked: string[];
  coverage: AnchorCoverage;
}

function emptyCoverage(
  basis: "pinned-rekor-key" | "none"
): AnchorCoverage {
  return {
    checkpoints: 0,
    verified: 0,
    consistent: 0,
    unverified: 0,
    invalid: 0,
    anchor_failed: 0,
    unanchored: 0,
    statuses: [],
    newest_verified_integrated_time: null,
    log_signature_basis: basis,
  };
}

/** Parse an --expect-fresh window ("36h", "90m", "7d", "3600s", or seconds). */
export function parseFreshnessWindow(text: string): number {
  const match = /^(\d+)(s|m|h|d)?$/.exec(text.trim());
  if (!match) {
    throw new Error(
      `invalid --expect-fresh window "${text}" (use e.g. 36h, 90m, 7d, or seconds)`
    );
  }
  const value = Number(match[1]!);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`--expect-fresh window must be a positive integer: ${text}`);
  }
  const unit = match[2] ?? "s";
  const multiplier =
    unit === "d" ? 86_400_000 : unit === "h" ? 3_600_000 : unit === "m" ? 60_000 : 1000;
  return value * multiplier;
}

/**
 * Verify operator-exported anchor evidence against an already
 * chain-verified set of checkpoint records. Pure: no I/O; live-fetched
 * entry material arrives via opts.fetchedEntries.
 */
export function verifyAnchorEvidence(
  records: VerifierCheckpointRecord[],
  anchorsDoc: unknown,
  opts: AnchorVerifyOptions = {}
): AnchorVerifyResult {
  const findings: TransparencyFinding[] = [];
  const notChecked: string[] = [];

  // Pinned log key (optional, out-of-band).
  let rekorPoint: Uint8Array | null = null;
  let rekorLogIdHex: string | null = null;
  if (opts.rekorPublicKeyPem) {
    try {
      const parsed = parseSpkiP256Pem(opts.rekorPublicKeyPem);
      rekorPoint = parsed.point;
      rekorLogIdHex = bytesToHex(sha256(parsed.der));
    } catch (err) {
      findings.push({
        kind: "anchors_input_invalid",
        message: `the supplied Rekor log public key could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
      });
      return { findings, not_checked: notChecked, coverage: emptyCoverage("none") };
    }
  }
  const basis: "pinned-rekor-key" | "none" = rekorPoint
    ? "pinned-rekor-key"
    : "none";

  if (!isTransparencyAnchorsExport(anchorsDoc)) {
    findings.push({
      kind: "anchors_input_invalid",
      message:
        "the anchors input is not a SANCTUARY_TRANSPARENCY_ANCHORS_V1 export (export one on the fortress host with: sanctuary transparency anchor export)",
    });
    return { findings, not_checked: notChecked, coverage: emptyCoverage(basis) };
  }

  let anchorPoint: Uint8Array;
  try {
    anchorPoint = parseSpkiP256Pem(anchorsDoc.anchor_public_key_pem).point;
  } catch (err) {
    findings.push({
      kind: "anchors_input_invalid",
      message: `the anchors export's anchoring public key could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
    });
    return { findings, not_checked: notChecked, coverage: emptyCoverage(basis) };
  }

  const sorted = [...records].sort((a, b) => a.counter - b.counter);
  const fortressId = sorted[0]?.fortress_id;
  if (fortressId !== undefined && anchorsDoc.fortress_id !== fortressId) {
    findings.push({
      kind: "anchors_fortress_mismatch",
      expected: fortressId,
      actual: anchorsDoc.fortress_id,
      message: `the anchors export belongs to fortress "${anchorsDoc.fortress_id}", not "${fortressId}"; it is not evidence about this bundle`,
    });
  }

  // Receipts by counter; a duplicate counter in a hand-edited file is
  // malformed evidence, not something to silently pick from.
  const receiptsByCounter = new Map<number, ExportedAnchorReceipt>();
  for (const receipt of anchorsDoc.receipts) {
    if (receiptsByCounter.has(receipt.counter)) {
      findings.push({
        kind: "anchors_input_invalid",
        counter: receipt.counter,
        message: `the anchors export carries two receipts for checkpoint counter ${receipt.counter}; receipts are keyed by counter and must be unique`,
      });
      continue;
    }
    receiptsByCounter.set(receipt.counter, receipt);
  }

  const statuses: AnchorCounterStatus[] = [];
  let newestVerifiedTime: number | null = null;
  for (const record of sorted) {
    const receipt = receiptsByCounter.get(record.counter);
    if (!receipt) {
      statuses.push({
        counter: record.counter,
        status: "unanchored",
        detail: "no anchor receipt for this checkpoint",
        integrated_time: null,
      });
      continue;
    }
    if (receipt.status === "failed") {
      statuses.push({
        counter: record.counter,
        status: "anchor_failed",
        detail: `anchor attempt failed at ${receipt.failed_at}: ${receipt.error}`,
        integrated_time: null,
      });
      continue;
    }
    const status = checkAnchoredReceipt({
      record,
      receipt,
      salt: anchorsDoc.salt,
      anchorPoint,
      rekorPoint,
      rekorLogIdHex,
      fetched: opts.fetchedEntries?.get(record.counter) ?? null,
      findings,
      notChecked,
    });
    statuses.push(status);
    if (status.status === "verified" && status.integrated_time !== null) {
      newestVerifiedTime = Math.max(
        newestVerifiedTime ?? status.integrated_time,
        status.integrated_time
      );
    }
  }

  // Receipts for counters NOT in the bundle. An anchored receipt above the
  // bundle's top counter is direct evidence of a withheld suffix: the
  // operator anchored a checkpoint they are not presenting.
  const topCounter = sorted.at(-1)?.counter ?? 0;
  const bottomCounter = sorted[0]?.counter ?? 0;
  for (const receipt of receiptsByCounter.values()) {
    if (sorted.some((record) => record.counter === receipt.counter)) continue;
    if (receipt.status === "anchored" && receipt.counter > topCounter) {
      findings.push({
        kind: "anchor_beyond_bundle",
        counter: receipt.counter,
        expected: topCounter,
        actual: receipt.counter,
        message: `the anchors export proves checkpoint ${receipt.counter} was anchored, but the bundle ends at counter ${topCounter}: the newest checkpoints are being withheld from this bundle`,
      });
    } else if (receipt.counter < bottomCounter) {
      notChecked.push(
        `anchor receipt for checkpoint ${receipt.counter}: below the bundle's earliest counter ${bottomCounter}; not checkable against this (partial) bundle`
      );
    } else {
      notChecked.push(
        `anchor receipt for checkpoint ${receipt.counter}: no matching checkpoint in the bundle (the chain verifier reports the gap itself)`
      );
    }
  }

  if (basis === "none") {
    notChecked.push(
      "Rekor log signatures: no log public key was pinned (--rekor-public-key-file). Inclusion proofs were recomputed only against receipt-embedded roots, which the receipt author could fabricate together with the proofs, so anchors are reported as CONSISTENT (internal consistency of the operator-supplied evidence), never as verified. Pin the log key, obtained out-of-band from the log operator, for log-attested verification."
    );
  }
  notChecked.push(
    "anchor completeness: this file shows the receipts the operator chose to export. Anchors published under the same anchoring public key but omitted here are invisible offline; enumerate the pseudonym's entries on the public log independently to bound that"
  );

  // --expect-fresh: staleness policy over LOG-ATTESTED time only. Receipt
  // timestamps without a pinned log key are operator-controlled, and a
  // freshness pass built on them would be theater.
  if (opts.expectFreshMs !== undefined) {
    if (basis === "none") {
      findings.push({
        kind: "anchor_freshness_unverifiable",
        message:
          "--expect-fresh requires a pinned Rekor log public key: without it the integration timestamps are unverified operator-supplied values and freshness cannot be asserted",
      });
    } else if (newestVerifiedTime === null) {
      findings.push({
        kind: "anchor_freshness_unverifiable",
        message:
          "--expect-fresh was requested but no anchor verified end-to-end under the pinned log key; there is no log-attested timestamp to bound staleness with",
      });
    } else {
      const nowMs = (opts.now?.() ?? new Date()).getTime();
      const ageMs = nowMs - newestVerifiedTime * 1000;
      if (ageMs > opts.expectFreshMs) {
        findings.push({
          kind: "anchor_freshness_stale",
          expected: `newest verified anchor within ${Math.round(opts.expectFreshMs / 60000)} minutes`,
          actual: `${Math.round(ageMs / 60000)} minutes old`,
          message: `STALE EVIDENCE: the newest log-attested anchor is ${Math.round(ageMs / 3_600_000)} hour(s) old, outside the required freshness window; the operator is presenting an old view of the enforcement history`,
        });
      }
    }
  }

  const coverage: AnchorCoverage = {
    checkpoints: sorted.length,
    verified: statuses.filter((s) => s.status === "verified").length,
    consistent: statuses.filter((s) => s.status === "consistent").length,
    unverified: statuses.filter((s) => s.status === "unverified").length,
    invalid: statuses.filter((s) => s.status === "invalid").length,
    anchor_failed: statuses.filter((s) => s.status === "anchor_failed").length,
    unanchored: statuses.filter((s) => s.status === "unanchored").length,
    statuses,
    newest_verified_integrated_time: newestVerifiedTime,
    log_signature_basis: basis,
  };
  return { findings, not_checked: notChecked, coverage };
}

// ---- Per-receipt checks ---------------------------------------------------------

function checkAnchoredReceipt(input: {
  record: VerifierCheckpointRecord;
  receipt: ExportedAnchoredReceipt;
  salt: string;
  anchorPoint: Uint8Array;
  rekorPoint: Uint8Array | null;
  rekorLogIdHex: string | null;
  fetched: FetchedAnchorEntry | null;
  findings: TransparencyFinding[];
  notChecked: string[];
}): AnchorCounterStatus {
  const { record, receipt, findings, notChecked } = input;
  const counter = record.counter;
  let invalid = false;
  let incomplete: string | null = null;

  // 1. Commitment binding to the checkpoint ACTUALLY IN THE BUNDLE.
  const recomputedHash = checkpointPayloadHash(record);
  if (receipt.checkpoint_hash !== recomputedHash) {
    invalid = true;
    findings.push({
      kind: "anchor_checkpoint_mismatch",
      counter,
      expected: recomputedHash,
      actual: receipt.checkpoint_hash,
      message: `anchor receipt for checkpoint ${counter} names a different checkpoint hash than the checkpoint in the bundle; the anchor is evidence about some OTHER history`,
    });
  }
  const digest = bytesToHex(
    sha256(
      new TextEncoder().encode(
        `${ANCHOR_COMMITMENT_DOMAIN}\n${input.salt}\n${counter}\n${recomputedHash}`
      )
    )
  );
  if (receipt.commitment_digest !== digest) {
    invalid = true;
    findings.push({
      kind: "anchor_commitment_mismatch",
      counter,
      expected: digest,
      actual: receipt.commitment_digest,
      message: `anchor receipt for checkpoint ${counter}: the commitment digest does not recompute from the exported salt and the bundle's checkpoint hash (wrong salt, tampered receipt, or an anchor for a divergent history)`,
    });
  }

  // 2. Entry binding. Prefer live-fetched material when supplied.
  const material = input.fetched ?? receipt.rekor;
  const materialSource = input.fetched ? "log-fetched" : "receipt-embedded";
  let leafHashHex: string | null = null;
  if (material.body_b64 === undefined) {
    incomplete = `entry body unavailable (${materialSource} material carries no body); entry binding and inclusion not checkable offline. Re-anchor with a current build, or run with --fetch-anchors`;
  } else {
    let bodyBytes: Uint8Array | null = null;
    let body: unknown = null;
    try {
      bodyBytes = b64ToBytes(material.body_b64);
      body = JSON.parse(Buffer.from(bodyBytes).toString("utf8"));
    } catch {
      invalid = true;
      findings.push({
        kind: "anchor_entry_binding_invalid",
        counter,
        message: `anchor entry for checkpoint ${counter}: the ${materialSource} entry body is not decodable base64 JSON`,
      });
    }
    if (bodyBytes && isObject(body)) {
      const spec = isObject(body.spec) ? body.spec : undefined;
      const dataHash =
        spec && isObject(spec.data) && isObject((spec.data as Record<string, unknown>).hash)
          ? ((spec.data as Record<string, unknown>).hash as Record<string, unknown>)
          : undefined;
      const signature =
        spec && isObject(spec.signature)
          ? (spec.signature as Record<string, unknown>)
          : undefined;
      const publicKey =
        signature && isObject(signature.publicKey)
          ? (signature.publicKey as Record<string, unknown>)
          : undefined;
      if (
        body.kind !== "hashedrekord" ||
        !dataHash ||
        dataHash.algorithm !== "sha256" ||
        typeof dataHash.value !== "string"
      ) {
        invalid = true;
        findings.push({
          kind: "anchor_entry_binding_invalid",
          counter,
          message: `anchor entry for checkpoint ${counter}: the log entry is not a sha256 hashedrekord`,
        });
      } else if (dataHash.value !== digest) {
        invalid = true;
        findings.push({
          kind: "anchor_entry_binding_invalid",
          counter,
          expected: digest,
          actual: String(dataHash.value),
          message: `anchor entry for checkpoint ${counter}: the log entry commits to a different digest than the one recomputed from the salt and the bundle's checkpoint`,
        });
      } else {
        // Anchoring key binding: the entry must carry the fortress's
        // derived anchoring key, not just any key over the right digest.
        let entryPoint: Uint8Array | null = null;
        try {
          if (typeof publicKey?.content !== "string") {
            throw new Error("entry carries no public key");
          }
          const pem = Buffer.from(
            b64ToBytes(publicKey.content)
          ).toString("utf8");
          entryPoint = parseSpkiP256Pem(pem).point;
        } catch (err) {
          invalid = true;
          findings.push({
            kind: "anchor_entry_binding_invalid",
            counter,
            message: `anchor entry for checkpoint ${counter}: the entry public key could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
        if (entryPoint && bytesToHex(entryPoint) !== bytesToHex(input.anchorPoint)) {
          invalid = true;
          entryPoint = null;
          findings.push({
            kind: "anchor_entry_binding_invalid",
            counter,
            message: `anchor entry for checkpoint ${counter}: the entry was signed by a DIFFERENT key than this fortress's anchoring key; it is someone else's anchor`,
          });
        }
        if (entryPoint) {
          let signatureOk: boolean;
          try {
            if (typeof signature?.content !== "string") {
              throw new Error("no signature content");
            }
            signatureOk = verifyP256Der(
              b64ToBytes(signature.content),
              hexToBytes(digest),
              entryPoint
            );
          } catch {
            signatureOk = false;
          }
          if (!signatureOk) {
            invalid = true;
            findings.push({
              kind: "anchor_signature_invalid",
              counter,
              message: `anchor entry for checkpoint ${counter}: the P-256 signature over the commitment digest does not verify under the fortress anchoring key`,
            });
          }
        }
      }
      // 2b. UUID binding: the entry UUID's leaf-hash part must recompute
      // from the body bytes (RFC 6962 leaf hashing).
      leafHashHex = bytesToHex(rfc6962LeafHash(bodyBytes));
      const uuidLeaf =
        material.uuid.length >= 64 ? material.uuid.slice(-64) : material.uuid;
      if (!HEX64.test(uuidLeaf) || uuidLeaf !== leafHashHex) {
        invalid = true;
        findings.push({
          kind: "anchor_entry_binding_invalid",
          counter,
          expected: leafHashHex,
          actual: uuidLeaf,
          message: `anchor entry for checkpoint ${counter}: the entry UUID does not match the RFC 6962 leaf hash of the entry body`,
        });
      }
    }
  }

  // 3. Inclusion proof (Merkle arithmetic) + checkpoint-note consistency.
  const verification = material.verification;
  const proof = verification && isObject(verification.inclusionProof)
    ? (verification.inclusionProof as Record<string, unknown>)
    : undefined;
  if (!proof) {
    incomplete ??= `no inclusion proof available (${materialSource} material); run with --fetch-anchors to obtain one from the log`;
  } else if (leafHashHex) {
    const hashes = Array.isArray(proof.hashes) ? proof.hashes : null;
    const rootHash = typeof proof.rootHash === "string" ? proof.rootHash : null;
    const proofIndex = typeof proof.logIndex === "number" ? proof.logIndex : null;
    const treeSize = typeof proof.treeSize === "number" ? proof.treeSize : null;
    if (
      !hashes ||
      !hashes.every((h) => typeof h === "string" && HEX64.test(h)) ||
      !rootHash ||
      !HEX64.test(rootHash) ||
      proofIndex === null ||
      treeSize === null
    ) {
      invalid = true;
      findings.push({
        kind: "anchor_inclusion_proof_invalid",
        counter,
        message: `anchor entry for checkpoint ${counter}: the inclusion proof is malformed`,
      });
    } else if (proofIndex !== material.log_index) {
      // INDEX BINDING, checked BEFORE any proof recomputation: the signed
      // entry timestamp covers material.log_index, but the inclusion proof
      // is recomputed over proof.logIndex. RFC 6962 trees allow duplicate
      // leaves, so a valid proof for a DIFFERENT index with the same leaf
      // hash must never satisfy an entry signed for this index.
      invalid = true;
      findings.push({
        kind: "anchor_inclusion_proof_invalid",
        counter,
        expected: material.log_index,
        actual: proofIndex,
        message: `anchor entry for checkpoint ${counter}: the inclusion proof claims leaf index ${proofIndex} but the log entry (and its signed timestamp) name log index ${material.log_index}; a proof for a different index does not attest this entry's inclusion (duplicate leaves make such proofs forgeable)`,
      });
    } else if (material.log_index >= treeSize) {
      invalid = true;
      findings.push({
        kind: "anchor_inclusion_proof_invalid",
        counter,
        expected: `log index below tree size ${treeSize}`,
        actual: material.log_index,
        message: `anchor entry for checkpoint ${counter}: the entry's log index ${material.log_index} is not inside the inclusion proof's claimed tree of size ${treeSize}; the proof cannot cover this entry`,
      });
    } else {
      const computed = rootFromInclusionProof({
        leafHash: hexToBytes(leafHashHex),
        leafIndex: proofIndex,
        treeSize,
        proofHashes: hashes.map((h) => hexToBytes(h as string)),
      });
      if (!computed || bytesToHex(computed) !== rootHash) {
        invalid = true;
        findings.push({
          kind: "anchor_inclusion_proof_invalid",
          counter,
          expected: rootHash,
          actual: computed ? bytesToHex(computed) : "(impossible proof shape)",
          message: `anchor entry for checkpoint ${counter}: the Merkle inclusion proof does not recompute to the claimed tree root`,
        });
      }
      const note =
        typeof proof.checkpoint === "string"
          ? parseSignedNote(proof.checkpoint)
          : null;
      if (!note) {
        invalid = true;
        findings.push({
          kind: "anchor_inclusion_proof_invalid",
          counter,
          message: `anchor entry for checkpoint ${counter}: the signed checkpoint note is missing or unparseable`,
        });
      } else {
        if (note.treeSize !== treeSize || bytesToHex(note.rootHash) !== rootHash) {
          invalid = true;
          findings.push({
            kind: "anchor_inclusion_proof_invalid",
            counter,
            message: `anchor entry for checkpoint ${counter}: the signed checkpoint note disagrees with the inclusion proof (tree size or root hash)`,
          });
        }
        // 4. Log signatures, only under a pinned log key.
        if (input.rekorPoint) {
          const noteDigest = sha256(note.signedBytes);
          const noteOk = note.signatureBlobs.some((blob) =>
            verifyP256Der(blob.slice(4), noteDigest, input.rekorPoint!)
          );
          if (!noteOk) {
            invalid = true;
            findings.push({
              kind: "anchor_log_signature_invalid",
              counter,
              message: `anchor entry for checkpoint ${counter}: no checkpoint-note signature verifies under the pinned Rekor log key`,
            });
          }
        }
      }
    }
  }

  // 4b. Signed entry timestamp + logID, only under a pinned log key.
  if (input.rekorPoint && input.rekorLogIdHex) {
    if (material.log_id !== input.rekorLogIdHex) {
      invalid = true;
      findings.push({
        kind: "anchor_log_signature_invalid",
        counter,
        expected: input.rekorLogIdHex,
        actual: material.log_id,
        message: `anchor entry for checkpoint ${counter}: the entry's logID is not the pinned Rekor log key's ID; the entry belongs to a different log`,
      });
    }
    const setB64 =
      verification && typeof verification.signedEntryTimestamp === "string"
        ? verification.signedEntryTimestamp
        : null;
    if (!setB64 || material.body_b64 === undefined) {
      incomplete ??= `no signed entry timestamp available (${materialSource} material); the log-attested integration time is unverified`;
    } else {
      let setOk: boolean;
      try {
        const payload = canonicalJson({
          body: material.body_b64,
          integratedTime: material.integrated_time,
          logID: material.log_id,
          logIndex: material.log_index,
        });
        setOk = verifyP256Der(
          b64ToBytes(setB64),
          sha256(new TextEncoder().encode(payload)),
          input.rekorPoint
        );
      } catch {
        setOk = false;
      }
      if (!setOk) {
        invalid = true;
        findings.push({
          kind: "anchor_log_signature_invalid",
          counter,
          message: `anchor entry for checkpoint ${counter}: the signed entry timestamp does not verify under the pinned Rekor log key`,
        });
      }
    }
  }

  if (invalid) {
    return {
      counter,
      status: "invalid",
      detail: "one or more anchor checks FAILED; see findings",
      integrated_time: null,
    };
  }
  if (incomplete) {
    notChecked.push(`anchor for checkpoint ${counter}: ${incomplete}`);
    return {
      counter,
      status: "unverified",
      detail: incomplete,
      integrated_time: null,
    };
  }
  if (input.rekorPoint) {
    return {
      counter,
      status: "verified",
      detail:
        "commitment, entry binding, inclusion proof, and log signatures verified",
      integrated_time: material.integrated_time,
    };
  }
  // No pinned log key: every input above (salt, anchoring key, entry body,
  // proof, root, note, timestamp) is operator-supplied and could have been
  // fabricated together. The honest ceiling is internal consistency; the
  // integration time is unattested and therefore not reported as verified.
  return {
    counter,
    status: "consistent",
    detail:
      "commitment, entry binding, and inclusion arithmetic are internally consistent with the operator-supplied evidence; NOT log-attested (no pinned log key)",
    integrated_time: null,
  };
}
