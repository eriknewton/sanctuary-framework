/**
 * sanctuary audit-chain verify
 *
 * Standalone external verifier for exported Sanctuary audit chains.
 *
 * Reads a JSONL export produced by `sanctuary audit-chain export` and
 * independently verifies:
 *   1. Entry hash recomputation (SHA-256 over canonical JSON of envelope fields)
 *   2. Chain monotonicity (sequence numbers, prev_hash linkage)
 *   3. Checkpoint root hash recomputation
 *   4. Checkpoint Ed25519 signature verification
 *   5. Legacy-anchor soundness
 *   6. Rotation-anchor LINKAGE and shape ONLY. The anchor's authenticity MAC
 *      is keyed from the fortress custody (master) key, which this standalone
 *      verifier deliberately does not hold, so it does NOT and CANNOT prove a
 *      rotation anchor is authentic; only the fortress runtime can verify the
 *      MAC (the export carries it for exactly that purpose). The report states
 *      this bound in `rotation_anchor_scope`.
 *
 * STANDALONE PROPERTY, stated precisely (corrected 2026-08-05; the previous
 * wording claimed this module imports NO Sanctuary server module, which was
 * already false when it was written). What is true, and what the property
 * actually buys, is that NOTHING on this module's transitive import graph
 * requires a running server, a fortress, storage, or key material:
 *
 *   - `@noble/curves`, `@noble/hashes`, and Node builtins.
 *   - `../lockdown/status.js`, whose own imports are `node:fs/promises` and
 *     `node:path` and nothing else.
 *   - `../audit/checkpoint-shape.js`, which has ZERO imports of any kind and
 *     exists specifically so this file and the raw exporter can share
 *     definitions rather than hand-copy them.
 *
 * So: no storage backend, no AuditLog, no encryption key, no passphrase. A
 * security reviewer can run it against an exported chain without a running
 * Sanctuary server. The rule for future edits is the CAPABILITY bound above,
 * not a literal no-server-imports rule: adding an import is fine only if it
 * drags in nothing that needs a live fortress.
 *
 * Usage:
 *   sanctuary audit-chain verify --input chain.jsonl [--public-key <base64url>]
 *   sanctuary audit-chain verify --input chain.jsonl --no-strict
 *     # still reports FAIL findings, but exits 0 after completing verification
 */

import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";
import { flagValue } from "./argv.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  AUDIT_CHECKPOINT_DOMAIN_PREFIX,
} from "../audit/checkpoint-shape.js";

// ---- Minimal canonical-JSON implementation (no server imports) ---------------

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
    // Invariant: `undefined` means "field absent," never signable data. Without
    // this filter the hand-built object path would emit `"key":undefined`,
    // while JSON object serialization drops the same field entirely; the
    // standalone verifier carries this exact rule and the structure gate keeps
    // the two bodies byte-equivalent.
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

// ---- Minimal base64url decode (no server imports) ---------------------------

const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_LOOKUP = new Uint8Array(256).fill(255);
for (let i = 0; i < BASE64URL_CHARS.length; i++) {
  BASE64URL_LOOKUP[BASE64URL_CHARS.charCodeAt(i)!] = i;
}

function fromBase64url(s: string): Uint8Array {
  // Normalize: accept standard base64 with + / or url-safe - _
  const normalized = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const pad = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(pad);
  const std = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBase64url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64urlStrict(s: string): Uint8Array {
  if (!/^[A-Za-z0-9\-_]*$/.test(s) || s.length % 4 === 1) {
    throw new TypeError("non-canonical base64url");
  }
  const decoded = fromBase64url(s);
  if (toBase64url(decoded) !== s) {
    throw new TypeError("non-canonical base64url");
  }
  return decoded;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Hash helpers -----------------------------------------------------------

function sha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  return toHex(sha256(bytes));
}

// These three are IMPORTED from `audit/checkpoint-shape.js` at the top of this
// file, not re-typed, so they cannot drift. That module has ZERO imports (it
// exists precisely so the raw exporter and this verifier can share definitions
// without pulling the server runtime in), which is why importing it costs this
// module nothing. `canonicalJson`, `computeAuditEntryHash`, `computeAuditRoot`,
// and `checkpointSigningBytes` below are still hand-duplicated from
// `audit/chain.ts`, because `checkpointSigningBytes` needs `stringToBytes` from
// `core/encoding.ts` and cannot move to the zero-import module. A drifted copy
// of THOSE compiles and runs; it just reports a signature FAILURE on a valid
// chain, which reads as tampering rather than as drift.
// Enforced by `server/test/structure/cross-file-contract-pins.test.ts`.

interface AuditEntryHashInput {
  sequence: number;
  prev_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
  schema_version: number;
}

function computeAuditEntryHash(input: AuditEntryHashInput): string {
  return sha256Hex(canonicalJson(input));
}

function computeAuditRoot(hashes: string[]): string {
  return sha256Hex(canonicalJson({ leaf_hashes: hashes }));
}

interface CheckpointSigningPayload {
  checkpoint_kind: "audit-checkpoint" | "legacy-anchor";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
}

function checkpointSigningBytes(payload: CheckpointSigningPayload): Uint8Array {
  return new TextEncoder().encode(
    `${AUDIT_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(payload)}`
  );
}

function verifyEd25519(
  message: Uint8Array,
  signatureB64: string,
  publicKeyB64: string
): boolean {
  try {
    const sig = fromBase64urlStrict(signatureB64);
    const pub = fromBase64urlStrict(publicKeyB64);
    return ed25519.verify(sig, message, pub);
  } catch {
    return false;
  }
}

// ---- Export record types (duplicated from export module for standalone use) --

export interface EntryExportRecord {
  type: "entry";
  seq: number;
  schema_version: number;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
}

export interface CheckpointExportRecord {
  type: "checkpoint";
  checkpoint_kind: "audit-checkpoint";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
  signer_kid: string | null;
  signature: string | null;
  public_key?: string;
  unsigned: boolean;
}

export interface LegacyAnchorExportRecord {
  type: "legacy_anchor";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
  signer_kid: string | null;
  signature: string | null;
  public_key?: string;
  unsigned: boolean;
}

export interface RotationAnchorExportRecord {
  type: "rotation_anchor";
  base_sequence: number;
  base_prev_hash: string;
  /**
   * The anchor's custody-keyed MAC (canonical 43-char unpadded base64url of
   * the 32-byte HMAC-SHA256), present in exports
   * from re-gate round 3 on; optional so pre-existing export files still
   * parse. This verifier does NOT check it (no custody key); it is carried
   * for a key-holding verifier (the fortress runtime).
   */
  mac?: string;
}

export type ExportRecord =
  | EntryExportRecord
  | CheckpointExportRecord
  | LegacyAnchorExportRecord
  | RotationAnchorExportRecord;

// ---- Verification report types ----------------------------------------------

export type RecordFindingKind =
  | "empty_input"
  | "malformed_input"
  | "entry_hash_mismatch"
  | "prev_hash_mismatch"
  | "sequence_gap"
  | "checkpoint_root_mismatch"
  | "checkpoint_signature_invalid"
  | "checkpoint_signature_missing_key"
  | "legacy_anchor_mismatch"
  | "rotation_anchor_mismatch"
  | "schema_error";

export interface RecordFinding {
  kind: RecordFindingKind;
  seq?: number;
  message: string;
  expected?: string | number;
  actual?: string | number;
}

export type VerifyVerdict = "PASS" | "FAIL";

export interface VerifyReport {
  verdict: VerifyVerdict;
  entries_verified: number;
  checkpoints_verified: number;
  signatures_verified: number;
  signatures_skipped: number;
  legacy_anchors_verified: number;
  findings: RecordFinding[];
  /**
   * Re-gate round 3 (honesty): the fixed statement of what this tool does and
   * does not prove about rotation anchors, printed in every report so a PASS
   * can never be read as proof of anchor authenticity.
   */
  rotation_anchor_scope: string;
}

/**
 * The honest bound on what a PASS means for rotation anchors, stamped into
 * every report (see {@link VerifyReport.rotation_anchor_scope}).
 */
export const ROTATION_ANCHOR_SCOPE =
  "Rotation anchors are checked for shape and chain linkage ONLY. An anchor's " +
  "authenticity MAC is keyed from the fortress custody key, which this " +
  "standalone tool does not hold, so a PASS does not prove the anchor is " +
  "authentic; MAC verification requires the fortress runtime (the exported " +
  "anchor carries its mac field for that purpose).";

// ---- Core verification logic (pure, no I/O) ---------------------------------

/**
 * Verify an array of ExportRecords parsed from a JSONL export.
 *
 * @param records - Parsed records from the export file (entries + checkpoints in any order)
 * @param opts.publicKey - Optional base64url-encoded public key override for checkpoint verification.
 *   If omitted, each checkpoint's embedded public_key field is used.
 * @param opts.strict - Kept for callers that pair report generation with CLI exit policy.
 *   Report truth is independent of strictness: any finding yields a FAIL verdict.
 */
export function verifyAuditChainRecords(
  records: ExportRecord[],
  opts: { publicKey?: string; strict?: boolean } = {}
): VerifyReport {
  const findings: RecordFinding[] = [];
  let signaturesVerified = 0;
  let signaturesSkipped = 0;

  // Partition records
  const entries = records
    .filter((r): r is EntryExportRecord => r.type === "entry")
    .sort((a, b) => a.seq - b.seq);
  const checkpoints = records
    .filter((r): r is CheckpointExportRecord => r.type === "checkpoint")
    .sort((a, b) => a.checkpoint_sequence - b.checkpoint_sequence);
  const legacyAnchors = records
    .filter((r): r is LegacyAnchorExportRecord => r.type === "legacy_anchor")
    .sort((a, b) => a.checkpoint_sequence - b.checkpoint_sequence);
  const rotationAnchors = records
    .filter((r): r is RotationAnchorExportRecord => r.type === "rotation_anchor")
    .sort((a, b) => a.base_sequence - b.base_sequence);

  if (
    entries.length === 0 &&
    checkpoints.length === 0 &&
    legacyAnchors.length === 0 &&
    rotationAnchors.length === 0
  ) {
    return {
      verdict: "FAIL",
      entries_verified: 0,
      checkpoints_verified: 0,
      signatures_verified: 0,
      signatures_skipped: 0,
      legacy_anchors_verified: 0,
      rotation_anchor_scope: ROTATION_ANCHOR_SCOPE,
      findings: [
        {
          kind: "empty_input",
          message:
            "audit chain export is empty (0 bytes); chain must contain at least one entry or checkpoint",
        },
      ],
    };
  }

  // Step 1 + 2: Verify entry hashes and chain linkage
  let expectedSeq = 1;
  let expectedPrevHash = AUDIT_CHAIN_GENESIS;

  // Account for legacy anchor: if there is a legacy anchor, entries start after it
  const legacyAnchor = legacyAnchors[0];
  if (legacyAnchor) {
    // Legacy entries would have been migrated; v2 entries start at legacy_count+1
    expectedSeq = legacyAnchor.checkpoint_sequence + 1;
    expectedPrevHash = legacyAnchor.root_hash;
  }
  const rotationAnchor = rotationAnchors.at(-1);
  if (rotationAnchor && entries.length > 0) {
    const firstSeq = entries[0]!.seq;
    if (rotationAnchor.base_sequence !== firstSeq) {
      findings.push({
        kind: "rotation_anchor_mismatch",
        seq: firstSeq,
        expected: rotationAnchor.base_sequence,
        actual: firstSeq,
        message: `Rotation anchor base_sequence ${rotationAnchor.base_sequence} does not match first exported entry ${firstSeq}`,
      });
    } else {
      expectedSeq = rotationAnchor.base_sequence;
      expectedPrevHash = rotationAnchor.base_prev_hash;
    }
  }

  const entryHashBySeq = new Map<number, string>();

  for (const entry of entries) {
    // Sequence monotonicity
    if (entry.seq !== expectedSeq) {
      findings.push({
        kind: "sequence_gap",
        seq: entry.seq,
        expected: expectedSeq,
        actual: entry.seq,
        message: `Sequence break: expected ${expectedSeq}, found ${entry.seq}`,
      });
      // Advance expected to next to continue detecting further issues
      expectedSeq = entry.seq + 1;
      expectedPrevHash = entry.entry_hash;
      entryHashBySeq.set(entry.seq, entry.entry_hash);
      continue;
    }

    // prev_hash linkage
    if (entry.prev_hash !== expectedPrevHash) {
      findings.push({
        kind: "prev_hash_mismatch",
        seq: entry.seq,
        expected: expectedPrevHash,
        actual: entry.prev_hash,
        message: `prev_hash mismatch at seq ${entry.seq}`,
      });
    }

    // entry_hash recomputation
    const recomputed = computeAuditEntryHash({
      sequence: entry.seq,
      prev_hash: entry.prev_hash,
      timestamp: entry.timestamp,
      encrypted_payload_bytes: entry.encrypted_payload_bytes,
      schema_version: entry.schema_version ?? AUDIT_CHAIN_SCHEMA_VERSION,
    });
    if (recomputed !== entry.entry_hash) {
      findings.push({
        kind: "entry_hash_mismatch",
        seq: entry.seq,
        expected: recomputed,
        actual: entry.entry_hash,
        message: `entry_hash mismatch at seq ${entry.seq}`,
      });
    }

    // Use the recomputed hash for chain propagation so that a tampered entry
    // causes downstream prev_hash failures, surfacing the full chain break.
    entryHashBySeq.set(entry.seq, recomputed);
    expectedSeq = entry.seq + 1;
    expectedPrevHash = recomputed;
  }

  // Step 3 + 4: Verify checkpoints
  for (const cp of checkpoints) {
    // Collect hashes for this checkpoint span
    const spansRotatedEntries =
      rotationAnchor !== undefined && cp.from_sequence < rotationAnchor.base_sequence;
    if (!spansRotatedEntries) {
      const hashes: string[] = [];
      let rootOk = true;
      for (let seq = cp.from_sequence; seq <= cp.checkpoint_sequence; seq++) {
        const h = entryHashBySeq.get(seq);
        if (h == null) {
          findings.push({
            kind: "checkpoint_root_mismatch",
            seq: cp.checkpoint_sequence,
            message: `Checkpoint at seq ${cp.checkpoint_sequence} references missing entry seq ${seq}`,
          });
          rootOk = false;
          break;
        }
        hashes.push(h);
      }
      if (rootOk) {
        const expectedRoot = computeAuditRoot(hashes);
        if (expectedRoot !== cp.root_hash) {
          findings.push({
            kind: "checkpoint_root_mismatch",
            seq: cp.checkpoint_sequence,
            expected: expectedRoot,
            actual: cp.root_hash,
            message: `Checkpoint root mismatch at seq ${cp.checkpoint_sequence}`,
          });
        }
      }
    }

    // Signature verification
    if (cp.unsigned) {
      signaturesSkipped += 1;
    } else {
      const pubKey = opts.publicKey ?? cp.public_key;
      if (!pubKey) {
        findings.push({
          kind: "checkpoint_signature_missing_key",
          seq: cp.checkpoint_sequence,
          message: `Checkpoint at seq ${cp.checkpoint_sequence} has no public key for signature verification`,
        });
      } else if (!cp.signature) {
        findings.push({
          kind: "checkpoint_signature_invalid",
          seq: cp.checkpoint_sequence,
          message: `Checkpoint at seq ${cp.checkpoint_sequence} is marked signed but has no signature`,
        });
      } else {
        const payload: CheckpointSigningPayload = {
          checkpoint_kind: cp.checkpoint_kind,
          checkpoint_sequence: cp.checkpoint_sequence,
          from_sequence: cp.from_sequence,
          root_hash: cp.root_hash,
          previous_checkpoint_sequence: cp.previous_checkpoint_sequence,
          signed_at: cp.signed_at,
        };
        const sigBytes = checkpointSigningBytes(payload);
        const valid = verifyEd25519(sigBytes, cp.signature, pubKey);
        if (valid) {
          signaturesVerified += 1;
        } else {
          findings.push({
            kind: "checkpoint_signature_invalid",
            seq: cp.checkpoint_sequence,
            message: `Checkpoint signature invalid at seq ${cp.checkpoint_sequence}`,
          });
        }
      }
    }
  }

  // Step 5: Legacy anchor soundness
  for (const anchor of legacyAnchors) {
    // Legacy anchors have their own root_hash; we can only verify it's present
    // (we don't have the raw legacy v1 entries in the export - they pre-date v2)
    if (
      typeof anchor.root_hash !== "string" ||
      !/^[0-9a-f]{64}$/.test(anchor.root_hash)
    ) {
      findings.push({
        kind: "legacy_anchor_mismatch",
        message: `Legacy anchor has invalid root_hash: ${String(anchor.root_hash)}`,
      });
    }
  }

  // Strictness controls CLI exit policy only; the JSON verdict must always tell
  // the truth about findings so relaxed callers cannot mistake them for PASS.
  const verdict: VerifyVerdict = findings.length > 0 ? "FAIL" : "PASS";

  return {
    verdict,
    entries_verified: entries.length,
    checkpoints_verified: checkpoints.length,
    signatures_verified: signaturesVerified,
    signatures_skipped: signaturesSkipped,
    legacy_anchors_verified: legacyAnchors.length,
    rotation_anchor_scope: ROTATION_ANCHOR_SCOPE,
    findings,
  };
}

// ---- JSONL parsing ----------------------------------------------------------

export function parseJsonl(content: string): ExportRecord[] {
  return content
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line) as ExportRecord;
      } catch (err) {
        throw new Error(`JSONL parse error on line ${index + 1}: ${String(err)}`, {
          cause: err,
        });
      }
    });
}

export function emptyInputReport(): VerifyReport {
  return {
    verdict: "FAIL",
    entries_verified: 0,
    checkpoints_verified: 0,
    signatures_verified: 0,
    signatures_skipped: 0,
    legacy_anchors_verified: 0,
    rotation_anchor_scope: ROTATION_ANCHOR_SCOPE,
    findings: [
      {
        kind: "empty_input",
        message:
          "audit chain export is empty (0 bytes); chain must contain at least one entry or checkpoint",
      },
    ],
  };
}

export function malformedInputReport(err: unknown): VerifyReport {
  return {
    verdict: "FAIL",
    entries_verified: 0,
    checkpoints_verified: 0,
    signatures_verified: 0,
    signatures_skipped: 0,
    legacy_anchors_verified: 0,
    rotation_anchor_scope: ROTATION_ANCHOR_SCOPE,
    findings: [
      {
        kind: "malformed_input",
        message: `audit chain export is not valid JSONL: ${String(err)}`,
      },
    ],
  };
}

export function verifyAuditChainContent(
  content: string,
  opts: { publicKey?: string; strict?: boolean } = {}
): VerifyReport {
  if (content.length === 0) {
    return emptyInputReport();
  }

  let records: ExportRecord[];
  try {
    records = parseJsonl(content);
  } catch (err) {
    return malformedInputReport(err);
  }

  return verifyAuditChainRecords(records, opts);
}

// ---- CLI entry point --------------------------------------------------------

export interface VerifyArgs {
  input: string;
  strict: boolean;
  publicKey?: string;
  storagePath?: string;
}

export function parseVerifyArgs(argv: string[], env?: NodeJS.ProcessEnv): VerifyArgs {
  const input = flagValue(argv, "--input") ?? flagValue(argv, "-i") ?? "";
  const strict = !argv.includes("--no-strict");
  const publicKey = flagValue(argv, "--public-key");
  const storagePath =
    flagValue(argv, "--storage-path") ??
    env?.SANCTUARY_STORAGE_PATH ??
    env?.SANCTUARY_FORTRESS_PATH;
  return { input, strict, publicKey, storagePath };
}

export async function runVerify(args: VerifyArgs): Promise<void> {
  if (!args.input) {
    process.stderr.write("Error: --input <path> is required\n");
    process.exit(1);
  }

  let content: string;
  try {
    content = readFileSync(args.input, "utf8");
  } catch (err) {
    process.stderr.write(`Error reading ${args.input}: ${String(err)}\n`);
    process.exit(1);
  }

  const report = verifyAuditChainContent(content, {
    publicKey: args.publicKey,
    strict: args.strict,
  });

  const banner = lockdownBanner(await readLockdownStatus(args.storagePath));
  if (banner) process.stderr.write(banner);
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");

  if (args.strict && report.verdict === "FAIL") {
    process.exit(1);
  }
}
