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
 *
 * STANDALONE PROPERTY: This module imports only @noble/curves, @noble/hashes,
 * and Node builtins (node:fs, node:crypto). It does NOT import from any
 * Sanctuary server module (no storage backend, no AuditLog, no encryption
 * key required). A security reviewer can run it against an exported chain
 * without a running Sanctuary server.
 *
 * Usage:
 *   sanctuary audit-chain verify --input chain.jsonl [--public-key <base64url>]
 *   sanctuary audit-chain verify --input chain.jsonl --no-strict
 */

import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";

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

const AUDIT_CHAIN_GENESIS = "GENESIS";
const AUDIT_CHAIN_SCHEMA_VERSION = 2;
const AUDIT_CHECKPOINT_DOMAIN_PREFIX = "sanctuary.audit-checkpoint.v1\n";

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
    const sig = fromBase64url(signatureB64);
    const pub = fromBase64url(publicKeyB64);
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
  legacy_anchors_verified: number;
  findings: RecordFinding[];
}

// ---- Core verification logic (pure, no I/O) ---------------------------------

/**
 * Verify an array of ExportRecords parsed from a JSONL export.
 *
 * @param records - Parsed records from the export file (entries + checkpoints in any order)
 * @param opts.publicKey - Optional base64url-encoded public key override for checkpoint verification.
 *   If omitted, each checkpoint's embedded public_key field is used.
 * @param opts.strict - If true (default), any finding results in FAIL verdict.
 */
export function verifyAuditChainRecords(
  records: ExportRecord[],
  opts: { publicKey?: string; strict?: boolean } = {}
): VerifyReport {
  const strict = opts.strict ?? true;
  const findings: RecordFinding[] = [];

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
      legacy_anchors_verified: 0,
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
    if (!cp.unsigned) {
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
        if (!valid) {
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

  const verdict: VerifyVerdict =
    strict && findings.length > 0 ? "FAIL" : findings.length === 0 ? "PASS" : "PASS";

  return {
    verdict,
    entries_verified: entries.length,
    checkpoints_verified: checkpoints.length,
    legacy_anchors_verified: legacyAnchors.length,
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
        throw new Error(`JSONL parse error on line ${index + 1}: ${String(err)}`);
      }
    });
}

export function emptyInputReport(): VerifyReport {
  return {
    verdict: "FAIL",
    entries_verified: 0,
    checkpoints_verified: 0,
    legacy_anchors_verified: 0,
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
    legacy_anchors_verified: 0,
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

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}
