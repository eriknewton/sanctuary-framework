import { createHash } from "node:crypto";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { verify as verifyIdentitySignature } from "../core/identity.js";

/**
 * CROSS-FILE CONTRACT. These four values, `canonicalJson` below, and
 * `checkpointSigningBytes`'s prefix+canonical-JSON composition are DUPLICATED
 * verbatim in `cli/audit-chain-verify.ts` (its `AUDIT_CHAIN_GENESIS`,
 * `AUDIT_CHAIN_SCHEMA_VERSION`, `AUDIT_CHECKPOINT_DOMAIN_PREFIX`,
 * `canonicalJson`, `checkpointSigningBytes`). The duplication is DELIBERATE:
 * that module's documented STANDALONE PROPERTY is that it imports only
 * @noble/* and Node builtins, so a third party can verify an exported chain
 * with no Sanctuary server present. Importing these constants from here would
 * drag the server runtime in and destroy that property, so the copy stays and
 * this pin is the tripwire.
 *
 * Failure mode of a drifted copy: nothing throws and nothing fails to compile.
 * The external verifier simply recomputes different signing bytes and reports
 * a signature FAILURE on a chain the fortress considers perfectly valid, which
 * reads to an auditor as evidence of tampering rather than as a stale mirror.
 * Change a value here and in `cli/audit-chain-verify.ts` in the SAME PR.
 * Enforced by `test/structure/cross-file-contract-pins.test.ts`.
 */
export const AUDIT_CHAIN_GENESIS = "GENESIS";
export const AUDIT_CHAIN_SCHEMA_VERSION = 2;
export const AUDIT_CHECKPOINT_DOMAIN = "sanctuary.audit-checkpoint.v1";
export const AUDIT_CHECKPOINT_DOMAIN_PREFIX = `${AUDIT_CHECKPOINT_DOMAIN}\n`;

// G1 (post-#969 sweep re-gate): the checkpoint record shape, its schema
// version, the strict shape predicate, and the `_audit_checkpoints`
// control-key constants moved to the PURE, dependency-free
// `checkpoint-shape.ts` so the raw CLI exporter (which must not import the
// server runtime) and the runtime audit log share ONE definition instead of
// hand-duplicated copies that drifted. Re-exported here so existing importers
// are unchanged.
export {
  AUDIT_CHECKPOINT_SCHEMA_VERSION,
  AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS,
  AUDIT_EPOCH_KEYS_KEY,
  AUDIT_HEAD_ANCHOR_KEY,
  AUDIT_ROTATION_ANCHOR_MARKER,
  isAuditCheckpointRecord,
  isAuditRotationAnchorEnvelope,
} from "./checkpoint-shape.js";
export type {
  AuditCheckpointRecord,
  AuditCheckpointSigningPayload,
  AuditRotationAnchorEnvelope,
} from "./checkpoint-shape.js";
import type { AuditCheckpointSigningPayload } from "./checkpoint-shape.js";

export interface AuditEntryHashInput {
  sequence: number;
  prev_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
  schema_version: number;
}

export interface AuditCheckpointSignature {
  signer_kid: string;
  signature: string;
  public_key?: string;
}

export function canonicalJson(value: unknown): string {
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

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function computeAuditEntryHash(input: AuditEntryHashInput): string {
  return sha256Hex(canonicalJson(input));
}

export function computeAuditRoot(entryHashes: readonly string[]): string {
  return sha256Hex(canonicalJson({ leaf_hashes: entryHashes }));
}

export function checkpointSigningBytes(
  payload: AuditCheckpointSigningPayload
): Uint8Array {
  return stringToBytes(`${AUDIT_CHECKPOINT_DOMAIN_PREFIX}${canonicalJson(payload)}`);
}

export function verifyCheckpointSignature(
  payload: AuditCheckpointSigningPayload,
  signature: string,
  publicKey: string | Uint8Array
): boolean {
  const keyBytes =
    typeof publicKey === "string" ? fromBase64url(publicKey) : publicKey;
  return verifyIdentitySignature(
    checkpointSigningBytes(payload),
    fromBase64url(signature),
    keyBytes
  );
}
