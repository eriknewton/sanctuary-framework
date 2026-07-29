import { createHash } from "node:crypto";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { verify as verifyIdentitySignature } from "../core/identity.js";

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
