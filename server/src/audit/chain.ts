import { createHash } from "node:crypto";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { verify as verifyIdentitySignature } from "../core/identity.js";

export const AUDIT_CHAIN_GENESIS = "GENESIS";
export const AUDIT_CHAIN_SCHEMA_VERSION = 2;
export const AUDIT_CHECKPOINT_SCHEMA_VERSION = 1;
export const AUDIT_CHECKPOINT_DOMAIN = "sanctuary.audit-checkpoint.v1";
export const AUDIT_CHECKPOINT_DOMAIN_PREFIX = `${AUDIT_CHECKPOINT_DOMAIN}\n`;

export interface AuditEntryHashInput {
  sequence: number;
  prev_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
  schema_version: number;
}

export interface AuditCheckpointSigningPayload {
  checkpoint_kind: "audit-checkpoint" | "legacy-anchor";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
}

export interface AuditCheckpointSignature {
  signer_kid: string;
  signature: string;
  public_key?: string;
}

export interface AuditCheckpointRecord extends AuditCheckpointSigningPayload {
  schema_version: typeof AUDIT_CHECKPOINT_SCHEMA_VERSION;
  signer_kid: string | null;
  signature: string | null;
  signature_algorithm: "Ed25519" | null;
  payload_encoding: "domain-separated-canonical-json-v1";
  unsigned: boolean;
  unsigned_reason?: string;
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
