/** Pure snapshot wire contract; new top-level fields or algorithms require a new format. */
import { sha256 } from "@noble/hashes/sha256";
import { parseStrictJson } from "../hermes-memory-bridge/strict-json.js";
import { isStrictEd25519PointEncoding } from "../core/identity.js";
import { canonicalJson } from "../audit/chain.js";
import { AUDIT_CHAIN_GENESIS, AUDIT_CHAIN_SCHEMA_VERSION } from "../audit/checkpoint-shape.js";
import { TRANSPARENCY_BUNDLE_FORMAT } from "../transparency/checkpoint.js";
import { isVerifierCheckpointRecord, type VerifierCheckpointRecord } from "../transparency/verify.js";
import type { ExportRecord } from "../cli/audit-chain-verify.js";

export const SNAPSHOT_FORMAT = "SANCTUARY_EVIDENCE_SNAPSHOT_V0";
export const TRUST_FORMAT = "SANCTUARY_EVIDENCE_TRUST_V0";
export const RECEIPT_FORMAT = "SANCTUARY_EVIDENCE_EXPORT_RECEIPT_V0";
export const RESULT_FORMAT = "SANCTUARY_EVIDENCE_VERIFICATION_V0";
// Must match EVIDENCE_SNAPSHOT_MANIFEST_DOMAIN in core/signing-domains.ts, including the raw-sign refusal.
import { EVIDENCE_SNAPSHOT_MANIFEST_DOMAIN as MANIFEST_DOMAIN } from "../core/signing-domains.js";
export { MANIFEST_DOMAIN };
import { extensionRolesAllowed } from "./snapshot-extensions.js";
export const SIGNATURE_SCHEME = "ed25519-v1";
export const HASH_ALGORITHM = "sha256";
export const MANIFEST_FILENAME = "00_pack_manifest.json";
export const REPORT_FILENAME = "01_evidence_pack.md";
export const PDF_FILENAME = "evidence-pack.pdf";
export const TRUST_FILENAME = "public-trust.json";
export const RECIPIENT_FILENAME = "verify.md";
export const AUDIT_FILENAME = "audit-chain.jsonl";
export const TRANSPARENCY_FILENAME = "transparency-bundle.json";
export const EXIT_PASS = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;
export const EXIT_PARTIAL = 10;
export const MAX_MANIFEST_BYTES = 1048576;
export const MAX_TRUST_BYTES = 1048576;
export const MAX_FILE_BYTES = 67108864;
export const MAX_PACK_BYTES = 268435456;
export const MAX_FILES = 256;
export const MAX_NAME_BYTES = 128;
// Imported, not copied, so a bundle format change in the transparency producer cannot silently fail every pack.
export { TRANSPARENCY_BUNDLE_FORMAT };
export const MAX_JSON_DEPTH = 32;
export const MAX_RECORDS = 100000;
export const MAX_JSONL_LINE_BYTES = 1048576;
export const MAX_KEYS = 64;
export const MAX_ROTATION_HOPS = 64;
export const MAX_AUDIT_TRAVERSAL = MAX_KEYS * MAX_RECORDS;
export const KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;
export const ALGORITHM = "Ed25519";
export const DIGEST_PREFIX = "sha256:";
export const LF = "\n";
export const HEX = /^[0-9a-f]{64}$/;
export const DIGEST = /^sha256:[0-9a-f]{64}$/;
export const REVISION = /^[0-9a-f]{40}$/;
export const IDENTITY_ID = /^[0-9a-f]{32}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const EXTENSION_ID = /^[a-z][a-z0-9-]{0,63}$/;
export const NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
export const BASE64URL = /^[A-Za-z0-9_-]+$/;
export const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const STATES = { ARGUMENTS: "ARGUMENTS", PIN_INPUTS: "PIN_INPUTS", MANIFEST_BYTES: "MANIFEST_BYTES", MANIFEST_AUTHENTICATED: "MANIFEST_AUTHENTICATED", EXPECTED_SNAPSHOT: "EXPECTED_SNAPSHOT", FILE_SET_AUTHENTICATED: "FILE_SET_AUTHENTICATED", BYTES_VERIFIED: "BYTES_VERIFIED", NESTED_VERIFIED: "NESTED_VERIFIED", FINAL_RECHECK: "FINAL_RECHECK" } as const;
export const STATUS = { PASS: "PASS", PARTIAL: "PARTIAL", FAIL: "FAIL" } as const;
export const INTEGRITY = { verified: "verified", bytes_match: "bytes_match", unverified: "unverified" } as const;
// Must match the closed diagnostic filter in snapshot-export-cli.ts; no free-form error code is exported.
export const HARD = Object.freeze({ pin_invalid: "pin_invalid", manifest_invalid: "manifest_invalid", manifest_signature_invalid: "manifest_signature_invalid", embedded_key_mismatch: "embedded_key_mismatch", manifest_digest_mismatch: "manifest_digest_mismatch", unsupported_format: "unsupported_format", unsafe_path: "unsafe_path", file_set_mismatch: "file_set_mismatch", file_type_invalid: "file_type_invalid", file_digest_mismatch: "file_digest_mismatch", descriptor_mismatch: "descriptor_mismatch", extent_mismatch: "extent_mismatch", nested_invalid: "nested_invalid", limit_exceeded: "limit_exceeded", io_error: "io_error", snapshot_changed: "snapshot_changed", unexpected_metadata: "unexpected_metadata", unlisted_os_metadata: "unlisted_os_metadata" } as const);
export const PARTIAL = Object.freeze({ audit_absent: "audit_absent", transparency_absent: "transparency_absent", checkpoint_unsigned: "checkpoint_unsigned", checkpoint_coverage_absent: "checkpoint_coverage_absent", audit_legacy_anchor_unverified: "audit_legacy_anchor_unverified", audit_rotation_anchor_unverified: "audit_rotation_anchor_unverified", audit_pruned_root_unverified: "audit_pruned_root_unverified", audit_custody_mac_unverified: "audit_custody_mac_unverified", transparency_prefix_unverified: "transparency_prefix_unverified", extension_unverified: "extension_unverified", audit_tail_unanchored: "audit_tail_unanchored", audit_span_gap: "audit_span_gap", audit_empty_verified: "audit_empty_verified", audit_read_failed: "audit_read_failed", transparency_empty_verified: "transparency_empty_verified", transparency_read_failed: "transparency_read_failed" } as const);
export const HUMAN = { PASS: "PASS: expected snapshot bytes verified; supported nested checks passed.", PARTIAL: "PARTIAL: snapshot bytes match the expected digest; some checks are incomplete; do not rely on this pack as complete.", FAIL: "FAIL: snapshot verification failed.", USAGE_ERROR: "USAGE_ERROR: invalid command arguments." } as const;
export const NOT_CHECKED = ["Continuous history, legal compliance, wall enforcement, external approval, freshness and a globally atomic cut are not established."] as const;
export const ROLE = { report: "report", pdf: "pdf", trust: "trust", recipient: "recipient", audit: "audit", transparency: "transparency", extension: "extension" } as const;
export const PIN_ROLE = { pack: "pack-manifest", audit: "audit-checkpoint", transparency: "transparency-checkpoint", extension: "extension:" } as const;
export const COMPONENT = { included: "included", empty_verified: "empty_verified", read_failed: "read_failed", absent: "absent" } as const;
export const ABSENT_REASONS = ["no_records", "split_store", "mixed_keys", "read_error", "invalid_records", "pin_unavailable", "key_mismatch"] as const;
export const ROTATION = { history: "identity-history", oob: "out-of-band-only", castle: "castle-pin" } as const;
export const RECORD = { entry: "entry", checkpoint: "checkpoint", legacy: "legacy_anchor", rotation: "rotation_anchor", extension: "extension" } as const;
export const PUBLIC_AUDIT_KINDS = [RECORD.entry, RECORD.checkpoint] as const;
export const AUDIT_PARTIAL_FINDINGS: readonly string[] = [PARTIAL.checkpoint_unsigned, PARTIAL.checkpoint_coverage_absent];
export const SIGNATURE_BASIS = "pinned";
export const FILE_TYPE = { file: "file", directory: "directory" } as const;
// Must match the name-only checks in snapshot-verify.ts and capture in snapshot-trust-cli.ts.
export const OS_ATTACHED_METADATA: readonly string[] = Object.freeze(["com.apple.provenance", "com.apple.quarantine", "security.selinux"]);
export const OS_ATTACHED_METADATA_NOT_CHECKED = "OS-attached file metadata (provenance, quarantine, security label) is outside the signed set.";
export const OS_METADATA = /^\.DS_Store$|^\._/;
export const FIXED_FILES = {
  report: [REPORT_FILENAME, "text/markdown"], pdf: [PDF_FILENAME, "application/pdf"], trust: [TRUST_FILENAME, "application/json"], recipient: [RECIPIENT_FILENAME, "text/markdown"], audit: [AUDIT_FILENAME, "application/jsonl"], transparency: [TRANSPARENCY_FILENAME, "application/json"],
} as const;
export const EXTENSION_MIME = "application/octet-stream";
export type HardCode = typeof HARD[keyof typeof HARD];
export type PartialReason = typeof PARTIAL[keyof typeof PARTIAL];
export type ProtocolState = typeof STATES[keyof typeof STATES];
export type SnapshotStatus = typeof STATUS[keyof typeof STATUS];
export class SnapshotError extends Error {
  constructor(readonly code: HardCode) { super(code); }
}
export function requireSnapshot(ok: unknown, code: HardCode = HARD.manifest_invalid): asserts ok { if (!ok) throw new SnapshotError(code); }
export function cap(value: number, maximum: number): void { requireSnapshot(value <= maximum, HARD.limit_exceeded); }
export function sha256Hex(bytes: Uint8Array): string { return Buffer.from(sha256(bytes)).toString("hex"); }
export function manifestDigest(bytes: Uint8Array): string { return DIGEST_PREFIX + sha256Hex(bytes); }
export function utf8(text: string): Uint8Array { return new TextEncoder().encode(text); }
export function canonicalSnapshotJSON(value: unknown): string { return canonicalJson(value); }
export function manifestSigningBytes(value: Record<string, unknown>): Uint8Array {
  const body = { ...value };
  delete body.manifest_signature;
  // Signing the prefixed message preserves raw-sign refusal because a digest hides the internal domain.
  return utf8(MANIFEST_DOMAIN + canonicalSnapshotJSON(body));
}
export function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  requireSnapshot(value !== null && typeof value === "object" && !Array.isArray(value));
  const row = value as Record<string, unknown>;
  requireSnapshot(required.every(k => Object.hasOwn(row, k)) && Object.keys(row).every(k => required.includes(k) || optional.includes(k)));
  return row;
}
export function text(value: unknown, pattern?: RegExp): asserts value is string { requireSnapshot(typeof value === "string" && value.length > 0 && (!pattern || pattern.test(value))); }
export function integer(value: unknown, positive = false): asserts value is number { requireSnapshot(typeof value === "number" && Number.isSafeInteger(value) && value >= (positive ? 1 : 0)); }
export function timestamp(value: unknown): asserts value is string { text(value, TIME); requireSnapshot(new Date(value).toISOString() === value); }
export function array(value: unknown, maximum: number): asserts value is unknown[] { requireSnapshot(Array.isArray(value)); cap(value.length, maximum); }
export function base64(value: unknown, length?: number): Uint8Array {
  text(value, BASE64URL);
  const decoded = Buffer.from(value, "base64url");
  requireSnapshot(decoded.toString("base64url") === value && (length === undefined || decoded.length === length));
  return decoded;
}
export function publicKey(value: unknown): Uint8Array {
  const bytes = base64(value, KEY_BYTES);
  // Authority pins must be canonical prime-order points before any signature check can attribute a signer.
  requireSnapshot(isStrictEd25519PointEncoding(bytes), HARD.pin_invalid);
  return bytes;
}
export function parseSnapshotJSON(bytes: Uint8Array, maximum: number): unknown {
  cap(bytes.byteLength, maximum);
  // Duplicate members, invalid UTF-8 and unsafe numbers cannot acquire a second meaning across consumers.
  try { return parseStrictJson(bytes, MAX_JSON_DEPTH - 1); }
  catch { throw new SnapshotError(HARD.manifest_invalid); }
}
export function safeName(value: unknown): asserts value is string {
  requireSnapshot(typeof value === "string" && NAME.test(value) && !value.includes(".."), HARD.unsafe_path);
}
export interface AuditExtent { entry_count: number; first_sequence: number | null; last_sequence: number | null; head_hash: string | null; checkpoint_count: number; first_checkpoint_sequence: number | null; last_checkpoint_sequence: number | null }
export interface TransparencyExtent { checkpoint_count: number; first_counter: number; last_counter: number; last_checkpoint_payload_sha256: string; fortress_id: string }
export type Component<E> = { state: "included"; filename: string; extent: E } | { state: "empty_verified"; reason: "no_records" } | { state: "read_failed"; reason: Exclude<typeof ABSENT_REASONS[number], "no_records"> };
export interface SnapshotFile { filename: string; content_type: string; size_bytes: number; sha256: string; role: typeof ROLE[keyof typeof ROLE] }
export interface SnapshotManifest { format: typeof SNAPSHOT_FORMAT; signature_scheme: typeof SIGNATURE_SCHEME; hash_algorithm: typeof HASH_ALGORITHM; export_id: string; generated_at: string; source_revision: string; signer: { identity_id: string; public_key_base64url: string }; files: SnapshotFile[]; components: { audit: Component<AuditExtent>; transparency: Component<TransparencyExtent> }; extensions: { id: string; filenames: string[]; signing_roles: string[] }[]; manifest_signature: string }
const AUDIT_EXTENT_FIELDS = ["entry_count", "first_sequence", "last_sequence", "head_hash", "checkpoint_count", "first_checkpoint_sequence", "last_checkpoint_sequence"];
const TRANSPARENCY_EXTENT_FIELDS = ["checkpoint_count", "first_counter", "last_counter", "last_checkpoint_payload_sha256", "fortress_id"];
export function parseComponent(value: unknown, role: "audit" | "transparency"): Component<AuditExtent | TransparencyExtent> {
  const r = object(value, ["state"], ["filename", "extent", "reason"]);
  if (r.state !== COMPONENT.included) {
    object(r, ["state", "reason"]);
    requireSnapshot(r.state === COMPONENT.empty_verified ? r.reason === ABSENT_REASONS[0] : r.state === COMPONENT.read_failed && ABSENT_REASONS.slice(1).includes(r.reason as never));
  } else {
    object(r, ["state", "filename", "extent"]);
    requireSnapshot(r.filename === FIXED_FILES[role][0]);
    if (role === ROLE.audit) {
      const e = object(r.extent, AUDIT_EXTENT_FIELDS);
      integer(e.entry_count); integer(e.checkpoint_count);
      cap(e.entry_count, MAX_RECORDS); cap(e.checkpoint_count, MAX_RECORDS);
      requireSnapshot(e.entry_count + e.checkpoint_count > 0);
      for (const k of ["first_sequence", "last_sequence"]) { if (e.entry_count === 0) requireSnapshot(e[k] === null); else integer(e[k], true); }
      if (e.entry_count === 0) requireSnapshot(e.head_hash === null); else text(e.head_hash, HEX);
      for (const k of ["first_checkpoint_sequence", "last_checkpoint_sequence"]) { if (e.checkpoint_count === 0) requireSnapshot(e[k] === null); else integer(e[k], true); }
    } else {
      const e = object(r.extent, TRANSPARENCY_EXTENT_FIELDS);
      integer(e.checkpoint_count, true); cap(e.checkpoint_count, MAX_RECORDS); integer(e.first_counter, true); integer(e.last_counter, true); text(e.last_checkpoint_payload_sha256, HEX); text(e.fortress_id);
    }
  }
  return r as unknown as Component<AuditExtent | TransparencyExtent>;
}
export function parseManifestEnvelope(bytes: Uint8Array): Record<string, unknown> {
  const r = parseSnapshotJSON(bytes, MAX_MANIFEST_BYTES);
  requireSnapshot(r !== null && typeof r === "object" && !Array.isArray(r));
  const row = r as Record<string, unknown>;
  // The envelope names the protocol before authentication so legacy packs are never misdiagnosed as bad signatures.
  requireSnapshot(row.format === SNAPSHOT_FORMAT, HARD.unsupported_format);
  return row;
}
export function parseManifest(value: unknown): SnapshotManifest {
  const r = object(value, ["format", "signature_scheme", "hash_algorithm", "export_id", "generated_at", "source_revision", "signer", "files", "components", "extensions", "manifest_signature"]);
  requireSnapshot(r.format === SNAPSHOT_FORMAT && r.signature_scheme === SIGNATURE_SCHEME && r.hash_algorithm === HASH_ALGORITHM, HARD.unsupported_format);
  text(r.export_id, UUID); timestamp(r.generated_at); text(r.source_revision, REVISION); base64(r.manifest_signature, SIGNATURE_BYTES);
  const signer = object(r.signer, ["identity_id", "public_key_base64url"]); text(signer.identity_id, IDENTITY_ID); publicKey(signer.public_key_base64url);
  array(r.files, MAX_FILES - 1);
  const names = new Set<string>(); const roles = new Map<string, number>(); let previous = ""; let total = 0;
  for (const file of r.files) {
    const f = object(file, ["filename", "content_type", "size_bytes", "sha256", "role"]);
    // Exact unique names forbid path normalization and ambiguous directory-to-manifest mappings.
    safeName(f.filename); requireSnapshot(f.filename !== MANIFEST_FILENAME && !names.has(f.filename), HARD.unsafe_path); requireSnapshot(previous < f.filename); previous = f.filename; names.add(f.filename);
    integer(f.size_bytes); cap(f.size_bytes, MAX_FILE_BYTES); total += f.size_bytes; cap(total, MAX_PACK_BYTES); text(f.sha256, HEX);
    requireSnapshot(Object.values(ROLE).includes(f.role as never));
    const role = f.role as SnapshotFile["role"];
    roles.set(role, (roles.get(role) ?? 0) + 1);
    if (role === ROLE.extension) requireSnapshot(f.content_type === EXTENSION_MIME);
    else { requireSnapshot(f.filename === FIXED_FILES[role][0] && f.content_type === FIXED_FILES[role][1]); requireSnapshot(f.size_bytes > 0); }
  }
  for (const role of [ROLE.report, ROLE.pdf, ROLE.trust, ROLE.recipient]) requireSnapshot(roles.get(role) === 1);
  const components = object(r.components, [ROLE.audit, ROLE.transparency]);
  for (const role of [ROLE.audit, ROLE.transparency] as const) {
    const c = parseComponent(components[role], role);
    requireSnapshot((roles.get(role) ?? 0) === (c.state === COMPONENT.included ? 1 : 0));
  }
  array(r.extensions, MAX_FILES); const ids = new Set<string>(); const extensionNames = new Set<string>();
  for (const extension of r.extensions) {
    const e = object(extension, ["id", "filenames", "signing_roles"]); text(e.id, EXTENSION_ID); requireSnapshot(!ids.has(e.id)); ids.add(e.id);
    // Every extension declares at least one signing role for independent pin binding.
    array(e.filenames, MAX_FILES); array(e.signing_roles, MAX_KEYS); requireSnapshot(e.signing_roles.length > 0 && e.filenames.length > 0 && new Set(e.signing_roles).size === e.signing_roles.length);
    for (const name of e.filenames) { safeName(name); requireSnapshot(!extensionNames.has(name) && r.files.some(f => (f as SnapshotFile).filename === name && (f as SnapshotFile).role === ROLE.extension)); extensionNames.add(name); }
    for (const role of e.signing_roles) { text(role); requireSnapshot(role.startsWith(PIN_ROLE.extension) && EXTENSION_ID.test(role.slice(PIN_ROLE.extension.length))); }
    // Registered roles constrain authority without claiming that a handler has verified the payload.
    requireSnapshot(extensionRolesAllowed(e.id, e.signing_roles as string[]));
  }
  requireSnapshot(extensionNames.size === (roles.get(ROLE.extension) ?? 0));
  return r as unknown as SnapshotManifest;
}

export interface RotationHistory { kind: "identity-history"; identity_id: string; current_public_key: string; history: { old_public_key: string; new_public_key: string; rotation_event: string; rotated_at: string }[] }
export interface TrustKey { role: string; key_id: string; algorithm: typeof ALGORITHM; public_key_base64url: string; fingerprint: string; rotation_evidence: RotationHistory | { kind: "out-of-band-only" } | { kind: "castle-pin"; path_class: "global" | "fortress-local" } }
export interface TrustDescriptor { format: typeof TRUST_FORMAT; keys: TrustKey[] }
export function parseTrustDescriptor(bytes: Uint8Array): TrustDescriptor {
  const r = object(parseSnapshotJSON(bytes, MAX_TRUST_BYTES), ["format", "keys"]);
  requireSnapshot(r.format === TRUST_FORMAT, HARD.unsupported_format); array(r.keys, MAX_KEYS); let previous = "";
  for (const key of r.keys) {
    const k = object(key, ["role", "key_id", "algorithm", "public_key_base64url", "fingerprint", "rotation_evidence"]);
    text(k.role); requireSnapshot([PIN_ROLE.pack, PIN_ROLE.audit, PIN_ROLE.transparency].includes(k.role as never) || (k.role.startsWith(PIN_ROLE.extension) && EXTENSION_ID.test(k.role.slice(PIN_ROLE.extension.length))));
    requireSnapshot(k.algorithm === ALGORITHM, HARD.unsupported_format); const raw = publicKey(k.public_key_base64url);
    requireSnapshot(k.key_id === manifestDigest(raw) && k.fingerprint === k.key_id, HARD.pin_invalid);
    const order = k.role + ":" + k.key_id; requireSnapshot(order > previous, HARD.pin_invalid); previous = order;
    const e = object(k.rotation_evidence, ["kind"], ["identity_id", "current_public_key", "history", "path_class"]);
    if (e.kind === ROTATION.history) {
      object(e, ["kind", "identity_id", "current_public_key", "history"]); text(e.identity_id, IDENTITY_ID); publicKey(e.current_public_key); array(e.history, MAX_ROTATION_HOPS);
      for (const hop of e.history) {
        const h = object(hop, ["old_public_key", "new_public_key", "rotation_event", "rotated_at"]); publicKey(h.old_public_key); publicKey(h.new_public_key); timestamp(h.rotated_at);
        const event = object(parseSnapshotJSON(base64(h.rotation_event), MAX_TRUST_BYTES), ["old_public_key", "new_public_key", "identity_id", "reason", "rotated_at", "signature"]);
        publicKey(event.old_public_key); publicKey(event.new_public_key); text(event.identity_id, IDENTITY_ID); text(event.reason); timestamp(event.rotated_at); base64(event.signature, SIGNATURE_BYTES);
      }
    } else if (e.kind === ROTATION.castle) {
      object(e, ["kind", "path_class"]); requireSnapshot(k.role === PIN_ROLE.transparency && (e.path_class === "global" || e.path_class === "fortress-local"));
    } else { object(e, ["kind"]); requireSnapshot(e.kind === ROTATION.oob); }
    requireSnapshot(!(k.role === PIN_ROLE.pack || k.role === PIN_ROLE.audit) || e.kind === ROTATION.history, HARD.pin_invalid);
  }
  requireSnapshot(r.keys.filter(k => (k as TrustKey).role === PIN_ROLE.pack).length === 1, HARD.pin_invalid);
  return r as unknown as TrustDescriptor;
}

/** Field and null tables are shared preflight contracts for every audit partition. */
export const AUDIT_FIELDS = {
  entry: { required: ["type", "seq", "schema_version", "prev_hash", "entry_hash", "timestamp", "encrypted_payload_bytes"], optional: [], nullable: [] },
  checkpoint: { required: ["type", "checkpoint_kind", "checkpoint_sequence", "from_sequence", "root_hash", "previous_checkpoint_sequence", "signed_at", "signer_kid", "signature", "unsigned"], optional: ["public_key"], nullable: ["signer_kid", "signature"] },
  legacy_anchor: { required: ["type", "checkpoint_sequence", "from_sequence", "root_hash", "previous_checkpoint_sequence", "signed_at", "signer_kid", "signature", "unsigned"], optional: ["public_key"], nullable: ["signer_kid", "signature"] },
  rotation_anchor: { required: ["type", "base_sequence", "base_prev_hash"], optional: ["mac"], nullable: [] },
} as const;
export type AuditRecord = ExportRecord | { type: "extension"; extension_id: string; [key: string]: unknown };
function nestedSchema<T>(parse: () => T): T {
  // Nested schema failures retain their file boundary while resource and trust errors keep their codes.
  try { return parse(); }
  catch (error) { if (error instanceof SnapshotError && error.code === HARD.manifest_invalid) throw new SnapshotError(HARD.nested_invalid); throw error; }
}
/** Only the reserved extension envelope permits unknown audit content; bare unknown kinds fail. */
export function parseAuditRecords(bytes: Uint8Array): AuditRecord[] { return nestedSchema(() => parseAuditRecordsBody(bytes)); }
function parseAuditRecordsBody(bytes: Uint8Array): AuditRecord[] {
  cap(bytes.length, MAX_FILE_BYTES); const records: AuditRecord[] = []; let start = 0;
  // Byte-level line limits apply before UTF-8 decoding or record allocation.
  for (let i = 0; i <= bytes.length; i++) {
    if (i !== bytes.length && bytes[i] !== 10) continue;
    if (i === bytes.length && i === start) break;
    cap(i - start, MAX_JSONL_LINE_BYTES); cap(records.length + 1, MAX_RECORDS);
    const value = parseSnapshotJSON(bytes.subarray(start, i), MAX_JSONL_LINE_BYTES); start = i + 1;
    requireSnapshot(value !== null && typeof value === "object" && !Array.isArray(value));
    const r = value as Record<string, unknown>;
    if (r.type === RECORD.extension) { text(r.extension_id, EXTENSION_ID); records.push(r as AuditRecord); continue; }
    requireSnapshot(typeof r.type === "string" && Object.hasOwn(AUDIT_FIELDS, r.type));
    const fields = AUDIT_FIELDS[r.type as keyof typeof AUDIT_FIELDS]; object(r, fields.required, fields.optional);
    if (r.type === RECORD.entry) {
      integer(r.seq, true); requireSnapshot(r.schema_version === AUDIT_CHAIN_SCHEMA_VERSION); text(r.entry_hash, HEX); text(r.prev_hash); requireSnapshot(r.prev_hash === AUDIT_CHAIN_GENESIS || HEX.test(r.prev_hash)); timestamp(r.timestamp); base64(r.encrypted_payload_bytes);
    } else if (r.type === RECORD.rotation) {
      integer(r.base_sequence, true); text(r.base_prev_hash, HEX); if (r.mac !== undefined) base64(r.mac, KEY_BYTES);
    } else {
      if (r.type === RECORD.checkpoint) requireSnapshot(r.checkpoint_kind === PIN_ROLE.audit);
      integer(r.checkpoint_sequence, true); integer(r.from_sequence, true); integer(r.previous_checkpoint_sequence); text(r.root_hash, HEX); timestamp(r.signed_at);
      requireSnapshot(r.from_sequence <= r.checkpoint_sequence && r.previous_checkpoint_sequence < r.checkpoint_sequence);
      requireSnapshot(typeof r.unsigned === "boolean");
      if (r.unsigned) requireSnapshot(r.signature === null && r.signer_kid === null && !Object.hasOwn(r, "public_key"));
      else { base64(r.signature, SIGNATURE_BYTES); publicKey(r.public_key); text(r.signer_kid); }
    }
    records.push(r as unknown as AuditRecord);
  }
  requireSnapshot(records.length > 0, HARD.nested_invalid); return records;
}
const TRANSPARENCY_FIELDS = ["checkpoint_kind", "schema_version", "counter", "previous_checkpoint_hash", "issued_at", "fortress_id", "audit", "policy", "daemon", "enforcement", "signer_kid", "signature", "signature_algorithm", "payload_encoding", "public_key"];
// The existing nested validator owns its frozen format; this table only closes extra fields.
export function parseTransparency(bytes: Uint8Array): { format: string; exported_at: string; public_key: string; checkpoints: VerifierCheckpointRecord[] } {
  return nestedSchema(() => parseTransparencyBody(bytes));
}
function parseTransparencyBody(bytes: Uint8Array): ReturnType<typeof parseTransparency> {
  const b = object(parseSnapshotJSON(bytes, MAX_FILE_BYTES), ["format", "exported_at", "public_key", "checkpoints"]);
  // The nested bundle must name the supported transparency wire format.
  requireSnapshot(b.format === TRANSPARENCY_BUNDLE_FORMAT, HARD.nested_invalid); timestamp(b.exported_at); publicKey(b.public_key); array(b.checkpoints, MAX_RECORDS); requireSnapshot(b.checkpoints.length > 0);
  for (const candidate of b.checkpoints) {
    const c = object(candidate, TRANSPARENCY_FIELDS); requireSnapshot(isVerifierCheckpointRecord(c)); timestamp(c.issued_at); publicKey(c.public_key); base64(c.signature, SIGNATURE_BYTES);
    object(c.audit, ["merkle_root", "lowest_sequence", "highest_sequence", "head_hash", "entry_count"]); object(c.policy, ["rules_sha256", "rules_count", "manifest_sha256"]); object(c.daemon, ["version", "binary_sha256"]);
    const e = object(c.enforcement, ["total_allowed", "total_blocked", "rules"]); array(e.rules, MAX_RECORDS);
    for (const rule of e.rules) object(rule, ["rule_label", "allowed", "blocked"]);
  }
  return b as unknown as ReturnType<typeof parseTransparency>;
}
export interface CapturedStat { type: string; dev: string; ino: string; size: number; nlink: number; mtime: string; ctime: string }
export function validateCapturedStat(value: CapturedStat): void {
  const r = object(value, ["type", "dev", "ino", "size", "nlink", "mtime", "ctime"]);
  text(r.type); text(r.dev); text(r.ino); text(r.mtime); text(r.ctime); integer(r.size); integer(r.nlink, true);
}
export interface CapturedFile { name: Uint8Array; bytes: Uint8Array; before: CapturedStat; after: CapturedStat; metadata: readonly string[] }
/** Observations are adapter evidence; full runtime adapter typing belongs to slice 3. */
export interface CapturedSnapshot { files: readonly CapturedFile[]; rootBefore: CapturedStat; rootAfter: CapturedStat; finalNames: readonly Uint8Array[]; rootMetadata: readonly string[] }
export interface NestedReport { state?: "absent"; reason?: string; verdict?: SnapshotStatus; findings?: string[]; entries_verified?: number; checkpoints_verified?: number; signatures_verified?: number; signature_basis?: string; not_checked?: readonly string[] }
/**
 * Exit 0 iff PASS iff accepted; partial_reasons is nonempty iff PARTIAL.
 * FAIL has at least one finding and empty partial_reasons; nested reports on FAIL are diagnostic only.
 */
export interface VerificationResult { format: typeof RESULT_FORMAT; status: SnapshotStatus; exit_code: number; accepted: boolean; snapshot_integrity: typeof INTEGRITY[keyof typeof INTEGRITY]; export_id: string | null; manifest_digest: string | null; verifier_source_revision: string; findings: { code: HardCode; state: ProtocolState; filename: string | null }[]; partial_reasons: PartialReason[]; nested: { audit: NestedReport | null; transparency: NestedReport | null }; not_checked: readonly string[] }
