import { createIdentity, sign, type StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { computeAuditEntryHash, computeAuditRoot, checkpointSigningBytes } from "../../src/audit/chain.js";
import { checkpointSigningBytes as transparencySigningBytes, checkpointPayloadOf, computeCheckpointHash, TRANSPARENCY_BUNDLE_FORMAT, type EnforcementCheckpointRecord, type TransparencyBundle } from "../../src/transparency/checkpoint.js";
import { checkpointPayloadHash } from "../../src/transparency/verify.js";
import type { EntryExportRecord, CheckpointExportRecord } from "../../src/cli/audit-chain-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { auditExtent } from "../../src/evidence-pack/snapshot-nested.js";
import type { SnapshotPins } from "../../src/evidence-pack/snapshot-trust.js";
export const NOW = "2026-10-02T00:00:00.000Z";
export const SOURCE = "6e1e47d4b2ce59b053db3830183bd714eeb606c1";
export const master = new Uint8Array(32).fill(7);
export const encryptionKey = derivePurposeKey(master, "identity-encryption");
export function identity(): StoredIdentity { return createIdentity("synthetic snapshot fixture", encryptionKey, "passphrase").storedIdentity; }
export function signBytes(bytes: Uint8Array, who: StoredIdentity): string { return Buffer.from(sign(bytes, who.encrypted_private_key, encryptionKey)).toString("base64url"); }
export function trustRow(who: StoredIdentity, role: string): C.TrustKey {
  const fingerprint = C.manifestDigest(Buffer.from(who.public_key, "base64url"));
  return { role, key_id: fingerprint, fingerprint, algorithm: C.ALGORITHM, public_key_base64url: who.public_key, rotation_evidence: role === C.PIN_ROLE.transparency ? { kind: C.ROTATION.oob } : { kind: C.ROTATION.history, identity_id: who.identity_id, current_public_key: who.public_key, history: who.rotation_history.map(h => ({ old_public_key: h.old_public_key, new_public_key: h.new_public_key, rotation_event: h.rotation_event, rotated_at: h.rotated_at })) } };
}
export function descriptorBytes(keys: C.TrustKey[]): Uint8Array { return jsonBytes({ format: C.TRUST_FORMAT, keys: [...keys].sort((a, b) => (a.role + ":" + a.key_id) < (b.role + ":" + b.key_id) ? -1 : 1) }); }
export function jsonBytes(value: unknown): Uint8Array { return C.utf8(JSON.stringify(value, null, 2) + C.LF); }
export function auditBytes(records: readonly C.AuditRecord[]): Uint8Array { return C.utf8(records.map(r => JSON.stringify(r)).join(C.LF) + C.LF); }
export function auditFixture(keys: StoredIdentity[]): C.AuditRecord[] {
  const records: C.AuditRecord[] = []; let prev = "GENESIS";
  for (let i = 0; i < keys.length; i++) {
    const entry: EntryExportRecord = { type: "entry", seq: i + 1, schema_version: 2, prev_hash: prev, entry_hash: "", timestamp: NOW, encrypted_payload_bytes: "AQ" };
    entry.entry_hash = computeAuditEntryHash({ sequence: entry.seq, schema_version: entry.schema_version, prev_hash: prev, timestamp: NOW, encrypted_payload_bytes: entry.encrypted_payload_bytes }); prev = entry.entry_hash;
    const payload = { checkpoint_kind: "audit-checkpoint" as const, checkpoint_sequence: i + 1, from_sequence: i + 1, root_hash: computeAuditRoot([entry.entry_hash]), previous_checkpoint_sequence: i, signed_at: NOW };
    const cp: CheckpointExportRecord = { type: "checkpoint", ...payload, signer_kid: keys[i].identity_id, signature: signBytes(checkpointSigningBytes(payload), keys[i]), public_key: keys[i].public_key, unsigned: false };
    records.push(entry, cp);
  }
  return records;
}
export function transparencyFixture(who: StoredIdentity): TransparencyBundle {
  const checkpoints: EnforcementCheckpointRecord[] = []; let prev = "GENESIS";
  for (let counter = 1; counter <= 2; counter++) {
    const payload = { checkpoint_kind: "enforcement-checkpoint" as const, schema_version: 1 as const, counter, previous_checkpoint_hash: prev, issued_at: NOW, fortress_id: who.identity_id, audit: { merkle_root: "a".repeat(64), lowest_sequence: 1, highest_sequence: 2, head_hash: "b".repeat(64), entry_count: 2 }, policy: { rules_sha256: "c".repeat(64), rules_count: 0, manifest_sha256: null }, daemon: { version: "synthetic", binary_sha256: "d".repeat(64) }, enforcement: { total_allowed: 0, total_blocked: 0, rules: [] } };
    checkpoints.push({ ...payload, signer_kid: who.identity_id, signature: signBytes(transparencySigningBytes(payload), who), signature_algorithm: "Ed25519", payload_encoding: "domain-separated-canonical-json-v1", public_key: who.public_key }); prev = computeCheckpointHash(payload);
  }
  return { format: TRANSPARENCY_BUNDLE_FORMAT, exported_at: NOW, public_key: who.public_key, checkpoints };
}
export function resignCheckpoint(cp: CheckpointExportRecord, who: StoredIdentity): void {
  const { checkpoint_kind, checkpoint_sequence, from_sequence, root_hash, previous_checkpoint_sequence, signed_at } = cp;
  cp.signature = signBytes(checkpointSigningBytes({ checkpoint_kind, checkpoint_sequence, from_sequence, root_hash, previous_checkpoint_sequence, signed_at }), who);
}
export function resignTransparency(cp: EnforcementCheckpointRecord, who: StoredIdentity): void { cp.signature = signBytes(transparencySigningBytes(checkpointPayloadOf(cp)), who); }
export function stat(size: number, type = C.FILE_TYPE.file as string): C.CapturedStat { return { type, size, nlink: 1, dev: "1", ino: "1", mtime: NOW, ctime: NOW }; }
export function capturedFile(name: string, bytes: Uint8Array): C.CapturedFile { return { name: C.utf8(name), bytes, before: stat(bytes.length), after: stat(bytes.length), metadata: [] }; }
export interface Fixture { pack: StoredIdentity; audit: StoredIdentity; secondAudit: StoredIdentity; transparency: StoredIdentity; records: C.AuditRecord[]; bundle: TransparencyBundle; manifest: C.SnapshotManifest; capture: C.CapturedSnapshot; pins: SnapshotPins }
export function fixture(): Fixture {
  const pack = identity(), audit = identity(), secondAudit = identity(), transparency = identity();
  const records = auditFixture([audit, secondAudit]); const bundle = transparencyFixture(transparency);
  const trust = descriptorBytes([trustRow(pack, C.PIN_ROLE.pack), trustRow(audit, C.PIN_ROLE.audit), trustRow(secondAudit, C.PIN_ROLE.audit), trustRow(transparency, C.PIN_ROLE.transparency)]);
  const manifest: C.SnapshotManifest = { format: C.SNAPSHOT_FORMAT, signature_scheme: C.SIGNATURE_SCHEME, hash_algorithm: C.HASH_ALGORITHM, export_id: "12345678-1234-4123-8123-123456789012", generated_at: NOW, source_revision: SOURCE, signer: { identity_id: pack.identity_id, public_key_base64url: pack.public_key }, files: [], components: { audit: { state: C.COMPONENT.included, filename: C.AUDIT_FILENAME, extent: auditExtent(records) }, transparency: { state: C.COMPONENT.included, filename: C.TRANSPARENCY_FILENAME, extent: transparencyExtent(bundle) } }, extensions: [], manifest_signature: "" };
  const files = [capturedFile(C.REPORT_FILENAME, C.utf8("Synthetic report")), capturedFile(C.PDF_FILENAME, new Uint8Array([37, 80, 68, 70, 255, 0, 128])), capturedFile(C.RECIPIENT_FILENAME, C.utf8("Synthetic recipient procedure")), capturedFile(C.TRUST_FILENAME, trust), capturedFile(C.AUDIT_FILENAME, auditBytes(records)), capturedFile(C.TRANSPARENCY_FILENAME, jsonBytes(bundle))];
  const capture: C.CapturedSnapshot = { files, rootBefore: stat(0, C.FILE_TYPE.directory), rootAfter: stat(0, C.FILE_TYPE.directory), finalNames: [], rootMetadata: [] };
  const f: Fixture = { pack, audit, secondAudit, transparency, records, bundle, manifest, capture, pins: { packKey: pack.public_key, descriptorBytes: trust.slice(), expectedManifestDigest: "" } };
  refreshFiles(f); return f;
}
export function transparencyExtent(bundle: TransparencyBundle): C.TransparencyExtent { const c = bundle.checkpoints; return { checkpoint_count: c.length, first_counter: c[0].counter, last_counter: c.at(-1)!.counter, last_checkpoint_payload_sha256: checkpointPayloadHash(c.at(-1)!), fortress_id: c[0].fortress_id }; }
export function refreshFiles(f: Fixture): void {
  f.manifest.files = f.capture.files.filter(file => Buffer.from(file.name).toString() !== C.MANIFEST_FILENAME).map(file => {
    const filename = Buffer.from(file.name).toString(); const role = Object.entries(C.FIXED_FILES).find(([, pair]) => pair[0] === filename)?.[0] as C.SnapshotFile["role"] | undefined;
    return { filename, content_type: role && role !== C.ROLE.extension ? C.FIXED_FILES[role][1] : C.EXTENSION_MIME, size_bytes: file.bytes.length, sha256: C.sha256Hex(file.bytes), role: role ?? C.ROLE.extension };
  }).sort((a, b) => a.filename < b.filename ? -1 : 1); resignManifest(f);
}
export function resignManifest(f: Fixture, signBody = true): void {
  if (signBody) { f.manifest.manifest_signature = signBytes(C.manifestSigningBytes(f.manifest as unknown as Record<string, unknown>), f.pack); }
  const bytes = jsonBytes(f.manifest);
  f.capture.files = [...f.capture.files.filter(file => Buffer.from(file.name).toString() !== C.MANIFEST_FILENAME), capturedFile(C.MANIFEST_FILENAME, bytes)];
  f.capture.finalNames = f.capture.files.map(file => file.name.slice()); f.pins.expectedManifestDigest = C.manifestDigest(bytes);
}
export function replaceFile(f: Fixture, name: string, bytes: Uint8Array): void { f.capture.files = f.capture.files.map(file => Buffer.from(file.name).toString() === name ? capturedFile(name, bytes) : file); }
export function syncAudit(f: Fixture): void { replaceFile(f, C.AUDIT_FILENAME, auditBytes(f.records)); f.manifest.components.audit = { state: C.COMPONENT.included, filename: C.AUDIT_FILENAME, extent: auditExtent(f.records) }; refreshFiles(f); }
export function syncTransparency(f: Fixture): void { replaceFile(f, C.TRANSPARENCY_FILENAME, jsonBytes(f.bundle)); f.manifest.components.transparency = { state: C.COMPONENT.included, filename: C.TRANSPARENCY_FILENAME, extent: transparencyExtent(f.bundle) }; refreshFiles(f); }
export async function exporterFixture() {
  const { mkdtemp } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { exportDependencies } = await import("../../src/evidence-pack/snapshot-export-cli.js");
  const f = fixture(); const root = await mkdtemp(join(tmpdir(), "snapshot-"));
  const options = { fortress: join(root, "fortress"), output: join(root, "pack"), receipt: join(root, "receipt.json"), publicKeyFile: join(root, "key.txt") };
  const states: string[] = [], stdout: string[] = [], stderr: string[] = [];
  const identities = [f.pack, f.audit, f.secondAudit]; let cleanupCount = 0;
  const gathered: import("../../src/evidence-pack/snapshot-gather.js").SnapshotGather = { audit: f.manifest.components.audit, transparency: f.manifest.components.transparency, auditBytes: auditBytes(f.records), transparencyBytes: jsonBytes(f.bundle), transparencyPin: { key: f.transparency.public_key, pathClass: "fortress-local" } };
  const deps: import("../../src/evidence-pack/snapshot-export-cli.js").ExportDependencies = { ...exportDependencies, runtimeRevision: SOURCE, buildRevision: SOURCE, boot: async () => ({ config: { storage_path: options.fortress }, identityManager: { getDefault: () => f.pack, list: () => identities, get: (id: string) => identities.find(i => i.identity_id === id) }, masterKey: master, cleanup: async () => { cleanupCount++; } }) as unknown as Awaited<ReturnType<typeof exportDependencies.boot>>, gather: async () => gathered, phase: async state => { states.push(state); }, io: { stdout: text => { stdout.push(text); }, stderr: text => { stderr.push(text); } } };
  return { f, root, options, deps, gathered, states, stdout, stderr, cleanupCount: () => cleanupCount };
}
