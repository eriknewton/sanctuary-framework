/** Every acceptance assertion crosses the packed and installed command boundary. */
import { beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, unlinkSync, renameSync, symlinkSync, linkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { functionalCandidateForTests } from "./snapshot-artifact-fixtures.js";
import { fixture, refreshFiles, resignManifest, resignCheckpoint, NOW, syncAudit, syncTransparency, descriptorBytes, trustRow, identity, replaceFile, capturedFile, type Fixture } from "./snapshot-fixtures.js";
import { verifySnapshotAudit } from "../../src/evidence-pack/snapshot-nested.js";
import { validateSnapshotPins } from "../../src/evidence-pack/snapshot-trust.js";
import type { EntryExportRecord, CheckpointExportRecord } from "../../src/cli/audit-chain-verify.js";
import { computeAuditEntryHash, computeAuditRoot } from "../../src/audit/chain.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
let command: string;
const CHILD_TIMEOUT_MS = 30_000;
beforeAll(async () => { command = (await functionalCandidateForTests()).command; }, 120_000);
function delivery(f: Fixture) {
  const root = mkdtempSync(join(tmpdir(), "recipient-")), pack = join(root, "pack"); mkdirSync(pack);
  for (const file of f.capture.files) writeFileSync(join(pack, Buffer.from(file.name).toString()), file.bytes);
  writeFileSync(join(root, "key"), f.pins.packKey + "\n"); writeFileSync(join(root, "trust"), f.pins.descriptorBytes);
  return { root, pack, args: ["--pack", pack, "--public-key-file", join(root, "key"), "--trust-descriptor-file", join(root, "trust"), "--expect-manifest-digest", f.pins.expectedManifestDigest, "--json"] };
}
function check(d: ReturnType<typeof delivery>, status: string, exit: number, code?: string) {
  const child = spawnSync(process.env.EVIDENCE_PACK_TEST_NODE ?? process.execPath, [command, ...d.args], { env: { ...process.env, HOME: join(d.root, "no-home"), SANCTUARY_STORAGE_PATH: join(d.root, "no-storage") }, encoding: "utf8", timeout: CHILD_TIMEOUT_MS });
  expect(child.error).toBeUndefined(); expect(child.status, child.stderr + child.stdout).toBe(exit);
  const result = JSON.parse(child.stdout); expect(result).toMatchObject({ status, exit_code: exit, accepted: status === "PASS" });
  expect(result.partial_reasons.length > 0).toBe(status === "PARTIAL");
  if (code) expect(result.findings).toEqual(expect.arrayContaining([expect.objectContaining({ code })]));
  if (code === C.HARD.manifest_digest_mismatch) expect(result.findings[0].state).toBe(C.STATES.EXPECTED_SNAPSHOT);
  if (code === C.HARD.manifest_signature_invalid) expect(result.findings[0].state).toBe(C.STATES.MANIFEST_AUTHENTICATED);
  return result;
}
describe("installed selected-snapshot acceptance", () => {
  it("clean snapshot accepts with the authenticated export id", () => { const f = fixture(); expect(check(delivery(f), "PASS", 0).export_id).toBe(f.manifest.export_id); });
  it.each([C.MANIFEST_FILENAME, ...Object.values(C.FIXED_FILES).map(v => v[0])])("every delivered byte edit rejects %s", name => {
    const f = fixture(), d = delivery(f); check(d, "PASS", 0); const file = join(d.pack, name), bytes = readFileSync(file);
    if (name === C.MANIFEST_FILENAME) writeFileSync(file, Buffer.concat([bytes, Buffer.from("\n")])); else { bytes[0] ^= 1; writeFileSync(file, bytes); }
    check(d, "FAIL", 1, name === C.MANIFEST_FILENAME ? C.HARD.manifest_digest_mismatch : C.HARD.file_digest_mismatch);
  });
  it.each(Object.values(C.FIXED_FILES).map(v => v[0]))("removed required file rejects %s", name => { const d = delivery(fixture()); check(d, "PASS", 0); unlinkSync(join(d.pack, name)); check(d, "FAIL", 1, C.HARD.file_set_mismatch); });
  it("shortened signed audit retains a valid checkpoint prefix but rejects the selected pack", () => {
    const f = fixture(), d = delivery(f); check(d, "PASS", 0); f.records = f.records.slice(0, 2); syncAudit(f);
    const bytes = f.capture.files.find(x => Buffer.from(x.name).toString() === C.AUDIT_FILENAME)!.bytes;
    const component = f.manifest.components.audit; if (component.state !== "included") throw new Error("fixture");
    expect(verifySnapshotAudit(bytes, component.extent, validateSnapshotPins(f.pins).keys).report.verdict).toBe("PASS");
    writeFileSync(join(d.pack, C.AUDIT_FILENAME), bytes); check(d, "FAIL", 1, C.HARD.file_digest_mismatch);
  });
  it.each(["other", "stale"])("valid same-key %s snapshot passes its own pins and rejects current digest", kind => {
    const f = fixture(), current = delivery(f); check(current, "PASS", 0);
    if (kind === "other") { f.manifest.export_id = "22345678-1234-4123-8123-123456789012"; resignManifest(f); }
    else { f.records = f.records.slice(0, 2); syncAudit(f); }
    const alternate = delivery(f); check(alternate, "PASS", 0); alternate.args[7] = current.args[7]; check(alternate, "FAIL", 1, C.HARD.manifest_digest_mismatch);
  });
  it("wrong pack key rejects at pin inputs", () => { const d = delivery(fixture()); check(d, "PASS", 0); writeFileSync(join(d.root, "key"), identity().public_key); check(d, "FAIL", 1, C.HARD.pin_invalid); });
  it("consistent wrong key and wrong descriptor reach the signature gate", () => { const f = fixture(), d = delivery(f), wrong = identity(); check(d, "PASS", 0); writeFileSync(join(d.root, "key"), wrong.public_key); const descriptor = C.parseSnapshotJSON(f.pins.descriptorBytes, C.MAX_TRUST_BYTES) as { keys: C.TrustKey[] }; writeFileSync(join(d.root, "trust"), descriptorBytes([trustRow(wrong, C.PIN_ROLE.pack), ...descriptor.keys.filter(k => k.role !== C.PIN_ROLE.pack)])); check(d, "FAIL", 1, C.HARD.manifest_signature_invalid); });
  it("independent descriptor byte equality is mandatory", () => { const d = delivery(fixture()); check(d, "PASS", 0); writeFileSync(join(d.root, "trust"), Buffer.concat([readFileSync(join(d.root, "trust")), Buffer.from("\n")])); check(d, "FAIL", 1, C.HARD.descriptor_mismatch); });
  it.each([C.PIN_ROLE.audit, C.PIN_ROLE.transparency])("wrong role key rejects %s", role => {
    const f = fixture(); const descriptor = C.parseSnapshotJSON(f.pins.descriptorBytes, C.MAX_TRUST_BYTES) as { keys: C.TrustKey[] }; const bytes = descriptorBytes([...descriptor.keys.filter(k => k.role !== role), trustRow(identity(), role)]);
    replaceFile(f, C.TRUST_FILENAME, bytes); f.pins.descriptorBytes = bytes; refreshFiles(f); check(delivery(f), "FAIL", 1, C.HARD.pin_invalid);
  });
  it.each([".DS_Store", "hidden.log", "extra-directory", "case-name", "symlink", "hardlink"])("exhaustive typed inventory refuses %s", kind => {
    const d = delivery(fixture()); check(d, "PASS", 0);
    if (kind === "extra-directory") mkdirSync(join(d.pack, "extra"));
    else if (kind === "case-name") renameSync(join(d.pack, C.REPORT_FILENAME), join(d.pack, C.REPORT_FILENAME.toUpperCase()));
    else if (kind === "symlink" || kind === "hardlink") { const outside = join(d.root, "original"); renameSync(join(d.pack, C.REPORT_FILENAME), outside); (kind === "symlink" ? symlinkSync : linkSync)(outside, join(d.pack, C.REPORT_FILENAME)); }
    else writeFileSync(join(d.pack, kind), "unlisted");
    check(d, "FAIL", 1, kind === ".DS_Store" ? C.HARD.unlisted_os_metadata : ["symlink", "hardlink"].includes(kind) ? C.HARD.file_type_invalid : C.HARD.file_set_mismatch);
  });
  it("binary bytes differing only under replacement decoding reject", () => { const f = fixture(); replaceFile(f, C.PDF_FILENAME, new Uint8Array([255])); refreshFiles(f); const d = delivery(f); check(d, "PASS", 0); writeFileSync(join(d.pack, C.PDF_FILENAME), new Uint8Array([254])); check(d, "FAIL", 1, C.HARD.file_digest_mismatch); });
  it.each(["empty_verified", "read_failed"])("both components %s remain PARTIAL", state => { const f = fixture(); f.capture.files = f.capture.files.filter(x => ![C.AUDIT_FILENAME, C.TRANSPARENCY_FILENAME].includes(Buffer.from(x.name).toString())); const absent = state === "empty_verified" ? { state: C.COMPONENT.empty_verified, reason: "no_records" as const } : { state: C.COMPONENT.read_failed, reason: "read_error" as const }; f.manifest.components = { audit: absent, transparency: absent }; refreshFiles(f); check(delivery(f), "PARTIAL", 10); });
  it("unknown extension remains PARTIAL", () => { const f = fixture(); const role = "extension:future"; f.manifest.extensions = [{ id: "future", filenames: ["future.bin"], signing_roles: [role] }]; f.capture.files = [...f.capture.files, capturedFile("future.bin", C.utf8("opaque"))]; const descriptor = C.parseSnapshotJSON(f.pins.descriptorBytes, C.MAX_TRUST_BYTES) as { keys: C.TrustKey[] }; const bytes = descriptorBytes([...descriptor.keys, trustRow(f.pack, role)]); replaceFile(f, C.TRUST_FILENAME, bytes); f.pins.descriptorBytes = bytes; refreshFiles(f); check(delivery(f), "PARTIAL", 10); });
  it.each([false, true])("unsigned checkpoints with hard root mismatch %s preserve exact verdict", hard => { const f = fixture(); for (const r of f.records) if (r.type === "checkpoint") { r.unsigned = true; r.signature = null; r.signer_kid = null; delete r.public_key; if (hard) r.root_hash = "f".repeat(64); } syncAudit(f); check(delivery(f), hard ? "FAIL" : "PARTIAL", hard ? 1 : 10, hard ? C.HARD.nested_invalid : undefined); });
  it("transparency suffix remains PARTIAL", () => { const f = fixture(); f.bundle.checkpoints = f.bundle.checkpoints.slice(1); syncTransparency(f); check(delivery(f), "PARTIAL", 10); });
  it("cross-partition previous hash break fails", () => { const f = fixture(); const r = f.records.find(x => x.type === "entry" && x.seq === 2)!; const e = r as EntryExportRecord; e.prev_hash = "f".repeat(64); e.entry_hash = computeAuditEntryHash({ sequence: e.seq, schema_version: e.schema_version, prev_hash: e.prev_hash, timestamp: e.timestamp, encrypted_payload_bytes: e.encrypted_payload_bytes }); const cp = f.records[3] as CheckpointExportRecord; cp.root_hash = computeAuditRoot([e.entry_hash]); resignCheckpoint(cp, f.secondAudit); syncAudit(f); check(delivery(f), "FAIL", 1, C.HARD.nested_invalid); });

  it.each(["legacy", "rotation"])("installed %s anchor keeps its explicit PARTIAL reason", kind => {
    const f = fixture(); const entry = f.records[2] as EntryExportRecord;
    f.records = kind === "legacy" ? [{ type: C.RECORD.legacy, checkpoint_sequence: 1, from_sequence: 1, root_hash: (f.records[0] as EntryExportRecord).entry_hash, previous_checkpoint_sequence: 0, signed_at: NOW, unsigned: true, signature: null, signer_kid: null }, ...f.records.slice(2)] : [{ type: C.RECORD.rotation, base_sequence: 2, base_prev_hash: entry.prev_hash }, ...f.records.slice(2)];
    const cp = f.records[2] as CheckpointExportRecord; cp.previous_checkpoint_sequence = kind === "legacy" ? 1 : 0; resignCheckpoint(cp, f.secondAudit); syncAudit(f);
    expect(check(delivery(f), "PARTIAL", 10).partial_reasons).toContain(kind === "legacy" ? C.PARTIAL.audit_legacy_anchor_unverified : C.PARTIAL.audit_rotation_anchor_unverified);
  });
  it("installed small-order key is refused", () => { const f = fixture(), d = delivery(f); const small = Buffer.alloc(C.KEY_BYTES); small[0] = 1; const key = small.toString("base64url"), row = trustRow(f.pack, C.PIN_ROLE.pack); row.public_key_base64url = key; row.fingerprint = row.key_id = C.manifestDigest(small); if (row.rotation_evidence.kind !== C.ROTATION.history) throw new Error("fixture"); row.rotation_evidence.current_public_key = key; writeFileSync(join(d.root, "key"), key); writeFileSync(join(d.root, "trust"), descriptorBytes([row])); check(d, "FAIL", 1, C.HARD.pin_invalid); });
  it("installed unknown signed member is authenticated before schema inspection", () => { const f = fixture(); Object.assign(f.manifest, { unknown: true }); resignManifest(f, false); check(delivery(f), "FAIL", 1, C.HARD.manifest_signature_invalid); });
  it("installed unreadable pack never becomes acceptance", () => { const d = delivery(fixture()); d.args[1] = join(d.root, "missing"); check(d, "FAIL", 1, C.HARD.io_error); });
});

it("installed whitespace key reports the pin finding", () => { const d = delivery(fixture()); writeFileSync(join(d.root, "key"), " " + readFileSync(join(d.root, "key"), "utf8")); check(d, "FAIL", C.EXIT_FAIL, C.HARD.pin_invalid); });
