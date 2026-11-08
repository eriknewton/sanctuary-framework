import { describe, expect, it } from "vitest";
import { rotateKeys } from "../../src/core/identity.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import { joinSnapshotVerdict, verifySnapshotTransparency, type NestedOutcome } from "../../src/evidence-pack/snapshot-nested.js";
import type { EntryExportRecord } from "../../src/cli/audit-chain-verify.js";
import { fixture, SOURCE, NOW, identity, encryptionKey, descriptorBytes, trustRow, replaceFile, refreshFiles, capturedFile, jsonBytes, auditBytes, syncAudit, transparencyExtent } from "./snapshot-fixtures.js";
const run = (f: ReturnType<typeof fixture>) => verifySnapshot(f.capture, f.pins, SOURCE);
function rejection(f: ReturnType<typeof fixture>, code: C.HardCode): C.VerificationResult {
  const r = run(f);
  expect([r.status, r.exit_code, r.accepted]).toEqual([C.STATUS.FAIL, C.EXIT_FAIL, false]);
  expect(r.findings[0].code).toBe(code);
  expect(r.partial_reasons).toEqual([]);
  return r;
}
function setPins(f: ReturnType<typeof fixture>, rows: C.TrustKey[]): void {
  f.pins.descriptorBytes = descriptorBytes(rows);
  replaceFile(f, C.TRUST_FILENAME, f.pins.descriptorBytes);
  refreshFiles(f);
}
function extension(f: ReturnType<typeof fixture>, signingRoles: string[]): void {
  f.capture.files = [...f.capture.files, capturedFile("future.bin", C.utf8("opaque"))];
  f.manifest.extensions = [{ id: "future", filenames: ["future.bin"], signing_roles: signingRoles }];
  refreshFiles(f);
}
describe("snapshot boundary witnesses", () => {
  it("bare pruned_root record is a hard nested failure", () => {
    const f = fixture();
    replaceFile(f, C.AUDIT_FILENAME, C.utf8(Buffer.from(auditBytes(f.records)).toString() + '{"type":"pruned_root"}\n'));
    refreshFiles(f); rejection(f, C.HARD.nested_invalid);
  });
  it("bogus component state is manifest_invalid", () => {
    const f = fixture(); Object.assign(f.manifest.components, { audit: { state: "bogus", reason: "no_records" } });
    f.capture.files = f.capture.files.filter(file => Buffer.from(file.name).toString() !== C.AUDIT_FILENAME);
    refreshFiles(f); rejection(f, C.HARD.manifest_invalid);
  });
  it.each(["captured", "final"])("lone-surrogate bytes in %s names are unsafe_path", where => {
    const f = fixture(); const invalid = new Uint8Array([0xed, 0xa0, 0x80, 0x2e, 0x62, 0x69, 0x6e]);
    if (where === "captured") f.capture.files[0].name = invalid;
    else f.capture.finalNames = [...f.capture.finalNames, invalid];
    rejection(f, C.HARD.unsafe_path);
  });
  it.each(["captured", "final"])("%s name byte length is capped before conversion", where => {
    const f = fixture(); const oversized = C.utf8("a".repeat(129));
    if (where === "captured") f.capture.files[0].name = oversized;
    else f.capture.finalNames = [...f.capture.finalNames, oversized];
    rejection(f, C.HARD.limit_exceeded);
  });
  it("name at the inclusive byte cap remains usable", () => {
    const f = fixture(); const name = "a".repeat(128); const role = C.PIN_ROLE.extension + "future";
    f.capture.files = [...f.capture.files, capturedFile(name, C.utf8("opaque"))];
    f.manifest.extensions = [{ id: "future", filenames: [name], signing_roles: [role] }];
    setPins(f, [...C.parseTrustDescriptor(f.pins.descriptorBytes).keys, trustRow(identity(), role)]);
    expect(run(f).status).toBe(C.STATUS.PARTIAL);
  });
  it("extension without signing roles is manifest_invalid", () => {
    const f = fixture(); extension(f, []); rejection(f, C.HARD.manifest_invalid);
  });
  it("extension signing role requires an independent descriptor pin", () => {
    const f = fixture(); extension(f, [C.PIN_ROLE.extension + "future"]);
    const r = rejection(f, C.HARD.pin_invalid);
    expect(r.findings[0].state).toBe(C.STATES.BYTES_VERIFIED);
    expect(r.nested).toEqual({ audit: null, transparency: null });
  });
  it.each(["retired signer", "identity mismatch"])("pack history rejects %s before nested work", kind => {
    const f = fixture(); const rows = C.parseTrustDescriptor(f.pins.descriptorBytes).keys;
    const old = trustRow(f.pack, C.PIN_ROLE.pack);
    if (kind === "retired signer") {
      const current = rotateKeys(f.pack, encryptionKey, "scheduled").updatedIdentity;
      old.rotation_evidence = trustRow(current, C.PIN_ROLE.pack).rotation_evidence;
    } else {
      if (old.rotation_evidence.kind !== C.ROTATION.history) throw new Error();
      old.rotation_evidence.identity_id = "f".repeat(32);
    }
    setPins(f, [...rows.filter(row => row.role !== C.PIN_ROLE.pack), old]);
    const r = rejection(f, C.HARD.pin_invalid);
    expect(r.findings[0].state).toBe(C.STATES.BYTES_VERIFIED);
    expect(r.nested).toEqual({ audit: null, transparency: null });
  });
  it.each(["audit blank", "audit field", "transparency field", "transparency JSON"])("%s schema error is nested_invalid", kind => {
    const f = fixture(); let name: string = C.AUDIT_FILENAME; let bytes: Uint8Array;
    if (kind === "audit blank") bytes = C.utf8(Buffer.from(auditBytes(f.records)).toString() + C.LF);
    else if (kind === "audit field") { Object.assign(f.records[0], { extra: true }); bytes = auditBytes(f.records); }
    else {
      name = C.TRANSPARENCY_FILENAME;
      if (kind === "transparency field") { Object.assign(f.bundle.checkpoints[0], { extra: true }); bytes = jsonBytes(f.bundle); }
      else bytes = C.utf8("{");
    }
    replaceFile(f, name, bytes); refreshFiles(f);
    expect(rejection(f, C.HARD.nested_invalid).findings[0].filename).toBe(name);
  });
  it.each(["audit", "transparency"])("%s parser retains limit_exceeded", kind => {
    if (kind === "audit") expect(() => C.parseAuditRecords(new Uint8Array(C.MAX_JSONL_LINE_BYTES + 1).fill(32))).toThrow(C.HARD.limit_exceeded);
    else {
      const f = fixture(); Object.assign(f.bundle, { checkpoints: Array(C.MAX_RECORDS + 1).fill(null) });
      expect(() => C.parseTransparency(jsonBytes(f.bundle))).toThrow(C.HARD.limit_exceeded);
    }
  });
  it.each(["legacy", "rotation"])("duplicate %s anchors reject before partition verification", kind => {
    const f = fixture(); const entry = f.records[2] as EntryExportRecord;
    const anchor: C.AuditRecord = kind === "legacy"
      ? { type: C.RECORD.legacy, checkpoint_sequence: 1, from_sequence: 1, root_hash: entry.prev_hash, previous_checkpoint_sequence: 0, signed_at: NOW, unsigned: true, signature: null, signer_kid: null }
      : { type: C.RECORD.rotation, base_sequence: 2, base_prev_hash: entry.prev_hash };
    f.records = [anchor, ...f.records.slice(2)]; syncAudit(f);
    expect(run(f).status).toBe(C.STATUS.PARTIAL);
    f.records.unshift({ ...anchor }); syncAudit(f); rejection(f, C.HARD.nested_invalid);
  });
  it("two transparency pins reject before either nested verifier", () => {
    const f = fixture(); setPins(f, [...C.parseTrustDescriptor(f.pins.descriptorBytes).keys, trustRow(identity(), C.PIN_ROLE.transparency)]);
    const r = rejection(f, C.HARD.pin_invalid);
    expect(r.findings[0].state).toBe(C.STATES.BYTES_VERIFIED);
    expect(r.nested).toEqual({ audit: null, transparency: null });
  });
  it("direct transparency boundary rejects two pins with the genuine pin first", () => {
    const f = fixture(); const pins = [trustRow(f.transparency, C.PIN_ROLE.transparency), trustRow(identity(), C.PIN_ROLE.transparency)];
    expect(() => verifySnapshotTransparency(jsonBytes(f.bundle), transparencyExtent(f.bundle), pins)).toThrow(C.HARD.pin_invalid);
  });
  it("transparency parser pins the literal bundle format", () => {
    const f = fixture(); Object.assign(f.bundle, { format: "SOMETHING_ELSE" });
    expect(() => C.parseTransparency(jsonBytes(f.bundle))).toThrow(C.HARD.nested_invalid);
  });
  it.each(["format", "algorithm"])("unsupported descriptor %s keeps its code", kind => {
    const f = fixture(); const d = C.parseTrustDescriptor(f.pins.descriptorBytes);
    if (kind === "format") Object.assign(d, { format: "OTHER" });
    else Object.assign(d.keys[0], { algorithm: "OTHER" });
    f.pins.descriptorBytes = jsonBytes(d);
    const r = rejection(f, C.HARD.unsupported_format);
    expect(r.findings[0]).toMatchObject({ state: C.STATES.PIN_INPUTS, filename: null });
  });
  it.each(["digest", "type", "metadata", "size", "final stat"])("file-specific %s finding names the authenticated file", kind => {
    const f = fixture(); const file = f.capture.files.find(file => Buffer.from(file.name).toString() === C.PDF_FILENAME)!;
    let code: C.HardCode = C.HARD.snapshot_changed;
    if (kind === "digest") { file.bytes[0] ^= 1; code = C.HARD.file_digest_mismatch; }
    if (kind === "type") { file.before.type = "symlink"; code = C.HARD.file_type_invalid; }
    if (kind === "metadata") { file.metadata = ["xattr"]; code = C.HARD.unexpected_metadata; }
    if (kind === "size") file.after.size++;
    if (kind === "final stat") file.after.ino += "changed";
    expect(rejection(f, code).findings[0].filename).toBe(C.PDF_FILENAME);
  });
  it("all statuses obey the result invariant", () => {
    for (const status of Object.values(C.STATUS)) {
      const f = fixture();
      if (status === C.STATUS.PARTIAL) { f.bundle.checkpoints.shift(); replaceFile(f, C.TRANSPARENCY_FILENAME, jsonBytes(f.bundle)); f.manifest.components.transparency = { state: C.COMPONENT.included, filename: C.TRANSPARENCY_FILENAME, extent: transparencyExtent(f.bundle) }; refreshFiles(f); }
      if (status === C.STATUS.FAIL) f.capture.files[0].bytes[0] ^= 1;
      const r = run(f); expect(r.status).toBe(status);
      expect(r.exit_code === 0).toBe(status === C.STATUS.PASS);
      expect(r.accepted).toBe(status === C.STATUS.PASS);
      expect(r.partial_reasons.length > 0).toBe(status === C.STATUS.PARTIAL);
      expect(r.findings.length > 0).toBe(status === C.STATUS.FAIL);
      if (status === C.STATUS.FAIL) expect(r.partial_reasons).toEqual([]);
    }
  });
  it.each(["audit state", "transparency state", "audit verdict", "transparency verdict", "record kinds", "missing kinds", "extensions"])("positive join refuses missing reasons for %s", kind => {
    const f = fixture();
    const a: NestedOutcome = { report: { verdict: C.STATUS.PASS }, partial: [], recordKinds: [C.RECORD.entry, C.RECORD.checkpoint] };
    const t: NestedOutcome = { report: { verdict: C.STATUS.PASS }, partial: [] };
    if (kind === "audit state") f.manifest.components.audit = { state: C.COMPONENT.empty_verified, reason: "no_records" };
    if (kind === "transparency state") f.manifest.components.transparency = { state: C.COMPONENT.read_failed, reason: "read_error" };
    if (kind === "audit verdict") a.report.verdict = C.STATUS.FAIL;
    if (kind === "transparency verdict") t.report.verdict = C.STATUS.PARTIAL;
    if (kind === "record kinds") a.recordKinds = [C.RECORD.extension];
    if (kind === "missing kinds") delete a.recordKinds;
    if (kind === "extensions") f.manifest.extensions = [{ id: "future", filenames: ["future.bin"], signing_roles: ["extension:future"] }];
    expect(() => joinSnapshotVerdict([], f.manifest, a, t)).toThrow(C.HARD.nested_invalid);
  });
});
