import { describe, it, expect } from "vitest";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import { fixture, SOURCE, replaceFile, resignManifest, refreshFiles, capturedFile, identity, descriptorBytes, trustRow, jsonBytes } from "./snapshot-fixtures.js";
const run = (f: ReturnType<typeof fixture>) => verifySnapshot(f.capture, f.pins, SOURCE);
function rejected(f: ReturnType<typeof fixture>, code: C.HardCode) { const r = run(f); expect([r.status, r.exit_code, r.accepted]).toEqual([C.STATUS.FAIL, C.EXIT_FAIL, false]); expect(r.findings[0].code).toBe(code); }
describe("snapshot-verify", () => {
  it("clean real producer signatures accept with independent pins", () => { const r = run(fixture()); expect(r.findings).toEqual([]); expect([r.status, r.exit_code, r.accepted, r.snapshot_integrity]).toEqual([C.STATUS.PASS, 0, true, C.INTEGRITY.verified]); });
  it("signature gate rejects edited body with recalculated expected digest", () => { const f = fixture(); f.manifest.generated_at = "2026-10-03T00:00:00.000Z"; resignManifest(f, false); rejected(f, C.HARD.manifest_signature_invalid); });
  it("embedded equality rejects a pin signature naming another key", () => { const f = fixture(); f.manifest.signer.public_key_base64url = identity().public_key; resignManifest(f); rejected(f, C.HARD.embedded_key_mismatch); });
  it("consistent wrong key and descriptor reach the signature gate", () => { const f = fixture(), other = identity(); f.pins.packKey = other.public_key; f.pins.descriptorBytes = descriptorBytes([trustRow(other, C.PIN_ROLE.pack)]); rejected(f, C.HARD.manifest_signature_invalid); });
  it("exact manifest whitespace changes the expected snapshot", () => { const f = fixture(); const file = f.capture.files.find(f => Buffer.from(f.name).toString() === C.MANIFEST_FILENAME)!; replaceFile(f, C.MANIFEST_FILENAME, C.utf8(Buffer.from(file.bytes).toString() + C.LF)); rejected(f, C.HARD.manifest_digest_mismatch); });
  it.each(["other", "stale"])("%s valid same-key pack passes own digest and rejects selected digest", kind => { const f = fixture(); const expected = f.pins.expectedManifestDigest; f.manifest.export_id = "12345678-1234-4123-8123-123456789013"; if (kind === "stale") f.manifest.generated_at = "2026-09-01T00:00:00.000Z"; resignManifest(f); expect(run(f).status).toBe(C.STATUS.PASS); f.pins.expectedManifestDigest = expected; rejected(f, C.HARD.manifest_digest_mismatch); });
  it("legacy format is diagnosed before signature verification", () => { const f = fixture(); replaceFile(f, C.MANIFEST_FILENAME, jsonBytes({ pack_version: "0.1-preview" })); rejected(f, C.HARD.unsupported_format); expect(run(f).findings[0].state).toBe(C.STATES.MANIFEST_BYTES); });
  it.each([C.REPORT_FILENAME, C.PDF_FILENAME, C.TRUST_FILENAME, C.RECIPIENT_FILENAME, C.AUDIT_FILENAME, C.TRANSPARENCY_FILENAME])("byte edit of %s rejects", name => { const f = fixture(); const file = f.capture.files.find(f => Buffer.from(f.name).toString() === name)!; file.bytes[0] ^= 1; rejected(f, C.HARD.file_digest_mismatch); });
  it("invalid UTF-8 binary pair cannot collide through decoding", () => { const f = fixture(); replaceFile(f, C.PDF_FILENAME, new Uint8Array([255])); refreshFiles(f); expect(run(f).status).toBe(C.STATUS.PASS); replaceFile(f, C.PDF_FILENAME, new Uint8Array([254])); rejected(f, C.HARD.file_digest_mismatch); });
  it("signed false size fails even with a correct hash", () => { const f = fixture(); f.manifest.files.find(f => f.role === C.ROLE.pdf)!.size_bytes++; resignManifest(f); rejected(f, C.HARD.file_digest_mismatch); });
  it.each([C.REPORT_FILENAME, C.PDF_FILENAME, C.TRUST_FILENAME, C.RECIPIENT_FILENAME, C.AUDIT_FILENAME, C.TRANSPARENCY_FILENAME])("missing required %s rejects", name => { const f = fixture(); f.capture.files = f.capture.files.filter(f => Buffer.from(f.name).toString() !== name); rejected(f, C.HARD.file_set_mismatch); });
  it.each([".DS_Store", "._evidence-pack.pdf", "receipt.json", "log.txt", "Evidence-pack.pdf"])("unlisted exact-byte name %s rejects", name => { const f = fixture(); f.capture.files = [...f.capture.files, capturedFile(name, C.utf8("extra"))]; rejected(f, C.OS_METADATA.test(name) ? C.HARD.unlisted_os_metadata : C.HARD.file_set_mismatch); });
  it("case-variant replacement fails", () => { const f = fixture(); f.capture.files.find(f => Buffer.from(f.name).toString() === C.PDF_FILENAME)!.name = C.utf8("Evidence-pack.pdf"); rejected(f, C.HARD.file_set_mismatch); });
  it.each(["symlink", "fifo", "device", "directory"])("%s is never a regular evidence file", type => { const f = fixture(); const file = f.capture.files[0]; file.before.type = type; file.after.type = type; rejected(f, C.HARD.file_type_invalid); });
  it("hardlink is rejected", () => { const f = fixture(); f.capture.files[0].before.nlink = 2; f.capture.files[0].after.nlink = 2; rejected(f, C.HARD.file_type_invalid); });
  it("root symlink is rejected", () => { const f = fixture(); f.capture.rootBefore.type = "symlink"; rejected(f, C.HARD.file_type_invalid); });
  it.each(["ino", "dev", "mtime", "ctime"] as const)("changed file %s fails final recheck", field => { const f = fixture(); f.capture.files[0].after[field] += "changed"; rejected(f, C.HARD.snapshot_changed); expect(run(f).findings[0].state).toBe(C.STATES.FINAL_RECHECK); });
  it("changed root fails final recheck", () => { const f = fixture(); f.capture.rootAfter.ino = "new"; rejected(f, C.HARD.snapshot_changed); });
  it("changed final inventory fails final recheck", () => { const f = fixture(); f.capture.finalNames = [...f.capture.finalNames, C.utf8("new")]; rejected(f, C.HARD.snapshot_changed); });
  it("captured size change fails", () => { const f = fixture(); f.capture.files[0].after.size++; rejected(f, C.HARD.snapshot_changed); });
  it.each(["xattr", "resource-fork"])("nonempty %s fails", meta => { const f = fixture(); f.capture.files[0].metadata = [meta]; rejected(f, C.HARD.unexpected_metadata); });
  it("root metadata fails", () => { const f = fixture(); f.capture.rootMetadata = ["xattr"]; rejected(f, C.HARD.unexpected_metadata); });
  it("exceptions are terminal FAIL", () => { const f = fixture(); Object.defineProperty(f.capture, "files", { get() { throw new Error("hostile raw exception"); } }); rejected(f, C.HARD.io_error); expect(JSON.stringify(run(f))).not.toContain("hostile raw exception"); });
  it("unknown signed field is authenticated rather than dropped by canonicalization", () => { const f = fixture(); Object.assign(f.manifest, { unknown: "changed" }); resignManifest(f, false); rejected(f, C.HARD.manifest_signature_invalid); });
  it("signed unknown field requires a new format", () => { const f = fixture(); Object.assign(f.manifest, { unknown: true }); resignManifest(f); rejected(f, C.HARD.manifest_invalid); });
  it("both absent components are PARTIAL with exact state reasons", () => { const f = fixture(); f.manifest.components = { audit: { state: C.COMPONENT.empty_verified, reason: "no_records" }, transparency: { state: C.COMPONENT.read_failed, reason: "read_error" } }; f.capture.files = f.capture.files.filter(file => ![C.AUDIT_FILENAME, C.TRANSPARENCY_FILENAME].includes(Buffer.from(file.name).toString())); refreshFiles(f); const r = run(f); expect([r.status, r.exit_code, r.accepted, r.snapshot_integrity]).toEqual([C.STATUS.PARTIAL, 10, false, C.INTEGRITY.bytes_match]); expect(r.partial_reasons).toEqual([C.PARTIAL.audit_absent, C.PARTIAL.audit_empty_verified, C.PARTIAL.transparency_absent, C.PARTIAL.transparency_read_failed].sort()); });
  it("unknown extension payload forces PARTIAL", () => { const f = fixture(); f.capture.files = [...f.capture.files, capturedFile("future.bin", C.utf8("opaque"))]; f.manifest.extensions = [{ id: "future", filenames: ["future.bin"], signing_roles: [C.PIN_ROLE.extension + "future"] }]; f.pins.descriptorBytes = descriptorBytes([...C.parseTrustDescriptor(f.pins.descriptorBytes).keys, trustRow(identity(), C.PIN_ROLE.extension + "future")]); replaceFile(f, C.TRUST_FILENAME, f.pins.descriptorBytes); refreshFiles(f); expect(run(f).partial_reasons).toEqual([C.PARTIAL.extension_unverified]); expect(run(f).status).toBe(C.STATUS.PARTIAL); });
});

const osLabels = ["com.apple.provenance", "com.apple.quarantine", "security.selinux"];
const metadataNotice = "OS-attached file metadata (provenance, quarantine, security label) is outside the signed set.";
it.each(["PASS", "PARTIAL"])("OS labels preserve %s and disclose one fixed unsigned scope", status => {
  const f = fixture();
  if (status === "PARTIAL") {
    f.manifest.components.audit = { state: C.COMPONENT.empty_verified, reason: "no_records" };
    f.capture.files = f.capture.files.filter(file => Buffer.from(file.name).toString() !== C.AUDIT_FILENAME); refreshFiles(f);
  }
  const before = run(f); expect(before.status).toBe(status); expect(before.not_checked).not.toContain(metadataNotice);
  f.capture.rootMetadata = osLabels;
  for (const file of f.capture.files) file.metadata = osLabels;
  const after = run(f);
  expect(after).toEqual({ ...before, not_checked: [...before.not_checked, metadataNotice] });
});
it.each(["root", "file"])("OS labels on only %s disclose scope", location => {
  const f = fixture();
  if (location === "root") f.capture.rootMetadata = osLabels; else f.capture.files[0].metadata = osLabels;
  expect(run(f)).toMatchObject({ status: "PASS", findings: [], not_checked: [...C.NOT_CHECKED, metadataNotice] });
});
it.each(osLabels.flatMap(allowed => ["root", "file"].map(location => ({ allowed, location }))))("OS label $allowed with unknown metadata on $location refuses", ({ allowed, location }) => {
  const f = fixture(), names = [allowed, "user.private-sentinel"];
  if (location === "root") f.capture.rootMetadata = names; else f.capture.files[0].metadata = names;
  rejected(f, C.HARD.unexpected_metadata);
  expect(JSON.stringify(run(f))).not.toContain("private-sentinel");
});
it.each(["com.apple.ResourceFork", "com.apple.FinderInfo", "Com.apple.provenance", "com.apple.quarantine ", "security.selinux\0"].flatMap(name => ["root", "file"].map(location => ({ name, location }))))("exact metadata name $name on $location refuses", ({ name, location }) => {
  const f = fixture();
  if (location === "root") f.capture.rootMetadata = [name]; else f.capture.files[0].metadata = [name];
  rejected(f, C.HARD.unexpected_metadata);
});
