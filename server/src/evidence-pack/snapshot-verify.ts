/** Pure verification of captured bytes and adapter observations, with no ambient lookup. */
import { verify } from "../core/identity.js";
import * as C from "./snapshot-contract.js";
import { validateSnapshotPins, bindSnapshotTrust, type SnapshotPins } from "./snapshot-trust.js";
import { verifySnapshotAudit, verifySnapshotTransparency, absentOutcome, joinSnapshotVerdict } from "./snapshot-nested.js";
function sameStat(a: C.CapturedStat, b: C.CapturedStat): boolean { return C.canonicalSnapshotJSON(a) === C.canonicalSnapshotJSON(b); }
function capturedName(name: Uint8Array): string {
  // Captured names are bounded before encoding and decode injectively without replacement or BOM stripping.
  C.cap(name.byteLength, C.MAX_NAME_BYTES);
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(name); }
  catch { throw new C.SnapshotError(C.HARD.unsafe_path); }
}
function nameKey(name: Uint8Array): string { capturedName(name); return Buffer.from(name).toString("hex"); }
function fileName(file: C.CapturedFile): string { return capturedName(file.name); }
function checkType(file: C.CapturedFile): void {
  C.validateCapturedStat(file.before); C.validateCapturedStat(file.after);
  // Type and metadata observations are mandatory evidence supplied by the future no-follow adapter.
  C.requireSnapshot(file.before.type === C.FILE_TYPE.file && file.after.type === C.FILE_TYPE.file, C.HARD.file_type_invalid);
  C.requireSnapshot(file.before.nlink === 1 && file.after.nlink === 1, C.HARD.file_type_invalid);
  C.requireSnapshot(file.metadata.length === 0, C.HARD.unexpected_metadata);
}
export function verifySnapshot(capture: C.CapturedSnapshot, pins: SnapshotPins, verifierSourceRevision: string): C.VerificationResult {
  let state: C.ProtocolState = C.STATES.ARGUMENTS; let exportId: string | null = null; let digest: string | null = null;
  let filename: string | null = null;
  const nested: C.VerificationResult["nested"] = { audit: null, transparency: null };
  const resultBase = { format: C.RESULT_FORMAT, verifier_source_revision: verifierSourceRevision, not_checked: C.NOT_CHECKED } as const;
  try {
    C.text(pins.expectedManifestDigest, C.DIGEST); C.text(verifierSourceRevision, C.REVISION);
    state = C.STATES.PIN_INPUTS; const descriptor = validateSnapshotPins(pins);
    state = C.STATES.MANIFEST_BYTES; C.cap(capture.files.length, C.MAX_FILES);
    C.validateCapturedStat(capture.rootBefore); C.validateCapturedStat(capture.rootAfter);
    C.requireSnapshot(capture.rootBefore.type === C.FILE_TYPE.directory && capture.rootAfter.type === C.FILE_TYPE.directory, C.HARD.file_type_invalid);
    C.requireSnapshot(capture.rootMetadata.length === 0, C.HARD.unexpected_metadata);
    const manifests = capture.files.filter(f => nameKey(f.name) === nameKey(C.utf8(C.MANIFEST_FILENAME))); C.requireSnapshot(manifests.length === 1, C.HARD.file_set_mismatch);
    const mf = manifests[0]; filename = C.MANIFEST_FILENAME; checkType(mf); const raw = C.parseManifestEnvelope(mf.bytes);
    state = C.STATES.MANIFEST_AUTHENTICATED;
    // Authenticate every body member against the independent pin before trusting a listed field or filename.
    C.requireSnapshot(verify(C.manifestSigningBytes(raw), C.base64(raw.manifest_signature, C.SIGNATURE_BYTES), C.publicKey(pins.packKey)), C.HARD.manifest_signature_invalid);
    const signer = C.object(raw.signer, ["identity_id", "public_key_base64url"]); C.requireSnapshot(signer.public_key_base64url === pins.packKey, C.HARD.embedded_key_mismatch);
    state = C.STATES.EXPECTED_SNAPSHOT; digest = C.manifestDigest(mf.bytes);
    // Exact signed file bytes are compared because canonical body equality misses whitespace and snapshot substitution.
    C.requireSnapshot(digest === pins.expectedManifestDigest, C.HARD.manifest_digest_mismatch);
    state = C.STATES.FILE_SET_AUTHENTICATED; const manifest = C.parseManifest(raw); exportId = manifest.export_id;
    filename = null;
    const expected = [C.MANIFEST_FILENAME, ...manifest.files.map(f => f.filename)].map(n => nameKey(C.utf8(n))).sort(); const actual = capture.files.map(f => nameKey(f.name)).sort();
    // An exhaustive byte-name set forbids metadata exemptions and case-folded aliases.
    C.requireSnapshot(C.canonicalSnapshotJSON(expected) === C.canonicalSnapshotJSON(actual), capture.files.some(f => C.OS_METADATA.test(fileName(f))) ? C.HARD.unlisted_os_metadata : C.HARD.file_set_mismatch);
    let total = 0; const files = new Map<string, Uint8Array>();
    for (const file of capture.files) {
      // File diagnostics identify only protocol names or names authenticated by the manifest.
      filename = fileName(file); checkType(file); C.cap(file.bytes.length, C.MAX_FILE_BYTES); total += file.bytes.length; C.cap(total, C.MAX_PACK_BYTES);
      C.requireSnapshot(file.before.size === file.bytes.length && file.after.size === file.bytes.length, C.HARD.snapshot_changed);
      const name = fileName(file); files.set(name, file.bytes); if (name === C.MANIFEST_FILENAME) continue;
      const row = manifest.files.find(f => f.filename === name)!;
      // Raw-byte hashing covers PDF and non-UTF-8 binary evidence without lossy text decoding.
      C.requireSnapshot(row.size_bytes === file.bytes.length && row.sha256 === C.sha256Hex(file.bytes), C.HARD.file_digest_mismatch);
    }
    filename = C.TRUST_FILENAME; state = C.STATES.BYTES_VERIFIED; bindSnapshotTrust(manifest, descriptor, files.get(C.TRUST_FILENAME)!, pins.descriptorBytes);
    state = C.STATES.NESTED_VERIFIED; const audit = manifest.components.audit; const transparency = manifest.components.transparency;
    filename = audit.state === C.COMPONENT.included ? audit.filename : null;
    const a = audit.state === C.COMPONENT.included ? verifySnapshotAudit(files.get(audit.filename)!, audit.extent, descriptor.keys) : absentOutcome(audit, C.ROLE.audit); nested.audit = a.report;
    filename = transparency.state === C.COMPONENT.included ? transparency.filename : null;
    const t = transparency.state === C.COMPONENT.included ? verifySnapshotTransparency(files.get(transparency.filename)!, transparency.extent, descriptor.keys) : absentOutcome(transparency, C.ROLE.transparency); nested.transparency = t.report;
    const partial = [...a.partial, ...t.partial]; if (manifest.extensions.length) partial.push(C.PARTIAL.extension_unverified);
    filename = null; state = C.STATES.FINAL_RECHECK;
    // A completed verdict requires stable root and file observations plus an identical final inventory.
    C.requireSnapshot(sameStat(capture.rootBefore, capture.rootAfter), C.HARD.snapshot_changed);
    for (const file of capture.files) {
      filename = fileName(file);
      C.requireSnapshot(sameStat(file.before, file.after), C.HARD.snapshot_changed);
    }
    filename = null;
    C.requireSnapshot(C.canonicalSnapshotJSON(capture.finalNames.map(nameKey).sort()) === C.canonicalSnapshotJSON(actual), C.HARD.snapshot_changed);
    return { ...resultBase, ...joinSnapshotVerdict(partial, manifest, a, t), export_id: exportId, manifest_digest: digest, findings: [], nested };
  } catch (error) {
    return { ...resultBase, status: C.STATUS.FAIL, exit_code: C.EXIT_FAIL, accepted: false, snapshot_integrity: C.INTEGRITY.unverified, export_id: exportId, manifest_digest: digest, findings: [{ code: error instanceof C.SnapshotError ? error.code : C.HARD.io_error, state, filename }], partial_reasons: [], nested };
  }
}
