/** Production-consumer mutation witnesses complement the installed acceptance rows. */
import { describe, it, expect } from "vitest";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import { fixture, resignManifest, SOURCE, identity, signBytes, refreshFiles, replaceFile } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
describe("snapshot mutation sentinels", () => {
  it("outer signature rejects a changed body with a recalculated expected digest", () => { const f = fixture(); f.manifest.generated_at = "2026-10-03T00:00:00.000Z"; resignManifest(f, false); expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "FAIL", exit_code: 1, findings: [expect.objectContaining({ code: C.HARD.manifest_signature_invalid })] }); });
  it("embedded key equality precedes descriptor binding", () => { const f = fixture(); f.manifest.signer.public_key_base64url = identity().public_key; f.manifest.manifest_signature = signBytes(C.manifestSigningBytes(f.manifest as unknown as Record<string, unknown>), f.pack); resignManifest(f, false); expect(verifySnapshot(f.capture, f.pins, SOURCE).findings[0].code).toBe(C.HARD.embedded_key_mismatch); });
  it.each(["root", "file", "inventory"])("final observation refuses changed %s", kind => { const f = fixture(); if (kind === "root") f.capture.rootAfter.ino = "2"; else if (kind === "file") f.capture.files[0].after.ino = "2"; else f.capture.finalNames = f.capture.finalNames.slice(1); expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "FAIL", findings: [expect.objectContaining({ code: C.HARD.snapshot_changed })] }); });
  it("binary hash preserves every raw byte", () => { const f = fixture(); replaceFile(f, C.PDF_FILENAME, new Uint8Array([255])); refreshFiles(f); replaceFile(f, C.PDF_FILENAME, new Uint8Array([254])); expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "FAIL", findings: [expect.objectContaining({ code: C.HARD.file_digest_mismatch })] }); });
});
