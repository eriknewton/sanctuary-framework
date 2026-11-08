import { describe, it, expect } from "vitest";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { SNAPSHOT_EXTENSIONS, extensionRolesAllowed } from "../../src/evidence-pack/snapshot-extensions.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import { fixture, capturedFile, refreshFiles, descriptorBytes, trustRow, replaceFile, SOURCE } from "./snapshot-fixtures.js";
function extension(id: string, roles: string[]) {
  const f = fixture(); f.capture.files = [...f.capture.files, capturedFile("extension.bin", C.utf8("opaque"))];
  f.manifest.extensions = [{ id, filenames: ["extension.bin"], signing_roles: roles }];
  const keys = C.parseTrustDescriptor(f.pins.descriptorBytes).keys;
  for (const role of new Set(roles)) keys.push({ ...trustRow(f.audit, role), rotation_evidence: { kind: C.ROTATION.oob } });
  f.pins.descriptorBytes = descriptorBytes(keys); replaceFile(f, C.TRUST_FILENAME, f.pins.descriptorBytes); refreshFiles(f); return f;
}
describe("snapshot extension registry", () => {
  it("contains the exact complete role sets", () => {
    expect(SNAPSHOT_EXTENSIONS).toEqual({ "vendor-reconciliation-v0": ["extension:vendor-reconciliation-v0"], "linux-business-v0": ["extension:linux-business-producer-v0", "extension:linux-business-policy-v0"], "model-recorder-v0": ["extension:model-recorder-policy-v0", "extension:model-recorder-session-v0", "extension:model-recorder-extent-v0", "extension:model-recorder-v0"] });
  });
  it.each(Object.entries(SNAPSHOT_EXTENSIONS))("registered %s remains PARTIAL for every nonempty subset", (id, roles) => {
    for (let mask = 1; mask < 2 ** roles.length; mask++) {
      const subset = roles.filter((_, i) => mask & (1 << i)), f = extension(id, subset);
      expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "PARTIAL", exit_code: 10, accepted: false, partial_reasons: [C.PARTIAL.extension_unverified] });
    }
  });
  it("unregistered handler retains extension_unverified", () => { const f = extension("future", ["extension:future"]); expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "PARTIAL", exit_code: 10, accepted: false, partial_reasons: [C.PARTIAL.extension_unverified] }); });
  it.each([["extension:linux-business-policy-v0"], ["extension:future-role"], ["extension:future", "extension:vendor-reconciliation-v0"]].map(roles => [roles]))("unregistered handler cannot claim a registered or foreign role %j", roles => {
    const f = extension("future", roles); expect(extensionRolesAllowed("future", roles)).toBe(false); expect(verifySnapshot(f.capture, f.pins, SOURCE).status).toBe("FAIL");
  });
  it.each([[], ["extension:linux-business-producer-v0", "extension:linux-business-producer-v0"], ["extension:vendor-reconciliation-v0"]].map(roles => [roles]))("empty duplicate or foreign roles fail %j", roles => {
    const f = extension("linux-business-v0", roles); expect(extensionRolesAllowed("linux-business-v0", roles)).toBe(false); expect(verifySnapshot(f.capture, f.pins, SOURCE).status).toBe("FAIL");
  });
  it("every declared role requires an independent descriptor row", () => {
    const f = extension("linux-business-v0", [...SNAPSHOT_EXTENSIONS["linux-business-v0"]]);
    const keys = C.parseTrustDescriptor(f.pins.descriptorBytes).keys.filter(k => k.role !== "extension:linux-business-policy-v0");
    f.pins.descriptorBytes = descriptorBytes(keys); replaceFile(f, C.TRUST_FILENAME, f.pins.descriptorBytes); refreshFiles(f);
    expect(verifySnapshot(f.capture, f.pins, SOURCE).findings[0].code).toBe(C.HARD.pin_invalid);
  });
});
