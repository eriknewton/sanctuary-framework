import { describe, it, expect } from "vitest";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { canonicalJSON } from "../../src/evidence-pack/signer.js";
import { fixture, resignManifest, SOURCE } from "./snapshot-fixtures.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
describe("snapshot-contract", () => {
  it("canonical bytes match the existing signer golden", () => { const x = { z: [3, { b: 2, a: 1 }], a: { y: null, x: true }, unknown: "included" }; expect(C.canonicalSnapshotJSON(x)).toBe('{"a":{"x":true,"y":null},"unknown":"included","z":[3,{"a":1,"b":2}]}'); expect(C.canonicalSnapshotJSON(x)).toBe(canonicalJSON(x)); });
  it("manifest digest hashes exact bytes", () => { expect(C.manifestDigest(C.utf8("abc"))).toBe("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); });
  it.each(['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"n":9007199254740992}', '{"n":1e999}', '\ufeff{}', '{"x":"\\ud800"}'])("hostile raw JSON %s rejects", raw => { expect(() => C.parseSnapshotJSON(C.utf8(raw), C.MAX_MANIFEST_BYTES)).toThrow(); });
  it("invalid UTF-8 rejects", () => { expect(() => C.parseSnapshotJSON(new Uint8Array([123, 34, 120, 34, 58, 34, 255, 34, 125]), C.MAX_MANIFEST_BYTES)).toThrow(); });
  it("JSON depth cap is inclusive", () => { const nested = (n: number) => C.utf8('['.repeat(n) + '0' + ']'.repeat(n)); expect(() => C.parseSnapshotJSON(nested(C.MAX_JSON_DEPTH), C.MAX_MANIFEST_BYTES)).not.toThrow(); expect(() => C.parseSnapshotJSON(nested(C.MAX_JSON_DEPTH + 1), C.MAX_MANIFEST_BYTES)).toThrow(); });
  it.each(Object.entries({ MAX_MANIFEST_BYTES: C.MAX_MANIFEST_BYTES, MAX_TRUST_BYTES: C.MAX_TRUST_BYTES, MAX_FILE_BYTES: C.MAX_FILE_BYTES, MAX_PACK_BYTES: C.MAX_PACK_BYTES, MAX_FILES: C.MAX_FILES, MAX_RECORDS: C.MAX_RECORDS, MAX_JSONL_LINE_BYTES: C.MAX_JSONL_LINE_BYTES, MAX_KEYS: C.MAX_KEYS, MAX_ROTATION_HOPS: C.MAX_ROTATION_HOPS, MAX_AUDIT_TRAVERSAL: C.MAX_AUDIT_TRAVERSAL }))("%s limit rejects one above", (_name, max) => { expect(() => C.cap(max, max)).not.toThrow(); expect(() => C.cap(max + 1, max)).toThrow(C.HARD.limit_exceeded); });
  it.each(["../x", "a..b", "/tmp/x", "a/b", "a\\b", "a:b", "a\0b", "%2e%2e", "A.pdf", ".hidden", "x".repeat(129)])("signed unsafe name %s rejects through verifier", name => { const f = fixture(); f.manifest.files[0].filename = name; resignManifest(f); const r = verifySnapshot(f.capture, f.pins, SOURCE); expect(r.status).toBe(C.STATUS.FAIL); expect(r.findings[0].code).toBe(C.HARD.unsafe_path); });
  it("signed duplicate names reject", () => { const f = fixture(); f.manifest.files.splice(1, 0, { ...f.manifest.files[0] }); resignManifest(f); expect(verifySnapshot(f.capture, f.pins, SOURCE).findings[0].code).toBe(C.HARD.unsafe_path); });
  it("self-listed manifest rejects", () => { const f = fixture(); f.manifest.files[0].filename = C.MANIFEST_FILENAME; resignManifest(f); expect(verifySnapshot(f.capture, f.pins, SOURCE).findings[0].code).toBe(C.HARD.unsafe_path); });
  it.each([C.ROLE.report, C.ROLE.pdf, C.ROLE.trust, C.ROLE.recipient])("required %s cannot be empty", role => { const f = fixture(); f.manifest.files.find(r => r.role === role)!.size_bytes = 0; expect(() => C.parseManifest(f.manifest)).toThrow(); });
  it("file array cap applies before row inspection", () => { const f = fixture(); f.manifest.files = Array(C.MAX_FILES).fill(null); expect(() => C.parseManifest(f.manifest)).toThrow(C.HARD.limit_exceeded); });
  it("manifest byte cap applies before parsing", () => { expect(() => C.parseManifestEnvelope(new Uint8Array(C.MAX_MANIFEST_BYTES + 1))).toThrow(C.HARD.limit_exceeded); });
  it("trust byte cap applies before parsing", () => { expect(() => C.parseTrustDescriptor(new Uint8Array(C.MAX_TRUST_BYTES + 1))).toThrow(C.HARD.limit_exceeded); });
  it("JSONL line cap applies before parsing", () => { expect(() => C.parseAuditRecords(new Uint8Array(C.MAX_JSONL_LINE_BYTES + 1))).toThrow(C.HARD.limit_exceeded); });
  it("record cap applies before nested work", () => { const line = '{"type":"extension","extension_id":"future"}\n'; expect(() => C.parseAuditRecords(C.utf8(line.repeat(C.MAX_RECORDS + 1)))).toThrow(C.HARD.limit_exceeded); });
  it("file byte cap applies before JSONL scanning", () => { const bytes = new Uint8Array(C.MAX_FILE_BYTES + 1); bytes[0] = 10; expect(() => C.parseAuditRecords(bytes)).toThrow(C.HARD.limit_exceeded); });
  it("total pack cap applies to signed sizes", () => { const f = fixture(); for (const row of f.manifest.files) row.size_bytes = C.MAX_FILE_BYTES; expect(() => C.parseManifest(f.manifest)).toThrow(C.HARD.limit_exceeded); });
  it("per-file signed size cap rejects", () => { const f = fixture(); f.manifest.files[0].size_bytes = C.MAX_FILE_BYTES + 1; expect(() => C.parseManifest(f.manifest)).toThrow(C.HARD.limit_exceeded); });
  it("PARTIAL human line contains neither acceptance nor verification claim", () => { expect(C.HUMAN.PARTIAL).not.toContain("PASS"); expect(C.HUMAN.PARTIAL).not.toContain("verified"); });
});

// The raw signer must not mint a manifest accepted by the internal protocol.
it("manifest domain is refused by identity_sign", async () => {
  const { MemoryStorage } = await import("../../src/storage/memory.js");
  const { StateStore } = await import("../../src/cognitive/state-store.js");
  const { createCognitiveTools } = await import("../../src/cognitive/tools.js");
  const { AuditLog } = await import("../../src/operational/audit-log.js");
  const { encrypt } = await import("../../src/core/encryption.js");
  const { identity, master, encryptionKey } = await import("./snapshot-fixtures.js");
  const who = identity(), storage = new MemoryStorage();
  await storage.write("_identities", who.identity_id, C.utf8(JSON.stringify(encrypt(C.utf8(JSON.stringify(who)), encryptionKey))));
  const { tools, identityManager } = createCognitiveTools(new StateStore(storage, master), storage, master, "passphrase", new AuditLog(new MemoryStorage(), master));
  await identityManager.load();
  const result = await tools.find(t => t.name === "identity_sign")!.handler({ identity_id: who.identity_id, payload: Buffer.from(C.utf8(C.MANIFEST_DOMAIN + "{}" )).toString("base64url") });
  expect(JSON.parse(result.content[0].text).denied).toBe(true);
});
it("old digest manifest signature is rejected", async () => {
  const { signBytes } = await import("./snapshot-fixtures.js");
  const { sha256 } = await import("@noble/hashes/sha256");
  const f = fixture();
  const { manifest_signature: _signature, ...body } = f.manifest;
  f.manifest.manifest_signature = signBytes(sha256(C.utf8(C.MANIFEST_DOMAIN + C.canonicalSnapshotJSON(body))), f.pack);
  resignManifest(f, false);
  expect(verifySnapshot(f.capture, f.pins, SOURCE).findings[0]?.code).toBe(C.HARD.manifest_signature_invalid);
});
it("multi role Linux extension is incomplete rather than invalid", async () => {
  const { capturedFile, descriptorBytes, trustRow, replaceFile, refreshFiles } = await import("./snapshot-fixtures.js");
  const f = fixture(); const roles = ["extension:linux-business-producer-v0", "extension:linux-business-policy-v0"];
  f.capture.files = [...f.capture.files, capturedFile("linux.bin", C.utf8("opaque"))];
  f.manifest.extensions = [{ id: "linux-business-v0", filenames: ["linux.bin"], signing_roles: roles }];
  const rows = C.parseTrustDescriptor(f.pins.descriptorBytes).keys;
  rows.push(...roles.map(role => ({ ...trustRow(f.audit, role), rotation_evidence: { kind: C.ROTATION.oob } })));
  f.pins.descriptorBytes = descriptorBytes(rows); replaceFile(f, C.TRUST_FILENAME, f.pins.descriptorBytes); refreshFiles(f);
  expect(verifySnapshot(f.capture, f.pins, SOURCE)).toMatchObject({ status: "PARTIAL", exit_code: 10, accepted: false, partial_reasons: [C.PARTIAL.extension_unverified] });
});
