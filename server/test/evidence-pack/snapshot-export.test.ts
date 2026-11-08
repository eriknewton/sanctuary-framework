import { afterEach, describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile, readdir, chmod, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildPublicTrust, projectIdentity } from "../../src/evidence-pack/snapshot-generate.js";
import { gatherSnapshot, resolveSnapshotTransparencyPin } from "../../src/evidence-pack/snapshot-gather.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { TRANSPARENCY_CHECKPOINT_NAMESPACE } from "../../src/transparency/emitter.js";
import { exportSnapshot } from "../../src/evidence-pack/snapshot-export-cli.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import { captureSnapshotDirectory } from "../../src/evidence-pack/snapshot-trust-cli.js";
import { rotateKeys } from "../../src/core/identity.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { exporterFixture, identity, encryptionKey, master, NOW, SOURCE, jsonBytes, transparencyFixture, auditBytes, auditFixture, descriptorBytes, trustRow } from "./snapshot-fixtures.js";
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function transparencyStore() {
  const root = await mkdtemp(join(tmpdir(), "snapshot-gather-")), storage = new FilesystemStorage(join(root, "state"));
  const who = identity(), bundle = transparencyFixture(who);
  for (const record of bundle.checkpoints) await storage.write(TRANSPARENCY_CHECKPOINT_NAMESPACE, `enforcement-checkpoint-${String(record.counter).padStart(20, "0")}`, jsonBytes(record));
  const pin = join(root, "castle-pinned-pubkey.bin"), globalPinPath = join(root, "missing-global");
  await writeFile(pin, C.publicKey(who.public_key));
  const input = { storage, masterKey: master, fortress: root, generatedAt: NOW, localSign: true, globalPinPath };
  return { input, who, pin, root, bundle };
}
describe("snapshot exporter trust", () => {
  it("positive allowlist excludes nested stored identity secret sentinels from every byte", async () => {
    const x = await exporterFixture(); Object.assign(x.f.pack, { privateSentinel: "TOP_SECRET_SENTINEL", nested: { token: "NESTED_SECRET_SENTINEL" } });
    const current = rotateKeys(x.f.pack, encryptionKey, "scheduled").updatedIdentity;
    Object.assign(current.rotation_history[0], { secret: "HOP_SECRET_SENTINEL" });
    const row = projectIdentity(current, C.PIN_ROLE.pack);
    expect(JSON.stringify(row)).not.toMatch(/SECRET_SENTINEL/);
    expect(Object.keys(row.rotation_evidence).sort()).toEqual(["kind", "identity_id", "current_public_key", "history"].sort());
    expect(await exportSnapshot(x.options, x.deps)).toBe(0);
    for (const name of await readdir(x.options.output)) expect(await readFile(join(x.options.output, name), "utf8")).not.toMatch(/SECRET_SENTINEL|encrypted_private_key/);
  });
  it("public projection refuses a broken rotation chain", async () => {
    const x = await exporterFixture(); const current = rotateKeys(x.f.pack, encryptionKey, "scheduled").updatedIdentity; current.rotation_history[0].rotation_event = Buffer.from("{}").toString("base64url");
    expect(() => buildPublicTrust(current, [current], { audit: { state: "empty_verified", reason: "no_records" }, transparency: { state: "empty_verified", reason: "no_records" } })).toThrow();
  });
  it.each(["compromised", "post-retirement"])("retired key %s refuses export", async kind => {
    const who = identity(), current = rotateKeys(who, encryptionKey, kind === "compromised" ? "compromised" : "scheduled").updatedIdentity;
    const records = auditFixture([who]); if (kind === "post-retirement") Object.assign(records[1], { signed_at: "2099-01-01T00:00:00.000Z" });
    expect(() => buildPublicTrust(current, [current], { audit: { state: "empty_verified", reason: "no_records" }, transparency: { state: "empty_verified", reason: "no_records" }, auditBytes: auditBytes(records) })).toThrow();
  });
  it("transparency authenticated local pin permits actual signed records", async () => {
    const x = await transparencyStore(); const result = await gatherSnapshot(x.input);
    expect(result.transparency.state).toBe("included"); expect(result.transparencyPin).toEqual({ key: x.who.public_key, pathClass: "fortress-local" });
  });
  it("forged self consistent transparency key is key_mismatch", async () => {
    const x = await transparencyStore(); await writeFile(x.pin, C.publicKey(identity().public_key));
    const result = await gatherSnapshot(x.input); expect(result.transparency).toEqual({ state: "read_failed", reason: "key_mismatch" }); expect(result.transparencyBytes).toBeUndefined();
  });
  it("unavailable pin is pin_unavailable", async () => {
    const x = await transparencyStore(); x.input.localSign = false;
    expect((await gatherSnapshot(x.input)).transparency).toEqual({ state: "read_failed", reason: "pin_unavailable" });
  });
  it("existing invalid global pin never falls back to local", async () => {
    const x = await transparencyStore(); await writeFile(x.input.globalPinPath, "bad");
    expect((await gatherSnapshot(x.input)).transparency).toEqual({ state: "read_failed", reason: "pin_unavailable" });
  });
  it("authenticated global pin wins over a different local pin", async () => {
    const x = await transparencyStore(); await writeFile(x.input.globalPinPath, C.publicKey(x.who.public_key)); await writeFile(x.pin, C.publicKey(identity().public_key));
    const custody = await import("../../src/storage/custody-fs.js");
    const read = vi.spyOn(custody, "readFileCustodyWithStats").mockResolvedValue({ data: Buffer.from(C.publicKey(x.who.public_key)), stats: Object.assign(await stat(x.input.globalPinPath), { uid: 0 }) });
    expect(await resolveSnapshotTransparencyPin(x.root, true, x.input.globalPinPath)).toEqual({ key: x.who.public_key, pathClass: "global" });
    expect(read).toHaveBeenCalledExactlyOnceWith(x.input.globalPinPath, expect.objectContaining({ uid: 0, maxBytes: C.KEY_BYTES, verifyPathIdentity: true }));
  });
  it("invalid included transparency signature is a hard export failure", async () => {
    const x = await transparencyStore(); x.bundle.checkpoints[0].signature = Buffer.alloc(C.SIGNATURE_BYTES).toString("base64url");
    await x.input.storage.write(TRANSPARENCY_CHECKPOINT_NAMESPACE, "enforcement-checkpoint-00000000000000000001", jsonBytes(x.bundle.checkpoints[0]));
    await expect(gatherSnapshot(x.input)).rejects.toThrow(C.HARD.nested_invalid);
  });
  it("fortress path mismatch refuses before gathering", async () => { const x = await exporterFixture(), boot = x.deps.boot; x.deps.boot = async opts => { const server = await boot(opts); server.config.storage_path = x.root; return server; }; expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(x.stdout).toEqual([]); });
  it("exporter bundle has one canonical keychain module and no dist imports", async () => {
    const { build } = await import("esbuild");
    const result = await build({ entryPoints: ["src/evidence-pack/snapshot-export-cli.ts"], bundle: true, platform: "node", format: "esm", packages: "external", write: false, metafile: true, logLevel: "silent", define: { __SANCTUARY_SOURCE_SHA__: JSON.stringify(SOURCE) } });
    const inputs = Object.keys(result.metafile!.inputs);
    expect(inputs.filter(p => p.endsWith("wrap/keychain-exec.ts"))).toEqual(["src/wrap/keychain-exec.ts"]);
    expect(inputs.filter(p => p.startsWith("dist/") || p.includes("/dist/"))).toEqual([]);
  });
});
it("registered CLI argv commits a real temporary fortress with in-memory credentials", async () => {
  const { TOP_LEVEL_SUBCOMMANDS } = await import("../../src/cli/subcommands.js");
  expect(TOP_LEVEL_SUBCOMMANDS).toContain("export-evidence");
  expect(TOP_LEVEL_SUBCOMMANDS).toContain("export-evidence-trust");
  const root = await mkdtemp(join(tmpdir(), "snapshot-wired-")), fortress = join(root, "fortress");
  await mkdir(fortress);
  vi.stubEnv("HOME", root); vi.stubEnv("SANCTUARY_STORAGE_PATH", fortress); vi.stubEnv("SANCTUARY_FORTRESS_PATH", fortress);
  vi.stubEnv("SANCTUARY_PASSPHRASE", "snapshot-disposable-test-only"); vi.stubEnv("SANCTUARY_DASHBOARD_AUTO_OPEN", "false");
  vi.stubGlobal("__SANCTUARY_SOURCE_SHA__", SOURCE);
  const { createSanctuaryServer } = await import("../../src/index.js");
  const server = await createSanctuaryServer({ passphrase: process.env.SANCTUARY_PASSPHRASE });
  const { createIdentity } = await import("../../src/core/identity.js"); const { derivePurposeKey } = await import("../../src/core/key-derivation.js");
  const who = createIdentity("snapshot wired fixture", derivePurposeKey(server.masterKey, "identity-encryption"), "passphrase").storedIdentity;
  try { await server.identityManager.saveNew(who); await server.identityManager.setPrimary(who.identity_id); } finally { await server.cleanup(); }
  // The runtime source constant is installed before reloading the production command registration.
  vi.resetModules();
  const original = process.argv; const output = join(root, "pack"), receipt = join(root, "receipt.json"), key = join(root, "key.txt");
  const exits: number[] = [];
  vi.spyOn(process, "exit").mockImplementation(((code: number) => { exits.push(code); }) as never);
  const stdout: string[] = [];
  vi.spyOn(process.stdout, "write").mockImplementation(((text: string, callback?: (error?: Error) => void) => { stdout.push(String(text)); callback?.(); return true; }) as never);
  process.argv = [process.execPath, resolve("src/cli.ts"), "export-evidence", "--fortress", fortress, "--output", output, "--receipt", receipt, "--public-key-file", key];
  try { await (await import("../../src/cli.js")).cliEntryInvocation; } finally { process.argv = original; }
  expect(exits).toEqual([10]);
  const r = JSON.parse(await readFile(receipt, "utf8"));
  const descriptor = descriptorBytes([C.PIN_ROLE.pack, C.PIN_ROLE.audit].map(role => {
    const { key_id, algorithm, public_key_base64url, fingerprint, rotation_evidence } = trustRow(who, role);
    return { role, key_id, algorithm, public_key_base64url, fingerprint, rotation_evidence };
  }));
  expect(await readFile(join(output, C.TRUST_FILENAME))).toEqual(Buffer.from(descriptor));
  expect(await readFile(key, "utf8")).toBe(who.public_key + "\n");
  const result = verifySnapshot(await captureSnapshotDirectory(output, who.public_key, r.manifest_digest), { packKey: who.public_key, descriptorBytes: descriptor, expectedManifestDigest: r.manifest_digest }, SOURCE);
  expect(result).toMatchObject({ status: "PARTIAL", exit_code: 10, accepted: false });
  expect(stdout.join("")).toBe(`EXPORT_ID=${r.export_id}\nMANIFEST_DIGEST=${r.manifest_digest}\nEXPORT_STATUS=PARTIAL\nPACK_KEY_FINGERPRINT=${r.pack_key_fingerprint}\n`);
  vi.resetModules(); exits.length = 0; stdout.length = 0;
  const candidate = join(root, "candidate.json");
  process.argv = [process.execPath, resolve("src/cli.ts"), "export-evidence-trust", "--pack", output, "--public-key-file", key, "--expect-manifest-digest", r.manifest_digest, "--output", candidate];
  try { await (await import("../../src/cli.js")).cliEntryInvocation; } finally { process.argv = original; }
  expect(exits).toEqual([0]);
  expect(stdout.join("")).toBe(`TRUST_DESCRIPTOR_SHA256=${r.trust_descriptor_sha256}\n`);
  expect(await readFile(candidate)).toEqual(await readFile(join(output, C.TRUST_FILENAME)));
}, 60_000);

it("writable Castle pin is unavailable as authenticated authority", async () => {
  const x = await transparencyStore(); await chmod(x.pin, 0o666);
  expect((await gatherSnapshot(x.input)).transparency).toEqual({ state: "read_failed", reason: "pin_unavailable" });
});
