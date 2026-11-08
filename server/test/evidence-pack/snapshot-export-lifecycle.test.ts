import { it, expect, vi } from "vitest";
import { mkdir, readFile, readdir, writeFile, lstat } from "node:fs/promises";
import { join } from "node:path";
import { exportSnapshot, EXPORT_STATES, runSnapshotExportCommand } from "../../src/evidence-pack/snapshot-export-cli.js";
import { captureSnapshotDirectory, runSnapshotTrustCommand, requireOutside } from "../../src/evidence-pack/snapshot-trust-cli.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { exporterFixture, SOURCE } from "./snapshot-fixtures.js";
vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
it("lifecycle order cleanup receipt and stdout describe independently verified committed bytes", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(0);
  expect(x.states).toEqual(EXPORT_STATES); expect(x.cleanupCount()).toBe(1);
  const r = JSON.parse(await readFile(x.options.receipt, "utf8"));
  expect(Object.keys(r).sort()).toEqual(["format", "export_id", "manifest_digest", "source_revision", "trust_descriptor_sha256", "pack_path", "status", "pack_key_fingerprint"].sort());
  expect(r).toMatchObject({ format: C.RECEIPT_FORMAT, source_revision: SOURCE, pack_path: x.options.output, status: "PASS", pack_key_fingerprint: C.manifestDigest(C.publicKey(x.f.pack.public_key)) });
  expect(await readFile(x.options.publicKeyFile, "utf8")).toBe(x.f.pack.public_key + "\n");
  expect(x.stdout).toEqual([`EXPORT_ID=${r.export_id}\nMANIFEST_DIGEST=${r.manifest_digest}\nEXPORT_STATUS=PASS\nPACK_KEY_FINGERPRINT=${r.pack_key_fingerprint}\n`]);
  const trust = await readFile(join(x.options.output, C.TRUST_FILENAME));
  expect(r.trust_descriptor_sha256).toBe(C.manifestDigest(trust));
  const capture = await captureSnapshotDirectory(x.options.output, x.f.pack.public_key, r.manifest_digest);
  expect(verifySnapshot(capture, { packKey: x.f.pack.public_key, descriptorBytes: trust, expectedManifestDigest: r.manifest_digest }, SOURCE)).toMatchObject({ status: "PASS", accepted: true, exit_code: 0 });
  expect((await lstat(x.options.output)).mode & 0o777).toBe(0o700);
});
it.each(EXPORT_STATES)("fault at %s never emits success", async state => {
  const x = await exporterFixture(); x.deps.phase = async current => { if (current === state) throw new Error("fault"); };
  expect(await runSnapshotExportCommand(["--fortress", x.options.fortress, "--output", x.options.output, "--receipt", x.options.receipt, "--public-key-file", x.options.publicKeyFile], x.deps)).toBe(1);
  expect(x.stdout).toEqual([]);
  if (["SELF_VERIFY", "CLEANUP", "COMMIT"].includes(state)) expect((await readdir(x.root)).some(n => n.startsWith(".evidence-failed-stage-"))).toBe(true);
  if (state === "RECEIPT") expect(await readdir(x.options.output)).toContain(C.MANIFEST_FILENAME);
  else await expect(lstat(x.options.output)).rejects.toMatchObject({ code: "ENOENT" });
});
it("cleanup failure prevents commit and returns exit one", async () => {
  const x = await exporterFixture(), boot = x.deps.boot;
  x.deps.boot = async opts => ({ ...await boot(opts), cleanup: async () => { throw new Error("cleanup"); } });
  expect(await runSnapshotExportCommand(["--fortress", x.options.fortress, "--output", x.options.output, "--receipt", x.options.receipt, "--public-key-file", x.options.publicKeyFile], x.deps)).toBe(1);
  expect(x.stdout).toEqual([]); await expect(lstat(x.options.output)).rejects.toMatchObject({ code: "ENOENT" });
});
it("cleanup completes before destination is created", async () => {
  const x = await exporterFixture(), boot = x.deps.boot; let cleaned = false;
  x.deps.boot = async opts => ({ ...await boot(opts), cleanup: async () => { await expect(lstat(x.options.output)).rejects.toMatchObject({ code: "ENOENT" }); cleaned = true; } });
  x.deps.phase = async state => { if (state === "COMMIT") expect(cleaned).toBe(true); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(0);
});
it("destination race preserves the concurrently created directory", async () => {
  const x = await exporterFixture();
  x.deps.phase = async state => { if (state === "COMMIT") { await mkdir(x.options.output); await writeFile(join(x.options.output, "owner.txt"), "prior"); } };
  expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(await readdir(x.options.output)).toEqual(["owner.txt"]); expect(await readFile(join(x.options.output, "owner.txt"), "utf8")).toBe("prior"); expect(x.stdout).toEqual([]);
});
it.each(["receipt", "publicKeyFile"] as const)("exclusive %s race preserves existing bytes", async field => {
  const x = await exporterFixture();
  x.deps.phase = async state => { if (state === (field === "receipt" ? "RECEIPT" : "BUILD_PUBLIC_TRUST")) await writeFile(x.options[field], "prior"); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(await readFile(x.options[field], "utf8")).toBe("prior"); expect(x.stdout).toEqual([]);
  if (field === "receipt") expect(await readdir(x.options.output)).toContain(C.MANIFEST_FILENAME);
});
it("self verification rejects tampered staged PDF", async () => {
  const x = await exporterFixture(); x.deps.phase = async (state, stage) => { if (state === "SELF_VERIFY") await writeFile(join(stage!, C.PDF_FILENAME), "tampered"); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(x.stdout).toEqual([]); await expect(lstat(x.options.output)).rejects.toMatchObject({ code: "ENOENT" });
});
it("PARTIAL commits and exits ten without acceptance", async () => {
  const x = await exporterFixture(); x.gathered.audit = { state: "empty_verified", reason: "no_records" }; delete x.gathered.auditBytes;
  x.gathered.transparency = { state: "read_failed", reason: "pin_unavailable" }; delete x.gathered.transparencyBytes; delete x.gathered.transparencyPin;
  expect(await exportSnapshot(x.options, x.deps)).toBe(10); expect(JSON.parse(await readFile(x.options.receipt, "utf8")).status).toBe("PARTIAL"); expect(x.stdout.join("")).toContain("EXPORT_STATUS=PARTIAL\n");
});
it("runtime revision mismatch refuses before boot", async () => {
  const x = await exporterFixture(); x.deps.runtimeRevision = "f".repeat(40);
  expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(x.states).toEqual([]); expect(x.stdout).toEqual([]);
});
it("short build revision refuses before boot", async () => { const x = await exporterFixture(); x.deps.buildRevision = x.deps.runtimeRevision = "12345678"; expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(x.states).toEqual([]); });
it("trust command copies exact candidate bytes without boot or nested claims", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(0);
  const r = JSON.parse(await readFile(x.options.receipt, "utf8")), output = join(x.root, "candidate.json"); x.stdout.length = 0;
  const args = ["--pack", x.options.output, "--public-key-file", x.options.publicKeyFile, "--expect-manifest-digest", r.manifest_digest, "--output", output];
  expect(await runSnapshotTrustCommand(args, x.deps.io)).toBe(0); expect(await readFile(output)).toEqual(await readFile(join(x.options.output, C.TRUST_FILENAME))); expect(x.stdout).toEqual([`TRUST_DESCRIPTOR_SHA256=${r.trust_descriptor_sha256}\n`]);
  expect(await runSnapshotTrustCommand(args, x.deps.io)).toBe(1);
});
it.each([[], ["--help", "--output", "x"], ["--output", "x", "--output", "y"]].map(args => [args]))("invalid export arguments refuse before boot %j", async args => { const x = await exporterFixture(); expect(await runSnapshotExportCommand(args, x.deps)).toBe(2); expect(x.states).toEqual([]); });

it("external pin and receipt paths cannot be inside the delivery", () => {
  expect(() => requireOutside("/tmp/pack", "/tmp/pack/key.txt")).toThrow(C.HARD.unsafe_path);
  expect(() => requireOutside("/tmp/pack", "/tmp/pack")).toThrow(C.HARD.unsafe_path);
  expect(() => requireOutside("/tmp/pack", "/tmp/pins/key.txt")).not.toThrow();
});
it("stdout failure leaves committed bytes and returns exit one", async () => {
  const x = await exporterFixture(); x.deps.io.stdout = async () => { throw new Error("pipe"); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(1); expect(await readdir(x.options.output)).toContain(C.MANIFEST_FILENAME);
});

it("capture bounds actual bytes by the authenticated file row before reading", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(0);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8"));
  await writeFile(join(x.options.output, C.PDF_FILENAME), Buffer.alloc(C.MAX_MANIFEST_BYTES));
  await expect(captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow(C.HARD.limit_exceeded);
});
it("capture bounds inventory before allocating the complete directory list", async () => {
  const x = await exporterFixture(); await mkdir(x.options.output);
  for (let i = 0; i < C.MAX_FILES + 2; i++) await writeFile(join(x.options.output, `file-${i}`), "x");
  const fs = await import("node:fs/promises"), original = fs.opendir; let visited = 0;
  const spy = vi.spyOn(fs, "opendir").mockImplementation(async (path, options) => {
    const directory = await original(path, options);
    return new Proxy(directory, { get(target, key) {
      if (key === Symbol.asyncIterator) return async function* () { for await (const entry of target) { visited++; yield entry; } };
      return Reflect.get(target, key, target);
    } });
  });
  try {
    await expect(captureSnapshotDirectory(x.options.output, x.f.pack.public_key, C.manifestDigest(C.utf8("unused")))).rejects.toThrow(C.HARD.limit_exceeded);
    expect(visited).toBe(C.MAX_FILES + 1);
  } finally { spy.mockRestore(); }
});
