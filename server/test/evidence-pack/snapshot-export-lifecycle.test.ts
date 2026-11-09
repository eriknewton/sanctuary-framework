import { it, expect, vi, afterEach } from "vitest";
import { mkdir, readFile, readdir, writeFile, lstat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { exportSnapshot, EXPORT_STATES, runSnapshotExportCommand } from "../../src/evidence-pack/snapshot-export-cli.js";
import { captureSnapshotDirectory, runSnapshotTrustCommand, requireOutside } from "../../src/evidence-pack/snapshot-trust-cli.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { exporterFixture, SOURCE } from "./snapshot-fixtures.js";
afterEach(() => vi.restoreAllMocks());
vi.mock("../../src/evidence-pack/snapshot-trust-cli.js", async original => ({ ...await original<typeof import("../../src/evidence-pack/snapshot-trust-cli.js")>() }));
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
  expect(x.stderr.join("")).toBe((state === "RECEIPT" ? "Evidence export finalization failed; committed pack retained.\n" : "Evidence export failed; any failed stage is retained.\n") + "EXPORT_FINDING=io_error\n");
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
  expect(x.stderr.join("")).toBe("Evidence export finalization failed; committed pack retained.\nEXPORT_FINDING=io_error\n");
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

it.each(["GATHER", "BUILD_PUBLIC_TRUST", "RENDER", "HASH", "SIGN", "HASH_MANIFEST_FILE", "STAGE", "SELF_VERIFY", "CLEANUP", "COMMIT", "RECEIPT"] as const)("closed diagnostic preserves typed failure at %s", async state => {
  const x = await exporterFixture();
  x.deps.phase = async current => { if (current === state) throw new C.SnapshotError(C.HARD.pin_invalid); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  expect(x.stderr.join("")).toBe((state === "RECEIPT" ? "Evidence export finalization failed; committed pack retained.\n" : "Evidence export failed; any failed stage is retained.\n") + "EXPORT_FINDING=pin_invalid\n");
});
it("closed diagnostic rejects a forged error code", async () => {
  const x = await exporterFixture(); x.deps.phase = async () => { throw new C.SnapshotError("/private/sentinel" as C.HardCode); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  expect(x.stderr.join("")).toBe("Evidence export failed; any failed stage is retained.\nEXPORT_FINDING=io_error\n");
});
it("self check reports its actual metadata finding and leaves no public key", async () => {
  const x = await exporterFixture(), adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js"), original = adapter.captureSnapshotDirectory;
  vi.spyOn(adapter, "captureSnapshotDirectory").mockImplementation(async (...args) => { const capture = await original(...args); capture.rootMetadata = ["user.private-sentinel"]; return capture; });
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  expect(x.stderr.join("")).toBe("Evidence export failed; any failed stage is retained.\nEXPORT_FINDING=unexpected_metadata\n");
  await expect(lstat(x.options.publicKeyFile)).rejects.toMatchObject({ code: "ENOENT" });
});
it.each([false, true])("final confirm failure labels the delivery and deletes nothing %s", async concurrent => {
  const x = await exporterFixture(), adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js"), original = adapter.captureSnapshotDirectory;
  let confirmed = false;
  vi.spyOn(adapter, "captureSnapshotDirectory").mockImplementation(async (...args) => {
    const capture = await original(...args);
    if (args[0] === x.options.output) {
      confirmed = true;
      if (concurrent) await writeFile(join(x.options.output, "owner.txt"), "prior");
      capture.rootAfter.ino += "changed";
    }
    return capture;
  });
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL); expect(confirmed).toBe(true);
  expect(x.stdout).toEqual([]); await expect(lstat(x.options.receipt)).rejects.toMatchObject({ code: "ENOENT" });
  const listed = (await readdir(x.options.output)).sort();
  expect(listed).toContain("EXPORT_FAILED"); expect(listed).toContain(C.MANIFEST_FILENAME);
  expect(listed.includes("owner.txt")).toBe(concurrent);
  if (concurrent) expect(await readFile(join(x.options.output, "owner.txt"), "utf8")).toBe("prior");
  expect(await readFile(join(x.options.output, "EXPORT_FAILED"), "utf8")).toBe("");
  // The marker is an unlisted file, so the labeled delivery can never verify.
  vi.restoreAllMocks();
  const digest = C.manifestDigest(await readFile(join(x.options.output, C.MANIFEST_FILENAME)));
  await expect(original(x.options.output, x.f.pack.public_key, digest)).rejects.toMatchObject({ code: C.HARD.file_set_mismatch });
  expect(x.stderr.join("")).toBe("Evidence export failed; any failed stage is retained.\nEXPORT_FINDING=snapshot_changed\n");
});
it("partial destination write labels the delivery and keeps the partial file", async () => {
  const x = await exporterFixture(), fs = await import("node:fs/promises"), original = fs.open, originalWrite = fs.writeFile;
  vi.spyOn(fs, "writeFile").mockImplementation(async (...args: Parameters<typeof fs.writeFile>) => {
    if (String(args[0]).startsWith(x.options.output + "/")) { await originalWrite(args[0], "", args[2]); throw new Error("partial write"); }
    return originalWrite(...args);
  });
  vi.spyOn(fs, "open").mockImplementation(async (...args: Parameters<typeof fs.open>) => {
    const fd = await original(...args);
    if (String(args[0]).startsWith(x.options.output + "/") && args[1] === "wx") vi.spyOn(fd, "writeFile").mockImplementation(async () => { throw new Error("partial write"); });
    return fd;
  });
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  vi.restoreAllMocks();
  const listed = await readdir(x.options.output);
  expect(listed).toContain("EXPORT_FAILED"); expect(listed.length).toBeGreaterThan(1);
});
it("a failed delivery never removes a file it did not write, even one substituted at an exported name", async () => {
  const x = await exporterFixture(), adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js"), original = adapter.captureSnapshotDirectory;
  vi.spyOn(adapter, "captureSnapshotDirectory").mockImplementation(async (...args) => {
    const capture = await original(...args);
    if (args[0] === x.options.output) { await unlink(join(x.options.output, C.REPORT_FILENAME)); await writeFile(join(x.options.output, C.REPORT_FILENAME), "substituted"); capture.rootAfter.ino += "changed"; }
    return capture;
  });
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  expect(await readFile(join(x.options.output, C.REPORT_FILENAME), "utf8")).toBe("substituted");
  expect(await readFile(join(x.options.output, "EXPORT_FAILED"), "utf8")).toBe("");
});
it.each([["com.apple.quarantine\n", ["com.apple.quarantine", ""]], ["\ncom.apple.provenance", ["", "com.apple.provenance"]], ["", []]])("Darwin capture refuses interior empty names and admits an empty listing %j", async (stdout, names) => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8"));
  const platform = process.platform;
  const execute = vi.fn(() => Buffer.from(stdout === "" ? "" : stdout + C.LF));
  const lookup = vi.fn(() => ({ status: C.EXIT_PASS }));
  vi.doMock("node:child_process", async original => {
    const { promisify } = await import("node:util");
    return { ...await original<typeof import("node:child_process")>(), execFileSync: execute, spawnSync: lookup, execFile: Object.assign(vi.fn(), { [promisify.custom]: async () => ({ stdout: execute().toString() }) }) };
  });
  try {
    Object.defineProperty(process, "platform", { value: "darwin" }); vi.doUnmock("../../src/evidence-pack/snapshot-trust-cli.js"); vi.resetModules();
    const adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js");
    if (names.length > 0) {
      await expect(adapter.captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow(C.HARD.unexpected_metadata);
      expect(execute).toHaveBeenCalledOnce(); expect(lookup).not.toHaveBeenCalled();
      return;
    }
    const capture = await adapter.captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest);
    expect(capture.rootMetadata).toEqual(names);
    const result = verifySnapshot(capture, { packKey: x.f.pack.public_key, descriptorBytes: await readFile(join(x.options.output, C.TRUST_FILENAME)), expectedManifestDigest: receipt.manifest_digest }, SOURCE);
    expect(result.status).toBe("PASS");
    const paths = [x.options.output, ...capture.files.map(file => join(x.options.output, Buffer.from(file.name).toString()))];
    expect(execute.mock.calls).toEqual(paths.map(path => ["/usr/bin/xattr", ["-s", path], expect.objectContaining({ shell: false, env: { LC_ALL: "C" }, stdio: ["ignore", "pipe", "ignore"] })]));
    expect(lookup).not.toHaveBeenCalled();
  } finally { Object.defineProperty(process, "platform", { value: platform }); vi.doUnmock("node:child_process"); vi.resetModules(); }
});
it("capture closes the file handle when its first stat fails", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8")), fs = await import("node:fs/promises"), original = fs.open;
  const closed = vi.fn();
  vi.spyOn(fs, "open").mockImplementation(async (...args: Parameters<typeof fs.open>) => {
    const fd = await original(...args);
    if (String(args[0]) === join(x.options.output, C.MANIFEST_FILENAME)) {
      const close = fd.close.bind(fd);
      vi.spyOn(fd, "close").mockImplementation(async () => { closed(); await close(); });
      vi.spyOn(fd, "stat").mockRejectedValue(new Error("stat failed"));
    }
    return fd;
  });
  await expect(captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow("stat failed");
  expect(closed).toHaveBeenCalledOnce();
});
it.each(["leading space", "CRLF", "two LF", "BOM", "no LF"])("trust key grammar handles %s", async kind => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const key = x.f.pack.public_key;
  const text = kind === "leading space" ? " " + key : kind === "CRLF" ? key + "\r\n" : kind === "two LF" ? key + "\n\n" : kind === "BOM" ? "\ufeff" + key : key;
  await writeFile(x.options.publicKeyFile, text); x.stdout.length = 0;
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8")), output = join(x.root, "candidate.json");
  expect(await runSnapshotTrustCommand(["--pack", x.options.output, "--public-key-file", x.options.publicKeyFile, "--expect-manifest-digest", receipt.manifest_digest, "--output", output], x.deps.io)).toBe(kind === "no LF" ? C.EXIT_PASS : C.EXIT_FAIL);
  if (kind !== "no LF") { expect(x.stdout).toEqual([]); await expect(lstat(output)).rejects.toMatchObject({ code: "ENOENT" }); }
});

it.each(["unlink", "rmdir"] as const)("stage %s failure reports finalization and retains committed pack", async operation => {
  const x = await exporterFixture(), fs = await import("node:fs/promises");
  vi.spyOn(fs, operation).mockRejectedValue(new Error("stage cleanup"));
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  expect(await readdir(x.options.output)).toContain(C.MANIFEST_FILENAME);
  expect(x.stdout).toEqual([]);
  expect(x.stderr.join("")).toBe("Evidence export finalization failed; committed pack retained.\nEXPORT_FINDING=io_error\n");
});
it("Darwin capture refuses allowed names that do not exist under their exact name", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8"));
  const platform = process.platform;
  // One attribute whose name joins two allowed names with LF lists exactly like two attributes; the exact-name lookup then fails.
  const execute = vi.fn(() => Buffer.from("com.apple.provenance\ncom.apple.quarantine\n"));
  const lookup = vi.fn(() => ({ status: C.EXIT_FAIL }));
  vi.doMock("node:child_process", async original => {
    const { promisify } = await import("node:util");
    return { ...await original<typeof import("node:child_process")>(), execFileSync: execute, spawnSync: lookup, execFile: Object.assign(vi.fn(), { [promisify.custom]: async (_command: string, args: string[]) => {
      if (args.includes("-p")) throw new Error("No such xattr");
      return { stdout: execute().toString() };
    } }) };
  });
  try {
    Object.defineProperty(process, "platform", { value: "darwin" }); vi.doUnmock("../../src/evidence-pack/snapshot-trust-cli.js"); vi.resetModules();
    const adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js");
    await expect(adapter.captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow(C.HARD.unexpected_metadata);
    expect(lookup).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", "-p", C.OS_ATTACHED_METADATA[0], x.options.output], expect.objectContaining({ stdio: "ignore" }));
  } finally { Object.defineProperty(process, "platform", { value: platform }); vi.doUnmock("node:child_process"); vi.resetModules(); }
});
it.skipIf(process.platform !== "darwin")("on macOS a real LF-joined attribute name over genuine labels is refused", async () => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8")), { execFile } = await import("node:child_process"), { promisify } = await import("node:util");
  // macOS gives every new file a genuine provenance label, so this joined name lists as two existing names and only the repeat refuses it.
  await promisify(execFile)("/usr/bin/xattr", ["-w", "com.apple.provenance\ncom.apple.quarantine", "x", join(x.options.output, C.REPORT_FILENAME)]);
  await promisify(execFile)("/usr/bin/xattr", ["-w", "com.apple.quarantine", "q", join(x.options.output, C.REPORT_FILENAME)]);
  await expect(captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow(C.HARD.unexpected_metadata);
});
it.each(["com.apple.provenance ", " com.apple.quarantine"])("Darwin capture preserves metadata bytes %j", async name => {
  const x = await exporterFixture(); expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_PASS);
  const receipt = JSON.parse(await readFile(x.options.receipt, "utf8"));
  const platform = process.platform;
  const execute = vi.fn(() => Buffer.from(name + C.LF));
  const lookup = vi.fn(() => ({ status: C.EXIT_PASS }));
  vi.doMock("node:child_process", async original => {
    const { promisify } = await import("node:util");
    return { ...await original<typeof import("node:child_process")>(), execFileSync: execute, spawnSync: lookup, execFile: Object.assign(vi.fn(), { [promisify.custom]: async () => ({ stdout: execute().toString() }) }) };
  });
  try {
    Object.defineProperty(process, "platform", { value: "darwin" }); vi.doUnmock("../../src/evidence-pack/snapshot-trust-cli.js"); vi.resetModules();
    const adapter = await import("../../src/evidence-pack/snapshot-trust-cli.js");
    await expect(adapter.captureSnapshotDirectory(x.options.output, x.f.pack.public_key, receipt.manifest_digest)).rejects.toThrow(C.HARD.unexpected_metadata);
    expect(execute).toHaveBeenCalledOnce(); expect(lookup).not.toHaveBeenCalled();
    expect(execute).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", x.options.output], expect.objectContaining({ shell: false, env: { LC_ALL: "C" }, stdio: ["ignore", "pipe", "ignore"] }));
  } finally { Object.defineProperty(process, "platform", { value: platform }); vi.doUnmock("node:child_process"); vi.resetModules(); }
});

it("self check failure leaves no public key output", async () => {
  const x = await exporterFixture();
  x.deps.phase = async state => { if (state === "SELF_VERIFY") throw new Error("self check"); };
  expect(await exportSnapshot(x.options, x.deps)).toBe(C.EXIT_FAIL);
  await expect(lstat(x.options.publicKeyFile)).rejects.toMatchObject({ code: "ENOENT" });
});
