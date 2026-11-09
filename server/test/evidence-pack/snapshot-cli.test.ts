import { describe, it, expect, vi } from "vitest";
import { parseOfflineArguments, parseOfflineKey, runOfflineCommand, captureOfflineSnapshot, metadataNames, METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT, LINUX_METADATA_PROGRAM } from "../../src/evidence-pack/snapshot-offline-cli.js";
import * as child from "node:child_process";
vi.mock("node:child_process", async importOriginal => {
  const native = await importOriginal<typeof import("node:child_process")>();
  const { promisify } = await import("node:util");
  const execFile = vi.fn(native.execFile);
  Object.defineProperty(execFile, promisify.custom, { value: (...args: unknown[]) => new Promise((resolve, reject) => {
    Reflect.apply(execFile, undefined, [...args, (error: Error | null, stdout: string, stderr: string) => error ? reject(error) : resolve({ stdout, stderr })]);
  }) });
  return { ...native, execFile };
});
import * as fs from "node:fs/promises";
vi.mock("node:fs/promises", async importOriginal => ({ ...await importOriginal<typeof import("node:fs/promises")>() }));
import { identity } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { mkdtempSync, mkdirSync, writeFileSync, lstatSync, renameSync, symlinkSync, unlinkSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { HeldIdentity } from "../../src/evidence-pack/snapshot-metadata.js";
// Every capture now supplies the identity of a held file, so the simulated rows use a real file whose inode the recheck can observe.
function heldFile(): { path: string; held: HeldIdentity } {
  const path = join(mkdtempSync(join(tmpdir(), "held-")), "file"); writeFileSync(path, "held");
  return { path, held: lstatSync(path, { bigint: true }) };
}
// The source-level command receives the same full revision shape that tsup bakes into the installed command.
vi.hoisted(() => { Object.assign(globalThis, { __SANCTUARY_SOURCE_SHA__: "a".repeat(40) }); });
const valid = ["--pack", "/unused", "--public-key-file", "/unused-key", "--trust-descriptor-file", "/unused-trust", "--expect-manifest-digest", "sha256:" + "a".repeat(64)];
describe("offline CLI pin grammar", () => {
  it.each([valid.slice(0, -2), [...valid, "--pack", "/other"], [...valid, "--json", "--json"], [...valid, "--help"], [...valid, "--version"], ["--help", "--json"], ["--version", "--json"], [...valid, "--trust-embedded"], [...valid.slice(0, -1), "sha256:" + "A".repeat(64)]].map(args => [args]))("refuses arguments before pack reads %j", async args => {
    const opened = vi.spyOn(fs, "open");
    try { expect(await runOfflineCommand(args, { stdout: () => {}, stderr: () => {} })).toBe(C.EXIT_USAGE); expect(opened).not.toHaveBeenCalled(); }
    finally { opened.mockRestore(); }
  });
  it.each(["--help", "--version"])("only lone %s returns zero without a verdict", async flag => { const lines: string[] = []; expect(await runOfflineCommand([flag], { stdout: t => { lines.push(t); }, stderr: () => {} })).toBe(0); expect(lines.join("")).not.toContain('"status"'); });
  it.each(["--help", "--version", "--pack"])("stdout failure refuses %s", async flag => { expect(await runOfflineCommand([flag], { stdout: () => { throw new Error("closed"); }, stderr: () => { throw new Error("closed"); } })).toBe(1); });
  it("requires all explicit pins and never reads environment pins", () => { vi.stubEnv("SANCTUARY_PUBLIC_KEY", identity().public_key); try { expect(() => parseOfflineArguments(valid.slice(2))).toThrow(); expect(parseOfflineArguments([...valid, "--json"]).json).toBe(true); } finally { vi.unstubAllEnvs(); } });
  it.each(["", "\n"])("canonical key accepts optional terminator %j", suffix => { const key = identity().public_key; expect(parseOfflineKey(C.utf8(key + suffix))).toBe(key); });
  it.each(["leading-space", "trailing-space", "cr", "crlf", "internal-lf", "double-lf", "small-order"])("key grammar refuses %s", kind => {
    const key = identity().public_key;
    const values: Record<string, string> = { "leading-space": " " + key, "trailing-space": key + " ", cr: key + "\r", crlf: key + "\r\n", "internal-lf": key.slice(0, 10) + "\n" + key.slice(10), "double-lf": key + "\n\n", "small-order": Buffer.alloc(C.KEY_BYTES).toString("base64url") };
    expect(() => parseOfflineKey(C.utf8(values[kind]))).toThrow();
  });
});
describe("bounded name-only metadata capture", () => {
  it("Linux uses the sole fixed isolated interpreter and closed environment", () => {
    const { path, held } = heldFile();
    const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from('[]\n'));
    try { expect(metadataNames(path, "linux", held)).toEqual([]); expect(call).toHaveBeenCalledExactlyOnceWith("/usr/bin/python3", ["-I", "-S", "-c", LINUX_METADATA_PROGRAM, path], { env: { LC_ALL: "C" }, shell: false, timeout: METADATA_TIMEOUT_MS, maxBuffer: METADATA_OUTPUT_LIMIT, stdio: ["ignore", "pipe", "ignore"] }); } finally { call.mockRestore(); }
  });
  it.each(["interior-empty", "duplicate", "joined-name", "missing-exact", "tool-failure", "invalid-utf8"])("Darwin metadata refuses %s", kind => {
    const { path, held } = heldFile();
    const output = kind === "interior-empty" ? "com.apple.provenance\n\n" : kind === "duplicate" ? "com.apple.provenance\ncom.apple.provenance\n" : "com.apple.provenance\ncom.apple.quarantine\n";
    const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { if (kind === "tool-failure") throw new Error("missing"); return kind === "invalid-utf8" ? Buffer.from([255]) : Buffer.from(output); });
    const lookup = vi.spyOn(child, "spawnSync").mockReturnValue({ status: ["interior-empty", "duplicate"].includes(kind) ? 0 : 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: 1, output: [], signal: null });
    try { expect(() => metadataNames(path, "darwin", held)).toThrow(C.HARD.unexpected_metadata); } finally { call.mockRestore(); lookup.mockRestore(); }
  });
  it("Darwin allowed exact names discard values and keep fixed argv", () => {
    const { path, held } = heldFile();
    const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from("com.apple.provenance\n"));
    const lookup = vi.spyOn(child, "spawnSync").mockReturnValue({ status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: 1, output: [], signal: null });
    try { expect(metadataNames(path, "darwin", held)).toEqual(["com.apple.provenance"]); expect(call).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", path], expect.anything()); expect(lookup).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", "-p", "com.apple.provenance", path], expect.objectContaining({ stdio: "ignore", shell: false, env: { LC_ALL: "C" } })); } finally { call.mockRestore(); lookup.mockRestore(); }
  });
});

import { fixture, syncAudit } from "./snapshot-fixtures.js";
function verdictInput(status: string) {
  const f = fixture();
  if (status === "PARTIAL") { for (const row of f.records) if (row.type === "checkpoint") { row.unsigned = true; row.signature = null; row.signer_kid = null; delete row.public_key; } syncAudit(f); }
  // The exporter resolves the pack path, so the fixture root is resolved too; on macOS tmpdir() sits under the /var symlink to /private/var.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "verdict-"))), pack = join(root, "pack"); mkdirSync(pack);
  for (const file of f.capture.files) writeFileSync(join(pack, Buffer.from(file.name).toString()), file.bytes);
  if (status === "FAIL") writeFileSync(join(pack, C.PDF_FILENAME), "changed");
  writeFileSync(join(root, "key"), f.pins.packKey); writeFileSync(join(root, "trust"), f.pins.descriptorBytes);
  return ["--pack", pack, "--public-key-file", join(root, "key"), "--trust-descriptor-file", join(root, "trust"), "--expect-manifest-digest", f.pins.expectedManifestDigest, "--json"];
}
it.each(["PASS", "PARTIAL", "FAIL"])("verdict output failure refuses %s after reaching the verdict", async status => {
  const args = verdictInput(status), seen: string[] = [];
  await runOfflineCommand(args, { stdout: text => { seen.push(JSON.parse(text).status); }, stderr: () => {} });
  expect(seen).toEqual([status]);
  for (const asynchronous of [false, true]) {
    let reached = false;
    expect(await runOfflineCommand(args, { stdout: text => { expect(JSON.parse(text).status).toBe(status); reached = true; if (asynchronous) return Promise.reject(new Error("closed")); throw new Error("closed"); }, stderr: () => {} })).toBe(C.EXIT_FAIL);
    expect(reached).toBe(true);
  }
});
it.each(["linux", "darwin", "win32"])("absent enumerator has a distinct capture finding on %s", platform => {
  const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { throw Object.assign(new Error("absent"), { code: "ENOENT" }); });
  try { expect(() => metadataNames("/explicit/file", platform, heldFile().held)).toThrow("enumerator_unavailable"); } finally { call.mockRestore(); }
});
it.each(["bad-utf8", "bom", "space"])("malformed key maps to the pin finding %s", kind => {
  const bytes = kind === "bad-utf8" ? new Uint8Array([255]) : C.utf8((kind === "bom" ? "\uFEFF" : " ") + identity().public_key);
  expect(() => parseOfflineKey(bytes)).toThrow(C.HARD.pin_invalid);
});
it.each(["listing", "lookup"])("Darwin post-enumeration inode observation refuses a replacement after %s", stage => {
  const root = mkdtempSync(join(tmpdir(), "inode-")), path = join(root, "file"); writeFileSync(path, "held");
  const held = lstatSync(path, { bigint: true });
  const replace = () => { renameSync(path, path + ".held"); writeFileSync(path, "other"); };
  const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { if (stage === "listing") replace(); return Buffer.from("com.apple.provenance\n"); });
  const lookup = vi.spyOn(child, "spawnSync").mockImplementation(() => { if (stage === "lookup") replace(); return { status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: 1, output: [], signal: null }; });
  try { expect(() => metadataNames(path, "darwin", held)).toThrow(C.HARD.snapshot_changed); } finally { call.mockRestore(); lookup.mockRestore(); }
});
it.each(["linux", "darwin"])("%s capture refuses a missing held identity before any subprocess", platform => {
  const { path } = heldFile();
  const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from(platform === "linux" ? "[]\n" : ""));
  const lookup = vi.spyOn(child, "spawnSync");
  // The runtime refusal backs the required parameter for JavaScript callers that the type system cannot reach.
  try { expect(() => metadataNames(path, platform, undefined as unknown as HeldIdentity)).toThrow("held identity"); expect(call).not.toHaveBeenCalled(); expect(lookup).not.toHaveBeenCalled(); }
  finally { call.mockRestore(); lookup.mockRestore(); }
});
it.each([false, true])("Linux simulated listing with replacement %s binds names to the held inode", replaced => {
  const { path, held } = heldFile();
  // The simulated interpreter has the same shape as the fixed Linux adapter, so this row runs on every host.
  const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { if (replaced) { renameSync(path, path + ".held"); writeFileSync(path, "other"); } return Buffer.from('["security.selinux"]\n'); });
  try {
    if (replaced) expect(() => metadataNames(path, "linux", held)).toThrow(C.HARD.snapshot_changed);
    else expect(metadataNames(path, "linux", held)).toEqual(["security.selinux"]);
    expect(call).toHaveBeenCalledOnce();
  } finally { call.mockRestore(); }
});
it.skipIf(process.platform !== "darwin")("Darwin native xattr observes the link itself with fixed name lookups", () => {
  const root = mkdtempSync(join(tmpdir(), "darwin-xattr-")), path = join(root, "file"), link = join(root, "link");
  writeFileSync(path, "held"); symlinkSync(path, link);
  child.execFileSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "synthetic", path]);
  expect(metadataNames(path, "darwin", lstatSync(path, { bigint: true }))).toContain("com.apple.quarantine");
  child.execFileSync("/usr/bin/xattr", ["-w", "user.fixture", "value", path]);
  expect(() => metadataNames(path, "darwin", lstatSync(path, { bigint: true }))).toThrow(C.HARD.unexpected_metadata);
  // The link itself is never a capture target, so its listing is observed directly and the held-identity recheck then refuses it.
  const native = child.execFileSync, seen: string[] = [];
  const call = vi.spyOn(child, "execFileSync").mockImplementation((...args) => { const result = Reflect.apply(native, child, args); seen.push(String(result)); return result; });
  try { expect(() => metadataNames(link, "darwin", lstatSync(link, { bigint: true }))).toThrow(C.HARD.snapshot_changed); } finally { call.mockRestore(); }
  expect(seen).toHaveLength(1); expect(seen[0]).not.toContain("user.fixture");
  unlinkSync(link);
});
it.skipIf(process.platform !== "darwin")("Darwin native enumeration checks the held inode after the subprocess", () => {
  const root = mkdtempSync(join(tmpdir(), "darwin-inode-")), path = join(root, "file"); writeFileSync(path, "held");
  const held = lstatSync(path, { bigint: true }), native = child.execFileSync;
  const call = vi.spyOn(child, "execFileSync").mockImplementation((...args) => { const result = Reflect.apply(native, child, args); renameSync(path, path + ".held"); writeFileSync(path, "replacement"); return result; });
  try { expect(() => metadataNames(path, "darwin", held)).toThrow(C.HARD.snapshot_changed); } finally { call.mockRestore(); }
});

it("human capture diagnostics retain the named environment finding", async () => {
  const args = verdictInput("PASS").slice(0, -1), output: string[] = [];
  const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { throw Object.assign(new Error("absent"), { code: "ENOENT" }); });
  try { expect(await runOfflineCommand(args, { stdout: text => { output.push(text); }, stderr: () => {} })).toBe(C.EXIT_FAIL); expect(output.join("")).toContain("enumerator_unavailable"); } finally { call.mockRestore(); }
});

it.each(["not-json", "{}"])("malformed enumerator output retains the capture finding %s", output => {
  const { path, held } = heldFile();
  const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from(output));
  try { expect(() => metadataNames(path, "linux", held)).toThrow(C.HARD.unexpected_metadata); } finally { call.mockRestore(); }
});

import { captureSnapshotDirectory } from "../../src/evidence-pack/snapshot-trust-cli.js";
import { readFileSync } from "node:fs";
// Must match the shared metadata contract: both consumers bind every observation to an open handle.
it("exporter Darwin adapter uses bounded no-follow listing and discarded exact lookups", async () => {
  const args = verdictInput("PASS"), platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const legacy = vi.mocked(child.execFile).mockImplementation(((...argv: unknown[]) => {
    (argv.at(-1) as (error: null, stdout: string, stderr: string) => void)(null, "com.apple.quarantine\n", ""); return {};
  }) as typeof child.execFile);
  const listing = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from("com.apple.quarantine\n"));
  const lookup = vi.spyOn(child, "spawnSync").mockReturnValue({ status: C.EXIT_PASS } as ReturnType<typeof child.spawnSync>);
  Object.defineProperty(process, "platform", { value: "darwin" });
  try {
    const capture = await captureSnapshotDirectory(args[1], readFileSync(args[3], "utf8"), args[7]);
    const paths = [args[1], ...capture.files.map(file => join(args[1], Buffer.from(file.name).toString()))];
    expect(listing.mock.calls).toEqual(paths.map(path => ["/usr/bin/xattr", ["-s", path], { env: { LC_ALL: "C" }, shell: false, timeout: METADATA_TIMEOUT_MS, maxBuffer: METADATA_OUTPUT_LIMIT, stdio: ["ignore", "pipe", "ignore"] }]));
    expect(lookup.mock.calls).toEqual(paths.map(path => ["/usr/bin/xattr", ["-s", "-p", "com.apple.quarantine", path], { env: { LC_ALL: "C" }, shell: false, timeout: METADATA_TIMEOUT_MS, maxBuffer: METADATA_OUTPUT_LIMIT, stdio: "ignore" }]));
    expect(capture.rootMetadata).toEqual(["com.apple.quarantine"]);
    for (const file of capture.files) expect(file.metadata).toEqual(["com.apple.quarantine"]);
  } finally { Object.defineProperty(process, "platform", platform); listing.mockRestore(); lookup.mockRestore(); legacy.mockRestore(); }
});
const REPLACEMENT_STAGES = ["root listing", "root lookup", "file listing", "file lookup"];
it.each(REPLACEMENT_STAGES)("exporter Darwin simulated replacement refuses immediately after %s", stage => replacementWitness(stage, false));
it.skipIf(process.platform !== "darwin").each(REPLACEMENT_STAGES)("exporter Darwin native replacement refuses immediately after %s", stage => replacementWitness(stage, true));
// Must match the held-handle calls in snapshot-offline-cli.ts: the recipient capture binds each listing to the handle it already holds.
it.each(REPLACEMENT_STAGES)("verifier Darwin simulated replacement refuses immediately after %s", stage => replacementWitness(stage, false, captureOfflineSnapshot));
async function replacementWitness(stage: string, native: boolean, capture: typeof captureSnapshotDirectory = captureSnapshotDirectory) {
  const args = verdictInput("PASS"), path = stage.startsWith("root") ? args[1] : join(args[1], C.MANIFEST_FILENAME);
  if (native) child.execFileSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "synthetic", path]);
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const originalList = child.execFileSync, originalLookup = child.spawnSync;
  let replaced = false, callsAfterReplacement = 0;
  const replace = () => { renameSync(path, path + ".held"); if (stage.startsWith("root")) mkdirSync(path); else writeFileSync(path, "replacement"); replaced = true; };
  const listing = vi.spyOn(child, "execFileSync").mockImplementation((...argv) => {
    if (replaced) callsAfterReplacement++;
    const output = native ? Reflect.apply(originalList, child, argv) : Buffer.from("com.apple.quarantine\n");
    if (stage.endsWith("listing") && argv[1]?.at(-1) === path) replace();
    return output;
  });
  const lookup = vi.spyOn(child, "spawnSync").mockImplementation((...argv) => {
    if (replaced) callsAfterReplacement++;
    const output = native ? Reflect.apply(originalLookup, child, argv) : { status: C.EXIT_PASS } as ReturnType<typeof child.spawnSync>;
    if (stage.endsWith("lookup") && argv[1]?.at(-1) === path) replace();
    return output;
  });
  const legacy = vi.mocked(child.execFile).mockImplementation(((...argv: unknown[]) => {
    if (replaced) callsAfterReplacement++;
    const parameters = argv[1] as string[];
    if (parameters.at(-1) === path && stage.endsWith(parameters.includes("-p") ? "lookup" : "listing")) replace();
    (argv.at(-1) as (error: null, stdout: string, stderr: string) => void)(null, "com.apple.quarantine\n", ""); return {};
  }) as typeof child.execFile);
  Object.defineProperty(process, "platform", { value: "darwin" });
  try {
    await expect(capture(args[1], readFileSync(args[3], "utf8"), args[7])).rejects.toThrow(C.HARD.snapshot_changed);
    expect(replaced).toBe(true); expect(callsAfterReplacement).toBe(0);
  } finally { Object.defineProperty(process, "platform", platform); listing.mockRestore(); lookup.mockRestore(); legacy.mockRestore(); }
}
it.skipIf(process.platform !== "darwin")("exporter Darwin native accepts exact attached metadata", async () => {
  const args = verdictInput("PASS");
  child.execFileSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "synthetic", args[1]]);
  const capture = await captureSnapshotDirectory(args[1], readFileSync(args[3], "utf8"), args[7]);
  expect(capture.rootMetadata).toContain("com.apple.quarantine");
});
