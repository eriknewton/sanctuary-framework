import { describe, it, expect, vi } from "vitest";
import { parseOfflineArguments, parseOfflineKey, runOfflineCommand, metadataNames, METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT, LINUX_METADATA_PROGRAM } from "../../src/evidence-pack/snapshot-offline-cli.js";
import * as child from "node:child_process";
vi.mock("node:child_process", async importOriginal => ({ ...await importOriginal<typeof import("node:child_process")>() }));
import * as fs from "node:fs/promises";
vi.mock("node:fs/promises", async importOriginal => ({ ...await importOriginal<typeof import("node:fs/promises")>() }));
import { identity } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
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
    const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from('[]\n'));
    try { expect(metadataNames("/explicit/file", "linux")).toEqual([]); expect(call).toHaveBeenCalledExactlyOnceWith("/usr/bin/python3", ["-I", "-S", "-c", LINUX_METADATA_PROGRAM, "/explicit/file"], { env: { LC_ALL: "C" }, shell: false, timeout: METADATA_TIMEOUT_MS, maxBuffer: METADATA_OUTPUT_LIMIT, stdio: ["ignore", "pipe", "ignore"] }); } finally { call.mockRestore(); }
  });
  it.each(["interior-empty", "duplicate", "joined-name", "missing-exact", "tool-failure", "invalid-utf8"])("Darwin metadata refuses %s", kind => {
    const output = kind === "interior-empty" ? "com.apple.provenance\n\n" : kind === "duplicate" ? "com.apple.provenance\ncom.apple.provenance\n" : "com.apple.provenance\ncom.apple.quarantine\n";
    const call = vi.spyOn(child, "execFileSync").mockImplementation(() => { if (kind === "tool-failure") throw new Error("missing"); return kind === "invalid-utf8" ? Buffer.from([255]) : Buffer.from(output); });
    const lookup = vi.spyOn(child, "spawnSync").mockReturnValue({ status: ["interior-empty", "duplicate"].includes(kind) ? 0 : 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: 1, output: [], signal: null });
    try { expect(() => metadataNames("/explicit/file", "darwin")).toThrow(C.HARD.unexpected_metadata); } finally { call.mockRestore(); lookup.mockRestore(); }
  });
  it("Darwin allowed exact names discard values and keep fixed argv", () => {
    const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from("com.apple.provenance\n"));
    const lookup = vi.spyOn(child, "spawnSync").mockReturnValue({ status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), pid: 1, output: [], signal: null });
    try { expect(metadataNames("/explicit/file", "darwin")).toEqual(["com.apple.provenance"]); expect(call).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", "/explicit/file"], expect.anything()); expect(lookup).toHaveBeenCalledWith("/usr/bin/xattr", ["-s", "-p", "com.apple.provenance", "/explicit/file"], expect.objectContaining({ stdio: "ignore", shell: false, env: { LC_ALL: "C" } })); } finally { call.mockRestore(); lookup.mockRestore(); }
  });
});

import { mkdtempSync, mkdirSync, writeFileSync, lstatSync, renameSync, symlinkSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fixture, syncAudit } from "./snapshot-fixtures.js";
function verdictInput(status: string) {
  const f = fixture();
  if (status === "PARTIAL") { for (const row of f.records) if (row.type === "checkpoint") { row.unsigned = true; row.signature = null; row.signer_kid = null; delete row.public_key; } syncAudit(f); }
  const root = mkdtempSync(join(tmpdir(), "verdict-")), pack = join(root, "pack"); mkdirSync(pack);
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
  try { expect(() => metadataNames("/explicit/file", platform)).toThrow("enumerator_unavailable"); } finally { call.mockRestore(); }
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
it.skipIf(process.platform !== "darwin")("Darwin native xattr observes the link itself with fixed name lookups", () => {
  const root = mkdtempSync(join(tmpdir(), "darwin-xattr-")), path = join(root, "file"), link = join(root, "link");
  writeFileSync(path, "held"); symlinkSync(path, link);
  child.execFileSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "synthetic", path]);
  expect(metadataNames(path, "darwin", lstatSync(path, { bigint: true }))).toContain("com.apple.quarantine");
  child.execFileSync("/usr/bin/xattr", ["-w", "user.fixture", "value", path]);
  expect(() => metadataNames(path, "darwin")).toThrow(C.HARD.unexpected_metadata);
  expect(metadataNames(link, "darwin")).not.toContain("user.fixture");
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
  const call = vi.spyOn(child, "execFileSync").mockReturnValue(Buffer.from(output));
  try { expect(() => metadataNames("/explicit/file", "linux")).toThrow(C.HARD.unexpected_metadata); } finally { call.mockRestore(); }
});
