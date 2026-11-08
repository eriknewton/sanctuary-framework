import { describe, it, expect, vi } from "vitest";
import { parseOfflineArguments, parseOfflineKey, runOfflineCommand, metadataNames, METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT, LINUX_METADATA_PROGRAM } from "../../src/evidence-pack/snapshot-offline-cli.js";
import * as child from "node:child_process";
vi.mock("node:child_process", async importOriginal => ({ ...await importOriginal<typeof import("node:child_process")>() }));
import * as fs from "node:fs/promises";
vi.mock("node:fs/promises", async importOriginal => ({ ...await importOriginal<typeof import("node:fs/promises")>() }));
import { identity } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
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
    try { expect(metadataNames("/explicit/file", "darwin")).toEqual(["com.apple.provenance"]); expect(lookup).toHaveBeenCalledWith("/usr/bin/xattr", ["-p", "com.apple.provenance", "/explicit/file"], expect.objectContaining({ stdio: "ignore", shell: false, env: { LC_ALL: "C" } })); } finally { call.mockRestore(); lookup.mockRestore(); }
  });
});
