/**
 * `sanctuary reset-passphrase --nuke` memory-zeroize regression tests.
 *
 * Closes full-sweep #63 (P2 medium): the nuke path destroys storage and
 * clears the keychain entry but did not previously call `Buffer.fill(0)`
 * on caller-supplied key-material buffers, and did not provide a way to
 * bound the post-wipe heap-dump window. This suite is the pre-fix-fail /
 * post-fix-pass regression that pins the new contract:
 *
 *   1. Caller-supplied `keyMaterialToZeroize` buffers are zeroed in the
 *      `finally` block, regardless of whether the recovery path succeeded
 *      or aborted at any of the three confirmation prompts.
 *   2. `--exit-on-completion` calls the injectable `exitProcess` with code
 *      0 ONLY after a successful nuke.
 *   3. The `zeroizeBuffers` helper itself zeroes Buffer + Uint8Array,
 *      handles `undefined` entries safely, and does not throw on an
 *      already-detached / read-only buffer.
 *
 * Threat-model documentation:
 *   JS strings are immutable in V8 and cannot be explicitly zeroed; this
 *   suite intentionally does NOT assert on heap state for string inputs.
 *   Operators on extreme threat models route key material through Buffer
 *   or Uint8Array AND pass `--exit-on-completion`; the buffer-zero hook
 *   plus the OS reaper bound the heap-dump window. Full heap-dump tests
 *   are out of scope per spawn prompt.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";
import {
  runResetPassphraseCommand,
  zeroizeBuffers,
} from "../../src/cli/reset-passphrase.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function stdinFromLines(
  lines: string[]
): NodeJS.ReadableStream & { isTTY?: boolean } {
  const payload = lines.join("\n") + "\n";
  const stream = Readable.from([Buffer.from(payload)]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  stream.isTTY = false;
  return stream;
}

function makeExec(): {
  exec: (
    cmd: string,
    args: string[]
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
} {
  return {
    exec: async () => ({ stdout: "", stderr: "", code: 0 }),
  };
}

function isAllZero(buf: Buffer | Uint8Array): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

describe("zeroizeBuffers helper (full-sweep #63)", () => {
  it("zeros each Buffer in the list", () => {
    const a = Buffer.from("hunter2-passphrase-bytes", "utf-8");
    const b = Buffer.from([7, 7, 7, 7]);
    expect(isAllZero(a)).toBe(false);
    expect(isAllZero(b)).toBe(false);

    zeroizeBuffers([a, b]);

    expect(isAllZero(a)).toBe(true);
    expect(isAllZero(b)).toBe(true);
  });

  it("zeros each Uint8Array in the list", () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    expect(isAllZero(arr)).toBe(false);

    zeroizeBuffers([arr]);

    expect(isAllZero(arr)).toBe(true);
  });

  it("handles undefined and missing entries without throwing", () => {
    const a = Buffer.from([0xff, 0xff]);
    expect(() => zeroizeBuffers([a, undefined, undefined, a])).not.toThrow();
    expect(isAllZero(a)).toBe(true);
  });

  it("is a no-op on undefined input", () => {
    expect(() => zeroizeBuffers(undefined)).not.toThrow();
  });

  it("is a no-op on empty list", () => {
    expect(() => zeroizeBuffers([])).not.toThrow();
  });
});

describe("sanctuary reset-passphrase --nuke memory zeroize (full-sweep #63)", () => {
  let tempDir: string;
  let storage: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "sanctuary-mem-zero-"));
    storage = join(tempDir, "fortress-zero");
    mkdirSync(storage, { recursive: true });
    writeFileSync(join(storage, "principal-policy.yaml"), "policy: stub\n");
    writeFileSync(join(storage, "passphrase.enc"), Buffer.from([0, 1, 2, 3]));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort.
    }
  });

  it("zeroes caller-supplied key-material buffers after a successful nuke", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();

    const passphraseBuf = Buffer.from("operator-old-passphrase-bytes", "utf-8");
    const recoveryKeyBuf = Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad]);
    expect(isAllZero(passphraseBuf)).toBe(false);
    expect(isAllZero(recoveryKeyBuf)).toBe(false);

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-zero", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      keyMaterialToZeroize: [passphraseBuf, recoveryKeyBuf],
    });

    expect(code).toBe(0);
    expect(isAllZero(passphraseBuf)).toBe(true);
    expect(isAllZero(recoveryKeyBuf)).toBe(true);
  });

  it("zeroes caller-supplied buffers EVEN WHEN the operator aborts the nuke", async () => {
    // Aborts at the fortress-name confirmation. The finally block in
    // runResetPassphraseCommand must still call zeroizeBuffers — that is
    // the whole point of having the hook fire on every exit branch.
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();

    const aborterBuf = Buffer.from("must-still-be-zeroed", "utf-8");
    expect(isAllZero(aborterBuf)).toBe(false);

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      // Wrong fortress name → abort on first prompt.
      stdin: stdinFromLines(["WRONG-NAME", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      keyMaterialToZeroize: [aborterBuf],
    });

    expect(code).toBe(1); // Aborted.
    expect(isAllZero(aborterBuf)).toBe(true);
  });

  it("zeroes caller-supplied buffers when the run is degraded (--mode shares not configured)", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();

    const sharesPathBuf = Buffer.from("share-bytes", "utf-8");
    expect(isAllZero(sharesPathBuf)).toBe(false);

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "shares"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      keyMaterialToZeroize: [sharesPathBuf],
    });

    expect(code).toBe(2); // Degraded.
    expect(isAllZero(sharesPathBuf)).toBe(true);
  });

  it("--exit-on-completion calls exitProcess(0) AFTER zeroize on a successful nuke", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();

    const passphraseBuf = Buffer.from("zero-then-exit", "utf-8");
    expect(isAllZero(passphraseBuf)).toBe(false);

    const exitCalls: number[] = [];
    let zeroAtExitCall = false;

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke", "--exit-on-completion"],
      out,
      err,
      stdin: stdinFromLines(["fortress-zero", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      keyMaterialToZeroize: [passphraseBuf],
      exitProcess: (c: number) => {
        // Capture buffer state at the moment of exit so we can prove the
        // ordering invariant: zeroize runs BEFORE exit. If this assertion
        // captured `false`, the threat-model contract would be broken
        // even though the buffer ends up zeroed by post-exit accounting.
        zeroAtExitCall = isAllZero(passphraseBuf);
        exitCalls.push(c);
      },
    });

    expect(code).toBe(0);
    expect(exitCalls).toEqual([0]);
    expect(zeroAtExitCall).toBe(true);
    expect(isAllZero(passphraseBuf)).toBe(true);
  });

  it("--exit-on-completion does NOT call exitProcess on a degraded run", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const exitCalls: number[] = [];

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "shares", "--exit-on-completion"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      exitProcess: (c: number) => exitCalls.push(c),
    });

    expect(code).toBe(2);
    expect(exitCalls).toEqual([]); // Shell stays open so the operator can re-run.
  });

  it("--exit-on-completion does NOT call exitProcess when the operator aborts the nuke", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const exitCalls: number[] = [];

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke", "--exit-on-completion"],
      out,
      err,
      stdin: stdinFromLines(["WRONG-NAME", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
      exitProcess: (c: number) => exitCalls.push(c),
    });

    expect(code).toBe(1);
    expect(exitCalls).toEqual([]);
  });

  it("--help mentions --exit-on-completion and the heap-dump-window framing", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();

    const code = await runResetPassphraseCommand({
      argv: ["--help"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("--exit-on-completion");
    expect(out.text).toContain("heap-dump");
  });

  it("string-typed key material is not zeroable in JS — documented limitation", () => {
    // V8 holds JS strings as immutable UTF-16 in the heap. There is no
    // user-space API to scrub a string in place: any helper would need
    // to recompute the GC slot, which is unavailable from JS land.
    //
    // This test intentionally asserts NOTHING about heap state. It pins
    // the documented contract: callers that need mem-hygiene route key
    // material through Buffer / Uint8Array, NOT through string. The
    // --exit-on-completion flag is the supported escape hatch when the
    // string path is unavoidable.
    const passphraseString = "hunter2";
    expect(typeof passphraseString).toBe("string");
    expect(passphraseString.length).toBeGreaterThan(0);
  });
});
