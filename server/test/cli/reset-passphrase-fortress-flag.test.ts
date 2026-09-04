/**
 * `sanctuary reset-passphrase --fortress` flag tests.
 *
 * Verifies drill friction item 2: the --fortress flag is accepted and
 * plumbed into the storage path resolution, consistent with `wrap` and
 * `exit` which already accept --fortress.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";
import { runResetPassphraseCommand } from "../../src/cli/reset-passphrase.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(
      typeof chunk === "string" ? chunk : chunk.toString("utf8")
    );
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
  const stream = Readable.from([
    Buffer.from(payload),
  ]) as unknown as NodeJS.ReadableStream & { isTTY?: boolean };
  stream.isTTY = false;
  return stream;
}

describe("reset-passphrase --fortress flag", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanctuary-reset-fortress-"));
    mkdirSync(join(tmpDir, "state"), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("--fortress overrides the resolved storage path", async () => {
    const out = new StringWritable();
    const err = new StringWritable();

    // Put a runtime.json in the fortress to trigger the "refuse-if-unlocked"
    // guard. This proves the --fortress flag was used (the guard checks the
    // specified path, not the default ~/.sanctuary).
    writeFileSync(join(tmpDir, "runtime.json"), "{}");

    const code = await runResetPassphraseCommand({
      argv: ["--fortress", tmpDir, "--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: "/should/not/be/used",
    });

    // Exit 1 = refused because runtime.json exists at the --fortress path.
    expect(code).toBe(1);
    expect(err.text).toContain("runtime.json");
    expect(err.text).toContain(tmpDir);
  });

  it("--fortress= overrides the resolved storage path", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    writeFileSync(join(tmpDir, "runtime.json"), "{}");

    const code = await runResetPassphraseCommand({
      argv: [`--fortress=${tmpDir}`, "--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: "/should/not/be/used",
    });

    expect(code).toBe(1);
    expect(err.text).toContain("runtime.json");
    expect(err.text).toContain(tmpDir);
  });

  it("--storage= remains a fortress alias", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    writeFileSync(join(tmpDir, "runtime.json"), "{}");

    const code = await runResetPassphraseCommand({
      argv: [`--storage=${tmpDir}`, "--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: "/should/not/be/used",
    });

    expect(code).toBe(1);
    expect(err.text).toContain("runtime.json");
    expect(err.text).toContain(tmpDir);
  });

  it("refuses conflicting --fortress and --storage aliases", async () => {
    const err = new StringWritable();
    const code = await runResetPassphraseCommand({
      argv: ["--fortress", tmpDir, "--storage", "/different", "--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: stdinFromLines([]),
    });
    expect(code).toBe(2);
    expect(err.text).toMatch(/^Error: /);
    expect(err.text).toContain("--fortress");
    expect(err.text).toContain("--storage");
    expect(err.text).toMatch(/both|alias|conflict/i);
  });

  it("refuses missing fortress and storage values before resolving the default fortress", async () => {
    for (const flag of ["--fortress", "--storage"]) {
      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runResetPassphraseCommand({
        argv: [flag],
        out,
        err,
        stdin: stdinFromLines([]),
        storagePath: tmpDir,
      });

      expect(code).toBe(2);
      expect(err.text).toMatch(/^Error: /);
      expect(err.text).toContain(`${flag} requires a value`);
    }
  });

  it("help text documents --fortress", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runResetPassphraseCommand({
      argv: ["--help"],
      out,
      err,
      stdin: stdinFromLines([]),
    });
    expect(code).toBe(0);
    expect(out.text).toContain("--fortress");
  });
});
