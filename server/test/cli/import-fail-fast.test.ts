/**
 * `sanctuary exit import` fail-fast tests.
 *
 * Verifies drill friction item 4: exit import fails before prompting for
 * a passphrase when the bundle directory does not exist or the manifest
 * is malformed. Previously it would throw a passphrase-missing error
 * first (from openExitContext), confusing operators pointed at a bad path.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runExitCommand } from "../../src/exit/cli.js";

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

describe("exit import fail-fast", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-import-"));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("fails with bundle-not-found before asking for passphrase", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const nonexistent = join(tmpDir, "does-not-exist");

    // No passphrase env set. Pre-fix, this would throw the passphrase
    // error from openExitContext. Post-fix, it should fail with a
    // bundle-not-found error before any passphrase check.
    const code = await runExitCommand({
      argv: ["import", nonexistent],
      out,
      err,
      env: {},
    });

    expect(code).toBe(1);
    expect(err.text).toContain("bundle directory not found");
    expect(err.text).not.toContain("SANCTUARY_PASSPHRASE");
  });

  it("fails with manifest-malformed before asking for passphrase", async () => {
    const out = new StringWritable();
    const err = new StringWritable();

    // Create the directory but with a malformed manifest.
    const bundleDir = join(tmpDir, "bad-bundle");
    await mkdir(bundleDir, { recursive: true });
    await writeFile(join(bundleDir, "manifest.json"), "not valid json {{{");

    const code = await runExitCommand({
      argv: ["import", bundleDir],
      out,
      err,
      env: {},
    });

    expect(code).toBe(1);
    expect(err.text).toContain("manifest missing or malformed");
    expect(err.text).not.toContain("SANCTUARY_PASSPHRASE");
  });

  it("fails with manifest-missing before asking for passphrase", async () => {
    const out = new StringWritable();
    const err = new StringWritable();

    // Create the directory but without manifest.json.
    const bundleDir = join(tmpDir, "empty-bundle");
    await mkdir(bundleDir, { recursive: true });

    const code = await runExitCommand({
      argv: ["import", bundleDir],
      out,
      err,
      env: {},
    });

    expect(code).toBe(1);
    expect(err.text).toContain("manifest missing or malformed");
    expect(err.text).not.toContain("SANCTUARY_PASSPHRASE");
  });
});
