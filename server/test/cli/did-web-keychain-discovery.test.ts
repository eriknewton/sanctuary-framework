/**
 * `sanctuary did-web issue` Keychain auto-discovery test (KKKKK)
 *
 * Verifies that did-web issue attempts Keychain auto-discovery when
 * --passphrase is not provided, and that explicit --passphrase still works.
 */

import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import { runDidWebCommand } from "../../src/cli/did-web.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

describe("sanctuary did-web Keychain auto-discovery (KKKKK)", () => {
  it("issue without passphrase mentions Keychain in error", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDidWebCommand({
      argv: ["issue", "--authority-host", "example.com", "--fortress", "/tmp/nonexistent-fortress-kkkkk"],
      out,
      err,
      env: {}, // no SANCTUARY_PASSPHRASE, no SANCTUARY_RECOVERY_KEY
    });
    // Should fail (no keychain entry for nonexistent fortress), but
    // error message should mention Keychain auto-discovery
    expect(code).not.toBe(0);
    expect(err.text).toContain("Keychain auto-discovery");
  });

  it("issue with explicit --passphrase does not mention Keychain", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDidWebCommand({
      argv: ["issue", "--authority-host", "example.com", "--fortress", "/tmp/nonexistent-fortress-kkkkk", "--passphrase", "test-pass"],
      out,
      err,
      env: {},
    });
    // Will fail for other reasons (no fortress), but should NOT mention Keychain
    expect(err.text).not.toContain("Keychain auto-discovery");
  });
});
