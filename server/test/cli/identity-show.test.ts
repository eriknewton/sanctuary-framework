/**
 * `sanctuary identity show` CLI tests.
 *
 * Verifies:
 *   - Help output on --help.
 *   - Error exit when no passphrase is provided.
 *   - Unknown subcommand returns exit 2 with hint.
 *
 * Does NOT test actual identity decryption (that requires a real seeded
 * fortress with Argon2id derivation, which is exercised in integration
 * tests). The goal here is to confirm the CLI surface exists and routes
 * correctly, fixing drill friction item 1: "sanctuary identity show is
 * not a real subcommand."
 */

import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import { runIdentityCommand } from "../../src/cli/identity.js";

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

describe("sanctuary identity CLI", () => {
  it("prints help on --help", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({ argv: ["--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary identity");
    expect(out.text).toContain("show");
    expect(out.text).toContain("--fortress");
  });

  it("prints help on empty argv", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({ argv: [], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("show");
  });

  it("returns exit 2 for unknown subcommand", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runIdentityCommand({
      argv: ["nonexistent"],
      out,
      err,
    });
    expect(code).toBe(2);
    expect(err.text).toContain("Unknown identity command");
    expect(err.text).toContain("--help");
  });

  it("returns exit 1 when no passphrase is provided", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const savedPass = process.env.SANCTUARY_PASSPHRASE;
    const savedKey = process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      const code = await runIdentityCommand({
        argv: ["show"],
        out,
        err,
        env: {},
      });
      expect(code).toBe(1);
      expect(err.text).toContain("requires SANCTUARY_PASSPHRASE");
    } finally {
      if (savedPass !== undefined) process.env.SANCTUARY_PASSPHRASE = savedPass;
      else delete process.env.SANCTUARY_PASSPHRASE;
      if (savedKey !== undefined) process.env.SANCTUARY_RECOVERY_KEY = savedKey;
      else delete process.env.SANCTUARY_RECOVERY_KEY;
    }
  });
});
