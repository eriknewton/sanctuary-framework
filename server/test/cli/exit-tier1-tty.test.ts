import { describe, expect, it } from "vitest";
import { Readable, Writable } from "node:stream";

import { confirmTier1, runExitCommand } from "../../src/exit/cli.js";

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

describe("Tier 1 CLI approval terminal binding", () => {
  it("denies piped stdin when no interactive terminal is available", async () => {
    const err = new StringWritable();
    const approved = await confirmTier1(
      "Tier 1 approval required?",
      false,
      Readable.from(["y\n"]),
      err,
    );

    expect(approved).toBe(false);
    expect(err.text).toContain("no interactive terminal available");
    expect(err.text).toContain("--yes");
  });

  it("preserves explicit non-interactive approval through assumeYes", async () => {
    const err = new StringWritable();
    const approved = await confirmTier1(
      "Tier 1 approval required?",
      true,
      Readable.from([]),
      err,
    );

    expect(approved).toBe(true);
    expect(err.text).toBe("");
  });

  it("denies exit export without --yes and without an interactive terminal", async () => {
    const out = new StringWritable();
    const err = new StringWritable();

    const code = await runExitCommand({
      argv: ["export", "--out", "/tmp/sanctuary-f-ga-5-denied"],
      out,
      err,
      stdin: Readable.from(["y\n"]),
      env: { SANCTUARY_PASSPHRASE: "unused-because-approval-denies-first" },
    });

    expect(code).toBe(1);
    expect(out.text).toBe("");
    expect(err.text).toContain("no interactive terminal available");
    expect(err.text).toContain("--yes");
    expect(err.text).toContain("Aborted.");
  });
});
