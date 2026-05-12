import { describe, expect, it } from "vitest";
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

describe("sanctuary did-web key rotation CLI", () => {
  it("help lists issue, show, rotate-key, and key-history", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDidWebCommand({ argv: ["--help"], out, err });
    expect(code).toBe(0);
    expect(out.text).toContain("issue");
    expect(out.text).toContain("show");
    expect(out.text).toContain("rotate-key");
    expect(out.text).toContain("key-history");
  });

  it("rotate-key rejects invalid reasons before loading a fortress identity", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDidWebCommand({
      argv: ["rotate-key", "--reason", "automatic"],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--reason must be periodic, compromised, or manual");
  });

  it("rotate-key rejects invalid preservation windows before loading identity", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runDidWebCommand({
      argv: ["rotate-key", "--reason", "manual", "--preserve-days", "-1"],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--preserve-days must be a non-negative integer");
  });
});
