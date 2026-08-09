import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runDidWebCommand } from "../../src/cli/did-web.js";
import { writeLockdownStatus } from "../../src/lockdown/status.js";

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

  it("show prints a lockdown banner when the fortress is locked", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-did-web-lockdown-"));
    const recognition = join(fortress, "recognition");
    await mkdir(recognition, { recursive: true });
    await writeFile(
      join(recognition, "did-web.json"),
      JSON.stringify({
        version: 1,
        identifier: {
          did: "did:web:example.com",
          authority_host: "example.com",
          created_at: "2026-05-19T11:00:00.000Z",
          did_document: {},
        },
        artifact: {
          url: "https://example.com/.well-known/did.json",
          sha256: "0".repeat(64),
        },
      }),
    );
    await writeLockdownStatus(fortress, {
      active: true,
      activated_at: "2026-05-19T12:00:00.000Z",
      reason: "operator_lockdown",
    });

    const out = new StringWritable();
    const err = new StringWritable();
    const prior = process.env.SANCTUARY_STORAGE_PATH;
    try {
      const code = await runDidWebCommand({
        argv: ["show", "--fortress", fortress],
        out,
        err,
      });
      expect(code).toBe(0);
      expect(out.text).toContain(
        "Fortress lockdown status is ACTIVE (since 2026-05-19T12:00:00.000Z). CLI status only; writes are not blocked by this flag.",
      );
      expect(out.text).toContain("did:web identifier registered");
    } finally {
      if (prior === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = prior;
      await rm(fortress, { recursive: true, force: true });
    }
  });
});
