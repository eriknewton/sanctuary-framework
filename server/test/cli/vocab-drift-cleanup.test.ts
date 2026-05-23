import { describe, it, expect, afterEach, vi } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runAnomalyCommand } from "../../src/cli/anomaly.js";
import { runExitCommand } from "../../src/exit/cli.js";
import { runIntelligenceCommand } from "../../src/cli/intelligence.js";

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

describe("CLI vocabulary drift cleanup (F-GA-10/11/12)", () => {
  let tempDir: string | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
      tempDir = undefined;
    }
  });

  it("sanctuary anomaly status is a non-error alias for list-subscribed", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-anomaly-status-"));
    const out = new StringWritable();
    const err = new StringWritable();

    const code = await runAnomalyCommand({
      argv: ["status"],
      out,
      err,
      storagePath: tempDir,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("(no subscriptions)");
    expect(err.text).toBe("");
  });

  it("sanctuary intelligence diagnose --json emits machine-readable JSON", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-intelligence-json-"));
    await mkdir(join(tempDir, "state", "_intelligence"), { recursive: true });

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const code = await runIntelligenceCommand({
      argv: ["diagnose", "--fortress", tempDir, "--json"],
    });

    expect(code).toBe(0);
    expect(errSpy).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledTimes(1);

    const payload = JSON.parse(logSpy.mock.calls[0]![0] as string);
    expect(payload).toMatchObject({
      ok: true,
      fortress: tempDir,
      intelligence: {
        exists: true,
        entries: [],
      },
    });
  });

  it("sanctuary exit help prints exit help with code 0", async () => {
    const out = new StringWritable();
    const err = new StringWritable();

    const code = await runExitCommand({ argv: ["help"], out, err });

    expect(code).toBe(0);
    expect(out.text).toContain("Usage: sanctuary exit <command> [options]");
    expect(out.text).toContain("SANCTUARY_EXIT_BUNDLE_V1");
    expect(err.text).toBe("");
  });
});
