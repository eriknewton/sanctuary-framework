/**
 * ZZZZZ Batch 5b PR 1/3 — audit-write regression tests for
 * anomaly subscribe/unsubscribe and sentinel subscribe/unsubscribe.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runAnomalyCommand } from "../../src/cli/anomaly.js";
import { runSentinelCommand } from "../../src/cli/sentinel.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ANOMALY_CATALOG } from "../../src/anomaly-detection/anomaly-catalog.js";
import { PHI1_BASELINE_CATALOG } from "../../src/sentinel/sentinels/index.js";

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

describe("anomaly subscribe/unsubscribe audit writes (ZZZZZ pr 1/3)", () => {
  let tempDir: string;
  let appendSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-anomaly-audit-"));
    await mkdir(join(tempDir, "state"), { recursive: true });
    appendSpy = vi.spyOn(AuditLog.prototype, "append").mockImplementation(() => {});
  });

  afterEach(async () => {
    appendSpy.mockRestore();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("anomaly subscribe writes an audit entry on success", async () => {
    // Skip if no catalog entries exist (test environment).
    if (ANOMALY_CATALOG.length === 0) return;
    const entry = ANOMALY_CATALOG[0]!;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAnomalyCommand({
      argv: ["subscribe", entry.detectorId, "--classifier", entry.classifierId],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("Subscribed");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "anomaly.subscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        detector_id: entry.detectorId,
        classifier_id: entry.classifierId,
      }),
    );
  });

  it("anomaly unsubscribe writes an audit entry on success", async () => {
    if (ANOMALY_CATALOG.length === 0) return;
    const entry = ANOMALY_CATALOG[0]!;

    // First subscribe so we can unsubscribe.
    await runAnomalyCommand({
      argv: ["subscribe", entry.detectorId, "--classifier", entry.classifierId],
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });
    appendSpy.mockClear();

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAnomalyCommand({
      argv: ["unsubscribe", entry.detectorId, "--classifier", entry.classifierId],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("Unsubscribed");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "anomaly.unsubscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        detector_id: entry.detectorId,
        classifier_id: entry.classifierId,
      }),
    );
  });

  it("anomaly subscribe writes a failure audit entry for unknown detector", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAnomalyCommand({
      argv: ["subscribe", "nonexistent-detector", "--classifier", "nonexistent-classifier"],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(2);
    expect(err.text).toContain("Unknown detector/classifier pair");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "anomaly.subscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        detector_id: "nonexistent-detector",
        classifier_id: "nonexistent-classifier",
      }),
      "failure",
    );
  });
});

describe("sentinel subscribe/unsubscribe audit writes (ZZZZZ pr 1/3)", () => {
  let tempDir: string;
  let appendSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-sentinel-audit-"));
    await mkdir(join(tempDir, "state"), { recursive: true });
    appendSpy = vi.spyOn(AuditLog.prototype, "append").mockImplementation(() => {});
  });

  afterEach(async () => {
    appendSpy.mockRestore();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("sentinel subscribe writes an audit entry on success", async () => {
    if (PHI1_BASELINE_CATALOG.length === 0) return;
    const sentinel = PHI1_BASELINE_CATALOG[0]!;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runSentinelCommand({
      argv: ["subscribe", sentinel.sentinelId],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("Subscribed");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "sentinel.subscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        sentinel_id: sentinel.sentinelId,
      }),
    );
  });

  it("sentinel unsubscribe writes an audit entry on success", async () => {
    if (PHI1_BASELINE_CATALOG.length === 0) return;
    const sentinel = PHI1_BASELINE_CATALOG[0]!;

    // First subscribe.
    await runSentinelCommand({
      argv: ["subscribe", sentinel.sentinelId],
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });
    appendSpy.mockClear();

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runSentinelCommand({
      argv: ["unsubscribe", sentinel.sentinelId],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(0);
    expect(out.text).toContain("Unsubscribed");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "sentinel.unsubscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        sentinel_id: sentinel.sentinelId,
      }),
    );
  });

  it("sentinel subscribe writes a failure audit entry for unknown sentinel", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runSentinelCommand({
      argv: ["subscribe", "nonexistent-sentinel-id"],
      out,
      err,
      passphrase: "test-passphrase",
      storagePath: tempDir,
    });

    expect(code).toBe(2);
    expect(err.text).toContain("Unknown sentinel");
    expect(appendSpy).toHaveBeenCalledWith(
      "l2",
      "sentinel.subscribe",
      expect.stringContaining("fortress:"),
      expect.objectContaining({
        sentinel_id: "nonexistent-sentinel-id",
      }),
      "failure",
    );
  });
});
