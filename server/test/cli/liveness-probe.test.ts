import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  formatLivenessProbeResultLine,
  runLivenessProbeCommand,
} from "../../src/cli/liveness-probe.js";

class CaptureStream extends Writable {
  chunks: string[] = [];

  _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }

  text(): string {
    return this.chunks.join("");
  }
}

describe("sanctuary liveness-probe CLI", () => {
  it("prints help for the standalone verb", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runLivenessProbeCommand({ argv: ["--help"], out, err });

    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary liveness-probe");
    expect(out.text()).toContain("<fortress>/config/liveness-probe/telegram.json");
    expect(err.text()).toBe("");
  });

  it("refuses a MISSING fortress instead of degrading it to no_channel_configured (re-gate round 3)", async () => {
    // This test previously enshrined the bypass: a nonexistent fortress read as
    // the benign "no probe channel configured" case, so a caller pointed at the
    // wrong path — or a fortress that vanished under it — got a quiet unverified
    // instead of a refusal. An absent CONFIG FILE inside a VERIFIED fortress is
    // still the benign case; a missing fortress BASE is a config error.
    const out = new CaptureStream();
    const err = new CaptureStream();
    // Guaranteed-absent: a child of a freshly created temp dir, so the pin does
    // not depend on a hard-coded /tmp path staying nonexistent on the runner.
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-liveness-missing-"));
    const missingFortress = join(parent, "no-such-fortress");

    const code = await runLivenessProbeCommand({
      argv: ["--fortress", missingFortress],
      out,
      err,
      env: {},
    });

    expect(code).toBe(2);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("config_unreadable");
    // The credential path must never reach operator output on any error path.
    expect(err.text()).not.toContain("telegram.json");
    expect(err.text()).not.toContain(missingFortress);
    await rm(parent, { recursive: true, force: true });
  });

  it("returns config-error exit for malformed CLI options", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();

    const code = await runLivenessProbeCommand({
      argv: ["--timeout-ms", "0"],
      out,
      err,
      env: {},
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("--timeout-ms must be a positive integer");
    expect(out.text()).toBe("");
  });

  it("renders verified liveness only as a Telegram confined-path round trip", () => {
    const line = formatLivenessProbeResultLine({
      kind: "cos_liveness_verified",
      roundTrip: {
        channel: "telegram",
        requestId: "telegram:700:nonce8:abcdef12",
        responseId: "telegram:8001",
      },
    });

    expect(line).toBe(
      "verified: Telegram round trip verified on the confined path channel=telegram request=telegram:700:nonce8:abcdef12 response=telegram:8001",
    );
    expect(line).not.toMatch(/brain|provider/i);
  });

  it("prints only sanitized config codes for malformed token-file content", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cli-liveness-secret-"));
    const out = new CaptureStream();
    const err = new CaptureStream();
    const distinctiveSecret = "CLI_LIVENESS_CONFIG_SECRET_MUST_NOT_PRINT_91b82e";
    try {
      const configDir = join(dir, "config", "liveness-probe");
      await mkdir(configDir, { recursive: true, mode: 0o700 });
      await chmod(join(dir, "config"), 0o700);
      await chmod(configDir, 0o700);
      const configPath = join(configDir, "telegram.json");
      await writeFile(configPath, distinctiveSecret, { mode: 0o600 });

      const code = await runLivenessProbeCommand({
        argv: ["--fortress", dir],
        out,
        err,
        env: {},
      });

      expect(code).toBe(2);
      expect(err.text()).toBe("liveness-probe config error: config_malformed\n");
      expect(err.text()).not.toContain(distinctiveSecret);
      expect(err.text()).not.toContain(configPath);
      expect(err.text()).not.toContain("telegram.json");
      expect(err.text()).not.toMatch(/Unexpected token|not valid JSON|JSON\.parse/i);
      expect(out.text()).not.toContain(distinctiveSecret);
      expect(out.text()).not.toContain(configPath);
      expect(out.text()).not.toContain("telegram.json");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
