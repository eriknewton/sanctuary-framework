/**
 * HABEAS PORT — distress config loader tests.
 *
 * Fail-closed properties: a missing file is the documented local-only
 * default; a PRESENT but malformed file throws (operator intent is never
 * silently substituted); a secret-bearing file readable by non-owner is
 * rejected.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readDistressConfig,
  validateDistressConfig,
  defaultDistressConfig,
  DistressConfigError,
  DISTRESS_DEFAULT_MAX_PER_HOUR,
} from "../../src/distress/config.js";

describe("validateDistressConfig", () => {
  it("accepts an empty object as the local-only default", () => {
    expect(validateDistressConfig({})).toEqual({
      max_signals_per_hour: DISTRESS_DEFAULT_MAX_PER_HOUR,
    });
  });

  it("rejects non-objects and unknown keys", () => {
    expect(() => validateDistressConfig(null)).toThrow(DistressConfigError);
    expect(() => validateDistressConfig([])).toThrow(DistressConfigError);
    expect(() => validateDistressConfig({ exfil_path: "x" })).toThrow(/unknown key/);
  });

  it("rejects max_signals_per_hour outside [1, 60] and non-integers (no silent clamping)", () => {
    expect(() => validateDistressConfig({ max_signals_per_hour: 0 })).toThrow(
      DistressConfigError,
    );
    expect(() => validateDistressConfig({ max_signals_per_hour: 500 })).toThrow(
      DistressConfigError,
    );
    expect(() => validateDistressConfig({ max_signals_per_hour: 1.5 })).toThrow(
      DistressConfigError,
    );
    expect(validateDistressConfig({ max_signals_per_hour: 7 }).max_signals_per_hour).toBe(7);
    expect(validateDistressConfig({ max_signals_per_hour: 1 }).max_signals_per_hour).toBe(1);
    expect(validateDistressConfig({ max_signals_per_hour: 60 }).max_signals_per_hour).toBe(60);
  });

  it("parses a valid webhook config into a webhook_target", () => {
    const config = validateDistressConfig({
      webhook_url: "https://ops.example.com/distress",
      webhook_secret: "0123456789abcdef",
    });
    expect(config.webhook_target).toEqual({ host: "ops.example.com", port: 443 });
  });

  it("requires an HMAC secret (>= 16 chars) with any webhook", () => {
    expect(() =>
      validateDistressConfig({ webhook_url: "https://ops.example.com/d" }),
    ).toThrow(/webhook_secret/);
    expect(() =>
      validateDistressConfig({
        webhook_url: "https://ops.example.com/d",
        webhook_secret: "short",
      }),
    ).toThrow(/webhook_secret/);
    expect(() => validateDistressConfig({ webhook_secret: "0123456789abcdef" })).toThrow(
      /requires webhook_url/,
    );
  });

  it("rejects plain-http webhooks except to loopback (case-insensitive scheme)", () => {
    expect(() =>
      validateDistressConfig({
        webhook_url: "http://ops.example.com/d",
        webhook_secret: "0123456789abcdef",
      }),
    ).toThrow(/https/);
    // Mixed-case scheme must not dodge the check (codex round-1 finding 5).
    expect(() =>
      validateDistressConfig({
        webhook_url: "HTTP://ops.example.com/d",
        webhook_secret: "0123456789abcdef",
      }),
    ).toThrow(/https/);
    expect(
      validateDistressConfig({
        webhook_url: "http://127.0.0.1:9000/d",
        webhook_secret: "0123456789abcdef",
      }).webhook_target,
    ).toEqual({ host: "127.0.0.1", port: 9000 });
  });

  it("rejects non-http(s) webhook URLs", () => {
    expect(() =>
      validateDistressConfig({
        webhook_url: "ftp://ops.example.com/d",
        webhook_secret: "0123456789abcdef",
      }),
    ).toThrow(DistressConfigError);
  });
});

describe("readDistressConfig", () => {
  let fortress: string;

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "habeas-config-"));
    await mkdir(join(fortress, "policy", "egress"), { recursive: true });
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  const configPath = () => join(fortress, "policy", "egress", "distress.json");

  it("returns the local-only default when the file is missing", async () => {
    expect(await readDistressConfig(fortress)).toEqual(defaultDistressConfig());
  });

  it("throws on malformed JSON instead of silently defaulting", async () => {
    await writeFile(configPath(), "{nope");
    await expect(readDistressConfig(fortress)).rejects.toThrow(DistressConfigError);
  });

  it("loads a valid config", async () => {
    await writeFile(
      configPath(),
      JSON.stringify({
        webhook_url: "https://ops.example.com/distress",
        webhook_secret: "0123456789abcdef",
        max_signals_per_hour: 3,
      }),
      { mode: 0o600 },
    );
    const config = await readDistressConfig(fortress);
    expect(config.max_signals_per_hour).toBe(3);
    expect(config.webhook_target).toEqual({ host: "ops.example.com", port: 443 });
  });

  it("rejects a secret-bearing file readable by non-owner", async () => {
    await writeFile(
      configPath(),
      JSON.stringify({
        webhook_url: "https://ops.example.com/distress",
        webhook_secret: "0123456789abcdef",
      }),
    );
    await chmod(configPath(), 0o644);
    await expect(readDistressConfig(fortress)).rejects.toThrow(/non-owner/);
  });
});
