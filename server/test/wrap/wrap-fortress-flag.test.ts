/**
 * sanctuary wrap --fortress <path> — flag honored end-to-end (Finding T)
 *
 * v1.1.0 silently ignored `sanctuary wrap --fortress <path>`, found the
 * existing harness config, and updated the singleton at ~/.sanctuary
 * regardless. v1.1.1 promotes --fortress and SANCTUARY_FORTRESS_PATH
 * onto SANCTUARY_STORAGE_PATH at the very top of runWrap, before any
 * downstream code calls resolveStoragePath().
 *
 * These tests pin both halves of the fix:
 *
 *   1. parseWrapArgs captures --fortress into WrapOptions.fortress.
 *   2. promoteFortressToStoragePath honors the documented precedence
 *      (flag > FORTRESS env > STORAGE env).
 *   3. buildSanctuaryEnv persists the winning storage source into the
 *      harness entry env with the same precedence: fortress sources win
 *      and travel as SANCTUARY_FORTRESS_PATH; a bare SANCTUARY_STORAGE_PATH
 *      tenancy travels as SANCTUARY_STORAGE_PATH (so harness restarts and
 *      the wrapped-install update-advice probe resolve the tenant fortress,
 *      not the default).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  buildSanctuaryEnv,
  parseWrapArgs,
  promoteFortressToStoragePath,
} from "../../src/wrap/cli.js";

describe("parseWrapArgs --fortress capture", () => {
  it("captures --fortress <path> into WrapOptions", () => {
    const opts = parseWrapArgs([
      "--claude-code",
      "--fortress",
      "/tmp/test-fortress-1",
    ]);
    expect(opts.fortress).toBe("/tmp/test-fortress-1");
    expect(opts.claudeCode).toBe(true);
  });

  it("returns undefined when --fortress is not passed", () => {
    const opts = parseWrapArgs(["--claude-code"]);
    expect(opts.fortress).toBeUndefined();
  });
});

describe("promoteFortressToStoragePath", () => {
  let originalStoragePath: string | undefined;
  let originalFortressPath: string | undefined;

  beforeEach(() => {
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalFortressPath = process.env.SANCTUARY_FORTRESS_PATH;
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_FORTRESS_PATH;
  });

  afterEach(() => {
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    if (originalFortressPath === undefined) {
      delete process.env.SANCTUARY_FORTRESS_PATH;
    } else {
      process.env.SANCTUARY_FORTRESS_PATH = originalFortressPath;
    }
  });

  it("promotes options.fortress onto SANCTUARY_STORAGE_PATH", () => {
    promoteFortressToStoragePath({ fortress: "/tmp/from-flag" });
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe("/tmp/from-flag");
  });

  it("promotes SANCTUARY_FORTRESS_PATH onto SANCTUARY_STORAGE_PATH when flag is absent", () => {
    process.env.SANCTUARY_FORTRESS_PATH = "/tmp/from-fortress-env";
    promoteFortressToStoragePath({});
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe("/tmp/from-fortress-env");
  });

  it("flag wins over SANCTUARY_FORTRESS_PATH env var", () => {
    process.env.SANCTUARY_FORTRESS_PATH = "/tmp/env-loses";
    promoteFortressToStoragePath({ fortress: "/tmp/flag-wins" });
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe("/tmp/flag-wins");
  });

  it("leaves SANCTUARY_STORAGE_PATH untouched when neither flag nor FORTRESS env is set", () => {
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/preexisting-storage";
    promoteFortressToStoragePath({});
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe("/tmp/preexisting-storage");
  });

  it("flag wins over preexisting SANCTUARY_STORAGE_PATH (operator intent supersedes legacy)", () => {
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/preexisting-storage";
    promoteFortressToStoragePath({ fortress: "/tmp/operator-supplied" });
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe("/tmp/operator-supplied");
  });
});

describe("buildSanctuaryEnv storage-path persistence", () => {
  const ENV_KEYS = [
    "SANCTUARY_STORAGE_PATH",
    "SANCTUARY_FORTRESS_PATH",
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_DASHBOARD_AUTH_TOKEN",
    "SANCTUARY_DASHBOARD_ENABLED",
    "SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE",
  ] as const;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
  });

  it("persists SANCTUARY_STORAGE_PATH into the harness entry when no fortress source exists", () => {
    // Tenant wrap: the pointer/custody writes honour SANCTUARY_STORAGE_PATH,
    // so the persisted entry must carry the same path or a harness that does
    // not inherit the shell var spawns the pinned server against the default
    // storage (wrong fortress; wrapped-install update advice false-negative).
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/tenant-storage";
    const env = buildSanctuaryEnv({});
    expect(env.SANCTUARY_STORAGE_PATH).toBe("/tmp/tenant-storage");
    expect(env.SANCTUARY_FORTRESS_PATH).toBeUndefined();
  });

  it("--fortress supersedes SANCTUARY_STORAGE_PATH (fortress var alone is persisted)", () => {
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/tenant-storage";
    const env = buildSanctuaryEnv({ fortress: "/tmp/flag-fortress" });
    expect(env.SANCTUARY_FORTRESS_PATH).toBe("/tmp/flag-fortress");
    expect(env.SANCTUARY_STORAGE_PATH).toBeUndefined();
  });

  it("SANCTUARY_FORTRESS_PATH env supersedes SANCTUARY_STORAGE_PATH", () => {
    process.env.SANCTUARY_FORTRESS_PATH = "/tmp/env-fortress";
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/tenant-storage";
    const env = buildSanctuaryEnv({});
    expect(env.SANCTUARY_FORTRESS_PATH).toBe("/tmp/env-fortress");
    expect(env.SANCTUARY_STORAGE_PATH).toBeUndefined();
  });

  it("persists neither storage var when no source is set", () => {
    const env = buildSanctuaryEnv({});
    expect(env.SANCTUARY_FORTRESS_PATH).toBeUndefined();
    expect(env.SANCTUARY_STORAGE_PATH).toBeUndefined();
  });
});
