// fail-before-exempt: tsup source SHA resolution lives in server/tsup.config.ts, outside the server/src revert set.
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Must match SANCTUARY_SOURCE_SHA_ENV in server/tsup.config.ts.
const SANCTUARY_SOURCE_SHA_ENV = "SANCTUARY_SOURCE_SHA";
const SOURCE_SHA_BYTES = 20; // SHA-1 commit ids are 20 raw bytes.
const HEX_CHARS_PER_BYTE = 2;
const SOURCE_SHA_HEX_CHARS = SOURCE_SHA_BYTES * HEX_CHARS_PER_BYTE;
const VALID_SOURCE_SHA = "a".repeat(SOURCE_SHA_HEX_CHARS);
const SPAWN_TIMEOUT_MS = 10_000; // 10_000 ms = 10 seconds for one config import.
const CONFIG = resolve("tsup.config.ts");
const TSX_LOADER = resolve("node_modules/tsx/dist/loader.mjs");
const SCRIPT = `
  const mod = await import(${JSON.stringify(CONFIG)});
  const config = Array.isArray(mod.default) ? mod.default[0] : mod.default;
  process.stdout.write(JSON.parse(config.define.__SANCTUARY_SOURCE_SHA__));
`;

function sourceTarballEnv(
  extra: NodeJS.ProcessEnv = {},
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith("GIT_") && key !== SANCTUARY_SOURCE_SHA_ENV) {
      env[key] = value;
    }
  }
  return { ...env, ...extra };
}

describe("tsup source SHA resolution", () => {
  const temps: string[] = [];

  afterEach(async () => {
    for (const temp of temps.splice(0)) {
      await rm(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("refuses outside a git checkout without an explicit source SHA", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "sanctuary-tsup-config-"));
    temps.push(cwd);

    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd,
      encoding: "utf8",
      env: { ...sourceTarballEnv(), VITEST: process.env.VITEST },
      timeout: SPAWN_TIMEOUT_MS,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(SANCTUARY_SOURCE_SHA_ENV);
    expect(result.stderr).toContain("git metadata is unavailable");
  });

  it("refuses a malformed explicit source SHA", () => {
    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd: resolve("."),
      encoding: "utf8",
      env: {
        ...sourceTarballEnv({ [SANCTUARY_SOURCE_SHA_ENV]: "unknown" }),
        VITEST: process.env.VITEST,
      },
      timeout: SPAWN_TIMEOUT_MS,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(SANCTUARY_SOURCE_SHA_ENV);
    expect(result.stderr).toContain("malformed");
  });

  it("uses a valid explicit source SHA outside a git checkout", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "sanctuary-tsup-config-"));
    temps.push(cwd);

    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd,
      encoding: "utf8",
      env: {
        ...sourceTarballEnv({ [SANCTUARY_SOURCE_SHA_ENV]: VALID_SOURCE_SHA }),
        VITEST: process.env.VITEST,
      },
      timeout: SPAWN_TIMEOUT_MS,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(VALID_SOURCE_SHA);
    expect(result.stderr).not.toContain("git metadata is unavailable");
  });

  it("uses git metadata when no explicit source SHA is set", () => {
    const expected = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      timeout: SPAWN_TIMEOUT_MS,
    }).trim();

    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd: resolve("."),
      encoding: "utf8",
      env: { ...sourceTarballEnv(), VITEST: process.env.VITEST },
      timeout: SPAWN_TIMEOUT_MS,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(expected);
  });
});
