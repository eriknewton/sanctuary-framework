import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

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
    if (!key.startsWith("GIT_") && key !== "SANCTUARY_SOURCE_SHA") {
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

  it("uses the explicit source SHA override outside a git checkout", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "sanctuary-tsup-config-"));
    temps.push(cwd);
    const sha = "a".repeat(40);

    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd,
      encoding: "utf8",
      env: { ...sourceTarballEnv({ SANCTUARY_SOURCE_SHA: sha }), VITEST: process.env.VITEST },
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(sha);
    expect(result.stderr).not.toContain("git metadata is unavailable");
  });

  it("falls back to unknown with a warning outside a git checkout", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "sanctuary-tsup-config-"));
    temps.push(cwd);
    const result = spawnSync(process.execPath, ["--import", TSX_LOADER, "--eval", SCRIPT], {
      cwd,
      encoding: "utf8",
      env: { ...sourceTarballEnv(), VITEST: process.env.VITEST },
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toBe("unknown");
    expect(result.stderr).toContain("git metadata is unavailable; using unknown.");
  });
});
