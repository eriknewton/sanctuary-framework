// fail-before-exempt: guards behavior whose fix merged in PR #1073 (train predecessor); fail-before was proven there by blob-swap against the pre-fix tree (F3, PR body evidence) — against current main these guard tests pass by design.
/**
 * Dashboard one-surface fold — structural retirement guard (fold PR-5).
 *
 * The fold's two by-construction claims only stay true if no future change
 * quietly reintroduces the retired pattern. These are the teeth:
 *
 *  1. runtime.json SINGLE-WRITER: `writeTenantRuntime` has exactly ONE
 *     production caller (dashboard-standalone.ts). The pre-fold two-writer
 *     race (wrap/cli.ts also wrote it, last-writer-wins, either exit
 *     clearing the other's record) must not come back.
 *  2. NO PRODUCTION RE-SPAWN of the retired wrap-served dashboard: the
 *     only call site of `startDashboardWithFallback` in server/src is its
 *     own definition in wrap/cli.ts (kept exported for the legacy test
 *     seam). `sanctuary protect` routes through `ensureMainDashboardForWrap`
 *     instead.
 *
 * Scanner notes: comments and string literals are NOT stripped here, so the
 * assertions match call-shaped text (`name(`) and import-shaped text only —
 * both are absent from prose. Keep referencing the names in comments freely.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER_SRC = resolve(HERE, "..", "..", "src");

function allTsFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
    }
  };
  walk(dir);
  out.sort();
  return out;
}

describe("dashboard-fold retirement guard", () => {
  const files = allTsFiles(SERVER_SRC);

  it("runtime.json has exactly ONE production writer (dashboard-standalone.ts)", () => {
    // Call-shaped occurrences of writeTenantRuntime, excluding its defining
    // module and barrel re-exports (an `export { writeTenantRuntime }` line
    // is not a call).
    const callers: string[] = [];
    for (const file of files) {
      const rel = relative(SERVER_SRC, file);
      if (rel === join("cli", "agents", "runtime.ts")) continue; // definition
      if (rel === join("cli", "agents", "index.ts")) continue; // barrel
      const src = readFileSync(file, "utf-8");
      if (/\bwriteTenantRuntime\s*\(/.test(src)) callers.push(rel);
    }
    expect(
      callers,
      "runtime.json single-writer (dashboard fold PR-4): only the main " +
        "dashboard's boot path may write runtime.json. A second production " +
        "writer reintroduces the last-writer-wins race the fold closed.",
    ).toEqual(["dashboard-standalone.ts"]);
  });

  it("no production module calls startDashboardWithFallback (retired spawn path)", () => {
    const callers: string[] = [];
    for (const file of files) {
      const rel = relative(SERVER_SRC, file);
      const src = readFileSync(file, "utf-8");
      const calls = src.match(/\bstartDashboardWithFallback\s*\(/g) ?? [];
      // wrap/cli.ts contains exactly ONE call-shaped occurrence: the
      // function's own definition header. Anything beyond that — or any
      // occurrence in another module — is a re-spawn of the retired server.
      const allowed = rel === join("wrap", "cli.ts") ? 1 : 0;
      if (calls.length > allowed) callers.push(`${rel} (${calls.length})`);
    }
    expect(
      callers,
      "dashboard fold PR-4 retired the wrap-spawned dashboard: production " +
        "code must route through ensureMainDashboardForWrap, never " +
        "startDashboardWithFallback.",
    ).toEqual([]);
  });

  // ── Fix round 1, F3 (behavioral): a FAILED standalone boot must not leave
  // a live-PID runtime.json behind. The unlocked-boot path writes the tenant
  // record BEFORE the listener binds; without the F3 clear-on-start-failure,
  // an EADDRINUSE from a FOREIGN port owner left a record whose pid is alive
  // (it names the failed booter) and whose port answers (the foreign owner),
  // which the protect ensure-and-reuse race-close could bless as "the running
  // dashboard". F2(b) (self-pid records never reusable) is the ensure-side
  // belt; this pins the chokepoint fix itself.
  it("F3: a standalone boot that fails to bind leaves NO runtime.json behind", async () => {
    const { startStandaloneDashboard } = await import(
      "../../src/dashboard-standalone.js"
    );
    const tempDir = await mkdtemp(join(tmpdir(), "sanctuary-f3-runtime-"));
    const escrowDir = await mkdtemp(join(tmpdir(), "sanctuary-f3-escrow-"));
    const discoveryRoot = join(tempDir, "discovery-root");
    const discoveryHome = join(tempDir, "discovery-home");
    await mkdir(discoveryRoot, { recursive: true, mode: 0o700 });
    await mkdir(discoveryHome, { recursive: true, mode: 0o700 });
    const storagePath = join(tempDir, ".sanctuary");
    const priorRecoveryOut = process.env.SANCTUARY_RECOVERY_OUT;
    process.env.SANCTUARY_RECOVERY_OUT = join(escrowDir, "recovery.txt");

    // Occupy a loopback port with a foreign (non-Sanctuary) listener.
    const squatter = createServer();
    await new Promise<void>((resolvePromise) =>
      squatter.listen(0, "127.0.0.1", resolvePromise),
    );
    const addr = squatter.address();
    const occupiedPort =
      typeof addr === "object" && addr !== null ? addr.port : 0;

    try {
      await expect(
        startStandaloneDashboard({
          storagePath,
          passphrase: "f3-test-passphrase",
          port: occupiedPort,
          host: "127.0.0.1",
          noConfirm: true,
          distressPort: 0,
          discoveryOptions: {
            root: discoveryRoot,
            home: discoveryHome,
            env: {},
          },
        }),
      ).rejects.toThrow();

      expect(
        existsSync(join(storagePath, "runtime.json")),
        "a failed bind must clear the pre-written tenant runtime record " +
          "(F3): a surviving live-PID record points reuse at the port's " +
          "FOREIGN owner",
      ).toBe(false);
    } finally {
      await new Promise<void>((resolvePromise) =>
        squatter.close(() => resolvePromise()),
      );
      if (priorRecoveryOut === undefined) {
        delete process.env.SANCTUARY_RECOVERY_OUT;
      } else {
        process.env.SANCTUARY_RECOVERY_OUT = priorRecoveryOut;
      }
      await rm(tempDir, { recursive: true, force: true }).catch(() => {});
      await rm(escrowDir, { recursive: true, force: true }).catch(() => {});
    }
  }, 30_000);
});
