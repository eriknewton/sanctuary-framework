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
import { readdirSync, readFileSync } from "node:fs";
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
});
