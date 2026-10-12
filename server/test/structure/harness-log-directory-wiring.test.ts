/**
 * Structure witness for AGENT-HOME-LOGS-SYMLINK-01: the production harness
 * install path must route log-directory custody through the shared helper.
 */

import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const AUTO_PROVISION_SOURCE = resolve(REPO_ROOT, "server/src/wrap/auto-provision.ts");

function installHarnessDaemonSource(source: string): string {
  const start = source.indexOf("installHarnessDaemon: async (uid) => {");
  const end = source.indexOf("uninstallHarnessDaemon: async () => {", start);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

function ensureHarnessDaemonLogDirSource(source: string): string {
  const start = source.indexOf("export async function ensureHarnessDaemonLogDir(");
  const end = source.indexOf("/**\n * Bug B", start);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

function awaitedCalls(source: string): string[] {
  return [...source.matchAll(/\bawait\s+([A-Za-z0-9_.]+)\s*\(/g)].map((match) => match[1]!);
}

describe("structure: harness log directory install wiring", () => {
  it("pins agent-authority creation at the production helper", async () => {
    const source = await readFile(AUTO_PROVISION_SOURCE, "utf8");
    const helperSource = ensureHarnessDaemonLogDirSource(source);

    expect(source).toContain("createHarnessLogDirectoryAsAgent");
    expect(source).toContain('spawnImpl("/bin/mkdir", ["-m", HARNESS_LOG_DIR_MODE_ARG, "--", path], options)');
    expect(helperSource).toContain(
      [
        "ops: HarnessLogDirectoryOps = {",
        "    lstat,",
        "    createDirectoryAsAgent: createHarnessLogDirectoryAsAgent,",
        "  },",
      ].join("\n"),
    );
    expect(helperSource).toContain("await ops.createDirectoryAsAgent(harnessLogDir, uid, gid);");
    expect(awaitedCalls(helperSource)).toEqual([
      "ops.lstat",
      "ops.lstat",
      "ops.createDirectoryAsAgent",
      "ops.lstat",
    ]);
    expect(helperSource).not.toMatch(
      /(?:\b|\.)?(?:fsChown|chown|lchown|fchown|chmod|fchmod|mkdir|rename|open|unlink|writeFile)\s*\(/,
    );
    expect(helperSource).not.toContain("openDirectoryNoFollow");
    expect(helperSource).not.toContain("readEntries");
    expect(helperSource).not.toContain("/dev/fd");
  });

  it("routes the install path through the custody helper and keeps path mutation out of the caller", async () => {
    const source = await readFile(AUTO_PROVISION_SOURCE, "utf8");
    const installSource = installHarnessDaemonSource(source);

    expect(installSource).toContain("const harnessLogDir = resolveHarnessDaemonLogDir(newAccountHome);");
    expect(installSource).toContain("await ensureHarnessDaemonLogDir(harnessLogDir, uid, uid);");

    expect(installSource).not.toMatch(/\bmkdir\s*\(\s*harnessLogDir\b/);
    expect(installSource).not.toMatch(/\bchmod\s*\(\s*harnessLogDir\b/);
    expect(installSource).not.toMatch(/\bfsChown\s*\(\s*harnessLogDir\b/);
    expect(installSource).not.toMatch(/\bchown\s*\(\s*harnessLogDir\b/);
  });
});
