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

describe("structure: harness log directory install wiring", () => {
  it("pins the default directory open flags at the production helper", async () => {
    const source = await readFile(AUTO_PROVISION_SOURCE, "utf8");

    expect(source).toMatch(
      /export const HARNESS_LOG_DIRECTORY_OPEN_FLAGS =\s*fsConstants\.O_RDONLY \|\s*fsConstants\.O_NOFOLLOW \|\s*fsConstants\.O_DIRECTORY;/,
    );
    expect(source).toContain("open(path, HARNESS_LOG_DIRECTORY_OPEN_FLAGS)");
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
