/**
 * MCP-registry metadata lockstep guard.
 *
 * THE RISK: the official MCP registry manifest (`server/server.json`) duplicates
 * facts whose source of truth is `server/package.json` (version, npm package
 * name, `mcpName`). The registry validates at publish time that the npm package
 * named in the manifest carries a matching `mcpName` at the manifest's version,
 * so any drift between the two files produces a publish that fails — or worse,
 * a listing that points at the wrong artifact. JSON cannot carry pin comments,
 * so this test IS the both-sides tripwire required by the cross-file-contract
 * rule (AGENTS.md, prose hygiene): a release cascade that bumps
 * `package.json` without `server.json` (or vice versa) goes red here, on every
 * commit, before the publish workflow can fail late.
 *
 * If a namespace decision changes `mcpName` (e.g. `ai.sanctuaryprotocol/*` vs
 * `io.github.eriknewton/*`), both files must change in the same commit.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_DIR = join(fileURLToPath(import.meta.url), "..", "..", "..");

function readJson(rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(SERVER_DIR, rel), "utf8"));
}

describe("MCP registry metadata lockstep (server.json <-> package.json)", () => {
  const pkg = readJson("package.json");
  const manifest = readJson("server.json");

  it("manifest name matches package.json mcpName", () => {
    expect(pkg.mcpName, "package.json must declare mcpName").toBeTruthy();
    expect(manifest.name).toBe(pkg.mcpName);
  });

  it("manifest version matches package.json version (release-cascade lockstep)", () => {
    expect(manifest.version).toBe(pkg.version);
  });

  it("manifest npm package entry points at this package, same version", () => {
    const packages = manifest.packages as Array<Record<string, unknown>>;
    expect(Array.isArray(packages) && packages.length > 0).toBe(true);
    const npmEntry = packages.find((p) => p.registryType === "npm");
    expect(npmEntry, "manifest must list the npm package").toBeTruthy();
    expect(npmEntry?.identifier).toBe(pkg.name);
    expect(npmEntry?.version).toBe(pkg.version);
  });

  it("manifest repository points at the canonical repo", () => {
    const repository = manifest.repository as Record<string, unknown>;
    expect(repository.url).toBe(
      "https://github.com/eriknewton/sanctuary-framework",
    );
  });
});
