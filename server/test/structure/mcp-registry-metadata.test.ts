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
    // The registry rejects a description over 100 characters at publish time
    // (schema maxLength, observed as a 422 on 2026-10-12); fail here instead,
    // on every commit, before a publish attempt does.
    const REGISTRY_DESCRIPTION_MAX = 100;
    expect(typeof manifest.description).toBe("string");
    expect((manifest.description as string).length).toBeLessThanOrEqual(REGISTRY_DESCRIPTION_MAX);
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

  // The publish workflow (.github/workflows/publish-on-tag.yml) exports
  // RELEASE_VERSION, the exact version the maintainer dispatched, and runs this
  // suite against the release tag. The registry listing must name that exact
  // version: on 2026-10-19 main's manifest named 1.8.6-rc.1, a version npm never
  // published, and an agent reading the listing would have tried to install it.
  // Outside a publish run the variable is unset and this check is skipped; the
  // shape check below still runs on every commit.
  const RELEASE_VERSION = process.env.RELEASE_VERSION;

  it.runIf(Boolean(RELEASE_VERSION))("manifest carries the exact version being published", () => {
    expect(manifest.version).toBe(RELEASE_VERSION);
    const npmEntry = (manifest.packages as Array<Record<string, unknown>>).find(
      (p) => p.registryType === "npm",
    );
    expect(npmEntry?.version).toBe(RELEASE_VERSION);
  });

  it("manifest version has the numeric shape the publish workflow accepts", () => {
    // Must match the version-shape regex in the validate-intent job of
    // .github/workflows/publish-on-tag.yml.
    expect(manifest.version).toMatch(/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+(\.[A-Za-z0-9]+)*)?$/);
  });

  it("manifest repository points at the canonical repo", () => {
    const repository = manifest.repository as Record<string, unknown>;
    expect(repository.url).toBe(
      "https://github.com/eriknewton/sanctuary-framework",
    );
  });
});
