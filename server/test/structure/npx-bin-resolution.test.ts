/**
 * Structural gate: bare-npx executable resolution (v1.6.1 install-path
 * hardening, F1).
 *
 * `npx @sanctuary-framework/mcp-server` resolves an executable from the
 * package `bin` map. When a package declares MULTIPLE bins, npm
 * (libnpmexec's getBinFromManifest) auto-selects one in exactly two
 * cases: (1) ALL bin values point at the same file, in which case npm
 * treats them as aliases and picks the first key; or (2) a bin name
 * matches the package's unscoped name (`mcp-server`). Versions through
 * v1.3.x resolved via case (1): two bins, both dist/cli.js. v1.4.0
 * added `verify-transparency` with a second distinct target, which
 * broke the alias rule, and with no `mcp-server` bin present every
 * published version from 1.4.0 through 1.6.0 failed bare `npx` with
 * "could not determine executable to run". The `mcp-server` bin pins
 * case (2), which keeps bare npx resolving no matter how many distinct
 * bin targets ship.
 *
 * These tests pin the invariant in the tree; the npx-install-gate CI
 * workflow proves it against a real `npm pack` + clean-cache `npx` run.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJsonPath = join(__dirname, "..", "..", "package.json");

async function readPackageJson(): Promise<{
  name: string;
  bin: Record<string, string>;
}> {
  return JSON.parse(await readFile(packageJsonPath, "utf-8"));
}

describe("npx bin resolution (install-path hardening F1)", () => {
  it("declares a bin matching the unscoped package name so bare npx resolves", async () => {
    const pkg = await readPackageJson();
    const unscopedName = pkg.name.split("/").pop()!;
    expect(unscopedName).toBe("mcp-server");
    // With multiple distinct bin targets in the map, the unscoped-name
    // bin is the only npm auto-selection rule that still applies (the
    // all-values-identical alias rule stopped matching in v1.4.0).
    expect(pkg.bin[unscopedName]).toBe("dist/cli.js");
  });

  it("keeps the explicit `sanctuary` bin the wrap-written MCP entry names", async () => {
    const pkg = await readPackageJson();
    // resolveSanctuaryCommand writes `npx -y -p <pkg>@<version> sanctuary`;
    // removing or renaming this bin would kill every wrapped harness.
    expect(pkg.bin["sanctuary"]).toBe("dist/cli.js");
  });

  it("points every dist/cli.js bin at the same entrypoint (no drift)", async () => {
    const pkg = await readPackageJson();
    for (const name of ["mcp-server", "sanctuary", "sanctuary-mcp-server"]) {
      expect(pkg.bin[name]).toBe("dist/cli.js");
    }
  });
});
