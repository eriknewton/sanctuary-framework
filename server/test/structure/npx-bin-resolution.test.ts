/**
 * Structural gate: bare-npx executable resolution (v1.6.1 install-path
 * hardening, F1).
 *
 * `npx @sanctuary-framework/mcp-server` resolves an executable from the
 * package `bin` map. When a package declares MULTIPLE bins, npm only
 * auto-selects one if a bin name matches the package's unscoped name
 * (`mcp-server`). v1.4.0 dropped that invariant when extra bins were
 * added, and every published version from 1.4.0 through 1.6.0 failed
 * bare `npx` with "could not determine executable to run".
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
    // npm's multi-bin auto-selection rule: a bin named exactly like the
    // unscoped package name is what makes `npx <pkg>` runnable at all.
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
