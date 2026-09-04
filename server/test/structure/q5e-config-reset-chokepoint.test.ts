/**
 * Structural pin for the local-intelligence config recovery chokepoint.
 *
 * `IntelligenceConfigStore.quarantineUnreadable` carries only data-plane
 * refusals; its consent gates (interactive TTY, typed confirmation word,
 * write-intent master unlock) live in the `sanctuary intelligence config-reset`
 * verb. This test asserts that verb is the ONLY production call site and that
 * the gates precede the call, so a new MCP tool or HTTP route cannot reach the
 * quarantine without re-running review.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "..", "..", "src");
const ONLY_CALLER = "cli/intelligence.ts";
const CALL = /\.quarantineUnreadable\(/g;

async function productionSourceFiles(dir = srcRoot): Promise<string[]> {
  const files: string[] = [];
  for (const name of await readdir(dir)) {
    const path = join(dir, name);
    if ((await stat(path)).isDirectory()) files.push(...await productionSourceFiles(path));
    else if (/\.(?:ts|tsx|js|mjs|cjs)$/.test(path)) files.push(path);
  }
  return files;
}

describe("Q5E config-reset chokepoint", () => {
  it("quarantineUnreadable has exactly one production caller: the CLI verb", async () => {
    const callers: Record<string, number> = {};
    for (const path of await productionSourceFiles()) {
      const source = await readFile(path, "utf8");
      // Strip comments so a doc reference to the method is not counted as a call.
      const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      const count = code.match(CALL)?.length ?? 0;
      if (count > 0) callers[relative(srcRoot, path).replaceAll("\\", "/")] = count;
    }
    expect(callers).toEqual({ [ONLY_CALLER]: 1 });
  });

  it("the CLI verb runs every consent gate before the call", async () => {
    const source = await readFile(join(srcRoot, ONLY_CALLER), "utf8");
    const call = source.indexOf(".quarantineUnreadable(");
    expect(call).toBeGreaterThan(0);
    const before = source.slice(0, call);
    for (const gate of [
      "requires an interactive terminal",
      "CONFIG_RESET_CONFIRMATION_WORD",
      "writeIntent: true",
    ]) {
      expect(before).toContain(gate);
    }
    // No server-side surface imports the CLI verb.
    for (const path of await productionSourceFiles()) {
      const rel = relative(srcRoot, path).replaceAll("\\", "/");
      if (rel === "cli.ts" || rel === ONLY_CALLER) continue;
      expect(await readFile(path, "utf8")).not.toContain("runIntelligenceConfigReset");
    }
  });
});
