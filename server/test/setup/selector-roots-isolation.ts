import {requireCliTestRunner} from "../../src/cli/argv.js";
import {aroundAll} from "vitest";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {installSelectorRootsForTest, isolatedSelectorRoots} from "../../src/linux-business/profile-selection.js";

const key = Symbol.for("sanctuary.test.selector-root-lifetime");
const state = globalThis as Record<symbol, string | undefined>;
// File lifetime survives module resets and never depends on environment overrides.
if (!state[key]) {
  const root = mkdtempSync(join(tmpdir(), "k1-selector-worker-"));
  state[key] = root;
}
installSelectorRootsForTest(isolatedSelectorRoots(state[key]!), requireCliTestRunner("selectorRoots"));

// Shared setup must not lengthen every test's socket paths by redirecting TMPDIR.
// Worker shutdown can bypass exit listeners; aroundAll also runs after a throwing file hook.
const root = state[key]!;
aroundAll(async runSuite => {
  try { await runSuite(); }
  finally {
    rmSync(root, {recursive: true, force: true});
    delete state[key];
  }
});
