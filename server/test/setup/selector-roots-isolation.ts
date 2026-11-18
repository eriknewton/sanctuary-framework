import {requireCliTestRunner} from "../../src/cli/argv.js";
import {aroundAll} from "vitest";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {basename, join} from "node:path";
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
// Invariant: aroundAll removes the root after the file body and every file hook, pass or fail.
// A file that never enters aroundAll (fully skipped, or failed at collection) leaves its root
// to the exit fallback, which is best effort: a worker that ends without running exit
// listeners keeps that root.
const root = state[key]!;
function releaseSelectorRoot(): void {
  if (state[key] === root) delete state[key];
  if (!basename(root).startsWith("k1-selector-worker-")) return;
  rmSync(root, {recursive: true, force: true});
}
process.once("exit", releaseSelectorRoot);
aroundAll(async runSuite => {
  try { await runSuite(); }
  finally { releaseSelectorRoot(); }
});
