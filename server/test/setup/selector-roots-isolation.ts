import {requireCliTestRunner} from "../../src/cli/argv.js";
import {aroundAll, inject} from "vitest";
import {createOwnedTempRoot, removeOwnedTempRoot, SELECTOR_ROOT_PREFIX, TEMP_ROOT_REGISTRY, type OwnedTempRoot} from "../helpers/owned-temp-roots.js";
import {installSelectorRootsForTest, isolatedSelectorRoots} from "../../src/linux-business/profile-selection.js";

const key = Symbol.for("sanctuary.test.selector-root-lifetime");
const state = globalThis as Record<symbol, OwnedTempRoot | undefined>;
// File lifetime survives module resets and never depends on environment overrides.
if (!state[key]) {
  const root = createOwnedTempRoot(SELECTOR_ROOT_PREFIX, inject(TEMP_ROOT_REGISTRY));
  state[key] = root;
}
installSelectorRootsForTest(isolatedSelectorRoots(state[key]!.path), requireCliTestRunner("selectorRoots"));

// Shared setup must not lengthen every test's socket paths by redirecting TMPDIR.
// Invariant: aroundAll removes the root after the file body and every file hook, pass or fail.
// Global teardown owns the recorded allocation when collection fails or every test is skipped.
const root = state[key]!;
function releaseSelectorRoot(): void {
  if (state[key] === root) delete state[key];
  // The captured allocation identity confines removal to the root this run created.
  removeOwnedTempRoot(root);
}
aroundAll(async runSuite => {
  try { await runSuite(); }
  finally { releaseSelectorRoot(); }
});
