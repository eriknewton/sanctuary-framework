import {requireCliTestRunner} from "../../src/cli/argv.js";
import {mkdtempSync, rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {installSelectorRootsForTest, isolatedSelectorRoots} from "../../src/linux-business/profile-selection.js";

const key = Symbol.for("sanctuary.test.selector-root-lifetime");
const state = globalThis as Record<symbol, string | undefined>;
// Worker-global lifetime survives module resets and never depends on environment overrides.
if (!state[key]) {
  const root = mkdtempSync(join(tmpdir(), "k1-selector-worker-"));
  state[key] = root;
  process.once("exit", () => { try { rmdirSync(root); } catch { /* Teardown must not throw from exit. */ } });
}
installSelectorRootsForTest(isolatedSelectorRoots(state[key]!), requireCliTestRunner("selectorRoots"));
