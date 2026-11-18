import { readFileSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { TestProject } from "vitest/node";
import { createOwnedTempRoot, removeOwnedTempRoot, SELECTOR_ROOT_PREFIX, TEMP_ROOT_REGISTRY, type OwnedTempRoot } from "../helpers/owned-temp-roots.js";

export default function setup(project: TestProject): () => void {
  // mkdtemp reserves a private registry for exactly this run, including concurrent runs
  // in the same checkout. Keeping records outside fixture roots preserves socket path lengths.
  const registry = createOwnedTempRoot(SELECTOR_ROOT_PREFIX);
  project.provide(TEMP_ROOT_REGISTRY, registry.path);
  return () => {
    const errors: unknown[] = [];
    // Global teardown follows worker collection and execution even for skipped or failed files.
    // Only records written by this run's creators authorize recursive deletion, never a scan
    // of other runs' prefix-matching roots. The remover verifies uid and allocation identity.
    for (const name of readdirSync(registry.path)) {
      const record = join(registry.path, name);
      try {
        const root: OwnedTempRoot = JSON.parse(readFileSync(record, "utf8"));
        removeOwnedTempRoot(root);
        unlinkSync(record);
      } catch (error) { errors.push(error); }
    }
    // Nonrecursive removal cannot erase an unprocessed record or another run's registry.
    if (errors.length) throw new AggregateError(errors, "Test temp root cleanup failed");
    rmdirSync(registry.path);
  };
}
