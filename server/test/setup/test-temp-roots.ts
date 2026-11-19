import { mkdtempSync, readdirSync, realpathSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vitest/node";
import { readOwnedTempRootRecord, removeOwnedTempRoot, TEMP_ROOT_REGISTRY } from "../helpers/owned-temp-roots.js";

const REGISTRY_PREFIX = "sanctuary-test-registry-";
const CLEANUP_FAILURE_EXIT_CODE = 1; // Conventional unsuccessful process exit status.

export default function setup(project: TestProject): () => void {
  // mkdtemp reserves a private registry for exactly this run, including concurrent runs
  // in the same checkout. Keeping records outside fixture roots preserves socket path lengths.
  const registry = realpathSync(mkdtempSync(join(tmpdir(), REGISTRY_PREFIX)));
  project.provide(TEMP_ROOT_REGISTRY, registry);
  return () => {
    try {
      const errors: unknown[] = [];
      // Global teardown follows worker collection and execution even for skipped or failed files.
      // Only records written by this run's creators authorize recursive deletion, never a scan
      // of other runs' prefix-matching roots. The remover verifies uid and allocation identity.
      for (const name of readdirSync(registry)) {
        try { removeOwnedTempRoot(readOwnedTempRootRecord(join(registry, name))); }
        catch (error) { errors.push(error); }
      }
      // Nonrecursive removal cannot erase an unprocessed record or another run's registry.
      if (errors.length) throw new AggregateError(errors, "Test temp root cleanup failed");
      rmdirSync(registry);
    } catch (error) {
      // Global cleanup failures must fail the run even when Vitest only logs close errors.
      process.exitCode = CLEANUP_FAILURE_EXIT_CODE;
      throw error;
    }
  };
}
