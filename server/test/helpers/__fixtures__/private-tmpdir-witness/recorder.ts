/**
 * Child-run setup file for the private temp root hook-failure witness. It records the state the
 * fixture file leaves behind, for the parent test to read after the child exits.
 */
import { aroundAll } from "vitest";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  END_STATE_RECORD_FILENAME,
  ROOT_RECORD_FILENAME,
  witnessRecordDir,
  type WitnessEndState,
} from "./contract.js";

// A setup file registers before the fixture file is imported, so this hook wraps every hook the
// fixture file registers, the helper's included: the lines after `runSuite()` see the final state.
aroundAll(async (runSuite) => {
  await runSuite();
  const dir = witnessRecordDir(process.env);
  const root = readFileSync(join(dir, ROOT_RECORD_FILENAME), "utf8");
  const state: WitnessEndState = { root, rootExists: existsSync(root), tmpdir: process.env.TMPDIR ?? null };
  writeFileSync(join(dir, END_STATE_RECORD_FILENAME), JSON.stringify(state));
});
