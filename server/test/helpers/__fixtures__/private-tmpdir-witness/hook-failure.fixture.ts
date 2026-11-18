import { privateTmpdirRoot } from "../../private-tmpdir.js"; // Must stay the first import: scopes TMPDIR to this file and removes it afterwards.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, it } from "vitest";
import {
  FIXTURE_ERROR_MESSAGE,
  ROOT_RECORD_FILENAME,
  WITNESS_SCENARIO_ENV,
  isWitnessScenario,
  witnessRecordDir,
} from "./contract.js";

/**
 * Child fixture for test/helpers/private-tmpdir-hook-failure.test.ts. The name does not end in
 * `.test.ts`, so the suite's own include never collects it; only the child config beside it does.
 * One file-level hook throws, chosen by the parent test, and the file reports that failure.
 */
const scenario = process.env[WITNESS_SCENARIO_ENV];
if (!isWitnessScenario(scenario)) throw new Error(`${WITNESS_SCENARIO_ENV} names no witness scenario`);

writeFileSync(join(witnessRecordDir(process.env), ROOT_RECORD_FILENAME), privateTmpdirRoot);

// Both hooks register after the helper's own, which is the order every importing test file produces.
if (scenario === "a later beforeAll throws") {
  beforeAll(() => { throw new Error(FIXTURE_ERROR_MESSAGE[scenario]); });
} else {
  afterAll(() => { throw new Error(FIXTURE_ERROR_MESSAGE[scenario]); });
}

it("is the only test in the fixture file", () => {});
