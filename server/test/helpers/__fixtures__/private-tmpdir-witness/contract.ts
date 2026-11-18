/**
 * Shared names for the private temp root hook-failure witness. The parent test
 * (test/helpers/private-tmpdir-hook-failure.test.ts), the child fixture and the child recorder all
 * import this one module, so the three sides read the same values by construction.
 */

/** Names the hook that throws in the child fixture file. */
export const WITNESS_SCENARIO_ENV = "SANCTUARY_PRIVATE_TMPDIR_WITNESS_SCENARIO";
/** Absolute directory, owned by the parent test, that receives the two record files below. */
export const WITNESS_RECORD_DIR_ENV = "SANCTUARY_PRIVATE_TMPDIR_WITNESS_RECORD_DIR";

export const WITNESS_SCENARIOS = ["a later beforeAll throws", "an afterAll throws"] as const;
export type WitnessScenario = (typeof WITNESS_SCENARIOS)[number];

/** The error each scenario's hook throws; the parent test finds it in the child's report. */
export const FIXTURE_ERROR_MESSAGE: Record<WitnessScenario, string> = {
  "a later beforeAll throws": "witness fixture beforeAll failure",
  "an afterAll throws": "witness fixture afterAll failure",
};

/** Written by the fixture at import time: the private root the helper created for the fixture file. */
export const ROOT_RECORD_FILENAME = "private-root.txt";
/** Written by the recorder once the fixture file's hooks and teardown have all finished. */
export const END_STATE_RECORD_FILENAME = "end-state.json";

/** What the fixture file leaves behind in its worker. */
export interface WitnessEndState {
  root: string;
  rootExists: boolean;
  tmpdir: string | null;
}

export function isWitnessScenario(value: string | undefined): value is WitnessScenario {
  return (WITNESS_SCENARIOS as readonly string[]).includes(value ?? "");
}

export function witnessRecordDir(env: NodeJS.ProcessEnv): string {
  const dir = env[WITNESS_RECORD_DIR_ENV];
  if (!dir) throw new Error(`${WITNESS_RECORD_DIR_ENV} is not set; this module runs only under the witness test`);
  return dir;
}
