import "./private-tmpdir.js"; // Must stay the first import: scopes TMPDIR to this file and removes it afterwards.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { leaseGuardHookTimeoutMs } from "../../vitest.config.js";
import {
  END_STATE_RECORD_FILENAME,
  FIXTURE_ERROR_MESSAGE,
  WITNESS_RECORD_DIR_ENV,
  WITNESS_SCENARIO_ENV,
  WITNESS_SCENARIOS,
  type WitnessEndState,
} from "./__fixtures__/private-tmpdir-witness/contract.js";

/**
 * Witness for test/helpers/private-tmpdir.ts: a test file whose own file-level hook throws still
 * ends with its private temp root removed and `TMPDIR` restored, and still reports the hook's error.
 * Each scenario runs the fixture file in a child Vitest run under the suite's own hook order.
 */
const serverRoot = fileURLToPath(new URL("../../", import.meta.url));
const childConfigPath = fileURLToPath(new URL("./__fixtures__/private-tmpdir-witness/child.vitest.config.ts", import.meta.url));
const childStartupHeadroomMs = 30_000; // Allow module loading on a loaded runner.
const childExitHeadroomMs = 10_000; // Allow reporting and worker shutdown after teardown.
const parentHeadroomMs = 10_000; // Allow the fixture folders and record reads outside the child budget.
// The fixture's test body is empty, so the child spends its time on startup, one hook budget and exit.
const childTimeoutMs = childStartupHeadroomMs + leaseGuardHookTimeoutMs + childExitHeadroomMs;

it.each(WITNESS_SCENARIOS)("removes the private temp root and restores TMPDIR when %s", async (scenario) => {
  // Inside this file's own private temp root, so the records and the child's temp folders go with it.
  const directory = await mkdtemp(join(tmpdir(), "private-tmpdir-witness-"));
  const recordDir = join(directory, "records");
  const childTmpdir = join(directory, "tmp");
  await mkdir(recordDir);
  await mkdir(childTmpdir);

  // Thread workers die with the synchronous child, which is reaped even when its timeout fires.
  const result = spawnSync(process.execPath, [
    join(serverRoot, "node_modules/vitest/vitest.mjs"), "run", "--config", childConfigPath,
  ], {
    cwd: serverRoot,
    encoding: "utf8",
    timeout: childTimeoutMs,
    killSignal: "SIGKILL",
    env: { ...process.env, TMPDIR: childTmpdir, [WITNESS_SCENARIO_ENV]: scenario, [WITNESS_RECORD_DIR_ENV]: recordDir },
  });
  const output = result.stdout + result.stderr;
  // The child's expected failure stays out of this run's summary unless an assertion below fails.
  expect(result.error, output).toBeUndefined();
  expect(result.signal, output).toBeNull();
  // The fixture's own hook error fails the file and is the error the child reports.
  expect(result.status, output).toBe(1);
  expect(output).toContain(FIXTURE_ERROR_MESSAGE[scenario]);

  const end = JSON.parse(await readFile(join(recordDir, END_STATE_RECORD_FILENAME), "utf8")) as WitnessEndState;
  // The helper created its root under the temp directory the child was given.
  expect(end.root.startsWith((await realpath(childTmpdir)) + sep), end.root).toBe(true);
  // Seen from inside the worker after every hook of the file, and again from here after the child exited.
  expect(end.rootExists).toBe(false);
  expect(existsSync(end.root)).toBe(false);
  // The worker's TMPDIR is the value the child process started with.
  expect(end.tmpdir).toBe(childTmpdir);
}, childTimeoutMs + parentHeadroomMs);
