/**
 * Process lifetime of the observer verbs under the production timers. Vitest
 * keeps its own event loop alive, so a verb that lets Node exit early cannot be
 * seen in process here: each case runs the verb in a real child Node process
 * (`test/fixtures/watch-lifetime-child.ts`) whose timers are `realRunnerTimers`,
 * over modelled children and temp directories.
 *
 * - run-watch stays alive across the process reread gap and the idle time
 *   between cycles, publishes more than one record, and exits 0 only on SIGTERM.
 * - install-watch sleeps its whole stability window and returns its computed
 *   status, instead of exiting while a stability sleep is pending.
 *
 * Failure mode: a child that exits 0 without a `RETURNED` line is the defect
 * shape, an exit that launchd and the operator read as success.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { CENSUS_REREAD, OBSERVER_LABEL, OBSERVER_PERIOD, SECOND } from "../../src/castle-wall/liveness/constants.js";
import { parseObserverRecord } from "../../src/castle-wall/liveness/schema.js";
import { STABLE_WINDOW_MS, WATCH_EXIT_INSTALLED } from "../../src/cli/castle-wall-watch.js";

const FIXTURE = fileURLToPath(new URL("../fixtures/watch-lifetime-child.ts", import.meta.url));
/** Starting a tsx child under a loaded suite can take tens of seconds; timing pressure must not read as a lifetime defect. */
const CHILD_START_ALLOWANCE_MS = 60_000;
/** Two observer periods plus the start allowance: the second record lands one OBSERVER_PERIOD after the first. */
const RUN_WATCH_TEST_MS = CHILD_START_ALLOWANCE_MS + 3 * OBSERVER_PERIOD;
const INSTALL_TEST_MS = CHILD_START_ALLOWANCE_MS + 3 * STABLE_WINDOW_MS;
const POLL_MS = 50;

type Run = { child: ChildProcess; stdout: () => string; done: Promise<{ code: number | null; signal: NodeJS.Signals | null }> };
const owned: ChildProcess[] = [];
const roots: Array<{ root: string; files: string[]; dirs: string[] }> = [];

function launch(args: string[]): Run {
  // VITEST stays set so the child latches the credential chokepoint under test, as every spawned test child does.
  const child = spawn(process.execPath, ["--import", "tsx", FIXTURE, ...args], {
    detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR ?? tmpdir(), VITEST: "true" },
  });
  owned.push(child);
  let out = "";
  let err = "";
  child.stdout!.on("data", (chunk: Buffer) => { out += chunk.toString(); });
  child.stderr!.on("data", (chunk: Buffer) => { err = (err + chunk.toString()).slice(-4000); });
  const done = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  return { child, stdout: () => `${out}${err ? `\n[stderr] ${err}` : ""}`, done };
}

const alive = (child: ChildProcess): boolean => child.exitCode === null && child.signalCode === null;
const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

/** Wait for `check`, failing at once if the child exits first: an early exit is exactly what these witnesses detect. */
async function until(run: Run, what: string, check: () => boolean, ms: number): Promise<void> {
  const limit = Date.now() + ms;
  while (!check()) {
    if (!alive(run.child)) throw new Error(`the child exited (${run.child.exitCode ?? run.child.signalCode}) before ${what}; output: ${run.stdout()}`);
    if (Date.now() > limit) throw new Error(`timed out waiting for ${what}; output: ${run.stdout()}`);
    await pause(POLL_MS);
  }
}

function returned(text: string): number | null {
  const match = /^RETURNED (-?\d+)$/m.exec(text);
  return match === null ? null : Number(match[1]);
}

afterEach(async () => {
  for (const child of owned.splice(0)) {
    if (child.pid !== undefined && alive(child)) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
      await new Promise(resolve => child.once("close", resolve));
    }
  }
  // Remove only what each case created, one entry at a time, deepest first.
  for (const { root, files, dirs } of roots.splice(0)) {
    for (const file of files) { try { unlinkSync(file); } catch { /* absent */ } }
    for (const dir of [...dirs, root]) { try { rmdirSync(dir); } catch { /* absent or not empty */ } }
  }
});

describe("observer process lifetime under production timers", () => {
  it("run-watch stays alive past the reread gap and between cycles, and exits 0 only when signalled", async () => {
    const root = mkdtempSync(join(tmpdir(), "lv-life-"));
    const fortress = join(root, "fortress");
    mkdirSync(fortress, { mode: 0o700 });
    const liveness = join(fortress, "liveness");
    const record = join(liveness, "observer.json");
    roots.push({ root, files: [record, `${record}.publisher`], dirs: [liveness, fortress] });
    const run = launch(["run-watch", fortress]);
    const sequence = (): number => {
      try { return (JSON.parse(readFileSync(record, "utf8")) as { sequence: number }).sequence; } catch { return 0; }
    };
    // The first record lands only after the process reread gap (CENSUS_REREAD) inside the first cycle.
    await until(run, "the first observer record", () => sequence() >= 1, CHILD_START_ALLOWANCE_MS);
    const first = JSON.parse(readFileSync(record, "utf8"));
    expect(parseObserverRecord(first).ok).toBe(true);
    // Then the process is idle until the next fixed-rate tick; it must survive that whole OBSERVER_PERIOD.
    const idleFrom = Date.now();
    await until(run, "the second observer record", () => sequence() >= 2, 2 * OBSERVER_PERIOD);
    expect(Date.now() - idleFrom).toBeGreaterThanOrEqual(OBSERVER_PERIOD - CENSUS_REREAD - SECOND);
    expect(alive(run.child)).toBe(true);
    // In --launch-agent mode the verb writes nothing; the only output is the fixture's own report after it returns.
    expect(returned(run.stdout())).toBeNull();
    run.child.kill("SIGTERM");
    const exit = await run.done;
    expect(exit).toEqual({ code: 0, signal: null });
    const report = run.stdout();
    expect(returned(report)).toBe(0);
    const { out, err } = JSON.parse(report.split("\n")[0]!) as { out: string; err: string };
    expect(out).toBe("");
    expect(err).toBe("");
    expect(readdirSync(liveness).sort()).toEqual(["observer.json", "observer.json.publisher"]);
  }, RUN_WATCH_TEST_MS);

  it("install-watch sleeps its whole stability window and returns its computed status", async () => {
    const root = mkdtempSync(join(tmpdir(), "lv-life-"));
    const fortress = join(root, "fortress");
    const liveness = join(fortress, "liveness");
    mkdirSync(liveness, { recursive: true, mode: 0o700 });
    const home = join(root, "home");
    const agents = join(home, "Library", "LaunchAgents");
    mkdirSync(agents, { recursive: true });
    roots.push({
      root,
      files: [join(liveness, "canary.plist"), join(agents, `${OBSERVER_LABEL}.plist`)],
      dirs: [liveness, fortress, agents, join(home, "Library"), home],
    });
    const startedAt = Date.now();
    const run = launch(["install-watch", fortress, home]);
    const exit = await run.done;
    const elapsed = Date.now() - startedAt;
    const report = run.stdout();
    // A pending stability sleep must hold the process: without it the child exits 0 with no RETURNED line.
    expect(returned(report), report).toBe(WATCH_EXIT_INSTALLED);
    expect(exit).toEqual({ code: 0, signal: null });
    expect(elapsed).toBeGreaterThanOrEqual(STABLE_WINDOW_MS);
    const { out, calls } = JSON.parse(report.split("\n")[0]!) as { out: string; calls: string[][] };
    expect(out).toContain("Observer LaunchAgent installed");
    expect(out).toContain("Canary integrity passes");
    // The observer print is sampled across the whole window, at one-second intervals, before staging runs.
    const prints = calls.filter(c => c[0] === "/bin/launchctl" && c[1] === "print" && c[2]!.startsWith("gui/"));
    expect(prints.length).toBeGreaterThanOrEqual(STABLE_WINDOW_MS / SECOND);
    expect(calls.some(c => c[0] === "/usr/bin/id" && c[1] === "-u")).toBe(true);
    expect(existsSync(join(liveness, "canary.plist"))).toBe(true);
  }, INSTALL_TEST_MS);
});
