/** A signal-time exit fence covers scheduler, daemon, session and final cleanup. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import fs from "node:fs";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runDaemon, runProvisionPin, type CastleWallCommandContext } from "../../src/cli/castle-wall.js";
import { MacOSFlowEventConsumer } from "../../src/castle-wall/runtime/macos-flow-events.js";
import { CASTLE_WALL_STOP_EXIT_DEADLINE_MS } from "../../src/castle-wall/constants.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";
import * as custody from "../../src/core/master-custody.js";
import * as scheduler from "../../src/transparency/scheduler.js";
import { FullAgentStateStore } from "../../src/cli/castle-wall-full-agent-state.js";
// Must match CASTLE_WALL_STOP_TEST_SLACK_MS in test/castle-wall/runtime/macos-daemon-stop-budget.test.ts: one fake-clock millisecond.
const CASTLE_WALL_STOP_TEST_SLACK_MS = 1;
const passphrase = "isolated-stop-fence-fixture";
class Capture extends Writable { text = ""; override _write(chunk: unknown, _encoding: BufferEncoding, done: () => void) { this.text += String(chunk); done(); } }
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
function requireSummary() {
  const consumer = new MacOSFlowEventConsumer({ fortressId: "fixture", auditSink: { append() {}, async flush() {} }, defaultApprovalTimeoutSeconds: 30,
    approvalQueue: { async enqueue() {} }, manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
  expect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
}
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); });
describe("CLI stop completion fence", () => {
  it.each(["daemon", "scheduler", "session", "cleanup", "prompt"])("exit fence fires after the stderr line: %s", async held => {
    requireSummary();
    const root = await mkdtemp("/tmp/cw-stop-exit-"); const home = join(root, "home"); await mkdir(home);
    vi.stubEnv("HOME", home); vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "locks"));
    const gate = deferred(), entered = deferred(); const order: string[] = []; let releases = 0;
    const prior = new Map(["SIGINT", "SIGTERM"].map(signal => [signal, new Set(process.rawListeners(signal))]));
    let run: Promise<number> | undefined;
    const sessionCleanup: Array<() => Promise<void>> = [];
    const errors: unknown[] = [];
    try {
      await initializeTestCustody(root, { passphrase });
      expect(await runProvisionPin(["--fortress", root], { out: new Capture(), err: new Capture(), env: { HOME: home, SANCTUARY_PASSPHRASE: passphrase }, globalPinnedPublicKeyPath: join(root, "pin") })).toBe(0);
      const establish = custody.establishMaster;
      vi.spyOn(custody, "establishMaster").mockImplementation(async (...args) => {
        const result = await establish(...args); const barrier = result.masterWriteBarrier;
        const release = barrier?.release.bind(barrier);
        // Retain the real release so teardown can close sessions after the simulated exit fence.
        // Repeated release calls reuse the lease's cached close promise.
        sessionCleanup.push(async () => {
          try { await release?.(); }
          finally { result.masterKey.fill(0); }
        });
        if (barrier) {
          barrier.release = async () => {
            releases++; order.push("release");
            if (held === "cleanup" && releases === 1) throw new Error("fixture first release retry");
            if (held === "session" || held === "cleanup") { entered.resolve(); await gate.promise; }
            return release!();
          };
        }
        return result;
      });
      vi.spyOn(scheduler, "startTransparencyScheduler").mockImplementation(() => ({ async stop() {
        order.push("scheduler"); if (held === "scheduler") { entered.resolve(); await gate.promise; }
      } }));
      const exit = vi.fn((code: number) => { order.push(`exit:${code}`); });
      const stderr = vi.spyOn(fs, "writeSync").mockImplementation((_fd, buffer) => { order.push(`stderr:${String(buffer).trim()}`); return String(buffer).length; });
      const clean = vi.spyOn(FullAgentStateStore.prototype, "stoppedClean");
      const ctx: CastleWallCommandContext = { platform: "darwin", getuid: () => 501, out: new Capture(), err: new Capture(),
        env: { HOME: home, SANCTUARY_STORAGE_PATH: root, SANCTUARY_PASSPHRASE: passphrase, SANCTUARY_CASTLE_LOCAL_SIGN: "1", SANCTUARY_TRANSPARENCY_INTERVAL: held === "scheduler" ? "1m" : "off" },
        stopExit: exit, fullDaemonStart: async () => ({ socketPath: join(root, "fixture.sock"), async stop() {
          order.push("daemon"); if (held === "daemon") { entered.resolve(); await gate.promise; }
        } }),
      };
      run = runDaemon(["--fortress", root], ctx);
      let signal: ((signal: "SIGTERM") => void) | undefined;
      const turns = 500; // Five seconds of bounded startup polling, independent of stop timing.
      for (let index = 0; index < turns; index++) {
        signal = process.rawListeners("SIGTERM").find(listener => !prior.get("SIGTERM")!.has(listener));
        if (signal) break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(signal, "production daemon installs its signal handler").toBeDefined();
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); signal!("SIGTERM");
      if (held === "prompt") {
        expect(await run).toBe(0);
        await vi.advanceTimersByTimeAsync(CASTLE_WALL_STOP_EXIT_DEADLINE_MS + CASTLE_WALL_STOP_TEST_SLACK_MS);
        expect(exit).not.toHaveBeenCalled();
      } else {
        await entered.promise;
        await vi.advanceTimersByTimeAsync(CASTLE_WALL_STOP_EXIT_DEADLINE_MS + CASTLE_WALL_STOP_TEST_SLACK_MS);
        expect(exit, "signal-time deadline calls the injected process exit").toHaveBeenCalledExactlyOnceWith(1);
        expect(stderr).toHaveBeenCalledOnce();
        expect(order.indexOf("stderr:[castle-wall] process stop budget lapsed"), "synchronous diagnostic precedes exit").toBeLessThan(order.indexOf("exit:1"));
        const before = [...order]; gate.resolve(); expect(await run, "a returning exit retains the failed completion code").toBe(1);
        expect(order, "returning exit and late release start no later cleanup action").toEqual(before);
        expect(clean).not.toHaveBeenCalled();
      }
    } catch (error) {
      errors.push(error);
    } finally {
      gate.resolve(); vi.useRealTimers();
      try {
        for (const signal of ["SIGINT", "SIGTERM"]) for (const listener of process.rawListeners(signal)) if (!prior.get(signal)!.has(listener)) { Reflect.apply(listener, process, []); process.removeListener(signal, listener); }
        await run;
      } catch (error) {
        if (!errors.includes(error)) errors.push(error);
      } finally {
        const results = await Promise.allSettled(sessionCleanup.map(cleanup => cleanup()));
        const failures = results.flatMap(result => result.status === "rejected" ? [result.reason] : []);
        if (failures.length > 0) errors.push(new AggregateError(failures, "Stop fixture session cleanup failed"));
        try { await rm(root, { recursive: true, force: true }); }
        catch (error) { errors.push(error); }
      }
    }
    // Preserve the run or assertion failure before any teardown failures.
    if (errors.length > 1) throw new AggregateError(errors, "Stop fixture run and cleanup failed");
    if (errors.length > 0) throw errors[0];
  });
});
