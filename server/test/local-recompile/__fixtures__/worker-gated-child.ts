/**
 * Child process that runs the real local job worker with three injected
 * controls, so the worker's terminal states can be driven without timing luck:
 *
 * - a gate on storage reads: the first read in the operator log (init modes)
 *   or in the results store after `ready` (sweep mode) waits until a shutdown
 *   or a second init arrives;
 * - a deferred exit: `process.exit` waits EXIT_DEFER_MS, so work that resumes
 *   after a shutdown or fault gets to run before the process ends;
 * - captured housekeeping ticks: the worker's interval never runs on its own,
 *   and a `fixture_tick_overlap` message runs it twice in one turn.
 *
 * Every message the worker tries to send is recorded with the triggers that
 * had arrived by then. The record is rewritten to `resultFile` on every change,
 * so it survives an exit that skips the `exit` event.
 *
 * argv: resultFile mode, where mode is one of
 *   shutdown-during-init | init-during-init | shutdown-during-sweep | overlapping-sweep
 */
import { writeFileSync } from "node:fs";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { LocalResultsStore } from "../../../src/local-recompile/results-store.js";

const [resultFile, mode] = process.argv.slice(2) as [string, string];
// Long enough for a resumed init or sweep to finish its remaining store calls on a temp directory.
const EXIT_DEFER_MS = 1_000;

const record = {
  sent: [] as Array<{ type: string; after: string[] }>,
  triggers: [] as string[],
  duplicateInitKeysZeroed: null as boolean | null,
  sweepCallsDuringTicks: 0,
};
function persist(): void {
  writeFileSync(resultFile, JSON.stringify(record));
}
persist();

// ── Deferred exit ────────────────────────────────────────────────────
const realExit = process.exit.bind(process);
let exiting = false;
process.exit = ((code?: number) => {
  if (exiting) return undefined as never;
  exiting = true;
  // Node treats an explicit undefined argument as exit code 0, so the no-argument form keeps process.exitCode.
  setTimeout(() => (code === undefined ? realExit() : realExit(code)), EXIT_DEFER_MS);
  return undefined as never;
}) as typeof process.exit;

// ── Captured housekeeping ticks ──────────────────────────────────────
const ticks: Array<() => void> = [];
globalThis.setInterval = ((callback: () => void) => {
  ticks.push(callback);
  return { unref() {}, ref() {}, hasRef: () => false, refresh() { return this; }, [Symbol.toPrimitive]: () => 0 } as unknown as NodeJS.Timeout;
}) as unknown as typeof setInterval;
globalThis.clearInterval = (() => undefined) as typeof clearInterval;

// ── Gate on storage reads ────────────────────────────────────────────
const gatedNamespace = mode === "shutdown-during-init" || mode === "init-during-init" ? "_local_oplog" : "_local_results";
let gateArmed = mode === "shutdown-during-init" || mode === "init-during-init";
let release: (() => void) | undefined;
const realSend = process.send!.bind(process);
for (const method of ["read", "readBounded"] as const) {
  const original = FilesystemStorage.prototype[method] as (this: FilesystemStorage, ...args: unknown[]) => Promise<Uint8Array | null>;
  (FilesystemStorage.prototype as unknown as Record<string, unknown>)[method] = async function (this: FilesystemStorage, ...args: unknown[]) {
    if (gateArmed && args[0] === gatedNamespace) {
      gateArmed = false;
      const opened = new Promise<void>((resolve) => { release = resolve; });
      realSend({ type: "fixture_gated" });
      await opened;
    }
    return original.apply(this, args);
  };
}

const realSweep = LocalResultsStore.prototype.sweep;
let countingSweeps = false;
LocalResultsStore.prototype.sweep = function (this: LocalResultsStore, ...args: Parameters<typeof realSweep>) {
  if (countingSweeps) record.sweepCallsDuringTicks += 1;
  return realSweep.apply(this, args);
};

// ── Recorded sends ───────────────────────────────────────────────────
process.send = ((message: { type: string }, ...rest: unknown[]) => {
  record.sent.push({ type: message.type, after: [...record.triggers] });
  persist();
  // The sweep mode gates the first results read after ready, which is the post-ready sweep's.
  if (message.type === "ready" && mode === "shutdown-during-sweep") gateArmed = true;
  try {
    return (realSend as (...input: unknown[]) => boolean)(message, ...rest);
  } catch {
    return false;
  }
}) as typeof process.send;

await import("../../../src/local-recompile/worker-entry.js");

// Registered after the worker's own listener, so each trigger runs after the worker has handled it.
let inits = 0;
process.on("message", (raw: { type?: string; oplog_key?: Uint8Array; results_key?: Uint8Array }) => {
  if (raw.type === "init") {
    inits += 1;
    if (inits === 2) {
      record.triggers.push("second_init");
      record.duplicateInitKeysZeroed = [raw.oplog_key!, raw.results_key!].every((key) => key.every((byte) => byte === 0));
      persist();
      release?.();
    }
  } else if (raw.type === "shutdown") {
    record.triggers.push("shutdown");
    persist();
    release?.();
  } else if (raw.type === "fixture_tick_overlap") {
    // Two ticks in one turn: the second runs while the first tick's sweep is still awaiting its store.
    countingSweeps = true;
    ticks[0]?.();
    ticks[0]?.();
    countingSweeps = false;
    persist();
    realSend({ type: "fixture_ticked", ticks: ticks.length });
  }
});
