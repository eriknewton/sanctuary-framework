// fail-before-exempt: this file witnesses a capability the base already has (a pending checkpoint body read keeps its permit through a verdict-triggered stop and returns it on settlement), so it passes against the base by construction; the mutant catalog in the PR description is what fails it.
/** Checkpoint reads retain their permits through a verdict until settlement. */
// Witnesses OrderedAuditBodyReads.capture and OrderedAuditBodyReads.stop in operational/audit-log.ts: a read permit is released in the read's own settlement, never at stop(). Must match AUDIT_CHECKPOINT_READ_CONCURRENCY and withAuditWriteLock's checkpointReadAbort pairing in operational/audit-log.ts.
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as auditModule from "../../src/operational/audit-log.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY } from "../../scripts/measure-audit-append.js";

// Three admissions is the empirical production budget; must match
// AUDIT_CHECKPOINT_READ_CONCURRENCY in operational/audit-log.ts.
const P = 3;
const CHECKPOINTS = 3 * P; // Mirrors the three-window fixture in audit-log-checkpoint-read-schedule.test.ts.
type Signal = { aborted: boolean; checkpointReadAbort?: AbortSignal };
// Mirrors checkpointKey in audit-log-checkpoint-read-schedule.test.ts; storage sequences use 20 digits.
const checkpointKey = (n: number) => `audit-checkpoint-${String(n).padStart(20, "0")}`;
// Mirrors entryKey in audit-log-checkpoint-read-schedule.test.ts; storage sequences use 20 digits.
const entryKey = (n: number) => `entry-${String(n).padStart(20, "0")}-fixture`;
// Mirrors gate in audit-log-checkpoint-read-schedule.test.ts.
function gate() { let release!: () => void; const wait = new Promise<void>((resolve) => { release = resolve; }); return { wait, release }; }
// Mirrors turns in audit-log-checkpoint-read-schedule.test.ts; P squared drains admission and decision continuations.
async function turns(count = P * P) { for (let i = 0; i < count; i++) await new Promise<void>((resolve) => setImmediate(resolve)); }
// Mirrors settle in audit-log-checkpoint-read-schedule.test.ts.
const settle = <T>(promise: Promise<T>) => promise.then(value => ({ state: "read" as const, value }), error => ({ state: "faulted" as const, error }));
let root: string;
// Mirrors HOME isolation in audit-log-checkpoint-read-schedule.test.ts; suite setup injects the in-memory keychain.
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "checkpoint-permit-verdict-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); });

// Mirrors Mode in audit-log-checkpoint-read-schedule.test.ts.
type Mode = "collector" | "predecessor";
// Mirrors modes in audit-log-checkpoint-read-schedule.test.ts.
const modes: Mode[] = ["collector", "predecessor"];
// Mirrors invoke in audit-log-checkpoint-read-schedule.test.ts.
function invoke(log: AuditLog, mode: Mode, keys: string[], signal?: Signal, sealed = 0) {
  return mode === "collector"
    ? (log as any).collectPersistedEntryHashes(1, P, sealed, keys, signal)
    : (log as any).readHighestAuditCheckpointSequence(sealed, signal);
}
// Mirrors fixture in audit-log-checkpoint-read-schedule.test.ts.
function fixture(mode: Mode, count = CHECKPOINTS) {
  const keys = Array.from({ length: count }, (_, i) => mode === "collector" ? entryKey(i + 1) : checkpointKey(i + 1));
  const storage = new MemoryStorage();
  vi.spyOn(storage, "listKeys").mockResolvedValue(keys);
  const log = new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  return { keys, storage, log };
}

// Mirrors permitSchedule in audit-log-checkpoint-read-schedule.test.ts, with an immediate fault option.
// Must match withAuditWriteLock's paired retirement fields in operational/audit-log.ts;
// the production reader composes checkpointReadAbort with its own stop signal.
function permitSchedule() {
  let outstanding = 0; let maximum = 0;
  const admissions: number[] = [];
  const flights: { retire: () => void; holds: ReturnType<typeof gate>[]; run: Promise<unknown> }[] = [];
  return {
    admissions,
    outstanding: () => outstanding,
    maximum: () => maximum,
    start(mode: Mode, count = P, faultAt?: number) {
      const { keys, storage, log } = fixture(mode, count);
      const holds = keys.map(() => gate());
      const faults = keys.map(key => new Error(`read fault for ${key}`));
      const controller = new AbortController();
      const signal = { aborted: false, checkpointReadAbort: controller.signal };
      const id = flights.length; const issued: string[] = [];
      vi.spyOn(storage, "read").mockImplementation(async (_ns, key) => {
        issued.push(key); admissions.push(id);
        const index = keys.indexOf(key);
        // An immediate fault owns no pending storage work, so only gated reads count here.
        if (index === faultAt) throw faults[index];
        outstanding++; maximum = Math.max(maximum, outstanding);
        try { await holds[index]!.wait; return null; }
        finally { outstanding--; }
      });
      const retire = () => { signal.aborted = true; controller.abort(new Error("hold retired")); };
      const run = settle(invoke(log, mode, keys, signal));
      flights.push({ retire, holds, run });
      return { id, keys, holds, faults, issued, retire, run };
    },
    async close() {
      // Retire queued admissions before releasing gates, including assertion failures.
      for (const flight of flights) flight.retire();
      for (const flight of flights) for (const hold of flight.holds) hold.release();
      await Promise.all(flights.map(flight => flight.run));
      await turns();
    },
  };
}

for (const mode of modes) {
  const otherMode = mode === "collector" ? "predecessor" : "collector";
  it(`T-VERDICT (${mode}) retains permits for reads pending at a verdict`, async () => {
    const schedule = permitSchedule();
    try {
      if (mode === modes[0]) expect(auditModule.AUDIT_CHECKPOINT_READ_CONCURRENCY).toBe(P);
      const wave0 = schedule.start(mode, P, 0);
      await turns();
      const verdict = await wave0.run;
      expect(verdict).toMatchObject({ state: "faulted" });
      expect((verdict as { error: unknown }).error).toBe(wave0.faults[0]);
      expect(wave0.issued).toEqual(wave0.keys);
      expect(schedule.outstanding()).toBe(P - 1);
      const before = schedule.outstanding();
      const wave1 = schedule.start(otherMode, P);
      await turns();
      // A1: A verdict retires queued admissions; the permits of reads still pending stay owned until each read settles.
      expect(wave1.issued).toHaveLength(P - before);
      // A2: Separate instances share the same budget while those reads remain pending.
      expect(schedule.outstanding()).toBe(P);
      expect(schedule.maximum()).toBeLessThanOrEqual(auditModule.AUDIT_CHECKPOINT_READ_CONCURRENCY);
      wave0.holds[1]!.release(); await turns(); // The first pending read follows the fault at index zero.
      // A3: No new acquirer exists, so only the settlement can supply this admission.
      expect(wave1.issued).toHaveLength(P - before + 1);
      wave0.holds[P - 1]!.release(); await turns(); // The final pending read supplies the remaining permit.
      // A4: Both settlements restore the second scan's full window.
      expect(wave1.issued).toEqual(wave1.keys);
      expect(schedule.outstanding()).toBe(P);
    } finally { await schedule.close(); expect(schedule.outstanding()).toBe(0); }
    expect(schedule.outstanding()).toBe(0);
  });

  it(`T-VERDICT (${mode}) returns every permit once pending reads settle`, async () => {
    const schedule = permitSchedule();
    try {
      const wave0 = schedule.start(mode, P, 0);
      await turns();
      const verdict = await wave0.run;
      expect(verdict).toMatchObject({ state: "faulted" });
      expect((verdict as { error: unknown }).error).toBe(wave0.faults[0]);
      expect(wave0.issued).toEqual(wave0.keys);
      expect(schedule.outstanding()).toBe(P - 1);
      for (const hold of wave0.holds) hold.release();
      await turns();
      expect(schedule.outstanding()).toBe(0);
      const wave1 = schedule.start(otherMode, P);
      await turns();
      // B1: Every settled read returns its permit even when its scan has reached a verdict.
      expect(wave1.issued).toHaveLength(P);
      // B2: A later scan can own the entire shared budget after those settlements.
      expect(schedule.outstanding()).toBe(P);
      expect(schedule.maximum()).toBe(P);
    } finally { await schedule.close(); expect(schedule.outstanding()).toBe(0); }
    expect(schedule.outstanding()).toBe(0);
  });
}
