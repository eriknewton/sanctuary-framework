/** Observe reservation callers and raw entry writes until both have settled. */
import { AsyncLocalStorage } from "node:async_hooks";
import { expect, vi } from "vitest";
import { AuditLockHoldDeadlineError, DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS, type AuditLog } from "../../../src/operational/audit-log.js";
import type { FilesystemStorage } from "../../../src/storage/filesystem.js";
// The audit log's default hold deadline; the two selected holds each last that full deadline while every other storage operation runs under the same default.
export const WAVES_HOLD_DEADLINE_MS = DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS;
import { FLOW_STOP_FINAL_RECORD_RESERVE_MS } from "../../../src/castle-wall/constants.js";
import { FLOW_COALESCE_SUMMARY_OPERATION } from "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
const FIXTURE_RESERVE_SPLIT = 2;
// Test setting: the fixture hold budget is half the final-record reserve, sized for this small store; it states no production timing.
export const SHORT_HOLD_DEADLINE_MS = FLOW_STOP_FINAL_RECORD_RESERVE_MS / FIXTURE_RESERVE_SPLIT;
export const SINGLE_OWNER = 1; // One writer per immutable reservation.
export const HELD_SUMMARY_COUNT = 1; // One selected summary supplies the first recovery and summary failure.
export const SERIAL_DEADLINES = 2; // Summary then loss expire independently.
// The production summary operation, imported so a rename fails here instead of drifting.
export const SUMMARY_OPERATION = FLOW_COALESCE_SUMMARY_OPERATION;
// Must match the ingress-loss append operation in macos-flow-events.ts.
export const LOSS_OPERATION = "castle_wall_ingress_discarded";
export const POLL_INTERVAL_MS = 1; // One millisecond polling joins real I/O without delaying admission.
const REACTION_TURN_TIMEOUT_MS = SHORT_HOLD_DEADLINE_MS; // Bound a later event-loop turn independently of storage holds.
export function reactionTurn(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("fixture reaction turn did not complete")), REACTION_TURN_TIMEOUT_MS);
    setImmediate(() => { clearTimeout(timer); resolve(); });
  });
}
// Joins every started operation before reporting, so no settlement is left running, and a rejection still fails the caller.
export async function joinAll(promises: readonly (Promise<unknown> | undefined)[]): Promise<void> {
  const outcomes = await Promise.allSettled(promises);
  const rejected = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
  if (rejected) throw rejected.reason;
}
// Cleanup completes even when the body fails, and the body's assertion remains the reported failure.
export async function withFixtureCleanup<T>(body: () => Promise<T>, cleanup: () => Promise<void>): Promise<T> {
  const [result] = await Promise.allSettled([Promise.resolve().then(body)]);
  const [teardown] = await Promise.allSettled([Promise.resolve().then(cleanup)]);
  if (result.status === "rejected") throw result.reason;
  if (teardown.status === "rejected") throw teardown.reason;
  return result.value;
}
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
export interface LedgerPolicy {
  holdMs: number; setupMs: number; slackMs: number; cleanupMs: number;
  operations: string[];
  select?: (operation: string, details: Record<string, unknown> | undefined) => boolean;
}
// Caller rejection cannot retire an attempt while its raw entry write still owns storage work.
export function ownershipLedger(audit: AuditLog, storage: FilesystemStorage, policy: LedgerPolicy) {
  type Attempt = { id: string; operation: string; token: symbol; callerSettled: boolean; children: number; error?: unknown; active: boolean };
  const context = new AsyncLocalStorage<Attempt>();
  const attempts: Attempt[] = [];
  const overlaps: Array<{ id: string; operation: string; count: number }> = [];
  const activeAttempts = new Map<string, number>(), outstandingPhysicalWrites = new Map<string, number>();
  const highAttempts = new Map<string, number>(), highWrites = new Map<string, number>(), totalPhysicalWrites = new Map<string, number>();
  const selected = new Map<string, string>(), bytes = new Map<string, string>();
  const selectedTokens = new Map<string, symbol>(), heldTokens = new Set<symbol>();
  const byteMismatches: string[] = [];
  const gates = new Map<string, ReturnType<typeof deferred>>(), entries = new Map<string, ReturnType<typeof deferred>>();
  const recoveries: Array<{ reason: string }> = [];
  const settled: Promise<unknown>[] = [];
  const payloads: Array<{ operation: string; details: Record<string, unknown> | undefined }> = [];
  const appendEvents: Array<{ operation: string; started: number; completed?: number; failed?: number }> = [];
  const flushEvents: Array<{ started: number; completed?: number; failed?: number }> = [];
  const observeAppend = (operation: string, started: number, original: Promise<unknown>) => {
    const event = { operation, started } as typeof appendEvents[number]; appendEvents.push(event);
    observations.push(original.then(() => { event.completed = performance.now(); }, () => { event.failed = performance.now(); }));
  };
  let hold = true;
  const errors: Array<{ method: string; error: unknown }> = [];
  const observations: Promise<unknown>[] = [];
  const append = audit.append.bind(audit), write = storage.writeDurable.bind(storage);
  const watched = audit as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const store = storage as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const auditMethods = ["withAuditWriteLock", "persistChainedEntry", "maybeRotate", "writeCheckpointIfNeeded", "collectPersistedEntryHashes", "flush", "flushDurable"];
  const flush = audit.flush.bind(audit);
  const monitors = [...auditMethods.map(method => {
    const spy = vi.spyOn(watched, method);
    if (method === "flush") spy.mockImplementation(() => {
      const event: typeof flushEvents[number] = { started: performance.now() };
      flushEvents.push(event);
      const original = flush();
      observations.push(original.then(() => { event.completed = performance.now(); }, () => { event.failed = performance.now(); }));
      return original;
    });
    return { method, spy, seen: 0 };
  }),
    ...["list", "listKeys", "read"].map(method => ({ method, spy: vi.spyOn(store, method), seen: 0 }))];
  const observe = (method: string, promise: Promise<unknown>) => {
    observations.push(promise.then(() => undefined, error => { errors.push({ method, error }); }));
  };
  const harvest = () => {
    for (const monitor of monitors) {
      while (monitor.seen < monitor.spy.mock.results.length) {
        const result = monitor.spy.mock.results[monitor.seen++]!;
        if (result.type === "throw") errors.push({ method: monitor.method, error: result.value });
        else if (result.type === "return" && result.value instanceof Promise) observe(monitor.method, result.value);
      }
    }
  };
  audit.onWriteLockRecovery(event => { recoveries.push(event); });
  const increment = (map: Map<string, number>, id: string, amount: number) => map.set(id, (map.get(id) ?? 0) + amount);
  const retire = (attempt: Attempt) => {
    if (attempt.active && attempt.callerSettled && attempt.children === 0) {
      attempt.active = false; increment(activeAttempts, attempt.id, -SINGLE_OWNER);
    }
  };
  for (const operation of policy.operations) { gates.set(operation, deferred()); entries.set(operation, deferred()); }
  const appendSpy = vi.spyOn(audit, "append").mockImplementation((...args) => {
    const started = performance.now();
    const operation = args[1], details = args[3]; payloads.push({ operation, details });
    if (!policy.operations.includes(operation) || policy.select?.(operation, details) === false) {
      const original = append(...args); observeAppend(operation, started, original); observe("append", original); return original;
    }
    const id = JSON.stringify([operation, details!.consumer_instance_id, details!.summary_seq ?? details!.batch_seq]);
    const serialized = JSON.stringify(details);
    if (!bytes.has(id)) bytes.set(id, serialized);
    else if (serialized !== bytes.get(id)) byteMismatches.push(id);
    if (!selected.has(operation)) selected.set(operation, id);
    const attempt: Attempt = { id, operation, token: Symbol(id), callerSettled: false, children: 0, active: true };
    if (!selectedTokens.has(operation)) selectedTokens.set(operation, attempt.token);
    attempts.push(attempt); increment(activeAttempts, id, SINGLE_OWNER);
    highAttempts.set(id, Math.max(highAttempts.get(id) ?? 0, activeAttempts.get(id)!));
    // A prompt later completion cannot erase simultaneous ownership observed at invocation.
    if (activeAttempts.get(id)! > SINGLE_OWNER) overlaps.push({ id, operation, count: activeAttempts.get(id)! });
    const original = context.run(attempt, () => append(...args));
    observeAppend(operation, started, original); observe("append", original);
    settled.push(original.then(() => { attempt.callerSettled = true; retire(attempt); }, error => {
      attempt.error = error; attempt.callerSettled = true; retire(attempt);
    }));
    return original;
  });
  const writeSpy = vi.spyOn(storage, "writeDurable").mockImplementation((...args) => {
    const attempt = context.getStore();
    if (!attempt || args[0] !== "_audit" || !args[1].startsWith("entry-")) {
      const original = write(...args); observe("writeDurable", original); return original;
    }
    attempt.children++; increment(outstandingPhysicalWrites, attempt.id, SINGLE_OWNER); increment(totalPhysicalWrites, attempt.id, SINGLE_OWNER);
    highWrites.set(attempt.id, Math.max(highWrites.get(attempt.id) ?? 0, outstandingPhysicalWrites.get(attempt.id)!));
    let original: ReturnType<typeof write>;
    if (hold && selectedTokens.get(attempt.operation) === attempt.token && !heldTokens.has(attempt.token)) {
      heldTokens.add(attempt.token); entries.get(attempt.operation)!.resolve();
      original = gates.get(attempt.operation)!.promise.then(() => { throw new Error("fixture late entry unavailable"); });
    } else original = write(...args);
    const retireChild = () => { attempt.children--; increment(outstandingPhysicalWrites, attempt.id, -SINGLE_OWNER); retire(attempt); };
    settled.push(original.then(retireChild, retireChild));
    return original;
  });
  return {
    attempts, activeAttempts, outstandingPhysicalWrites, totalPhysicalWrites, highAttempts, highWrites, selected, payloads, recoveries, byteMismatches, errors, harvest, appendEvents, flushEvents,
    auditCalls(method: string) { return monitors.find(monitor => monitor.method === method)!.spy.mock.calls.length; },
    async completedCalls(method: string, from: number) {
      const monitor = monitors.find(item => item.method === method)!;
      const results = monitor.spy.mock.results.slice(from);
      for (const result of results) { expect(result.type).toBe("return"); await result.value; }
      return results.length;
    },
    async deadline(operation: string, count: number) {
      await vi.waitFor(() => expect(outstandingPhysicalWrites.get(selected.get(operation)!)).toBe(SINGLE_OWNER), { timeout: policy.setupMs });
      await entries.get(operation)!.promise;
      await vi.waitFor(() => {
        expect(recoveries).toHaveLength(count);
        const attempt = attempts.find(item => item.id === selected.get(operation))!;
        expect(attempt.callerSettled).toBe(true);
        expect(attempt.error).toBeInstanceOf(AuditLockHoldDeadlineError);
        expect(attempt.error).toMatchObject({ name: "AuditLockHoldDeadlineError", deadlineMs: policy.holdMs });
      }, { timeout: policy.holdMs + policy.slackMs });
      await reactionTurn();
      harvest();
      expect(recoveries.at(-1)?.reason).toBe("write_lock_hold_deadline_exceeded");
    },
    exclusive(operations = policy.operations) {
      harvest();
      expect(byteMismatches, "immutable reservation bytes").toEqual([]);
      for (const operation of operations) {
        const id = selected.get(operation)!; expect(id).toBeDefined();
        expect(overlaps.filter(event => event.operation === operation), `${operation} active attempts`).toEqual([]);
        expect(activeAttempts.get(id), `${operation} active attempts`).toBe(SINGLE_OWNER);
        expect(outstandingPhysicalWrites.get(id), `${operation} outstanding entry writes`).toBe(SINGLE_OWNER);
      }
      for (const count of highAttempts.values()) expect(count, "exclusive attempt high-water").toBeLessThanOrEqual(SINGLE_OWNER);
      for (const count of highWrites.values()) expect(count, "exclusive entry-write high-water").toBeLessThanOrEqual(SINGLE_OWNER);
      expect(new Set(attempts.filter(item => item.active).map(item => item.token)).size).toBe(attempts.filter(item => item.active).length);
    },
    release() { hold = false; for (const gate of gates.values()) gate.resolve(); },
    async join() {
      let observed = 0;
      while (observed !== settled.length) { observed = settled.length; await Promise.all(settled); }
      expect(byteMismatches, "immutable reservation bytes").toEqual([]);
      let total = -1;
      while (total !== observations.length) { harvest(); total = observations.length; await Promise.all(observations); await reactionTurn(); harvest(); }
      await vi.waitFor(() => {
        expect([...activeAttempts.values()].every(count => count === 0)).toBe(true);
        expect([...outstandingPhysicalWrites.values()].every(count => count === 0)).toBe(true);
      }, { timeout: policy.cleanupMs });
    },
    clean(expectedRecoveries: number) {
      harvest();
      expect(recoveries).toHaveLength(expectedRecoveries);
      expect(byteMismatches, "immutable reservation bytes").toEqual([]);
      const expected = new Set(attempts.filter(attempt => selectedTokens.get(attempt.operation) === attempt.token && attempt.error instanceof AuditLockHoldDeadlineError).map(attempt => attempt.error));
      expect(expected.size).toBe(expectedRecoveries);
      expect(errors.filter(({ error }) => !expected.has(error)), "all audit errors belong to selected callers").toEqual([]);
    },
    restore() { for (const monitor of monitors) monitor.spy.mockRestore(); appendSpy.mockRestore(); writeSpy.mockRestore(); context.disable(); },
  };
}
