/** Own-memory admissions share durable, bounded caller budgets and hold on unavailable accounting. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as custody from "../../src/storage/custody-fs.js";
import * as locks from "../../src/storage/cross-process-lock.js";
import { ApprovalGate, OWN_SCOPE_SAVE_MAX_PER_WINDOW as CAP, OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS as CALLERS,
  OWN_SCOPE_SAVE_MAX_FILE_BYTES as FILE_CAP, OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS as DEADLINE,
  OWN_SCOPE_SAVE_MAX_QUEUED_ADMISSIONS as QUEUE_CAP, OWN_SCOPE_SAVE_WINDOW_MS as WINDOW } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { BaselineTracker } from "../../src/principal-policy/baseline.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";

let dir: string;
let path: string;
const logs: Array<Record<string, any>> = [];
const requests: import("../../src/principal-policy/types.js").ApprovalRequest[] = [];
const lockOperations: Promise<unknown>[] = [];
const releasePaused: Array<() => void> = [];
const gates: ApprovalGate[] = [];
const digest = (caller: string) => createHash("sha256").update(`agent:${caller}`).digest("hex");
function gate(caller = "owner", directory: string | undefined = dir) {
  const instance = new ApprovalGate(DEFAULT_POLICY, {
    recordToolCall() {}, isFirstSession: false, isNewNamespace: () => false,
    getCallRate: () => 0, getAverageCallRate: () => 0,
  } as unknown as BaselineTracker,
  new CallbackApprovalChannel(async request => { requests.push(request); return { decision: "deny", decided_by: "human", decided_at: new Date().toISOString() }; }),
  { appendCritical: async (entry: Record<string, any>) => { logs.push(entry); } } as unknown as AuditLog,
  undefined, undefined, undefined, { currentAgentId: () => caller, ownScopeSaveStateDirectory: directory });
  gates.push(instance);
  return instance;
}
const save = (g: ApprovalGate, bytes: unknown = 1) => g.evaluate("memory_insert", { text_bytes: bytes }, undefined, undefined, "memory_insert");
const seed = (count: number) => writeFile(path, JSON.stringify([[digest("owner"), Date.now(), count, count]]));
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "shared-save-quota-"));
  path = join(dir, "own-scope-save-quota.json");
  logs.length = 0;
  requests.length = 0;
  lockOperations.length = 0;
  const original = locks.withPathLock;
  vi.spyOn(locks, "withPathLock").mockImplementation((...args) => {
    const operation = original(...args);
    lockOperations.push(operation);
    return operation;
  });
});
afterEach(async () => {
  for (const release of releasePaused.splice(0)) release();
  vi.useRealTimers();
  // Even a failed assertion or test timeout must drain the injected writer before deleting its fortress.
  await Promise.allSettled(gates.splice(0).map(g => (g as unknown as { ownScopeSaveTail: Promise<unknown> }).ownScopeSaveTail));
  await Promise.allSettled(lockOperations);
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

describe("shared own-memory quota", () => {
  it("two gates on one directory share one caller budget", async () => {
    const a = gate(), b = gate();
    for (let n = 0; n < CAP; n++) expect((await save(n % 2 ? a : b)).tier).toBe(3);
    expect((await save(a)).tier).toBe(2);
    expect((await save(b)).tier).toBe(2);
    expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(CAP);
  });
  it("a restarted gate loads the durable reservation", async () => {
    await seed(CAP - 1);
    expect((await save(gate())).tier).toBe(3);
    expect((await save(gate())).tier).toBe(2);
  });
  it.each(["corrupt", "oversized", "locked", "unwritable"])("holds on %s state with only a cause class", async (fault) => {
    if (fault === "corrupt") await writeFile(path, "invalid JSON");
    if (fault === "oversized") await writeFile(path, " ".repeat(FILE_CAP + 1));
    if (fault === "locked") vi.spyOn(locks, "kernelBackedCrossProcessLockPlatformSupported").mockReturnValue(false);
    if (fault === "locked") await writeFile(join(dir, "own-scope-save-quota.lock"), "held");
    // Inject the OS permission failure so this also exercises root-run test environments.
    if (fault === "unwritable") vi.spyOn(custody, "writeFileCustody").mockRejectedValue(Object.assign(new Error("private OS detail"), { code: "EACCES" }));
    if (fault === "locked") vi.useFakeTimers();
    const pending = save(gate());
    if (fault === "locked") await vi.advanceTimersByTimeAsync(DEADLINE);
    expect((await pending).tier).toBe(2);
    const rows = logs.filter(e => e.operation === "memory_save_quota_unavailable");
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0].details)).toEqual(["cause_class"]);
    expect(["invalid_state", "deadline", "write"]).toContain(rows[0].details.cause_class);
    expect(JSON.stringify(rows)).not.toContain("private OS detail");
  });
  it("concurrent admissions and repeated waves from two instances never exceed the cap", async () => {
    const a = gate(), b = gate();
    let allowed = 0;
    for (let wave = 0; wave < CAP; wave++) {
      const results = await Promise.all([save(a), save(b)]);
      allowed += results.filter(r => r.allowed).length;
    }
    expect(allowed).toBe(CAP);
    expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(CAP);
  });
  it("write timeout retains the lock until late completion and never admits over the cap", async () => {
    // Exercise the O_EXCL fallback's file ownership through a delayed write.
    vi.spyOn(locks, "kernelBackedCrossProcessLockPlatformSupported").mockReturnValue(false);
    await seed(CAP - 1);
    const original = custody.writeFileCustody;
    let release!: () => void;
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const paused = new Promise<void>(resolve => { release = resolve; });
    releasePaused.push(release);
    vi.spyOn(custody, "writeFileCustody").mockImplementationOnce(async (...args) => { entered(); await paused; await original(...args); });
    vi.useFakeTimers();
    const a = gate(), b = gate();
    const first = save(a);
    await started;
    await vi.advanceTimersByTimeAsync(DEADLINE);
    expect((await first).tier).toBe(2);
    expect((await stat(join(dir, "own-scope-save-quota.lock"))).isFile()).toBe(true);
    const second = save(b);
    await vi.advanceTimersByTimeAsync(DEADLINE);
    expect((await second).tier).toBe(2);
    const third = save(a);
    await vi.advanceTimersByTimeAsync(DEADLINE);
    expect((await third).tier).toBe(2); // The queued waiter has its own arrival deadline.
    release();
    vi.useRealTimers();
    // Drain the actual primitive, without polling or sleeping, before inspecting the final reservation.
    await Promise.allSettled(lockOperations);
    expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(CAP);
    await expect(stat(join(dir, "own-scope-save-quota.lock"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await save(gate())).tier).toBe(2);
  });
  it("bounds inspection and file size at the caller cap and prunes every expired row", async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await writeFile(path, JSON.stringify(Array.from({ length: CALLERS }, (_, n) => [digest(`old-${n}`), now, 1, 1])));
    const g = gate();
    for (let n = 0; n < CAP; n++) {
      expect((await save(g)).tier).toBe(2);
      expect(logs.at(-2)).toMatchObject({ operation: "memory_save_quota_unavailable", details: { cause_class: "caller_table_full" } });
      expect(g.getOwnScopeSaveQuotaDiagnostics()).toEqual({ trackedCallers: CALLERS, lastWork: 1, scannedEntries: CALLERS }); // Full active tables allow lookup only, never eviction.
      expect((await readFile(path)).length).toBeLessThanOrEqual(FILE_CAP);
    }
    const rows = JSON.parse(await readFile(path, "utf8"));
    expect(rows).toEqual(Array.from({ length: CALLERS }, (_, n) => [digest(`old-${n}`), now, 1, 1]));
    clock.mockReturnValue(now + WINDOW);
    expect((await save(g)).tier).toBe(3);
    expect(JSON.parse(await readFile(path, "utf8"))).toHaveLength(1);
  });
  it("ten concurrent saves on one gate produce no holds and exactly ten reservations", async () => {
    const g = gate();
    const results = await Promise.all(Array.from({ length: 10 }, () => save(g))); // A short burst below the waiter cap.
    expect(results.every(r => r.allowed && r.tier === 3)).toBe(true);
    expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(results.length);
    expect(logs.filter(e => e.operation.startsWith("gate_deny") || e.operation.startsWith("memory_save_quota_"))).toEqual([]);
    expect(locks.withPathLock).toHaveBeenCalledWith(dir, "own-scope-save-quota.lock", expect.any(Function),
      expect.objectContaining({ kernelBacked: locks.kernelBackedCrossProcessLockPlatformSupported(process.platform) }));
  });
  it("bounds queued waiters and preserves quota through three timeout then release waves", async () => {
    const g = gate();
    await seed(CAP - 3); // Three late active writes may spend the last three reservations, never refund them.
    const original = custody.writeFileCustody;
    for (let wave = 0; wave < 3; wave++) {
      let release!: () => void, entered!: () => void;
      const paused = new Promise<void>(resolve => { release = resolve; });
      const started = new Promise<void>(resolve => { entered = resolve; });
      releasePaused.push(release);
      const writer = vi.spyOn(custody, "writeFileCustody").mockImplementationOnce(async (...args) => { entered(); await paused; await original(...args); });
      vi.useFakeTimers();
      const first = save(g);
      await started;
      const queued = Array.from({ length: QUEUE_CAP }, () => save(g));
      let overflowSettled = false;
      const overflow = save(g).then(result => { overflowSettled = true; return result; });
      await vi.advanceTimersByTimeAsync(0);
      expect(overflowSettled).toBe(true);
      expect((await overflow).tier).toBe(2);
      expect(logs).toContainEqual(expect.objectContaining({ operation: "memory_save_quota_unavailable", details: { cause_class: "admission_queue_full" } }));
      await vi.advanceTimersByTimeAsync(DEADLINE);
      expect((await Promise.all([first, ...queued])).every(r => r.tier === 2 && !r.allowed)).toBe(true);
      const deadlineRows = logs.filter(e => e.operation === "memory_save_quota_unavailable" && e.details.cause_class === "deadline");
      expect(deadlineRows).toHaveLength((wave + 1) * (QUEUE_CAP + 1));
      release();
      vi.useRealTimers();
      // Wait for the queue itself, including canceled waiters, rather than only its active filesystem call.
      await (g as unknown as { ownScopeSaveTail: Promise<unknown> }).ownScopeSaveTail;
      expect(writer).toHaveBeenCalledTimes(1);
      writer.mockRestore();
      expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(CAP - 3 + wave + 1);
    }
    expect((await save(g)).tier).toBe(2);
    expect(JSON.parse(await readFile(path, "utf8"))[0][2]).toBe(CAP);
  });
  it("caller churn never renews an active exhausted budget", async () => {
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now);
    await seed(CAP);
    const a = gate();
    expect((await save(a)).tier).toBe(2);
    for (let n = 0; n < CALLERS; n++) {
      expect((await save(gate(`other-${n}`))).tier).toBe(n < CALLERS - 1 ? 3 : 2);
    }
    expect((await save(a)).tier).toBe(2);
    expect(JSON.parse(await readFile(path, "utf8")).find((r: unknown[]) => r[0] === digest("owner"))).toEqual([digest("owner"), now, CAP, CAP]);
    expect(logs).toContainEqual(expect.objectContaining({ operation: "memory_save_quota_unavailable", details: { cause_class: "caller_table_full" } }));
  });
  it("a backward clock step preserves usage and restarts only the window timestamp", async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await seed(CAP - 1);
    clock.mockReturnValue(now - WINDOW);
    const g = gate();
    expect((await save(g)).tier).toBe(3);
    expect(JSON.parse(await readFile(path, "utf8"))[0]).toEqual([digest("owner"), now - WINDOW, CAP, CAP]);
    expect((await save(g)).tier).toBe(2);
  });
  it.each([-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1", null, undefined])("holds invalid text_bytes %s", async bytes => {
    // Explicit undefined must reach the gate rather than the helper's default.
    const result = await gate().evaluate("memory_insert", { text_bytes: bytes }, undefined, undefined, "memory_insert");
    expect(result.tier).toBe(2);
    expect(logs).toContainEqual(expect.objectContaining({ operation: "memory_save_quota_unavailable", details: { cause_class: "invalid_bytes" } }));
  });
});


it.each([
  ["capability", "lock_capability"], ["contention", "lock"], ["scaffold-integrity", "lock_integrity"], ["io", "lock"],
] as const)("reports typed lock %s as %s without private error text", async (kind, cause) => {
  vi.spyOn(locks, "withPathLock").mockRejectedValue(new locks.CrossProcessLockError("private lock path", kind));
  expect((await save(gate())).tier).toBe(2);
  const row = logs.find(e => e.operation === "memory_save_quota_unavailable");
  expect(row!.details).toEqual({ cause_class: cause, lock_kind: kind });
  expect(requests.at(-1)!.context).toMatchObject({ cause_class: cause, lock_kind: kind });
  expect(JSON.stringify(logs)).not.toContain("private lock path");
});

it("names the removable quota lock file only in the O_EXCL runbook paragraph", async () => {
  const doc = await readFile(new URL("../../../docs/rung1-fresh-host.md", import.meta.url), "utf8");
  const paragraphs = doc.split(/\n\s*\n/).filter(p => p.includes("own-scope-save-quota.lock"));
  expect(paragraphs).toHaveLength(1);
  expect(paragraphs[0]).toContain("On O_EXCL platforms");
  expect(doc).toContain("lock_capability");
  expect(doc).toContain("loginctl enable-linger");
  expect(doc).toContain("process never holds");
  expect(doc).toContain("A `lock` hold means the save could not acquire or retain the directory lock: most often another process holds it; it also covers I/O errors on the lock directory and a holder lost after acquisition.");
});
