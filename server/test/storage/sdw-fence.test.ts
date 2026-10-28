import { afterEach, describe, expect, it, vi } from "vitest";
import children from "node:child_process";
import * as locks from "../../src/storage/cross-process-lock.js";
import { readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createSdwFenceFixture, sdwDeferred, fixtureEpochs } from "./sdw-journal-fixtures.js";
import { withSdwJournalAdmission } from "../../src/storage/exit-import-journal.js";
import { SDW_JOURNAL_NAMESPACES, SdwStorageError, type SdwAdmissionToken } from "../../src/storage/sdw-journal-contract.js";
import { installSdwFence } from "../../src/storage/sdw-fence.js";

const NS = SDW_JOURNAL_NAMESPACES[0];
const rigs: Awaited<ReturnType<typeof createSdwFenceFixture>>[] = [];
async function rig() { const value = await createSdwFenceFixture(); rigs.push(value); return value; }
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(rigs.splice(0).map(r => r.cleanup())); });
const refusal = (reason: string, decision = "none") => ({ reason, decision });

describe("SDW injected guard and lifetime model", () => {
  it("held_scope_observer_refuses", async () => {
    const r = await rig();
    const held = sdwDeferred(); const release = sdwDeferred();
    const holder = withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "new", [NS], undefined, async scope => {
      await scope.drainMutations(() => r.publish("BUILDING")); held.resolve(); await release.promise;
    }));
    await held.promise;
    try {
      const contender = vi.fn();
      await expect(locks.withPathLock(r.journal, "fence.lock", async () => {},
        { kernelBacked: true, timeoutMs: 0, onContended: contender })).rejects.toMatchObject({ kind: "contention" });
      expect(contender).toHaveBeenCalled();
      const read = vi.fn(async () => "old");
      await expect(r.fence.read(NS, read)).rejects.toMatchObject(refusal("storage_recovery_pending"));
      expect(read).not.toHaveBeenCalled();
    } finally { release.resolve(); await holder; }
    await r.publish("APPLIED");
    await expect(r.fence.read(NS, async () => "new")).resolves.toBe("new");
  });

  it("exists_pending_fixture", async () => {
    const r = await rig(); await r.publish("PREPARED");
    await expect(r.fence.read(NS, async () => false)).rejects.toMatchObject({
      reason: "storage_recovery_pending", message: "SDW recovery is pending. This build has no SDW recovery command; use the storage recovery API. Exit recovery does not clear this state.",
    });
    await r.publish("CLEAN");
    await expect(r.fence.read(NS, async () => false)).resolves.toBe(false);
  });

  it.each(["BUILDING", "PREPARED", "COMMIT", "INVALID"] as const)("pending_%s masks and decisions", async state => {
    const r = await rig(); await r.publish(state, 1, 1);
    await expect(r.fence.read(NS, async () => null)).rejects.toMatchObject(refusal(
      state === "INVALID" ? "storage_plan_invalid" : "storage_recovery_pending", state === "COMMIT" ? "committed" : "none"));
    if (state !== "INVALID") await expect(r.fence.read(SDW_JOURNAL_NAMESPACES[1], async () => "unaffected")).resolves.toBe("unaffected");
  });

  it("read_retries: exactly three attempts, no lock or child even for 32 concurrent reads", async () => {
    const r = await rig(); await r.publish("CLEAN");
    const lock = vi.spyOn(locks, "withPathLock"); const spawn = vi.spyOn(children, "spawn"); const fork = vi.spyOn(children, "fork");
    const read = vi.fn(async () => { await r.publish("CLEAN", read.mock.calls.length + 1); return "discard"; });
    await expect(r.fence.read(NS, read)).rejects.toMatchObject(refusal("storage_busy"));
    expect(read).toHaveBeenCalledTimes(3); expect(r.counters.observations).toBe(6);
    const values = await Promise.all(Array.from({ length: 32 }, () => r.fence.read(NS, async () => "stable")));
    expect(values).toEqual(Array(32).fill("stable"));
    expect(r.counters.observations).toBe(6 + 32 * 2);
    expect(lock).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled(); expect(fork).not.toHaveBeenCalled();
  });

  it("a moving read may succeed on the third attempt without retaining prior controls", async () => {
    const r = await rig(); await r.publish("CLEAN");
    let count = 0;
    await expect(r.fence.read(NS, async () => {
      count++; if (count < 3) await r.publish("CLEAN", count + 1); return count;
    })).resolves.toBe(3);
    expect(r.counters.observations).toBe(6);
  });

  it("single-execution scope rejects movement, nested scopes, mutations and late contexts", async () => {
    const r = await rig(); await r.publish("CLEAN");
    const callback = vi.fn(async () => { await r.publish("CLEAN", 2); return "discard"; });
    await expect(r.fence.withReadScope(callback)).rejects.toMatchObject(refusal("storage_busy"));
    expect(callback).toHaveBeenCalledTimes(1);
    const release = sdwDeferred(); let late!: Promise<unknown>;
    await r.fence.withReadScope(async () => {
      await expect(r.fence.withReadScope(async () => {})).rejects.toMatchObject(refusal("storage_scope_invalid"));
      await expect(r.fence.mutate(NS, async () => {})).rejects.toMatchObject(refusal("storage_scope_invalid"));
      late = release.promise.then(() => r.fence.read(NS, async () => "leak"));
      return "good";
    });
    const checked = expect(late).rejects.toMatchObject(refusal("storage_scope_invalid")); release.resolve(); await checked;
  });

  it("forged, foreign, closed and detached invocation tokens cannot enter", async () => {
    const r = await rig(); const foreign = await rig();
    const call = (token: SdwAdmissionToken) => r.fence.withEngine(token, "new", [NS], undefined, async () => {});
    await expect(call({} as SdwAdmissionToken)).rejects.toMatchObject(refusal("storage_scope_invalid"));
    let saved!: SdwAdmissionToken;
    await withSdwJournalAdmission(r.storage, async token => {
      saved = token;
      await expect(foreign.fence.withEngine(token, "new", [NS], undefined, async () => {})).rejects.toMatchObject(refusal("storage_scope_invalid"));
      await call(token);
    });
    await expect(call(saved)).rejects.toMatchObject(refusal("storage_scope_invalid"));
  });

  it("cancel_late_completion_waves", async () => {
    const r = await rig();
    let competing = false;
    const originalAdmission = r.storage.withNamespaceLock.bind(r.storage);
    const onContended = vi.fn();
    r.storage.withNamespaceLock = (namespace, name, operation, options) => originalAdmission(namespace, name, operation,
      competing ? { ...options, timeoutMs: 100, retryMs: 5, onContended } : options);
    // 100 ms is twenty 5 ms retries: a deterministic acquisition opportunity
    // after callback closure, rather than one zero-time probe before release.

    // Four independent admission waves expose capacity reuse after cancellation.
    for (let wave = 0; wave < 4; wave++) {
      const entered = sdwDeferred(); const release = sdwDeferred(); const returned = sdwDeferred();
      const controller = new AbortController(); let closed = false; let active = 0; let maxActive = 0;
      let lateAccept!: () => Promise<unknown>;
      const holder = withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "recover", [NS], controller.signal, async scope => {
        lateAccept = () => scope.accept(async () => {});
        void scope.accept(async () => { active++; maxActive = Math.max(maxActive, active); entered.resolve(); await release.promise; active--; });
        await entered.promise; await returned.promise;
      })).finally(() => { closed = true; });
      const result = expect(holder).rejects.toMatchObject(refusal("operation_aborted"));
      await entered.promise; controller.abort(); returned.resolve();
      competing = true; onContended.mockClear();
      try {
        await expect(withSdwJournalAdmission(r.storage, async () => { active++; })).rejects.toMatchObject({ reason: "storage_busy" });
        expect(onContended).toHaveBeenCalled();
        expect(closed).toBe(false); expect(active).toBe(1);
        await expect(lateAccept()).rejects.toMatchObject(refusal("storage_scope_invalid"));
      } finally { competing = false; release.resolve(); await result; }
      expect(maxActive).toBe(1); expect(active).toBe(0);
      expect(await readdir(r.journal)).toEqual(["fence.lock"]);
    }
    await expect(withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "recover", [NS], undefined, async () => "next"))).resolves.toBe("next");
  });

  it("detached accepted failure drains before admission release and remains observable", async () => {
    const r = await rig(); const entered = sdwDeferred(); const release = sdwDeferred();
    const holder = withSdwJournalAdmission(r.storage, async token => {
      void r.fence.withEngine(token, "recover", [NS], undefined, async scope => {
        void scope.accept(async () => { entered.resolve(); await release.promise; throw new Error("disk failed"); });
        await entered.promise;
      }).catch(() => {});
      await entered.promise;
    });
    const failed = expect(holder).rejects.toThrow("disk failed");
    await entered.promise;
    try { await expect(withSdwJournalAdmission(r.storage, async () => {})).rejects.toMatchObject({ reason: "storage_busy" }); }
    finally { release.resolve(); await failed; }
  });

  it("engine-only capacity does not cap ordinary reads; occupied durable slots allow recovery and retirement", async () => {
    const r = await rig(); await r.publish("APPLIED");
    const callback = vi.fn(async () => {});
    await expect(withSdwJournalAdmission(r.storage, token =>
      r.fence.withEngine(token, "new", [NS], undefined, callback))).rejects.toMatchObject({ reason: "storage_busy" });
    for (const mode of ["recover", "retire"] as const) {
      await withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, mode, [NS], undefined, async () => {
        await expect(r.fence.read(NS, async () => "ordinary")).resolves.toBe("ordinary");
      }));
    }
    expect(callback).not.toHaveBeenCalled();
  });

  it("committed observation is not relabeled none by parser or callback errors", async () => {
    const r = await rig(); await r.publish("COMMIT");
    await expect(withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "recover", [NS], undefined,
      async () => { throw new SdwStorageError("storage_plan_invalid", "none"); }))).rejects.toMatchObject(refusal("storage_plan_invalid", "committed"));
    const value = JSON.parse(await readFile(r.control, "utf8")); value.generation.epochs = {};
    await writeFile(r.control, JSON.stringify(value));
    await expect(r.fence.read(NS, async () => false)).rejects.toMatchObject(refusal("storage_plan_invalid", "committed"));
  });

  it("unanswerable observation is unavailable and retains every file", async () => {
    const r = await rig(); await r.publish("COMMIT");
    r.port.observe = async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); };
    await expect(r.fence.read(NS, async () => false)).rejects.toMatchObject(refusal("storage_capability_unavailable"));
    expect(JSON.parse(await readFile(r.control, "utf8")).state).toBe("COMMIT");
  });

  it("mutation interlock drains an earlier writer before BUSY and sorts the whole namespace set", async () => {
    const r = await rig(); await r.publish("CLEAN");
    const entered = sdwDeferred(); const release = sdwDeferred(); const contended = sdwDeferred();
    const original = locks.withPathLock;
    const spy = vi.spyOn(locks, "withPathLock").mockImplementation((directory, name, operation, options) => original(directory, name, operation,
      { ...options, onContended: () => contended.resolve() }));
    const order: string[] = [];
    const ordinary = r.fence.mutate(NS, async () => { order.push("ordinary-enter"); entered.resolve(); await release.promise; order.push("ordinary-end"); });
    await entered.promise;
    const engine = withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "new", [...SDW_JOURNAL_NAMESPACES].reverse(), undefined,
      async scope => scope.drainMutations(async () => { order.push("busy"); await r.publish("BUILDING"); })));
    await contended.promise;
    try { expect(order).toEqual(["ordinary-enter"]); }
    finally { release.resolve(); await ordinary; await engine; }
    expect(order).toEqual(["ordinary-enter", "ordinary-end", "busy"]);
    expect(spy.mock.calls.filter(([, name]) => name === ".sdw-mutation.lock").slice(-SDW_JOURNAL_NAMESPACES.length)
      .map(([directory]) => directory.split("/").at(-1))).toEqual([...SDW_JOURNAL_NAMESPACES].sort());
    const mutate = vi.fn(async () => {});
    await expect(r.fence.mutate(NS, mutate)).rejects.toMatchObject(refusal("storage_recovery_pending")); expect(mutate).not.toHaveBeenCalled();
  });

  it("no retry of an effective mutation, no automatic stale break", async () => {
    const r = await rig(); await r.publish("CLEAN");
    const effect = vi.fn(async () => r.publish("CLEAN", 2));
    await expect(r.fence.mutate(NS, effect)).rejects.toMatchObject(refusal("storage_io_failed")); expect(effect).toHaveBeenCalledTimes(1);
    const lock = join(r.root, NS, ".sdw-mutation.lock"); await writeFile(lock, "stale", { mode: 0o600 });
    await expect(locks.withPathLock(join(r.root, NS), ".sdw-mutation.lock", async () => {}, { timeoutMs: 0 })).rejects.toMatchObject({ kind: "contention" });
    expect(await readFile(lock, "utf8")).toBe("stale");
  });

  it("missing observation dependencies and invalid masks fail closed", async () => {
    const r = await rig();
    expect(() => installSdwFence(r.storage, r.port)).toThrow(SdwStorageError);
    await r.publish("BUILDING");
    const value = JSON.parse(await readFile(r.control, "utf8")); value.generation.affected_mask = 0;
    await writeFile(r.control, JSON.stringify(value));
    await expect(r.fence.read(NS, async () => false)).rejects.toMatchObject(refusal("storage_plan_invalid"));
    expect(Object.keys(fixtureEpochs())).toEqual([...SDW_JOURNAL_NAMESPACES]);
  });
  it("detached read scope closes admission and drains accepted reads", async () => {
    const r = await rig(); const entered = sdwDeferred(); const release = sdwDeferred();
    let settled = false; let detached!: Promise<unknown>;
    const scoped = r.fence.withReadScope(async () => {
      detached = r.fence.read(NS, async () => { entered.resolve(); await release.promise; return "must not escape"; });
      void detached.catch(() => {});
      await entered.promise;
    }).finally(() => { settled = true; });
    const checked = expect(scoped).rejects.toMatchObject({ reason: "storage_scope_invalid" });
    await entered.promise;
    try { await Promise.resolve(); expect(settled).toBe(false); }
    finally { release.resolve(); await checked; }
    await expect(detached).rejects.toMatchObject({ reason: "storage_scope_invalid" });
  });

  it("abort during drain still reports abortion and does not release capacity early", async () => {
    const r = await rig(); const entered = sdwDeferred(); const release = sdwDeferred(); const returned = sdwDeferred();
    const abort = new AbortController();
    const holder = withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "recover", [NS], abort.signal, async scope => {
      void scope.accept(async () => { entered.resolve(); await release.promise; });
      await entered.promise; returned.resolve();
    }));
    const checked = expect(holder).rejects.toMatchObject({ reason: "operation_aborted" });
    await returned.promise; await Promise.resolve(); abort.abort();
    try { await expect(withSdwJournalAdmission(r.storage, async () => {})).rejects.toMatchObject({ reason: "storage_busy" }); }
    finally { release.resolve(); await checked; }
  });

  it("one accepted I/O, foreign invocation and rebound root refuse before effects", async () => {
    const r = await rig(); const entered = sdwDeferred(); const release = sdwDeferred();
    const tokenReady = sdwDeferred<SdwAdmissionToken>(); const finish = sdwDeferred();
    const holder = withSdwJournalAdmission(r.storage, async token => { tokenReady.resolve(token); await finish.promise; });
    const token = await tokenReady.promise;
    try {
      await expect(r.fence.withEngine(token, "new", [NS], undefined, async () => {})).rejects.toMatchObject({ reason: "storage_scope_invalid" });
    } finally { finish.resolve(); await holder; }
    await withSdwJournalAdmission(r.storage, token => r.fence.withEngine(token, "recover", [NS], undefined, async scope => {
      const accepted = scope.accept(async () => { entered.resolve(); await release.promise; });
      await entered.promise;
      try { await expect(scope.accept(async () => "overlap")).rejects.toMatchObject({ reason: "storage_busy" }); }
      finally { release.resolve(); await accepted; }
    }));
    r.port.assertBinding = async () => { throw new SdwStorageError("storage_holder_lost", "none"); };
    const callback = vi.fn(async () => {});
    await expect(withSdwJournalAdmission(r.storage, callback)).rejects.toMatchObject({ reason: "storage_holder_lost" });
    expect(callback).not.toHaveBeenCalled();
  });

  it("unstable private samples share the three-attempt budget; absence is not cached", async () => {
    const r = await rig(); const observe = r.port.observe;
    const sample = vi.fn(async () => { throw new SdwStorageError("storage_busy", "none"); });
    r.port.observe = sample;
    await expect(r.fence.read(NS, async () => false)).rejects.toMatchObject({ reason: "storage_busy" });
    expect(sample).toHaveBeenCalledTimes(3);
    r.port.observe = observe;
    await expect(r.fence.read(NS, async () => "old")).resolves.toBe("old");
    await r.publish("BUILDING");
    await expect(r.fence.read(NS, async () => "stale clean")).rejects.toMatchObject({ reason: "storage_recovery_pending" });
  });

  it("APPLIED errors retain committed decision and relevant epochs permit unaffected reads", async () => {
    const r = await rig(); await r.publish("APPLIED");
    await expect(r.fence.read(NS, async () => { throw new Error("read EIO"); })).rejects.toMatchObject({ reason: "storage_io_failed", decision: "committed" });
    await expect(r.fence.mutate(NS, async () => { throw new Error("write EIO"); })).rejects.toMatchObject({ reason: "storage_io_failed", decision: "committed" });
    await r.publish("CLEAN");
    await expect(r.fence.read(NS, async () => {
      const observation = JSON.parse(await readFile(r.control, "utf8"));
      observation.generation.epochs[SDW_JOURNAL_NAMESPACES[1]]++;
      await writeFile(r.control, JSON.stringify(observation)); return "same namespace epoch";
    })).resolves.toBe("same namespace epoch");
  });

});
