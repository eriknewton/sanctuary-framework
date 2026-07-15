/**
 * Tests for the locked multi-uid pf-anchor registry (Unified Protect Slice 5
 * S5-1). The registry is the single source of truth for the shared anchor's
 * contents; every mutation is lock-serialized, transaction-safe (journaled
 * pending -> commit, rollback-on-failure, dirty-on-rollback-failure), and
 * drift-repairing (reconcile-on-entry). Every side effect (store, lock, pf
 * arm/disarm/liveness) is injected, so the whole state machine is exercised
 * without a real host, root, or pf.
 */

import { describe, it, expect } from "vitest";

import {
  PfAnchorRegistry,
  PfAnchorRegistryDirtyError,
  PfAnchorRegistryStateError,
  ProvisionLockHeldError,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
} from "../../src/egress-gate/anchor-registry.js";
import type { ArmPfAnchorResult, PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";
import type { ProvisionLockOps } from "../../src/castle-wall/provision/lockfile.js";

const A: PfAnchorRegistryEntry = { agent_uid: 502, gate_port: 19998, fortress_path: "/f/a" };
const B: PfAnchorRegistryEntry = { agent_uid: 504, gate_port: 20001, fortress_path: "/f/b" };

/** In-memory store that logs a sequence of persisted snapshots. */
function memStore(initial: PfAnchorRegistryState | null = null): PfAnchorRegistryStore & {
  saves: PfAnchorRegistryState[];
  current: PfAnchorRegistryState | null;
} {
  let current = initial;
  const saves: PfAnchorRegistryState[] = [];
  return {
    saves,
    get current() {
      return current;
    },
    async load() {
      return current === null ? null : structuredClone(current);
    },
    async save(state) {
      current = structuredClone(state);
      saves.push(structuredClone(state));
    },
  };
}

/** In-memory O_EXCL lock (fail-loud on double-acquire). */
function memLock(): ProvisionLockOps & { acquired: number } {
  let held = false;
  const box = {
    acquired: 0,
    async acquire() {
      if (held) {
        const err = new Error("EEXIST") as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      held = true;
      box.acquired += 1;
    },
    async release() {
      held = false;
    },
  };
  return box;
}

const okArm = (token?: string): ArmPfAnchorResult =>
  token === undefined ? { settleProbes: 1 } : { settleProbes: 1, enableToken: token };
const live: PfLivenessResult = { live: true, reasons: [] };
const notLive: PfLivenessResult = { live: false, reasons: ["drift"] };

/** Build a registry with recording mocks; returns the registry + spies. */
function makeRegistry(opts: {
  initial?: PfAnchorRegistryState | null;
  armImpl?: (entries: readonly { agent_uid: number }[], options: { existingEnableToken?: string }) => Promise<ArmPfAnchorResult>;
  disarmImpl?: (options: { enableToken?: string }) => Promise<void>;
  livenessImpl?: () => Promise<PfLivenessResult>;
} = {}) {
  const store = memStore(opts.initial ?? null);
  const lock = memLock();
  const armCalls: Array<{ uids: number[]; existingEnableToken?: string }> = [];
  const disarmCalls: Array<{ enableToken?: string }> = [];
  const runner = { async run() { return { code: 0, stdout: "", stderr: "" }; } };
  const ops: PfAnchorRegistryOps = {
    store,
    lock,
    runner,
    armUnion: async (entries, options) => {
      armCalls.push({
        uids: entries.map((e) => e.agent_uid),
        ...(options.existingEnableToken !== undefined
          ? { existingEnableToken: options.existingEnableToken }
          : {}),
      });
      return (opts.armImpl ?? (async () => okArm(options.existingEnableToken ?? "1")))(entries, options);
    },
    disarm: async (options) => {
      disarmCalls.push({ ...(options.enableToken !== undefined ? { enableToken: options.enableToken } : {}) });
      await (opts.disarmImpl ?? (async () => {}))(options);
    },
    unionLiveness: opts.livenessImpl ?? (async () => live),
  };
  return { registry: new PfAnchorRegistry(ops), store, lock, armCalls, disarmCalls };
}

describe("egress-gate/anchor-registry", () => {
  it("adds the first confined uid: arms [A] with no existing token, persists one entry", async () => {
    const { registry, store, armCalls } = makeRegistry();
    const res = await registry.addOrUpdate(A);
    expect(res.committed.map((e) => e.agent_uid)).toEqual([502]);
    expect(res.dirty).toBe(false);
    expect(armCalls).toEqual([{ uids: [502] }]); // no existingEnableToken on first arm
    expect(store.current?.committed).toHaveLength(1);
    expect(store.current?.enable_token).toBe("1");
  });

  it("adds a second uid without dropping the first (HIGH-4 regression guard)", async () => {
    const { registry, armCalls, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
    });
    const res = await registry.addOrUpdate(B);
    expect(res.committed.map((e) => e.agent_uid).sort()).toEqual([502, 504]);
    // The arm carries BOTH uids in one union load, reusing the existing token.
    expect(armCalls).toEqual([{ uids: [502, 504], existingEnableToken: "1" }]);
    expect(store.current?.committed).toHaveLength(2);
  });

  it("updating an existing uid replaces its entry, never duplicates it", async () => {
    const { registry, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
    });
    await registry.addOrUpdate({ agent_uid: 502, gate_port: 30000, fortress_path: "/f/a2" });
    expect(store.current?.committed).toHaveLength(1);
    expect(store.current?.committed[0]?.gate_port).toBe(30000);
  });

  it("removes one of two uids: re-arms the remainder, does NOT flush (remove-one-keeps-other)", async () => {
    const { registry, armCalls, disarmCalls, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A, B], enable_token: "1" },
    });
    const res = await registry.remove(502);
    expect(res.committed.map((e) => e.agent_uid)).toEqual([504]);
    expect(armCalls).toEqual([{ uids: [504], existingEnableToken: "1" }]);
    expect(disarmCalls).toHaveLength(0); // NO flush while a uid remains
    expect(store.current?.committed).toHaveLength(1);
  });

  it("removing the LAST uid flushes the anchor and releases the enable token", async () => {
    const { registry, armCalls, disarmCalls, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [B], enable_token: "1" },
    });
    const res = await registry.remove(504);
    expect(res.committed).toEqual([]);
    expect(armCalls).toHaveLength(0);
    expect(disarmCalls).toEqual([{ enableToken: "1" }]); // flush + release
    expect(store.current?.committed).toEqual([]);
    expect(store.current?.enable_token).toBeUndefined();
  });

  it("refuses when the lock is already held (fail-loud, no pf mutation)", async () => {
    const { registry, lock, armCalls } = makeRegistry();
    await lock.acquire(); // pre-hold the lock
    await expect(registry.addOrUpdate(A)).rejects.toBeInstanceOf(ProvisionLockHeldError);
    expect(armCalls).toHaveLength(0);
  });

  it("reconcile-on-entry re-asserts a DRIFTED committed union before the new mutation (Codex H5)", async () => {
    let probes = 0;
    const { registry, armCalls } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
      livenessImpl: async () => (++probes === 1 ? notLive : live),
    });
    await registry.addOrUpdate(B);
    // First arm re-asserts the drifted committed [A]; second arm applies [A,B].
    expect(armCalls).toEqual([
      { uids: [502], existingEnableToken: "1" },
      { uids: [502, 504], existingEnableToken: "1" },
    ]);
  });

  it("journals the pending desired set BEFORE arming (Codex B1)", async () => {
    const events: string[] = [];
    const { registry } = makeRegistry({
      armImpl: async () => {
        events.push("arm");
        return okArm("1");
      },
    });
    const store = memStore(null);
    const originalSave = store.save.bind(store);
    // Rebuild with an instrumented store to observe save-vs-arm ordering.
    const lock = memLock();
    const reg = new PfAnchorRegistry({
      store: {
        load: store.load.bind(store),
        save: async (s) => {
          events.push(s.pending !== undefined ? "save(pending)" : "save(commit)");
          await originalSave(s);
        },
      },
      lock,
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async () => {
        events.push("arm");
        return okArm("1");
      },
      unionLiveness: async () => live,
    });
    await reg.addOrUpdate(A);
    expect(events.indexOf("save(pending)")).toBeLessThan(events.indexOf("arm"));
    expect(events.indexOf("arm")).toBeLessThan(events.indexOf("save(commit)"));
    void registry;
  });

  it("rolls back to the previous committed union on apply failure (original error surfaces, not dirty)", async () => {
    let armN = 0;
    const { registry, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
      armImpl: async (entries) => {
        armN += 1;
        // arm #1 = reconcile re-assert (skipped, live). The mutation arm for
        // [A,B] FAILS; the rollback arm for [A] succeeds.
        if (entries.some((e) => e.agent_uid === 504)) throw new Error("arm B failed");
        return okArm("1");
      },
    });
    await expect(registry.addOrUpdate(B)).rejects.toThrow(/arm B failed/);
    // committed stayed [A]; not dirty (rollback succeeded).
    expect(store.current?.committed.map((e) => e.agent_uid)).toEqual([502]);
    expect(store.current?.dirty).toBeUndefined();
    expect(armN).toBeGreaterThanOrEqual(2); // failed mutation arm + rollback arm
  });

  it("marks the registry DIRTY when rollback also fails (Codex B1 -> posture red)", async () => {
    const { registry, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
      armImpl: async () => {
        throw new Error("every arm fails (mutation AND rollback)");
      },
    });
    await expect(registry.addOrUpdate(B)).rejects.toBeInstanceOf(PfAnchorRegistryDirtyError);
    expect(store.current?.dirty).toBe(true);
    const listed = await registry.list();
    expect(listed.dirty).toBe(true);
  });

  it("fails closed on corrupt persisted state (never mutates from an unknown baseline)", async () => {
    const badStore: PfAnchorRegistryStore = {
      // committed is not an array -> corruption.
      async load() {
        return { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: "nope" } as unknown as PfAnchorRegistryState;
      },
      async save() {},
    };
    const armCalls: number[] = [];
    const reg = new PfAnchorRegistry({
      store: badStore,
      lock: memLock(),
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async () => {
        armCalls.push(1);
        return okArm("1");
      },
      unionLiveness: async () => live,
    });
    await expect(reg.addOrUpdate(A)).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
    expect(armCalls).toHaveLength(0);
  });

  it("rejects a malformed entry (root uid) before any lock or pf work", async () => {
    const { registry, armCalls } = makeRegistry();
    await expect(
      registry.addOrUpdate({ agent_uid: 0, gate_port: 19998, fortress_path: "/f" }),
    ).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
    expect(armCalls).toHaveLength(0);
  });

  it("list() reflects the committed set and dirty flag", async () => {
    const { registry } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A, B], enable_token: "1", dirty: true },
    });
    const listed = await registry.list();
    expect(listed.entries.map((e) => e.agent_uid).sort()).toEqual([502, 504]);
    expect(listed.dirty).toBe(true);
  });

  it("re-adding the same entry is idempotent (one entry, still re-asserted)", async () => {
    const { registry, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
    });
    await registry.addOrUpdate(A);
    expect(store.current?.committed).toHaveLength(1);
  });

  it("removing an absent uid is a no-op that keeps the current union", async () => {
    const { registry, store, disarmCalls } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A], enable_token: "1" },
    });
    const res = await registry.remove(999);
    expect(res.committed.map((e) => e.agent_uid)).toEqual([502]);
    expect(disarmCalls).toHaveLength(0);
    expect(store.current?.committed).toHaveLength(1);
  });
});
