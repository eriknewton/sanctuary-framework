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
  createFsQuarantineForensicsWriter,
  createFsRegistryStore,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
} from "../../src/egress-gate/anchor-registry.js";
import {
  GenerationCoordinator,
  type GenerationStagingRecord,
} from "../../src/egress-gate/generation.js";
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
  forensicsImpl?: (payload: string) => Promise<string>;
} = {}) {
  const store = memStore(opts.initial ?? null);
  const lock = memLock();
  const armCalls: Array<{ uids: number[]; existingEnableToken?: string }> = [];
  const disarmCalls: Array<{ enableToken?: string }> = [];
  const forensicWrites: string[] = [];
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
    quarantineForensics: async (payload) => {
      forensicWrites.push(payload);
      if (opts.forensicsImpl !== undefined) return opts.forensicsImpl(payload);
      return "/var/db/sanctuary/egress-anchor-registry.json.quarantine-test.json";
    },
  };
  return { registry: new PfAnchorRegistry(ops), store, lock, armCalls, disarmCalls, forensicWrites };
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

  // ── gate-round fix-round tests ──────────────────────────────────────────

  it("list() reports dirty when a journaled pending set is present (crashed mid-mutation)", async () => {
    const { registry } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [A],
        enable_token: "1",
        pending: [A, B],
      },
    });
    const listed = await registry.list();
    expect(listed.dirty).toBe(true);
  });

  it("list() reports dirty when committed is non-empty but the enable token is missing", async () => {
    const { registry } = makeRegistry({
      // No enable_token despite a non-empty committed set: inconsistent -> dirty.
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A] },
    });
    const listed = await registry.list();
    expect(listed.dirty).toBe(true);
  });

  it("a journaled pending forces reconcile to re-assert committed before the next mutation", async () => {
    const { registry, armCalls } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [A],
        enable_token: "1",
        pending: [A, B], // a crashed prior mutation left this journal
      },
    });
    await registry.addOrUpdate(B);
    // reconcile re-asserts committed [A] (because pending was set), THEN the
    // mutation applies [A,B].
    expect(armCalls).toEqual([
      { uids: [502], existingEnableToken: "1" },
      { uids: [502, 504], existingEnableToken: "1" },
    ]);
  });

  it("reconcile on an empty-but-dirty registry ACTIVELY flushes before proceeding (gate finding)", async () => {
    const { registry, disarmCalls } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [], dirty: true },
    });
    await registry.addOrUpdate(A);
    // The empty+dirty reconcile flushed the anchor to a known-empty state
    // (disarm called) rather than just clearing the marker.
    expect(disarmCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("stays DIRTY when the empty-registry repair flush itself fails (gate finding)", async () => {
    const { registry, store } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [], dirty: true },
      disarmImpl: async () => {
        throw new Error("flush failed");
      },
    });
    await expect(registry.addOrUpdate(A)).rejects.toBeInstanceOf(PfAnchorRegistryDirtyError);
    expect(store.current?.dirty).toBe(true);
  });

  it("rollback of a failed remove-last re-arms with a FRESH -E, not the released token (gate finding)", async () => {
    // Store throws on the COMMIT save (2nd save: after pending journal), so the
    // remove-last forward path (flush + -X token) succeeds but the commit fails.
    let saveN = 0;
    let current: PfAnchorRegistryState | null = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [B],
      enable_token: "1",
    };
    const store: PfAnchorRegistryStore = {
      async load() {
        return current === null ? null : structuredClone(current);
      },
      async save(s) {
        saveN += 1;
        if (saveN === 2) throw new Error("commit save failed"); // the commit
        current = structuredClone(s);
      },
    };
    const armCalls: Array<{ uids: number[]; existingEnableToken?: string }> = [];
    const disarmCalls: Array<{ enableToken?: string }> = [];
    const reg = new PfAnchorRegistry({
      store,
      lock: memLock(),
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async (entries, options) => {
        armCalls.push({
          uids: entries.map((e) => e.agent_uid),
          ...(options.existingEnableToken !== undefined
            ? { existingEnableToken: options.existingEnableToken }
            : {}),
        });
        return okArm(options.existingEnableToken ?? "2"); // fresh -E yields token "2"
      },
      disarm: async (options) => {
        disarmCalls.push({ ...(options.enableToken !== undefined ? { enableToken: options.enableToken } : {}) });
      },
      unionLiveness: async () => live,
    });
    await expect(reg.remove(504)).rejects.toThrow(/commit save failed/);
    // Forward flush released token "1"; rollback re-armed [B] with a FRESH -E
    // (no existingEnableToken), never reusing the spent token.
    expect(disarmCalls).toEqual([{ enableToken: "1" }]);
    expect(armCalls).toEqual([{ uids: [504] }]); // fresh -E, no existing token
  });

  it("rollback of a failed add-to-empty RELEASES the freshly acquired -E token, no leak (gate re-review)", async () => {
    // Fresh empty registry. add A: applyUnion acquires -E token "1", then the
    // COMMIT save (2nd save) fails -> rollback to empty must FLUSH+release that
    // fresh token, never drop it (the re-review's new-hole finding).
    let saveN = 0;
    let current: PfAnchorRegistryState | null = null;
    const store: PfAnchorRegistryStore = {
      async load() {
        return current === null ? null : structuredClone(current);
      },
      async save(s) {
        saveN += 1;
        if (saveN === 2) throw new Error("commit save failed");
        current = structuredClone(s);
      },
    };
    const disarmCalls: Array<{ enableToken?: string }> = [];
    const reg = new PfAnchorRegistry({
      store,
      lock: memLock(),
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async (_entries, options) => okArm(options.existingEnableToken ?? "1"),
      disarm: async (options) => {
        disarmCalls.push({ ...(options.enableToken !== undefined ? { enableToken: options.enableToken } : {}) });
      },
      unionLiveness: async () => live,
    });
    await expect(reg.addOrUpdate(A)).rejects.toThrow(/commit save failed/);
    // The freshly acquired token "1" was released by the rollback flush (no leak).
    expect(disarmCalls).toEqual([{ enableToken: "1" }]);
    expect(current?.committed).toEqual([]);
    expect(current?.enable_token).toBeUndefined();
  });
});

describe("egress-gate/anchor-registry listQuarantined (fix-round-2 MED-6: per-entry quarantine for the refresh read)", () => {
  const GOOD_STATE = (committed: unknown[]): PfAnchorRegistryState =>
    ({ version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed, enable_token: "1" }) as PfAnchorRegistryState;

  it("one malformed committed entry is quarantined (index + reason) while the valid entries stay usable; dirty forced", async () => {
    const { registry } = makeRegistry({
      initial: GOOD_STATE([A, { agent_uid: "nope", gate_port: -1 }, B]),
    });
    const listed = await registry.listQuarantined();
    expect(listed.entries.map((e) => e.agent_uid)).toEqual([502, 504]);
    expect(listed.quarantined).toEqual([{ index: 1, reason: expect.stringContaining("malformed") }]);
    // Repair owed: never green over a quarantine.
    expect(listed.dirty).toBe(true);
    // The wholesale-fail-closed read STILL throws for mutation-path callers.
    await expect(registry.list()).rejects.toThrow(PfAnchorRegistryStateError);
  });

  it("a duplicate agent_uid quarantines the LATER occurrence and names the uid", async () => {
    const { registry } = makeRegistry({
      initial: GOOD_STATE([A, { ...A, gate_port: 30001 }]),
    });
    const listed = await registry.listQuarantined();
    expect(listed.entries).toHaveLength(1);
    expect(listed.quarantined).toEqual([{ index: 1, reason: expect.stringContaining("duplicate committed agent_uid 502") }]);
    expect(listed.dirty).toBe(true);
  });

  it("a clean state lists clean: no quarantine, dirty false, same entries as list()", async () => {
    const { registry } = makeRegistry({ initial: GOOD_STATE([A, B]) });
    const listed = await registry.listQuarantined();
    expect(listed.quarantined).toEqual([]);
    expect(listed.dirty).toBe(false);
    expect(listed.entries).toEqual((await registry.list()).entries);
  });

  it("STRUCTURAL corruption still throws wholesale (nothing trustworthy to salvage)", async () => {
    for (const initial of [
      { version: 999, committed: [A] },
      { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: "not-an-array" },
    ]) {
      const { registry } = makeRegistry({ initial: initial as never });
      await expect(registry.listQuarantined()).rejects.toThrow(PfAnchorRegistryStateError);
    }
  });

  it("dirty semantics preserved: journaled pending, explicit dirty, and a missing enable token each force dirty", async () => {
    const pending = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [A],
      enable_token: "1",
      pending: [B],
    } as PfAnchorRegistryState;
    expect((await makeRegistry({ initial: pending }).registry.listQuarantined()).dirty).toBe(true);
    const explicit = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [A],
      enable_token: "1",
      dirty: true,
    } as PfAnchorRegistryState;
    expect((await makeRegistry({ initial: explicit }).registry.listQuarantined()).dirty).toBe(true);
    const noToken = { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A] } as PfAnchorRegistryState;
    expect((await makeRegistry({ initial: noToken }).registry.listQuarantined()).dirty).toBe(true);
  });
});

describe("egress-gate/anchor-registry repairQuarantined (fix-round-4 P2: coded recovery for a quarantined committed entry)", () => {
  const MALFORMED_NO_UID = { bogus: true, fortress_path: "/f/x" };
  const MALFORMED_SALVAGEABLE = {
    agent_uid: 601,
    gate_port: 20002,
    fortress_path: "/f/c",
    generation_id: 0, // invalid: committed generations start at 1
  };

  function quarantinedState(malformed: unknown): PfAnchorRegistryState {
    return {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [A, malformed as never],
      enable_token: "1",
    };
  }

  it("repairs over a malformed sibling: forensic payload FIRST, union re-armed from the valid entry, registry CLEAN (tokens resume), mutations work again", async () => {
    const { registry, store, armCalls, forensicWrites } = makeRegistry({
      initial: quarantinedState(MALFORMED_NO_UID),
    });
    // Pre-fix: every mutation (and any repair built on mutations) entered
    // normalizeState and THREW "a committed entry is malformed" -- the
    // documented repair verb could never rewrite anything.
    await expect(registry.addOrUpdate(B)).rejects.toThrow(PfAnchorRegistryStateError);

    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.findings).toEqual([
      {
        index: 1,
        reason: "malformed committed entry (failed the fail-closed entry validation)",
        agent_uid: null, // no recoverable uid on the raw entry
        disposition: "removed",
      },
    ]);
    expect(res.forensicPath).toBe("/var/db/sanctuary/egress-anchor-registry.json.quarantine-test.json");
    expect(res.remaining.map((e) => e.agent_uid)).toEqual([502]);
    // The raw entry's content was captured for forensics before removal.
    expect(forensicWrites).toHaveLength(1);
    expect(forensicWrites[0]).toContain('"bogus": true');
    expect(forensicWrites[0]).toContain("re-provisioned");
    // The union was re-rendered from the remaining valid entry only.
    expect(armCalls.at(-1)?.uids).toEqual([502]);
    // Persisted CLEAN: the round-3 dirty-registry machinery (posture red,
    // freshness tokens withheld host-wide) stands down -- the valid
    // sibling's tokens resume on the next oracle tick.
    expect(store.current?.committed).toEqual([A]);
    expect(store.current?.dirty).toBeUndefined();
    expect(store.current?.pending).toBeUndefined();
    expect(await registry.list()).toEqual({ entries: [A], dirty: false });
    // And ordinary mutations enter normalizeState cleanly again.
    const after = await registry.addOrUpdate(B);
    expect(after.committed.map((e) => e.agent_uid).sort()).toEqual([502, 504]);
  });

  it("a salvageable malformed entry (garbled generation_id, valid uid/port/fortress) is TOMBSTONED block-only, never dropped", async () => {
    const { registry, store, armCalls } = makeRegistry({
      initial: quarantinedState(MALFORMED_SALVAGEABLE),
    });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.findings).toEqual([
      {
        index: 1,
        reason: "malformed committed entry (failed the fail-closed entry validation)",
        agent_uid: 601,
        disposition: "tombstoned",
      },
    ]);
    // The uid STAYS in the union as a block-only tombstone: dropping it would
    // drop its live block rules from the anchor (fail-open direction).
    const kept = res.remaining.find((e) => e.agent_uid === 601);
    expect(kept).toEqual({
      agent_uid: 601,
      gate_port: 20002,
      fortress_path: "/f/c",
      tombstone: true,
    });
    expect(armCalls.at(-1)?.uids.sort()).toEqual([502, 601]);
    expect(store.current?.committed).toHaveLength(2);
    expect((await registry.list()).dirty).toBe(false);
  });

  it("a salvaged tombstone CARRIES a still-valid generation_id (garbled tombstone flag case): monotonicity preserved", async () => {
    const { registry } = makeRegistry({
      initial: quarantinedState({
        agent_uid: 601,
        gate_port: 20002,
        fortress_path: "/f/c",
        generation_id: 9, // valid; the entry is malformed for the tombstone flag
        tombstone: "yes",
      }),
    });
    const res = await registry.repairQuarantined();
    expect(res.findings[0]?.disposition).toBe("tombstoned");
    // The live generation id survives the recovery, so the next bring-up
    // cannot reuse an already-committed id for this uid.
    expect(res.remaining.find((e) => e.agent_uid === 601)).toEqual({
      agent_uid: 601,
      gate_port: 20002,
      fortress_path: "/f/c",
      generation_id: 9,
      tombstone: true,
    });
  });

  it("a duplicate committed uid is REMOVED (the first valid entry keeps the uid confined; no tombstone shadowing) and reported LOUDLY as a valid duplicate", async () => {
    const dup = { ...A, gate_port: 20009 };
    const { registry } = makeRegistry({ initial: quarantinedState(dup) });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.findings).toEqual([
      {
        index: 1,
        reason: "duplicate committed agent_uid 502",
        agent_uid: 502,
        disposition: "removed",
        // Fix-round-5 P1: a removed structurally VALID duplicate names both
        // generations (null here: neither entry carries one).
        duplicate: { kept_generation_id: null, removed_generation_id: null },
      },
    ]);
    expect(res.remaining).toEqual([A]);
  });

  it("transiently-invalid state (missing enable token) is NEVER grounds to drop an entry: read-only no-op", async () => {
    const { registry, store, armCalls, forensicWrites } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [A, B] }, // no enable_token -> dirty
    });
    const res = await registry.repairQuarantined();
    expect(res).toEqual({ repaired: false, findings: [], forensicPath: null, remaining: [A, B] });
    // Nothing written, nothing armed, nothing removed; the normal mutation
    // reconcile owns this dirt without discarding confinement state.
    expect(forensicWrites).toHaveLength(0);
    expect(armCalls).toHaveLength(0);
    expect(store.saves).toHaveLength(0);
    expect((await registry.list()).entries).toEqual([A, B]);
  });

  it("a forensic-write failure ABORTS with the registry untouched (an entry is never dropped without its bytes preserved)", async () => {
    const { registry, store, armCalls } = makeRegistry({
      initial: quarantinedState(MALFORMED_NO_UID),
      forensicsImpl: async () => {
        throw new Error("forensic sink full");
      },
    });
    await expect(registry.repairQuarantined()).rejects.toThrow("forensic sink full");
    expect(armCalls).toHaveLength(0);
    expect(store.saves).toHaveLength(0);
    expect((store.current?.committed as unknown[])[1]).toEqual(MALFORMED_NO_UID);
  });

  it("a re-arm failure leaves the on-disk registry untouched (still quarantined + dirty, posture red) and throws", async () => {
    const { registry, store } = makeRegistry({
      initial: quarantinedState(MALFORMED_NO_UID),
      armImpl: async () => {
        throw new Error("pfctl exploded");
      },
    });
    await expect(registry.repairQuarantined()).rejects.toThrow("pfctl exploded");
    expect(store.saves).toHaveLength(0);
    expect((store.current?.committed as unknown[])[1]).toEqual(MALFORMED_NO_UID);
    expect((await registry.listQuarantined()).dirty).toBe(true);
  });

  it("STRUCTURAL corruption still throws wholesale (nothing salvageable from an unknown shape)", async () => {
    const { registry } = makeRegistry({
      initial: { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: "nope" as never },
    });
    await expect(registry.repairQuarantined()).rejects.toThrow(PfAnchorRegistryStateError);
  });

  it("all entries quarantined: the anchor is flushed to a known-empty state and the enable token released", async () => {
    const { registry, store, disarmCalls } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [MALFORMED_NO_UID as never],
        enable_token: "1",
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.remaining).toEqual([]);
    expect(disarmCalls).toEqual([{ enableToken: "1" }]);
    expect(store.current?.enable_token).toBeUndefined();
    expect(await registry.list()).toEqual({ entries: [], dirty: false });
  });
});

describe("egress-gate/anchor-registry fix-round-5 (P1 generation floor on removal + P3 byte-exact forensics)", () => {
  const KEPT7: PfAnchorRegistryEntry = {
    agent_uid: 502,
    gate_port: 19998,
    fortress_path: "/f/a",
    generation_id: 7,
  };
  const DUP8 = { agent_uid: 502, gate_port: 20009, fortress_path: "/f/a", generation_id: 8 };

  /** Two structurally VALID committed entries for one uid: gen 7 kept, gen 8 quarantined as duplicate. */
  function gen78State(): PfAnchorRegistryState {
    return {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [KEPT7, DUP8 as never],
      enable_token: "1",
    };
  }

  it("P1: removing the VALID gen-8 duplicate of a kept gen-7 uid is LOUD (uid + both generations in the report) and folds gen 8 into the persisted floor", async () => {
    const { registry, store } = makeRegistry({ initial: gen78State() });
    const res = await registry.repairQuarantined();
    expect(res.findings).toEqual([
      {
        index: 1,
        reason: "duplicate committed agent_uid 502",
        agent_uid: 502,
        disposition: "removed",
        duplicate: { kept_generation_id: 7, removed_generation_id: 8 },
      },
    ]);
    expect(res.remaining).toEqual([KEPT7]);
    // Pre-fix the removed gen 8 survived NOWHERE: the next bring-up recomputed
    // from the kept gen 7 and reallocated 8. The persisted floor closes that.
    expect(store.current?.generation_floor).toBe(8);
    expect((await registry.list()).generationFloor).toBe(8);
  });

  it("P1: after the gen7-kept/gen8-duplicate repair, a REAL bring-up through the registry adapter allocates generation 9 (never reuses the discarded 8)", async () => {
    const { registry } = makeRegistry({ initial: gen78State() });
    await registry.repairQuarantined();
    // Wire the repaired registry into the generation machine exactly like the
    // production adapter (arming-wiring): readEntry + readGenerationFloor both
    // come from registry.list().
    const staging = new Map<number, GenerationStagingRecord>();
    const coord = new GenerationCoordinator({
      bind: async () => ({
        port: 45001,
        pid: 9001,
        pidStart: "start-9001",
        release: async () => {},
      }),
      verifyOwner: async () => true,
      registry: {
        armEntry: async (entry) => {
          await registry.addOrUpdate(entry);
        },
        tombstone: async (uid, fallback) => {
          await registry.tombstone(uid, fallback);
        },
        readEntry: async (uid) =>
          (await registry.list()).entries.find((e) => e.agent_uid === uid) ?? null,
        readGenerationFloor: async () => (await registry.list()).generationFloor,
      },
      publishManifest: async () => {},
      staging: {
        load: async (uid) => staging.get(uid) ?? null,
        save: async (record) => {
          staging.set(record.agent_uid, record);
        },
        delete: async (uid) => {
          staging.delete(uid);
        },
      },
      lock: memLock(),
    });
    const committed = await coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" });
    // Pre-fix: computeNextGenerationId(7, undefined) allocated 8 -- the very
    // id the repair just discarded. The floor forces strictly above it.
    expect(committed.generation_id).toBe(9);
  });

  it("P1: a REMOVED malformed entry (nothing salvageable) still folds its parseable generation_id into the floor", async () => {
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        // gate_port is garbage, so the tombstone salvage fails and the entry
        // is removed outright -- but its generation_id 12 parsed fine and must
        // not become reallocatable.
        committed: [
          A,
          { agent_uid: 601, gate_port: "not-a-port", fortress_path: "/f/c", generation_id: 12 } as never,
        ],
        enable_token: "1",
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.findings[0]?.disposition).toBe("removed");
    // Not a structurally valid duplicate, so no duplicate detail -- just the floor.
    expect(res.findings[0]?.duplicate).toBeUndefined();
    expect(store.current?.generation_floor).toBe(12);
  });

  it("P1: the floor is MONOTONE (a smaller removed generation never lowers it) and survives later ordinary mutations", async () => {
    const { registry, store } = makeRegistry({
      initial: { ...gen78State(), generation_floor: 20 },
    });
    await registry.repairQuarantined();
    expect(store.current?.generation_floor).toBe(20); // 8 < 20: not lowered
    await registry.addOrUpdate(B);
    expect(store.current?.generation_floor).toBe(20); // normalizeState carries it
    expect((await registry.list()).generationFloor).toBe(20);
  });

  it("P1: a present-but-malformed generation_floor is a repair signal (dirty), never silently coerced", async () => {
    const { registry } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [A],
        enable_token: "1",
        generation_floor: -2 as never,
      },
    });
    expect((await registry.list()).dirty).toBe(true);
  });

  it("P3: the forensic sidecar is the BYTE-EXACT pre-repair file when the store exposes raw bytes (odd formatting + duplicate JSON keys preserved)", async () => {
    const odd =
      '{\n  "version": 1,\n\t"committed": [ {"agent_uid":502,"gate_port":19998,"fortress_path":"/f/a"} ,\n    {"bogus":true,"bogus":true} ],\n  "enable_token": "1"\n}\n';
    // A raw-capable store: load() parses the odd bytes; loadRaw() returns them verbatim.
    let current = odd;
    const store: PfAnchorRegistryStore = {
      load: async () => JSON.parse(current) as PfAnchorRegistryState,
      loadRaw: async () => current,
      save: async (state) => {
        current = JSON.stringify(state);
      },
    };
    const forensicWrites: string[] = [];
    const registry = new PfAnchorRegistry({
      store,
      lock: memLock(),
      runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
      armUnion: async () => ({ settleProbes: 1, enableToken: "1" }),
      disarm: async () => {},
      unionLiveness: async () => live,
      quarantineForensics: async (payload) => {
        forensicWrites.push(payload);
        return "/var/db/sanctuary/egress-anchor-registry.json.quarantine-test.json";
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    // Pre-fix the sidecar was JSON.stringify of PARSED objects: the duplicate
    // JSON key and the formatting were already lost at load's JSON.parse.
    expect(forensicWrites).toEqual([odd]);
  });

  it("P3: FS store + FS forensics writer end-to-end: the on-disk sidecar's bytes equal the pre-repair registry file's bytes", async () => {
    const { mkdtemp, readFile, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-anchor-forensics-"));
    try {
      const path = join(dir, "egress-anchor-registry.json");
      const odd =
        '{"version":1,"committed":[{"agent_uid":502,"gate_port":19998,"fortress_path":"/f/a"},' +
        '{"bogus":  true,\t"bogus":false}],"enable_token":"1"}';
      await writeFile(path, odd);
      const preRepair = await readFile(path);
      const registry = new PfAnchorRegistry({
        store: createFsRegistryStore(path),
        lock: memLock(),
        runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
        armUnion: async () => ({ settleProbes: 1, enableToken: "1" }),
        disarm: async () => {},
        unionLiveness: async () => live,
        quarantineForensics: createFsQuarantineForensicsWriter(path),
      });
      const res = await registry.repairQuarantined();
      expect(res.repaired).toBe(true);
      expect(res.forensicPath).not.toBeNull();
      const sidecar = await readFile(res.forensicPath as string);
      expect(sidecar.equals(preRepair)).toBe(true);
      expect(sidecar.toString("utf8")).toBe(odd);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("egress-gate/anchor-registry fix-round-6 (F1 malformed generation_floor preserved + repaired; F2 quarantine visibility)", () => {
  const KEPT7: PfAnchorRegistryEntry = {
    agent_uid: 502,
    gate_port: 19998,
    fortress_path: "/f/a",
    generation_id: 7,
  };
  const TOMB9: PfAnchorRegistryEntry = {
    agent_uid: 601,
    gate_port: 20002,
    fortress_path: "/f/c",
    generation_id: 9,
    tombstone: true,
  };

  /** One valid committed entry at gen 7, with a MALFORMED (string) floor "8". */
  function malformedFloorState(floor: unknown = "8"): PfAnchorRegistryState {
    return {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [KEPT7],
      enable_token: "1",
      generation_floor: floor as never,
    };
  }

  it("F1: a malformed (string) floor is dirty AND its parseable value is folded into the effective floor -- never invisible to the allocator read", async () => {
    const { registry } = makeRegistry({ initial: malformedFloorState("8") });
    const listed = await registry.list();
    expect(listed.dirty).toBe(true);
    // Pre-fix the malformed floor was DROPPED (generationFloor undefined), so
    // readGenerationFloor returned undefined and bring-up could allocate 8.
    expect(listed.generationFloor).toBe(8);
  });

  it("F1: the raw floor SURVIVES ordinary mutations and dirty stays STICKY -- a successful mutation must never launder the floor away", async () => {
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [A],
        enable_token: "1",
        generation_floor: "8" as never,
      },
    });
    const res = await registry.addOrUpdate(B);
    // Pre-fix: the mutation's commit save cleared dirty and persisted a state
    // WITHOUT the floor (raw dropped at normalizeState) -- monotonicity
    // fail-open. The result also hardcoded dirty: false.
    expect(res.dirty).toBe(true);
    expect(store.current?.dirty).toBe(true);
    expect(store.current?.generation_floor_raw).toBe("8");
    expect(store.current?.generation_floor).toBe(8);
    // A second mutation still carries it (nothing but repair may consume it).
    await registry.remove(B.agent_uid);
    expect(store.current?.dirty).toBe(true);
    expect(store.current?.generation_floor_raw).toBe("8");
    expect(store.current?.generation_floor).toBe(8);
  });

  it("F1: a REAL bring-up through the production-shaped adapter allocates ABOVE the parseable raw floor while dirty (never at-or-below)", async () => {
    const { registry } = makeRegistry({ initial: malformedFloorState("8") });
    const staging = new Map<number, GenerationStagingRecord>();
    const coord = new GenerationCoordinator({
      bind: async () => ({
        port: 45001,
        pid: 9001,
        pidStart: "start-9001",
        release: async () => {},
      }),
      verifyOwner: async () => true,
      registry: {
        armEntry: async (entry) => {
          await registry.addOrUpdate(entry);
        },
        tombstone: async (uid, fallback) => {
          await registry.tombstone(uid, fallback);
        },
        readEntry: async (uid) =>
          (await registry.list()).entries.find((e) => e.agent_uid === uid) ?? null,
        readGenerationFloor: async () => (await registry.list()).generationFloor,
      },
      publishManifest: async () => {},
      staging: {
        load: async (uid) => staging.get(uid) ?? null,
        save: async (record) => {
          staging.set(record.agent_uid, record);
        },
        delete: async (uid) => {
          staging.delete(uid);
        },
      },
      lock: memLock(),
    });
    const committed = await coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" });
    // Pre-fix: the dropped floor made computeNextGenerationId(7, undefined,
    // undefined) allocate 8 -- exactly the id the floor "8" says is spent.
    // (The dirty registry separately withholds RELEASE; this pins that the
    // ALLOCATOR also respects the parseable raw floor.)
    expect(committed.generation_id).toBe(9);
  });

  it("F2: listQuarantined reports a malformed floor as a distinct registry-LEVEL finding (index -1) and FORCES dirty", async () => {
    const { registry } = makeRegistry({ initial: malformedFloorState("8") });
    const listed = await registry.listQuarantined();
    // Pre-fix: dirty false + quarantined [] -- the boot refresh path read
    // green over the malformed floor.
    expect(listed.dirty).toBe(true);
    expect(listed.entries).toEqual([KEPT7]);
    expect(listed.quarantined).toEqual([
      { index: -1, reason: expect.stringContaining("generation_floor is malformed") },
    ]);
  });

  it("F1: repairQuarantined RESOLVES a parseable raw floor -- forensics first, floor persisted, raw consumed, dirty un-stuck", async () => {
    const { registry, store, forensicWrites } = makeRegistry({
      initial: malformedFloorState("8"),
    });
    const res = await registry.repairQuarantined();
    // Pre-fix: no quarantined ENTRY meant "nothing to repair" (repaired:
    // false) while the sticky dirty could never clear -- an unrepairable red.
    expect(res.repaired).toBe(true);
    expect(res.findings).toEqual([]); // no committed entry was touched
    expect(res.remaining).toEqual([KEPT7]);
    expect(res.floorRepair).toEqual({
      raw: "8",
      parsed: 8,
      resolved_floor: 8,
      unrecoverable: false,
    });
    expect(forensicWrites).toHaveLength(1); // bytes preserved BEFORE the rewrite
    expect(store.current?.generation_floor).toBe(8);
    expect(store.current?.generation_floor_raw).toBeUndefined();
    const after = await registry.list();
    expect(after.dirty).toBe(false);
    expect(after.generationFloor).toBe(8);
  });

  it("F1: an UNPARSEABLE raw floor is reset to the max observable generation across entries + tombstones (no invented margin) and flagged unrecoverable", async () => {
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [KEPT7, TOMB9],
        enable_token: "1",
        generation_floor: { bogus: true } as never,
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.floorRepair).toEqual({
      raw: { bogus: true },
      parsed: null,
      resolved_floor: 9, // max(gen 7 entry, gen 9 tombstone) + 0
      unrecoverable: true,
    });
    expect(store.current?.generation_floor).toBe(9);
    expect(store.current?.generation_floor_raw).toBeUndefined();
    expect((await registry.list()).dirty).toBe(false);
  });

  it("F1: an unparseable raw floor with NO observable generation anywhere persists no floor at all (resolved_floor null, still loud)", async () => {
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [A], // no generation_id anywhere
        enable_token: "1",
        generation_floor: true as never,
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.floorRepair).toEqual({
      raw: true,
      parsed: null,
      resolved_floor: null,
      unrecoverable: true,
    });
    expect(store.current?.generation_floor).toBeUndefined();
    expect(store.current?.generation_floor_raw).toBeUndefined();
    expect((await registry.list()).dirty).toBe(false);
  });

  it("F1: a floor repair COMPOSES with an entry repair -- the parseable raw folds monotonically with a removed duplicate's generation", async () => {
    const DUP8 = { agent_uid: 502, gate_port: 20009, fortress_path: "/f/a", generation_id: 8 };
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [KEPT7, DUP8 as never],
        enable_token: "1",
        generation_floor: "20" as never,
      },
    });
    const res = await registry.repairQuarantined();
    expect(res.findings).toHaveLength(1); // the removed gen-8 duplicate
    expect(res.floorRepair).toEqual({
      raw: "20",
      parsed: 20,
      resolved_floor: 20, // max(removed 8, parsed 20): monotone fold
      unrecoverable: false,
    });
    expect(store.current?.generation_floor).toBe(20);
    expect((await registry.list()).dirty).toBe(false);
  });
});

describe("egress-gate/anchor-registry fix-round-7 (unsafe-integer generation floor has no allocation headroom)", () => {
  const KEPT7: PfAnchorRegistryEntry = {
    agent_uid: 502,
    gate_port: 19998,
    fortress_path: "/f/a",
    generation_id: 7,
  };

  it("an unsafe-integer RAW floor is UNRECOVERABLE (never folded, never persisted): floor+1 would allocate the same id forever", async () => {
    const { registry, store } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [KEPT7],
        enable_token: "1",
        generation_floor: "9007199254740993" as never,
      },
    });
    const listed = await registry.list();
    expect(listed.dirty).toBe(true);
    // Pre-fix: Number("9007199254740993") rounded to 2^53 and was folded as a
    // "parseable" floor, so the allocator would return the SAME unsafe id
    // forever (floor+1 === floor at that magnitude).
    expect(listed.generationFloor).toBeUndefined();
    const res = await registry.repairQuarantined();
    expect(res.repaired).toBe(true);
    expect(res.floorRepair).toEqual({
      raw: "9007199254740993",
      parsed: null,
      resolved_floor: 7,
      unrecoverable: true,
    });
    expect(store.current?.generation_floor).toBe(7);
    expect(store.current?.generation_floor_raw).toBeUndefined();
  });

  it("a well-formed but unsafe-integer NUMBER floor is malformed evidence (dirty), not a valid floor", async () => {
    const { registry } = makeRegistry({
      initial: {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: [KEPT7],
        enable_token: "1",
        generation_floor: 9007199254740992 as never,
      },
    });
    const listed = await registry.list();
    // Pre-fix: Number.isInteger(2^53) is true, so this read as a VALID floor
    // and flowed straight into allocation with no headroom.
    expect(listed.dirty).toBe(true);
    expect(listed.generationFloor).toBeUndefined();
  });
});
