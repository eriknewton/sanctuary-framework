/**
 * Tests for the S5-2 ADDITIVE registry surface: the optional `generation_id`
 * field (version-compatible with v1 on-disk state) and the block-only
 * `tombstone()` mutation. Host-state-free (store/lock/pf all injected).
 */

import { describe, it, expect } from "vitest";

import {
  PfAnchorRegistry,
  PfAnchorRegistryStateError,
  PF_ANCHOR_REGISTRY_STATE_VERSION,
  type PfAnchorRegistryEntry,
  type PfAnchorRegistryOps,
  type PfAnchorRegistryState,
  type PfAnchorRegistryStore,
} from "../../src/egress-gate/anchor-registry.js";
import type { ArmPfAnchorResult, PfAnchorUnionEntry, PfLivenessResult } from "../../src/egress-gate/pf-anchor.js";
import type { ProvisionLockOps } from "../../src/castle-wall/provision/lockfile.js";

function memStore(initial: PfAnchorRegistryState | null = null): PfAnchorRegistryStore & {
  current: PfAnchorRegistryState | null;
} {
  let current = initial;
  return {
    get current() {
      return current;
    },
    async load() {
      return current === null ? null : structuredClone(current);
    },
    async save(state) {
      current = structuredClone(state);
    },
  };
}

function memLock(): ProvisionLockOps {
  let held = false;
  return {
    async acquire() {
      if (held) {
        const err = new Error("EEXIST") as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      held = true;
    },
    async release() {
      held = false;
    },
  };
}

const live: PfLivenessResult = { live: true, reasons: [] };

function makeRegistry(initial: PfAnchorRegistryState | null = null) {
  const store = memStore(initial);
  const armCalls: PfAnchorUnionEntry[][] = [];
  const ops: PfAnchorRegistryOps = {
    store,
    lock: memLock(),
    runner: { async run() { return { code: 0, stdout: "", stderr: "" }; } },
    armUnion: async (entries, options): Promise<ArmPfAnchorResult> => {
      armCalls.push(entries.map((e) => ({ ...e })));
      return options.existingEnableToken !== undefined
        ? { settleProbes: 1, enableToken: options.existingEnableToken }
        : { settleProbes: 1, enableToken: "1" };
    },
    disarm: async () => {},
    unionLiveness: async () => live,
  };
  return { registry: new PfAnchorRegistry(ops), store, armCalls };
}

describe("egress-gate/anchor-registry generation_id (S5-2 additive)", () => {
  it("loads v1 on-disk state that predates generation_id (no field) unchanged", async () => {
    // A legacy entry with NO generation_id / tombstone -- the v1 shape.
    const legacy: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [{ agent_uid: 502, gate_port: 19998, fortress_path: "/f/a" }],
      enable_token: "1",
    };
    const { registry } = makeRegistry(legacy);
    const listed = await registry.list();
    expect(listed.entries).toHaveLength(1);
    expect(listed.entries[0]?.generation_id).toBeUndefined();
    expect(listed.dirty).toBe(false);
  });

  it("persists generation_id on addOrUpdate and reads it back", async () => {
    const { registry, store } = makeRegistry();
    await registry.addOrUpdate({ agent_uid: 502, gate_port: 19998, fortress_path: "/f/a", generation_id: 7 });
    expect(store.current?.committed[0]?.generation_id).toBe(7);
  });

  it("rejects a present-but-malformed generation_id (fail-closed load)", async () => {
    const bad: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [{ agent_uid: 502, gate_port: 19998, fortress_path: "/f/a", generation_id: -3 } as PfAnchorRegistryEntry],
      enable_token: "1",
    };
    const { registry } = makeRegistry(bad);
    await expect(registry.list()).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
  });
});

describe("egress-gate/anchor-registry tombstone (S5-2 M4)", () => {
  it("tombstones an existing uid: keeps the entry, arms it block-only, no flush", async () => {
    const initial: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [{ agent_uid: 502, gate_port: 19998, fortress_path: "/f/a", generation_id: 3 }],
      enable_token: "1",
    };
    const { registry, store, armCalls } = makeRegistry(initial);
    const res = await registry.tombstone(502);
    expect(res.committed).toHaveLength(1);
    expect(store.current?.committed[0]?.tombstone).toBe(true);
    // The generation_id is retained (monotonicity for the next generation).
    expect(store.current?.committed[0]?.generation_id).toBe(3);
    // The arm carried the uid as a tombstone member.
    const lastArm = armCalls.at(-1);
    expect(lastArm).toEqual([{ agent_uid: 502, gate_port: 19998, tombstone: true }]);
  });

  it("tombstoning an absent uid ADDS a block-only entry from the fallback (fail-closed)", async () => {
    const { registry, store, armCalls } = makeRegistry();
    const res = await registry.tombstone(777, { gate_port: 30000, fortress_path: "/f/x" });
    expect(res.committed).toHaveLength(1);
    expect(store.current?.committed[0]).toMatchObject({ agent_uid: 777, gate_port: 30000, tombstone: true });
    expect(armCalls.at(-1)).toEqual([{ agent_uid: 777, gate_port: 30000, tombstone: true }]);
  });

  it("refuses to tombstone an absent uid with NO fallback (no port to validate)", async () => {
    const { registry } = makeRegistry();
    await expect(registry.tombstone(777)).rejects.toBeInstanceOf(PfAnchorRegistryStateError);
  });

  it("tombstoning one of two uids leaves the other LIVE (keeps its pass)", async () => {
    const initial: PfAnchorRegistryState = {
      version: PF_ANCHOR_REGISTRY_STATE_VERSION,
      committed: [
        { agent_uid: 502, gate_port: 19998, fortress_path: "/f/a", generation_id: 1 },
        { agent_uid: 504, gate_port: 20001, fortress_path: "/f/b", generation_id: 1 },
      ],
      enable_token: "1",
    };
    const { registry, armCalls } = makeRegistry(initial);
    await registry.tombstone(502);
    const lastArm = armCalls.at(-1) ?? [];
    const a = lastArm.find((e) => e.agent_uid === 502);
    const b = lastArm.find((e) => e.agent_uid === 504);
    expect(a?.tombstone).toBe(true);
    expect(b?.tombstone).toBeUndefined(); // uid 504 stays LIVE (pass rendered)
  });
});
