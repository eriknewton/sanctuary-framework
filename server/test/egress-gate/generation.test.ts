/**
 * Tests for the gate-port generation state machine + bind-first helper
 * (Unified Protect Slice 5 S5-2, folds Codex M6 + M4). Every side effect
 * (bind, owner-check, registry, manifest-publish, staging store) is injected,
 * so the whole G1-G5 machine and every crash-recovery branch runs host-free.
 */

import { describe, it, expect } from "vitest";

import {
  GenerationCoordinator,
  GenerationStateError,
  bindEphemeralGatePort,
  computeNextGenerationId,
  evaluateGenerationMatch,
  resolveCommittedGeneration,
  resolveGateRestart,
  type CommittedGeneration,
  type GateBinding,
  type GenerationOps,
  type GenerationRegistryOps,
  type GenerationStagingRecord,
  type GenerationStagingStore,
} from "../../src/egress-gate/generation.js";
import type { ProvisionLockOps } from "../../src/castle-wall/provision/lockfile.js";

/** In-memory O_EXCL lock (fail-loud on double-acquire), records contention. */
function memLock(): ProvisionLockOps & { held: boolean } {
  const box = {
    held: false,
    async acquire() {
      if (box.held) {
        const err = new Error("EEXIST") as NodeJS.ErrnoException;
        err.code = "EEXIST";
        throw err;
      }
      box.held = true;
    },
    async release() {
      box.held = false;
    },
  };
  return box;
}

/** In-memory staging store (one record per uid). */
function memStaging(): GenerationStagingStore & { records: Map<number, GenerationStagingRecord> } {
  const records = new Map<number, GenerationStagingRecord>();
  return {
    records,
    async load(uid) {
      return records.has(uid) ? structuredClone(records.get(uid)!) : null;
    },
    async save(record) {
      records.set(record.agent_uid, structuredClone(record));
    },
    async delete(uid) {
      records.delete(uid);
    },
  };
}

/** In-memory registry ops that record calls + hold committed entries. */
function memRegistry(
  initial: Array<{ agent_uid: number; gate_port: number; generation_id?: number; tombstone?: boolean }> = [],
) {
  const entries = new Map<number, { agent_uid: number; gate_port: number; generation_id?: number; tombstone?: boolean }>();
  for (const e of initial) entries.set(e.agent_uid, { ...e });
  const armCalls: Array<{ agent_uid: number; gate_port: number; generation_id: number }> = [];
  const tombstoneCalls: Array<{ uid: number; fallback?: { gate_port: number; fortress_path: string; generation_id?: number } }> = [];
  const ops: GenerationRegistryOps = {
    async armEntry(entry) {
      armCalls.push({ ...entry });
      entries.set(entry.agent_uid, { agent_uid: entry.agent_uid, gate_port: entry.gate_port, generation_id: entry.generation_id });
    },
    async tombstone(uid, fallback) {
      tombstoneCalls.push({ uid, ...(fallback !== undefined ? { fallback } : {}) });
      const existing = entries.get(uid);
      if (existing !== undefined) entries.set(uid, { ...existing, tombstone: true });
      else if (fallback !== undefined) entries.set(uid, { agent_uid: uid, gate_port: fallback.gate_port, generation_id: fallback.generation_id, tombstone: true });
    },
    async readEntry(uid) {
      return entries.has(uid) ? { ...entries.get(uid)! } : null;
    },
  };
  return { ops, entries, armCalls, tombstoneCalls };
}

interface Harness {
  coord: GenerationCoordinator;
  staging: ReturnType<typeof memStaging>;
  reg: ReturnType<typeof memRegistry>;
  events: string[];
  manifestPublished: Array<{ agent_uid: number; gate_port: number; generation_id: number }>;
  lock: ReturnType<typeof memLock>;
}

function makeHarness(opts: {
  registryInitial?: Array<{ agent_uid: number; gate_port: number; generation_id?: number }>;
  bindPort?: number;
  ownerHolds?: boolean;
  failAt?: "bind" | "owner" | "arm" | "manifest";
  tombstoneThrows?: boolean;
} = {}): Harness {
  const staging = memStaging();
  const reg = memRegistry(opts.registryInitial ?? []);
  const events: string[] = [];
  const manifestPublished: Array<{ agent_uid: number; gate_port: number; generation_id: number }> = [];
  const bindPort = opts.bindPort ?? 45001;
  const lock = memLock();

  const ops: GenerationOps = {
    async bind() {
      events.push("bind");
      if (opts.failAt === "bind") throw new Error("bind failed");
      const binding: GateBinding = {
        port: bindPort,
        pid: 9001,
        pidStart: "start-9001",
        async release() {
          events.push("release");
        },
      };
      return binding;
    },
    async verifyOwner() {
      if (opts.failAt === "owner") return false;
      return opts.ownerHolds ?? true;
    },
    registry: {
      async armEntry(entry) {
        if (opts.failAt === "arm") throw new Error("arm failed");
        await reg.ops.armEntry(entry);
        events.push("arm");
      },
      async tombstone(uid, fallback) {
        events.push("tombstone");
        if (opts.tombstoneThrows === true) throw new Error("tombstone failed");
        await reg.ops.tombstone(uid, fallback);
      },
      readEntry: reg.ops.readEntry,
    },
    async publishManifest(gen) {
      if (opts.failAt === "manifest") throw new Error("manifest failed");
      manifestPublished.push({ ...gen });
      events.push("manifest");
    },
    staging,
    lock,
  };
  return { coord: new GenerationCoordinator(ops), staging, reg, events, manifestPublished, lock };
}

describe("egress-gate/generation bringUp (G1-G5 happy path)", () => {
  it("runs G1-G5 to a committed generation and deletes the staging record", async () => {
    const h = makeHarness();
    const committed = await h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" });
    const expected: CommittedGeneration = {
      generation_id: 1,
      agent_uid: 502,
      gate_port: 45001,
      gate_pid: 9001,
      gate_pid_start: "start-9001",
      fortress_path: "/f/a",
    };
    expect(committed).toEqual(expected);
    // Staging record removed at G5 (committed).
    expect(h.staging.records.has(502)).toBe(false);
    // G3 armed the uid at the staged port + generation.
    expect(h.reg.armCalls).toEqual([{ agent_uid: 502, gate_port: 45001, fortress_path: "/f/a", generation_id: 1 }]);
    // G4 published the generation-bearing gate policy.
    expect(h.manifestPublished).toEqual([{ agent_uid: 502, gate_port: 45001, generation_id: 1 }]);
    // The gate port is NOT released on the committed path.
    expect(h.events).not.toContain("release");
  });

  it("assigns a monotonic generation id above the prior committed one", async () => {
    const h = makeHarness({ registryInitial: [{ agent_uid: 502, gate_port: 111, generation_id: 8 }] });
    const committed = await h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" });
    expect(committed.generation_id).toBe(9);
  });

  it("refuses to start when a staging record already exists (recover first)", async () => {
    const h = makeHarness();
    await h.staging.save({
      generation_id: 4, agent_uid: 502, gate_port: 1, gate_pid: 1, gate_pid_start: "s", fortress_path: "/f/a", phase: "pf_loaded",
    });
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toBeInstanceOf(GenerationStateError);
  });

  it("rejects a root/non-positive agent_uid", async () => {
    const h = makeHarness();
    await expect(h.coord.bringUp({ agent_uid: 0, fortress_path: "/f/a" })).rejects.toBeInstanceOf(GenerationStateError);
  });
});

describe("egress-gate/generation bringUp failure -> in-process recovery", () => {
  it("G2 owner-check failure: releases the port, discards (pf never armed)", async () => {
    const h = makeHarness({ failAt: "owner" });
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toBeInstanceOf(GenerationStateError);
    expect(h.events).toContain("release");
    // Owner failed before the owner_checked journal, so no staging record + no arm.
    expect(h.reg.armCalls).toHaveLength(0);
    expect(h.staging.records.has(502)).toBe(false);
  });

  it("G3 arm failure: TOMBSTONES the uid BEFORE releasing the port (no squat window)", async () => {
    const h = makeHarness({ failAt: "arm" });
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toThrow("arm failed");
    // Recovery tombstoned the uid from the pf_loaded write-ahead (fail-closed)...
    expect(h.reg.tombstoneCalls.map((c) => c.uid)).toContain(502);
    // ...and the DROP of the uncommitted pass happened BEFORE freeing the port
    // (else a stale pass would point at a now-free squattable port).
    expect(h.events.indexOf("tombstone")).toBeLessThan(h.events.indexOf("release"));
    expect(h.staging.records.has(502)).toBe(false);
    // The tombstone carried the dead generation id (monotonicity guard).
    expect(h.reg.tombstoneCalls.at(-1)?.fallback?.generation_id).toBe(1);
  });

  it("recovery failure KEEPS the port held (never freed to a squatter)", async () => {
    const h = makeHarness({ failAt: "arm", tombstoneThrows: true });
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toThrow("arm failed");
    // Tombstone was attempted but threw -> the port must NOT be released.
    expect(h.events).toContain("tombstone");
    expect(h.events).not.toContain("release");
    // The staging record survives for a later recover().
    expect(h.staging.records.has(502)).toBe(true);
  });

  it("G4 manifest failure: pf was armed, recovery tombstones the uncommitted pass", async () => {
    const h = makeHarness({ failAt: "manifest" });
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toThrow("manifest failed");
    expect(h.reg.armCalls).toHaveLength(1); // arm did land
    expect(h.reg.tombstoneCalls.map((c) => c.uid)).toContain(502);
    expect(h.staging.records.has(502)).toBe(false);
  });
});

describe("egress-gate/generation recover (crash-recovery table)", () => {
  it("no staging record -> none", async () => {
    const h = makeHarness();
    const out = await h.coord.recover(502);
    expect(out.action).toBe("none");
  });

  it("owner_checked (G2 crash) -> discarded, no tombstone, no packet change", async () => {
    const h = makeHarness();
    await h.staging.save({
      generation_id: 3, agent_uid: 502, gate_port: 45001, gate_pid: 9001, gate_pid_start: "start-9001", fortress_path: "/f/a", phase: "owner_checked",
    });
    const out = await h.coord.recover(502);
    expect(out.action).toBe("discarded");
    expect(out.generation_id).toBe(3);
    expect(h.reg.tombstoneCalls).toHaveLength(0);
    expect(h.staging.records.has(502)).toBe(false);
  });

  it("pf_loaded (G3 crash) -> tombstoned with the staged port as fallback", async () => {
    const h = makeHarness();
    await h.staging.save({
      generation_id: 3, agent_uid: 502, gate_port: 45001, gate_pid: 9001, gate_pid_start: "start-9001", fortress_path: "/f/a", phase: "pf_loaded",
    });
    const out = await h.coord.recover(502);
    expect(out.action).toBe("tombstoned");
    expect(h.reg.tombstoneCalls).toEqual([{ uid: 502, fallback: { gate_port: 45001, fortress_path: "/f/a", generation_id: 3 } }]);
    expect(h.staging.records.has(502)).toBe(false);
  });

  it("manifest_reloaded (G4 crash) -> tombstoned (uncommitted pass dropped)", async () => {
    const h = makeHarness();
    await h.staging.save({
      generation_id: 3, agent_uid: 502, gate_port: 45001, gate_pid: 9001, gate_pid_start: "start-9001", fortress_path: "/f/a", phase: "manifest_reloaded",
    });
    const out = await h.coord.recover(502);
    expect(out.action).toBe("tombstoned");
    expect(h.reg.tombstoneCalls.map((c) => c.uid)).toEqual([502]);
  });
});

describe("egress-gate/generation pure helpers", () => {
  it("computeNextGenerationId is strictly-greater over committed + staging", () => {
    expect(computeNextGenerationId(undefined, undefined)).toBe(1);
    expect(computeNextGenerationId(5, undefined)).toBe(6);
    expect(computeNextGenerationId(5, 9)).toBe(10);
    expect(computeNextGenerationId(9, 5)).toBe(10);
  });

  it("evaluateGenerationMatch serves ONLY when all three surfaces agree", () => {
    expect(
      evaluateGenerationMatch({ committedGenerationId: 3, committedPort: 45001, pfPassPort: 45001, manifestPort: 45001, manifestGenerationId: 3 }).serve,
    ).toBe(true);
  });

  it("evaluateGenerationMatch refuses on a pf-port mismatch", () => {
    const r = evaluateGenerationMatch({ committedGenerationId: 3, committedPort: 45001, pfPassPort: 45002, manifestPort: 45001, manifestGenerationId: 3 });
    expect(r.serve).toBe(false);
    expect(r.reasons.join(" ")).toContain("pf pass port");
  });

  it("evaluateGenerationMatch refuses on a manifest generation mismatch", () => {
    const r = evaluateGenerationMatch({ committedGenerationId: 3, committedPort: 45001, pfPassPort: 45001, manifestPort: 45001, manifestGenerationId: 2 });
    expect(r.serve).toBe(false);
    expect(r.reasons.join(" ")).toContain("manifest generation");
  });

  it("evaluateGenerationMatch refuses when there is no committed generation", () => {
    const r = evaluateGenerationMatch({ committedGenerationId: undefined, committedPort: undefined, pfPassPort: 45001, manifestPort: 45001, manifestGenerationId: 3 });
    expect(r.serve).toBe(false);
  });

  it("resolveGateRestart resumes only on rebind + owner", () => {
    expect(resolveGateRestart({ committed: { generation_id: 3, gate_port: 45001 }, rebindOk: true, ownerVerified: true }).action).toBe("resume");
  });

  it("resolveGateRestart requires a new generation on a failed rebind", () => {
    const r = resolveGateRestart({ committed: { generation_id: 3, gate_port: 45001 }, rebindOk: false, ownerVerified: false });
    expect(r.action).toBe("new_generation_required");
    expect(r.reasons.join(" ")).toContain("rebind");
  });

  it("resolveGateRestart reports no committed generation when absent", () => {
    expect(resolveGateRestart({ committed: null, rebindOk: false, ownerVerified: false }).action).toBe("no_committed_generation");
  });

  it("resolveCommittedGeneration treats an armed-but-uncommitted (staging present) entry as NOT committed", () => {
    const entry = { gate_port: 45001, generation_id: 3 };
    // A staging record in flight -> the entry is NOT yet committed (G4-before-G5).
    const withStaging = resolveCommittedGeneration({ entry, stagingRecordPresent: true });
    expect(withStaging.committedGenerationId).toBeUndefined();
    expect(withStaging.committedPort).toBeUndefined();
    // Fed to the match check, an uncommitted generation NEVER serves green.
    expect(
      evaluateGenerationMatch({ ...withStaging, pfPassPort: 45001, manifestPort: 45001, manifestGenerationId: 3 }).serve,
    ).toBe(false);
    // No staging record -> committed.
    const committed = resolveCommittedGeneration({ entry, stagingRecordPresent: false });
    expect(committed).toEqual({ committedGenerationId: 3, committedPort: 45001 });
  });

  it("resolveCommittedGeneration treats a tombstoned or dirty entry as NOT committed", () => {
    expect(
      resolveCommittedGeneration({ entry: { gate_port: 45001, generation_id: 3, tombstone: true }, stagingRecordPresent: false }).committedGenerationId,
    ).toBeUndefined();
    expect(
      resolveCommittedGeneration({ entry: { gate_port: 45001, generation_id: 3 }, stagingRecordPresent: false, registryDirty: true }).committedGenerationId,
    ).toBeUndefined();
    expect(resolveCommittedGeneration({ entry: null, stagingRecordPresent: false }).committedGenerationId).toBeUndefined();
  });
});

describe("egress-gate/generation per-uid lock (TOCTOU guard)", () => {
  it("bringUp runs under the per-uid lock (acquired + released)", async () => {
    const h = makeHarness();
    await h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" });
    expect(h.lock.held).toBe(false); // released in finally
  });

  it("refuses to start a concurrent bring-up for the same uid while the lock is held", async () => {
    const h = makeHarness();
    // Simulate the lock already held by another in-flight run.
    await h.lock.acquire();
    await expect(h.coord.bringUp({ agent_uid: 502, fortress_path: "/f/a" })).rejects.toThrow(/lock held|in progress/i);
    // No bind happened -- the race was refused before G1.
    expect(h.events).not.toContain("bind");
  });
});

describe("egress-gate/generation bind-first helper", () => {
  it("bindEphemeralGatePort binds a real loopback port and releases it", async () => {
    const binding = await bindEphemeralGatePort();
    expect(binding.port).toBeGreaterThan(0);
    expect(binding.port).toBeLessThanOrEqual(65535);
    expect(binding.pid).toBe(process.pid);
    await binding.release();
    // After release the port is free: a second bind-first must succeed.
    const again = await bindEphemeralGatePort();
    expect(again.port).toBeGreaterThan(0);
    await again.release();
  });

  it("refuses a non-loopback host (loopback-only by construction)", async () => {
    await expect(bindEphemeralGatePort("0.0.0.0")).rejects.toBeInstanceOf(GenerationStateError);
  });
});
