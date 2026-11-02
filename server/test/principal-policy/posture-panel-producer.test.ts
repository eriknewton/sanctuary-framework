/** Posture panels preserve independent freshness, bounded admission, and honest historical values. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  NO_PANEL_INPUTS, createPosturePanelStore, capStalePanel, POSTURE_PANEL_IDS, POSTURE_PANEL_BUDGETS,
  POSTURE_HOME_COMPOSE_BUDGET_MS, POSTURE_HOME_RESPONSE_HEADROOM_MS,
  POSTURE_PANEL_REUSE_MS, POSTURE_PANEL_SINGLE_FLIGHT_CAP, POSTURE_PRELUDE_BUDGET_MS,
} from "../../src/principal-policy/panel-producer.js";
import { DASHBOARD_READ_RESPONSE_DEADLINE_MS, createDashboardReadFlightMap } from "../../src/dashboard/read-response.js";
import { AUDIT_EAGER_SENTINEL_INTERVAL_MS, AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import * as posture from "../../src/principal-policy/posture.js";
import * as health from "../../src/principal-policy/feature-health.js";
import type { PostureRouteDeps } from "../../src/principal-policy/posture-routes.js";
import { buildHome, withPostureProducerKeys, handlePostureRoute } from "../../src/principal-policy/posture-routes.js";
import type { PostureHome } from "../../src/principal-policy/posture-home-types.js";

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
const EPOCH = Date.UTC(2026, 0, 1);
function pending<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
async function fixture() {
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const deps = { resolvePinnedProducerKey: () => null, resolveBrokerPinnedProducerKey: () => null, auditLog, originMachine: "panels", listAgents: () => [],
    detectInstalledHarnesses: async () => [], panelStore: createPosturePanelStore(), readFlightMap: createDashboardReadFlightMap() };
  return { deps, home: await buildHome(deps) };
}

describe("posture producer store", () => {
  it("reserves response headroom and pins the byte-pass reuse cadence", () => {
    // Must match the budget relation beside POSTURE_HOME_RESPONSE_HEADROOM_MS in panel-producer.ts.
    expect(POSTURE_HOME_COMPOSE_BUDGET_MS + POSTURE_HOME_RESPONSE_HEADROOM_MS).toBeLessThanOrEqual(DASHBOARD_READ_RESPONSE_DEADLINE_MS);
    expect(POSTURE_PANEL_REUSE_MS).toBe(AUDIT_EAGER_SENTINEL_INTERVAL_MS);
    expect(Object.keys(POSTURE_PANEL_BUDGETS).sort()).toEqual([...POSTURE_PANEL_IDS].sort());
  });
  it("reuses fresh values only at the same local audit state", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const produce = vi.fn(() => "value");
    expect((await store.read("digest", 0, produce, NO_PANEL_INPUTS)).status.state).toBe("fresh");
    expect((await store.read("digest", 0, produce, NO_PANEL_INPUTS)).status.age_ms).toBe(0);
    expect(produce).toHaveBeenCalledTimes(1);
    await store.read("digest", 1, produce, NO_PANEL_INPUTS);
    expect(produce).toHaveBeenCalledTimes(2);
  });
  it("append then immediate home observes the new entry while no append reuses", async () => {
    const { deps, home } = await fixture();
    const query = vi.spyOn(deps.auditLog, "runEagerReads");
    await buildHome(deps); expect(query).not.toHaveBeenCalled();
    await deps.auditLog.appendCritical({ layer: "l1", operation: "panel_test", identity_id: "fixture", result: "success" });
    const next = await buildHome(deps);
    expect(next.digest.total_operations).toBeGreaterThan(home.digest.total_operations);
    expect(query).toHaveBeenCalled();
    expect(Object.keys(next.panels).sort()).toEqual([...POSTURE_PANEL_IDS].sort());
  });
  it("budgets every producer independently and reports unavailable without error text", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const held = pending<string>();
    try {
      const reads = POSTURE_PANEL_IDS.map(id => store.read(id, 0, () => held.promise, NO_PANEL_INPUTS));
      await vi.advanceTimersByTimeAsync(Math.max(...Object.values(POSTURE_PANEL_BUDGETS)));
      for (const result of await Promise.all(reads)) expect(result.status).toMatchObject({ state: "unavailable", reason: "budget_exceeded", age_ms: null, completed_at: null });
      expect(store.snapshot("digest").status.reason).toBe("never_completed");
      expect(store.snapshot("digest", "upstream_unavailable").status.reason).toBe("upstream_unavailable");
    } finally { held.resolve("late"); await Promise.resolve(); }
  });
  it("prelude completes its response wait within its reserved budget", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const held = pending<void>(); let answered = false;
    const result = store.read("producer_keys", 0, () => held.promise, NO_PANEL_INPUTS).then(value => { answered = true; return value; });
    try {
      await vi.advanceTimersByTimeAsync(POSTURE_PRELUDE_BUDGET_MS);
      expect(answered).toBe(true);
      expect((await result).status.reason).toBe("budget_exceeded");
    } finally { held.resolve(); await result; }
  });
  it("defers synchronous throws into one panel's producer_failed result", async () => {
    const store = createPosturePanelStore(); let invoked = false;
    const result = store.read("digest", 0, () => { invoked = true; throw new Error("private text"); }, NO_PANEL_INPUTS);
    expect(invoked).toBe(false);
    expect((await result).status).toMatchObject({ state: "unavailable", reason: "producer_failed" });
    expect(JSON.stringify(await result)).not.toContain("private text");
    expect((await store.read("unwrapped", 0, () => [], NO_PANEL_INPUTS)).status.state).toBe("fresh");
  });
  it("reports synchronous budget overruns honestly", async () => {
    let now = EPOCH; const store = createPosturePanelStore({ now: () => now });
    const result = await store.read("digest", 0, () => { now += POSTURE_PANEL_BUDGETS.digest; return "complete"; }, NO_PANEL_INPUTS);
    expect(result.status).toMatchObject({ state: "stale", reason: "budget_exceeded" });
  });
  it("holds admission through three timeout and late-completion waves", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const held = pending<string>();
    let active = 0; let peak = 0;
    const produce = vi.fn(async () => { active++; peak = Math.max(peak, active); try { return await held.promise; } finally { active--; } });
    const WAVE_SIZE = 20;
    try {
      const first = Array.from({ length: WAVE_SIZE }, () => store.read("unwrapped", 0, produce, NO_PANEL_INPUTS));
      await vi.advanceTimersByTimeAsync(POSTURE_PANEL_BUDGETS.unwrapped);
      expect((await Promise.all(first)).every(r => r.status.reason === "budget_exceeded")).toBe(true);
      const second = Array.from({ length: WAVE_SIZE }, () => store.read("unwrapped", 0, produce, NO_PANEL_INPUTS));
      held.resolve("late complete");
      expect((await Promise.all(second)).every(r => r.value === "late complete")).toBe(true);
      const third = await Promise.all(Array.from({ length: WAVE_SIZE }, () => store.read("unwrapped", 0, produce, NO_PANEL_INPUTS)));
      expect(third.every(r => r.value === "late complete")).toBe(true);
      expect(produce).toHaveBeenCalledTimes(1);
      expect(peak).toBe(POSTURE_PANEL_SINGLE_FLIGHT_CAP);
      vi.setSystemTime(EPOCH + POSTURE_PANEL_REUSE_MS + POSTURE_PANEL_BUDGETS.unwrapped);
      const failure = await store.read("unwrapped", 1, () => { throw new Error("failed"); }, NO_PANEL_INPUTS);
      expect(failure.status).toMatchObject({ state: "stale", reason: "producer_failed", age_ms: POSTURE_PANEL_REUSE_MS });
    } finally { held.resolve("cleanup"); await Promise.resolve(); }
  });
  it("marks a joiner stale when its audit sequence advanced during the run", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const held = pending<string>();
    const first = store.read("digest", 1, () => held.promise, NO_PANEL_INPUTS);
    const second = store.read("digest", 2, () => "newer", NO_PANEL_INPUTS);
    held.resolve("sequence one");
    expect((await first).status.state).toBe("fresh");
    expect(await second).toMatchObject({ value: "sequence one", status: { state: "stale", age_ms: 0, completed_at: new Date(EPOCH).toISOString(), budget_ms: POSTURE_PANEL_BUDGETS.digest, reason: "observation_superseded" } });
    expect(await store.read("digest", 2, () => "sequence two", NO_PANEL_INPUTS)).toMatchObject({ value: "sequence two", status: { state: "fresh" } });
  });
  it("removes timed-out waiters across ten thousand stalled reads", async () => {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore(); const held = pending<string>();
    const produce = vi.fn(() => held.promise);
    const WAVE_SIZE = 100, WAVES = 100; // Ten thousand waits in bounded concurrent waves.
    try {
      for (let wave = 0; wave < WAVES; wave++) {
        const reads = Array.from({ length: WAVE_SIZE }, () => store.read("digest", wave, produce, NO_PANEL_INPUTS));
        expect(store.waiterCount("digest")).toBe(WAVE_SIZE);
        await vi.advanceTimersByTimeAsync(POSTURE_PANEL_BUDGETS.digest);
        expect((await Promise.all(reads)).every(read => read.status.reason === "budget_exceeded")).toBe(true);
        expect(store.waiterCount("digest")).toBe(0);
      }
      expect(produce).toHaveBeenCalledTimes(1);
    } finally { held.resolve("cleanup"); await Promise.resolve(); }
  });
  it("contains a generation mismatch within the failed panel", async () => {
    const store = createPosturePanelStore();
    const get = Map.prototype.get;
    const lookup = vi.spyOn(Map.prototype, "get").mockImplementation(function (this: Map<unknown, any>, key) {
      const slot = get.call(this, key);
      if (key === "digest" && slot?.state === "state_RUNNING") slot.generation++;
      return slot;
    });
    try {
      const first = store.read("digest", 1, () => "discarded", NO_PANEL_INPUTS);
      const second = store.read("digest", 1, () => "not admitted", NO_PANEL_INPUTS);
      expect((await first).status).toMatchObject({ state: "unavailable", reason: "producer_failed" });
      expect((await second).status.reason).toBe("producer_failed");
      expect((await store.read("unwrapped", 1, () => [], NO_PANEL_INPUTS)).status.state).toBe("fresh");
    } finally { lookup.mockRestore(); }
  });
  it("retains exactly the closed inventory after 1000 waves", async () => {
    const store = createPosturePanelStore();
    for (let wave = 0; wave < 1000; wave++) await Promise.all(POSTURE_PANEL_IDS.map(id => store.read(id, wave, () => wave, NO_PANEL_INPUTS)));
    expect([...store.ids()].sort()).toEqual([...POSTURE_PANEL_IDS].sort());
  });
  it.each(["castle_wall", "feature_health", "digest", "query_privacy", "custody_exit", "federation", "agents"] as const)("caps green-bearing fields for %s without changing the cached value", async id => {
    const { home } = await fixture();
    home.castle_wall.arm_state = "armed"; home.castle_wall.audit_integrity_ok = true;
    home.castle_wall.producer_authenticity = "producer_signed";
    home.castle_wall.castle_wall_provision = "walled";
    home.castle_wall.exclusive_egress = { fine_grained_declared: true, exclusive_egress_live: true, mode: "exclusive", reasons: [],
      agents: [{ agent_uid: 1, // One synthetic agent; no host lookup or credential access.
        fine_grained_declared: true, mode: "exclusive", exclusive_egress_live: true,
        manifest_gate_rule_generation: 1, // First synthetic generation.
        pf_liveness: { live: true, reasons: [] }, gate_process: { up: true, port_owner_verified: true, reasons: [] },
        generation_match: { serve: true, reasons: [] }, reasons: [] }] };
    const activeAvailability = { status: "live", reason: "fixture", observed_at: new Date(EPOCH).toISOString(), freshness_window_ms: POSTURE_PANEL_REUSE_MS, active_connection_count: 1 } as any;
    home.castle_wall.enforcement_availability = activeAvailability;
    home.feature_health.rows.forEach(row => { row.status = "active"; row.audit_integrity_ok = true; row.enforcement_availability = activeAvailability; });
    home.feature_health.audit_integrity_ok = true;
    home.feature_health.plugin_rows = [{ status: "active", basis: "fixture" } as any];
    home.digest.chain_verified = true; home.digest.window_complete = true; home.digest.chain_verdict = "verified";
    home.query_privacy.rows.forEach(row => { row.status = "active"; }); home.query_privacy.tier_a_strip_observed = true;
    home.custody_exit.audit_integrity_ok = true; home.custody_exit.clean_exit_guaranteed = true;
    home.federation.available = true;
    home.agents = [{ enforcement_active: "active" } as PostureHome["agents"][number]];
    const original = JSON.stringify(home[id]); const value: any = capStalePanel(id, home[id]);
    if (id === "castle_wall") { expect(value.arm_state).toBe("unknown"); expect(value.audit_integrity_ok).toBe(false); expect(value.evidence_basis).toBe("stale_evidence");
      expect(value.producer_authenticity).toBe("not_applicable");
      expect(value.castle_wall_provision).toBe("not_yet_walled");
      expect(value.exclusive_egress).toMatchObject({ fine_grained_declared: true, exclusive_egress_live: false, mode: null });
      expect(value.exclusive_egress.agents).toEqual([]);
      expect(value.exclusive_egress.reasons).toEqual(["exclusive-egress posture read failed: budget_exceeded"]);
      expect(value.enforcement_availability).toMatchObject({ status: "undetermined", reason: "availability_budget_exceeded" }); }
    if (id === "feature_health") { expect(value.rows.every((r: any) => r.status === "unknown" && r.basis === "stale_evidence" && !r.audit_integrity_ok)).toBe(true); expect(value.audit_integrity_ok).toBe(false);
      expect(value.rows.length).toBeGreaterThan(0);
      for (const row of value.rows) expect(row.enforcement_availability).toMatchObject({ status: "undetermined", reason: "availability_budget_exceeded" });
      expect(value.plugin_rows).toMatchObject([{ status: "unknown", basis: "integrity_tainted" }]);
    }
    if (id === "digest") expect(value).toMatchObject({ chain_verified: false, window_complete: false, window_incomplete_reason: "coverage_unknown", chain_verdict: "verified" });
    if (id === "query_privacy") { expect(value.tier_a_strip_observed).toBe(false); expect(value.rows.every((r: any) => r.status === "unknown")).toBe(true);
      const tierA = value.rows.filter((r: any) => r.tier === "A");
      expect(tierA.length).toBeGreaterThan(0);
      for (const row of tierA) expect(row.tier_a_evidence).toBe("no_calls"); }
    if (id === "custody_exit") expect(value).toMatchObject({ audit_integrity_ok: false, clean_exit_guaranteed: false });
    if (id === "federation") expect(value.available).toBe(false);
    if (id === "agents") expect(value[0].enforcement_active).toBe("unknown");
    expect(JSON.stringify(home[id])).toBe(original);
  });
});

// The composition contract must require a per-instance store at compile time.
const storeIsRequired: {} extends Pick<PostureRouteDeps, "panelStore"> ? false : true = true;
it("requires a per-instance panel store", () => expect(storeIsRequired).toBe(true));

it("passes one fail-closed resolver snapshot to both evidence consumers", async () => {
  const { deps } = await fixture();
  const wall = vi.spyOn(posture, "buildCastleWallPosture");
  const features = vi.spyOn(health, "buildFeatureHealthPanel");
  const failing = () => { throw new Error("private resolver failure"); };
  const home = await buildHome({ ...deps, panelStore: createPosturePanelStore(),
    exclusiveEgressPosture: failing, resolveEnforcementAvailability: failing,
    resolveVaultProvisionClaimed: failing });
  expect(wall).toHaveBeenCalledTimes(1);
  expect(features).toHaveBeenCalledTimes(1);
  const wallInput = wall.mock.calls[0]![0];
  const featureInput = features.mock.calls[0]![0];
  expect(wallInput.exclusiveEgress).toEqual(posture.failedExclusiveEgressStatus("budget_exceeded"));
  expect(wallInput.enforcementAvailability).toMatchObject({ status: "undetermined", reason: "availability_budget_exceeded" });
  expect(wallInput.vaultProvisionClaimed).toBe(true);
  expect(featureInput.exclusiveEgress).toEqual(wallInput.exclusiveEgress);
  expect(featureInput.enforcementAvailability).toEqual(wallInput.enforcementAvailability);
  expect(home.castle_wall.arm_state).not.toBe("armed");
});

it.each([false, true])("key-load failure requires cached present keys (%s)", async present => {
  const { deps } = await fixture();
  const result = await withPostureProducerKeys({ ...deps, panelStore: createPosturePanelStore(),
    producerKeyObservation: present ? "present" : "unreadable", brokerProducerKeyObservation: present ? "present" : "unreadable",
    prepareProducerKeys: async () => { throw new Error("private keys failure"); },
    resolvePinnedProducerKey: () => present ? "cached-key" : null,
    resolveBrokerPinnedProducerKey: () => present ? "cached-broker-key" : null });
  expect(result.producerKeysStatus).toMatchObject({ state: "unavailable", reason: "producer_failed" });
  expect(result.producerKeyExpectedButUnavailable).toBe(!present);
  expect(result.brokerProducerKeyExpectedButUnavailable).toBe(!present);
});

it("budgets key preparation at the production composition boundary", async () => {
  const { deps } = await fixture();
  vi.useFakeTimers(); vi.setSystemTime(EPOCH);
  const held = pending<{}>(); let answered = false;
  const result = withPostureProducerKeys({ ...deps, panelStore: createPosturePanelStore(),
    prepareProducerKeys: () => held.promise }).then(value => { answered = true; return value; });
  try {
    await vi.advanceTimersByTimeAsync(POSTURE_PRELUDE_BUDGET_MS);
    expect(answered).toBe(true);
    expect((await result).producerKeysStatus).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
  } finally { held.resolve({}); await result; }
});

it("keeps a cold unresolved key restrictive after a slow load", async () => {
  const { deps } = await fixture();
  vi.useFakeTimers(); vi.setSystemTime(EPOCH);
  const held = pending<{}>();
  const read = buildHome({ ...deps, panelStore: createPosturePanelStore(),
    resolvePinnedProducerKey: () => null, prepareProducerKeys: () => held.promise });
  try {
    await vi.advanceTimersByTimeAsync(POSTURE_PRELUDE_BUDGET_MS);
    const home = await read;
    expect(home.panels.producer_keys.state).toBe("unavailable");
    expect(home.digest.chain_verified).toBe(false);
    expect(home.digest.total_operations).toBe(0);
    expect(home.producer_keys?.message).toBe("Producer key state is not yet determined.");
    expect(home.panels.digest).toMatchObject({ state: "unavailable", reason: "upstream_unavailable", completed_at: null, age_ms: null });
  } finally { held.resolve({}); await read; }
});

it("marks upstream-capped bodies and statuses consistently", async () => {
  const { deps } = await fixture();
  const home = await buildHome({ ...deps, panelStore: createPosturePanelStore(),
    exclusiveEgressPosture: () => { throw new Error("unavailable"); } });
  expect(home.panels.castle_wall).toMatchObject({ state: "stale", reason: "upstream_unavailable" });
  expect(home.castle_wall.evidence_basis).toBe("stale_evidence");
  expect(home.panels.feature_health).toMatchObject({ state: "stale", reason: "upstream_unavailable" });
  expect(home.feature_health.rows.every(row => row.basis === "stale_evidence")).toBe(true);
});

it("refreshes dependent evidence when current resolver values change at the same audit head", async () => {
  const { deps } = await fixture();
  const WALL_LAG_MS = 100; // Wall finishes one tenth of a second after the resolver.
  let clock = EPOCH;
  const store = createPosturePanelStore({ now: () => clock });
  const live = { fine_grained_declared: true, exclusive_egress_live: true, mode: "exclusive", reasons: [], agents: [] } as posture.ExclusiveEgressStatus;
  const restricted = { ...live, exclusive_egress_live: false, mode: null };
  let exclusive = live;
  const originalWall = posture.buildCastleWallPosture;
  const wall = vi.spyOn(posture, "buildCastleWallPosture").mockImplementation(async input => {
    const result = await originalWall(input);
    clock += WALL_LAG_MS;
    return result;
  });
  await deps.auditLog.appendCritical({ layer: "l1", operation: "egress_allowed", identity_id: "fixture/uid-601", result: "success",
    timestamp: new Date(EPOCH).toISOString(), details: { cw_source: "castle_wall_audit_consumer" } });
  const requestDeps = { ...deps, panelStore: store, now: () => clock, platform: "linux" as const,
    exclusiveEgressPosture: () => exclusive, resolveProtectionClaimSubject: async () => "fixture/uid-601",
    resolveEnforcementAvailability: async () => ({ status: "live" as const, reason: "ok" as const, observed_at: new Date(EPOCH).toISOString(), freshness_window_ms: POSTURE_PANEL_REUSE_MS * 2, active_connection_count: 1 }) };
  const server = createServer(async (req, res) => {
    await handlePostureRoute(requestDeps, req, res, new URL(req.url!, "http://localhost"), "GET");
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const read = async () => {
    const response = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/api/posture/home`);
    expect(response.status).toBe(200);
    return await response.json() as PostureHome;
  };
  try {
  const first = await read();
  expect(first.castle_wall.arm_state).toBe("armed");
  const sequence = deps.auditLog.currentInMemorySequence();
  clock = EPOCH + POSTURE_PANEL_REUSE_MS;
  exclusive = restricted;
  const second = await read();
  expect(deps.auditLog.currentInMemorySequence()).toBe(sequence);
  expect(second.panels.castle_wall.state).toBe("fresh");
  expect(second.castle_wall.arm_state).not.toBe("armed");
  expect(second.castle_wall.exclusive_egress).toEqual(restricted);
  expect(second.feature_health.rows.find(row => row.feature_id === "castle_wall_egress")?.status).not.toBe("active");
  expect(wall).toHaveBeenCalledTimes(2);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await deps.auditLog.flush(); }
});

it("rechecks key expectations at the same audit head", async () => {
  const { deps } = await fixture();
  const panelStore = createPosturePanelStore();
  for (const expected of [false, true, false]) {
    const ready = await withPostureProducerKeys({ ...deps, panelStore, producerKeyObservation: expected ? "unreadable" : "absent" });
    expect(ready.producerKeyExpectedButUnavailable).toBe(expected);
  }
});
it("preserves a current configured-key expectation across a missed refresh", async () => {
  const { deps } = await fixture();
  vi.useFakeTimers(); vi.setSystemTime(EPOCH);
  const panelStore = createPosturePanelStore();
  await withPostureProducerKeys({ ...deps, panelStore, producerKeyObservation: "absent" });
  const held = pending<{}>();
  const read = withPostureProducerKeys({ ...deps, panelStore, producerKeyObservation: "unreadable",
    resolvePinnedProducerKey: () => null, prepareProducerKeys: () => held.promise });
  try {
    await vi.advanceTimersByTimeAsync(POSTURE_PRELUDE_BUDGET_MS);
    const ready = await read;
    expect(ready.producerKeysStatus).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
    expect(ready.producerKeyExpectedButUnavailable).toBe(true);
  } finally { held.resolve({}); await read; }
});

it.each(["castle_wall", "feature_health", "query_privacy", "digest"] as const)("keeps %s own failure reasons when upstream also caps its body", async id => {
  const { deps } = await fixture();
  for (const reason of ["budget_exceeded", "producer_failed"] as const) {
    vi.useFakeTimers(); vi.setSystemTime(EPOCH);
    const store = createPosturePanelStore();
    const held = pending<never>();
    const original = store.read.bind(store);
    vi.spyOn(store, "read").mockImplementation((panel, sequence, produce, inputKey) => original(panel, sequence,
      panel === id ? () => reason === "budget_exceeded" ? held.promise : Promise.reject(new Error("private panel fault")) : produce, inputKey));
    const reading = buildHome({ ...deps, panelStore: store, producerKeyObservation: "unknown" });
    try {
      await vi.advanceTimersByTimeAsync(POSTURE_HOME_COMPOSE_BUDGET_MS);
      const home = await reading;
      expect(home.panels[id]).toEqual({ state: "unavailable", reason, completed_at: null, age_ms: null, budget_ms: POSTURE_PANEL_BUDGETS[id] });
      const fields = { castle_wall: home.castle_wall.audit_integrity_ok, feature_health: home.feature_health.audit_integrity_ok,
        query_privacy: home.query_privacy.tier_a_strip_observed, digest: home.digest.chain_verified };
      expect(fields[id]).toBe(false);
      expect(JSON.stringify(home)).not.toContain("private panel fault");
    } finally { held.resolve(undefined as never); await reading; vi.useRealTimers(); }
  }
});

it("shares an unchanged-sequence home body and privately caps every audit reader at a newer sequence", async () => {
  const { deps } = await fixture();
  await deps.auditLog.appendCritical({ layer: "l2", operation: "query_anonymity_headers_stripped", identity_id: "fixture", result: "success",
    details: { stripped_count: 1, removed: [{ name: "User-Agent", reason: "user-agent" }] } });
  const home = await buildHome(deps);
  const { reconcilePostureHomeJoiner } = await import("../../src/principal-policy/posture-routes.js");
  expect(reconcilePostureHomeJoiner(home, 1, 1)).toBe(home);
  const original = structuredClone(home);
  const newer = reconcilePostureHomeJoiner(home, 1, 2);
  expect(newer).not.toBe(home);
  expect(newer.panels).not.toBe(home.panels);
  for (const id of ["castle_wall", "digest", "feature_health", "query_privacy", "custody_exit", "federation"] as const) {
    expect(newer[id]).not.toBe(home[id]);
    expect(newer.panels[id]).toEqual({ ...home.panels[id], state: "stale", reason: home.panels[id].reason ?? "observation_superseded" });
  }
  expect(home.query_privacy.tier_a_strip_observed).toBe(true);
  expect(newer.query_privacy.tier_a_strip_observed).toBe(false);
  expect(home.custody_exit.audit_integrity_ok).toBe(true);
  expect(newer.custody_exit.audit_integrity_ok).toBe(false);
  expect(home).toEqual(original);
});

// A required key makes omitted resolver invalidation a compile-time error, including for future callers.
type ReadRequiresInputs = undefined extends Parameters<ReturnType<typeof createPosturePanelStore>["read"]>[3] ? false : true;
const readRequiresInputs: ReadRequiresInputs = true;
it("requires an explicit panel input key at the type boundary", () => { expect(readRequiresInputs).toBe(true); });

it.each(["unknown", "unreadable"] as const)("caps broker-only %s observations at the home composition", async broker => {
  const { deps } = await fixture();
  const home = await buildHome({ ...deps, producerKeyObservation: "present", brokerProducerKeyObservation: broker });
  expect(home.producer_keys).toMatchObject({ producer: "present", broker });
  for (const id of ["castle_wall", "feature_health"] as const) {
    expect(home.panels[id]).toMatchObject({ state: "stale", reason: "upstream_unavailable" });
    expect(home[id].audit_integrity_ok).toBe(false);
  }
  expect(home.castle_wall.arm_state).not.toBe("armed");
  expect(home.feature_health.rows.every(row => row.status !== "active")).toBe(true);
  expect(home.panels.digest).toMatchObject({ state: "unavailable", reason: "upstream_unavailable", completed_at: null, age_ms: null });
  expect(home.digest).toMatchObject({ chain_verified: false, total_operations: 0, kernel_blocks: 0, kernel_allows: 0, window_complete: false });
  const recovered = await buildHome({ ...deps, producerKeyObservation: "present", brokerProducerKeyObservation: "present" });
  expect(recovered.panels.digest.state).toBe("fresh");
  expect(recovered.digest.chain_verified).toBe(true);
});

it.each(["unknown", "unreadable"] as const)("retries one retained %s key result after positive recovery", async negative => {
  const { deps } = await fixture();
  const sequence = deps.auditLog.currentInMemorySequence();
  deps.panelStore.invalidate("producer_keys");
  await deps.panelStore.read("producer_keys", sequence, () => ({ producerKeyObservation: negative, brokerProducerKeyObservation: "absent" }), JSON.stringify(["present", "absent"]));
  const prepare = vi.fn(async () => ({ producerKeyObservation: "present" as const, brokerProducerKeyObservation: "absent" as const }));
  const recovered = await withPostureProducerKeys({ ...deps, producerKeyObservation: "present", brokerProducerKeyObservation: "absent", prepareProducerKeys: prepare });
  expect(prepare).toHaveBeenCalledTimes(1);
  expect(recovered.producerKeyObservation).toBe("present");
  expect(recovered.producerKeysStatus?.state).toBe("fresh");

  deps.panelStore.invalidate("producer_keys");
  await deps.panelStore.read("producer_keys", sequence, () => ({ producerKeyObservation: negative, brokerProducerKeyObservation: "absent" }), JSON.stringify(["present", "absent"]));
  const stillNegative = vi.fn(async () => ({ producerKeyObservation: negative, brokerProducerKeyObservation: "absent" as const }));
  const bounded = await withPostureProducerKeys({ ...deps, producerKeyObservation: "present", brokerProducerKeyObservation: "absent", prepareProducerKeys: stillNegative });
  expect(stillNegative).toHaveBeenCalledTimes(1);
  expect(bounded.producerKeysStatus?.state).toBe("unavailable");
});

it("does not spend a second key budget on a timed-out negative refresh", async () => {
  const { deps } = await fixture();
  vi.useFakeTimers(); vi.setSystemTime(EPOCH);
  deps.panelStore = createPosturePanelStore();
  await deps.panelStore.read("producer_keys", deps.auditLog.currentInMemorySequence(),
    () => ({ producerKeyObservation: "unreadable", brokerProducerKeyObservation: "absent" }), JSON.stringify(["absent", "absent"]));
  const held = pending<never>();
  const prepare = vi.fn(() => held.promise);
  let settled = false;
  const reading = withPostureProducerKeys({ ...deps, producerKeyObservation: "present", brokerProducerKeyObservation: "absent", prepareProducerKeys: prepare })
    .then(value => { settled = true; return value; });
  try {
    await vi.advanceTimersByTimeAsync(POSTURE_PRELUDE_BUDGET_MS);
    expect(settled).toBe(true);
    expect((await reading).producerKeysStatus).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(deps.panelStore.waiterCount("producer_keys")).toBe(0);
  } finally { held.resolve(undefined as never); await reading; }
});


it("caps digest authority without rewriting either observed verdict", async () => {
  const { home } = await fixture();
  for (const verdict of ["verified", "findings"] as const) {
    const digest = { ...home.digest, chain_verdict: verdict, chain_verified: verdict === "verified", integrity_finding_count: verdict === "findings" ? 1 : 0 };
    const before = structuredClone(digest);
    expect(capStalePanel("digest", digest)).toEqual({ ...digest, chain_verified: false, window_complete: false, window_incomplete_reason: "coverage_unknown" });
    expect(digest).toEqual(before);
  }
});

it("preserves clean and failed observations on private home and joined-panel copies", async () => {
  const { home } = await fixture();
  const { reconcilePostureHomeJoiner } = await import("../../src/principal-policy/posture-routes.js");
  for (const verdict of ["verified", "findings"] as const) {
    const digest = { ...home.digest, chain_verdict: verdict, chain_verified: verdict === "verified", integrity_finding_count: verdict === "findings" ? 1 : 0 };
    const leader = { ...home, digest };
    const original = structuredClone(leader);
    const follower = reconcilePostureHomeJoiner(leader, 1, 2);
    expect(follower.digest).toMatchObject({ chain_verdict: verdict, integrity_finding_count: digest.integrity_finding_count, chain_verified: false });
    expect(follower.panels.digest.reason).toBe("observation_superseded");
    expect(leader).toEqual(original);
    const store = createPosturePanelStore();
    const held = pending<typeof digest>();
    const first = store.read("digest", 1, () => held.promise, NO_PANEL_INPUTS);
    const second = store.read("digest", 2, () => digest, NO_PANEL_INPUTS);
    try {
      held.resolve(digest);
      expect((await first).value).toBe(digest);
      const joined = await second;
      expect(joined.status).toMatchObject({ state: "stale", reason: "observation_superseded" });
      expect(capStalePanel("digest", joined.value!)).toMatchObject({ chain_verdict: verdict, integrity_finding_count: digest.integrity_finding_count, chain_verified: false });
      expect(leader).toEqual(original);
    } finally { held.resolve(digest); await Promise.all([first, second]); }
  }
});
