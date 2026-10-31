/** Production home routes keep independent panels available across repeated producer waves. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { AUDIT_CHAIN_GENESIS, AUDIT_CHAIN_SCHEMA_VERSION, computeAuditEntryHash } from "../../src/audit/chain.js";
import { resolveProducerPubKeyPath } from "../../src/castle-wall/runtime/producer-signature.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { startDashboardServer } from "../../src/dashboard/server.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createPosturePanelStore, POSTURE_PANEL_IDS, POSTURE_PANEL_REUSE_MS, POSTURE_PANEL_SINGLE_FLIGHT_CAP, POSTURE_PANEL_BUDGETS } from "../../src/principal-policy/panel-producer.js";
import { DASHBOARD_READ_RESPONSE_DEADLINE_MS } from "../../src/dashboard/read-response.js";
import * as routes from "../../src/principal-policy/posture-routes.js";
import * as posture from "../../src/principal-policy/posture.js";
import type { PostureHome } from "../../src/principal-policy/posture-home-types.js";

vi.mock("../../src/wrap/config-reader.js", async importOriginal => ({
  ...await importOriginal<object>(),
  getPlatformPaths: () => ({ cursor: [] }),
  detectAgentConfigWithDiagnostics: async () => ({ config: { configPath: "/fixture/cursor.json" } }),
}));
const TOKEN = "isolated-panel-fixture";
const TEST_TIMER_MS = 1; // Smallest timer interval, retaining production budget ordering in the wire status.
const WAVE_SIZE = 20;
afterEach(() => vi.restoreAllMocks());
async function freePort() {
  const server = createServer();
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  return port;
}
function heldProducer<T>(value: T) {
  const holders: (() => void)[] = [];
  let active = 0, peak = 0;
  const run = vi.fn(() => {
    active++; peak = Math.max(peak, active);
    return new Promise<T>(resolve => holders.push(() => { active--; resolve(value); }));
  });
  return { run, release: () => holders.splice(0).forEach(resolve => resolve()), peak: () => peak };
}
async function rig(stalls: string[], options: { syncThrow?: boolean; syncOverrun?: boolean; auditLog?: AuditLog; realTimers?: boolean; homeDirectory?: string } = {}) {
  const home = options.homeDirectory ?? await mkdtemp(join(tmpdir(), "posture-panels-"));
  const priorHome = process.env.HOME; process.env.HOME = home;
  const auditLog = options.auditLog ?? new AuditLog(new MemoryStorage(), generateRandomKey());
  const port = await freePort();
  const dashboard = new DashboardApprovalChannel({ port, host: "127.0.0.1", timeout_seconds: 30, auth_token: TOKEN, auto_open: false, producer_key_load_options: { platform: "linux" } });
  (dashboard as any)._sanctuaryConfig = { storage_path: home };
  let clock = Date.now();
  const store = options.realTimers ? createPosturePanelStore() : createPosturePanelStore({ now: () => clock, setTimer: ((handler: () => void) => setTimeout(handler, TEST_TIMER_MS)) as typeof setTimeout });
  (dashboard as any).panelStore = store;
  if (!options.realTimers) {
    // Accelerated-budget fixtures positively establish absence without disk latency.
    (dashboard as any).ensureProducerKeyLoaded = async () => { (dashboard as any)._producerKeyObservation = "absent"; };
    (dashboard as any).ensureBrokerProducerKeyLoaded = async () => { (dashboard as any)._brokerProducerKeyObservation = "absent"; };
  }
  const enforcement = heldProducer({ status: "undetermined", reason: "fixture", observed_at: null, freshness_window_ms: 30_000, active_connection_count: 0 });
  const exclusive = heldProducer(null);
  const keys = heldProducer(undefined);
  const scan = heldProducer(undefined);
  const subject = heldProducer("fixture/uid-601");
  const provision = heldProducer(false);
  const controls = { enforcement_availability: enforcement, exclusive_egress: exclusive, producer_keys: keys, unwrapped: scan, protection_subject: subject, vault_provision_claim: provision };
  (dashboard as any).resolveProtectionClaimSubject = stalls.includes("protection_subject") ? subject.run : async () => "fixture/uid-601";
  (dashboard as any).resolveVaultProvisionClaimed = stalls.includes("vault_provision_claim") ? provision.run : async () => false;
  if (stalls.includes("producer_keys")) (dashboard as any).ensureProducerKeyLoaded = keys.run;
  dashboard.setDependencies({ auditLog,
    ...(stalls.includes("producer_keys") ? {} : { resolvePinnedProducerKey: () => null }),
    resolveEnforcementAvailability: stalls.includes("enforcement_availability") ? enforcement.run : async () => null,
  } as never);
  if (stalls.includes("exclusive_egress")) dashboard.setExclusiveEgressPostureProvider(exclusive.run);
  if (options.syncThrow) dashboard.setExclusiveEgressPostureProvider(() => { throw new Error("private fixture text"); });
  if (options.syncOverrun) dashboard.setExclusiveEgressPostureProvider(() => { clock += POSTURE_PANEL_BUDGETS.exclusive_egress; return null; });
  const originalAppend = auditLog.append.bind(auditLog);
  const append = vi.spyOn(auditLog, "append").mockImplementation(async (...args) => {
    if (args[1] === "posture_unwrapped_scan" && stalls.includes("unwrapped")) { await scan.run(); return undefined as never; }
    return originalAppend(...args);
  });
  try { await dashboard.start(); } catch (error) { process.env.HOME = priorHome; await rm(home, { recursive: true, force: true }); throw error; }
  return { auditLog, dashboard, store, controls, append, url: `http://127.0.0.1:${port}`,
    advance: () => { clock += POSTURE_PANEL_REUSE_MS; },
    async read() {
      const start = performance.now();
      const response = await fetch(`http://127.0.0.1:${port}/api/posture/home`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      const body = await response.json() as PostureHome;
      return { status: response.status, elapsed: performance.now() - start, body };
    },
    async stop() {
      Object.values(controls).forEach(control => control.release());
      await dashboard.stop(); await auditLog.flush();
      if (priorHome === undefined) delete process.env.HOME; else process.env.HOME = priorHome;
      if (!options.homeDirectory) await rm(home, { recursive: true, force: true });
    },
  };
}

describe("production posture home panel isolation", () => {
  it.each([
    ["enforcement_availability"], ["exclusive_egress"], ["producer_keys"], ["unwrapped"],
    ["protection_subject"], ["vault_provision_claim"],
    ["enforcement_availability", "exclusive_egress", "producer_keys", "unwrapped"],
  ])("serves HTTP 200 with independently bounded %j", async (...stalls) => {
    const fixture = await rig(stalls);
    try {
      for (let wave = 0; wave < 3; wave++) {
        const response = await fixture.read();
        expect(response.status).toBe(200);
        expect(response.elapsed).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS);
        expect(Object.keys(response.body.panels).sort()).toEqual([...POSTURE_PANEL_IDS].sort());
        for (const id of stalls) {
          expect(response.body.panels[id as keyof PostureHome["panels"]]).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
          expect((fixture.controls as any)[id].run).toHaveBeenCalledTimes(1);
        }
        expect(response.body.castle_wall.arm_state).not.toBe("armed");
        expect(response.body.feature_health.rows.every(row => row.status !== "active")).toBe(true);
        if (!stalls.includes("producer_keys")) expect(response.body.panels.digest.state).toBe("fresh");
        if (stalls.includes("producer_keys")) expect(response.body.digest.chain_verified).toBe(false);
        if (stalls.includes("exclusive_egress")) expect(response.body.castle_wall.exclusive_egress).toBeDefined();
        if (stalls.includes("enforcement_availability")) expect(response.body.castle_wall.enforcement_availability).toMatchObject({ status: "undetermined", reason: "availability_budget_exceeded" });
        if (stalls.includes("vault_provision_claim")) expect(response.body.castle_wall.castle_wall_provision).toBe("not_yet_walled");
        if (stalls.includes("protection_subject")) {
          expect(response.body.panels.castle_wall.reason).toBe("upstream_unavailable");
          expect(response.body.panels.feature_health.reason).toBe("upstream_unavailable");
        }
      }
    } finally { await fixture.stop(); }
  });
  it.each(["producer", "broker"])("retains both key loads when the %s key load throws", async failed => {
    const fixture = await rig([]);
    (fixture.dashboard as any).injectedResolvePinnedProducerKey = undefined;
    const held = heldProducer(undefined);
    const rejected = vi.fn(() => { throw new Error("private key load exception"); });
    (fixture.dashboard as any).ensureProducerKeyLoaded = failed === "producer" ? rejected : held.run;
    (fixture.dashboard as any).ensureBrokerProducerKeyLoaded = failed === "broker" ? rejected : held.run;
    try {
      for (let wave = 0; wave < 3; wave++) {
        const responses = await Promise.all(Array.from({ length: WAVE_SIZE }, () => fixture.read()));
        for (const response of responses) {
          expect(response.status).toBe(200);
          expect(response.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
          expect(response.body.digest.chain_verified).toBe(false);
          expect(JSON.stringify(response.body)).not.toContain("private key load exception");
        }
      }
      expect(held.run).toHaveBeenCalledTimes(1); expect(rejected).toHaveBeenCalledTimes(1);
      expect(held.peak()).toBe(POSTURE_PANEL_SINGLE_FLIGHT_CAP);
    } finally { held.release(); await fixture.stop(); }
  });
  it("holds scan admission and its append across twenty-reader timeout waves", async () => {
    const fixture = await rig(["unwrapped"]);
    try {
      const wave = () => Promise.all(Array.from({ length: WAVE_SIZE }, () => fixture.read()));
      const first = await wave(); expect(first.every(r => r.status === 200 && r.body.panels.unwrapped.state === "unavailable")).toBe(true);
      const second = wave(); fixture.controls.unwrapped.release();
      expect((await second).every(r => r.status === 200)).toBe(true);
      fixture.advance();
      await fixture.auditLog.appendCritical({ layer: "l1", operation: "wave", identity_id: "fixture", result: "success" });
      const third = await wave();
      expect(third.every(r => r.status === 200 && r.body.panels.unwrapped.state === "stale")).toBe(true);
      expect(third.every(r => r.body.unwrapped.unwrapped[0]?.harness === "cursor")).toBe(true);
      expect(fixture.controls.unwrapped.run.mock.calls.length).toBeLessThanOrEqual(2);
      expect(fixture.controls.unwrapped.peak()).toBe(POSTURE_PANEL_SINGLE_FLIGHT_CAP);
      expect(fixture.append.mock.calls.filter(call => call[1] === "posture_unwrapped_scan").length).toBeLessThanOrEqual(fixture.controls.unwrapped.run.mock.calls.length);
    } finally { await fixture.stop(); }
  });
  it.each(["syncThrow", "syncOverrun"] as const)("contains %s on the HTTP route", async mode => {
    const fixture = await rig([], { [mode]: true });
    try {
      const response = await fixture.read(); expect(response.status).toBe(200);
      expect(response.body.panels.exclusive_egress.reason).toBe(mode === "syncThrow" ? "producer_failed" : "budget_exceeded");
      expect(response.body.panels.exclusive_egress.state).not.toBe("fresh");
      expect(JSON.stringify(response.body)).not.toContain("private fixture text");
    } finally { await fixture.stop(); }
  });
  it("serves a late joined digest as stale at a newer audit sequence over HTTP", async () => {
    const fixture = await rig([], { realTimers: true });
    const original = posture.buildAuditDigest;
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    const digest = vi.spyOn(posture, "buildAuditDigest").mockImplementation(async input => {
      const value = await original(input);
      await held;
      return value;
    });
    try {
      const first = await fixture.read();
      expect(first.status).toBe(200);
      expect(first.body.panels.digest.state).toBe("unavailable");
      await fixture.auditLog.appendCritical({ layer: "l1", operation: "joined_sequence", identity_id: "fixture", result: "success" });
      // Release only after the second HTTP request has joined the original flight.
      const read = fixture.store.read.bind(fixture.store);
      vi.spyOn(fixture.store, "read").mockImplementation((id, sequence, produce, inputKey) => {
        const result = read(id, sequence, produce, inputKey);
        if (id === "digest") release();
        return result;
      });
      const second = await fixture.read();
      expect(second.status).toBe(200);
      expect(second.body.panels.digest).toMatchObject({ state: "stale", age_ms: expect.any(Number), completed_at: expect.any(String), budget_ms: POSTURE_PANEL_BUDGETS.digest, reason: "observation_superseded" });
      expect(second.body.digest.chain_verified).toBe(false);
      expect(digest).toHaveBeenCalledTimes(1);
    } finally { release(); await fixture.stop(); }
  });
  it("uses the post-load key on the first recovered HTTP request", async () => {
    const fixture = await rig([]);
    const key = toBase64url(generateRandomKey());
    const channel = fixture.dashboard as any;
    channel.injectedResolvePinnedProducerKey = undefined;
    channel.ensureProducerKeyLoaded = async () => { channel._producerKeyLoad = { status: "unreadable", reason: "fixture" }; channel._producerKeyObservation = "unreadable"; };
    const wall = vi.spyOn(posture, "buildCastleWallPosture");
    vi.spyOn(fixture.auditLog, "append").mockResolvedValue(undefined as never);
    const sequence = fixture.auditLog.currentInMemorySequence();
    const started = performance.now();
    try {
      const first = await fixture.read();
      expect(first.status).toBe(200);
      expect(wall.mock.calls.at(-1)![0].producerKeyExpectedButUnavailable).toBe(true);
      expect(first.body.producer_keys?.producer).toBe("unreadable");
      expect(first.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "producer_failed" });
      expect((await fixture.read()).body.producer_keys?.producer).toBe("unreadable");
      channel.ensureProducerKeyLoaded = async () => { channel._producerKeyLoad = { status: "present", keyB64url: key }; channel._producerKeyObservation = "present"; };
      const second = await fixture.read();
      expect(second.status).toBe(200);
      expect(wall.mock.calls.at(-1)![0].pinnedProducerKeyB64url).toBe(key);
      expect(wall.mock.calls.at(-1)![0].producerKeyExpectedButUnavailable).not.toBe(true);
      expect(second.body.panels.castle_wall.state).toBe("fresh");
      expect(second.body.producer_keys?.producer).toBe("present");
      expect(second.body.panels.producer_keys.state).toBe("fresh");
      expect(fixture.auditLog.currentInMemorySequence()).toBe(sequence);
      expect(performance.now() - started).toBeLessThan(POSTURE_PANEL_REUSE_MS);
    } finally { await fixture.stop(); }
  });
  it("the second composition root retains one federation admission across requests", async () => {
    const roster = heldProducer(null as never);
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const server = await startDashboardServer({ port: 0, host: "127.0.0.1", authToken: TOKEN, mode: "standalone", sources: { auditLog, resolvePinnedProducerKey: () => null, resolveBrokerPinnedProducerKey: () => null, mode: "standalone", server_version: "fixture" }, fleetRoster: roster.run });
    try {
      for (let wave = 0; wave < 2; wave++) {
        const response = await fetch(`${server.url}/api/posture/home`, { headers: { Authorization: `Bearer ${TOKEN}` } });
        expect(response.status).toBe(200);
        const body = await response.json() as PostureHome;
        expect(body.panels.federation).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
        expect(body.panels.digest.state).toBe("fresh");
      }
      expect(roster.run).toHaveBeenCalledTimes(1);
    } finally { roster.release(); await server.stop(); await auditLog.flush(); }
  });
});

it("measures the production route on a 10000-entry chain with a separate one-second appender", async () => {
  const TOTAL = 10_000;
  const APPEND_INTERVAL_MS = 1000; // One append per second, as in the requested measurement.
  const directory = await mkdtemp(join(tmpdir(), "posture-chain-measurement-"));
  const storage = new FilesystemStorage(directory);
  const key = generateRandomKey(); const encryptionKey = derivePurposeKey(key, "audit-log");
  let previous = AUDIT_CHAIN_GENESIS;
  let fixture: Awaited<ReturnType<typeof rig>> | undefined;
  let child: ReturnType<typeof spawn> | undefined;
  try {
    const pendingWrites: Promise<void>[] = [];
    const FIXTURE_WRITE_CONCURRENCY = 64; // 2^6 concurrent temp-file writes bounds fixture setup work.
    for (let sequence = 1; sequence < TOTAL; sequence++) {
      const timestamp = new Date().toISOString();
      const entry = { timestamp, layer: "l1", operation: "measurement", identity_id: "fixture", result: "success", details: {} };
      const encrypted_payload_bytes = toBase64url(stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(entry)), encryptionKey))));
      const envelope = { sequence, timestamp, prev_hash: previous, schema_version: AUDIT_CHAIN_SCHEMA_VERSION, encrypted_payload_bytes };
      const entry_hash = computeAuditEntryHash(envelope); previous = entry_hash;
      pendingWrites.push(storage.write("_audit", `entry-${String(sequence).padStart(20, "0")}-fixture`, stringToBytes(JSON.stringify({ ...envelope, entry_hash }))));
      if (pendingWrites.length === FIXTURE_WRITE_CONCURRENCY) await Promise.all(pendingWrites.splice(0));
    }
    await Promise.all(pendingWrites);
    const bootstrap = new AuditLog(storage, key, { checkpointInterval: 0, integrityMode: "lenient" });
    await bootstrap.appendCritical({ layer: "l1", operation: "measurement", identity_id: "fixture", result: "success" }); await bootstrap.flush();
    const reader = new AuditLog(storage, key, { checkpointInterval: 0 });
    fixture = await rig([], { auditLog: reader, realTimers: true, homeDirectory: directory });
    const buildTimes: number[] = [];
    const originalBuildHome = routes.buildHome;
    const measured = vi.spyOn(routes, "buildHome").mockImplementation(async deps => {
      const start = performance.now();
      try { return await originalBuildHome(deps); } finally { buildTimes.push(performance.now() - start); }
    });
    const unstalled = [];
    const WAVE_INTERVAL_MS = POSTURE_PANEL_REUSE_MS + 100; // 2.1 seconds exceeds the byte-pass cadence by one tenth of a second.
    let previousStart = performance.now();
    for (let wave = 0; wave < 3; wave++) {
      if (wave > 0) await new Promise(resolve => setTimeout(resolve, Math.max(0, WAVE_INTERVAL_MS - (performance.now() - previousStart))));
      previousStart = performance.now();
      unstalled.push(await fixture.read());
    }
    process.stdout.write(JSON.stringify({ measurement: "posture-home-unstalled", entries: TOTAL, buildHome_ms: buildTimes,
      states: unstalled.map(response => ({ digest: response.body.panels.digest.state, castle_wall: response.body.panels.castle_wall.state })),
      panels: unstalled.map(response => response.body.panels) }) + "\n");
    measured.mockRestore();
    await fixture.stop();
    fixture = await rig(["enforcement_availability", "exclusive_egress", "producer_keys", "unwrapped"], { auditLog: reader, realTimers: true, homeDirectory: directory });
    let appends = 0;
    const worker = `
      import { AuditLog } from './src/operational/audit-log.ts';
      import { FilesystemStorage } from './src/storage/filesystem.ts';
      const options = JSON.parse(process.argv[1]);
      const log = new AuditLog(new FilesystemStorage(options.directory), new Uint8Array(options.key), { checkpointInterval: 0 });
      let tail = Promise.resolve();
      const timer = setInterval(() => { tail = tail.then(async () => {
        await log.appendCritical({ layer: 'l1', operation: 'measurement_append', identity_id: 'fixture', result: 'success' });
        process.send({ type: 'append' });
      }); }, options.interval);
      process.on('message', async message => { if (message === 'stop') { clearInterval(timer); await tail; await log.flush(); process.exit(0); } });
      process.send({ type: 'ready' });
    `;
    child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", worker,
      JSON.stringify({ directory, key: [...key], interval: APPEND_INTERVAL_MS })], {
      cwd: process.cwd(), env: { ...process.env, HOME: directory }, stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    child.on("message", (message: any) => { if (message.type === "append") appends++; });
    await Promise.race([once(child, "message"), once(child, "error").then(([error]) => { throw error; })]);
    const latencies: number[] = [];
    for (let wave = 0; wave < 3; wave++) {
      const responses = await Promise.all(Array.from({ length: WAVE_SIZE }, () => fixture!.read()));
      for (const response of responses) {
        expect(response.status).toBe(200); expect(response.elapsed).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS);
        expect(response.body.panels.unwrapped.state).toBe("unavailable");
        expect(response.body.castle_wall.arm_state).not.toBe("armed");
        latencies.push(response.elapsed);
      }
    }
    for (const id of ["enforcement_availability", "exclusive_egress", "producer_keys", "unwrapped"] as const) expect(fixture.controls[id].run).toHaveBeenCalledTimes(1);
    expect(appends).toBeGreaterThan(0);
    latencies.sort((a, b) => a - b);
    const P95_FRACTION = 95 / 100;
    process.stdout.write(JSON.stringify({ measurement: "posture-home", entries: TOTAL, responses: latencies.length,
      appender_interval_ms: APPEND_INTERVAL_MS, out_of_process_appends: appends,
      p95_ms: latencies[Math.ceil(latencies.length * P95_FRACTION) - 1], max_ms: latencies.at(-1) }) + "\n");
    for (const response of unstalled) {
      expect(response.status).toBe(200);
      for (const id of ["digest", "castle_wall"] as const) {
        const panel = response.body.panels[id];
        expect(panel).toEqual({
          state: expect.stringMatching(/^(fresh|stale|unavailable)$/),
          completed_at: panel.state === "unavailable" ? null : expect.any(String),
          age_ms: panel.state === "unavailable" ? null : expect.any(Number),
          budget_ms: POSTURE_PANEL_BUDGETS[id],
          reason: panel.state === "fresh" ? null : expect.stringMatching(/^(budget_exceeded|producer_failed|never_completed|upstream_unavailable|observation_superseded)$/),
        });
      }
    }
    // The byte pass completes in about 1.2 seconds on APFS but does not complete within the reuse window on the Hetzner ext4 boxes.
    // Freshness at this chain length on Linux is the incremental-extension slice's job, and this case records the numbers everywhere.
    if (process.platform === "darwin") {
      for (const response of unstalled.slice(1)) {
        expect(response.body.panels.digest.state).toBe("fresh");
        expect(response.body.panels.castle_wall.state).toBe("fresh");
      }
    }
  } finally {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      const reapTimer = setTimeout(() => child!.kill("SIGKILL"), DASHBOARD_READ_RESPONSE_DEADLINE_MS);
      try { child.send("stop"); await exited; } finally { clearTimeout(reapTimer); }
    }
    await fixture?.stop(); await rm(directory, { recursive: true, force: true });
  }
}, 60_000); // Setup plus three real-budget waves and bounded worker teardown.

it("caps a newer HTTP joiner while preserving the leader and one route flight", async () => {
  const fixture = await rig([], { realTimers: true });
  // Freeze the scan append so the schedule is exactly S, then the explicit append at S+1.
  fixture.append.mockResolvedValue(undefined as never);
  await fixture.auditLog.appendCritical({ layer: "l2", operation: "query_anonymity_headers_stripped", identity_id: "fixture", result: "success",
    details: { stripped_count: 1, removed: [{ name: "User-Agent", reason: "user-agent" }] } });
  const admissionSequence = fixture.auditLog.currentInMemorySequence();
  const original = posture.buildAuditDigest;
  let release!: () => void, computed!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { computed = resolve; });
  const digest = vi.spyOn(posture, "buildAuditDigest").mockImplementation(async input => {
    const result = await original(input); computed(); await held; return result;
  });
  const flights = (fixture.dashboard as any).readFlightMap as Map<string, unknown>;
  const set = vi.spyOn(flights, "set");
  let first: ReturnType<typeof fixture.read> | undefined;
  let second: ReturnType<typeof fixture.read> | undefined;
  try {
    first = fixture.read();
    await ready;
    expect(flights.size).toBe(1);
    expect(fixture.auditLog.currentInMemorySequence()).toBe(admissionSequence);
    await fixture.auditLog.appendCritical({ layer: "l1", operation: "arrival_sequence", identity_id: "fixture", result: "success" });
    expect(fixture.auditLog.currentInMemorySequence()).toBe(admissionSequence + 1);
    const get = flights.get.bind(flights);
    vi.spyOn(flights, "get").mockImplementation(route => {
      const flight = get(route);
      if (route === "posture_home" && flight) queueMicrotask(release);
      return flight;
    });
    second = fixture.read();
    const [a, b] = await Promise.all([first, second]);
    expect(a.status).toBe(200); expect(b.status).toBe(200);
    expect(a.body.panels.digest.state).toBe("fresh");
    expect(a.body.digest.chain_verified).toBe(true);
    expect(b.body.panels.digest).toEqual({ state: "stale", completed_at: a.body.panels.digest.completed_at,
      age_ms: a.body.panels.digest.age_ms, budget_ms: POSTURE_PANEL_BUDGETS.digest, reason: "observation_superseded" });
    for (const id of ["castle_wall", "digest", "feature_health", "query_privacy", "custody_exit", "federation"] as const) expect(b.body.panels[id].state).not.toBe("fresh");
    expect(b.body.digest).toMatchObject({ chain_verified: false, window_complete: false });
    expect(b.body.castle_wall.audit_integrity_ok).toBe(false);
    expect(b.body.feature_health.audit_integrity_ok).toBe(false);
    expect(b.body.query_privacy.tier_a_strip_observed).toBe(false);
    expect(a.body.query_privacy.tier_a_strip_observed).toBe(true);
    expect(a.body.custody_exit.audit_integrity_ok).toBe(true);
    expect(b.body.custody_exit.audit_integrity_ok).toBe(false);
    expect(b.body.custody_exit.clean_exit_guaranteed).toBe(false);
    expect(set).toHaveBeenCalledTimes(1);
    expect(digest).toHaveBeenCalledTimes(1);
    expect(flights.size).toBe(0);
  } finally { release(); await Promise.all([first, second]); await fixture.stop(); }
});

it("keeps a cold key load beyond 400 ms restrictive with unknown copy", async () => {
  const fixture = await rig(["producer_keys"], { realTimers: true });
  try {
    const response = await fixture.read();
    expect(response.status).toBe(200);
    expect(response.elapsed).toBeGreaterThanOrEqual(POSTURE_PANEL_BUDGETS.producer_keys);
    expect(response.body.producer_keys).toMatchObject({ producer: "unknown", message: "Producer key state is not yet determined." });
    expect(JSON.stringify(response.body.producer_keys)).not.toMatch(/expected|configured/);
    expect(response.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
    const capped = [
      ["castle_wall", response.body.castle_wall.audit_integrity_ok, false],
      ["feature_health", response.body.feature_health.audit_integrity_ok, false],
      ["query_privacy", response.body.query_privacy.tier_a_strip_observed, false],
      ["digest", response.body.digest.kernel_allows, 0],
    ] as const;
    for (const [id, field, value] of capped) {
      expect(field).toBe(value);
      expect(response.body.panels[id]).toMatchObject({ state: id === "digest" ? "unavailable" : "stale", reason: "upstream_unavailable" });
      if (id === "digest") expect(response.body.panels[id]).toMatchObject({ completed_at: null, age_ms: null });
    }
    expect(response.body.digest.chain_verified).toBe(false);
    expect(fixture.controls.producer_keys.run).toHaveBeenCalledTimes(1);
  } finally { await fixture.stop(); }
});

it("uses the ordinary digest path for a positively absent configured key", async () => {
  const fixture = await rig([], { realTimers: true });
  (fixture.dashboard as any).injectedResolvePinnedProducerKey = undefined;
  try {
    const response = await fixture.read();
    expect(response.body.producer_keys).toEqual({ producer: "absent", broker: "absent", message: null });
    expect(response.body.panels.producer_keys.state).toBe("fresh");
    expect(response.body.panels.digest.state).toBe("fresh");
    expect(response.body.digest.chain_verified).toBe(true);
  } finally { await fixture.stop(); }
});

it("reports a repaired key file present on the first request within the reuse window", async () => {
  const fixture = await rig([], { realTimers: true });
  const channel = fixture.dashboard as any;
  channel.injectedResolvePinnedProducerKey = undefined;
  fixture.append.mockResolvedValue(undefined as never);
  const path = resolveProducerPubKeyPath(channel._sanctuaryConfig.storage_path);
  const sequence = fixture.auditLog.currentInMemorySequence();
  const started = performance.now();
  try {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "malformed public key");
    for (const request of ["first", "repeated"] as const) {
      const response = await fixture.read();
      expect(response.body.producer_keys, request).toMatchObject({ producer: "unreadable", message: "A producer key is expected and unavailable." });
      expect(response.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "producer_failed" });
    }
    await writeFile(path, generateRandomKey());
    const recovered = await fixture.read();
    expect(recovered.body.producer_keys).toEqual({ producer: "present", broker: "absent", message: null });
    expect(recovered.body.panels.producer_keys.state).toBe("fresh");
    expect(recovered.body.panels.digest.state).toBe("fresh");
    expect(fixture.auditLog.currentInMemorySequence()).toBe(sequence);
    expect(performance.now() - started).toBeLessThan(POSTURE_PANEL_REUSE_MS);
  } finally { await fixture.stop(); }
});

it("contains a synchronous injected key resolver failure on the HTTP route", async () => {
  const fixture = await rig([]);
  fixture.dashboard.setDependencies({ auditLog: fixture.auditLog, resolvePinnedProducerKey: () => { throw new Error("private injected key failure"); } } as never);
  try {
    const response = await fixture.read();
    expect(response.status).toBe(200);
    expect(response.body.producer_keys?.producer).toBe("unknown");
    expect(response.body.digest.chain_verified).toBe(false);
    expect(response.body.panels.producer_keys.state).toBe("unavailable");
    expect(response.body.panels.agents_roster.state).toBe("fresh");
    expect(JSON.stringify(response.body)).not.toContain("private injected key failure");
  } finally { await fixture.stop(); }
});

it("observes a pending reload before reusing absence on the HTTP home", async () => {
  const fixture = await rig([], { realTimers: true });
  const channel = fixture.dashboard as any;
  channel.injectedResolvePinnedProducerKey = undefined;
  fixture.append.mockResolvedValue(undefined as never);
  const path = resolveProducerPubKeyPath(channel._sanctuaryConfig.storage_path);
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let entered!: () => void;
  const loading = new Promise<void>(resolve => { entered = resolve; });
  let reading: ReturnType<typeof fixture.read> | undefined;
  try {
    for (const wave of ["first", "reused"]) {
      const response = await fetch(`${fixture.url}/api/posture/digest`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      expect(response.status, wave).toBe(200);
      expect((await response.json() as PostureHome["digest"]).chain_verified).toBe(true);
    }
    expect(channel._producerKeyObservation).toBe("absent");
    const sequence = fixture.auditLog.currentInMemorySequence();
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "malformed public key");
    const original = channel.ensureProducerKeyLoaded.bind(channel);
    vi.spyOn(channel, "ensureProducerKeyLoaded").mockImplementation(async () => { entered(); await held; await original(); });
    const started = performance.now();
    reading = fixture.read();
    await loading;
    expect(channel._postureKeyLoad).toBeDefined();
    release();
    const response = await reading;
    expect(response.body.producer_keys?.producer).toBe("unreadable");
    expect(response.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "producer_failed" });
    expect(response.body.panels.digest.state).toBe("unavailable");
    expect(response.body.digest).toMatchObject({ chain_verified: false, total_operations: 0, kernel_allows: 0 });
    expect(fixture.auditLog.currentInMemorySequence()).toBe(sequence);
    expect(performance.now() - started).toBeLessThan(POSTURE_PANEL_REUSE_MS);
  } finally { release(); await reading; await fixture.stop(); }
});

it("reports unknown when a reload of previous absence misses its budget", async () => {
  const fixture = await rig([], { realTimers: true });
  const channel = fixture.dashboard as any;
  channel.injectedResolvePinnedProducerKey = undefined;
  fixture.append.mockResolvedValue(undefined as never);
  const held = heldProducer(undefined);
  try {
    expect((await fixture.read()).body.producer_keys?.producer).toBe("absent");
    channel.ensureProducerKeyLoaded = held.run;
    for (const wave of ["first", "repeated"]) {
      const response = await fixture.read();
      expect(response.status, wave).toBe(200);
      expect(response.body.producer_keys?.producer).toBe("unknown");
      expect(response.body.panels.producer_keys).toMatchObject({ state: "unavailable", reason: "budget_exceeded" });
      expect(response.body.panels.digest.state).toBe("unavailable");
      expect(channel.postureKeyLoadWaiters.size).toBe(0);
    }
    expect(held.run).toHaveBeenCalledTimes(1);
  } finally { held.release(); await channel._postureKeyLoad; await fixture.stop(); }
});

it("refreshes both SSE streams after key repair within the reuse window", async () => {
  const fixture = await rig([], { realTimers: true });
  const channel = fixture.dashboard as any;
  channel.injectedResolvePinnedProducerKey = undefined;
  fixture.append.mockResolvedValue(undefined as never);
  let offset = 0;
  channel.panelStore = createPosturePanelStore({ now: () => Date.now() + offset });
  const ticks: (() => void)[] = [];
  const keyWaits = vi.spyOn(channel.postureKeyLoadWaiters, "add");
  const originalRoute = routes.handlePostureRoute;
  const { DEFAULT_STREAM_INTERVAL_MS } = await import("../../src/principal-policy/posture-stream.js");
  vi.spyOn(routes, "handlePostureRoute").mockImplementation((deps, ...args) => originalRoute({ ...deps,
    streamSetInterval: (callback, ms) => { if (ms === DEFAULT_STREAM_INTERVAL_MS) ticks.push(callback); return {} as NodeJS.Timeout; },
    streamClearInterval: () => {},
  }, ...args));
  const readers: ReadableStreamDefaultReader<Uint8Array>[] = [];
  const controllers: AbortController[] = [];
  async function open() {
    const controller = new AbortController(); controllers.push(controller);
    const response = await fetch(`${fixture.url}/api/posture/stream`, { headers: { Authorization: `Bearer ${TOKEN}` }, signal: controller.signal });
    expect(response.status).toBe(200);
    const reader = response.body!.getReader(); readers.push(reader);
    let buffer = "";
    return async (): Promise<PostureHome> => {
      while (true) {
        const end = buffer.indexOf("\n\n");
        if (end >= 0) {
          const frame = buffer.slice(0, end); buffer = buffer.slice(end + 2);
          if (frame.startsWith("event: home\n")) return JSON.parse(frame.slice(frame.indexOf("data: ") + "data: ".length));
          expect(frame).not.toContain("event: error");
        } else {
          const next = await reader.read(); expect(next.done).toBe(false);
          buffer += new TextDecoder().decode(next.value);
        }
      }
    };
  }
  const path = resolveProducerPubKeyPath(channel._sanctuaryConfig.storage_path);
  try {
    const a = await open(); expect((await a()).producer_keys?.producer).toBe("absent");
    const b = await open(); expect((await b()).producer_keys?.producer).toBe("absent");
    expect(ticks).toHaveLength(2);
    expect(keyWaits).toHaveBeenCalledTimes(2); // One bounded key wait per initial frame, one for each stream.
    const sequence = fixture.auditLog.currentInMemorySequence();
    offset += POSTURE_PANEL_REUSE_MS;
    await mkdir(dirname(path), { recursive: true }); await writeFile(path, "malformed public key");
    ticks[0]();
    expect((await a()).producer_keys?.producer).toBe("unreadable");
    const started = performance.now();
    await writeFile(path, generateRandomKey());
    ticks[1]();
    const repaired = await b();
    expect(repaired.producer_keys?.producer).toBe("present");
    expect(repaired.panels.producer_keys.state).toBe("fresh");
    expect(repaired.panels.digest.state).toBe("fresh");
    expect(fixture.auditLog.currentInMemorySequence()).toBe(sequence);
    expect(performance.now() - started).toBeLessThan(POSTURE_PANEL_REUSE_MS);
  } finally {
    controllers.forEach(controller => controller.abort());
    await Promise.allSettled(readers.map(reader => reader.cancel()));
    await fixture.stop();
  }
});

it("releases an SSE admission when the client closes during its first key reload", async () => {
  const fixture = await rig(["producer_keys"], { realTimers: true });
  const channel = fixture.dashboard as any;
  const controller = new AbortController();
  let opening: Promise<Response | Error> | undefined;
  let routeFinished: Promise<boolean> | undefined;
  const originalRoute = routes.handlePostureRoute;
  vi.spyOn(routes, "handlePostureRoute").mockImplementation((deps, ...args) => routeFinished = originalRoute({ ...deps,
    streamSetInterval: () => ({} as NodeJS.Timeout), streamClearInterval: () => {},
  }, ...args));
  try {
    opening = fetch(`${fixture.url}/api/posture/stream`, { headers: { Authorization: `Bearer ${TOKEN}` }, signal: controller.signal })
      .catch(error => error as Error);
    await vi.waitFor(() => expect(fixture.controls.producer_keys.run).toHaveBeenCalledTimes(1));
    expect(channel.postureStreamRegistry.active).toBe(1);
    expect(channel.postureKeyLoadWaiters.size).toBe(1);
    controller.abort();
    expect((await opening as Error).name).toBe("AbortError");
    await vi.waitFor(() => expect(channel.postureStreamRegistry.active).toBe(0));
    fixture.controls.producer_keys.release();
    await channel._postureKeyLoad;
    expect(channel.postureKeyLoadWaiters.size).toBe(0);
  } finally {
    controller.abort(); await opening;
    fixture.controls.producer_keys.release(); await channel._postureKeyLoad;
    // Drain the first frame before restoring HOME, even when its socket closed before the key wait settled.
    await new Promise<void>(resolve => setImmediate(resolve)); await routeFinished;
    await fixture.stop();
  }
}, DASHBOARD_READ_RESPONSE_DEADLINE_MS * 2); // One response deadline plus one allowance for aborted-socket teardown.
