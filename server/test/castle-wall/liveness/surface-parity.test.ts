import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as browserContract from "../../../src/castle-wall/liveness/browser-contract.js";
import * as readerModule from "../../../src/castle-wall/liveness/read-status.js";
import { nodeReaderFs } from "../../../src/castle-wall/liveness/read-status.js";
import { join, basename } from "node:path";
import { Writable } from "node:stream";
import vm from "node:vm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateLiveness, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";
import { readAndEvaluateLiveness, readAndEvaluateLivenessWithInput, type ReaderFs } from "../../../src/castle-wall/liveness/read-status.js";
import { LivenessSurfaceSource, project } from "../../../src/castle-wall/liveness/surface-reader.js";
import { buildLivenessSchedule, LIVENESS_SCHEDULE_FN_SOURCE, verdicts, type LivenessProjection, type LivenessVerdicts } from "../../../src/castle-wall/liveness/browser-contract.js";
import { LIVENESS_SEVERITY_ORDER, AGENT_WINDOW_BASE, HISTORY_WINDOW, OBSERVER_WINDOW, LOCAL_JITTER, SCHEDULE_STEPS, DISPLAY_PERIOD, SECOND, STATUS_READ_DEADLINE } from "../../../src/castle-wall/liveness/constants.js";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { renderPostureHomeHTML } from "../../../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../../../src/principal-policy/posture-agent-html.js";
import { livenessFortressId, runLivenessStatus, formatLivenessLines, wallOnlyStatusExit } from "../../../src/cli/castle-wall-liveness-status.js";
import { checkCastleWallLiveness } from "../../../src/cli/doctor.js";
import { renderTable } from "../../../src/cli/status.js";
import { handleRequest, type APIDeps } from "../../../src/dashboard/api.js";
import { buildHome, handlePostureRoute, type PostureRouteDeps } from "../../../src/principal-policy/posture-routes.js";
import { createDashboardReadFlightMap } from "../../../src/dashboard/read-response.js";
import { createPosturePanelStore } from "../../../src/principal-policy/panel-producer.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { startRig, openDurableSession } from "../../v1/rig.js";
import type { IncomingMessage, ServerResponse } from "node:http";

const fixture = JSON.parse(readFileSync(join(__dirname, "fixtures/states.json"), "utf8"));
const cases: { name: string; charge_remaining_ms?: number; census_remaining_ms?: number; patches: { path: string; value: unknown }[] }[] =
  JSON.parse(readFileSync(join(__dirname, "fixtures/schedule-cases.json"), "utf8")).cases;
const fortressPath = "/fixture/fortress";
function base(): LivenessInput {
  const input = structuredClone(fixture.base);
  input.local.operator_uid = process.getuid!();
  input.local.fortress_id = livenessFortressId(fortressPath);
  for (const record of [input.daemon.value, input.observer.value]) {
    record.subject.operator_uid = input.local.operator_uid;
    record.subject.fortress_id = input.local.fortress_id;
  }
  return input;
}
function record(input: LivenessInput, name: "daemon" | "observer" | "config"): any {
  return (input[name] as { value: unknown }).value;
}
function caseInput(row: typeof cases[number]): LivenessInput {
  const input = base();
  const observer = record(input, "observer");
  if (row.charge_remaining_ms !== undefined) observer.raw.full_service.last_charge_at_ms = input.nowMs - HISTORY_WINDOW + row.charge_remaining_ms;
  if (row.census_remaining_ms !== undefined) {
    const samples = observer.raw.census.samples;
    const delta = input.nowMs - AGENT_WINDOW_BASE + row.census_remaining_ms - Date.parse(samples.at(-1).observed_at);
    for (const sample of samples) {
      sample.observed_at = new Date(Date.parse(sample.observed_at) + delta).toISOString();
      sample.observed_uptime_ms += delta;
    }
  }
  for (const patch of row.patches) {
    const keys = patch.path.split("."); const last = keys.pop()!;
    let target: any = input; for (const key of keys) target = target[key]; target[last] = patch.value;
  }
  return input;
}
function advance(input: LivenessInput, ms: number): LivenessInput {
  return { ...input, nowMs: input.nowMs + ms, host: input.host.ok ? { ...input.host, uptimeMs: input.host.uptimeMs + ms } : input.host };
}
function filesystem(input: LivenessInput, hook?: (path: string) => void, owner = process.getuid!(), serialized = new Map<string, string>()) {
  let opens = 0, reads = 0;
  const fs: ReaderFs = { open: async path => {
    opens++; hook?.(path);
    const name = basename(path).replace(".json", "") as "daemon" | "observer" | "config";
    const directory = !path.endsWith(".json");
    const data = directory ? Buffer.alloc(0) : Buffer.from(serialized.get(name) ?? JSON.stringify(record(input, name)));
    return {
      stat: async () => ({ uid: owner, mode: directory ? 0o700 : 0o600, size: data.length, isFile: () => !directory, isDirectory: () => directory }),
      read: async (buffer, offset, length, position) => { reads++; const part = data.subarray(position, position + length); buffer.set(part, offset); return { bytesRead: part.length }; },
      close: async () => undefined,
    };
  } };
  return { fs, opens: () => opens, reads: () => reads };
}
function options(input: LivenessInput, fs: ReaderFs) {
  return { fortressPath, fortressId: input.local.fortress_id, operatorUid: process.getuid!(), platform: "darwin", nowMs: () => input.nowMs,
    host: { read: async () => input.host }, fs };
}
function projection(input = base()) { return project(evaluateLiveness(input), input, input.nowMs); }
const select = (p: LivenessProjection, age: number) => p.schedule.filter(entry => entry.after_ms <= age).at(-1)!.projection;
const components = ["wall", "agent", "coverage"] as const;
function rank(component: typeof components[number], state: string): number {
  const order = LIVENESS_SEVERITY_ORDER[component];
  const name = state.slice(component.length + 1); const i = order.indexOf(name.startsWith("OK_") ? "OK" : name);
  return i < 0 ? order.length : i;
}
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe("shared reader snapshot", () => {
  it("shares a deadline verdict after a returning reader leaves a close pending", async () => {
    vi.useFakeTimers();
    const input = base(), backing = filesystem(input);
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const fs: ReaderFs = { open: async (...args) => ({ ...await backing.fs.open(...args), close: () => gate }) };
    const read = vi.spyOn(readerModule, "readAndEvaluateLivenessWithInput").mockImplementation(async opts => {
      const handle = await opts.fs!.open("daemon.json", 0);
      void handle.close();
      return { envelope: evaluateLiveness(input), input };
    });
    const source = new LivenessSurfaceSource(options(input, fs));
    expect((await source.readProjection()).exit_code).toBe(0);
    expect((await source.readProjection()).exit_code).toBe(70);
    expect(read).toHaveBeenCalledTimes(1);
    release(); await vi.advanceTimersByTimeAsync(1);
    expect((await source.readProjection()).exit_code).toBe(0);
    expect(read).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
  });
  it("ignores a released flight's stale deadline callback", async () => {
    const input = base(), fs = filesystem(input), callbacks: (() => void)[] = [];
    const source = new LivenessSurfaceSource({ ...options(input, fs.fs), deadline: {
      after: (_ms, callback) => { callbacks.push(callback); return { cancel() {} }; },
    } });
    expect((await source.readProjection()).exit_code).toBe(0);
    callbacks[0]!();
    expect((await source.readProjection()).exit_code).toBe(0);
    expect(fs.opens()).toBe(10);
  });
  it.each(["healthy", "incomplete", "refused"])("preserves the envelope and one read for %s evidence", async kind => {
    const input = base();
    if (kind === "incomplete") record(input, "daemon").raw.lock_recovery = { state: "not_instrumented" };
    if (kind === "refused") record(input, "observer").subject.fortress_id = "another-fortress";
    const owner = process.getuid!() + (kind === "refused" ? 1 : 0);
    const a = filesystem(input, undefined, owner), b = filesystem(input, undefined, owner);
    const old = await readAndEvaluateLiveness(options(input, a.fs));
    const result = await readAndEvaluateLivenessWithInput(options(input, b.fs));
    expect(result.envelope).toEqual(old);
    expect(result.envelope).toEqual(evaluateLiveness(result.input));
    expect(b.opens()).toBe(a.opens()); expect(b.reads()).toBe(a.reads());
    expect(b.opens()).toBe(kind === "refused" ? 1 : 5); expect(b.reads()).toBe(kind === "refused" ? 0 : 6);
    expect(() => { result.input.nowMs++; }).toThrow();
    expect(() => { result.input.directory.status = "ok"; }).toThrow();
    if (kind !== "refused") expect(() => { record(result.input, "observer").sequence++; }).toThrow();
    if (kind === "healthy") expect(old.wall.state).toMatch(/^wall_OK_/);
    if (kind === "incomplete") expect(old.wall.reasons).toContain("evidence_incomplete");
    if (kind === "refused") expect(old.wall.alarm).toBe(true);
  });
  it("captures the evaluation clock after record reads", async () => {
    const input = base(); let now = input.nowMs;
    const fs = filesystem(input, () => { now += SECOND; });
    const result = await readAndEvaluateLivenessWithInput({ ...options(input, fs.fs), nowMs: () => now });
    expect(result.input.nowMs).toBe(input.nowMs + fs.opens() * SECOND);
    expect(result.envelope.evaluated_at).toBe(new Date(result.input.nowMs).toISOString());
  });
  it("preserves invalid-record refusal without freezing the clock provider", async () => {
    const input = base();
    // Five thousand JSON arrays occupy ten thousand bytes, below the record cap but beyond a recursive clone's stack.
    const serialized = JSON.stringify(record(input, "observer")).slice(0, -1) + ',"unexpected":' + "[".repeat(5000) + "null" + "]".repeat(5000) + "}";
    (input.observer as { value: unknown }).value = JSON.parse(serialized);
    const expected = evaluateLiveness(input), fs = filesystem(input, undefined, process.getuid!(), new Map([["observer", serialized]]));
    const result = await readAndEvaluateLivenessWithInput(options(input, fs.fs));
    expect(result.envelope).toEqual(expected);
    expect(result.envelope.wall.alarm).toBe(true);
    expect(Object.isFrozen(input.host)).toBe(false);
    expect(Object.isFrozen(result.input.host)).toBe(true);
    expect(Object.isFrozen(record(result.input, "observer").unexpected)).toBe(true);
  });
  it("shares a thousand concurrent callers and starts a fresh read after settlement", async () => {
    const input = base(), fs = filesystem(input); const source = new LivenessSurfaceSource(options(input, fs.fs));
    const schedule = vi.spyOn(browserContract, "buildLivenessSchedule");
    const values = await Promise.all(Array.from({ length: 1000 }, () => source.readProjection()));
    expect(schedule).toHaveBeenCalledTimes(1);
    expect(fs.opens()).toBe(5); expect(new Set(values.map(v => JSON.stringify(v))).size).toBe(1);
    await source.readProjection(); expect(fs.opens()).toBe(10);
    expect(schedule).toHaveBeenCalledTimes(2);
  });
  it.each(["open", "stat", "read", "close", "host"] as const)("holds admission across a hundred deadline waves with a detached %s", async operation => {
    vi.useFakeTimers(); const input = base(); const backing = filesystem(input);
    let release!: () => void, calls = 0;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const fs: ReaderFs = { open: async (path, flags) => {
      if (path.endsWith("daemon.json")) {
        calls++;
        if (operation === "open") await gate;
        const handle = await backing.fs.open(path, flags);
        if (operation === "stat") return { ...handle, stat: async () => { await gate; return handle.stat(); } };
        if (operation === "read") return { ...handle, read: async (...args) => { await gate; return handle.read(...args); } };
        if (operation === "close") return { ...handle, close: async () => { await gate; return handle.close(); } };
        return handle;
      }
      return backing.fs.open(path, flags);
    } };
    const source = new LivenessSurfaceSource({ ...options(input, fs),
      host: { read: async () => { if (operation === "host") await gate; return input.host; } } });
    const initial = source.readProjection();
    await vi.advanceTimersByTimeAsync(STATUS_READ_DEADLINE);
    expect((await initial).exit_code).toBe(70);
    for (let wave = 0; wave < 100; wave++) {
      const waiting = Promise.all(Array.from({ length: 10 }, () => source.readProjection()));
      await vi.advanceTimersByTimeAsync(STATUS_READ_DEADLINE);
      const results = await waiting;
      expect(results.every(v => v.exit_code === 70)).toBe(true);
      expect(calls).toBe(1);
    }
    release(); await vi.advanceTimersByTimeAsync(1);
    const fresh = await source.readProjection(); expect(fresh.exit_code).toBe(0); expect(calls).toBe(2);
  });
});

describe("conservative evaluator schedule", () => {
  it("keeps newer complete reasons at an equal severity collision", () => {
    const p = projection(caseInput(cases.find(c => c.name === "equal severity collision")!));
    expect(p.wall.reasons).toEqual(["evidence_incomplete"]);
    expect(select(p, 0).wall).toEqual({ state: "wall_DOWN", alarm: true,
      reasons: ["canary_unprovisioned", "evidence_incomplete"], cause: null });
    expect(select(p, 0).exit_code).toBe(1);
  });
  it("keeps TTL warning above degraded at a wall collision", () => {
    const p = projection(caseInput(cases.find(c => c.name === "TTL warning collision")!));
    expect(p.wall.state).toBe("wall_DEGRADED");
    expect(select(p, 0).wall).toEqual({ state: "wall_TTL_WARNING", alarm: true,
      reasons: ["recent_restart", "ttl_expiring"], cause: null });
    expect(select(p, 0).exit_code).toBe(3);
  });
  it("keeps unavailable coverage at an adjacent collision", () => {
    const p = projection(caseInput(cases.find(c => c.name === "coverage collision")!));
    expect(select(p, 2000).coverage).toEqual({ state: "coverage_UNAVAILABLE", alarm: true,
      reasons: ["canary_unprovisioned"], cause: null });
  });
  it.each(cases)("keeps complete verdicts and bounded precedence for $name", row => {
    const input = caseInput(row), p = projection(input);
    expect(p.schedule.length).toBeLessThanOrEqual(2 * SCHEDULE_STEPS + 1);
    const evaluations = Array.from({ length: SCHEDULE_STEPS + 1 }, (_, k) => verdicts(evaluateLiveness(advance(input, k * LOCAL_JITTER))));
    for (const entry of p.schedule) {
      for (const component of components) expect(evaluations.some(v => JSON.stringify(v[component]) === JSON.stringify(entry.projection[component]) &&
        (component !== "wall" || v.exit_code === entry.projection.exit_code))).toBe(true);
      if (entry.projection.wall.state === "wall_DOWN") { expect(entry.projection.exit_code).toBe(1); expect(entry.projection.wall.reasons).not.toEqual(["none"]); }
    }
    // A deterministic coprime walk samples a thousand distinct instants across the entire horizon.
    for (let i = 0; i < 1000; i++) {
      const t = (i * 7919) % (SCHEDULE_STEPS * LOCAL_JITTER + 1);
      const shown = select(p, t), actual = verdicts(evaluateLiveness(advance(input, t)));
      for (const component of components) {
        expect(rank(component, shown[component].state)).toBeGreaterThanOrEqual(rank(component, actual[component].state));
        if (rank(component, shown[component].state) > rank(component, actual[component].state)) {
          const future = verdicts(evaluateLiveness(advance(input, t + LOCAL_JITTER)));
          const past = verdicts(evaluateLiveness(advance(input, Math.max(0, t - LOCAL_JITTER))));
          expect(rank(component, shown[component].state)).toBeLessThanOrEqual(Math.max(rank(component, future[component].state), rank(component, past[component].state)));
        }
      }
    }
  });
  it("preserves agent DOWN at an adjacent improvement collision", () => {
    const p = projection(caseInput(cases.find(c => c.name === "adjacent collision")!));
    expect(p.wall.state).toBe("wall_DEGRADED"); expect(p.agent.state).toBe("agent_DEGRADED_STALE_MCP");
    for (const t of [3001, 4000, 10000]) expect(select(p, t).agent.state).toBe("agent_DOWN");
    expect(select(p, 999).wall.state).toBe("wall_DEGRADED");
  });
  it("always emits a stale terminal entry even for zero-age evidence", () => {
    const input = base(), observer = record(input, "observer");
    observer.observed_at = new Date(input.nowMs).toISOString(); observer.observed_uptime_ms = input.host.ok ? input.host.uptimeMs : 0;
    observer.collection = { started_at_ms: input.nowMs, ended_at_ms: input.nowMs };
    observer.raw.canary_integrity.checked_at_ms = input.nowMs; observer.raw.availability.resolved_at_ms = input.nowMs;
    const schedule = buildLivenessSchedule(input);
    expect(SCHEDULE_STEPS).toBe(Math.floor(OBSERVER_WINDOW / LOCAL_JITTER) + 1);
    expect(SCHEDULE_STEPS * LOCAL_JITTER).toBeGreaterThan(OBSERVER_WINDOW); expect(DISPLAY_PERIOD).toBe(SECOND);
    expect(schedule[0]!.after_ms).toBe(0); expect(schedule.at(-1)!.after_ms).toBe(SCHEDULE_STEPS * LOCAL_JITTER);
    expect(schedule.at(-1)!.projection.wall.state).toBe("wall_DOWN"); expect(schedule.at(-1)!.projection.agent.state).not.toMatch(/^agent_OK_/);
    expect(schedule.at(-1)!.projection.coverage.state).toBe("coverage_UNAVAILABLE");
  });
});

function browser(script: string) {
  let now = 0, perf = 0, painted: LivenessVerdicts | undefined;
  const intervals: { fn: () => void; ms: number }[] = []; const listeners: Record<string, () => void> = {};
  const elements = new Map<string, any>();
  const element = () => ({ textContent: "", innerHTML: "", style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {}, addEventListener() {}, appendChild() {}, querySelectorAll: () => [], querySelector: () => null });
  const document = { body: { appendChild(e: any) { elements.set(e.id, e); } }, documentElement: element(),
    getElementById: (id: string) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    createElement: element, querySelectorAll: () => [], querySelector: () => element(),
    addEventListener: (event: string, fn: () => void) => { listeners[event] = fn; } };
  const context = vm.createContext({ Date: class extends Date { static override now() { return now; } }, performance: { now: () => perf },
    document, window: { addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) },
    location: { hash: "", search: "", pathname: "/posture/agent/fixture", origin: "http://fixture" },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} }, localStorage: { getItem: () => null, setItem() {} },
    URL, URLSearchParams, AbortController, Headers, TextDecoder, TextEncoder, console: { error() {}, warn() {}, log() {} },
    fetch: () => new Promise(() => {}), setTimeout: () => 0, clearTimeout() {}, clearInterval() {},
    setInterval: (fn: () => void, ms: number) => { intervals.push({ fn, ms }); return 0; },
  });
  const visibleScript = script.replace("function renderWall(w)", "globalThis.renderWall = function renderWall(w)");
  script = visibleScript;
  const closure = script.lastIndexOf("})();");
  const mounted = script.trimStart().startsWith("(function")
    ? script.slice(0, closure) + "globalThis.mountedLiveness = livenessDisplay;\n" + script.slice(closure)
    : script + "\nglobalThis.mountedLiveness = livenessDisplay;";
  vm.runInContext(mounted, context);
  // Exercise the exact embedded factory as well as the actual mount's timer and visibility hook.
  (context as any).capture = (v: LivenessVerdicts) => { painted = v; };
  vm.runInContext("globalThis.testDisplay = createLivenessDisplay(capture)", context);
  const display = (context as any).testDisplay;
  return { install: (p: LivenessProjection) => { display.install(p); (context as any).mountedLiveness.install(p); },
    tick: (date: number, performance: number) => { now = date; perf = performance; display.render(); for (const timer of intervals.filter(t => t.ms === DISPLAY_PERIOD)) timer.fn(); },
    shown: () => painted!, intervals, listeners, context, elements };
}
const shipped = [
  ["dashboard", () => getClientScript()],
  ["posture home", () => renderPostureHomeHTML().match(/<script>[\s\S]*?<\/script>/g)!.find(s => s.includes(LIVENESS_SCHEDULE_FN_SOURCE))!.replace(/^<script>|<\/script>$/g, "")],
  ["posture agent", () => renderPostureAgentHTML().match(/<script>[\s\S]*?<\/script>/g)!.find(s => s.includes(LIVENESS_SCHEDULE_FN_SOURCE))!.replace(/^<script>|<\/script>$/g, "")],
] as const;
describe("shipped browser clocks", () => {
  it.each(shipped)("expires and accepts only newer evaluation lifetimes in %s", (_name, source) => {
    const script = source(); expect(script).toContain(LIVENESS_SCHEDULE_FN_SOURCE);
    // Keep the embedded functions visible after the page IIFE exits.
    const exposed = script.replace("function createLivenessDisplay(paint)", "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
    for (const row of cases) {
      const scheduled = projection(caseInput(row)), page = browser(exposed);
      page.install(scheduled);
      const instants = [...new Set([...scheduled.schedule.map(entry => entry.after_ms),
        ...Array.from({ length: 1000 }, (_, i) => (i * 7919) % (SCHEDULE_STEPS * LOCAL_JITTER + 1))])].sort((a, b) => a - b);
      for (const t of instants) {
        page.tick(t, 0);
        expect(page.shown()).toEqual(select(scheduled, t));
        for (const component of components) expect(page.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="' + select(scheduled, t)[component].state + '"');
      }
    }
    const performancePage = browser(exposed); performancePage.install(projection());
    performancePage.tick(0, SCHEDULE_STEPS * LOCAL_JITTER);
    expect(performancePage.shown().wall.state).toBe("wall_DOWN");
    const b = browser(exposed), p = projection();
    const intervalsBeforeEvidence = b.intervals.length;
    b.install(p);
    expect(b.intervals.length).toBe(intervalsBeforeEvidence + 1);
    expect(b.intervals.some(t => t.ms === DISPLAY_PERIOD)).toBe(true); expect(b.listeners.visibilitychange).toBeTypeOf("function");
    let refreshed = p, refreshedAt = 0;
    for (let t = 0; t <= 2 * OBSERVER_WINDOW; t += DISPLAY_PERIOD) {
      b.tick(t, t);
      if (t % (5 * SECOND) === 0) {
        const input = advance(base(), t);
        refreshed = project(evaluateLiveness(input), input, input.nowMs);
        refreshedAt = t;
        b.install(refreshed);
      }
      expect(b.shown()).toEqual(select(refreshed, t - refreshedAt));
    }
    b.install(p); b.tick(2 * OBSERVER_WINDOW, 2 * OBSERVER_WINDOW); expect(b.shown()).toEqual(select(refreshed, 2 * OBSERVER_WINDOW - refreshedAt));
    const fresh = projection(); fresh.evaluated_at = new Date(base().nowMs + 3 * OBSERVER_WINDOW).toISOString();
    b.install(fresh); expect(b.shown().wall.state).toMatch(/^wall_OK_/);
    for (let i = 0; i < 100; i++) { b.tick(2 * OBSERVER_WINDOW + i * SECOND, 2 * OBSERVER_WINDOW); b.install(fresh); }
    expect(b.intervals.length).toBe(intervalsBeforeEvidence + 1);
    expect(b.shown().wall.state).toBe("wall_DOWN");
    expect(b.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="wall_DOWN"');
    const aged = { ...fresh, evaluated_at: new Date(base().nowMs + 4 * OBSERVER_WINDOW).toISOString(), served_age_ms: OBSERVER_WINDOW + 1 };
    b.install(aged); expect(b.shown().wall.state).toBe("wall_DOWN");
    b.install(fresh); expect(b.shown().wall.state).toBe("wall_DOWN");
    b.tick(0, 0); expect(b.shown().wall.state).toBe("wall_DOWN");
    b.install({ ...projection(), evaluated_at: "2026-11-09T12:00:00" });
    expect(b.shown().wall.state).toBe("wall_DOWN");
    b.listeners.visibilitychange!();
    expect(b.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="wall_DOWN"');
  });
});

function response() {
  let body = "", status = 0;
  return { res: { writeHead(code: number) { status = code; }, end(value: string) { body = value; }, on() {}, once() {}, off() {} } as unknown as ServerResponse,
    json: () => JSON.parse(body), status: () => status };
}
function request(path: string) { return { url: path, method: "GET", headers: { authorization: "Bearer fixture-token" }, once() {}, off() {} } as unknown as IncomingMessage; }
function postureDeps(source: LivenessSurfaceSource): PostureRouteDeps {
  return { auditLog: new AuditLog(new MemoryStorage(), new Uint8Array(32)), originMachine: "fixture", listAgents: () => [],
    detectInstalledHarnesses: async () => [], readFlightMap: createDashboardReadFlightMap(), panelStore: createPosturePanelStore(), livenessSource: source };
}
describe("component surface parity", () => {
  it("shows a failed audit integrity gate beside a healthy wall badge", async () => {
    const input = base(), deps = postureDeps(new LivenessSurfaceSource(options(input, filesystem(input).fs)));
    deps.resolvePinnedProducerKey = () => null;
    deps.resolveBrokerPinnedProducerKey = () => null;
    const verdict = vi.spyOn(deps.auditLog!, "getAuditChainVerdict").mockResolvedValue({ status: "findings", findings: [{ kind: "entry_hash_mismatch" }] } as never);
    const home = await buildHome(deps);
    expect(verdict).toHaveBeenCalled();
    expect(home.castle_wall.audit_integrity_ok).toBe(false);
    expect(home.castle_wall_liveness!.wall.state).toBe("wall_OK_IDLE");
    const script = shipped[1][1]().replace("function createLivenessDisplay(paint)", "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
    const page = browser(script);
    (page.context as any).renderWall(home.castle_wall);
    page.install(home.castle_wall_liveness!);
    expect(page.elements.get("wall").innerHTML).toContain("Audit integrity finding present");
    expect(page.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="wall_OK_IDLE"');
    expect(page.elements.get("castle-wall-liveness").innerHTML).toContain("Healthy, idle");
  });

  it("reads configured fortress evidence through the dashboard posture routes", async () => {
    const path = mkdtempSync(join(tmpdir(), "posture-liveness-"));
    mkdirSync(join(path, "liveness"), { mode: 0o700 });
    const input = base();
    input.local.fortress_id = livenessFortressId(path);
    for (const name of ["daemon", "observer"] as const) record(input, name).subject.fortress_id = input.local.fortress_id;
    const read = readerModule.readAndEvaluateLivenessWithInput;
    vi.spyOn(readerModule, "readAndEvaluateLivenessWithInput").mockImplementation(opts => read({ ...opts,
      platform: "darwin", host: { read: async () => input.host }, nowMs: () => input.nowMs }));
    for (const name of ["daemon", "observer", "config"] as const) {
      writeFileSync(join(path, "liveness", name + ".json"), JSON.stringify(record(input, name)), { mode: 0o600 });
    }
    const open = vi.spyOn(nodeReaderFs, "open");
    const rig = await startRig();
    (rig.dashboard as any)._sanctuaryConfig = { storage_path: path };
    (rig.dashboard as any).baseline = null;
    try {
      for (const route of ["/api/posture/home", "/api/posture/feature-health"]) {
        open.mockClear();
        const response = await fetch(rig.baseUrl + route, { headers: { Authorization: `Bearer ${rig.authToken}` } });
        expect(response.status).toBe(200);
        const body = await response.json() as any;
        for (const component of components) expect(body.castle_wall_liveness[component]).toEqual(projection(input)[component]);
        expect(open.mock.calls.map(call => call[0])).toContain(join(path, "liveness", "observer.json"));
      }
    } finally { await rig.stop(); }
  });

  it.each(["healthy", "agent down", "observer stale"])("carries the same independent verdicts through consumers for %s", async kind => {
    let input = base(); if (kind === "agent down") record(input, "observer").raw.gateway.alive = false;
    if (kind === "observer stale") input = advance(input, OBSERVER_WINDOW + 1);
    const fs = filesystem(input), source = new LivenessSurfaceSource(options(input, fs.fs)), expected = projection(input);
    const same = (p: LivenessProjection) => { for (const c of components) expect(p[c]).toEqual(expected[c]); expect(p.exit_code).toBe(expected.exit_code); };
    let text = ""; const out = new Writable({ write(chunk, _enc, done) { text += chunk; done(); } });
    await runLivenessStatus(["--json", "--fortress", fortressPath], { out, platform: "darwin", getuid: process.getuid, now: () => input.nowMs, hostClock: { read: async () => input.host }, readerFs: fs.fs });
    const envelope = JSON.parse(text); same(project(envelope, input, input.nowMs));
    for (const c of components) expect(formatLivenessLines(envelope)).toContain(expected[c].state);
    expect(wallOnlyStatusExit(envelope)).toBe(expected.exit_code);
    const liveness = { getuid: process.getuid, now: () => input.nowMs, hostClock: { read: async () => input.host }, readerFs: fs.fs };
    const { runStatus } = await import("../../../src/cli/castle-wall.js");
    text = "";
    expect(await runStatus(["--fortress", fortressPath], { out, platform: "darwin", env: {}, liveness,
      execSyncFn: () => "", hostAppCandidates: [], globalPinReader: async () => { throw Object.assign(new Error("absent"), { code: "ENOENT" }); },
      enforcementAvailabilityQuery: async () => ({ status: "undetermined", reason: "fixture", observed_at: null, freshness_window_ms: OBSERVER_WINDOW, active_connection_count: 0 }),
    })).toBe(expected.exit_code);
    expect(text).toContain(formatLivenessLines(envelope));
    const full = await import("../../../src/cli/castle-wall-full-agent.js");
    const syncFs = await import("node:fs");
    const args = ["/fixture/node", "/fixture/cli.js", "castle-wall", "daemon", "--fortress", fortressPath, "--launch-agent"];
    const plist = full.generateFullAgentPlist(args);
    text = "";
    expect(await full.runFullStatus(["--fortress", fortressPath], { out, platform: "darwin", home: "/fixture/home", euid: process.getuid!(), liveness,
      fs: { ...syncFs, readFileSync: () => plist, realpathSync: (path: string) => path } as never,
      stateStore: () => ({ read: () => null }) as never,
      execFileFn: () => ({ code: 0, stderr: "", stdout: `gui/${process.getuid!()}/${full.FULL_AGENT_LABEL} = {\nstate = running\npid = 4242\narguments = {\n${args.join("\n")}\n}\n}\n` }),
    })).toBe(expected.exit_code);
    expect(text).toContain(formatLivenessLines(envelope));
    const doctor = await checkCastleWallLiveness({ storagePath: fortressPath, platform: "darwin", livenessSource: source, livenessDirectoryExists: async () => true });
    for (const c of components) expect(doctor.find(d => d.name.endsWith(`(${c})`))!.message).toContain(expected[c].state);
    expect(doctor[0]!.status).toBe(kind === "observer stale" ? "FAIL" : "OK");
    expect(doctor[1]!.status).toBe(kind === "healthy" ? "OK" : "WARN");
    const deps = postureDeps(source), home = await buildHome(deps); same(home.castle_wall_liveness!);
    expect(home.castle_wall.audit_integrity_ok).toBe(false);
    const apiDeps: APIDeps = { sources: { mode: "co-located", server_version: "fixture" }, authToken: "fixture-token", readFlightMap: deps.readFlightMap, panelStore: deps.panelStore, livenessSource: source };
    const res = response(); await handleRequest(apiDeps, request("/api/status"), res.res); same(res.json().castle_wall_liveness);
    const health = response(); await handlePostureRoute(deps, request("/api/posture/feature-health"), health.res, new URL("http://fixture/api/posture/feature-health"), "GET");
    same(health.json().castle_wall_liveness);
    expect(health.json().liveness_rows.map((row: any) => row.state)).toEqual(components.map(c => expected[c].state));
    const rig = await startRig({ withOperatorIdentity: true });
    (rig.dashboard as any).baseline = null;
    vi.spyOn(LivenessSurfaceSource.prototype, "readProjection").mockImplementation(() => Promise.resolve(expected));
    try {
      const token = await openDurableSession(rig);
      for (const [path, auth] of [["/v1/status", token], ["/api/status", rig.authToken]]) {
        const result = await fetch(rig.baseUrl + path, { headers: { Authorization: `Bearer ${auth}` } });
        const body = await result.json() as Record<string, any>; same(body.castle_wall_liveness);
        if (path === "/v1/status") for (const c of components) expect(renderTable(body)).toContain(expected[c].state);
      }
    } finally { await rig.stop(); }
    if (kind === "agent down") { expect(expected.wall.state).toMatch(/^wall_OK_/); expect(expected.agent.state).toBe("agent_DOWN"); }
    if (kind === "observer stale") expect(expected.wall.reasons).toContain("observer_stale");
  });
  it("re-reads liveness beside a stale panel after a producer failure", async () => {
    const input = base(), source = new LivenessSurfaceSource(options(input, filesystem(input).fs));
    const deps = postureDeps(source); const first = await buildHome(deps);
    expect(first.castle_wall_liveness!.wall.state).toMatch(/^wall_OK_/);
    input.nowMs += 10 * 60 * SECOND; if (input.host.ok) input.host.uptimeMs += 10 * 60 * SECOND;
    deps.listAgents = () => { throw new Error("producer unavailable"); };
    const stale = await buildHome(deps);
    expect(stale.castle_wall_liveness!.wall.state).toBe("wall_DOWN");
    expect(stale.castle_wall_liveness!.wall.reasons).toContain("observer_stale");
    expect((deps.panelStore as any).castle_wall_liveness).toBeUndefined();
  });
});
