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
import { LIVENESS_STATES, HTTP_BODY_BYTES, STATUS_BYTES, LIVENESS_SEVERITY_ORDER, AGENT_WINDOW_BASE, HISTORY_WINDOW, OBSERVER_WINDOW, LOCAL_JITTER, SCHEDULE_STEPS, DISPLAY_PERIOD, SECOND, STATUS_READ_DEADLINE } from "../../../src/castle-wall/liveness/constants.js";
import { buildLivenessBadges, renderLivenessBadges, LIVENESS_BADGE_FN_SOURCE } from "../../../src/principal-policy/posture.js";
import { renderDashboardV11Html } from "../../../src/dashboard/v1_1/html.js";
import { defaultConfig } from "../../../src/config.js";
import { createFixtureLivenessSource } from "../../helpers/fixture-liveness-source.js";
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
// Script blocks of the pages' own rendered markup, located by index rather than by a stripping regex, so a tag's case or attributes never hide a block.
function scriptBlocks(markup: string): { start: number; end: number; body: string }[] {
  const lower = markup.toLowerCase(), blocks: { start: number; end: number; body: string }[] = [];
  for (let start = lower.indexOf("<script"); start !== -1; start = lower.indexOf("<script", start + 1)) {
    const open = lower.indexOf(">", start), close = lower.indexOf("</script", open);
    if (open === -1 || close === -1) throw new Error("unterminated script block in rendered markup");
    const end = lower.indexOf(">", close);
    if (end === -1) throw new Error("unterminated script close tag in rendered markup");
    blocks.push({ start, end: end + 1, body: markup.slice(open + 1, close) }); start = end;
  }
  return blocks;
}
function withoutScripts(markup: string): string {
  let out = "", from = 0;
  for (const block of scriptBlocks(markup)) { out += markup.slice(from, block.start); from = block.end; }
  return out + markup.slice(from);
}

const fixture = JSON.parse(readFileSync(join(__dirname, "fixtures/states.json"), "utf8"));
const cases: { name: string; charge_remaining_ms?: number; census_remaining_ms?: number; patches: { path: string; value?: unknown; offset_ms?: number }[] }[] =
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
    let target: any = input; for (const key of keys) target = target[key]; target[last] = patch.offset_ms === undefined ? patch.value : input.nowMs + patch.offset_ms;
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
// Deliberately hand-written rather than imported: the sweep must remain independent of production precedence.
const oracleOrder = {
  wall: ["OK", "RECOVERING", "DEGRADED", "TTL_WARNING"],
  agent: ["OK", "RECOVERING", "DEGRADED_STALE_MCP", "INITIALIZING", "DOWN", "UNMONITORED"],
  coverage: ["COMPLETE", "WALL_ONLY", "LEGACY_PARTIAL", "UNAVAILABLE"],
};
function rank(component: typeof components[number], state: string): number {
  const order = oracleOrder[component];
  const name = state.slice(component.length + 1); const i = order.indexOf(name.startsWith("OK_") ? "OK" : name);
  return i < 0 ? order.length : i;
}
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe("shared reader snapshot", () => {
  it("keeps fixture host evidence unavailable", async () => {
    const evaluate = vi.spyOn(await import("../../../src/castle-wall/liveness/evaluate.js"), "evaluateLiveness");
    const result = await createFixtureLivenessSource().readProjection();
    expect(evaluate.mock.calls[0]![0].host.ok).toBe(false);
    expect(result.wall.alarm).toBe(true);
  });
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
    for (const value of values) {
      const pending: unknown[] = [value.wall, value.agent, value.coverage, value.schedule];
      while (pending.length > 0) {
        const next = pending.pop();
        if (next === null || typeof next !== "object") continue;
        expect(Object.isFrozen(next)).toBe(true);
        pending.push(...Object.values(next));
      }
    }
    expect(() => { values[0]!.schedule[0]!.projection.wall.reasons.push("changed"); }).toThrow();
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
    expect(HTTP_BODY_BYTES).toBe(STATUS_BYTES);
    expect(SCHEDULE_STEPS).toBe(Math.floor(OBSERVER_WINDOW / LOCAL_JITTER) + 1);
    expect(SCHEDULE_STEPS * LOCAL_JITTER).toBeGreaterThan(OBSERVER_WINDOW); expect(DISPLAY_PERIOD).toBe(SECOND);
    expect(schedule[0]!.after_ms).toBe(0); expect(schedule.at(-1)!.after_ms).toBe(SCHEDULE_STEPS * LOCAL_JITTER);
    expect(schedule.at(-1)!.projection.wall.state).toBe("wall_DOWN"); expect(schedule.at(-1)!.projection.agent.state).not.toMatch(/^agent_OK_/);
    expect(schedule.at(-1)!.projection.coverage.state).toBe("coverage_UNAVAILABLE");
  });
});

function browser(script: string, html = renderPostureHomeHTML(), route?: "overview" | "first run" | "enforcement") {
  let now = 0, perf = 0, painted: LivenessVerdicts | undefined;
  const intervals: { fn: () => void; ms: number }[] = []; const listeners: Record<string, () => void> = {};
  const elements = new Map<string, any>();
  function declare(markup: string) {
    for (const match of withoutScripts(markup).matchAll(/\bid="([^"]+)"/g)) {
      if (!elements.has(match[1]!)) elements.set(match[1]!, element());
    }
  }
  const element = () => ({ textContent: "", _html: "",
    get innerHTML() { return this._html; }, set innerHTML(value: string) { this._html = value; declare(value); }, style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {}, addEventListener() {}, appendChild() {}, querySelectorAll: () => [], querySelector: () => null });
  declare(html);
  const document = { body: { appendChild(e: any) { elements.set(e.id, e); } }, documentElement: element(),
    getElementById: (id: string) => elements.get(id) ?? null,
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
  script = script.replace(/(?<!globalThis.createLivenessDisplay = )function createLivenessDisplay\(paint\)/, "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
  const visibleScript = script.replace("function renderWall(w)", "globalThis.renderWall = function renderWall(w)");
  script = visibleScript;
  const closure = script.lastIndexOf("})();");
  const mounted = script.trimStart().startsWith("(function")
    ? script.slice(0, closure) + "globalThis.mountedLiveness = livenessDisplay;\n" + script.slice(closure)
    : script + "\nglobalThis.mountedLiveness = livenessDisplay;";
  vm.runInContext(mounted, context);
  if (route) {
    (context as any).routeName = route === "enforcement" ? "enforcement" : "posture";
    (context as any).firstRun = route === "first run";
    vm.runInContext(`
      sourceReads.forEach(function(read) { read.state = "state_LOADED"; });
      state.posture.home = { agents: firstRun ? [] : [{ agent_id: "fixture", harness: "fixture" }], castle_wall: {}, unwrapped: [] };
      state.route = routeName;
      renderMain();
    `, context);
  }
  // Exercise the exact embedded factory as well as the actual mount's timer and visibility hook.
  (context as any).capture = (v: LivenessVerdicts) => { painted = v; };
  vm.runInContext("globalThis.testDisplay = createLivenessDisplay(capture)", context);
  const display = (context as any).testDisplay;
  return { install: (p: LivenessProjection) => { display.install(p); (context as any).mountedLiveness.install(p); },
    tick: (date: number, performance: number) => { now = date; perf = performance; display.render(); for (const timer of intervals.filter(t => t.ms === DISPLAY_PERIOD)) timer.fn(); },
    shown: () => painted!, intervals, listeners, context, elements };
}
const shipped = [
  ...(["overview", "first run", "enforcement"] as const).map(route =>
    ["dashboard " + route, () => getClientScript(), () => renderDashboardV11Html({ embedClient: false }), route] as const),
  ["posture home", () => scriptBlocks(renderPostureHomeHTML()).map(b => b.body).find(s => s.includes(LIVENESS_SCHEDULE_FN_SOURCE))!, renderPostureHomeHTML, undefined],
  ["posture agent", () => scriptBlocks(renderPostureAgentHTML()).map(b => b.body).find(s => s.includes(LIVENESS_SCHEDULE_FN_SOURCE))!, renderPostureAgentHTML, undefined],
] as const;
describe("liveness presentation contract", () => {
  it("matches the documented precedence order", () => {
    expect(oracleOrder).toEqual(LIVENESS_SEVERITY_ORDER);
  });
  it("ships browser badge source with only browser globals", () => {
    expect(LIVENESS_BADGE_FN_SOURCE).not.toMatch(/\b__\w+\b/);
    const contract = readFileSync(join(__dirname, "../../../src/castle-wall/liveness/browser-contract.ts"), "utf8");
    expect(contract).not.toContain("principal-policy/posture");
    const shell = renderDashboardV11Html({ embedClient: false });
    expect(shell).toContain(".pill.tone-verified { background: var(--sage-bg); color: var(--sage)");
    expect(shell).toContain(".pill.tone-unverified { background: var(--rust-bg); color: var(--rust)");
    const context = vm.createContext({});
    vm.runInContext(LIVENESS_BADGE_FN_SOURCE, context);
    for (const component of components) for (const state of [...LIVENESS_STATES[component], component + "_FUTURE", component + "_OK_FUTURE", component === "wall" ? "agent_OK_PASSIVE" : "wall_OK_IDLE"]) {
      for (const alarm of [false, true]) {
        const value = structuredClone(projection());
        Object.assign(value[component], { state, alarm, reasons: ['<reason & "detail">'] });
        expect((context as any).buildLivenessBadges(value)).toEqual(buildLivenessBadges(value));
        expect((context as any).renderLivenessBadges(value)).toBe(renderLivenessBadges(value));
      }
    }
  });
  it.each(shipped)("declares one scheduled badge mount in %s", (_name, source, markup, route) => {
    const page = browser(source(), markup(), route);
    const html = route ? page.elements.get("main").innerHTML : withoutScripts(markup());
    expect([...html.matchAll(/\bid="castle-wall-liveness"/g)]).toHaveLength(1);
    page.install(projection());
    expect(page.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="wall_OK_IDLE"');
  });
});
describe("shipped browser clocks", () => {
  it.each(shipped)("refuses malformed liveness projections in %s", (_name, source, markup, route) => {
    const script = source().replace("function createLivenessDisplay(paint)", "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
    const malformed = [
      (p: any) => { delete p.served_age_ms; }, (p: any) => { p.served_age_ms = NaN; },
      (p: any) => { p.served_age_ms = Infinity; }, (p: any) => { p.served_age_ms = -1; },
      (p: any) => { p.schedule = []; }, (p: any) => { p.schedule.length = 1; },
      (p: any) => { p.schedule.at(-1).projection = p.schedule[0].projection; }, (p: any) => { p.schedule[0] = null; },
      (p: any) => { p.schedule[0].after_ms = 1; }, (p: any) => { delete p.wall.reasons; },
      (p: any) => { delete p.schedule[0].projection.wall.reasons; },
      (p: any) => { p.schedule[0].projection = null; },
      ...components.flatMap(component => [
        (p: any) => { p[component].state = component + "_FUTURE"; p[component].alarm = false; },
        (p: any) => { p.schedule[0].projection[component].state = component + "_FUTURE"; p.schedule[0].projection[component].alarm = false; },
        (p: any) => { p[component].state = component === "wall" ? "agent_OK_PASSIVE" : "wall_OK_IDLE"; p[component].alarm = false; },
        (p: any) => { p.schedule[0].projection[component].state = component === "wall" ? "agent_OK_PASSIVE" : "wall_OK_IDLE"; p.schedule[0].projection[component].alarm = false; },
      ]),
    ];
    for (const damage of malformed) {
      const page = browser(script, markup(), route), valid = projection(), invalid = structuredClone(valid);
      page.install(valid); damage(invalid);
      expect(() => page.install(invalid)).not.toThrow();
      page.tick(SECOND, SECOND);
      expect(page.shown().wall.state).toBe("wall_DOWN");
      expect(page.shown().agent.state).toBe("agent_DOWN");
      expect(page.shown().coverage.state).toBe("coverage_UNAVAILABLE");
      expect(page.elements.get("castle-wall-liveness").innerHTML).toContain('data-state="wall_DOWN"');
    }
  });

  it.each(shipped)("expires and accepts only newer evaluation lifetimes in %s", (_name, source, markup, route) => {
    const script = source(); expect(script).toContain(LIVENESS_SCHEDULE_FN_SOURCE);
    // Keep the embedded functions visible after the page IIFE exits.
    const exposed = script.replace("function createLivenessDisplay(paint)", "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
    for (const row of cases) {
      const scheduled = projection(caseInput(row)), page = browser(exposed, markup(), route);
      page.install(scheduled);
      const instants = [...new Set([...scheduled.schedule.map(entry => entry.after_ms),
        ...Array.from({ length: 1000 }, (_, i) => (i * 7919) % (SCHEDULE_STEPS * LOCAL_JITTER + 1))])].sort((a, b) => a - b);
      for (const t of instants) {
        page.tick(t, 0);
        expect(page.shown()).toEqual(select(scheduled, t));
        for (const component of components) {
          const verdict = select(scheduled, t)[component];
          const healthy = !verdict.alarm && (verdict.state.includes("_OK_") || verdict.state === "coverage_COMPLETE");
          expect(page.elements.get("castle-wall-liveness").innerHTML).toContain(
            '<span class="pill ' + (healthy ? 'green tone-verified' : 'amber tone-unverified') +
            '" data-liveness-component="' + component + '" data-state="' + verdict.state + '"');
        }
      }
    }
    const performancePage = browser(exposed, markup(), route); performancePage.install(projection());
    performancePage.tick(0, SCHEDULE_STEPS * LOCAL_JITTER);
    expect(performancePage.shown().wall.state).toBe("wall_DOWN");
    const b = browser(exposed, markup(), route), p = projection();
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

function getHomeScript() {
  return shipped.find(([name]) => name === "posture home")![1]();
}

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
    const script = getHomeScript().replace("function createLivenessDisplay(paint)", "globalThis.createLivenessDisplay = function createLivenessDisplay(paint)");
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
    rig.dashboard.setDependencies({ policy: { version: 1, tier1_always_approve: [], tier3_auto_allow: [] } as never,
      baseline: null as never, auditLog: rig.auditLog, sanctuaryConfig: { ...defaultConfig(), storage_path: path } });
    try {
      for (const route of ["/api/posture/home", "/api/posture/feature-health"]) {
        open.mockClear();
        const response = await fetch(rig.baseUrl + route, { headers: { Authorization: `Bearer ${rig.authToken}` } });
        expect(response.status).toBe(200);
        const body = await response.json() as any;
        for (const component of components) expect(body.castle_wall_liveness[component]).toEqual(projection(input)[component]);
        expect(open.mock.calls.map(call => call[0])).toContain(join(path, "liveness", "observer.json"));
      }
      const controller = new AbortController();
      const stream = await fetch(rig.baseUrl + "/api/posture/stream", {
        headers: { Authorization: `Bearer ${rig.authToken}` }, signal: controller.signal,
      });
      expect(stream.status).toBe(200);
      const reader = stream.body!.getReader();
      try {
        let frame = "";
        while (!frame.includes("\n\n")) {
          const chunk = await reader.read();
          if (chunk.done) break;
          frame += new TextDecoder().decode(chunk.value);
        }
        const data = frame.split("\n").find(line => line.startsWith("data: "));
        const body = data ? JSON.parse(data.slice("data: ".length)) : {};
        expect(body.castle_wall_liveness).toEqual({ ...projection(input), served_age_ms: expect.any(Number) });
        expect(body.castle_wall_liveness.served_age_ms).toBeGreaterThanOrEqual(0);
        expect(frame).toContain("event: home");
      } finally { await reader.cancel(); controller.abort(); }
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
    expect(health.json()).not.toHaveProperty("liveness_rows");
    expect(home.feature_health).not.toHaveProperty("liveness_rows");
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
