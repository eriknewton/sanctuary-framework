/** Response release, cache and admission remain terminal under asynchronous faults. */
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import { InjectionDetector } from "../../src/security/injection-detector.js";
import { ResponseController, ResponseSession } from "../../src/proxy/response-runtime.js";
import { CallGovernor } from "../../src/operational/call-governor.js";
import { LocalPrivacyEngine, type PrivacyPolicy } from "../../src/operational/privacy-core.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { ResponseScreen } from "../../src/proxy/response-screen.js";
import { RequestResponseBindings } from "../../src/proxy/response-bounds.js";
import { RESPONSE_LIMITS as L } from "../../src/proxy/response-limits.js";

const text = (value: string) => ({ content: [{ type: "text", text: value }] });
const settleFixtures: Array<() => void> = [];
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r; }); settleFixtures.push(() => resolve(undefined as T)); return { promise, resolve }; }
const screens: ResponseScreen[] = [];
async function harness() {
  const controller = new ResponseController(); const screen = new ResponseScreen(new ResponseSession(controller));
  screens.push(screen); await screen.initialize();
  const manager = { getAllTools: () => new Map([["fixture", [{ name: "read", description: "fixture", inputSchema: { type: "object" } }]]]), getServerConfig: () => ({ default_tier: 3 }), callTool: vi.fn(async (_server?: string, _tool?: string, _args?: Record<string, unknown>) => text("hello")) };
  const audit = { append: vi.fn(async () => {}), appendCritical: vi.fn(async (_entry?: unknown) => {}) };
  const governor = new CallGovernor(); const cache = vi.spyOn(governor, "recordResult");
  const router = new ProxyRouter(manager as never, new InjectionDetector(), audit as never, screen, { governor });
  const handler = router.getProxiedTools()[0]!.handler;
  return { controller, screen, manager, audit, governor, cache, router, handler };
}
afterEach(async () => {
  vi.useRealTimers();
  // Even a failed assertion must settle injected work before draining real worker ownership.
  screens.forEach(screen => screen.stop());
  settleFixtures.splice(0).forEach(settle => settle());
  await Promise.all(screens.splice(0).map(screen => screen.close()));
});
describe("response fault schedules", () => {
  it("requires a ready response screen before proxy registration", () => {
    expect(() => new ProxyRouter({} as never, new InjectionDetector(), {} as never, undefined as never)).toThrow();
  });
  it("refuses a request already cancelled before dispatch", async () => {
    const h = await harness(); const abort = new AbortController(); abort.abort();
    expect(JSON.stringify(await h.handler({}, undefined, { signal: abort.signal }))).toContain("Operation not permitted");
    expect(h.manager.callTool).not.toHaveBeenCalled();
  });
  it.each([ErrorCode.InvalidParams, ErrorCode.InvalidRequest])("SDK protocol refusal %s has a fixed upstream reason without response bytes", async code => {
    const h = await harness();
    h.manager.callTool.mockRejectedValue(new McpError(code, "private-upstream-protocol-marker"));
    const result = await h.handler({});
    expect(JSON.stringify(result)).toContain("Operation not permitted");
    expect(h.audit.appendCritical).toHaveBeenCalledWith(expect.objectContaining({ details: expect.objectContaining({ reason: "withhold_upstream_failure" }) }));
    expect(JSON.stringify([result, h.audit.appendCritical.mock.calls])).not.toContain("private-upstream-protocol-marker");
  });
  it("cancellation during context gating never dispatches upstream", async () => {
    const h = await harness(); const gate = deferred<Record<string, unknown>>();
    (h.router as unknown as { options: { contextGateFilter: unknown } }).options.contextGateFilter = () => gate.promise;
    const abort = new AbortController(); const result = h.handler({}, undefined, { signal: abort.signal });
    abort.abort(); gate.resolve({});
    expect(JSON.stringify(await result)).toContain("Operation not permitted");
    expect(h.manager.callTool).not.toHaveBeenCalled();
    expect(h.audit.appendCritical).toHaveBeenCalledWith(expect.objectContaining({ details: expect.objectContaining({ reason: "withhold_cancelled" }) }));
  });
  it("reserves before governor lookup and dispatch", async () => {
    const h = await harness(); const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
    const check = vi.spyOn(h.governor, "check");
    const a = h.handler({ a: 1 }); const b = h.handler({ a: 2 });
    expect(JSON.stringify(await h.handler({ a: 3 }))).toContain("Operation not permitted");
    expect(h.audit.appendCritical).toHaveBeenCalledWith(expect.objectContaining({ details: expect.objectContaining({ reason: "withhold_capacity" }) }));
    expect(check).toHaveBeenCalledTimes(L.ACTIVE_PER_SESSION); expect(h.manager.callTool).toHaveBeenCalledTimes(L.ACTIVE_PER_SESSION);
    work.resolve(text("hello")); await Promise.all([a, b]); h.governor.clearResponseCache();
  });
  it("never caches or releases after timeout even when upstream completes later", async () => {
    const h = await harness(); vi.useFakeTimers();
    for (let wave = 0; wave < 3; wave++) {
      const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
      const calls = [h.handler({ wave, n: 0 }), h.handler({ wave, n: 1 })];
      await vi.advanceTimersByTimeAsync(30_001);
      for (const call of calls) expect(JSON.stringify(await call)).toContain("Operation not permitted");
      expect(h.audit.appendCritical).toHaveBeenCalledWith(expect.objectContaining({ details: expect.objectContaining({ reason: "withhold_upstream_timeout" }) }));
      expect(h.controller.snapshot().active).toBe(L.ACTIVE_PER_SESSION);
      expect(JSON.stringify(await h.handler({ wave, n: 2 }))).toContain("Operation not permitted");
      work.resolve(text("late")); await work.promise; await Promise.resolve();
      expect(h.controller.snapshot().active).toBe(0); expect(h.cache).not.toHaveBeenCalled();
      expect(h.screen.session.exposure.tainted).toBe(true);
    }
  });
  it("cancels during critical audit without late release or cache mutation", async () => {
    const h = await harness(); const work = deferred<void>(); h.audit.appendCritical.mockReturnValue(work.promise);
    const abort = new AbortController(); const result = h.handler({}, undefined, { signal: abort.signal });
    await vi.waitFor(() => expect(h.audit.appendCritical).toHaveBeenCalled());
    abort.abort(); expect(JSON.stringify(await result)).toContain("Operation not permitted");
    expect(h.controller.snapshot().active).toBe(1); expect(h.cache).not.toHaveBeenCalled();
    work.resolve(); await work.promise; await Promise.resolve();
    expect(h.controller.snapshot().active).toBe(0); expect(h.cache).not.toHaveBeenCalled();
  });
  it("does not cache until a successful critical audit settles", async () => {
    const h = await harness(); const work = deferred<void>(); h.audit.appendCritical.mockReturnValue(work.promise);
    const result = h.handler({}); await vi.waitFor(() => expect(h.audit.appendCritical).toHaveBeenCalled());
    expect(h.cache).not.toHaveBeenCalled(); work.resolve(); expect(await result).toEqual(text("hello"));
    expect(h.cache).toHaveBeenCalledOnce(); h.governor.clearResponseCache();
  });
  it("does not cache on detector or critical audit failure", async () => {
    const h = await harness(); vi.spyOn(h.screen, "screen").mockRejectedValueOnce(new Error("failure"));
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted"); expect(h.cache).not.toHaveBeenCalled();
    h.audit.appendCritical.mockRejectedValue(new Error("audit"));
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted"); expect(h.cache).not.toHaveBeenCalled();
  });
  it("holds capacity and observes receipt during teardown then replacement", async () => {
    const h = await harness(); const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
    const result = h.handler({}); const close = h.screen.session.close();
    expect(JSON.stringify(await result)).toContain("Operation not permitted");
    expect(h.controller.snapshot().active).toBe(1); expect(h.cache).not.toHaveBeenCalled();
    work.resolve(text("late")); await close;
    expect(h.controller.snapshot().active).toBe(0); expect(h.screen.session.exposure.tainted).toBe(true);
  });
  it("withholds oversized canonical metadata before normalization can drop it", async () => {
    const h = await harness(); h.manager.callTool.mockResolvedValue({ ...text("hello"), structuredContent: { extra: " ".repeat(L.CONTENT_UTF8_BYTES) } } as ReturnType<typeof text>);
    const scan = vi.spyOn(h.screen, "screen");
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted");
    expect(scan).not.toHaveBeenCalled(); expect(h.cache).not.toHaveBeenCalled();
  });
  it("withholds unproven capture even when an outbound override reports allowed", async () => {
    const h = await harness();
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = {
      policyResolver: async () => ({}),
      engine: { async filterOutbound(request: { responseBindings: RequestResponseBindings }) {
        try { request.responseBindings.capture("EMAIL_1", " ".repeat(L.CONTENT_UTF8_BYTES)); } catch { /* Simulated policy override. */ }
        return { status: "allowed", payload: {}, findings: [], audit_payload: {} };
      } },
    };
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted");
    expect(h.manager.callTool).not.toHaveBeenCalled();
  });
  it("bounds privacy expansion before joining replacement pieces", async () => {
    const h = await harness(); const master = generateRandomKey(); const vault = new PrivacyPlaceholderVault(new MemoryStorage(), master);
    const engine = new LocalPrivacyEngine(vault, master);
    const policy = { version: 1, policy_id: "fixture", identity_id: "fixture", detector_actions: {}, rehydration: { default_action: "allow" }, created_at: "2026-10-02T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" } satisfies PrivacyPolicy;
    const lookup = vi.spyOn(vault, "resolvePlaceholder");
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = {
      policyResolver: async () => policy, engine,
    };
    vi.spyOn(engine, "filterOutbound").mockImplementation(async request => {
      request.responseBindings!.capture("EMAIL_1", " ".repeat(L.CONTENT_UTF8_BYTES / 2));
      return { status: "filtered", payload: {}, findings: [], audit_payload: {} } as never;
    });
    h.manager.callTool.mockResolvedValue(text("EMAIL_1 EMAIL_1 EMAIL_1"));
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted");
    expect(lookup).not.toHaveBeenCalled();
    expect(h.cache).not.toHaveBeenCalled();
  });
  it("keeps canonical placeholders when the rehydration decision denies expansion", async () => {
    const h = await harness();
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = {
      policyResolver: async () => ({}), engine: {
        async filterOutbound() { return { status: "filtered", payload: {}, findings: [], audit_payload: {} }; },
        async rehydrateResponse() { return { status: "denied", response: text("must-never-expand") }; },
      },
    };
    h.manager.callTool.mockResolvedValue(text("EMAIL_1"));
    expect(await h.handler({})).toEqual(text("EMAIL_1"));
    h.governor.clearResponseCache();
  });
  it("screens request-specific rehydration on live and cached proxy responses", async () => {
    const h = await harness(); const master = generateRandomKey(); const storage = new MemoryStorage();
    const policy = { version: 1, policy_id: "fixture", identity_id: "fixture", detector_actions: {}, rehydration: { default_action: "allow" }, created_at: "2026-10-02T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" } satisfies PrivacyPolicy;
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = {
      policyResolver: async () => policy, engine: () => new LocalPrivacyEngine(new PrivacyPlaceholderVault(storage, master), master),
    };
    h.manager.callTool.mockImplementation(async (_server, _tool, args) => text(String(args!.email)));
    const scan = vi.spyOn(h.screen, "screen");
    try {
      for (let n = 0; n < 2; n++) expect(await h.handler({ email: "fixture@example.test" })).toEqual(text("fixture@example.test"));
      expect(h.manager.callTool).toHaveBeenCalledOnce();
      expect(h.cache).toHaveBeenCalledWith("fixture", "read", { email: "EMAIL_1" }, text("EMAIL_1"));
      expect(scan.mock.calls.map(c => c[0])).toEqual(["fixture@example.test", "fixture@example.test"]);
    } finally { h.governor.clearResponseCache(); }
  });
  it("proxy rehydration never resolves another request's historical placeholder", async () => {
    const h = await harness(); const master = generateRandomKey(); const storage = new MemoryStorage();
    const policy = { version: 1, policy_id: "fixture", identity_id: "fixture", detector_actions: {}, rehydration: { default_action: "allow" }, created_at: "2026-10-02T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" } satisfies PrivacyPolicy;
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = {
      policyResolver: async () => policy, engine: () => new LocalPrivacyEngine(new PrivacyPlaceholderVault(storage, master), master),
    };
    h.manager.callTool.mockResolvedValue(text("EMAIL_1"));
    try {
      expect(await h.handler({ email: "fixture@example.test" })).toEqual(text("fixture@example.test"));
      expect(await h.handler({ email: "second@example.test" })).toEqual(text("EMAIL_1"));
    } finally { h.governor.clearResponseCache(); }
  });
  it("real denied rehydration performs no request-binding or vault lookup through the proxy", async () => {
    const h = await harness(); const master = generateRandomKey();
    const vault = new PrivacyPlaceholderVault(new MemoryStorage(), master); const engine = new LocalPrivacyEngine(vault, master);
    const policy = { version: 1, policy_id: "fixture", identity_id: "fixture", detector_actions: {}, rehydration: { default_action: "deny" }, created_at: "2026-10-02T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" } satisfies PrivacyPolicy;
    (h.router as unknown as { options: { privacyEnforcement: unknown } }).options.privacyEnforcement = { policyResolver: async () => policy, engine };
    vi.spyOn(engine, "filterOutbound").mockImplementation(async request => {
      request.responseBindings!.capture("EMAIL_1", "private@example.test");
      return { status: "filtered", payload: {}, findings: [], audit_payload: {} } as never;
    });
    const lookup = vi.spyOn(vault, "resolvePlaceholder");
    const resolve = vi.spyOn(RequestResponseBindings.prototype, "resolve");
    h.manager.callTool.mockResolvedValue(text("EMAIL_1"));
    try {
      expect(await h.handler({})).toEqual(text("EMAIL_1"));
      expect(lookup).not.toHaveBeenCalled(); expect(resolve).not.toHaveBeenCalled();
    } finally { resolve.mockRestore(); h.governor.clearResponseCache(); }

  });
});
