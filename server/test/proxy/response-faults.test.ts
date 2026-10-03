/** Response release, cache and admission remain terminal under asynchronous faults. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import { InjectionDetector } from "../../src/security/injection-detector.js";
import { ResponseController } from "../../src/proxy/response-runtime.js";
import { CallGovernor } from "../../src/operational/call-governor.js";
import { LocalPrivacyEngine, type PrivacyPolicy } from "../../src/operational/privacy-core.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { unitResponseScreen } from "../helpers/response-screen.js";
import { rehydrationBudget, type RequestResponseBindings } from "../../src/proxy/response-bounds.js";
import { RESPONSE_LIMITS as L } from "../../src/proxy/response-limits.js";

const text = (value: string) => ({ content: [{ type: "text", text: value }] });
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
function harness() {
  const controller = new ResponseController(); const screen = unitResponseScreen(controller);
  const manager = { getAllTools: () => new Map([["fixture", [{ name: "read", description: "fixture", inputSchema: { type: "object" } }]]]), getServerConfig: () => ({ default_tier: 3 }), callTool: vi.fn(async () => text("hello")) };
  const audit = { append: vi.fn(async () => {}), appendCritical: vi.fn(async (_entry?: unknown) => {}) };
  const governor = new CallGovernor(); const cache = vi.spyOn(governor, "recordResult");
  const router = new ProxyRouter(manager as never, new InjectionDetector(), audit as never, screen, { governor });
  const handler = router.getProxiedTools()[0]!.handler;
  return { controller, screen, manager, audit, governor, cache, router, handler };
}
afterEach(() => { vi.useRealTimers(); });
describe("response fault schedules", () => {
  it("requires a ready response screen before proxy registration", () => {
    expect(() => new ProxyRouter({} as never, new InjectionDetector(), {} as never, undefined as never)).toThrow();
  });
  it("refuses a request already cancelled before dispatch", async () => {
    const h = harness(); const abort = new AbortController(); abort.abort();
    expect(JSON.stringify(await h.handler({}, undefined, { signal: abort.signal }))).toContain("Operation not permitted");
    expect(h.manager.callTool).not.toHaveBeenCalled();
  });
  it("reserves before governor lookup and dispatch", async () => {
    const h = harness(); const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
    const check = vi.spyOn(h.governor, "check");
    const a = h.handler({ a: 1 }); const b = h.handler({ a: 2 });
    expect(JSON.stringify(await h.handler({ a: 3 }))).toContain("Operation not permitted");
    expect(check).toHaveBeenCalledTimes(L.ACTIVE_PER_SESSION); expect(h.manager.callTool).toHaveBeenCalledTimes(L.ACTIVE_PER_SESSION);
    work.resolve(text("hello")); await Promise.all([a, b]); h.governor.clearResponseCache();
  });
  it("never caches or releases after timeout even when upstream completes later", async () => {
    vi.useFakeTimers(); const h = harness();
    for (let wave = 0; wave < 3; wave++) {
      const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
      const calls = [h.handler({ wave, n: 0 }), h.handler({ wave, n: 1 })];
      await vi.advanceTimersByTimeAsync(30_001);
      for (const call of calls) expect(JSON.stringify(await call)).toContain("Operation not permitted");
      expect(h.controller.snapshot().active).toBe(L.ACTIVE_PER_SESSION);
      expect(JSON.stringify(await h.handler({ wave, n: 2 }))).toContain("Operation not permitted");
      work.resolve(text("late")); await work.promise; await Promise.resolve();
      expect(h.controller.snapshot().active).toBe(0); expect(h.cache).not.toHaveBeenCalled();
      expect(h.screen.session.exposure.tainted).toBe(true);
    }
  });
  it("cancels during critical audit without late release or cache mutation", async () => {
    const h = harness(); const work = deferred<void>(); h.audit.appendCritical.mockReturnValue(work.promise);
    const abort = new AbortController(); const result = h.handler({}, undefined, { signal: abort.signal });
    await vi.waitFor(() => expect(h.audit.appendCritical).toHaveBeenCalled());
    abort.abort(); expect(JSON.stringify(await result)).toContain("Operation not permitted");
    expect(h.controller.snapshot().active).toBe(1); expect(h.cache).not.toHaveBeenCalled();
    work.resolve(); await work.promise; await Promise.resolve();
    expect(h.controller.snapshot().active).toBe(0); expect(h.cache).not.toHaveBeenCalled();
  });
  it("does not cache until a successful critical audit settles", async () => {
    const h = harness(); const work = deferred<void>(); h.audit.appendCritical.mockReturnValue(work.promise);
    const result = h.handler({}); await vi.waitFor(() => expect(h.audit.appendCritical).toHaveBeenCalled());
    expect(h.cache).not.toHaveBeenCalled(); work.resolve(); expect(await result).toEqual(text("hello"));
    expect(h.cache).toHaveBeenCalledOnce(); h.governor.clearResponseCache();
  });
  it("does not cache on detector or critical audit failure", async () => {
    const h = harness(); vi.spyOn(h.screen, "screen").mockRejectedValueOnce(new Error("failure"));
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted"); expect(h.cache).not.toHaveBeenCalled();
    h.audit.appendCritical.mockRejectedValue(new Error("audit"));
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted"); expect(h.cache).not.toHaveBeenCalled();
  });
  it("holds capacity and observes receipt during teardown then replacement", async () => {
    const h = harness(); const work = deferred<ReturnType<typeof text>>(); h.manager.callTool.mockReturnValue(work.promise);
    const result = h.handler({}); const close = h.screen.session.close();
    expect(JSON.stringify(await result)).toContain("Operation not permitted");
    expect(h.controller.snapshot().active).toBe(1); expect(h.cache).not.toHaveBeenCalled();
    work.resolve(text("late")); await close;
    expect(h.controller.snapshot().active).toBe(0); expect(h.screen.session.exposure.tainted).toBe(true);
  });
  it("withholds oversized canonical metadata before normalization can drop it", async () => {
    const h = harness(); h.manager.callTool.mockResolvedValue({ ...text("hello"), structuredContent: { extra: " ".repeat(L.CONTENT_UTF8_BYTES) } } as ReturnType<typeof text>);
    const scan = vi.spyOn(h.screen, "screen");
    expect(JSON.stringify(await h.handler({}))).toContain("Operation not permitted");
    expect(scan).not.toHaveBeenCalled(); expect(h.cache).not.toHaveBeenCalled();
  });
  it("withholds unproven capture even when an outbound override reports allowed", async () => {
    const h = harness();
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
    const h = harness(); const master = generateRandomKey(); const vault = new PrivacyPlaceholderVault(new MemoryStorage(), master);
    const engine = new LocalPrivacyEngine(vault, master);
    const policy = { version: 1, policy_id: "fixture", identity_id: "fixture", detector_actions: {}, rehydration: { default_action: "allow" }, created_at: "2026-10-02T00:00:00Z", updated_at: "2026-10-02T00:00:00Z" } satisfies PrivacyPolicy;
    const lookup = vi.spyOn(vault, "resolvePlaceholder");
    await expect(engine.rehydrateResponse({ response: text("EMAIL_1 EMAIL_1"), policy,
      agent_id: "fixture", destination_category: "tool-api",
      responseBudget: rehydrationBudget(() => {}, () => " ".repeat(L.CONTENT_UTF8_BYTES)),
    })).rejects.toThrow();
    expect(lookup).not.toHaveBeenCalled();
    expect(h.cache).not.toHaveBeenCalled();
  });
});
