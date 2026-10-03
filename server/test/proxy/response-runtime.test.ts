/** Process-local admission and exposure survive cancellation and session churn. */
import { describe, expect, it, vi } from "vitest";
import { ResponseController, ResponseSession, processResponseController } from "../../src/proxy/response-runtime.js";
import { RESPONSE_LIMITS as L } from "../../src/proxy/response-limits.js";
import { responseCache } from "../../src/proxy/response-cache.js";

const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; };
describe("response runtime bounds", () => {
  it("shares process quotas and cache accounting across module copies", async () => {
    const owner = Symbol(); responseCache.set(owner, "copy", "retained", Date.now() + L.IDLE_MS);
    try {
      vi.resetModules();
      const runtime = await import("../../src/proxy/response-runtime.js");
      const cache = await import("../../src/proxy/response-cache.js");
      expect(runtime.processResponseController).toBe(processResponseController);
      expect(cache.responseCache.get(owner, "copy", Date.now())).toBe("retained");
    } finally { responseCache.clear(owner); }
  });
  it("starts tainted and retains exposure across all reservations", async () => {
    const session = new ResponseSession(new ResponseController());
    expect(session.exposure).toEqual({ state: "state_TAINTED", tainted: true, observed: false });
    const lease = session.reserve(); lease.observe(); lease.cancel(); lease.finish();
    expect(session.exposure.observed).toBe(true);
    await session.close();
    expect(session.exposure).toEqual({ state: "state_TAINTED", tainted: true, observed: "unknown" });
    expect(() => session.reserve()).toThrow();
  });
  it("caps sessions and the process before admitting work", () => {
    const controller = new ResponseController();
    const sessions = Array.from({ length: L.ACTIVE_PER_PROCESS / L.ACTIVE_PER_SESSION }, () => new ResponseSession(controller));
    const leases = sessions.flatMap(s => Array.from({ length: L.ACTIVE_PER_SESSION }, () => s.reserve()));
    expect(() => sessions[0]!.reserve()).toThrow();
    expect(() => new ResponseSession(controller).reserve()).toThrow();
    expect(controller.snapshot().active).toBe(L.ACTIVE_PER_PROCESS);
    leases.forEach(l => l.finish());
    expect(controller.snapshot().active).toBe(0);
  });
  it("never recycles reservations across repeated timeout then release waves", async () => {
    const controller = new ResponseController();
    const session = new ResponseSession(controller);
    for (let wave = 0; wave < 4; wave++) {
      const work = Array.from({ length: L.ACTIVE_PER_SESSION }, deferred);
      const leases = work.map(w => { const l = session.reserve(); l.track(w.promise); l.cancel(); l.finish(); return l; });
      expect(() => session.reserve()).toThrow();
      expect(controller.snapshot().active).toBe(L.ACTIVE_PER_SESSION);
      work.forEach(w => w.resolve()); await Promise.all(leases.map(l => l.drained));
      expect(controller.snapshot().active).toBe(0);
    }
  });
  it("bounds replacement instances during repeated cancellation waves", async () => {
    const controller = new ResponseController();
    for (let wave = 0; wave < 3; wave++) { // Three distinct generations expose premature reservation reuse.
      const sessions = Array.from({ length: L.ACTIVE_PER_PROCESS / L.ACTIVE_PER_SESSION }, () => new ResponseSession(controller));
      const work = deferred();
      const leases = sessions.flatMap(s => Array.from({ length: L.ACTIVE_PER_SESSION }, () => s.reserve()));
      leases.forEach(l => { l.track(work.promise); l.cancel(); l.finish(); });
      const closes = sessions.map(s => s.close());
      expect(() => new ResponseSession(controller).reserve()).toThrow();
      expect(controller.snapshot().active).toBe(L.ACTIVE_PER_PROCESS);
      work.resolve(); await Promise.all(closes);
      expect(controller.snapshot().active).toBe(0);
    }
  });
  it("holds upstream, audit and worker settlement independently", async () => {
    const controller = new ResponseController();
    const session = new ResponseSession(controller);
    const lease = session.reserve();
    const work = [deferred(), deferred(), deferred()];
    work.forEach(w => lease.track(w.promise)); lease.cancel(); lease.finish();
    for (const w of work.slice(0, -1)) { w.resolve(); await w.promise; expect(controller.snapshot().active).toBe(1); }
    work.at(-1)!.resolve(); await lease.drained;
    expect(controller.snapshot().active).toBe(0);
  });
  it("evicts only inactive idle records and never mints fresh known slots for evicted handles", () => {
    let now = 0;
    const controller = new ResponseController(() => now);
    const active = new ResponseSession(controller); const lease = active.reserve();
    const idle = new ResponseSession(controller);
    now = L.IDLE_MS;
    expect(idle.exposure.observed).toBe("unknown");
    expect(active.exposure.observed).toBe(false);
    expect(controller.snapshot().records).toBe(1);
    lease.finish();
  });
  it("bounds session churn and shares one unknown admission bucket", () => {
    const controller = new ResponseController();
    for (let n = 0; n < L.RUNTIME_SLOTS; n++) new ResponseSession(controller);
    const overflow = Array.from({ length: L.ACTIVE_PER_SESSION + 1 }, () => new ResponseSession(controller));
    const leases = overflow.slice(0, L.ACTIVE_PER_SESSION).map(s => s.reserve());
    expect(() => overflow.at(-1)!.reserve()).toThrow();
    expect(controller.snapshot()).toEqual({ records: L.RUNTIME_SLOTS, active: L.ACTIVE_PER_SESSION, unknownActive: L.ACTIVE_PER_SESSION });
    expect(overflow[0]!.exposure.observed).toBe("unknown");
    leases.forEach(l => l.finish());
  });
  it("fences teardown until surviving work settles", async () => {
    const controller = new ResponseController(); const session = new ResponseSession(controller);
    const lease = session.reserve(); const work = deferred(); lease.track(work.promise);
    let closed = false; const close = session.close().then(() => { closed = true; });
    lease.finish(); await Promise.resolve();
    expect(closed).toBe(false); expect(() => session.reserve()).toThrow();
    work.resolve(); await close; expect(controller.snapshot().active).toBe(0);
  });
  it("bounds shared cache count, bytes, expiry and LRU across owners", () => {
    const owners = Array.from({ length: L.CACHE_ENTRIES + 1 }, () => Symbol());
    try {
      owners.forEach((owner, n) => responseCache.set(owner, String(n), { content: " ".repeat(L.CONTENT_UTF8_BYTES - 100) }, Date.now() + L.IDLE_MS));
      expect(owners.reduce((n, o) => n + responseCache.size(o), 0)).toBeLessThanOrEqual(L.CACHE_ENTRIES);
      expect(responseCache.bytes()).toBeLessThanOrEqual(L.CACHE_UTF8_BYTES);
      expect(responseCache.get(owners[0]!, "0", Date.now())).toBeUndefined();
      responseCache.prune(Date.now() + L.IDLE_MS);
      expect(responseCache.bytes()).toBe(0);
    } finally { owners.forEach(o => responseCache.clear(o)); }
  });
  it("enforces cache entry count independently of the byte budget", () => {
    const owner = Symbol();
    try {
      for (let n = 0; n <= L.CACHE_ENTRIES; n++) responseCache.set(owner, String(n), "small", Date.now() + L.IDLE_MS);
      expect(responseCache.size(owner)).toBe(L.CACHE_ENTRIES);
      expect(responseCache.get(owner, "0", Date.now())).toBeUndefined();
      responseCache.get(owner, "1", Date.now());
      responseCache.set(owner, "new", "small", Date.now() + L.IDLE_MS);
      expect(responseCache.get(owner, "1", Date.now())).toBe("small");
      expect(responseCache.get(owner, "2", Date.now())).toBeUndefined();
    } finally { responseCache.clear(owner); }
  });
  it("skips oversized caching and clears only the specified instance", () => {
    const a = Symbol(); const b = Symbol();
    responseCache.set(a, "a", " ".repeat(L.CONTENT_UTF8_BYTES), Date.now() + L.IDLE_MS);
    expect(responseCache.size(a)).toBe(0);
    responseCache.set(a, "a", "hello", Date.now() + L.IDLE_MS);
    responseCache.set(b, "b", "world", Date.now() + L.IDLE_MS);
    responseCache.clear(a); expect(responseCache.get(b, "b", Date.now())).toBe("world"); responseCache.clear(b);
  });
});
