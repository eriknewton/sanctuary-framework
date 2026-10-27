/**
 * A connected dashboard refetches on every distinct inbox frame, including a resolution or a re-emission of an item
 * it already saw, and drops only an exact duplicate (same item, state and emission time). IC-12.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const TARGETS = ["/api/hub/inbox", "/api/hub/activity", "/api/hub/agents"];
const emptyData = { data: { configured: false, surfaces: [], agents: [], items: [], traps: [], entries: [], policies: [], findings: [], rules: [], recommendations: [], messages: [] } };
const response = (body: unknown = emptyData) => ({
  ok: true, status: 200, json: async () => body,
  body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(body))); controller.close(); } }),
});
// Same real-script VM, minimal DOM, fake stream and fetch pattern as steady-refetch.test.ts.
function harness() {
  const calls: string[] = [];
  const streams: FakeEventSource[] = [];
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  const fortress = { innerHTML: "" };
  class FakeEventSource {
    static OPEN = 1;
    readyState = 0;
    onopen?: () => void;
    onerror?: () => void;
    listeners: Record<string, (event: { data: string }) => void> = {};
    constructor() { streams.push(this); }
    open() { this.readyState = FakeEventSource.OPEN; this.onopen?.(); }
    close() { this.readyState = 2; }
    addEventListener(name: string, listener: (event: { data: string }) => void) { this.listeners[name] = listener; }
  }
  const document = {
    visibilityState: "visible",
    getElementById: (id: string) => id === "main" ? main : id === "fortress" ? fortress : null,
    addEventListener() {}, querySelectorAll: () => [], documentElement: { setAttribute() {}, removeAttribute() {} },
  };
  const context = createContext({
    document, window: { addEventListener() {} }, location: { hash: "", search: "", origin: "http://fixture" },
    sessionStorage: { getItem: () => null }, URLSearchParams, URL, AbortController, TextDecoder, Date,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {}, EventSource: FakeEventSource,
    fetch: (url: string) => {
      const parsed = new URL(url, "http://fixture"); parsed.searchParams.delete("_t");
      calls.push(parsed.pathname + parsed.search);
      return Promise.resolve(response(parsed.pathname === "/api/posture/home" ? {
        origin_machine: "fixture", agents: [], castle_wall: { arm_state: "unknown" }, digest: {},
        protection_requested_count: 0, enforcement_confirmed_count: 0,
      } : emptyData));
    },
  });
  runInContext(getClientScript(), context);
  return { calls, streams, count: (path: string) => calls.filter(call => call === path).length };
}
async function settle() { const MICROTASK_DRAIN_LIMIT = 100; for (let i = 0; i < MICROTASK_DRAIN_LIMIT; i++) await Promise.resolve(); }
const frame = (over: Record<string, unknown> = {}) => ({ item_id: "inbox-001", kind: "approval_pending", identity_id: "op-1",
  fortress_id: "fortress-1", emitted_at: "2026-10-27T09:00:00.000Z", resolved: false, ...over });

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-27T09:00:00Z")); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe("inbox stream frames on a connected dashboard", () => {
  it("refetches for a resolution and a re-emission of a known item and drops only an exact duplicate", async () => {
    const h = harness(); await settle(); h.streams[0].open(); await settle();
    const counts = () => TARGETS.map(path => h.count(path));
    const before = counts();
    const push = async (data: Record<string, unknown>) => { h.streams[0].listeners.inbox({ data: JSON.stringify(data) }); await settle(); };
    await push(frame());
    expect(counts()).toEqual(before.map(n => n + 1)); // A new card refetches inbox, activity and agents.
    await push(frame());
    expect(counts()).toEqual(before.map(n => n + 1)); // The exact duplicate is dropped.
    await push(frame({ resolved: true, emitted_at: "2026-10-27T09:00:05.000Z" }));
    expect(counts()).toEqual(before.map(n => n + 2)); // Its resolution is a new announcement.
    await push(frame({ emitted_at: "2026-10-27T09:00:09.000Z" }));
    expect(counts()).toEqual(before.map(n => n + 3)); // A re-emission after a clear is a new incident.
  });
});
