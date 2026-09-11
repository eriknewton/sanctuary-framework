/** v1.1 launch-session read propagation. */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

const ORIGIN = "http://127.0.0.1:3711";

type FetchCall = { url: string; init?: RequestInit };

function loadClient(options: {
  config?: Record<string, string>;
  session?: string;
  streamSession?: string;
  streamSessionFailure?: "non-ok" | "throw";
} = {}) {
  const calls: FetchCall[] = [];
  const streams: string[] = [];
  const pollingIntervals: number[] = [];
  const config = options.config ?? {};
  const script = getClientScript().slice(0, getClientScript().lastIndexOf("// Boot."));
  const factory = new Function("env", `
    const document = env.document;
    const window = env.window;
    const sessionStorage = env.sessionStorage;
    const location = env.location;
    const fetch = env.fetch;
    const EventSource = env.EventSource;
    const setTimeout = env.setTimeout;
    const setInterval = env.setInterval;
    ${script}
    return { api, policyApi, autoTriggerApi, honeypotApi, loadInboxPrefs, fetchSovereignty, fetchPostureHome, connectStream };
  `) as (env: Record<string, unknown>) => Record<string, (...args: unknown[]) => Promise<unknown> | void>;

  const configElement = { textContent: JSON.stringify(config) };
  const client = factory({
    document: {
      getElementById: (id: string) => id === "dashboard-config" ? configElement : null,
      addEventListener: () => {},
      documentElement: { setAttribute: () => {}, removeAttribute: () => {} },
    },
    window: { matchMedia: () => null },
    sessionStorage: { getItem: () => null, setItem: () => {} },
    location: { origin: ORIGIN, search: options.session ? `?session=${encodeURIComponent(options.session)}` : "", hash: "" },
    fetch: async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      if (url === "/auth/session") {
        if (options.streamSessionFailure === "throw") throw new Error("session exchange unavailable");
        if (options.streamSessionFailure === "non-ok") {
          return { ok: false, status: 401, json: async () => ({ error: "unauthorized" }) };
        }
        return { ok: true, status: 200, json: async () => ({ session_id: options.streamSession ?? "" }) };
      }
      return { ok: true, status: 200, json: async () => ({ data: { findings: [] } }) };
    },
    EventSource: class {
      constructor(url: string) { streams.push(url); }
      addEventListener() {}
    },
    setTimeout: () => 0,
    setInterval: (_fn: unknown, ms: number) => { pollingIntervals.push(ms); return 0; },
  });
  return { client, calls, streams, pollingIntervals };
}

function sessionFrom(url: string): string | null {
  return new URL(url, ORIGIN).searchParams.get("session");
}

describe("v1.1 launch-session read propagation", () => {
  it("forwards the launch session through same-origin GET APIs, direct reads, and SSE", async () => {
    const { client, calls, streams } = loadClient({ session: "read-session" });
    await client.api("/agents");
    await client.policyApi("/current");
    await client.autoTriggerApi("/rules");
    await client.honeypotApi("/traps");
    await client.loadInboxPrefs();
    await client.fetchSovereignty();
    await client.fetchPostureHome();
    client.connectStream();
    await Promise.resolve();

    expect(calls).toHaveLength(8);
    expect(calls.map((call) => sessionFrom(call.url))).toEqual(Array(8).fill("read-session"));
    expect(streams).toEqual(["/api/stream?session=read-session"]);
  });

  it("does not forward the session to mutations or cross-origin API targets", async () => {
    const local = loadClient({ session: "read-session" });
    await local.client.api("/inbox/approval-1/approve", { method: "POST", body: {} });
    await local.client.policyApi("/drafts/draft-1/activate", { method: "POST", body: {} });
    await local.client.autoTriggerApi("/rules/rule-1", { method: "PATCH", body: {} });
    expect(local.calls.map((call) => sessionFrom(call.url))).toEqual([null, null, null]);

    const remote = loadClient({
      session: "read-session",
      config: { hubApiBase: "https://remote.invalid/api/hub" },
    });
    await remote.client.api("/agents");
    expect(remote.calls[0]?.url).toMatch(/^https:\/\/remote\.invalid\/api\/hub\/agents/);
    expect(new URL(remote.calls[0]!.url).searchParams.get("session")).toBeNull();
  });

  it("leaves no-session and cross-origin SSE URLs unchanged, while preserving a newer bearer-minted stream session", async () => {
    const noSession = loadClient();
    await noSession.client.api("/agents");
    noSession.client.connectStream();
    await Promise.resolve();
    expect(sessionFrom(noSession.calls[0]!.url)).toBeNull();
    expect(noSession.streams).toEqual(["/api/stream"]);

    const remoteStream = loadClient({ session: "read-session", config: { streamUrl: "https://remote.invalid/api/stream" } });
    remoteStream.client.connectStream();
    await Promise.resolve();
    expect(remoteStream.streams).toEqual(["https://remote.invalid/api/stream"]);

    const bearerStream = loadClient({
      session: "launch-session",
      streamSession: "bearer-minted-session",
      config: { authToken: "operator-bearer" },
    });
    bearerStream.client.connectStream();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(bearerStream.streams).toEqual(["/api/stream?session=bearer-minted-session"]);
  });

  it("falls back to polling without opening SSE when the bearer session exchange fails", async () => {
    for (const streamSessionFailure of ["non-ok", "throw"] as const) {
      const failed = loadClient({
        session: "launch-session",
        streamSessionFailure,
        config: { authToken: "operator-bearer" },
      });
      failed.client.connectStream();
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(failed.calls.map((call) => call.url)).toEqual(["/auth/session"]);
      expect(failed.streams).toEqual([]);
      expect(failed.pollingIntervals).toEqual([5000]);
    }
  });
});
