/**
 * The local task dashboard routes answer only an authenticated operator.
 * The surface here is a stand-in object, so this file runs against any
 * dashboard: without the routes, the authenticated reads are not served.
 * With loopback auto-auth on, loopback position alone is still refused, and a
 * session minted from the operator bearer is admitted.
 */
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { getFreePort } from "../helpers/free-port.js";

const ID = "0".repeat(31) + "1";
/**
 * The one independent copy of the route table, compared as a set below. Must match
 * LOCAL_DASHBOARD_ROUTES in src/local-recompile/dashboard-routes.ts.
 */
const EXPECTED_ROUTES = [
  "GET /local",
  "GET /api/local/status",
  "GET /api/local/results",
  "GET /api/local/results/:id",
  "POST /api/local/results/:id/delete",
  "GET /api/local/log",
];
// The table itself drives every case. A dashboard without the routes has no table, so its cases fail
// by assertion rather than at import.
const table = ((await import("../../src/local-recompile/dashboard-routes.js").catch(() => null)) as
  | { LOCAL_DASHBOARD_ROUTES: ReadonlyArray<{ method: string; path: string }> }
  | null)?.LOCAL_DASHBOARD_ROUTES ?? [];
// A concrete request per route: ids filled in, and the log read from its start.
const ROUTES: Array<[method: "GET" | "POST", path: string]> = table.map((route) => [
  route.method as "GET" | "POST",
  route.path.replace(":id", ID) + (route.path === "/api/local/log" ? "?since=0" : ""),
]);
const DRIVEN = ROUTES.length > 0 ? ROUTES : [["GET", "/api/local/status"] as ["GET", string]];

const stopped: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const stop of stopped.splice(0)) await stop();
});

/** Every store call the stand-in saw; the real stores write their operator-log rows inside these calls. */
function standInSurface(storeCalls: string[]) {
  const result = { request_id: ID, seat: "a".repeat(32), kind: "summarize", state: "committed", created_at: 1, deadline: 2, expires_at: 3, state_changed_at: 1, body: { summary: "text" } };
  return {
    status: { armed: false, cause: "test_runtime", authorityCause: () => null, workerPid: () => undefined, workerState: () => "state_CLOSED", queueDepth: () => 0 },
    modelTag: () => null,
    stores: {
      listResults: async () => (storeCalls.push("listResults"), []),
      viewResult: async () => (storeCalls.push("viewResult"), result),
      deleteResult: async () => (storeCalls.push("deleteResult"), true),
      readLog: async () => (storeCalls.push("readLog"), { ok: true, status: { head_seq: 0 }, rows: [] }),
    },
  };
}

async function start(options: { loopbackAutoAuth?: boolean; noToken?: boolean } = {}) {
  const authToken = `local-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    ...(options.noToken ? {} : { auth_token: authToken }),
    auto_open: false,
  });
  const storeCalls: string[] = [];
  (dashboard as unknown as { setLocalSurface?: (surface: unknown) => void }).setLocalSurface?.(standInSurface(storeCalls));
  // The production posture once an identity decrypts on a loopback dashboard host.
  if (options.loopbackAutoAuth) dashboard.setAutoAuthLocalhost(true);
  await dashboard.start();
  stopped.push(() => dashboard.stop());
  const baseUrl = `http://127.0.0.1:${port}`;
  const mintSession = async () => {
    const exchange = await fetch(`${baseUrl}/auth/session`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` } });
    expect(exchange.status).toBe(200);
    return ((await exchange.json()) as { session_id: string }).session_id;
  };
  return { baseUrl, authToken, storeCalls, mintSession };
}

function withSession(path: string, session: string): string {
  return `${path}${path.includes("?") ? "&" : "?"}session=${encodeURIComponent(session)}`;
}

describe("local task dashboard routes", () => {
  it("the driven routes are exactly the route table", () => {
    const driven = new Set(table.map((route) => `${route.method} ${route.path}`));
    expect(driven).toEqual(new Set(EXPECTED_ROUTES));
    expect(ROUTES).toHaveLength(EXPECTED_ROUTES.length);
  });

  it.each(DRIVEN)("%s %s refuses without operator auth", async (method, path) => {
    const h = await start();
    const res = await fetch(`${h.baseUrl}${path}`, { method });
    expect(res.status).toBe(401);
  });

  it.each(DRIVEN)("%s %s is served to the operator", async (method, path) => {
    const h = await start();
    const res = await fetch(`${h.baseUrl}${path}`, { method, headers: { Authorization: `Bearer ${h.authToken}` } });
    expect(res.status).toBe(200);
  });

  describe("with loopback auto-auth on and an operator token set", () => {
    it.each(DRIVEN)("%s %s refuses a tokenless loopback request and reaches no store", async (method, path) => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${path}`, { method });
      expect(res.status).toBe(401);
      expect(h.storeCalls).toEqual([]);
    });

    it.each(DRIVEN)("%s %s is served to a session minted from the operator bearer", async (method, path) => {
      const h = await start({ loopbackAutoAuth: true });
      const session = await h.mintSession();
      // A browser's own page marks its requests same-origin; a state change without that is refused below.
      const res = await fetch(`${h.baseUrl}${withSession(path, session)}`, { method, headers: { "Sec-Fetch-Site": "same-origin" } });
      expect(res.status).toBe(200);
    });

    it("no way of obtaining a session works without the operator bearer, and nothing obtained opens a route", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const obtained: string[] = [];
      for (const headers of [{}, { Authorization: "Bearer wrong" }, { Authorization: "Basic abc" }] as Array<Record<string, string>>) {
        const exchange = await fetch(`${h.baseUrl}/auth/session`, { method: "POST", headers });
        expect(exchange.status).toBe(401);
        obtained.push(exchange.headers.get("set-cookie") ?? "", (await exchange.text()));
      }
      // Whatever a tokenless loopback client could read back, as a cookie and as a session id.
      for (const [method, path] of DRIVEN) {
        for (const value of obtained) {
          const asCookie = await fetch(`${h.baseUrl}${path}`, { method, headers: { Cookie: `sanctuary_session=${encodeURIComponent(value)}` } });
          expect(asCookie.status).toBe(401);
          const asSession = await fetch(`${h.baseUrl}${withSession(path, value)}`, { method });
          expect(asSession.status).toBe(401);
        }
      }
      expect(h.storeCalls).toEqual([]);
    });

    it("a bogus session is refused", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${withSession("/api/local/results", "not-a-real-session")}`);
      expect(res.status).toBe(401);
      expect(h.storeCalls).toEqual([]);
    });
  });

  describe("a state change admitted by cookie or session comes from the dashboard's own origin", () => {
    const DELETE = `/api/local/results/${ID}/delete`;
    const otherPort = (baseUrl: string) => `http://127.0.0.1:${Number(new URL(baseUrl).port) === 65_535 ? 65_534 : Number(new URL(baseUrl).port) + 1}`;
    const cookie = (session: string) => ({ Cookie: `sanctuary_session=${encodeURIComponent(session)}` });

    it("a cookie POST from a page on another local port is refused and reaches no store", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: { ...cookie(await h.mintSession()), Origin: otherPort(h.baseUrl) } });
      expect(res.status).toBe(403);
      expect(h.storeCalls).toEqual([]);
    });

    it("a cookie POST with neither an origin nor a fetch-site header is refused", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: cookie(await h.mintSession()) });
      expect(res.status).toBe(403);
      expect(h.storeCalls).toEqual([]);
    });

    it("a session POST with neither an origin nor a fetch-site header is refused", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${withSession(DELETE, await h.mintSession())}`, { method: "POST" });
      expect(res.status).toBe(403);
      expect(h.storeCalls).toEqual([]);
    });

    it("a fetch-site header other than same-origin is refused even beside a matching origin", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: { ...cookie(await h.mintSession()), "Sec-Fetch-Site": "same-site", Origin: h.baseUrl } });
      expect(res.status).toBe(403);
      expect(h.storeCalls).toEqual([]);
    });

    it("a cookie POST whose origin is the dashboard's own is admitted", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: { ...cookie(await h.mintSession()), Origin: h.baseUrl } });
      expect(res.status).toBe(200);
      expect(h.storeCalls).toEqual(["deleteResult"]);
    });

    it("a cookie POST marked same-origin is admitted", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: { ...cookie(await h.mintSession()), "Sec-Fetch-Site": "same-origin" } });
      expect(res.status).toBe(200);
      expect(h.storeCalls).toEqual(["deleteResult"]);
    });

    it("a bearer POST is admitted whatever its origin", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}${DELETE}`, { method: "POST", headers: { Authorization: `Bearer ${h.authToken}`, Origin: otherPort(h.baseUrl) } });
      expect(res.status).toBe(200);
      expect(h.storeCalls).toEqual(["deleteResult"]);
    });

    it("a cookie read from another origin is still served: only a state change is checked", async () => {
      const h = await start({ loopbackAutoAuth: true });
      const res = await fetch(`${h.baseUrl}/api/local/results`, { headers: { ...cookie(await h.mintSession()), Origin: otherPort(h.baseUrl) } });
      expect(res.status).toBe(200);
      expect(h.storeCalls).toEqual(["listResults"]);
    });
  });

  describe("with no operator token configured", () => {
    it.each(DRIVEN)("%s %s refuses every request: there is no operator credential to admit", async (method, path) => {
      for (const loopbackAutoAuth of [false, true]) {
        const h = await start({ noToken: true, loopbackAutoAuth });
        const res = await fetch(`${h.baseUrl}${path}`, { method });
        expect(res.status).toBe(401);
        expect(h.storeCalls).toEqual([]);
      }
    });
  });
});
