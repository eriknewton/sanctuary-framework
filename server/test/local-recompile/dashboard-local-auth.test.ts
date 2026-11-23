/**
 * The local task dashboard routes answer only an authenticated operator.
 * The surface here is a stand-in object, so this file runs against any
 * dashboard: without the routes, the authenticated reads are not served.
 */
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { getFreePort } from "../helpers/free-port.js";

// Must match LOCAL_DASHBOARD_ROUTES in src/local-recompile/dashboard-routes.ts; dashboard-local.test.ts checks the set.
const ID = "0".repeat(31) + "1";
const ROUTES: Array<[method: "GET" | "POST", path: string]> = [
  ["GET", "/local"],
  ["GET", "/api/local/status"],
  ["GET", "/api/local/results"],
  ["GET", `/api/local/results/${ID}`],
  ["POST", `/api/local/results/${ID}/delete`],
  ["GET", "/api/local/log?since=0"],
];

const stopped: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const stop of stopped.splice(0)) await stop();
});

function standInSurface() {
  const result = { request_id: ID, seat: "a".repeat(32), kind: "summarize", state: "committed", created_at: 1, deadline: 2, expires_at: 3, state_changed_at: 1, body: { summary: "text" } };
  return {
    status: { armed: false, cause: "test_runtime", workerPid: () => undefined, workerState: () => "state_CLOSED", queueDepth: () => 0 },
    modelTag: () => null,
    stores: {
      listResults: async () => [],
      viewResult: async () => result,
      deleteResult: async () => true,
      readLog: async () => ({ ok: true, status: { head_seq: 0 }, rows: [] }),
    },
  };
}

async function start() {
  const authToken = `local-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();
  const dashboard = new DashboardApprovalChannel({ port, host: "127.0.0.1", timeout_seconds: 30, auth_token: authToken, auto_open: false });
  (dashboard as unknown as { setLocalSurface?: (surface: unknown) => void }).setLocalSurface?.(standInSurface());
  await dashboard.start();
  stopped.push(() => dashboard.stop());
  return { baseUrl: `http://127.0.0.1:${port}`, authToken };
}

describe("local task dashboard routes", () => {
  it.each(ROUTES)("%s %s refuses without operator auth", async (method, path) => {
    const h = await start();
    const res = await fetch(`${h.baseUrl}${path}`, { method });
    expect(res.status).toBe(401);
  });

  it.each(ROUTES)("%s %s is served to the operator", async (method, path) => {
    const h = await start();
    const res = await fetch(`${h.baseUrl}${path}`, { method, headers: { Authorization: `Bearer ${h.authToken}` } });
    expect(res.status).toBe(200);
  });
});
