// fail-before-exempt: the local dashboard routes and their module are new; dashboard-local-auth.test.ts carries the base failure.
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  LOCAL_DASHBOARD_ROUTES,
  LOCAL_PAGE_HTML,
  LOCAL_SUMMARY_NOTICE,
  type LocalDashboardSurface,
} from "../../src/local-recompile/dashboard-routes.js";
import { LocalOperatorStores } from "../../src/local-recompile/operator-surface.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { getFreePort } from "../helpers/free-port.js";
import { LOCK_ROOT, operatorFixture, requestId, type OperatorFixture } from "./helpers/operator-fixture.js";

// Must match LOCAL_SUMMARY_NOTICE in src/local-recompile/dashboard-routes.ts.
const NOTICE = "This was written by your local model from your stored records. Check it before pasting it anywhere, including back to an agent.";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of cleanups.splice(0).reverse()) await step();
});

async function start(options: { stores?: boolean; armed?: boolean; loopbackAutoAuth?: boolean } = {}) {
  const fixture: OperatorFixture = await operatorFixture();
  cleanups.push(() => fixture.close());
  const keys = deriveLocalStoreKeys(fixture.masterKey);
  const stores = options.stores === false ? null : new LocalOperatorStores(fixture.storage, keys, { runtimeRoot: LOCK_ROOT });
  if (stores) cleanups.push(async () => stores.close());
  const surface: LocalDashboardSurface = {
    status: {
      armed: options.armed ?? true,
      cause: options.armed === false ? "worker_unavailable" : null,
      authorityCause: () => null,
      workerPid: () => process.pid,
      queueDepth: () => 3,
    },
    modelTag: () => "qwen2.5:1.5b",
    stores,
  };
  const authToken = `local-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();
  const dashboard = new DashboardApprovalChannel({ port, host: "127.0.0.1", timeout_seconds: 30, auth_token: authToken, auto_open: false });
  dashboard.setLocalSurface(surface);
  if (options.loopbackAutoAuth) dashboard.setAutoAuthLocalhost(true);
  await dashboard.start();
  cleanups.push(() => dashboard.stop());
  const call = async (method: string, path: string) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { Authorization: `Bearer ${authToken}` } });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const tokenless = async (method: string, path: string) => (await fetch(`http://127.0.0.1:${port}${path}`, { method })).status;
  return { fixture, call, tokenless };
}

describe("local task dashboard", () => {
  // The route table's set parity lives in dashboard-local-auth.test.ts, the one independent copy.
  it("pins the summary notice", () => {
    expect(LOCAL_SUMMARY_NOTICE).toBe(NOTICE);
  });

  it("status reports arming, queue depth, worker liveness and the model tag", async () => {
    const h = await start();
    const res = await h.call("GET", "/api/local/status");
    expect(res.body).toEqual({ armed: true, ready: true, cause: null, authority_cause: null, queue_depth: 3, worker_alive: true, model_tag: "qwen2.5:1.5b" });
  });

  it("lists results and opens one, recording the view first", async () => {
    const h = await start();
    const id = await h.fixture.seed(1, "the summary");
    const list = await h.call("GET", "/api/local/results");
    expect((list.body.results as Array<{ request_id: string }>).map((r) => r.request_id)).toEqual([id]);
    const detail = await h.call("GET", `/api/local/results/${id}`);
    expect((detail.body.result as { body: { summary: string } }).body.summary).toBe("the summary");
    expect((await h.fixture.rows()).at(-1)!.kind).toBe("operator_render");
  });

  it("the summary is rendered as text", async () => {
    const h = await start();
    const id = await h.fixture.seed(1, '<img src=x onerror="alert(1)"> <a href="https://example.test">link</a>');
    const detail = await h.call("GET", `/api/local/results/${id}`);
    expect((detail.body.result as { body: { summary: string } }).body.summary).toBe('<img src=x onerror="alert(1)"> <a href="https://example.test">link</a>');
    expect(LOCAL_PAGE_HTML).toContain('el("summary").textContent =');
    expect(LOCAL_PAGE_HTML).toContain(JSON.stringify(NOTICE));
    expect(LOCAL_PAGE_HTML).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  });

  it("control characters in a summary are replaced before they reach the page", async () => {
    const h = await start();
    const id = await h.fixture.seed(1, "a\u001b[2Jb");
    const detail = await h.call("GET", `/api/local/results/${id}`);
    expect((detail.body.result as { body: { summary: string } }).body.summary).toBe("a�[2Jb");
  });

  it("delete writes its row and removes the result", async () => {
    const h = await start();
    const id = await h.fixture.seed(1, "text");
    const res = await h.call("POST", `/api/local/results/${id}/delete`);
    expect(res.status).toBe(200);
    expect(await h.fixture.hasResult(id)).toBe(false);
    expect((await h.fixture.rows()).at(-1)!.kind).toBe("result_deleted");
  });

  it("an unknown result is not found and writes no row", async () => {
    const h = await start();
    const before = (await h.fixture.rows()).length;
    expect((await h.call("GET", `/api/local/results/${requestId(9)}`)).status).toBe(404);
    expect((await h.fixture.rows()).length).toBe(before);
  });

  it("the log route returns verified rows", async () => {
    const h = await start();
    await h.fixture.seed(1, "text");
    const res = await h.call("GET", "/api/local/log?since=0");
    expect(res.status).toBe(200);
    expect((res.body.rows as Array<{ kind: string }>)[0]!.kind).toBe("genesis");
  });

  it("result and log routes answer unavailable when the stores did not open", async () => {
    const h = await start({ stores: false, armed: false });
    expect((await h.call("GET", "/api/local/results")).status).toBe(503);
    expect((await h.call("GET", "/api/local/log")).status).toBe(503);
    expect((await h.call("GET", "/api/local/status")).body.cause).toBe("worker_unavailable");
  });

  it("with loopback auto-auth on, a tokenless loopback request to every route is refused and writes no operator-log row", async () => {
    const h = await start({ loopbackAutoAuth: true });
    const id = await h.fixture.seed(1, "text");
    // Every route in the table is driven; the table's own parity is checked in dashboard-local-auth.test.ts.
    const driven = LOCAL_DASHBOARD_ROUTES.map((route) => ({ ...route, url: route.path.replace(":id", id) }));
    const before = await h.fixture.rows();
    for (const route of driven) expect(await h.tokenless(route.method, route.url), `${route.method} ${route.path}`).toBe(401);
    expect(await h.fixture.rows()).toEqual(before);
    expect(await h.fixture.hasResult(id)).toBe(true);
  });
});
