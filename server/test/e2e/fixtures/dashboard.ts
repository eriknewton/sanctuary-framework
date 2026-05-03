/**
 * Playwright fixture: a real v1.1 dashboard SPA booted against an
 * ephemeral in-memory fortress, served over a node http server, ready
 * for `page.goto(dashboard.url)`.
 *
 * Modelled on `intelligence-api-router.test.ts:startHarness` but mounts
 * the full v1.1 dispatch (SPA HTML at `/`, hub API at `/api/hub/*`,
 * intelligence API at `/api/hub/intelligence/*`). Auth is loopback
 * auto-auth so the SPA renders without sessionStorage gymnastics.
 *
 * Per-test fresh state: every test gets its own selector, audit log,
 * storage backend, and listening port. Tests that need failure entries
 * in the recent-failures buffer call `dashboard.selector.recordRecentFailureForTest`
 * directly. Tests that need to stub the concierge endpoint use
 * `page.route` to intercept `/api/hub/concierge/chat`.
 */
import { test as base } from "@playwright/test";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

import { MemoryStorage } from "../../../src/storage/memory.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { SubstrateSelector } from "../../../src/intelligence/selector.js";
import { dispatchV11Request } from "../../../src/dashboard/v1_1/dispatch.js";
import {
  buildV11Bindings,
  type V11Bindings,
} from "../../../src/dashboard/v1_1/wiring.js";

export interface DashboardHarness {
  url: string;
  selector: SubstrateSelector;
  auditLog: AuditLog;
  bindings: V11Bindings;
  stop: () => Promise<void>;
}

const IDENTITY = "operator-e2e";
const FORTRESS = "fortress-e2e";

async function startHarness(): Promise<DashboardHarness> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
  });
  await selector.load();
  const bindings = buildV11Bindings({
    identityId: IDENTITY,
    fortressId: FORTRESS,
    auditLog,
    intelligenceSelector: selector,
    storage,
    masterKey,
  });

  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const url = new URL(req.url ?? "/", `http://127.0.0.1`);
        const handled = await dispatchV11Request(
          { bindings, loopbackAutoAuth: true },
          req,
          res,
          url,
          (req.method ?? "GET").toUpperCase(),
        );
        if (!handled) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "not_found" }));
        }
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: (err as Error).message }));
      }
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const addr = server.address();
  if (!addr || typeof addr !== "object") throw new Error("no address");
  return {
    url: `http://127.0.0.1:${addr.port}`,
    selector,
    auditLog,
    bindings,
    // Force-close active connections before close. The SPA opens an
    // EventSource on /api/stream that Chromium keeps open across page
    // navigations; server.close alone waits indefinitely on that
    // socket and surfaces as a fixture-teardown timeout. Node 18.2
    // added closeAllConnections specifically for this teardown shape.
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

export const test = base.extend<{ dashboard: DashboardHarness }>({
  dashboard: async ({}, use) => {
    const harness = await startHarness();
    try {
      await use(harness);
    } finally {
      await harness.stop();
    }
  },
});

export { expect } from "@playwright/test";
