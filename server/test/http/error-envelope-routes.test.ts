import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";

import {
  handleHubRoute,
} from "../../src/hub/api-router.js";
import {
  HUB_API_PREFIX,
} from "../../src/hub/constants.js";
import type { HubService } from "../../src/hub/hub-service.js";
import { HubValidationError } from "../../src/hub/errors.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "../../src/principal-policy/approval-aggregator-routes.js";
import type { ApprovalAggregator } from "../../src/principal-policy/approval-aggregator.js";

const AUTH_TOKEN = "route-error-envelope-token";
const LEAKY_MESSAGE =
  "tier1_always_approve bulk_read_threshold /Users/eriknewton/secret/path";

function authHeaders(): HeadersInit {
  return { Authorization: `Bearer ${AUTH_TOKEN}` };
}

function leakyError(): Error {
  const err = new Error(LEAKY_MESSAGE);
  err.stack = [
    `Error: ${LEAKY_MESSAGE}`,
    "    at unsafeHandler (/Users/eriknewton/secret/path/server/src/principal-policy/gate.ts:17:9)",
  ].join("\n");
  return err;
}

async function startRouteServer(
  handler: (
    req: IncomingMessage,
    res: ServerResponse,
  ) => Promise<boolean>,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      const handled = await handler(req, res);
      if (!handled) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
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
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function expectNoExceptionLeak(text: string): void {
  expect(text).not.toContain(LEAKY_MESSAGE);
  expect(text).not.toContain("/Users/eriknewton/secret/path");
  expect(text).not.toContain("unsafeHandler");
  expect(text).not.toContain(" at ");
}

function expectNoPolicyLeak(text: string): void {
  expect(text).not.toContain("tier1_always_approve");
  expect(text).not.toContain("tier2_anomaly");
  expect(text).not.toContain("tier3_always_allow");
  expect(text).not.toContain("bulk_read_threshold");
}

describe("HTTP caught-error envelopes", () => {
  let consoleError: MockInstance<typeof console.error>;

  beforeEach(() => {
    consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

  it("hub unexpected exceptions return a stable code without message or stack", async () => {
    const service = {
      listInbox: () => {
        throw leakyError();
      },
    } as unknown as HubService;
    const server = await startRouteServer((req, res) =>
      handleHubRoute(
        {
          authConfig: { authToken: AUTH_TOKEN, loopbackAutoAuth: false },
          service,
        },
        req,
        res,
      ),
    );
    try {
      const res = await fetch(`${server.url}${HUB_API_PREFIX}/inbox`, {
        headers: authHeaders(),
      });
      const text = await res.text();
      expect(res.status).toBe(500);
      expect(JSON.parse(text)).toEqual({ error: "internal_error" });
      expectNoExceptionLeak(text);
      expectNoPolicyLeak(text);
    } finally {
      await server.close();
    }
  });

  it("hub approval denial errors do not name a principal-policy tier or rule", async () => {
    const service = {
      resolveInboxItem: () => {
        throw new HubValidationError(
          "tier1_always_approve blocked by bulk_read_threshold",
        );
      },
    } as unknown as HubService;
    const server = await startRouteServer((req, res) =>
      handleHubRoute(
        {
          authConfig: { authToken: AUTH_TOKEN, loopbackAutoAuth: false },
          service,
        },
        req,
        res,
      ),
    );
    try {
      const res = await fetch(`${server.url}${HUB_API_PREFIX}/inbox/item-1/deny`, {
        method: "POST",
        headers: authHeaders(),
      });
      const text = await res.text();
      expect(res.status).toBe(400);
      expect(JSON.parse(text)).toEqual({ error: "bad_request" });
      expectNoPolicyLeak(text);
    } finally {
      await server.close();
    }
  });

  it("principal-policy approval inbox exceptions return a stable code without message or stack", async () => {
    const aggregator = {
      resolve: () => {
        throw leakyError();
      },
    } as unknown as ApprovalAggregator;
    const server = await startRouteServer((req, res) =>
      handleApprovalInboxRoute(
        {
          authConfig: { authToken: AUTH_TOKEN, loopbackAutoAuth: false },
          aggregator,
        },
        req,
        res,
      ),
    );
    try {
      const res = await fetch(
        `${server.url}${APPROVAL_INBOX_API_PREFIX}/item-1/deny`,
        { method: "POST", headers: authHeaders() },
      );
      const text = await res.text();
      expect(res.status).toBe(500);
      expect(JSON.parse(text)).toEqual({ error: "internal_error" });
      expectNoExceptionLeak(text);
      expectNoPolicyLeak(text);
    } finally {
      await server.close();
    }
  });
});
