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

// Only the complete approved lift-refusal set reaches operator feedback. IC-11.
import { APPROVED_LIFT_REFUSALS_VIEW } from "../../src/hub/api-router.js";
import { HubCapabilityError, HubError } from "../../src/hub/errors.js";
import type { HubApprovalPendingItem } from "../../src/contracts/v1.1/hub-events.js";
import { liftFixture, LIFT_REASONS, REFUSAL_STATUS, refusalDetail, ApprovalReply } from "../hub/lift-refusal-fixture.js";

type Category = HubApprovalPendingItem["operation_category"];
const CATEGORIES = {
  state_export: true, state_import: true, state_delete: true, identity_rotate: true,
  reputation_export: true, reputation_import: true, sanctuary_export_identity_bundle: true,
  exit_bundle_export: true, exit_bundle_import: true, exit_bundle_rekey: true,
  policy_change: true, lockdown: true, lockdown_lift: true, unwrap: true, other: true,
} satisfies Record<Category, true>;
const categoryItem = (id: string, category: Category): HubApprovalPendingItem => ({
  version: "1.1", item_id: id, kind: "approval_pending", created_at: new Date().toISOString(),
  identity_id: "fixture", tier: "tier1", operation_category: category, resolved: false,
  display_template_id: "approval_pending.tier1.other", display_template_args: [],
});

describe("exact stored lift-refusal tuples", () => {
  afterEach(() => vi.restoreAllMocks());
  it("the full allowlist equals the two reviewed tuples and every category is crossed with both errors", async () => {
    const f = await liftFixture();
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const exposed: string[] = [];
    try {
      for (const category of [...Object.keys(CATEGORIES).filter(category => category !== "lockdown_lift"), "unknown-category", "lockdown_lift"] as Category[]) {
        for (const reason of LIFT_REASONS) {
          const id = `${category}.${reason}`;
          const error = new HubCapabilityError(reason);
          error.stack = LEAKY_MESSAGE; error.cause = LEAKY_MESSAGE;
          Object.defineProperty(error, "name", { value: LEAKY_MESSAGE });
          f.inboxStore.enqueueTier1(categoryItem(id, category), async () => { throw error; });
          const reply = await f.call(`/api/hub/inbox/${id}/approve`);
          if (category === "lockdown_lift") {
            expect(reply.statusCode).toBe(REFUSAL_STATUS);
            expect(reply.json()).toEqual({ ok: false, error: "HubCapabilityError", detail: refusalDetail(reason) });
            exposed.push(`${category}:${reason}`);
            expect(JSON.stringify(log.mock.calls)).toContain(`HubCapabilityError: ${refusalDetail(reason)}`);
          } else {
            expect(reply.json()).toEqual({ error: category === "exit_bundle_export" ? "internal_error" : "bad_request" });
          }
          expect(JSON.stringify(log.mock.calls)).not.toContain(LEAKY_MESSAGE);
        }
      }
      expect(Object.isFrozen(APPROVED_LIFT_REFUSALS_VIEW)).toBe(true);
      expect(Object.keys(APPROVED_LIFT_REFUSALS_VIEW).sort()).toEqual([...LIFT_REASONS].sort());
      for (const reason of LIFT_REASONS) {
        expect(APPROVED_LIFT_REFUSALS_VIEW[reason]).toEqual({ reason, detail: refusalDetail(reason) });
        expect(Object.isFrozen(APPROVED_LIFT_REFUSALS_VIEW[reason])).toBe(true);
      }
      expect(exposed).toEqual(LIFT_REASONS.map(reason => `lockdown_lift:${reason}`));
    } finally { await f.close(); }
  });

  it("unknown classes, raw values, permission-only reasons and every mismatched field stay scrubbed", async () => {
    class UnknownCapability extends HubCapabilityError {}
    const allowed = () => new HubCapabilityError(LIFT_REASONS[0]);
    const cases: unknown[] = [new UnknownCapability(LIFT_REASONS[0]), new HubError(refusalDetail(LIFT_REASONS[0]), REFUSAL_STATUS), refusalDetail(LIFT_REASONS[0]), new Error(refusalDetail(LIFT_REASONS[0])), new HubCapabilityError("lockdown_lift"), new HubCapabilityError("unreviewed")];
    for (const [field, value] of [["statusCode", 400], ["message", "different"], ["publicDetail", "different"], ["reasonCode", LIFT_REASONS[1]]] as const) {
      cases.push(Object.defineProperty(allowed(), field, { value }));
    }
    const f = await liftFixture();
    try {
      for (const [index, error] of cases.entries()) {
        const id = `mismatch-${index}`;
        f.inboxStore.enqueueTier1(categoryItem(id, "lockdown_lift"), async () => { throw error; });
        const reply = await f.call(`/api/hub/inbox/${id}/approve`);
        expect(reply.json()).toEqual({ error: error instanceof HubError ? "bad_request" : "internal_error" });
      }
    } finally { await f.close(); }
  });

  it("missing entries, non-approvals and refreshed categories stay scrubbed", async () => {
    const f = await liftFixture();
    const fail = () => { throw new HubCapabilityError(LIFT_REASONS[0]); };
    try {
      expect((await f.call("/api/hub/inbox/absent/approve")).json()).toEqual({ error: "not_found" });
      expect((await f.call("/api/hub/inbox/charter.approval.absent/approve")).json()).toEqual({ error: "not_found" });
      f.inboxStore.enqueueTier1(categoryItem("refresh", "lockdown_lift"), async () => fail());
      vi.spyOn(f.deps.inboxSources, "listPendingApprovals").mockReturnValue([categoryItem("refresh", "other")]);
      expect((await f.call("/api/hub/inbox/refresh/approve")).json()).toEqual({ error: "bad_request" });
      vi.restoreAllMocks();
      f.inboxStore.upsertFromSource({ ...categoryItem("notice", "lockdown_lift"), kind: "agent_error" } as never);
      vi.spyOn(f.inboxStore, "resolve").mockImplementation(async () => fail());
      expect((await f.call("/api/hub/inbox/notice/approve")).json()).toEqual({ error: "bad_request" });
    } finally { await f.close(); }
  });

  it.each(["get", "listPendingApprovals"] as const)("early %s faults on a fresh lift item stay scrubbed", async (fault) => {
    const f = await liftFixture();
    const id = `early-${fault}`;
    const fail = () => { throw new HubCapabilityError(LIFT_REASONS[0]); };
    try {
      f.inboxStore.enqueueTier1(categoryItem(id, "lockdown_lift"), async () => fail());
      // The same pending item and error disclose detail when category observation completes.
      const control = await f.call(`/api/hub/inbox/${id}/approve`);
      expect(control.statusCode).toBe(REFUSAL_STATUS);
      expect(control.json()).toEqual({ ok: false, error: "HubCapabilityError", detail: refusalDetail(LIFT_REASONS[0]) });
      expect(f.inboxStore.get(id)).toMatchObject({ operation_category: "lockdown_lift", resolved: false });
      const spy = fault === "get"
        ? vi.spyOn(f.inboxStore, "get").mockImplementation(fail)
        : vi.spyOn(f.deps.inboxSources, "listPendingApprovals").mockImplementation(fail);
      const reply = await f.call(`/api/hub/inbox/${id}/approve`);
      expect(spy).toHaveBeenCalled();
      expect(reply.statusCode).toBe(REFUSAL_STATUS);
      expect(reply.json()).toEqual({ error: "bad_request" });
    } finally { vi.restoreAllMocks(); await f.close(); }
  });

  it("no category observation means no disclosure", async () => {
    const f = await liftFixture();
    try {
      const spy = vi.spyOn(f.service, "resolveInboxItem").mockRejectedValue(new HubCapabilityError(LIFT_REASONS[0]));
      expect((await f.call("/api/hub/inbox/no-observation/approve")).json()).toEqual({ error: "bad_request" });
      spy.mockRestore();
    } finally { await f.close(); }
  });

  it("the local allowed-refusal writer aborts or scrubs transport faults", async () => {
    const f = await liftFixture();
    try {
      const probe = await f.enqueue(); f.setStatus("active");
      expect((await f.call(`/api/hub/inbox/${probe}/approve`)).json()).toEqual({
        ok: false, error: "HubCapabilityError", detail: refusalDetail(LIFT_REASONS[0]),
      });
      f.setStatus("locked_down");
      for (const started of [false, true]) {
        const id = await f.enqueue(); f.setStatus("active");
        const reply = new ApprovalReply();
        if (started) vi.spyOn(reply, "end").mockImplementationOnce(() => { throw new Error(LEAKY_MESSAGE); });
        else vi.spyOn(reply, "writeHead").mockImplementationOnce(() => { throw new Error(LEAKY_MESSAGE); });
        const log = vi.spyOn(console, "error").mockImplementation(() => {});
        await f.call(`/api/hub/inbox/${id}/approve`, "POST", reply);
        if (started) { expect(reply.destroyed).toBe(true); expect(reply.chunks).toEqual([]); }
        else expect(reply.json()).toEqual({ error: "internal_error" });
        expect(JSON.stringify(log.mock.calls)).not.toContain(LEAKY_MESSAGE);
        vi.restoreAllMocks(); f.setStatus("locked_down");
      }
    } finally { await f.close(); }
  });
});

it("resolved and in-flight entries stay generic and ordinary handlerless decisions still complete", async () => {
  const f = await liftFixture();
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  let winner: ReturnType<typeof f.call> | undefined;
  try {
    f.inboxStore.enqueueTier1(categoryItem("in-flight", "lockdown_lift"), async () => { enter(); await gate; });
    winner = f.call("/api/hub/inbox/in-flight/approve");
    await entered;
    expect((await f.call("/api/hub/inbox/in-flight/approve")).json()).toEqual({ error: "conflict" });
    release();
    expect((await winner).json().data.item.resolved).toBe(true);
    expect((await f.call("/api/hub/inbox/in-flight/approve")).json()).toEqual({ error: "conflict" });
    f.inboxStore.upsertFromSource(categoryItem("handlerless", "other"));
    expect((await f.call("/api/hub/inbox/handlerless/approve")).json().data.item.resolved).toBe(true);
  } finally { release(); await winner; await f.close(); }
});
