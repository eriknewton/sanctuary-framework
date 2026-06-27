/**
 * Dashboard API handler tests
 *
 * Covers: constantTimeEquals() behavior, token extraction, authorization,
 * request routing (health, snapshot, approvals, 404).
 * Not covered: SSE streaming performance, real HTTP socket behavior.
 */

import { describe, it, expect, vi } from "vitest";
import {
  constantTimeEquals,
  extractToken,
  isAuthorized,
  handleRequest,
  type APIDeps,
} from "../../src/dashboard/api.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function mockReq(opts: { url?: string; method?: string; headers?: Record<string, string> }): IncomingMessage {
  return {
    url: opts.url ?? "/",
    method: opts.method ?? "GET",
    headers: opts.headers ?? {},
  } as unknown as IncomingMessage;
}

function mockRes(): ServerResponse & { _status: number; _body: string; _headers: Record<string, string> } {
  const res = {
    _status: 0,
    _body: "",
    _headers: {} as Record<string, string>,
    writeHead: vi.fn((status: number, headers?: Record<string, string>) => {
      res._status = status;
      if (headers) Object.assign(res._headers, headers);
    }),
    end: vi.fn((body?: string) => { res._body = body ?? ""; }),
    write: vi.fn(),
    on: vi.fn(),
  };
  return res as any;
}

describe("Dashboard API", () => {
  describe("constantTimeEquals", () => {
    it("returns true for matching strings", () => {
      expect(constantTimeEquals("abc", "abc")).toBe(true);
    });

    it("returns false for different strings", () => {
      expect(constantTimeEquals("abc", "abd")).toBe(false);
    });

    it("returns false for different lengths", () => {
      expect(constantTimeEquals("ab", "abc")).toBe(false);
    });

    it("returns true for empty strings", () => {
      expect(constantTimeEquals("", "")).toBe(true);
    });

    it("handles long tokens", () => {
      const a = "x".repeat(1000);
      const b = "x".repeat(999) + "y";
      expect(constantTimeEquals(a, b)).toBe(false);
    });
  });

  describe("extractToken", () => {
    it("extracts from Authorization: Bearer header", () => {
      const req = mockReq({ headers: { authorization: "Bearer tok123" } });
      const url = new URL("http://localhost/");
      expect(extractToken(req, url)).toBe("tok123");
    });

    it("ignores ?token= query parameter", () => {
      const req = mockReq({ url: "/?token=qp-tok" });
      const url = new URL("http://localhost/?token=qp-tok");
      expect(extractToken(req, url)).toBeNull();
    });

    it("returns null when no token present", () => {
      const req = mockReq({});
      const url = new URL("http://localhost/");
      expect(extractToken(req, url)).toBeNull();
    });

    it("uses the header when a query token is also present", () => {
      const req = mockReq({
        url: "/?token=query",
        headers: { authorization: "Bearer header" },
      });
      const url = new URL("http://localhost/?token=query");
      expect(extractToken(req, url)).toBe("header");
    });
  });

  describe("isAuthorized", () => {
    it("returns true when no authToken configured", () => {
      const deps: APIDeps = { sources: {} as any };
      expect(isAuthorized(deps, mockReq({}), new URL("http://localhost/"))).toBe(true);
    });

    it("returns false when token is missing", () => {
      const deps: APIDeps = { sources: {} as any, authToken: "secret" };
      expect(isAuthorized(deps, mockReq({}), new URL("http://localhost/"))).toBe(false);
    });

    it("returns true when token matches", () => {
      const deps: APIDeps = { sources: {} as any, authToken: "secret" };
      const req = mockReq({ headers: { authorization: "Bearer secret" } });
      expect(isAuthorized(deps, req, new URL("http://localhost/"))).toBe(true);
    });

    it("returns true when a valid short-lived session is provided", () => {
      const deps: APIDeps = {
        sources: {} as any,
        authToken: "secret",
        sessions: { create: vi.fn(), validate: vi.fn((id: string) => id === "sess-ok") },
      };
      expect(
        isAuthorized(deps, mockReq({}), new URL("http://localhost/?session=sess-ok"))
      ).toBe(true);
    });

    it("rejects long-lived ?token= query auth", () => {
      const deps: APIDeps = { sources: {} as any, authToken: "secret" };
      expect(
        isAuthorized(deps, mockReq({ url: "/?token=secret" }), new URL("http://localhost/?token=secret"))
      ).toBe(false);
    });

    it("returns false when token mismatches", () => {
      const deps: APIDeps = { sources: {} as any, authToken: "secret" };
      const req = mockReq({ headers: { authorization: "Bearer wrong" } });
      expect(isAuthorized(deps, req, new URL("http://localhost/"))).toBe(false);
    });
  });

  describe("handleRequest", () => {
    function makeDeps(overrides?: Partial<APIDeps>): APIDeps {
      return {
        sources: {
          mode: "co-located" as const,
          stateStore: null,
          identityManager: null,
          policyLoader: null,
          auditLog: { query: vi.fn(async () => ({ entries: [], total: 0 })) },
          commitmentStore: null,
          reputationStore: null,
          upstreamStatus: null,
        } as any,
        authToken: "tok",
        ...overrides,
      };
    }

    it("returns 401 for unauthorized requests", async () => {
      const res = mockRes();
      const deps = makeDeps();
      await handleRequest(deps, mockReq({}), res);
      expect(res._status).toBe(401);
    });

    it("mints a short-lived session from the Authorization header only", async () => {
      const res = mockRes();
      const create = vi.fn(() => ({ id: "sess-created", expiresInSeconds: 300 }));
      const deps = makeDeps({
        sessions: { create, validate: vi.fn() },
      });
      const req = mockReq({
        url: "/auth/session",
        method: "POST",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      expect(create).toHaveBeenCalledOnce();
      expect(JSON.parse(res._body)).toEqual({
        session_id: "sess-created",
        expires_in_seconds: 300,
      });
    });

    it("rejects session exchange without a bearer header", async () => {
      const res = mockRes();
      const create = vi.fn(() => ({ id: "sess-created", expiresInSeconds: 300 }));
      const deps = makeDeps({
        sessions: { create, validate: vi.fn() },
      });
      const req = mockReq({
        url: "/auth/session?token=tok",
        method: "POST",
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(401);
      expect(create).not.toHaveBeenCalled();
    });

    it("serves /api/health without auth with ok/mode + opaque instance/since (brief D3)", async () => {
      const res = mockRes();
      const deps = makeDeps();
      const req = mockReq({ url: "/api/health" });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      const body = JSON.parse(res._body);
      // brief D3: `{ ok, mode }` plus the opaque restart-detection signal.
      expect(Object.keys(body).sort()).toEqual(["instance", "mode", "ok", "since"]);
      expect(body.ok).toBe(true);
      expect(body.mode).toBe("co-located");
      expect(typeof body.instance).toBe("string");
      expect(typeof body.since).toBe("number");
      // brief HIGH-1: readiness/posture MUST NOT be on the unauthenticated probe.
      expect(body.ready).toBeUndefined();
      expect(body.supervisor).toBeUndefined();
    });

    it("/api/readiness returns 401 without auth (brief D3 auth gate)", async () => {
      const res = mockRes();
      const deps = makeDeps();
      const req = mockReq({ url: "/api/readiness" });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(401);
      const body = JSON.parse(res._body);
      expect(body.ready).toBeUndefined();
      expect(body.supervisor).toBeUndefined();
    });

    it("/api/readiness returns ready=locked + supervisor=n/a with auth, no identity manager", async () => {
      const res = mockRes();
      const deps = makeDeps();
      const req = mockReq({
        url: "/api/readiness",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      const body = JSON.parse(res._body);
      expect(Object.keys(body).sort()).toEqual(["ready", "supervisor"]);
      expect(body.ready).toBe("locked");
      // "n/a" is honest in THIS mode only: the api.ts co-located read-aggregator
      // dashboard has no Protect launch route, so an absent bridge does NOT
      // guarantee a 503 (contrast the principal-policy dashboard, where absence
      // => 503 and the honest value is "unwired", brief Fix 1).
      expect(body.supervisor).toBe("n/a");
    });

    it("/api/readiness reports ready=serving when an identity manager is wired", async () => {
      const res = mockRes();
      const deps = makeDeps({
        sources: {
          mode: "co-located" as const,
          identityManager: {} as any,
          auditLog: { query: vi.fn(async () => ({ entries: [], total: 0 })) },
        } as any,
      });
      const req = mockReq({
        url: "/api/readiness",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      const body = JSON.parse(res._body);
      expect(body.ready).toBe("serving");
    });

    it("/api/readiness honors an explicit readiness + supervisor provider", async () => {
      const res = mockRes();
      const deps = makeDeps({
        readiness: () => "serving",
        supervisorStatus: () => "wired",
      });
      const req = mockReq({
        url: "/api/readiness",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      const body = JSON.parse(res._body);
      expect(body.ready).toBe("serving");
      expect(body.supervisor).toBe("wired");
    });

    it("wrap-auto posture home reports no live stream when no stream registry is wired", async () => {
      const res = mockRes();
      const deps = makeDeps();
      deps.sources.auditLog = new AuditLog(new MemoryStorage(), generateRandomKey()) as any;
      const req = mockReq({
        url: "/api/posture/home",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(200);
      const body = JSON.parse(res._body) as { stream_available?: boolean };
      expect(body.stream_available).toBe(false);
    });

    it("returns 503 for approvals when no handlers", async () => {
      const res = mockRes();
      const deps = makeDeps({ approvals: undefined });
      const req = mockReq({
        url: "/api/approvals/test-id/allow",
        method: "POST",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(true);
      expect(res._status).toBe(503);
    });

    it("returns false for unmatched routes", async () => {
      const res = mockRes();
      const deps = makeDeps();
      const req = mockReq({
        url: "/nonexistent",
        headers: { authorization: "Bearer tok" },
      });
      const matched = await handleRequest(deps, req, res);
      expect(matched).toBe(false);
    });
  });
});
