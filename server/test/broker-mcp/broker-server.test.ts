/**
 * Broker MCP Server Tests
 *
 * Verifies the MCP surface that harnesses (OpenClaw, Cline, etc.) see:
 * - request_token issues a binding for a valid (skill, secret) pair.
 * - request_token denies with a generic error when no grant exists.
 * - read_secret returns the value for a valid token.
 * - read_secret denies generically on unknown/expired/revoked tokens.
 * - list_grants surfaces grants without secret values.
 * - audit_query returns broker-scoped entries and never leaks values.
 */

import { describe, it, expect } from "vitest";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Backend } from "../../src/l3-disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/l3-disclosure/broker/backend-interface.js";
import { Broker } from "../../src/l3-disclosure/broker/broker.js";
import { AuditLog, BROKER_OPS } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";

function makeFakeBackend(seed: Record<string, string> = {}): Backend {
  const store = new Map(Object.entries(seed));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(n, v) {
      if (store.has(n)) throw new Error("exists");
      store.set(n, v);
    },
    async readSecret(n) {
      const v = store.get(n);
      if (v === undefined) throw new SecretNotFoundError(n);
      return v;
    },
    async rotateSecret(n, v) {
      if (!store.has(n)) throw new SecretNotFoundError(n);
      store.set(n, v);
    },
    async deleteSecret(n) {
      if (!store.delete(n)) throw new SecretNotFoundError(n);
    },
    async listSecretNames() {
      return Array.from(store.keys());
    },
  };
}

async function makeServer() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const backend = makeFakeBackend({ gmail_oauth: "SECRET-VALUE-XYZ" });
  const broker = new Broker({
    backend,
    auditLog,
    grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
    principalIdentityId: "did:sanctuary:1",
  });
  const server = createBrokerMcpServer(broker, {
    skill: "gmail-triage",
    agentId: "nsa",
    identityId: "did:sanctuary:1",
    tenantId: "tenant-alpha",
    fortressId: "fortress-alpha",
    audience: "sanctuary-broker",
  });
  return { server, broker, auditLog };
}

/** Simulate an MCP tools/call request via the server's request handler. */
async function callTool(server: ReturnType<typeof createBrokerMcpServer>, name: string, args: Record<string, unknown>) {
  const request = {
    method: "tools/call" as const,
    params: { name, arguments: args },
  };
  // @ts-expect-error the Server exposes _requestHandlers via private API; we
  // call via the MCP SDK's onRpcMessage path using listTools handler lookup.
  const handler = (server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get(
    "tools/call"
  );
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(request, {});
}

async function listTools(server: ReturnType<typeof createBrokerMcpServer>) {
  const request = {
    method: "tools/list" as const,
    params: {},
  };
  const handler = (server as unknown as { _requestHandlers: Map<string, Function> })._requestHandlers.get(
    "tools/list"
  );
  if (!handler) throw new Error("tools/list handler not registered");
  return await handler(request, {});
}

function parseContent(result: { content: Array<{ text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

describe("Broker MCP Server", () => {
  describe("tools/list", () => {
    it("advertises the four broker tools", async () => {
      const { server } = await makeServer();
      const result = await listTools(server);
      const names = (result.tools as Array<{ name: string }>).map((t) => t.name);
      expect(names).toContain("broker/request_token");
      expect(names).toContain("broker/read_secret");
      expect(names).toContain("broker/list_grants");
      expect(names).toContain("broker/audit_query");
    });
  });

  describe("broker/request_token", () => {
    it("returns {token, expires_at, scope} when grant exists", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
      });
      const body = parseContent(result);
      expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(body.scope).toBe("read");
      expect(Date.parse(body.expires_at)).toBeGreaterThan(Date.now());
    });

    it("returns generic error when no grant", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/request_token", {
        skill: "unknown",
        secret: "gmail_oauth",
      });
      expect(result.isError).toBe(true);
      const body = parseContent(result);
      expect(body.error).toBe("Broker denied");
    });

    it("denies impersonation when request skill does not match verified caller skill", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const broker = new Broker({
        backend: makeFakeBackend({ gmail_oauth: "SECRET-VALUE-XYZ" }),
        auditLog,
        grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
        principalIdentityId: "did:sanctuary:1",
      });
      const server = createBrokerMcpServer(broker, {
        skill: "ungranted-skill",
        agentId: "nsa",
        identityId: "did:sanctuary:1",
        tenantId: "tenant-alpha",
        fortressId: "fortress-alpha",
        audience: "sanctuary-broker",
      });

      const result = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
      });

      expect(result.isError).toBe(true);
      expect(parseContent(result).error).toBe("Broker denied");
      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
      expect(audit.entries[0]!.details?.reason).toBe("caller_skill_mismatch");
    });

    it("denies when scope exceeds grant", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
        scope: "rotate",
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("broker/read_secret", () => {
    it("returns the value for a valid token", async () => {
      const { server } = await makeServer();
      const issue = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
      });
      const { token } = parseContent(issue);
      const result = await callTool(server, "broker/read_secret", { token });
      const body = parseContent(result);
      expect(body.value).toBe("SECRET-VALUE-XYZ");
    });

    it("returns generic error on unknown token", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/read_secret", { token: "fake" });
      expect(result.isError).toBe(true);
      const body = parseContent(result);
      expect(body.error).toBe("Broker denied");
    });

    it("returns generic error when grant was revoked after issuance", async () => {
      const { server, broker } = await makeServer();
      const issue = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
      });
      const { token } = parseContent(issue);
      broker.revoke("gmail-triage", "gmail_oauth");
      const result = await callTool(server, "broker/read_secret", { token });
      expect(result.isError).toBe(true);
    });
  });

  describe("broker/list_grants", () => {
    it("lists grants without secret values", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/list_grants", {});
      const body = parseContent(result);
      expect(body.grants).toHaveLength(1);
      expect(body.grants[0].skill).toBe("gmail-triage");
      expect(body.grants[0].secret).toBe("gmail_oauth");
      const serialized = JSON.stringify(body);
      expect(serialized).not.toContain("SECRET-VALUE-XYZ");
    });
  });

  describe("broker/audit_query", () => {
    it("returns the allowlist-redacted view and leaks neither secret value, secret NAME, scope, ttl, reason, nor tenant", async () => {
      const { server } = await makeServer();
      // Generate audit activity: a successful issue+read, and a DENIED request
      // whose details (granted_scope, reason "scope_exceeds_grant") must not leak.
      const issue = await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
      });
      const { token } = parseContent(issue);
      await callTool(server, "broker/read_secret", { token });
      // Over-scope request → TOKEN_DENIED with reason "scope_exceeds_grant" +
      // granted_scope "read" in its operator details.
      await callTool(server, "broker/request_token", {
        skill: "gmail-triage",
        secret: "gmail_oauth",
        scope: "rotate",
      });

      const result = await callTool(server, "broker/audit_query", {});
      const body = parseContent(result);
      const ops = body.entries.map((e: { operation: string }) => e.operation);
      expect(ops).toContain(BROKER_OPS.TOKEN_ISSUED);
      expect(ops).toContain(BROKER_OPS.SECRET_READ);

      // Every entry is the fixed allowlist view — no `details`, no identity.
      for (const e of body.entries) {
        expect(Object.keys(e).sort()).toEqual([
          "has_details",
          "operation",
          "result",
          "timestamp",
        ]);
      }

      const serialized = JSON.stringify(body);
      // No secret value, no secret NAME, no scope/ttl/reason/tenant/audience.
      expect(serialized).not.toContain("SECRET-VALUE-XYZ");
      expect(serialized).not.toContain("gmail_oauth"); // the secret NAME
      expect(serialized).not.toContain("granted_scope");
      expect(serialized).not.toContain("scope_exceeds_grant");
      expect(serialized).not.toContain("ttl_seconds");
      expect(serialized).not.toContain("tenant-alpha");
      expect(serialized).not.toContain("sanctuary-broker"); // audience
    });
  });

  describe("unknown tools", () => {
    it("returns generic error for unknown tool name", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/does_not_exist", {});
      expect(result.isError).toBe(true);
    });
  });

  describe("argument validation", () => {
    it("denies generically on missing skill/secret", async () => {
      const { server } = await makeServer();
      const result = await callTool(server, "broker/request_token", {});
      expect(result.isError).toBe(true);
    });
  });
});
