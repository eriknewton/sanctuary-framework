/**
 * A broker request is one call: a refused or cancelled request adds nothing
 * to the broker's agent-facing audit read, a successful one does, and the
 * operator's broker audit keeps every row.
 */
import { afterEach, describe, expect, it } from "vitest";
import { getEventListeners } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import {
  AuditLog,
  BROKER_OPS,
  CALL_OUTCOME_SUCCESS_OPERATION,
  runInCallScope,
  settleCallOutcome,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import { AGENT_AUDIT_VIEW_FIELDS } from "../../src/operational/agent-audit-redaction.js";

const IDENTITY = "did:sanctuary:1";
const SECRET_VALUE = Buffer.from(generateRandomKey()).toString("base64url");

type Handler = (req: unknown, extra: unknown) => Promise<{ isError?: boolean; content: Array<{ text: string }> }>;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function backend(read?: () => Promise<void>): Backend {
  const store = new Map([["openai-api-key", SECRET_VALUE], ["bound-key", SECRET_VALUE]]);
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() { return true; },
    async addSecret(n, v) { store.set(n, v); },
    async readSecret(n) {
      await read?.();
      const v = store.get(n);
      if (v === undefined) throw new SecretNotFoundError(n);
      return v;
    },
    async rotateSecret(n, v) { store.set(n, v); },
    async deleteSecret(n) { store.delete(n); },
    async listSecretNames() { return Array.from(store.keys()); },
  };
}

function rig(read?: () => Promise<void>) {
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const broker = new Broker({
    backend: backend(read),
    auditLog,
    surrogateBoundSecrets: new Set(["bound-key"]),
    grants: [
      { skill: "gmail-triage", secret: "openai-api-key", scope: "read" },
      { skill: "gmail-triage", secret: "bound-key", scope: "read" },
    ],
    principalIdentityId: IDENTITY,
  });
  const server = createBrokerMcpServer(broker, {
    skill: "gmail-triage",
    agentId: "nsa",
    identityId: IDENTITY,
    tenantId: "tenant-alpha",
    fortressId: "fortress-alpha",
    audience: "sanctuary-broker",
  });
  const handler = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers.get("tools/call")!;
  const callTool = (name: string, args: Record<string, unknown>, signal: AbortSignal = new AbortController().signal) =>
    handler({ method: "tools/call", params: { name, arguments: args } }, { signal });
  return { auditLog, broker, server, callTool };
}

function parse(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function agentAudit(r: ReturnType<typeof rig>): Promise<Record<string, unknown>> {
  await r.auditLog.flush();
  return parse(await r.callTool("broker/audit_query", { limit: 1_000 }));
}

async function markers(log: AuditLog): Promise<number> {
  await log.flush();
  return (await log.query({ limit: 10_000, include_outcome_markers: true })).entries
    .filter((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION).length;
}

/** The agent read minus the audit_query call's own visible footprint, which is the same before and after. */
function shape(read: Record<string, unknown>): unknown {
  return { total: read.total, entries: (read.entries as Array<Record<string, unknown>>).map((e) => [e.operation, e.result, e.has_details]) };
}

describe("broker audit_query follows each request's outcome", () => {
  it("a surrogate-bound token request and a missing-grant request each leave broker audit_query output identical", async () => {
    const r = rig();
    expect((await r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" })).isError).toBeUndefined();
    for (const refused of [
      { skill: "gmail-triage", secret: "bound-key" },
      { skill: "gmail-triage", secret: "never-granted" },
    ]) {
      const before = shape(await agentAudit(r));
      const result = await r.callTool("broker/request_token", refused);
      expect(result.isError).toBe(true);
      expect(parse(result).error).toBe("Broker denied");
      const after = shape(await agentAudit(r));
      expect(after).toEqual(before);
    }
    // The operator view still holds both refusals.
    const operator = await r.broker.queryAuditOperator({ limit: 1_000 });
    const ops = operator.entries.map((e) => e.operation);
    expect(ops).toContain(BROKER_OPS.SURROGATE_TOKEN_REFUSED);
    expect(ops).toContain(BROKER_OPS.TOKEN_DENIED);
  });

  it("a broker request that succeeds is visible in broker audit_query", async () => {
    const r = rig();
    const before = await agentAudit(r);
    expect((await r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" })).isError).toBeUndefined();
    const after = await agentAudit(r);
    expect(after.total).toBe((before.total as number) + 1);
    expect((after.entries as Array<{ operation: string }>).map((e) => e.operation)).toContain(BROKER_OPS.TOKEN_ISSUED);
  });

  it("a broker request cancelled before it returns writes no marker and returns the generic denial", async () => {
    const r = rig();
    for (let wave = 0; wave < 3; wave++) {
      const before = await markers(r.auditLog);
      const controllers = Array.from({ length: 8 }, () => new AbortController());
      const pending = controllers.map((c) => r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" }, c.signal));
      for (const c of controllers) c.abort();
      for (const result of await Promise.all(pending)) {
        expect(result).toEqual({ content: [{ type: "text", text: JSON.stringify({ error: "Broker denied" }) }], isError: true });
      }
      expect(await markers(r.auditLog)).toBe(before);
      for (const c of controllers) expect(getEventListeners(c.signal, "abort")).toHaveLength(0);
      // The next request in the same server still commits and marks.
      expect((await r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" })).isError).toBeUndefined();
      expect(await markers(r.auditLog)).toBe(before + 1);
    }
  });

  it("a broker read cancelled through the SDK writes no marker and leaves no listener", async () => {
    let release!: () => void;
    let entered = 0;
    let gate = new Promise<void>((resolve) => { release = resolve; });
    const r = rig(async () => { entered += 1; await gate; });
    const issued = parse(await r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" }));
    const client = new Client({ name: "broker-cancel", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await r.server.connect(serverTransport);
    await client.connect(clientTransport);
    cleanups.push(async () => { await client.close(); await r.server.close(); });
    for (let wave = 0; wave < 3; wave++) {
      entered = 0;
      const before = await markers(r.auditLog);
      const controllers = Array.from({ length: 4 }, () => new AbortController());
      const pending = controllers.map((c) =>
        client.callTool({ name: "broker/read_secret", arguments: { token: issued.token } }, undefined, { signal: c.signal })
          .then(() => "resolved", () => "rejected"));
      for (let i = 0; i < 2_000 && entered < controllers.length; i++) await new Promise((resolve) => setImmediate(resolve));
      expect(entered).toBe(controllers.length);
      for (const c of controllers) c.abort();
      await new Promise((resolve) => setTimeout(resolve, 20));
      release();
      expect(await Promise.all(pending)).toEqual(Array(controllers.length).fill("rejected"));
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(await markers(r.auditLog)).toBe(before);
      gate = new Promise<void>((resolve) => { release = resolve; });
    }
  });

  it("broker audit_query entries carry exactly the four redacted fields and no call reference", async () => {
    const r = rig();
    expect((await r.callTool("broker/request_token", { skill: "gmail-triage", secret: "openai-api-key" })).isError).toBeUndefined();
    const read = await agentAudit(r);
    const entries = read.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(Object.keys(entry).sort()).toEqual([...AGENT_AUDIT_VIEW_FIELDS].sort());
      expect(Object.hasOwn(entry, "call_ref")).toBe(false);
    }
  });

  it("broker audit_query returns no row from a refused main-server call over the same log, and the operator broker audit still does", async () => {
    const r = rig();
    await runInCallScope(async (scope) => {
      await r.auditLog.append("l3", BROKER_OPS.TOKEN_ISSUED, IDENTITY, { secret: "openai-api-key" });
      settleCallOutcome(scope, "refused");
    });
    await r.auditLog.flush();
    const agent = await agentAudit(r);
    expect(agent.total).toBe(0);
    const operator = await r.broker.queryAuditOperator({ limit: 1_000 });
    expect(operator.entries.map((e) => e.operation)).toContain(BROKER_OPS.TOKEN_ISSUED);
  });
});
