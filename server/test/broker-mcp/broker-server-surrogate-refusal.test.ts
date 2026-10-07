/**
 * Capability: the refusal reaches the agent through the REAL MCP handler, not
 * just through the issuer in isolation. `broker/request_token` and
 * `broker/read_secret` are called the way a harness calls them, against a server
 * built by the production composition root (`createBrokerMcpServer`), and a
 * surrogate-bound secret is refused with the same generic error an ungranted one
 * produces.
 *
 * The MCP surface itself is untouched by this slice: no new tool, no new scope,
 * no description change. This suite is the wired-consumer proof that the refusal
 * still arrives, which is what lets the `read_secret` description stay true.
 *
 * Defect id: SURROGATE-BROKER-REACHABLE.
 */

import { describe, expect, it } from "vitest";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import { AuditLog, BROKER_OPS } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";

/** Generated per run; never a literal that could be mistaken for a real value. */
const BOUND_VALUE = Buffer.from(generateRandomKey()).toString("base64url");

function makeFakeBackend(seed: Record<string, string> = {}): Backend {
  const store = new Map(Object.entries(seed));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(n, v) {
      if (store.has(n)) throw new Error(`exists: ${n}`);
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

/**
 * A broker whose policy still names the bound secret, exactly as a fortress
 * looks in the moment before an operator removes the stale grant row. The
 * binding is what must refuse, not the absence of the grant.
 */
async function makeServer(bound: Set<string>) {
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const broker = new Broker({
    backend: makeFakeBackend({ "openai-api-key": BOUND_VALUE }),
    auditLog,
    surrogateBoundSecrets: bound,
    grants: [{ skill: "gmail-triage", secret: "openai-api-key", scope: "read" }],
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

async function callTool(
  server: ReturnType<typeof createBrokerMcpServer>,
  name: string,
  args: Record<string, unknown>,
) {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, (req: unknown, extra: unknown) => Promise<unknown>> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return (await handler({ method: "tools/call", params: { name, arguments: args } }, {})) as {
    isError?: boolean;
    content: Array<{ text: string }>;
  };
}

function parseContent(result: { content: Array<{ text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

describe("the MCP surface refuses a surrogate-bound secret", () => {
  it("request_token is denied generically, and the value never crosses", async () => {
    const { server, auditLog } = await makeServer(new Set(["openai-api-key"]));
    const result = await callTool(server, "broker/request_token", {
      skill: "gmail-triage",
      secret: "openai-api-key",
    });
    expect(result.isError).toBe(true);
    // The SAME wording an ungranted secret produces: the surface must not be
    // usable to enumerate which names are bound.
    expect(parseContent(result).error).toBe("Broker denied");
    expect(JSON.stringify(result)).not.toContain(BOUND_VALUE);

    await auditLog.flush();
    const refusals = await auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(refusals.entries).toHaveLength(1);
    expect(refusals.entries[0]!.details?.surface).toBe("issue_token");
  });

  it("read_secret is denied for a token whose secret became bound after issuance", async () => {
    const bound = new Set<string>();
    const { server, auditLog } = await makeServer(bound);
    const issue = await callTool(server, "broker/request_token", {
      skill: "gmail-triage",
      secret: "openai-api-key",
    });
    const { token } = parseContent(issue);

    bound.add("openai-api-key");

    const result = await callTool(server, "broker/read_secret", { token });
    expect(result.isError).toBe(true);
    expect(parseContent(result).error).toBe("Broker denied");
    expect(JSON.stringify(result)).not.toContain(BOUND_VALUE);

    await auditLog.flush();
    const refusals = await auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(refusals.entries).toHaveLength(1);
    expect(refusals.entries[0]!.details?.surface).toBe("read_via_token");
  });

  it("an unbound secret still reads through the same handler", async () => {
    // No-regression: the refusal is narrow. Without this, a broken bound-set
    // thread that denied everything would look like a passing suite.
    const { server } = await makeServer(new Set<string>());
    const issue = await callTool(server, "broker/request_token", {
      skill: "gmail-triage",
      secret: "openai-api-key",
    });
    const result = await callTool(server, "broker/read_secret", {
      token: parseContent(issue).token,
    });
    expect(parseContent(result).value).toBe(BOUND_VALUE);
  });
});
