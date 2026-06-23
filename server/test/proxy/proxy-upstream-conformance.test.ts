import { fileURLToPath } from "node:url";
import { describe, expect, it, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer, type ToolDefinition } from "../../src/router.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog, type AuditEntry } from "../../src/operational/audit-log.js";
import {
  createContextGateTools,
} from "../../src/operational/context-gate-tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { InjectionDetector } from "../../src/security/injection-detector.js";
import { ClientManager } from "../../src/proxy/client-manager.js";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

const FIXTURE_PATH = fileURLToPath(
  new URL("./fixtures/upstream-conformance-server.mjs", import.meta.url)
);
const UPSTREAM_NAME = "real_stdio";

type CallResult = Awaited<ReturnType<Client["callTool"]>>;

interface HarnessCleanup {
  client?: Client;
  clientManager: ClientManager;
}

const harnesses: HarnessCleanup[] = [];

class RecordingInjectionDetector extends InjectionDetector {
  readonly scannedTools: string[] = [];

  override scan(toolName: string, args: Record<string, unknown>) {
    this.scannedTools.push(toolName);
    return super.scan(toolName, args);
  }
}

interface ConformanceHarness {
  client: Client;
  clientManager: ClientManager;
  auditLog: AuditLog;
  injectionDetector: RecordingInjectionDetector;
}

afterEach(async () => {
  while (harnesses.length > 0) {
    const harness = harnesses.pop()!;
    try {
      await harness.client?.close();
    } finally {
      await harness.clientManager.shutdown();
    }
  }
});

describe("proxy upstream transport conformance", () => {
  it("exposes a real stdio upstream only under proxy names and routes allowed calls through the full chain", async () => {
    const harness = await makeHarness();

    const listed = await harness.client.listTools();
    const toolNames = listed.tools.map((tool) => tool.name).sort();

    expect(toolNames).toEqual([
      "proxy/real_stdio/echo",
      "proxy/real_stdio/explode",
      "proxy/real_stdio/malformed",
      "proxy/real_stdio/stats",
    ]);
    expect(toolNames).not.toContain("echo");
    expect(toolNames).not.toContain("stats");

    const result = await harness.client.callTool({
      name: "proxy/real_stdio/echo",
      arguments: { message: "hello through proxy" },
    });

    const payload = textJson(result);
    expect(payload).toEqual({
      echoed: { message: "hello through proxy" },
      forwardedCallCount: 1,
    });

    const audit = await auditEntries(harness.auditLog);
    expect(audit).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "gate_allow_proxy:proxy/real_stdio/echo",
          result: "success",
        }),
        expect.objectContaining({
          operation: "context_gate_enforcer_filter",
          result: "success",
        }),
        expect.objectContaining({
          operation: "proxy_call:proxy/real_stdio/echo",
          result: "success",
          details: expect.objectContaining({
            event_type: "proxy.call",
            decision: "allowed",
            server: "real_stdio",
            tool: "echo",
          }),
        }),
      ])
    );
    expect(
      harness.injectionDetector.scannedTools.filter(
        (toolName) => toolName === "proxy/real_stdio/echo"
      )
    ).toHaveLength(2);
  });

  it("blocks a context-gate deny before the real upstream sees the call", async () => {
    const harness = await makeHarness();
    expect(await forwardedCallCount(harness)).toBe(0);

    const result = await harness.client.callTool({
      name: "proxy/real_stdio/echo",
      arguments: {
        message: "allowed text",
        secret: "must not reach upstream",
      },
    });

    const payload = textJson(result);
    expect(payload.error).toBe("Operation not permitted");
    expect(JSON.stringify(payload)).not.toContain("must not reach upstream");
    expect(await forwardedCallCount(harness)).toBe(0);

    const audit = await auditEntries(harness.auditLog);
    expect(audit).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "gate_allow_proxy:proxy/real_stdio/echo",
          result: "success",
        }),
        expect.objectContaining({
          operation: "context_gate_enforcer_block",
          result: "success",
        }),
        expect.objectContaining({
          operation: "proxy_context_gating_blocked:proxy/real_stdio/echo",
          result: "failure",
          details: expect.objectContaining({
            decision: "denied",
            reason: "context_gating_blocked",
            denied_fields: ["secret"],
          }),
        }),
      ])
    );
    expect(audit).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "proxy_call:proxy/real_stdio/echo",
          result: "success",
        }),
      ])
    );
  });

  it("fails closed for raw and namespaced-twice bypass attempts", async () => {
    const harness = await makeHarness();
    expect(await forwardedCallCount(harness)).toBe(0);

    const raw = await harness.client.callTool({
      name: "echo",
      arguments: { message: "raw upstream name" },
    });
    const doubled = await harness.client.callTool({
      name: "proxy/real_stdio/proxy/real_stdio/echo",
      arguments: { message: "double namespace" },
    });

    expect(raw.isError).toBe(true);
    expect(doubled.isError).toBe(true);
    expect(textJson(raw).error).toBe("Unknown tool: echo");
    expect(textJson(doubled).error).toBe(
      "Unknown tool: proxy/real_stdio/proxy/real_stdio/echo"
    );
    expect(await forwardedCallCount(harness)).toBe(0);

    const audit = await auditEntries(harness.auditLog);
    expect(audit).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "proxy_call:proxy/real_stdio/echo",
        }),
      ])
    );
  });

  it("contains upstream malformed responses and thrown errors as audited proxy errors", async () => {
    const harness = await makeHarness();

    const malformed = await harness.client.callTool({
      name: "proxy/real_stdio/malformed",
      arguments: {},
    });
    const malformedPayload = textJson(malformed);
    expect(malformedPayload.proxy).toBe(true);
    expect(malformedPayload.code).toBe("upstream_error");
    expect(String(malformedPayload.error)).toContain("Invalid");

    const exploded = await harness.client.callTool({
      name: "proxy/real_stdio/explode",
      arguments: {},
    });
    const errorPayload = textJson(exploded);
    expect(errorPayload.proxy).toBe(true);
    expect(errorPayload.code).toBe("upstream_error");
    expect(String(errorPayload.error)).not.toContain("/tmp/private-path");
    expect(await forwardedCallCount(harness)).toBe(2);

    const audit = await auditEntries(harness.auditLog);
    expect(audit).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "proxy_call:proxy/real_stdio/malformed",
          result: "failure",
          details: expect.objectContaining({
            decision: "error",
            error_type: "upstream_error",
          }),
        }),
        expect.objectContaining({
          operation: "proxy_call:proxy/real_stdio/explode",
          result: "failure",
          details: expect.objectContaining({
            decision: "error",
            error_type: "upstream_error",
          }),
        }),
      ])
    );

    const explodedAudit = audit.find(
      (entry) =>
        entry.operation === "proxy_call:proxy/real_stdio/explode" &&
        entry.result === "failure"
    );
    expect(explodedAudit).toBeDefined();
    if (!explodedAudit) {
      throw new Error("expected audited failure for proxy/real_stdio/explode");
    }

    const explodedDetails = explodedAudit.details;
    expect(explodedDetails).toEqual(
      expect.objectContaining({
        error: expect.any(String),
      })
    );

    const explodedError = explodedDetails?.error;
    expect(typeof explodedError).toBe("string");
    if (typeof explodedError !== "string") {
      throw new Error("expected audited explode failure to include details.error");
    }
    expect(explodedError).toContain("[path-redacted]");
    expect(explodedError).not.toContain("/tmp/private-path");

    const auditedErrorFields = Object.entries(explodedDetails ?? {}).filter(([field]) =>
      field.toLowerCase().includes("error")
    );
    expect(auditedErrorFields.length).toBeGreaterThan(0);
    for (const [, value] of auditedErrorFields) {
      expect(String(value)).not.toContain("/tmp/private-path");
    }
  });
});

async function makeHarness(): Promise<ConformanceHarness> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const baseline = new BaselineTracker(storage, masterKey);
  const injectionDetector = new RecordingInjectionDetector();
  let finishToolDiscovery: (() => void) | undefined;
  let failToolDiscovery: ((error: Error) => void) | undefined;
  let discoverySettled = false;
  const toolDiscovery = new Promise<void>((resolve, reject) => {
    finishToolDiscovery = resolve;
    failToolDiscovery = reject;
  });
  const clientManager = new ClientManager({
    onToolListChanged: (serverName, tools, state) => {
      if (
        !discoverySettled &&
        serverName === UPSTREAM_NAME &&
        state === "connected" &&
        tools.length === 4
      ) {
        discoverySettled = true;
        finishToolDiscovery?.();
      }
    },
    onStateChange: (serverName, state, _toolCount, error) => {
      if (!discoverySettled && serverName === UPSTREAM_NAME && state === "error") {
        discoverySettled = true;
        failToolDiscovery?.(
          new Error(`real stdio upstream failed to connect: ${error ?? "unknown error"}`)
        );
      }
    },
  });
  const cleanup: HarnessCleanup = { clientManager };
  harnesses.push(cleanup);

  const upstream: UpstreamServer = {
    name: UPSTREAM_NAME,
    enabled: true,
    default_tier: 3,
    transport: {
      type: "stdio",
      command: process.execPath,
      args: [FIXTURE_PATH],
    },
  };

  await clientManager.configure([upstream]);
  await waitForDiscoveredTools(toolDiscovery, clientManager);

  const { enforcer, policyStore } = createContextGateTools(storage, masterKey, auditLog);
  const policy = await policyStore.create(
    "proxy-upstream-conformance",
    [
      {
        provider: "tool-api",
        allow: ["message"],
        redact: [],
        hash: [],
        summarize: [],
      },
    ],
    "deny"
  );
  enforcer.configureFromProfile({ enabled: true, policy_id: policy.policy_id });
  (enforcer as unknown as { config: { on_deny: "block" | "redact" } }).config.on_deny =
    "block";

  const proxyRouter = new ProxyRouter(
    clientManager,
    injectionDetector,
    auditLog,
    {
      contextGateFilter: (toolName, args) =>
        enforcer.filterArgs(toolName, args, { respectBypass: false }),
    }
  );
  const proxyTools = proxyRouter.getProxiedTools();
  expect(proxyTools).toHaveLength(4);

  const gate = new ApprovalGate(
    DEFAULT_POLICY,
    baseline,
    new CallbackApprovalChannel(async () => {
      throw new Error("Tier 3 proxy conformance calls should not request approval");
    }),
    auditLog,
    injectionDetector
  );
  gate.setProxyTierResolver((toolName) => {
    const parsed = ProxyRouter.parseProxyToolName(toolName);
    if (!parsed) return null;
    return proxyRouter.getTierForTool(parsed.serverName, parsed.toolName);
  });

  const downstreamServer = createServer(proxyTools as ToolDefinition[], {
    gate,
    auditLog,
  });
  const downstreamClient = new Client({
    name: "proxy-upstream-conformance-test",
    version: "1.0.0",
  });
  cleanup.client = downstreamClient;
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await downstreamServer.connect(serverTransport);
  await downstreamClient.connect(clientTransport);

  const harness = {
    client: downstreamClient,
    clientManager,
    auditLog,
    injectionDetector,
  };
  return harness;
}

async function waitForDiscoveredTools(
  toolDiscovery: Promise<void>,
  clientManager: ClientManager
): Promise<void> {
  const tools = clientManager.getAllTools().get(UPSTREAM_NAME) ?? [];
  if (tools.length === 4) return;

  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      toolDiscovery,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(
            new Error(
              `real stdio upstream did not expose all tools: ${JSON.stringify(clientManager.getStatus())}`
            )
          );
        }, 2_000);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function auditEntries(auditLog: AuditLog): Promise<AuditEntry[]> {
  await auditLog.flush();
  return (await auditLog.query({ limit: 200 })).entries;
}

async function forwardedCallCount(harness: ConformanceHarness): Promise<number> {
  const stats = await harness.client.callTool({
    name: "proxy/real_stdio/stats",
    arguments: {},
  });
  return Number(textJson(stats).forwardedCallCount);
}

function textJson(result: CallResult): Record<string, unknown> {
  const first = result.content[0];
  if (!first || first.type !== "text") {
    throw new Error(`expected text result, got ${JSON.stringify(result.content)}`);
  }
  return JSON.parse(first.text) as Record<string, unknown>;
}
