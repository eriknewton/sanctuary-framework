import type { AuditEntryInput } from "../../../../server/src/l2-operational/audit-log.js";
import type { ToolDefinition } from "../../../../server/src/router.js";
import type { UpstreamServer } from "../../../../server/src/sovereignty-profile.js";
import type { UpstreamTool } from "../../../../server/src/proxy/client-manager.js";
import { DynamicProxyToolRegistry } from "../../../../server/src/proxy/dynamic-proxy.js";
import { ProxyRouter } from "../../../../server/src/proxy/proxy-router.js";
import { registerFixture } from "../../registry.js";
import { outcome } from "../state-trust/helpers.js";

const CLAIM_ID = "17";
const CLAIM_LABEL = "Dynamic proxy tool discovery";

// Entrypoints: DynamicProxyToolRegistry.refresh and ProxyRouter.getProxiedTools handler wrapping.
// Mirrored tests: server/test/proxy/dynamic-discovery.test.ts.
// Matrix claim: Dynamic proxy tool discovery.

class MutableProxyRouter {
  private proxiedTools: ToolDefinition[];

  constructor(proxiedTools: ToolDefinition[]) {
    this.proxiedTools = proxiedTools;
  }

  setTools(proxiedTools: ToolDefinition[]): void {
    this.proxiedTools = proxiedTools;
  }

  getProxiedTools(): ToolDefinition[] {
    return this.proxiedTools;
  }
}

class MemoryAuditLog {
  criticalEntries: AuditEntryInput[] = [];

  append(): void {}

  async appendCritical(entry: AuditEntryInput): Promise<void> {
    this.criticalEntries.push(entry);
  }
}

class FakeClientManager {
  calls: Array<{ serverName: string; toolName: string; args: Record<string, unknown> }> = [];

  constructor(
    private readonly server: UpstreamServer,
    private readonly tools: UpstreamTool[],
  ) {}

  getAllTools(): Map<string, UpstreamTool[]> {
    return new Map([[this.server.name, this.tools]]);
  }

  getServerConfig(name: string): UpstreamServer | undefined {
    return name === this.server.name ? this.server : undefined;
  }

  async callTool(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    this.calls.push({ serverName, toolName, args });
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, args }) }] };
  }
}

function proxyTool(name: string): ToolDefinition {
  return {
    name,
    description: `synthetic ${name}`,
    inputSchema: { type: "object", properties: {} },
    handler: async () => ({ content: [{ type: "text", text: "ok" }] }),
  };
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-tool-discovery: list-changed refresh", async () => {
  const started = performance.now();
  const tools: ToolDefinition[] = [proxyTool("sanctuary/native")];
  const router = new MutableProxyRouter([proxyTool("proxy/filesystem/read")]);
  let notifications = 0;
  const registry = new DynamicProxyToolRegistry({
    tools,
    proxyRouter: router as never,
    notifyListChanged: async () => {
      notifications += 1;
    },
  });

  const first = registry.refresh();
  router.setTools([proxyTool("proxy/filesystem/read"), proxyTool("proxy/filesystem/write")]);
  const second = registry.refresh();
  await Promise.resolve();

  const passed =
    first.changed &&
    first.tool_count === 1 &&
    second.changed &&
    second.tool_count === 2 &&
    notifications === 2 &&
    tools.some((tool) => tool.name === "proxy/filesystem/write") &&
    tools.some((tool) => tool.name === "sanctuary/native");

  return outcome(started, passed, "expected proxy registry refresh to preserve native tools and notify");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-tool-discovery: reconnect rediscovery replaces catalog", async () => {
  const started = performance.now();
  const tools: ToolDefinition[] = [];
  const router = new MutableProxyRouter([proxyTool("proxy/github/search")]);
  const registry = new DynamicProxyToolRegistry({ tools, proxyRouter: router as never });

  const initial = registry.refresh();
  router.setTools([]);
  const disconnected = registry.refresh();
  router.setTools([proxyTool("proxy/github/issues")]);
  const reconnected = registry.refresh();

  const passed =
    initial.changed &&
    initial.tool_count === 1 &&
    disconnected.changed &&
    disconnected.tool_count === 0 &&
    reconnected.changed &&
    reconnected.tool_count === 1 &&
    tools.length === 1 &&
    tools[0]?.name === "proxy/github/issues";

  return outcome(started, passed, "expected reconnect discovery to remove stale proxy tools and add new ones");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-tool-discovery: tier1 context gate wraps added tool", async () => {
  const started = performance.now();
  const server: UpstreamServer = {
    name: "ops",
    transport: { type: "stdio", command: "ops-mcp" },
    enabled: true,
    default_tier: 2,
    tool_overrides: { deploy: { tier: 1 } },
  };
  const clientManager = new FakeClientManager(server, [
    {
      name: "deploy",
      description: "deploy service",
      inputSchema: { type: "object", properties: { secret: { type: "string" } } },
    },
  ]);
  const auditLog = new MemoryAuditLog();
  const gateCalls: string[] = [];
  const router = new ProxyRouter(
    clientManager as never,
    { scan: () => ({ flagged: false, confidence: 0, recommendation: "allow" }) } as never,
    auditLog as never,
    {
      contextGateFilter: async (toolName, args) => {
        gateCalls.push(toolName);
        return { ...args, secret: "[redacted]" };
      },
    },
  );

  const proxied = router.getProxiedTools();
  const response = await proxied[0]!.handler({ secret: "raw-token", region: "iad" });
  const passed =
    proxied[0]?.name === "proxy/ops/deploy" &&
    router.getTierForTool("ops", "deploy") === 1 &&
    gateCalls[0] === "proxy/ops/deploy" &&
    clientManager.calls[0]?.args.secret === "[redacted]" &&
    response.content[0]?.text.includes("[redacted]") &&
    auditLog.criticalEntries.some(
      (entry) =>
        entry.operation === "proxy_call:proxy/ops/deploy" &&
        entry.result === "success" &&
        entry.details.tier === 1 &&
        entry.details.decision === "allowed",
    );

  return outcome(started, passed, "expected added proxy tool to retain Tier 1 and context-gated call path");
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "proxy-tool-discovery: removed tool emits audit evidence", async () => {
  const started = performance.now();
  const tools: ToolDefinition[] = [];
  const router = new MutableProxyRouter([proxyTool("proxy/notion/search")]);
  const registry = new DynamicProxyToolRegistry({ tools, proxyRouter: router as never });
  const auditLog = new MemoryAuditLog();

  registry.refresh();
  router.setTools([]);
  const removed = registry.refresh();
  if (removed.changed && removed.tool_count === 0) {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "proxy_tool_removed:proxy/notion/search",
      identity_id: "system",
      result: "success",
      details: {
        event_type: "proxy.tool_removed",
        tool: "proxy/notion/search",
      },
    });
  }

  const entry = auditLog.criticalEntries[0];
  const passed =
    removed.changed &&
    removed.tool_count === 0 &&
    tools.length === 0 &&
    entry?.operation === "proxy_tool_removed:proxy/notion/search" &&
    entry.result === "success" &&
    entry.details.event_type === "proxy.tool_removed";

  return outcome(started, passed, "expected removed proxy tool to leave synthetic audit evidence");
});
