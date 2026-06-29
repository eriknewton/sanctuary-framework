import { describe, it, expect, vi, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { DynamicProxyToolRegistry } from "../../src/proxy/dynamic-proxy.js";
import {
  ClientManager,
  UpstreamUnavailableError,
} from "../../src/proxy/client-manager.js";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import type { ToolDefinition } from "../../src/router.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

const clientInstances: Array<{
  connect: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  listTools: ReturnType<typeof vi.fn>;
  callTool: ReturnType<typeof vi.fn>;
  onclose?: () => void;
  onerror?: (error: Error) => void;
}> = [];

// Vitest 4 rewrote the spy implementation (vitest PR #8363): a mock whose
// implementation is an arrow function is no longer a valid constructor, so the
// `new Client()` / `new StdioClientTransport()` call sites in client-manager.ts
// would throw "is not a constructor". Use regular `function` expressions (here
// and in the per-test mockImplementation overrides below) so the mocks are
// construct-callable.
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: vi.fn(function () {
    const client = {
      connect: vi.fn(async () => {}),
      close: vi.fn(async () => {}),
      listTools: vi.fn(async () => ({ tools: [] })),
      callTool: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
      onclose: undefined as (() => void) | undefined,
      onerror: undefined as ((error: Error) => void) | undefined,
    };
    clientInstances.push(client);
    return client;
  }),
}));

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: vi.fn(function () {
    return {
      close: vi.fn(async () => {}),
    };
  }),
}));

vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: vi.fn(function () {
    return {
      close: vi.fn(async () => {}),
    };
  }),
}));

function makeServer(overrides?: Partial<UpstreamServer>): UpstreamServer {
  return {
    name: "upstream",
    enabled: true,
    default_tier: 3,
    transport: { type: "stdio", command: "node", args: ["server.js"] },
    ...overrides,
  } as UpstreamServer;
}

function makeTool(name = "late_tool") {
  return {
    name,
    description: `${name} description`,
    inputSchema: { type: "object", properties: { value: { type: "string" } } },
  };
}

function makeAuditLog() {
  return {
    append: vi.fn(),
    appendCritical: vi.fn(async () => {}),
    query: vi.fn(async () => []),
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  clientInstances.length = 0;
});

describe("dynamic proxy discovery", () => {
  it("refreshes proxy tools when slow upstream startup completes after the old 2s window", async () => {
    vi.useFakeTimers();
    const onToolListChanged = vi.fn();
    vi.mocked(Client).mockImplementationOnce(function () {
      const client = {
        connect: vi.fn(
          () => new Promise<void>((resolve) => setTimeout(resolve, 2101))
        ),
        close: vi.fn(async () => {}),
        listTools: vi.fn(async () => ({ tools: [makeTool("slow_tool")] })),
        callTool: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
        onclose: undefined as (() => void) | undefined,
        onerror: undefined as ((error: Error) => void) | undefined,
      };
      clientInstances.push(client);
      return client as unknown as Client;
    });

    const cm = new ClientManager({ onToolListChanged });
    await cm.configure([makeServer()]);

    expect(cm.getAllTools().size).toBe(0);
    await vi.advanceTimersByTimeAsync(2101);

    expect(Array.from(cm.getAllTools().values())[0]![0]!.name).toBe("slow_tool");
    expect(onToolListChanged).toHaveBeenCalledWith(
      "upstream",
      [expect.objectContaining({ name: "slow_tool" })],
      "connected"
    );
    await cm.shutdown();
  });

  it("refreshes registered proxy ToolDefinitions without a Sanctuary restart", () => {
    let discovered: ToolDefinition[] = [];
    const tools: ToolDefinition[] = [];
    const notifyListChanged = vi.fn(async () => {});
    const registry = new DynamicProxyToolRegistry({
      tools,
      proxyRouter: {
        getProxiedTools: () => discovered,
      } as unknown as ProxyRouter,
      notifyListChanged,
    });

    expect(registry.refresh()).toEqual({ changed: false, tool_count: 0 });
    discovered = [
      {
        name: "proxy/upstream/late_tool",
        description: "late",
        inputSchema: { type: "object", properties: {} },
        handler: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
      },
    ];

    expect(registry.refresh()).toEqual({ changed: true, tool_count: 1 });
    expect(tools.map((tool) => tool.name)).toEqual(["proxy/upstream/late_tool"]);
    expect(notifyListChanged).toHaveBeenCalledOnce();
  });

  it("removes disconnected upstream tools, then re-discovers them on reconnect", async () => {
    vi.useFakeTimers();
    let discoveredName = "first_tool";
    const onToolListChanged = vi.fn();
    vi.mocked(Client).mockImplementation(function () {
      const client = {
        connect: vi.fn(async () => {}),
        close: vi.fn(async () => {}),
        listTools: vi.fn(async () => ({ tools: [makeTool(discoveredName)] })),
        callTool: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
        onclose: undefined as (() => void) | undefined,
        onerror: undefined as ((error: Error) => void) | undefined,
      };
      clientInstances.push(client);
      return client as unknown as Client;
    });

    const cm = new ClientManager({ onToolListChanged });
    await cm.configure([makeServer()]);
    await vi.advanceTimersByTimeAsync(0);
    expect(Array.from(cm.getAllTools().values())[0]![0]!.name).toBe("first_tool");

    discoveredName = "second_tool";
    clientInstances[0]!.onclose?.();
    expect(cm.getAllTools().size).toBe(0);
    expect(cm.getStatus()[0]!.tool_count).toBe(0);

    await vi.advanceTimersByTimeAsync(1000);
    expect(Array.from(cm.getAllTools().values())[0]![0]!.name).toBe("second_tool");
    expect(onToolListChanged).toHaveBeenLastCalledWith(
      "upstream",
      [expect.objectContaining({ name: "second_tool" })],
      "connected"
    );
    await cm.shutdown();
  });

  it("returns a typed UpstreamUnavailableError for disconnected upstream calls", async () => {
    const cm = new ClientManager();
    await cm.configure([makeServer()]);
    clientInstances[0]!.onclose?.();

    await expect(cm.callTool("upstream", "missing_tool", {})).rejects.toMatchObject({
      name: "UpstreamUnavailableError",
      code: "upstream_unavailable",
      serverName: "upstream",
      toolName: "missing_tool",
    });
    await expect(cm.callTool("upstream", "missing_tool", {})).rejects.toBeInstanceOf(
      UpstreamUnavailableError
    );
    await cm.shutdown();
  });
});

describe("proxied call enforcement preservation", () => {
  it("keeps Tier 1 proxied tools behind operator approval", async () => {
    const policy: PrincipalPolicy = {
      tier1_always_approve: [],
      tier2_confirm_on_anomaly: [],
      tier3_always_allow: [],
      notification_channels: ["stderr"],
    };
    const channel: ApprovalChannel = {
      requestApproval: vi.fn(async () => ({
        request_id: "req-1",
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "test",
      })),
    };
    const baseline = { recordToolCall: vi.fn() };
    const gate = new ApprovalGate(policy, baseline as any, channel, makeAuditLog() as any);
    gate.setProxyTierResolver((toolName) =>
      toolName === "proxy/upstream/tier1_tool" ? 1 : null
    );

    const decision = await gate.evaluate("proxy/upstream/tier1_tool", { value: "raw" });

    expect(decision.allowed).toBe(false);
    expect(decision.approval_required).toBe(true);
    expect(channel.requestApproval).toHaveBeenCalledOnce();
  });

  it("filters args before forwarding and emits appendCritical audit for allowed calls", async () => {
    const clientManager = {
      getAllTools: vi.fn(() => new Map([["upstream", [makeTool("filtered_tool")]]])),
      getServerConfig: vi.fn(() => ({
        name: "upstream",
        enabled: true,
        default_tier: 3,
        transport: { type: "stdio", command: "node" },
      })),
      callTool: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
    };
    const contextGateFilter = vi.fn(async () => ({ value: "[filtered]" }));
    const auditLog = makeAuditLog();
    const router = new ProxyRouter(
      clientManager as any,
      { scan: vi.fn(() => ({ flagged: false, confidence: 0, signals: [], recommendation: "allow" })) } as any,
      auditLog as any,
      { contextGateFilter }
    );

    const handler = router.getProxiedTools()[0]!.handler;
    await handler({ value: "secret" });

    expect(contextGateFilter).toHaveBeenCalledWith(
      "proxy/upstream/filtered_tool",
      { value: "secret" }
    );
    expect(clientManager.callTool).toHaveBeenCalledWith(
      "upstream",
      "filtered_tool",
      { value: "[filtered]" }
    );
    expect(auditLog.appendCritical).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "proxy_call:proxy/upstream/filtered_tool",
        result: "success",
        details: expect.objectContaining({ event_type: "proxy.call" }),
      })
    );
  });
});
