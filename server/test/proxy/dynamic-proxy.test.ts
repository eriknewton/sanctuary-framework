import { describe, expect, it, vi } from "vitest";

import { DynamicProxyToolRegistry } from "../../src/proxy/dynamic-proxy.js";
import type { ProxyRouter } from "../../src/proxy/proxy-router.js";
import type { ToolDefinition } from "../../src/router.js";

function makeTool(
  name: string,
  inputSchema: Record<string, unknown> = { type: "object", properties: {} },
): ToolDefinition {
  return {
    name,
    description: `${name} description`,
    inputSchema,
    tool_class: "read",
    handler: vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] })),
  };
}

function makeRegistry(
  tools: ToolDefinition[],
  discovered: () => ToolDefinition[],
  notifyListChanged = vi.fn(async () => {}),
): DynamicProxyToolRegistry {
  return new DynamicProxyToolRegistry({
    tools,
    proxyRouter: { getProxiedTools: discovered } as unknown as ProxyRouter,
    notifyListChanged,
  });
}

describe("DynamicProxyToolRegistry", () => {
  it("removes stale proxy tools while preserving non-proxy registrations", () => {
    let discovered = [makeTool("proxy/upstream/new")];
    const tools = [
      makeTool("sanctuary/status"),
      makeTool("proxy/upstream/stale"),
      makeTool("proxy/other/stale"),
    ];
    const registry = makeRegistry(tools, () => discovered);

    expect(registry.refresh()).toEqual({ changed: true, tool_count: 1 });

    expect(tools.map((tool) => tool.name)).toEqual([
      "sanctuary/status",
      "proxy/upstream/new",
    ]);

    discovered = [];
    expect(registry.refresh()).toEqual({ changed: true, tool_count: 0 });
    expect(tools.map((tool) => tool.name)).toEqual(["sanctuary/status"]);
  });

  it("uses a schema fingerprint that is stable across proxied tool order", () => {
    const alpha = makeTool("proxy/a/alpha", {
      type: "object",
      properties: { value: { type: "string" } },
    });
    const beta = makeTool("proxy/b/beta", {
      type: "object",
      properties: { count: { type: "number" } },
    });
    let discovered = [alpha, beta];
    const notifyListChanged = vi.fn(async () => {});
    const tools: ToolDefinition[] = [];
    const registry = makeRegistry(tools, () => discovered, notifyListChanged);

    expect(registry.refresh()).toEqual({ changed: true, tool_count: 2 });
    discovered = [beta, alpha];

    expect(registry.refresh()).toEqual({ changed: false, tool_count: 2 });
    expect(tools.map((tool) => tool.name)).toEqual([
      "proxy/a/alpha",
      "proxy/b/beta",
    ]);
    expect(notifyListChanged).toHaveBeenCalledOnce();
  });

  it("treats input schema changes as registry changes and swallows notify failures", async () => {
    let discovered = [makeTool("proxy/upstream/search")];
    const tools: ToolDefinition[] = [];
    const notifyListChanged = vi.fn(async () => {
      throw new Error("listener closed");
    });
    const registry = makeRegistry(tools, () => discovered, notifyListChanged);

    expect(registry.refresh()).toEqual({ changed: true, tool_count: 1 });
    discovered = [
      makeTool("proxy/upstream/search", {
        type: "object",
        properties: { q: { type: "string" } },
        required: ["q"],
      }),
    ];

    expect(registry.refresh()).toEqual({ changed: true, tool_count: 1 });
    await Promise.resolve();

    expect(tools).toHaveLength(1);
    expect(tools[0]!.inputSchema).toEqual(discovered[0]!.inputSchema);
    expect(notifyListChanged).toHaveBeenCalledTimes(2);
  });
});
