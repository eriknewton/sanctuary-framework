/**
 * Proxy Router Tests
 *
 * Verifies:
 * - Tool namespacing (proxy/{server}/{tool})
 * - Tier resolution (tool_overrides > default_tier > fallback)
 * - parseProxyToolName parsing and null returns
 * - Enforcement chain: injection block, injection escalation, context gate,
 *   governor block, governor duplicate cache, successful forward, error pass-through, timeout
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";

// ── Mocks ────────────────────────────────────────────────────────────

function createMockClientManager() {
  return {
    getAllTools: vi.fn().mockReturnValue(
      new Map([
        [
          "test-server",
          [
            {
              name: "list_files",
              description: "List files",
              inputSchema: { type: "object", properties: {} },
            },
            {
              name: "read_file",
              description: "Read a file",
              inputSchema: {
                type: "object",
                properties: { path: { type: "string" } },
              },
            },
          ],
        ],
      ])
    ),
    getServerConfig: vi.fn().mockReturnValue({
      name: "test-server",
      transport: { type: "stdio", command: "node" },
      enabled: true,
      default_tier: 2,
      tool_overrides: { read_file: { tier: 3 } },
    }),
    callTool: vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "result" }],
    }),
  };
}

function createMockInjectionDetector(overrides?: Partial<ReturnType<typeof defaultScanResult>>) {
  const scanResult = { ...defaultScanResult(), ...overrides };
  return {
    scan: vi.fn().mockReturnValue(scanResult),
    scanOutbound: vi.fn().mockReturnValue(scanResult),
  };
}

function defaultScanResult() {
  return {
    flagged: false,
    confidence: 0,
    signals: [] as string[],
    recommendation: "allow" as const,
  };
}

function createMockAuditLog() {
  return {
    append: vi.fn(),
    appendCritical: vi.fn().mockResolvedValue(undefined),
    query: vi.fn().mockResolvedValue([]),
  };
}

function createMockGovernor(overrides?: {
  checkResult?: Record<string, unknown>;
}) {
  return {
    check: vi.fn().mockReturnValue({ allowed: true, ...overrides?.checkResult }),
    recordResult: vi.fn(),
    getStatus: vi.fn().mockReturnValue({
      volume_current: 0,
      volume_limit: 200,
      lifetime_current: 0,
      lifetime_limit: 1000,
      rate_by_tool: {},
      duplicate_cache_size: 0,
      hard_stopped: false,
    }),
    reset: vi.fn(),
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("ProxyRouter", () => {
  let mockClientManager: ReturnType<typeof createMockClientManager>;
  let mockInjectionDetector: ReturnType<typeof createMockInjectionDetector>;
  let mockAuditLog: ReturnType<typeof createMockAuditLog>;
  let router: ProxyRouter;

  beforeEach(() => {
    mockClientManager = createMockClientManager();
    mockInjectionDetector = createMockInjectionDetector();
    mockAuditLog = createMockAuditLog();
    router = new ProxyRouter(
      mockClientManager as any,
      mockInjectionDetector as any,
      mockAuditLog as any
    );
  });

  // ── getProxiedTools ───────────────────────────────────────────────

  describe("getProxiedTools", () => {
    it("returns correctly namespaced tools", () => {
      const tools = router.getProxiedTools();
      expect(tools).toHaveLength(2);
      expect(tools[0]!.name).toBe("proxy/test-server/list_files");
      expect(tools[1]!.name).toBe("proxy/test-server/read_file");
    });

    it("includes server name in description", () => {
      const tools = router.getProxiedTools();
      expect(tools[0]!.description).toContain("[via test-server]");
    });

    it("preserves upstream inputSchema", () => {
      const tools = router.getProxiedTools();
      const readFile = tools.find((t) => t.name === "proxy/test-server/read_file");
      expect(readFile!.inputSchema).toEqual({
        type: "object",
        properties: { path: { type: "string" } },
      });
    });

    it("each tool has a handler function", () => {
      const tools = router.getProxiedTools();
      for (const tool of tools) {
        expect(typeof tool.handler).toBe("function");
      }
    });
  });

  // ── getTierForTool ────────────────────────────────────────────────

  describe("getTierForTool", () => {
    it("returns tool_override tier when present", () => {
      const tier = router.getTierForTool("test-server", "read_file");
      expect(tier).toBe(3);
    });

    it("returns default_tier when no tool override exists", () => {
      const tier = router.getTierForTool("test-server", "list_files");
      expect(tier).toBe(2);
    });

    it("returns tier 2 for unknown server", () => {
      mockClientManager.getServerConfig.mockReturnValue(null);
      const tier = router.getTierForTool("unknown-server", "any_tool");
      expect(tier).toBe(2);
    });
  });

  // ── parseProxyToolName ────────────────────────────────────────────

  describe("parseProxyToolName", () => {
    it("parses a valid proxy tool name", () => {
      const result = ProxyRouter.parseProxyToolName("proxy/my-server/my-tool");
      expect(result).toEqual({ serverName: "my-server", toolName: "my-tool" });
    });

    it("returns null for non-proxy names", () => {
      expect(ProxyRouter.parseProxyToolName("state_read")).toBeNull();
    });

    it("returns null for prefix-only name", () => {
      expect(ProxyRouter.parseProxyToolName("proxy/serveronly")).toBeNull();
    });

    it("handles tool names with slashes", () => {
      const result = ProxyRouter.parseProxyToolName("proxy/server/nested/tool/name");
      expect(result).toEqual({ serverName: "server", toolName: "nested/tool/name" });
    });
  });

  // ── Handler enforcement chain ─────────────────────────────────────

  describe("handler enforcement chain", () => {
    it("blocks when injection detector flags with block recommendation", async () => {
      mockInjectionDetector = createMockInjectionDetector();
      mockInjectionDetector.scan.mockReturnValue({
        flagged: true,
        confidence: 0.95,
        signals: ["prompt_injection"],
        recommendation: "block",
      });

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const result = await handler({});

      expect(result.content[0]!.text).toContain("Operation not permitted");
      expect(mockClientManager.callTool).not.toHaveBeenCalled();
      expect(mockAuditLog.appendCritical).toHaveBeenCalledWith(
        expect.objectContaining({
          layer: "l2",
          operation: expect.stringContaining("proxy_injection_blocked"),
          identity_id: "system",
          result: "failure",
          details: expect.objectContaining({ confidence: 0.95 }),
        })
      );
    });

    it("fails closed before forwarding when proxy block audit persistence fails", async () => {
      mockInjectionDetector = createMockInjectionDetector();
      mockInjectionDetector.scan.mockReturnValue({
        flagged: true,
        confidence: 0.95,
        signals: ["prompt_injection"],
        recommendation: "block",
      });
      mockAuditLog.appendCritical.mockRejectedValue(new Error("audit down"));

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any
      );

      const tools = router.getProxiedTools();
      const result = await tools[0]!.handler({});
      const parsed = JSON.parse(result.content[0]!.text);

      expect(parsed.proxy).toBe(true);
      expect(mockClientManager.callTool).not.toHaveBeenCalled();
      expect(mockAuditLog.appendCritical).toHaveBeenCalled();
    });

    it("logs escalation but continues when injection detector recommends escalate", async () => {
      mockInjectionDetector = createMockInjectionDetector();
      mockInjectionDetector.scan.mockReturnValue({
        flagged: true,
        confidence: 0.6,
        signals: ["suspicious"],
        recommendation: "escalate",
      });

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const result = await handler({});

      // Should log escalation
      expect(mockAuditLog.append).toHaveBeenCalledWith(
        "l2",
        expect.stringContaining("proxy_injection_escalated"),
        "system",
        expect.objectContaining({ confidence: 0.6 })
      );

      // Should still forward the call
      expect(mockClientManager.callTool).toHaveBeenCalled();
      expect(result.content[0]!.text).toBe("result");
    });

    it("calls context gate filter when provided", async () => {
      const contextGateFilter = vi.fn().mockResolvedValue({ filtered: true });

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any,
        { contextGateFilter }
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      await handler({ original: "data" });

      expect(contextGateFilter).toHaveBeenCalledWith(
        "proxy/test-server/list_files",
        { original: "data" }
      );
      // The filtered args should be forwarded
      expect(mockClientManager.callTool).toHaveBeenCalledWith(
        "test-server",
        "list_files",
        { filtered: true }
      );
    });

    it("proceeds with original args when context gate throws", async () => {
      const contextGateFilter = vi.fn().mockRejectedValue(new Error("gate error"));

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any,
        { contextGateFilter }
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      await handler({ original: "data" });

      // Should fall back to original args
      expect(mockClientManager.callTool).toHaveBeenCalledWith(
        "test-server",
        "list_files",
        { original: "data" }
      );
    });

    it("blocks when governor denies (rate exceeded)", async () => {
      const mockGovernor = createMockGovernor();
      mockGovernor.check.mockReturnValue({
        allowed: false,
        reason: "rate_exceeded",
        escalate: true,
      });

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any,
        { governor: mockGovernor as any }
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const result = await handler({});

      expect(result.content[0]!.text).toContain("Operation not permitted");
      expect(result.content[0]!.text).toContain("rate_exceeded");
      expect(mockClientManager.callTool).not.toHaveBeenCalled();
      expect(mockAuditLog.appendCritical).toHaveBeenCalledWith(
        expect.objectContaining({
          layer: "l2",
          operation: expect.stringContaining("proxy_governor_blocked"),
          identity_id: "system",
          result: "failure",
          details: expect.objectContaining({ reason: "rate_exceeded" }),
        })
      );
    });

    it("returns cached result from governor without forwarding", async () => {
      const mockGovernor = createMockGovernor();
      mockGovernor.check.mockReturnValue({
        allowed: true,
        reason: "duplicate_cached",
        cached_result: { data: "from-cache" },
      });

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any,
        { governor: mockGovernor as any }
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const result = await handler({});

      expect(result.content[0]!.text).toContain("from-cache");
      expect(mockClientManager.callTool).not.toHaveBeenCalled();
      expect(mockAuditLog.append).toHaveBeenCalledWith(
        "l2",
        expect.stringContaining("proxy_governor_cached"),
        "system",
        expect.objectContaining({ cached: true })
      );
    });

    it("forwards to upstream and logs success on allowed call", async () => {
      const tools = router.getProxiedTools();
      const readFileHandler = tools.find(
        (t) => t.name === "proxy/test-server/read_file"
      )!.handler;

      const result = await readFileHandler({ path: "/test.txt" });

      expect(mockClientManager.callTool).toHaveBeenCalledWith(
        "test-server",
        "read_file",
        { path: "/test.txt" }
      );
      expect(result.content[0]!.text).toBe("result");
      expect(mockAuditLog.append).toHaveBeenCalledWith(
        "l2",
        "proxy_call:proxy/test-server/read_file",
        "system",
        expect.objectContaining({
          decision: "allowed",
          server: "test-server",
          tool: "read_file",
        })
      );
    });

    it("records result with governor after successful forward", async () => {
      const mockGovernor = createMockGovernor();

      router = new ProxyRouter(
        mockClientManager as any,
        mockInjectionDetector as any,
        mockAuditLog as any,
        { governor: mockGovernor as any }
      );

      const tools = router.getProxiedTools();
      await tools[0]!.handler({});

      expect(mockGovernor.recordResult).toHaveBeenCalledWith(
        "test-server",
        "list_files",
        {},
        expect.objectContaining({
          content: [{ type: "text", text: "result" }],
        })
      );
    });

    it("passes upstream errors through to the agent", async () => {
      mockClientManager.callTool.mockRejectedValue(
        new Error("Connection refused")
      );

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const result = await handler({});

      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.error).toBe("Connection refused");
      expect(parsed.proxy).toBe(true);
      expect(parsed.server).toBe("test-server");

      expect(mockAuditLog.append).toHaveBeenCalledWith(
        "l2",
        expect.stringContaining("proxy_call:"),
        "system",
        expect.objectContaining({ decision: "error", error: "Connection refused" }),
        "failure"
      );
    });

    it("returns timeout error when upstream call exceeds timeout", async () => {
      // Make callTool hang indefinitely
      mockClientManager.callTool.mockImplementation(
        () => new Promise(() => {}) // never resolves
      );

      vi.useFakeTimers();

      const tools = router.getProxiedTools();
      const handler = tools[0]!.handler;
      const resultPromise = handler({});

      // Advance time past the 30s timeout
      vi.advanceTimersByTime(30001);

      const result = await resultPromise;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.error).toContain("timed out");
      expect(parsed.proxy).toBe(true);

      vi.useRealTimers();
    });
  });

  // ── Multiple servers ──────────────────────────────────────────────

  describe("multiple servers", () => {
    it("namespaces tools from multiple servers", () => {
      mockClientManager.getAllTools.mockReturnValue(
        new Map([
          [
            "server-a",
            [{ name: "tool1", description: "Tool 1", inputSchema: { type: "object" } }],
          ],
          [
            "server-b",
            [{ name: "tool2", description: "Tool 2", inputSchema: { type: "object" } }],
          ],
        ])
      );

      const tools = router.getProxiedTools();
      expect(tools).toHaveLength(2);
      expect(tools[0]!.name).toBe("proxy/server-a/tool1");
      expect(tools[1]!.name).toBe("proxy/server-b/tool2");
    });
  });
});
