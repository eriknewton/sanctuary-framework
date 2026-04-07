/**
 * Proxy Call Notification Tests
 *
 * Verifies the onProxyCall callback integration in the ProxyRouter,
 * which powers the Fortress View live feed.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
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
              name: "read_file",
              description: "Read a file",
              inputSchema: { type: "object", properties: {} },
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
    }),
    callTool: vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "result" }],
    }),
  };
}

function createMockInjectionDetector(flagged = false) {
  return {
    scan: vi.fn().mockReturnValue({
      flagged,
      confidence: flagged ? 0.95 : 0,
      signals: flagged ? ["prompt_injection"] : [],
      recommendation: flagged ? "block" : "allow",
    }),
    scanOutbound: vi.fn().mockReturnValue({
      flagged: false,
      confidence: 0,
      signals: [],
      recommendation: "allow",
    }),
  };
}

function createMockAuditLog() {
  return {
    append: vi.fn(),
    query: vi.fn().mockResolvedValue([]),
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("Proxy Call Notifications", () => {
  let mockClientManager: ReturnType<typeof createMockClientManager>;
  let mockAuditLog: ReturnType<typeof createMockAuditLog>;

  beforeEach(() => {
    mockClientManager = createMockClientManager();
    mockAuditLog = createMockAuditLog();
  });

  it("calls onProxyCall with 'allowed' on successful forward", async () => {
    const onProxyCall = vi.fn();
    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector() as any,
      mockAuditLog as any,
      { onProxyCall }
    );

    const tools = router.getProxiedTools();
    await tools[0]!.handler({});

    expect(onProxyCall).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: "proxy/test-server/read_file",
        server: "test-server",
        decision: "allowed",
        timestamp: expect.any(String),
      })
    );
  });

  it("calls onProxyCall with 'blocked' on injection detection", async () => {
    const onProxyCall = vi.fn();
    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector(true) as any,
      mockAuditLog as any,
      { onProxyCall }
    );

    const tools = router.getProxiedTools();
    await tools[0]!.handler({});

    expect(onProxyCall).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: "proxy/test-server/read_file",
        server: "test-server",
        decision: "blocked",
        reason: "injection_detected",
      })
    );
  });

  it("calls onProxyCall with 'error' on upstream failure", async () => {
    const onProxyCall = vi.fn();
    mockClientManager.callTool.mockRejectedValue(new Error("Connection refused"));

    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector() as any,
      mockAuditLog as any,
      { onProxyCall }
    );

    const tools = router.getProxiedTools();
    await tools[0]!.handler({});

    expect(onProxyCall).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: "proxy/test-server/read_file",
        server: "test-server",
        decision: "error",
        reason: "Connection refused",
      })
    );
  });

  it("calls onProxyCall with 'blocked' on governor denial", async () => {
    const onProxyCall = vi.fn();
    const mockGovernor = {
      check: vi.fn().mockReturnValue({ allowed: false, reason: "rate_exceeded" }),
      recordResult: vi.fn(),
    };

    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector() as any,
      mockAuditLog as any,
      { governor: mockGovernor as any, onProxyCall }
    );

    const tools = router.getProxiedTools();
    await tools[0]!.handler({});

    expect(onProxyCall).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "blocked",
        reason: "rate_exceeded",
      })
    );
  });

  it("does not throw when onProxyCall callback throws", async () => {
    const onProxyCall = vi.fn().mockImplementation(() => {
      throw new Error("callback error");
    });

    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector() as any,
      mockAuditLog as any,
      { onProxyCall }
    );

    const tools = router.getProxiedTools();
    // Should not throw
    const result = await tools[0]!.handler({});
    expect(result.content[0]!.text).toBe("result");
  });

  it("works without onProxyCall callback (no crash)", async () => {
    const router = new ProxyRouter(
      mockClientManager as any,
      createMockInjectionDetector() as any,
      mockAuditLog as any,
      // No onProxyCall
    );

    const tools = router.getProxiedTools();
    const result = await tools[0]!.handler({});
    expect(result.content[0]!.text).toBe("result");
  });
});
