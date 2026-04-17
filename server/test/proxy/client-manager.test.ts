/**
 * Proxy ClientManager tests
 *
 * Covers: server name validation, max upstream limit, getStatus/getServerConfig,
 * callTool rejection for unconfigured servers, shutdown safety.
 * Not covered: real MCP SDK transport, network I/O, reconnection timing.
 */

import { describe, it, expect, vi } from "vitest";
import { ClientManager } from "../../src/proxy/client-manager.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

// Mock the MCP SDK transports to prevent real process spawning
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: vi.fn().mockImplementation(() => ({
    connect: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    listTools: vi.fn(async () => ({ tools: [] })),
    callTool: vi.fn(async () => ({ content: [] })),
  })),
}));

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: vi.fn().mockImplementation(() => ({
    close: vi.fn(async () => {}),
  })),
}));

vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: vi.fn().mockImplementation(() => ({
    close: vi.fn(async () => {}),
  })),
}));

function makeServer(name: string, overrides?: Partial<UpstreamServer>): UpstreamServer {
  return {
    name,
    enabled: true,
    default_tier: 3,
    transport: { type: "stdio", command: "node", args: ["server.js"] },
    ...overrides,
  } as UpstreamServer;
}

describe("ClientManager", () => {
  describe("server name validation", () => {
    it("accepts valid server names", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("valid-name_123")]);
      const status = cm.getStatus();
      expect(status.length).toBe(1);
      expect(status[0]!.name).toBe("valid-name_123");
    });

    it("rejects server names with special characters", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("bad name!@#")]);
      const status = cm.getStatus();
      expect(status.length).toBe(0);
    });

    it("rejects server names with spaces", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("has space")]);
      expect(cm.getStatus().length).toBe(0);
    });
  });

  describe("max upstream servers", () => {
    it("rejects more than 20 upstream servers", async () => {
      const cm = new ClientManager();
      const servers = Array.from({ length: 21 }, (_, i) => makeServer(`s${i}`));
      await expect(cm.configure(servers)).rejects.toThrow("Maximum 20 upstream servers");
    });

    it("accepts exactly 20 servers", async () => {
      const cm = new ClientManager();
      const servers = Array.from({ length: 20 }, (_, i) => makeServer(`s${i}`));
      await cm.configure(servers);
      // Should not throw
    });
  });

  describe("getStatus", () => {
    it("returns empty status when no servers configured", () => {
      const cm = new ClientManager();
      expect(cm.getStatus()).toEqual([]);
    });

    it("returns server status after configure", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("test-server")]);
      const status = cm.getStatus();
      expect(status).toHaveLength(1);
      expect(status[0]!.name).toBe("test-server");
    });
  });

  describe("getServerConfig", () => {
    it("returns undefined for unconfigured server", () => {
      const cm = new ClientManager();
      expect(cm.getServerConfig("nope")).toBeUndefined();
    });
  });

  describe("state change callback", () => {
    it("fires callback on state changes", async () => {
      const callback = vi.fn();
      const cm = new ClientManager({ onStateChange: callback });
      await cm.configure([makeServer("cb-test")]);

      // Wait for async connection attempt
      await new Promise(r => setTimeout(r, 100));
      expect(callback).toHaveBeenCalled();
      await cm.shutdown();
    });
  });

  describe("shutdown", () => {
    it("completes without error on empty manager", async () => {
      const cm = new ClientManager();
      await cm.shutdown();
    });

    it("cleans up after configure", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("s1")]);
      await cm.shutdown();
      const status = cm.getStatus();
      expect(status.every(s => s.state === "disconnected")).toBe(true);
    });
  });

  describe("getAllTools", () => {
    it("returns empty map with no connections", () => {
      const cm = new ClientManager();
      expect(cm.getAllTools().size).toBe(0);
    });
  });

  describe("callTool", () => {
    it("rejects call to unconfigured server", async () => {
      const cm = new ClientManager();
      await expect(cm.callTool("nope", "tool", {})).rejects.toThrow();
    });
  });
});
