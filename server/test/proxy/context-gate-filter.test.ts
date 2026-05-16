import { describe, it, expect, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import { createContextGateTools, initializeContextGateEnforcerFromProfile } from "../../src/l2-operational/context-gate-tools.js";
import { createDefaultProfile } from "../../src/sovereignty-profile.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";

function createMockClientManager() {
  return {
    getAllTools: vi.fn().mockReturnValue(
      new Map([
        [
          "test-server",
          [
            {
              name: "send",
              description: "Send payload",
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
      content: [{ type: "text", text: "ok" }],
    }),
  };
}

function createInjectionDetector() {
  return {
    scan: vi.fn().mockReturnValue({
      flagged: false,
      confidence: 0,
      signals: [],
      recommendation: "allow",
    }),
  };
}

describe("proxy context gate filter", () => {
  it("filters sensitive proxy args when profile-backed context gating is enabled", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
    initializeContextGateEnforcerFromProfile(enforcer, profile);
    const clientManager = createMockClientManager();

    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        contextGateFilter: (toolName, args) =>
          profile.features.context_gating.enabled
            ? enforcer.filterArgs(toolName, args, { respectBypass: false })
            : Promise.resolve(args),
      }
    );

    await router.getProxiedTools()[0]!.handler({
      api_key: "secret",
      payload: "hello",
    });

    expect(clientManager.callTool).toHaveBeenCalledWith(
      "test-server",
      "send",
      {
        api_key: "[REDACTED]",
        payload: "hello",
      }
    );
  });

  it("passes proxy args through when profile-backed context gating is disabled", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const profile = createDefaultProfile();
    const { enforcer } = createContextGateTools(storage, masterKey, auditLog);
    initializeContextGateEnforcerFromProfile(enforcer, profile);
    const clientManager = createMockClientManager();

    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        contextGateFilter: (toolName, args) =>
          profile.features.context_gating.enabled
            ? enforcer.filterArgs(toolName, args, { respectBypass: false })
            : Promise.resolve(args),
      }
    );

    await router.getProxiedTools()[0]!.handler({
      api_key: "secret",
      payload: "hello",
    });

    expect(clientManager.callTool).toHaveBeenCalledWith(
      "test-server",
      "send",
      {
        api_key: "secret",
        payload: "hello",
      }
    );
  });
});
