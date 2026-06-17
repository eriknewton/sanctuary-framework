import { describe, it, expect, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import { createContextGateTools, initializeContextGateEnforcerFromProfile } from "../../src/operational/context-gate-tools.js";
import { createDefaultProfile } from "../../src/sovereignty-profile.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
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

  it("S1 (HIGH): FAILS CLOSED when the context gate filter throws — never forwards unredacted args, audits the gate error, returns generic denial", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const clientManager = createMockClientManager();

    const gateError = new Error("policy-store read failure: malformed policy");
    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        // A gate filter that always throws (simulates policy-store read
        // failure / malformed policy / runtime exception).
        contextGateFilter: () => Promise.reject(gateError),
      }
    );

    const result = await router.getProxiedTools()[0]!.handler({
      api_key: "secret",
      payload: "hello",
    });

    // (1) The upstream MUST NOT be called at all — the original UNREDACTED
    // args ("secret") must never leave the fortress on a gate error.
    expect(clientManager.callTool).not.toHaveBeenCalled();

    // (2) The caller gets a GENERIC denial, not a silent success, and the raw
    // gate error is NOT leaked into the agent response (invariant #7 style).
    const parsed = JSON.parse((result as any).content[0].text);
    expect(parsed.error).toBe("Operation not permitted");
    expect(JSON.stringify(parsed)).not.toContain("policy-store read failure");
    expect(JSON.stringify(parsed)).not.toContain("malformed policy");
    expect(JSON.stringify(parsed)).not.toContain("secret");

    // (3) The audit trail records the gate-error DENIAL (not a success), and
    // the raw error IS preserved operator-side in the audit log.
    const audit = await auditLog.query({ limit: 50 });
    const gateEntry = audit.entries.find((e) =>
      e.operation.startsWith("proxy_context_gate_error:")
    );
    expect(gateEntry).toBeDefined();
    expect(gateEntry!.result).toBe("failure");
    expect((gateEntry!.details as any).decision).toBe("denied");
    expect((gateEntry!.details as any).reason).toBe("context_gate_filter_error");
    expect((gateEntry!.details as any).error).toContain("policy-store read failure");
    // No "success"/"allowed" proxy_call entry was written for this request.
    const successEntry = audit.entries.find(
      (e) => e.operation.startsWith("proxy_call:") && e.result === "success"
    );
    expect(successEntry).toBeUndefined();
  });

  it("S2 (LOW/MED): a policyResolver rejection (vault outage) denies with reason class fail_closed_filter_error, NOT fail_closed_no_policy", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const clientManager = createMockClientManager();

    // Engine must NOT be consulted on a resolver rejection — the router denies
    // directly so the distinct vault-outage reason is preserved (passing a null
    // policy to the engine would mislabel it as "no policy bound").
    const filterOutbound = vi.fn(() => {
      throw new Error("engine.filterOutbound must not be called on resolver rejection");
    });

    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        privacyEnforcement: {
          engine: { filterOutbound, rehydrateResponse: vi.fn() } as any,
          policyResolver: () =>
            Promise.reject(new Error("vault unreachable: decrypt failure")),
        },
      }
    );

    const result = await router.getProxiedTools()[0]!.handler({ payload: "hello" });

    // Denied (fail closed), upstream never called, engine never consulted.
    expect(clientManager.callTool).not.toHaveBeenCalled();
    expect(filterOutbound).not.toHaveBeenCalled();
    const parsed = JSON.parse((result as any).content[0].text);
    expect(parsed.error).toBe("Operation not permitted");
    expect(parsed.privacy_denied).toBe(true);

    // The audit entry carries the DISTINCT vault/filter-error reason class —
    // not the mislabeled "no policy bound" class.
    const audit = await auditLog.query({ limit: 50 });
    const denied = audit.entries.find((e) =>
      e.operation.startsWith("proxy_privacy_denied:")
    );
    expect(denied).toBeDefined();
    expect((denied!.details as any).denial_reason_class).toBe("fail_closed_filter_error");
    expect((denied!.details as any).denial_reason_class).not.toBe("fail_closed_no_policy");
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
