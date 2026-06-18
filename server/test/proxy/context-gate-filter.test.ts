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

  it("HIGH (block-fail-open fix): on_deny=\"block\" at the PROXY DENIES — clientManager.callTool NEVER called, original/unredacted args never forwarded, block-reason audit entry written, generic denial returned, no success entry", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);

    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer, policyStore: store } = createContextGateTools(storage, masterKey, auditLog);

    // A real policy whose default_action is "deny": any field not explicitly
    // allowed produces a "deny" decision. "payload" is allowed; "api_key" is
    // not, so it triggers deny — and with on_deny="block" the whole request
    // must be blocked.
    const policy = await store.create(
      "block-policy",
      [
        {
          provider: "tool-api",
          allow: ["payload"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ],
      "deny"
    );
    enforcer.configureFromProfile({ enabled: true, policy_id: policy.policy_id });
    // Ensure the enforcer's on_deny is "block" (the strictest setting under test).
    (enforcer as any).config.on_deny = "block";

    const clientManager = createMockClientManager();
    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        contextGateFilter: (toolName, args) =>
          enforcer.filterArgs(toolName, args, { respectBypass: false }),
      }
    );

    const result = await router.getProxiedTools()[0]!.handler({
      api_key: "super-secret-value",
      payload: "hello",
    });

    // (1) CORE PROOF: upstream MUST NOT be called at all on a block decision.
    // Before the fix, filterArgs returned the ORIGINAL args and the proxy
    // forwarded them upstream (callTool called with unredacted "api_key").
    expect(clientManager.callTool).not.toHaveBeenCalled();

    // (2) The sensitive value never appears anywhere in the agent-facing result,
    // and the caller gets a GENERIC denial (not a silent success).
    const parsed = JSON.parse((result as any).content[0].text);
    expect(parsed.error).toBe("Operation not permitted");
    expect(JSON.stringify(parsed)).not.toContain("super-secret-value");

    // (3) The audit trail records the HONEST policy-block reason (not an infra
    // filter error, and not a success).
    const audit = await auditLog.query({ limit: 50 });
    const blockEntry = audit.entries.find((e) =>
      e.operation.startsWith("proxy_context_gating_blocked:")
    );
    expect(blockEntry).toBeDefined();
    expect(blockEntry!.result).toBe("failure");
    expect((blockEntry!.details as any).decision).toBe("denied");
    expect((blockEntry!.details as any).reason).toBe("context_gating_blocked");
    // The denied field is recorded operator-side for diagnosis.
    expect((blockEntry!.details as any).denied_fields).toContain("api_key");

    // It must NOT be mislabeled as an infra filter error.
    const infraError = audit.entries.find((e) =>
      e.operation.startsWith("proxy_context_gate_error:")
    );
    expect(infraError).toBeUndefined();

    // No success proxy_call entry was written.
    const successEntry = audit.entries.find(
      (e) => e.operation.startsWith("proxy_call:") && e.result === "success"
    );
    expect(successEntry).toBeUndefined();
  });

  it("redact path still forwards FILTERED args (no over-correction from the block fix)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);

    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer, policyStore: store } = createContextGateTools(storage, masterKey, auditLog);

    // default_action "redact": api_key (not allowed) is redacted, not denied.
    const policy = await store.create(
      "redact-policy",
      [
        {
          provider: "tool-api",
          allow: ["payload"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ],
      "redact"
    );
    enforcer.configureFromProfile({ enabled: true, policy_id: policy.policy_id });

    const clientManager = createMockClientManager();
    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        contextGateFilter: (toolName, args) =>
          enforcer.filterArgs(toolName, args, { respectBypass: false }),
      }
    );

    await router.getProxiedTools()[0]!.handler({
      api_key: "super-secret-value",
      payload: "hello",
    });

    // The proxy DID forward — but with api_key redacted, payload intact.
    expect(clientManager.callTool).toHaveBeenCalledWith("test-server", "send", {
      api_key: "[REDACTED]",
      payload: "hello",
    });
  });

  it("log_only path (redact default) still forwards ORIGINAL args by design (no over-correction)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);

    const profile = createDefaultProfile();
    profile.features.context_gating.enabled = true;
    const { enforcer, policyStore: store } = createContextGateTools(storage, masterKey, auditLog);

    // log_only governs the redact/hash path: it logs WHAT WOULD be filtered but
    // forwards ORIGINAL args. (An explicit deny→block decision is NOT a log_only
    // concern — it always blocks; that is asserted by the block test above.) Use
    // a redact-default policy so the filter has redaction work to "log only".
    const policy = await store.create(
      "logonly-policy",
      [
        {
          provider: "tool-api",
          allow: ["payload"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ],
      "redact"
    );
    enforcer.configureFromProfile({ enabled: true, policy_id: policy.policy_id });
    enforcer.setLogOnly(true);

    const clientManager = createMockClientManager();
    const router = new ProxyRouter(
      clientManager as any,
      createInjectionDetector() as any,
      auditLog,
      {
        contextGateFilter: (toolName, args) =>
          enforcer.filterArgs(toolName, args, { respectBypass: false }),
      }
    );

    await router.getProxiedTools()[0]!.handler({
      api_key: "super-secret-value",
      payload: "hello",
    });

    // log_only forwards original args unchanged (by design).
    expect(clientManager.callTool).toHaveBeenCalledWith("test-server", "send", {
      api_key: "super-secret-value",
      payload: "hello",
    });
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
