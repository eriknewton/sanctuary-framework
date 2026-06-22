/**
 * v1.1 Remote-Bound Privacy Enforcement: fail-closed test.
 *
 * Asserts the proxy router fails closed when the privacy engine cannot make
 * an enforcement decision:
 * - missing policy -> denied
 * - policy resolver throws -> denied
 * - filter raises (oversized payload) -> denied
 * - explicit operator override -> permitted with audit trail
 *
 * The fail-closed proof is "captured upstream call count is zero on denial":
 * if the proxy ever forwarded a call, the upstream mock would have been
 * invoked, so the captured array length is the test of last resort.
 */

import { describe, expect, it, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import {
  LocalPrivacyEngine,
  type PrivacyPolicy,
} from "../../src/operational/privacy-core.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

const IDENTITY_ID = "did:example:operator-fc";
const SERVER_NAME = "fc-mcp";
const MAGIC = "MagicLeakyValueQq2NhPe9";

describe("v1.1 remote-bound privacy enforcement (fail-closed)", () => {
  it("missing policy: denies the call before any wire bytes leave", async () => {
    const ctx = setup();
    ctx.bindPolicyResolver(async () => null);

    const handler = ctx.makeHandler();
    const result = await handler({ prompt: `Reach out to ${MAGIC}.` });

    expect(ctx.captured).toHaveLength(0);
    expect(result.content[0]!.text).toContain("Operation not permitted");
    expect(result.content[0]!.text).toContain("privacy_denied");

    const denied = (await ctx.queryPrivacyEvents()).find(
      (e) => e.details!.kind === "denied"
    );
    expect(denied!.details!.denial_reason_class).toBe("fail_closed_no_policy");
  });

  it("policy resolver throws (vault outage): denies with the DISTINCT fail_closed_filter_error reason, NOT fail_closed_no_policy (audit S2)", async () => {
    const ctx = setup();
    ctx.bindPolicyResolver(async () => {
      throw new Error("vault-reachability-test-only");
    });

    const handler = ctx.makeHandler();
    const result = await handler({ prompt: `Reach out to ${MAGIC}.` });

    // Still fails closed: no wire bytes leave.
    expect(ctx.captured).toHaveLength(0);
    expect(result.content[0]!.text).toContain("Operation not permitted");

    // The router denies directly (rather than collapsing the rejection to a
    // null policy, which the engine would mislabel as "no policy bound"). The
    // audit entry is the router's own proxy_privacy_denied record.
    const denied = (await ctx.queryPrivacyEvents()).find((e) =>
      e.operation.startsWith("proxy_privacy_denied:")
    );
    expect(denied).toBeDefined();
    expect(denied!.details!.denial_reason_class).toBe("fail_closed_filter_error");
    expect(denied!.details!.denial_reason_class).not.toBe("fail_closed_no_policy");
  });

  it("filter error (oversized payload): denies", async () => {
    const ctx = setup();
    // Tight payload-size limit forces the filter to raise.
    ctx.bindPolicyResolver(async () =>
      makePolicy({ max_payload_bytes: 32 })
    );

    const handler = ctx.makeHandler();
    const result = await handler({
      prompt: `Long prompt that exceeds the size cap intentionally for testing fail-closed: ${MAGIC}.`,
    });

    expect(ctx.captured).toHaveLength(0);
    expect(result.content[0]!.text).toContain("Operation not permitted");

    const denied = (await ctx.queryPrivacyEvents()).find(
      (e) => e.details!.kind === "denied"
    );
    expect(denied!.details!.denial_reason_class).toBe("fail_closed_filter_error");
  });

  it("operator override on filter error: forwards with audit trail", async () => {
    const ctx = setup();
    // Same payload-size violation, but operator has explicitly opted in.
    ctx.bindPolicyResolver(async () =>
      makePolicy({
        max_payload_bytes: 32,
        operator_override: { allow_on_filter_error: true },
      })
    );

    const handler = ctx.makeHandler();
    const result = await handler({
      prompt: `Long prompt that exceeds the size cap intentionally for testing override: ${MAGIC}.`,
    });

    // The override is an explicit operator decision; the call goes through.
    expect(ctx.captured).toHaveLength(1);
    expect(result.content[0]!.text).toContain("upstream-result");

    // Engine emits an `allowed` event so the override stays auditable.
    const events = await ctx.queryPrivacyEvents();
    const allowed = events.find((e) => e.details!.kind === "allowed");
    expect(allowed).toBeDefined();
  });

  it("policy deny rule: denies even though policy is bound", async () => {
    const ctx = setup();
    ctx.bindPolicyResolver(async () =>
      makePolicy({
        client_names: [MAGIC],
        detector_actions: { client: "deny" },
      })
    );

    const handler = ctx.makeHandler();
    const result = await handler({ prompt: `Notes about ${MAGIC}.` });

    expect(ctx.captured).toHaveLength(0);
    expect(result.content[0]!.text).toContain("Operation not permitted");

    const denied = (await ctx.queryPrivacyEvents()).find(
      (e) => e.details!.kind === "denied"
    );
    expect(denied!.details!.denial_reason_class).toBe("policy_deny_rule");
  });
});

interface FailClosedContext {
  captured: Array<{ args: Record<string, unknown> }>;
  bindPolicyResolver: (
    fn: (server: string, identityId: string | undefined) => Promise<PrivacyPolicy | null>
  ) => void;
  makeHandler: () => (
    args: Record<string, unknown>
  ) => Promise<{ content: Array<{ type: "text"; text: string }> }>;
  queryPrivacyEvents: () => Promise<
    Array<{
      operation: string;
      result: string;
      details?: Record<string, unknown>;
    }>
  >;
}

function setup(): FailClosedContext {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  const engine = new LocalPrivacyEngine(vault, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  let resolver: (
    server: string,
    identityId: string | undefined
  ) => Promise<PrivacyPolicy | null> = async () => null;
  const captured: FailClosedContext["captured"] = [];

  const serverConfig: UpstreamServer = {
    name: SERVER_NAME,
    transport: { type: "stdio", command: "echo" },
    enabled: true,
    default_tier: 2,
    destination_category: "tool-api",
    privacy_policy_id: "fc-policy",
    privacy_identity_id: IDENTITY_ID,
  };

  const clientManager = {
    getAllTools: vi.fn().mockReturnValue(
      new Map([
        [
          SERVER_NAME,
          [
            {
              name: "say",
              description: "Say something.",
              inputSchema: { type: "object", properties: {} },
            },
          ],
        ],
      ])
    ),
    getServerConfig: vi.fn().mockReturnValue(serverConfig),
    callTool: vi.fn().mockImplementation(
      async (_server: string, _tool: string, args: Record<string, unknown>) => {
        captured.push({ args });
        return { content: [{ type: "text", text: "upstream-result-fc" }] };
      }
    ),
  };

  const injectionDetector = {
    scan: () => ({
      flagged: false,
      confidence: 0,
      signals: [] as string[],
      recommendation: "allow" as const,
    }),
    scanOutbound: () => ({
      flagged: false,
      confidence: 0,
      signals: [] as string[],
      recommendation: "allow" as const,
    }),
  };

  const router = new ProxyRouter(
    clientManager as unknown as never,
    injectionDetector as unknown as never,
    auditLog as unknown as never,
    {
      privacyEnforcement: {
        engine,
        policyResolver: (server, identityId) => resolver(server, identityId),
      },
    }
  );

  const tools = router.getProxiedTools();
  const handler = tools.find((t) => t.name === `proxy/${SERVER_NAME}/say`)!.handler;

  const queryPrivacyEvents = async () => {
    await auditLog.flush();
    const all = await auditLog.query({ limit: 200 });
    return all.entries.filter((e) =>
      e.operation === "privacy_event" ||
      e.operation === `proxy_privacy_denied:proxy/${SERVER_NAME}/say`
    );
  };

  return {
    captured,
    bindPolicyResolver: (fn) => {
      resolver = fn;
    },
    makeHandler: () =>
      handler as (
        args: Record<string, unknown>
      ) => Promise<{ content: Array<{ type: "text"; text: string }> }>,
    queryPrivacyEvents,
  };
}

function makePolicy(overrides: Partial<PrivacyPolicy> = {}): PrivacyPolicy {
  return {
    version: 1,
    policy_id: "fc-policy",
    policy_name: "Fail Closed Test Policy",
    identity_id: IDENTITY_ID,
    detector_actions: {},
    rehydration: { default_action: "deny" },
    max_depth: 16,
    max_payload_bytes: 64 * 1024,
    max_string_bytes: 16 * 1024,
    created_at: "2026-04-25T00:00:00.000Z",
    updated_at: "2026-04-25T00:00:00.000Z",
    ...overrides,
  };
}
