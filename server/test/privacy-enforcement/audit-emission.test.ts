/**
 * v1.1 Remote-Bound Privacy Enforcement: audit emission test.
 *
 * Two assertions per enforcement path:
 *   1. The matching `privacy_event` is emitted with the right `kind`.
 *   2. NO field on any emitted audit entry contains the raw sensitive value.
 *
 * The full audit chain is read at the end of the test and grepped for the
 * MAGIC strings; if any field anywhere holds them, the test fails.
 */

import { describe, expect, it, vi } from "vitest";
import { ProxyRouter } from "../../src/proxy/proxy-router.js";
import {
  LocalPrivacyEngine,
  type PrivacyPolicy,
} from "../../src/l2-operational/privacy-core.js";
import { PrivacyPlaceholderVault } from "../../src/l2-operational/privacy-filter.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

const IDENTITY_ID = "did:example:operator-ae";
const SERVER_NAME = "ae-mcp";

// Magic high-entropy values that MUST not appear anywhere in the audit log
// at any layer for any decision class.
const MAGIC_EMAIL = "evelyn.audit42@worldsuniqueprivacytestmail.example";
const MAGIC_CLIENT = "Quasar-Audit-Industries-LLC-7c9";
const MAGIC_SECRET = "sk-audittest-Z9fA7Q4CbK0pRvLs1234567";

describe("v1.1 remote-bound privacy enforcement (audit emission)", () => {
  it("allowed decision: privacy_event/kind=allowed and no raw content anywhere", async () => {
    const ctx = setup();
    ctx.bindPolicy(makePolicy());

    const handler = ctx.makeHandler();
    await handler({ prompt: "weather forecast for tomorrow" });

    const all = await ctx.allAuditEntries();
    const privacy = all.filter((e) => e.operation === "privacy_event");
    expect(privacy.length).toBeGreaterThan(0);
    expect(privacy.at(-1)!.details!.kind).toBe("allowed");
    expectNoMagicAnywhere(all);
  });

  it("filtered decision: privacy_event/kind=filtered and no raw content anywhere", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
      })
    );

    const handler = ctx.makeHandler();
    await handler({
      prompt: `Email ${MAGIC_EMAIL} at ${MAGIC_CLIENT} using ${MAGIC_SECRET}.`,
    });

    const all = await ctx.allAuditEntries();
    const privacy = all.filter((e) => e.operation === "privacy_event");
    expect(privacy.length).toBeGreaterThan(0);
    const filtered = privacy.find((e) => e.details!.kind === "filtered");
    expect(filtered).toBeDefined();

    expectNoMagicAnywhere(all);
  });

  it("denied decision (policy_deny_rule): privacy_event/kind=denied and no raw content anywhere", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
        detector_actions: { client: "deny" },
      })
    );

    const handler = ctx.makeHandler();
    await handler({ prompt: `Notes about ${MAGIC_CLIENT}.` });

    const all = await ctx.allAuditEntries();
    const privacy = all.filter((e) => e.operation === "privacy_event");
    const denied = privacy.find((e) => e.details!.kind === "denied");
    expect(denied).toBeDefined();
    expect(denied!.details!.denial_reason_class).toBe("policy_deny_rule");

    // Proxy-level denial entry MUST also be present and safe.
    const proxyDenied = all.find((e) =>
      e.operation === `proxy_privacy_denied:proxy/${SERVER_NAME}/talk`
    );
    expect(proxyDenied).toBeDefined();
    expect(proxyDenied!.result).toBe("failure");
    expect(JSON.stringify(proxyDenied!.details ?? {})).not.toContain(MAGIC_CLIENT);

    expectNoMagicAnywhere(all);
  });

  it("denied decision (fail_closed_no_policy): privacy_event/kind=denied and no raw content anywhere", async () => {
    const ctx = setup();
    ctx.bindPolicy(null);

    const handler = ctx.makeHandler();
    await handler({ prompt: `Reach out to ${MAGIC_EMAIL} regarding ${MAGIC_CLIENT}.` });

    const all = await ctx.allAuditEntries();
    const denied = all
      .filter((e) => e.operation === "privacy_event")
      .find((e) => e.details!.kind === "denied");
    expect(denied).toBeDefined();
    expect(denied!.details!.denial_reason_class).toBe("fail_closed_no_policy");

    expectNoMagicAnywhere(all);
  });

  it("rehydrated decision: privacy_event/kind=rehydrated and no raw content anywhere", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
        rehydration: { allowed_destinations: ["tool-api"] },
      })
    );
    ctx.respondWith(() => ({
      content: [
        { type: "text", text: "Drafted note for CLIENT_1." },
      ],
    }));

    const handler = ctx.makeHandler();
    await handler({ prompt: `Plan kickoff for ${MAGIC_CLIENT}.` });

    const all = await ctx.allAuditEntries();
    const rehydrated = all
      .filter((e) => e.operation === "privacy_event")
      .find((e) => e.details!.kind === "rehydrated");
    expect(rehydrated).toBeDefined();
    expect(rehydrated!.details!.rehydrated_count).toBeGreaterThan(0);

    expectNoMagicAnywhere(all);
  });
});

function expectNoMagicAnywhere(
  entries: Array<{
    operation: string;
    result: string;
    details?: Record<string, unknown>;
    timestamp: string;
    layer: string;
    identity_id: string;
  }>
): void {
  const serialized = JSON.stringify(entries);
  expect(serialized).not.toContain(MAGIC_EMAIL);
  expect(serialized).not.toContain(MAGIC_CLIENT);
  expect(serialized).not.toContain(MAGIC_SECRET);
}

interface AuditContext {
  bindPolicy: (policy: PrivacyPolicy | null) => void;
  respondWith: (
    fn: () => {
      content: Array<{ type: string; text?: string; [key: string]: unknown }>;
    }
  ) => void;
  makeHandler: () => (
    args: Record<string, unknown>
  ) => Promise<{ content: Array<{ type: "text"; text: string }> }>;
  allAuditEntries: () => Promise<
    Array<{
      operation: string;
      result: string;
      details?: Record<string, unknown>;
      timestamp: string;
      layer: string;
      identity_id: string;
    }>
  >;
}

function setup(): AuditContext {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  const engine = new LocalPrivacyEngine(vault, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  let boundPolicy: PrivacyPolicy | null = null;
  let responder: () => {
    content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  } = () => ({
    content: [{ type: "text", text: "upstream-result-ae" }],
  });

  const serverConfig: UpstreamServer = {
    name: SERVER_NAME,
    transport: { type: "stdio", command: "echo" },
    enabled: true,
    default_tier: 2,
    destination_category: "tool-api",
    privacy_policy_id: "ae-policy",
    privacy_identity_id: IDENTITY_ID,
  };

  const clientManager = {
    getAllTools: vi.fn().mockReturnValue(
      new Map([
        [
          SERVER_NAME,
          [
            {
              name: "talk",
              description: "Talk.",
              inputSchema: { type: "object", properties: {} },
            },
          ],
        ],
      ])
    ),
    getServerConfig: vi.fn().mockReturnValue(serverConfig),
    callTool: vi.fn().mockImplementation(async () => responder()),
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
        policyResolver: async () => boundPolicy,
      },
    }
  );

  const tools = router.getProxiedTools();
  const handler = tools.find((t) => t.name === `proxy/${SERVER_NAME}/talk`)!.handler;

  const allAuditEntries = async () => {
    await auditLog.flush();
    const result = await auditLog.query({ limit: 500 });
    return result.entries;
  };

  return {
    bindPolicy: (p) => {
      boundPolicy = p;
    },
    respondWith: (fn) => {
      responder = fn;
    },
    makeHandler: () =>
      handler as (
        args: Record<string, unknown>
      ) => Promise<{ content: Array<{ type: "text"; text: string }> }>,
    allAuditEntries,
  };
}

function makePolicy(overrides: Partial<PrivacyPolicy> = {}): PrivacyPolicy {
  return {
    version: 1,
    policy_id: "ae-policy",
    policy_name: "Audit Emission Test Policy",
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
