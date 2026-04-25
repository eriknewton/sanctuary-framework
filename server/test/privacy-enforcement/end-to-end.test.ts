/**
 * v1.1 Remote-Bound Privacy Enforcement: end-to-end test.
 *
 * Drives the ProxyRouter with a real LocalPrivacyEngine, real
 * PrivacyPlaceholderVault, real AuditLog, and a fake ClientManager that
 * captures the bytes that *would* go upstream. The captured bytes are the
 * authoritative wire surface; raw sensitive spans MUST never appear there.
 *
 * Covers:
 * - allowed: payload with no sensitive content goes through unchanged
 * - filtered: payload with sensitive content reaches upstream with placeholders
 * - rehydrated: response placeholders restored on inbound
 * - rehydration denied: placeholders survive when policy denies rehydration
 *
 * Magic test value: a high-entropy literal is embedded in the payload and
 * grepped against the captured upstream args; zero hits is the proof.
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

const IDENTITY_ID = "did:example:operator-rb1";
const SERVER_NAME = "downstream-mcp";

const MAGIC_EMAIL = "alice.zzqq42@worldsuniqueprivacytestmail.example";
const MAGIC_CLIENT = "Hexapod-Industries-LLC-9f4e";
const MAGIC_PROJECT = "Project-Quintessence-XR-882";
const MAGIC_SECRET = "sk-rbtest-Z9fA7QwELx3pKvNs1234567";
const MAGIC_FILE_PATH = "/Users/erik/Clients/Hexapod-Industries-LLC-9f4e/plans.md";

describe("v1.1 remote-bound privacy enforcement (end-to-end)", () => {
  it("allowed: payload with no sensitive content forwards unchanged + audit shows allowed", async () => {
    const ctx = setup();
    ctx.bindPolicy(makePolicy());

    const handler = ctx.makeHandler();
    const args = { question: "What is the weather forecast for tomorrow?" };

    const result = await handler(args);

    expect(ctx.captured).toHaveLength(1);
    expect(ctx.captured[0]!.args).toEqual(args);
    expect(result.content[0]!.text).toContain("upstream-result");

    const events = await ctx.queryPrivacyEvents();
    expect(events.length).toBeGreaterThan(0);
    expect(events.at(-1)!.details!.kind).toBe("allowed");
  });

  it("filtered: sensitive spans never appear in upstream wire bytes", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
        project_names: [MAGIC_PROJECT],
        rehydration: { default_action: "deny" },
      })
    );

    const handler = ctx.makeHandler();
    const args = {
      messages: [
        {
          role: "user",
          content:
            `Email ${MAGIC_EMAIL} at ${MAGIC_CLIENT} about ${MAGIC_PROJECT}. ` +
            `Use ${MAGIC_SECRET} and ${MAGIC_FILE_PATH}.`,
        },
      ],
    };

    await handler(args);

    expect(ctx.captured).toHaveLength(1);
    const wireBytes = JSON.stringify(ctx.captured[0]!.args);

    // The proof: every magic value is absent from the wire.
    expect(wireBytes).not.toContain(MAGIC_EMAIL);
    expect(wireBytes).not.toContain(MAGIC_CLIENT);
    expect(wireBytes).not.toContain(MAGIC_PROJECT);
    expect(wireBytes).not.toContain(MAGIC_SECRET);
    expect(wireBytes).not.toContain(MAGIC_FILE_PATH);

    // Placeholders are present.
    expect(wireBytes).toContain("EMAIL_");
    expect(wireBytes).toContain("CLIENT_");
    expect(wireBytes).toContain("PROJECT_");
    expect(wireBytes).toContain("SECRET_");
    expect(wireBytes).toContain("FILE_PATH_");

    const events = await ctx.queryPrivacyEvents();
    const filtered = events.find((e) => e.details!.kind === "filtered");
    expect(filtered).toBeDefined();
    expect(filtered!.details!.policy_id).toBe("rb-policy");
  });

  it("rehydrated: upstream response placeholders restored when policy permits", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
        rehydration: { allowed_destinations: ["tool-api"] },
      })
    );

    // Upstream echoes back a response that references the placeholder. The
    // wire bytes are checked outside the responder via ctx.captured to avoid
    // having proxy try/catch swallow an in-responder assertion failure.
    ctx.respondWith(() => ({
      content: [
        {
          type: "text",
          text: "Drafted email for CLIENT_1 with detail summary.",
        },
      ],
    }));

    const handler = ctx.makeHandler();

    // Warm-up call establishes the placeholder mapping (CLIENT_1 -> magic).
    await handler({
      prompt: `Draft an email about ${MAGIC_CLIENT} priorities.`,
    });

    const result = await handler({
      prompt: `Follow up about ${MAGIC_CLIENT} priorities.`,
    });

    expect(JSON.stringify(ctx.captured.at(-1)!.args)).not.toContain(MAGIC_CLIENT);
    expect(JSON.stringify(ctx.captured.at(-1)!.args)).toContain("CLIENT_1");

    const text = result.content[0]!.text;
    expect(text).toContain(MAGIC_CLIENT);
    expect(text).not.toContain("CLIENT_1");

    const events = await ctx.queryPrivacyEvents();
    const rehydrated = events.filter((e) => e.details!.kind === "rehydrated");
    expect(rehydrated.length).toBeGreaterThan(0);
    expect(rehydrated.at(-1)!.details!.rehydrated_count).toBeGreaterThan(0);
  });

  it("rehydration denied: placeholders survive when policy denies rehydration", async () => {
    const ctx = setup();
    ctx.bindPolicy(
      makePolicy({
        client_names: [MAGIC_CLIENT],
        rehydration: { default_action: "deny" },
      })
    );

    ctx.respondWith((_args) => ({
      content: [{ type: "text", text: "Echo: CLIENT_1 plan ready." }],
    }));

    const handler = ctx.makeHandler();
    const result = await handler({
      prompt: `Plan kickoff for ${MAGIC_CLIENT}.`,
    });

    const text = result.content[0]!.text;
    expect(text).toContain("CLIENT_1");
    expect(text).not.toContain(MAGIC_CLIENT);

    const events = await ctx.queryPrivacyEvents();
    const denied = events.filter(
      (e) =>
        e.details!.kind === "denied" &&
        e.details!.denial_reason_class === "policy_deny_rule"
    );
    expect(denied.length).toBeGreaterThan(0);
  });
});

interface TestContext {
  storage: MemoryStorage;
  vault: PrivacyPlaceholderVault;
  engine: LocalPrivacyEngine;
  auditLog: AuditLog;
  captured: Array<{ server: string; tool: string; args: Record<string, unknown> }>;
  bindPolicy: (policy: PrivacyPolicy) => void;
  respondWith: (
    fn: (args: Record<string, unknown>) => {
      content: Array<{ type: string; text?: string; [key: string]: unknown }>;
    }
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

function setup(): TestContext {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  const engine = new LocalPrivacyEngine(vault, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  let boundPolicy: PrivacyPolicy | null = null;
  const captured: TestContext["captured"] = [];
  let responder: (
    args: Record<string, unknown>
  ) => {
    content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  } = () => ({
    content: [{ type: "text", text: "upstream-result-default" }],
  });

  const serverConfig: UpstreamServer = {
    name: SERVER_NAME,
    transport: { type: "stdio", command: "echo" },
    enabled: true,
    default_tier: 2,
    destination_category: "tool-api",
    privacy_policy_id: "rb-policy",
    privacy_identity_id: IDENTITY_ID,
  };

  const clientManager = {
    getAllTools: vi.fn().mockReturnValue(
      new Map([
        [
          SERVER_NAME,
          [
            {
              name: "draft",
              description: "Draft a message.",
              inputSchema: { type: "object", properties: {} },
            },
          ],
        ],
      ])
    ),
    getServerConfig: vi.fn().mockReturnValue(serverConfig),
    callTool: vi.fn().mockImplementation(
      async (server: string, tool: string, args: Record<string, unknown>) => {
        captured.push({ server, tool, args });
        return responder(args);
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
        policyResolver: async () => boundPolicy,
      },
    }
  );

  const tools = router.getProxiedTools();
  const handler = tools.find((t) => t.name === `proxy/${SERVER_NAME}/draft`)!.handler;

  const queryPrivacyEvents = async () => {
    await auditLog.flush();
    const all = await auditLog.query({ limit: 200 });
    return all.entries.filter((e) =>
      e.operation === "privacy_event" ||
      e.operation === `proxy_privacy_denied:proxy/${SERVER_NAME}/draft`
    );
  };

  return {
    storage,
    vault,
    engine,
    auditLog,
    captured,
    bindPolicy: (policy) => {
      boundPolicy = policy;
    },
    respondWith: (fn) => {
      responder = fn;
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
    policy_id: "rb-policy",
    policy_name: "Remote-Bound Test Policy",
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
