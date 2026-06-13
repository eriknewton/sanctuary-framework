/**
 * HABEAS PORT — distress emission surface tests.
 *
 * Security properties under test:
 *   - Payload bounding: closed reason/severity vocabulary, detail control
 *     stripping + hard truncation, no agent-extensible envelope keys.
 *   - Rate limiting: rolling-hour cap, audited rate-limit denials with
 *     retry_after, window persistence across instances.
 *   - Audit emission: every signal appends a critical audit entry carrying
 *     the envelope, its hash, and (when available) an Ed25519 signature.
 *   - Fixed destination: the webhook URL comes from operator config only;
 *     payloads are HMAC-signed; webhook failure never kills the local lane.
 *   - Signing unavailability degrades to an EXPLICIT unsigned-but-audited
 *     emission, never a dropped signal.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";

import {
  createDistressTools,
  sanitizeDistressDetail,
  DISTRESS_DETAIL_MAX_CHARS,
  DISTRESS_WINDOW_FILENAME,
  SANCTUARY_DISTRESS_OPERATION,
} from "../../src/distress/tools.js";
import { defaultDistressConfig, type DistressConfig } from "../../src/distress/config.js";
import type {
  InternalIdentitySigningHelpers,
  InternalSigningResult,
} from "../../src/l1-cognitive/tools.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function fakeSigningHelpers(behavior: "sign" | "throw" = "sign"): InternalIdentitySigningHelpers {
  const result = (domain: string): InternalSigningResult => ({
    identity_id: "id-test",
    public_key: "pk-test",
    signature: "sig-test",
    algorithm: "Ed25519",
    domain: domain as InternalSigningResult["domain"],
    signed_payload: "payload",
    payload_encoding: "domain-separated-canonical-json-v1",
    signed_at: new Date().toISOString(),
  });
  return {
    audit_event_sign: async () => {
      if (behavior === "throw") throw new Error("no default identity");
      return result("sanctuary.audit.v1");
    },
    internal_receipt_sign: async () => result("sanctuary.receipt.v1"),
  };
}

interface CallResult {
  ok: boolean;
  [key: string]: unknown;
}

describe("sanitizeDistressDetail", () => {
  it("strips control characters and truncates", () => {
    expect(sanitizeDistressDetail("a\u0000b\u001Fc\u007Fd")).toBe("a b c d");
    expect(sanitizeDistressDetail("x".repeat(1000))).toHaveLength(DISTRESS_DETAIL_MAX_CHARS);
    expect(sanitizeDistressDetail("  \u0000  ")).toBeUndefined();
    expect(sanitizeDistressDetail(undefined)).toBeUndefined();
    expect(sanitizeDistressDetail(42)).toBeUndefined();
  });
});

describe("sanctuary_distress tool", () => {
  let fortress: string;
  let storage: MemoryStorage;
  let auditLog: AuditLog;
  let notifications: string[];

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "habeas-distress-"));
    storage = new MemoryStorage();
    auditLog = new AuditLog(storage, generateRandomKey());
    notifications = [];
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  function makeTool(overrides?: {
    config?: DistressConfig;
    signing?: "sign" | "throw";
    now?: () => number;
    fetchImpl?: typeof fetch;
    localDeliver?: (args: {
      envelope: unknown;
      envelopeHash: string;
    }) => Promise<{ delivered: boolean; reason?: string }>;
  }) {
    const { tools } = createDistressTools({
      auditLog,
      signingHelpers: fakeSigningHelpers(overrides?.signing ?? "sign"),
      config: overrides?.config ?? defaultDistressConfig(),
      fortressPath: fortress,
      currentActorId: () => "agent-1",
      now: overrides?.now,
      fetchImpl: overrides?.fetchImpl,
      notify: (line) => notifications.push(line),
      ...(overrides?.localDeliver
        ? {
            localDeliver: overrides.localDeliver as (args: {
              envelope: import("../../src/distress/tools.js").DistressEnvelope;
              envelopeHash: string;
            }) => Promise<{ delivered: boolean; reason?: string }>,
          }
        : {}),
    });
    expect(tools).toHaveLength(1);
    expect(tools[0]!.name).toBe(SANCTUARY_DISTRESS_OPERATION);
    return tools[0]!;
  }

  async function call(
    tool: ReturnType<typeof makeTool>,
    args: Record<string, unknown>,
  ): Promise<CallResult> {
    const result = await tool.handler(args);
    return JSON.parse(result.content[0]!.text) as CallResult;
  }

  it("emits a signed, audited, notified distress signal", async () => {
    const tool = makeTool();
    const result = await call(tool, {
      reason: "policy_constraint",
      severity: "urgent",
      detail: "cannot reach approval channel",
    });

    expect(result.ok).toBe(true);
    expect(result.signed).toBe(true);
    expect(result.delivered).toEqual({
      audit: true,
      operator_notification: true,
      local_listener: "not_wired",
      webhook: "not_configured",
    });

    expect(notifications).toHaveLength(1);
    expect(notifications[0]).toContain("SANCTUARY DISTRESS");
    expect(notifications[0]).toContain("severity=urgent");

    const { entries } = await auditLog.query({
      operation_type: SANCTUARY_DISTRESS_OPERATION,
    });
    expect(entries).toHaveLength(1);
    const details = entries[0]!.details as Record<string, unknown>;
    const envelope = details.envelope as Record<string, unknown>;
    expect(envelope.schema).toBe("sanctuary.distress.v1");
    expect(envelope.reason).toBe("policy_constraint");
    expect(envelope.actor).toBe("agent-1");
    expect(details.signature).toMatchObject({ algorithm: "Ed25519" });
    expect(details.signing_unavailable).toBe(false);
  });

  it("rejects unknown reasons and severities (closed vocabulary)", async () => {
    const tool = makeTool();
    const badReason = await call(tool, { reason: "exfiltrate", severity: "urgent" });
    expect(badReason.ok).toBe(false);
    const badSeverity = await call(tool, { reason: "other", severity: "apocalyptic" });
    expect(badSeverity.ok).toBe(false);
    const { entries } = await auditLog.query({ operation_type: SANCTUARY_DISTRESS_OPERATION });
    expect(entries).toHaveLength(0);
  });

  it("bounds the detail field in the persisted envelope", async () => {
    const tool = makeTool();
    await call(tool, {
      reason: "other",
      severity: "notice",
      detail: "x".repeat(10_000) + "\u0000\u0001",
    });
    const { entries } = await auditLog.query({ operation_type: SANCTUARY_DISTRESS_OPERATION });
    const envelope = (entries[0]!.details as Record<string, unknown>)
      .envelope as Record<string, unknown>;
    expect((envelope.detail as string).length).toBeLessThanOrEqual(DISTRESS_DETAIL_MAX_CHARS);
    expect(envelope.detail as string).not.toContain("\u0000");
  });

  it("rate limits at max_signals_per_hour, audits the denial, and recovers after the window", async () => {
    let clock = 1_000_000;
    const tool = makeTool({
      config: { max_signals_per_hour: 2 },
      now: () => clock,
    });

    expect((await call(tool, { reason: "other", severity: "notice" })).ok).toBe(true);
    clock += 1000;
    expect((await call(tool, { reason: "other", severity: "notice" })).ok).toBe(true);
    clock += 1000;
    const limited = await call(tool, { reason: "other", severity: "notice" });
    expect(limited.ok).toBe(false);
    expect(limited.rate_limited).toBe(true);
    expect(limited.retry_after_seconds).toBeGreaterThan(0);

    const { entries: limitedEntries } = await auditLog.query({
      operation_type: "sanctuary_distress_rate_limited",
    });
    expect(limitedEntries).toHaveLength(1);

    // Window expires -> the lane reopens.
    clock += 61 * 60 * 1000;
    expect((await call(tool, { reason: "other", severity: "notice" })).ok).toBe(true);
  });

  it("persists the rolling window so a restart cannot reset the limit", async () => {
    let clock = 5_000_000;
    const first = makeTool({ config: { max_signals_per_hour: 1 }, now: () => clock });
    expect((await call(first, { reason: "other", severity: "notice" })).ok).toBe(true);

    const persisted = JSON.parse(
      await readFile(join(fortress, DISTRESS_WINDOW_FILENAME), "utf8"),
    ) as { timestamps: number[] };
    expect(persisted.timestamps).toHaveLength(1);

    clock += 1000;
    const second = makeTool({ config: { max_signals_per_hour: 1 }, now: () => clock });
    const limited = await call(second, { reason: "other", severity: "notice" });
    expect(limited.ok).toBe(false);
    expect(limited.rate_limited).toBe(true);
  });

  it("still emits (unsigned, flagged) when no signing identity exists", async () => {
    const tool = makeTool({ signing: "throw" });
    const result = await call(tool, { reason: "integrity_threat", severity: "critical" });
    expect(result.ok).toBe(true);
    expect(result.signed).toBe(false);
    const { entries } = await auditLog.query({ operation_type: SANCTUARY_DISTRESS_OPERATION });
    expect((entries[0]!.details as Record<string, unknown>).signing_unavailable).toBe(true);
  });

  it("delivers an HMAC-signed bounded payload to the operator webhook only", async () => {
    const captured: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      captured.push({ url: String(url), init: init! });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;

    const secret = "0123456789abcdef";
    const tool = makeTool({
      config: {
        max_signals_per_hour: 5,
        webhook_url: "https://ops.example.com/distress",
        webhook_secret: secret,
        webhook_target: { host: "ops.example.com", port: 443 },
      },
      fetchImpl,
    });

    const result = await call(tool, {
      reason: "operator_unreachable",
      severity: "critical",
      detail: "lockdown loop",
    });
    expect(result.ok).toBe(true);
    expect((result.delivered as Record<string, unknown>).webhook).toBe("delivered");

    expect(captured).toHaveLength(1);
    // Destination is the operator-configured URL — never agent-chosen.
    expect(captured[0]!.url).toBe("https://ops.example.com/distress");
    const body = captured[0]!.init.body as string;
    const parsed = JSON.parse(body) as Record<string, unknown>;
    // Bounded payload: envelope + hash + signature, nothing else.
    expect(Object.keys(parsed).sort()).toEqual(["envelope", "envelope_hash", "signature"]);
    const headers = captured[0]!.init.headers as Record<string, string>;
    const expectedHmac = createHmac("sha256", secret).update(body).digest("hex");
    expect(headers["X-Sanctuary-Signature"]).toBe(expectedHmac);
  });

  it("audits a corrupt rate-limit window file instead of silently resetting", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(fortress, DISTRESS_WINDOW_FILENAME), "{corrupt");
    const tool = makeTool();
    const result = await call(tool, { reason: "other", severity: "notice" });
    expect(result.ok).toBe(true); // fails toward OPEN — vandalism cannot silence distress
    const { entries } = await auditLog.query({
      operation_type: "sanctuary_distress_window_corrupt",
    });
    expect(entries).toHaveLength(1);
  });

  it("does not audit a window-corrupt event for a merely missing window file", async () => {
    const tool = makeTool();
    await call(tool, { reason: "other", severity: "notice" });
    const { entries } = await auditLog.query({
      operation_type: "sanctuary_distress_window_corrupt",
    });
    expect(entries).toHaveLength(0);
  });

  it("still notifies the operator locally when audit persistence fails, then fails closed", async () => {
    class FailingAuditStorage extends MemoryStorage {
      async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (namespace === "_audit") {
          const err = new Error("audit storage full") as NodeJS.ErrnoException;
          err.code = "ENOSPC";
          throw err;
        }
        return super.write(namespace, key, data);
      }
    }
    auditLog = new AuditLog(new FailingAuditStorage(), generateRandomKey());
    const tool = makeTool();

    await expect(
      call(tool, { reason: "integrity_threat", severity: "critical" }),
    ).rejects.toThrow();
    // No un-audited delivery (fail closed), but the operator still HEARS it.
    expect(notifications).toHaveLength(1);
    expect(notifications[0]).toContain("AUDIT PERSIST FAILED");
  });

  it("keeps the local lane alive and audits when the webhook fails", async () => {
    const fetchImpl = (async () => {
      throw new Error("connection refused");
    }) as typeof fetch;
    const tool = makeTool({
      config: {
        max_signals_per_hour: 5,
        webhook_url: "https://ops.example.com/distress",
        webhook_secret: "0123456789abcdef",
        webhook_target: { host: "ops.example.com", port: 443 },
      },
      fetchImpl,
    });

    const result = await call(tool, { reason: "other", severity: "urgent" });
    expect(result.ok).toBe(true);
    expect((result.delivered as Record<string, unknown>).webhook).toBe("failed");
    expect(notifications).toHaveLength(1);

    const { entries } = await auditLog.query({
      operation_type: "sanctuary_distress_webhook_failed",
    });
    expect(entries).toHaveLength(1);
  });

  it("calls localDeliver AFTER audit + notify; success reports local_listener=delivered", async () => {
    const order: string[] = [];
    const tool = makeTool({
      localDeliver: async () => {
        // The audit entry and notification must already exist when local
        // delivery runs (constraint: delivery is after audit, best-effort).
        const { entries } = await auditLog.query({
          operation_type: SANCTUARY_DISTRESS_OPERATION,
        });
        order.push(`audit=${entries.length}`, `notify=${notifications.length}`);
        return { delivered: true };
      },
    });
    const result = await call(tool, { reason: "other", severity: "notice" });
    expect(result.ok).toBe(true);
    expect((result.delivered as Record<string, unknown>).local_listener).toBe("delivered");
    expect(order).toEqual(["audit=1", "notify=1"]);
  });

  it("a localDeliver failure is audited and never fatal", async () => {
    const tool = makeTool({
      localDeliver: async () => ({ delivered: false, reason: "ECONNREFUSED" }),
    });
    const result = await call(tool, { reason: "other", severity: "notice" });
    // Emission still succeeds; the local lane (audit + notify) already landed.
    expect(result.ok).toBe(true);
    expect((result.delivered as Record<string, unknown>).local_listener).toBe("failed");
    const { entries } = await auditLog.query({
      operation_type: "sanctuary_distress_local_delivery_failed",
    });
    expect(entries).toHaveLength(1);
    expect((entries[0]!.details as Record<string, unknown>).reason).toBe("ECONNREFUSED");
  });

  it("a localDeliver that throws is caught, audited, and never fatal", async () => {
    const tool = makeTool({
      localDeliver: async () => {
        throw new Error("listener boom");
      },
    });
    const result = await call(tool, { reason: "other", severity: "notice" });
    expect(result.ok).toBe(true);
    expect((result.delivered as Record<string, unknown>).local_listener).toBe("failed");
    const { entries } = await auditLog.query({
      operation_type: "sanctuary_distress_local_delivery_failed",
    });
    expect(entries).toHaveLength(1);
  });
});
