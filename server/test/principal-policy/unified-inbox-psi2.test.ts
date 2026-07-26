/**
 * Psi-2 producer wiring + encrypted persistence regressions.
 */

import { describe, it, expect } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { BudgetTracker } from "../../src/policy-engine/budget-gate.js";
import { AuditConsumer } from "../../src/castle-wall/runtime/audit-consumer.js";
import {
  UnifiedInboxBridge,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import {
  UNIFIED_INBOX_NAMESPACE,
  UNIFIED_INBOX_KEY_PREFIX,
  UnifiedInboxStore,
} from "../../src/principal-policy/unified-inbox-store.js";
import {
  aggregateRhoDailyPrivacyEvents,
  ingestBudgetThreshold,
  ingestRecoveryPrompt,
  ingestWrappedAgentErrors,
} from "../../src/principal-policy/unified-inbox-producers.js";
import type { CastleWallAuditEvent } from "../../src/castle-wall/audit/events.js";

const FORTRESS = "fortress_psi2";
const IDENTITY = "identity_psi2";
const OBSERVED_AT = "2026-05-09T12:00:00.000Z";

function rig(opts?: { storage?: MemoryStorage; masterKey?: Uint8Array }) {
  const storage = opts?.storage ?? new MemoryStorage();
  const masterKey = opts?.masterKey ?? generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new UnifiedInboxStore({
    storage,
    masterKey,
    fortressId: FORTRESS,
    now: () => new Date(OBSERVED_AT),
  });
  const bridge = new UnifiedInboxBridge({
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
    store,
    now: () => new Date(OBSERVED_AT),
  });
  return { storage, masterKey, auditLog, store, bridge };
}

describe("Psi-2 - UnifiedInboxStore encrypted persistence", () => {
  it("round-trips an entry and does not store plaintext summary bytes", async () => {
    const { storage, store, bridge } = rig();
    const entry = bridge.ingestApproval({
      source_event_id: "approval-raw-sentinel",
      severity: "warn",
      summary: "PLAINTEXT_SENTINEL_UNIFIED_INBOX",
      observed_at: OBSERVED_AT,
    })!;
    await bridge.flushPersistence();

    const loaded = await store.get(entry.inbox_id);
    expect(loaded?.summary).toBe("PLAINTEXT_SENTINEL_UNIFIED_INBOX");
    const raw = await storage.read(
      UNIFIED_INBOX_NAMESPACE,
      `${UNIFIED_INBOX_KEY_PREFIX}${entry.inbox_id}`,
    );
    expect(raw).not.toBeNull();
    expect(bytesToString(raw!)).not.toContain("PLAINTEXT_SENTINEL_UNIFIED_INBOX");
  });

  it("AAD binding rejects an inbox_id substitution", async () => {
    const { storage, store, bridge } = rig();
    const entry = bridge.ingestApproval({
      source_event_id: "aad-a",
      severity: "warn",
      summary: "aad test",
      observed_at: OBSERVED_AT,
    })!;
    await bridge.flushPersistence();
    const raw = await storage.read(
      UNIFIED_INBOX_NAMESPACE,
      `${UNIFIED_INBOX_KEY_PREFIX}${entry.inbox_id}`,
    );
    await storage.write(
      UNIFIED_INBOX_NAMESPACE,
      `${UNIFIED_INBOX_KEY_PREFIX}substituted`,
      raw!,
    );
    await expect(store.get("substituted")).resolves.toBeNull();
  });

  it("rehydrates pending entries on restart", async () => {
    const { storage, masterKey, bridge } = rig();
    const entry = bridge.ingestApproval({
      source_event_id: "restart-a",
      severity: "warn",
      summary: "survives restart",
      observed_at: OBSERVED_AT,
    })!;
    await bridge.flushPersistence();
    const nextStore = new UnifiedInboxStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const nextBridge = new UnifiedInboxBridge({
      auditLog: new AuditLog(storage, masterKey),
      identityId: IDENTITY,
      fortressId: FORTRESS,
      store: nextStore,
    });
    await expect(nextBridge.rehydratePendingFromStore()).resolves.toBe(1);
    expect(nextBridge.get(entry.inbox_id)?.summary).toBe("survives restart");
  });

  it("prunes expired entries", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new UnifiedInboxStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
      retentionDays: 1,
      now: () => new Date("2026-05-01T00:00:00.000Z"),
    });
    await store.upsert({
      inbox_id: "expired-entry",
      source_class: "approval",
      source_event_id: "expired",
      severity: "warn",
      summary: "expired",
      details_url: "/api/inbox/unified/expired-entry",
      observed_at: "2026-05-01T00:00:00.000Z",
      fortress_id: FORTRESS,
    });
    await expect(store.pruneExpired(new Date("2026-05-03T00:00:00.000Z"))).resolves.toEqual({ pruned: 1 });
    await expect(store.get("expired-entry")).resolves.toBeNull();
  });

  it("isolates fortresses cryptographically", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new UnifiedInboxStore({
      storage,
      masterKey,
      fortressId: "fortress_a",
    });
    await storeA.upsert({
      inbox_id: "shared-inbox",
      source_class: "approval",
      source_event_id: "shared-source",
      severity: "warn",
      summary: "only A",
      details_url: "/api/inbox/unified/shared-inbox",
      observed_at: OBSERVED_AT,
      fortress_id: "fortress_a",
    });
    const storeB = new UnifiedInboxStore({
      storage,
      masterKey,
      fortressId: "fortress_b",
    });
    await expect(storeB.get("shared-inbox")).resolves.toBeNull();
  });
});

describe("Psi-2 - producer wiring", () => {
  it("Castle Wall AuditConsumer emits blocked egress into the bridge", async () => {
    const { auditLog, bridge } = rig();
    const consumer = new AuditConsumer(auditLog, bridge);
    const event: CastleWallAuditEvent = {
      schema_version: 1,
      layer: "l1",
      timestamp: OBSERVED_AT,
      fortress_id: FORTRESS,
      event_type: "egress_blocked",
      agent: { id: "agent_alpha", template: "coding-assistant" },
      destination: { host: "api.example.test", ip: "203.0.113.10", port: 443, protocol: "tcp" },
      decision: "deny_once",
      rule_id: null,
      details: { seq: 1, prior_sha256_hex: null, reason: "lockdown_active" },
    };
    await consumer.ingestCritical({ event, ack: async () => {} });
    const entries = bridge.list({ includeResolved: true });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.source_class).toBe("blocked_egress");
    expect(entries[0]!.severity).toBe("critical");
  });

  it("Rho-1 daily aggregation emits one privacy_event with top headers", async () => {
    const { auditLog, bridge } = rig();
    for (const removed of [
      [{ name: "User-Agent", reason: "user-agent" }],
      [{ name: "Accept-Language", reason: "locale-fingerprint" }, { name: "User-Agent", reason: "user-agent" }],
    ]) {
      await auditLog.append("l2", "query_anonymity_headers_stripped", IDENTITY, {
        fortress_id: FORTRESS,
        stripped_count: removed.length,
        removed,
      });
    }
    await auditLog.flush();
    const entry = await aggregateRhoDailyPrivacyEvents({
      auditLog,
      bridge,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      now: new Date("2026-05-09T23:00:00.000Z"),
    });
    expect(entry?.source_class).toBe("privacy_event");
    expect(entry?.summary).toContain("3");
    const ops = await auditLog.query({ operation_type: "query_anonymity_daily_aggregated", limit: 10 });
    expect(ops.entries[0]!.details?.top_headers).toEqual(["user-agent", "accept-language"]);
  });

  it("budget threshold emitter maps 75/90/100 to warn/alert/critical", () => {
    const { bridge } = rig();
    const warn = ingestBudgetThreshold({
      bridge,
      agent_id: "agent_budget",
      threshold_name: "75pct",
      current_value: 75,
      limit: 100,
      observed_at: `${OBSERVED_AT}:1`,
    });
    const alert = ingestBudgetThreshold({
      bridge,
      agent_id: "agent_budget",
      threshold_name: "90pct",
      current_value: 90,
      limit: 100,
      observed_at: `${OBSERVED_AT}:2`,
    });
    const critical = ingestBudgetThreshold({
      bridge,
      agent_id: "agent_budget",
      threshold_name: "100pct",
      current_value: 100,
      limit: 100,
      observed_at: `${OBSERVED_AT}:3`,
    });
    expect(warn?.severity).toBe("warn");
    expect(alert?.severity).toBe("alert");
    expect(critical?.severity).toBe("critical");
  });

  it("BudgetTracker invokes the threshold callback", () => {
    const seen: unknown[] = [];
    const tracker = new BudgetTracker({
      onThresholdCross: (event) => seen.push(event),
      now: () => new Date(OBSERVED_AT),
    });
    tracker.recordSpend("agent_budget", 90, OBSERVED_AT);
    tracker.checkBudget(
      "agent_budget",
      {
        daily: { amount: 100, unit: "tokens", soft_warn_threshold: 0.75 },
      },
      Date.parse(OBSERVED_AT),
    );
    expect(seen).toEqual([
      {
        agent_id: "agent_budget",
        threshold_name: "soft_warn",
        current_value: 90,
        limit: 100,
        window: "daily",
        observed_at: OBSERVED_AT,
      },
    ]);
  });

  it("recovery prompts distinguish opt-in, required, and deadline-bound severities", () => {
    const { bridge } = rig();
    const optIn = ingestRecoveryPrompt({
      bridge,
      recovery_class: "exit_drill",
      action_required: false,
      observed_at: `${OBSERVED_AT}:1`,
    });
    const required = ingestRecoveryPrompt({
      bridge,
      recovery_class: "keychain_rebind",
      action_required: true,
      observed_at: `${OBSERVED_AT}:2`,
    });
    const deadline = ingestRecoveryPrompt({
      bridge,
      recovery_class: "passphrase_reset",
      action_required: true,
      deadline: "2026-05-10T00:00:00.000Z",
      observed_at: `${OBSERVED_AT}:3`,
    });
    expect(optIn?.severity).toBe("warn");
    expect(required?.severity).toBe("alert");
    expect(deadline?.severity).toBe("critical");
  });

  it("wrapped-agent error reporter maps transient, repeated, and fatal errors", async () => {
    const { auditLog, bridge } = rig();
    await auditLog.append("l2", "wrapped_agent_error", IDENTITY, {
      context: "wrapped_agent",
      severity: "error",
      agent_id: "agent_err",
      harness_name: "claude_code",
      error_class: "TransientNetworkError",
    });
    for (let i = 0; i < 4; i++) {
      await auditLog.append("l2", "wrapped_agent_error", IDENTITY, {
        context: "wrapped_agent",
        severity: "error",
        agent_id: "agent_repeat",
        error_class: "RetryableToolError",
      });
    }
    await auditLog.append("l2", "wrapped_agent_error", IDENTITY, {
      context: "wrapped_agent",
      severity: "error",
      fatal: true,
      agent_id: "agent_fatal",
      error_class: "FatalHarnessExit",
    });
    await auditLog.flush();
    const entries = await ingestWrappedAgentErrors({
      auditLog,
      bridge,
      since: "2026-05-09T00:00:00.000Z",
    });
    expect(
      entries.find((e) => e.summary.includes("(TransientNetworkError)"))
        ?.severity,
    ).toBe("warn");
    expect(
      entries.find((e) => e.summary.includes("(RetryableToolError)"))
        ?.severity,
    ).toBe("alert");
    expect(
      entries.find((e) => e.summary.includes("(FatalHarnessExit)"))?.severity,
    ).toBe("critical");
    expect(entries.map((e) => e.agent_id)).toEqual(
      entries.map(() => "unknown"),
    );
  });

  it("does not attribute forged unsigned Castle Wall error evidence to a victim agent", async () => {
    const { auditLog, bridge } = rig();
    await auditLog.append("l1", "egress_blocked", IDENTITY, {
      context: "wrapped_agent",
      severity: "error",
      agent_id: "victim-agent-b",
      error_class: "E_FORGED_CASTLE_WALL",
      dest_host: "evil.example",
      dest_ip: "203.0.113.92",
      dest_port: 443,
      dest_protocol: "tcp",
    });
    await auditLog.flush();

    const entries = await ingestWrappedAgentErrors({
      auditLog,
      bridge,
      now: new Date("2026-05-09T13:00:00.000Z"),
    });

    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBe("unknown");
    expect(JSON.stringify(entries)).not.toContain("victim-agent-b");
    expect(JSON.stringify(entries)).not.toContain("verified");
  });
});
