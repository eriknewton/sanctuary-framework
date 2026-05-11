/**
 * WP-V1.3-4 Psi-1 Unified Inbox Bridge regression suite.
 *
 * Coverage:
 *   - Per-source-class ingest: approval, sentinel_finding,
 *     blocked_egress, privacy_event, budget_warning,
 *     recovery_prompt, agent_error.
 *   - Deduplication: same (source_class, source_event_id) ingested
 *     twice emits exactly one entry + a DEDUPED audit event.
 *   - Severity escalation: blocked_egress fail-closed -> critical;
 *     budget at 100% -> critical; budget 80% -> alert.
 *   - HTTP routes: list (with source_class + severity filter),
 *     detail, resolve.
 *   - Multi-fortress isolation: two bridges keep entries separate.
 *   - Audit emission: AGGREGATED + RESOLVED + DEDUPED fire correctly.
 *   - Castle-walking: no outbound surface; in-memory only.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  UnifiedInboxBridge,
  UNIFIED_INBOX_AUDIT_OPS,
  type UnifiedInboxBridgeEvent,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import {
  UNIFIED_INBOX_API_PREFIX,
  handleUnifiedInboxRoute,
} from "../../src/principal-policy/unified-inbox-routes.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";
const OBSERVED_AT = "2026-05-09T12:00:00.000Z";

function makeBridge(opts?: { fortressId?: string }): {
  bridge: UnifiedInboxBridge;
  auditLog: AuditLog;
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const bridge = new UnifiedInboxBridge({
    auditLog,
    identityId: IDENTITY,
    fortressId: opts?.fortressId ?? FORTRESS_A,
  });
  return { bridge, auditLog };
}

async function makeServer(bridge: UnifiedInboxBridge): Promise<{
  base: string;
  close: () => Promise<void>;
}> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleUnifiedInboxRoute(
      { authConfig: { loopbackAutoAuth: true }, bridge },
      req,
      res,
    );
    if (!handled) {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve) =>
        server.close(() => resolve()),
      ),
  };
}

async function auditOps(auditLog: AuditLog): Promise<string[]> {
  const result = await auditLog.query({ layer: "l2", limit: 200 });
  return result.entries.map((e: AuditEntry) => e.operation);
}

describe("Psi-1 — per-source-class ingest", () => {
  it("ingestApproval normalizes into a UnifiedInboxEntry", () => {
    const { bridge } = makeBridge();
    const entry = bridge.ingestApproval({
      source_event_id: "audit-1:state_export",
      severity: "warn",
      summary: "Tier 1 state_export awaiting approval",
      observed_at: OBSERVED_AT,
      agent_id: "agent_alpha",
    });
    expect(entry).not.toBeNull();
    expect(entry!.source_class).toBe("approval");
    expect(entry!.agent_id).toBe("agent_alpha");
    expect(entry!.details_url).toBe(`/api/inbox/unified/${entry!.inbox_id}`);
  });

  it("ingestSentinelFinding maps finding_id into source_event_id", () => {
    const { bridge } = makeBridge();
    const entry = bridge.ingestSentinelFinding({
      finding_id: "f-1",
      severity: "alert",
      summary: "egress-volume +6 sigma",
      observed_at: OBSERVED_AT,
      sentinel_id: "egress-volume",
      agent_id: "agent_beta",
    });
    expect(entry!.source_class).toBe("sentinel_finding");
    expect(entry!.source_event_id).toBe("f-1");
    expect(entry!.severity).toBe("alert");
  });

  it("ingestBlockedEgress escalates fail-closed to critical severity", () => {
    const { bridge } = makeBridge();
    const policyDeny = bridge.ingestBlockedEgress({
      source_event_id: "block-1",
      destination_category: "tool-api",
      block_reason_class: "egress_policy_deny",
      observed_at: OBSERVED_AT,
    });
    const failClosed = bridge.ingestBlockedEgress({
      source_event_id: "block-2",
      destination_category: "llm",
      block_reason_class: "privacy_fail_closed",
      observed_at: OBSERVED_AT,
    });
    expect(policyDeny!.severity).toBe("alert");
    expect(failClosed!.severity).toBe("critical");
  });

  it("ingestPrivacyEvent no-ops on zero count and summarizes a non-zero aggregation", () => {
    const { bridge } = makeBridge();
    const empty = bridge.ingestPrivacyEvent({
      source_event_id: "priv-empty",
      count: 0,
      privacy_event_kind: "headers_stripped_summary",
      observed_at: OBSERVED_AT,
    });
    expect(empty).toBeNull();
    const populated = bridge.ingestPrivacyEvent({
      source_event_id: "priv-1",
      count: 47,
      privacy_event_kind: "headers_stripped_summary",
      observed_at: OBSERVED_AT,
    });
    expect(populated).not.toBeNull();
    expect(populated!.summary).toContain("47");
    expect(populated!.severity).toBe("info");
  });

  it("ingestBudgetWarning severity scales with used_fraction", () => {
    const { bridge } = makeBridge();
    const soft = bridge.ingestBudgetWarning({
      source_event_id: "budget-1",
      bucket: "daily",
      used_fraction: 0.5,
      observed_at: OBSERVED_AT,
    });
    const alert = bridge.ingestBudgetWarning({
      source_event_id: "budget-2",
      bucket: "daily",
      used_fraction: 0.85,
      observed_at: OBSERVED_AT,
    });
    const critical = bridge.ingestBudgetWarning({
      source_event_id: "budget-3",
      bucket: "daily",
      used_fraction: 1.0,
      observed_at: OBSERVED_AT,
    });
    expect(soft!.severity).toBe("warn");
    expect(alert!.severity).toBe("alert");
    expect(critical!.severity).toBe("critical");
  });

  it("ingestRecoveryPrompt fires at alert severity with recovery_class in summary", () => {
    const { bridge } = makeBridge();
    const entry = bridge.ingestRecoveryPrompt({
      source_event_id: "rec-1",
      recovery_class: "passphrase_reset",
      observed_at: OBSERVED_AT,
    });
    expect(entry!.severity).toBe("alert");
    expect(entry!.summary).toContain("passphrase reset");
  });

  it("ingestAgentError marks inactive agents critical and active agents warn", () => {
    const { bridge } = makeBridge();
    const active = bridge.ingestAgentError({
      source_event_id: "err-1",
      agent_id: "agent_alpha",
      error_class: "TransientNetworkError",
      agent_still_active: true,
      observed_at: OBSERVED_AT,
    });
    const inactive = bridge.ingestAgentError({
      source_event_id: "err-2",
      agent_id: "agent_beta",
      error_class: "FatalAssertion",
      agent_still_active: false,
      observed_at: OBSERVED_AT,
    });
    expect(active!.severity).toBe("warn");
    expect(inactive!.severity).toBe("critical");
    expect(inactive!.summary).toContain("inactive");
  });
});

describe("Psi-1 — deduplication", () => {
  it("same (source_class, source_event_id) ingested twice produces one entry + a DEDUPED audit event", async () => {
    const { bridge, auditLog } = makeBridge();
    const first = bridge.ingestApproval({
      source_event_id: "audit-1:state_export",
      severity: "warn",
      summary: "first",
      observed_at: OBSERVED_AT,
    });
    const second = bridge.ingestApproval({
      source_event_id: "audit-1:state_export",
      severity: "warn",
      summary: "second (should dedupe)",
      observed_at: OBSERVED_AT,
    });
    expect(first).not.toBeNull();
    expect(second).toBeNull();
    expect(bridge.size()).toBe(1);
    const ops = await auditOps(auditLog);
    expect(ops).toContain(UNIFIED_INBOX_AUDIT_OPS.AGGREGATED);
    expect(ops).toContain(UNIFIED_INBOX_AUDIT_OPS.DEDUPED);
  });

  it("dedup is per source_class — same source_event_id across classes co-exists", () => {
    const { bridge } = makeBridge();
    bridge.ingestApproval({
      source_event_id: "shared-id",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    });
    bridge.ingestSentinelFinding({
      finding_id: "shared-id",
      severity: "info",
      summary: "sentinel",
      observed_at: OBSERVED_AT,
      sentinel_id: "egress-volume",
    });
    expect(bridge.size()).toBe(2);
  });
});

describe("Psi-1 — HTTP routes", () => {
  it("GET /api/inbox/unified lists entries and supports source_class + severity filters", async () => {
    const { bridge } = makeBridge();
    bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval-warn",
      observed_at: OBSERVED_AT,
    });
    bridge.ingestBlockedEgress({
      source_event_id: "b1",
      destination_category: "tool-api",
      block_reason_class: "egress_policy_deny",
      observed_at: OBSERVED_AT,
    });
    const { base, close } = await makeServer(bridge);
    try {
      const allRes = await fetch(`${base}${UNIFIED_INBOX_API_PREFIX}`);
      const allBody = (await allRes.json()) as {
        data: { entries: Array<{ source_class: string }> };
      };
      expect(allBody.data.entries.length).toBe(2);

      const filtRes = await fetch(
        `${base}${UNIFIED_INBOX_API_PREFIX}?source_class=blocked_egress`,
      );
      const filtBody = (await filtRes.json()) as {
        data: { entries: Array<{ source_class: string }> };
      };
      expect(filtBody.data.entries.length).toBe(1);
      expect(filtBody.data.entries[0]!.source_class).toBe("blocked_egress");
    } finally {
      await close();
    }
  });

  it("GET /api/inbox/unified/:inbox_id returns full detail; unknown id returns 404", async () => {
    const { bridge } = makeBridge();
    const entry = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval-warn",
      observed_at: OBSERVED_AT,
    })!;
    const { base, close } = await makeServer(bridge);
    try {
      const okRes = await fetch(
        `${base}${UNIFIED_INBOX_API_PREFIX}/${entry.inbox_id}`,
      );
      expect(okRes.status).toBe(200);
      const okBody = (await okRes.json()) as {
        data: { entry: { source_event_id: string } };
      };
      expect(okBody.data.entry.source_event_id).toBe("a1");

      const notFoundRes = await fetch(
        `${base}${UNIFIED_INBOX_API_PREFIX}/no-such-inbox-id`,
      );
      expect(notFoundRes.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("POST /api/inbox/unified/:inbox_id/resolve marks the entry resolved and emits a RESOLVED audit event", async () => {
    const { bridge, auditLog } = makeBridge();
    const entry = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    })!;
    const { base, close } = await makeServer(bridge);
    try {
      const res = await fetch(
        `${base}${UNIFIED_INBOX_API_PREFIX}/${entry.inbox_id}/resolve`,
        { method: "POST" },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { entry: { resolved_at?: string; resolved_by?: string } };
      };
      expect(body.data.entry.resolved_at).toBeDefined();
      expect(body.data.entry.resolved_by).toBe("operator");
      const ops = await auditOps(auditLog);
      expect(ops).toContain(UNIFIED_INBOX_AUDIT_OPS.RESOLVED);
    } finally {
      await close();
    }
  });

  it("by default, list excludes resolved entries; include_resolved=true surfaces them", async () => {
    const { bridge } = makeBridge();
    const e1 = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    })!;
    bridge.resolve(e1.inbox_id, "operator");
    const { base, close } = await makeServer(bridge);
    try {
      const hidden = (await (
        await fetch(`${base}${UNIFIED_INBOX_API_PREFIX}`)
      ).json()) as { data: { entries: unknown[] } };
      expect(hidden.data.entries.length).toBe(0);

      const shown = (await (
        await fetch(
          `${base}${UNIFIED_INBOX_API_PREFIX}?include_resolved=true`,
        )
      ).json()) as { data: { entries: unknown[] } };
      expect(shown.data.entries.length).toBe(1);
    } finally {
      await close();
    }
  });

  it("unknown path under /api/inbox/unified returns 404", async () => {
    const { bridge } = makeBridge();
    const { base, close } = await makeServer(bridge);
    try {
      const res = await fetch(`${base}${UNIFIED_INBOX_API_PREFIX}/foo/bar`);
      expect(res.status).toBe(404);
    } finally {
      await close();
    }
  });
});

describe("Psi-1 — subscribers + audit + multi-fortress + Castle-walking", () => {
  it("subscribers receive ingested + resolved events", () => {
    const { bridge } = makeBridge();
    const events: UnifiedInboxBridgeEvent[] = [];
    const unsub = bridge.onEvent((e) => events.push(e));
    const entry = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    })!;
    bridge.resolve(entry.inbox_id, "operator");
    unsub();
    bridge.ingestApproval({
      source_event_id: "a2",
      severity: "warn",
      summary: "after-unsubscribe",
      observed_at: OBSERVED_AT,
    });
    const types = events.map((e) => e.type);
    expect(types).toEqual(["ingested", "resolved"]);
  });

  it("audit emission: AGGREGATED fires on ingest, DEDUPED on duplicate, RESOLVED on operator resolve", async () => {
    const { bridge, auditLog } = makeBridge();
    const entry = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    })!;
    bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "dupe",
      observed_at: OBSERVED_AT,
    });
    bridge.resolve(entry.inbox_id, "operator");
    const ops = await auditOps(auditLog);
    expect(ops.filter((o) => o === UNIFIED_INBOX_AUDIT_OPS.AGGREGATED).length).toBe(1);
    expect(ops.filter((o) => o === UNIFIED_INBOX_AUDIT_OPS.DEDUPED).length).toBe(1);
    expect(ops.filter((o) => o === UNIFIED_INBOX_AUDIT_OPS.RESOLVED).length).toBe(1);
  });

  it("multi-fortress isolation: two bridges maintain independent entry sets", () => {
    const { bridge: bridgeA } = makeBridge({ fortressId: FORTRESS_A });
    const { bridge: bridgeB } = makeBridge({ fortressId: FORTRESS_B });
    bridgeA.ingestApproval({
      source_event_id: "shared",
      severity: "warn",
      summary: "in-A",
      observed_at: OBSERVED_AT,
    });
    expect(bridgeA.size()).toBe(1);
    expect(bridgeB.size()).toBe(0);
    const aEntries = bridgeA.list({ includeResolved: true });
    expect(aEntries[0]!.fortress_id).toBe(FORTRESS_A);
  });

  it("Castle-walking: a full ingest + resolve round-trip emits no outbound audit ops", async () => {
    const { bridge, auditLog } = makeBridge();
    const entry = bridge.ingestApproval({
      source_event_id: "a1",
      severity: "warn",
      summary: "approval",
      observed_at: OBSERVED_AT,
    })!;
    bridge.resolve(entry.inbox_id, "operator");
    const ops = new Set(await auditOps(auditLog));
    // No outbound: no proxy_call:*, no query_anonymity_*, no
    // intelligence_substrate_invoked, no cross-fortress mesh emit.
    expect([...ops].some((o) => o.startsWith("proxy_call:"))).toBe(false);
    expect(ops.has("query_anonymity_headers_stripped")).toBe(false);
    expect(ops.has("intelligence_substrate_invoked")).toBe(false);
  });
});
