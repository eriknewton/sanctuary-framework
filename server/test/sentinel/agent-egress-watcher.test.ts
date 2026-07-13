/**
 * Agent egress deny-spike watcher (MED-3, confined-agent egress design
 * 2026-07-10 section 5) regression suite.
 *
 * Covers:
 *  - Deny-spike: below-threshold silence, at/over-threshold alert naming the
 *    host, per-host independence, rule-attributed (non-default-deny) denials
 *    excluded, allowed flows excluded, out-of-window denials excluded.
 *  - Alert memoization: a continuing burst re-alerts at most once per
 *    window; a fresh burst after the window re-alerts.
 *  - Probe-failure surfacing: an `egress_probe_failed` audit entry raises
 *    the same alert rail.
 *  - Catalog visibility of the new sentinel id.
 */

import { describe, it, expect } from "vitest";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import {
  AgentEgressWatcher,
  AGENT_EGRESS_SENTINEL_ID,
  DENY_SPIKE_THRESHOLD,
  DENY_SPIKE_WINDOW_MINUTES,
} from "../../src/sentinel/sentinels/agent-egress-watcher.js";
import { PHI1_BASELINE_CATALOG } from "../../src/sentinel/sentinels/index.js";
import type { SentinelContext } from "../../src/sentinel/types.js";

const NOW = new Date("2026-07-10T12:00:00.000Z");

function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: {
      since?: string;
      layer?: AuditEntry["layer"];
      limit?: number;
    }): Promise<{ entries: AuditEntry[]; total: number }> {
      let filtered = entries;
      if (opts.since) {
        const sinceMs = Date.parse(opts.since);
        filtered = filtered.filter((e) => Date.parse(e.timestamp) >= sinceMs);
      }
      if (opts.layer) {
        filtered = filtered.filter((e) => e.layer === opts.layer);
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

function makeContext(entries: AuditEntry[], now: Date = NOW): SentinelContext {
  return {
    fortressId: "fortress-1",
    auditLog: makeStubAuditLog(entries),
    now: () => now,
  };
}

/** One recorded default-deny egress denial (the macOS extension shape). */
function deniedFlow(host: string, minutesAgo: number, ruleId: string | null = null): AuditEntry {
  return {
    timestamp: new Date(NOW.getTime() - minutesAgo * 60_000).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "fortress-1",
    result: "failure",
    details: {
      decision: "drop",
      ...(ruleId !== null ? { rule_id: ruleId } : {}),
      destination: { host, ip: "203.0.113.7", port: 443, protocol: "tcp" },
    },
  } as unknown as AuditEntry;
}

function allowedFlow(host: string, minutesAgo: number): AuditEntry {
  return {
    timestamp: new Date(NOW.getTime() - minutesAgo * 60_000).toISOString(),
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "fortress-1",
    result: "success",
    details: {
      decision: "allow",
      rule_id: "provisioned-hermes-abc123def456",
      destination: { host, ip: "203.0.113.8", port: 443, protocol: "tcp" },
    },
  } as unknown as AuditEntry;
}

function probeFailure(host: string, minutesAgo: number): AuditEntry {
  return {
    timestamp: new Date(NOW.getTime() - minutesAgo * 60_000).toISOString(),
    layer: "l1",
    operation: "egress_probe_failed",
    identity_id: "fortress-1",
    result: "failure",
    details: { host, port: 443, agent_uid: 503, rule_id: "provisioned-hermes-abc123def456" },
  } as unknown as AuditEntry;
}

async function subscribedWatcher(entries: AuditEntry[], now: Date = NOW): Promise<AgentEgressWatcher> {
  const watcher = new AgentEgressWatcher();
  await watcher.subscribe(makeContext(entries, now));
  return watcher;
}

describe("sentinel/agent-egress-watcher: deny-spike", () => {
  it("stays SILENT below the threshold", async () => {
    const entries = Array.from({ length: DENY_SPIKE_THRESHOLD - 1 }, (_, i) =>
      deniedFlow("api.venice.ai", (i % 9) + 1),
    );
    const watcher = await subscribedWatcher(entries);
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("raises ONE alert naming the host at the threshold", async () => {
    const entries = Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) =>
      deniedFlow("api.venice.ai", (i % 9) + 1),
    );
    const watcher = await subscribedWatcher(entries);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("alert");
    expect(findings[0]!.sentinel_id).toBe(AGENT_EGRESS_SENTINEL_ID);
    expect(findings[0]!.summary).toContain("api.venice.ai");
    expect(findings[0]!.details).toMatchObject({
      host: "api.venice.ai",
      deny_count: DENY_SPIKE_THRESHOLD,
      signal: "deny-spike",
    });
    expect(findings[0]!.evidence_audit_ids.length).toBeGreaterThan(0);
  });

  it("counts per host independently (two spiking hosts = two findings; a quiet host = none)", async () => {
    const entries = [
      ...Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) => deniedFlow("a.example", (i % 9) + 1)),
      ...Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) => deniedFlow("b.example", (i % 9) + 1)),
      deniedFlow("quiet.example", 1),
    ];
    const watcher = await subscribedWatcher(entries);
    const findings = await watcher.evaluate();
    const hosts = findings.map((f) => f.details.host).sort();
    expect(hosts).toEqual(["a.example", "b.example"]);
  });

  it("EXCLUDES rule-attributed denials (an explicit deny rule is operator intent, not silent drift) and allowed flows", async () => {
    const entries = [
      ...Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) =>
        deniedFlow("api.venice.ai", (i % 9) + 1, "operator-deny-rule"),
      ),
      ...Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) => allowedFlow("api.venice.ai", (i % 9) + 1)),
    ];
    const watcher = await subscribedWatcher(entries);
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("EXCLUDES denials older than the window", async () => {
    const entries = Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) =>
      deniedFlow("api.venice.ai", DENY_SPIKE_WINDOW_MINUTES + 1 + i),
    );
    const watcher = await subscribedWatcher(entries);
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("memoizes per host: a continuing burst does not re-alert within the window, and resetAlertMemo restores alerting", async () => {
    const entries = Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) =>
      deniedFlow("api.venice.ai", (i % 9) + 1),
    );
    const watcher = await subscribedWatcher(entries);
    expect(await watcher.evaluate()).toHaveLength(1);
    // Same burst, immediate re-tick: silent (already alerted this window).
    expect(await watcher.evaluate()).toEqual([]);
    watcher.resetAlertMemo();
    expect(await watcher.evaluate()).toHaveLength(1);
  });
});

describe("sentinel/agent-egress-watcher: as-uid probe failures", () => {
  it("surfaces an egress_probe_failed audit entry as an alert naming the host", async () => {
    const watcher = await subscribedWatcher([probeFailure("gmail.googleapis.com", 3)]);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("alert");
    expect(findings[0]!.summary).toContain("gmail.googleapis.com");
    expect(findings[0]!.details).toMatchObject({ signal: "as-uid-probe-failure" });
  });

  it("deny-spike and probe-failure signals are independent (both can fire in one evaluation)", async () => {
    const entries = [
      ...Array.from({ length: DENY_SPIKE_THRESHOLD }, (_, i) => deniedFlow("api.venice.ai", (i % 9) + 1)),
      probeFailure("gmail.googleapis.com", 2),
    ];
    const watcher = await subscribedWatcher(entries);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(2);
    const signals = findings.map((f) => f.details.signal).sort();
    expect(signals).toEqual(["as-uid-probe-failure", "deny-spike"]);
  });
});

describe("sentinel/agent-egress-watcher: catalog", () => {
  it("is registered in the baseline catalog with a factory producing the watcher", () => {
    const entry = PHI1_BASELINE_CATALOG.find((e) => e.sentinelId === AGENT_EGRESS_SENTINEL_ID);
    expect(entry).toBeDefined();
    expect(entry!.factory()).toBeInstanceOf(AgentEgressWatcher);
  });
});
