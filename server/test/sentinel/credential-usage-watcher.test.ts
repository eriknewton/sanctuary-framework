/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-2 Credential Usage Watcher regression suite.
 *
 * Covers:
 *  - Rate-spike: warmup silence, +3 sigma warn, +6 sigma alert, per
 *    (agent, secret) independence, only-success counting, both
 *    `broker_secret_read` and `broker_token_issued` consumed.
 *  - New-pair fingerprint: silence at warmup, silence on familiar
 *    pairs, warn on one new pair, alert on >=3 new pairs, requires
 *    >=2 distinct secrets in current window.
 *  - Multi-fortress isolation.
 *  - Phi-1 catalog visibility + registry subscribe/unsubscribe round-
 *    trip for the new sentinel id.
 */

import { describe, it, expect } from "vitest";
import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import {
  CredentialUsageWatcher,
  CREDENTIAL_USAGE_SENTINEL_ID,
} from "../../src/sentinel/sentinels/credential-usage-watcher.js";
import {
  PHI1_BASELINE_CATALOG,
  EGRESS_VOLUME_SENTINEL_ID,
} from "../../src/sentinel/sentinels/index.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import type { SentinelContext } from "../../src/sentinel/types.js";

const NOW = new Date("2026-05-10T15:00:00.000Z");

function fixedClock(now: Date): () => Date {
  return () => now;
}

/**
 * Minimal audit-log stub: returns pre-seeded entries with the same
 * filtering semantics the real `query()` provides. Matches the
 * pattern Phi-1's `sentinel-framework.test.ts` uses so the credential
 * watcher tests stay test-file-local without touching disk.
 */
function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: {
      since?: string;
      layer?: AuditEntry["layer"];
      operation_type?: string;
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
      if (opts.operation_type) {
        filtered = filtered.filter(
          (e) => e.operation === opts.operation_type,
        );
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

interface BackdatedOpts {
  now: Date;
  /** Counts per baseline day, index 0 = 1 day ago, index 6 = 7 days ago. */
  perDay: number[];
  /** Count for the current (window 0) 24h slice. */
  currentDayCount?: number;
  agent: string;
  secret: string;
  /** Defaults to `broker_secret_read`. */
  operation?: "broker_secret_read" | "broker_token_issued";
  /** Defaults to `success`. */
  result?: "success" | "failure";
}

/**
 * Build a synthetic audit-log slice for one (agent, secret) pair.
 * Drives the rate-spike path tests; helpers below layer additional
 * agents / secrets on top.
 */
function backdatedReads(opts: BackdatedOpts): AuditEntry[] {
  const dayMs = 24 * 60 * 60 * 1000;
  const entries: AuditEntry[] = [];
  const operation = opts.operation ?? "broker_secret_read";
  const result = opts.result ?? "success";
  for (let i = 0; i < (opts.currentDayCount ?? 0); i += 1) {
    entries.push({
      timestamp: new Date(
        opts.now.getTime() - 60_000 - i * 1000,
      ).toISOString(),
      layer: "l3",
      operation,
      identity_id: "id-1",
      result,
      details: { agent: opts.agent, secret: opts.secret, scope: "scope" },
    });
  }
  for (let day = 1; day <= opts.perDay.length; day += 1) {
    const count = opts.perDay[day - 1]!;
    for (let i = 0; i < count; i += 1) {
      entries.push({
        timestamp: new Date(
          opts.now.getTime() - day * dayMs - 60_000 - i * 1000,
        ).toISOString(),
        layer: "l3",
        operation,
        identity_id: "id-1",
        result,
        details: { agent: opts.agent, secret: opts.secret, scope: "scope" },
      });
    }
  }
  return entries;
}

function makeContext(audit: AuditLog, fortressId = "fortress-A"): SentinelContext {
  return {
    fortressId,
    auditLog: audit,
    now: fixedClock(NOW),
  };
}

// ── Rate-spike path ───────────────────────────────────────────────────────

describe("WP-V1.3-1 Phi-2 CredentialUsageWatcher: rate-spike path", () => {
  it("returns no findings when the audit log is empty", async () => {
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(makeStubAuditLog([])));
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("returns no findings during warmup (fewer than 7 populated baseline windows)", async () => {
    const audit = makeStubAuditLog(
      backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [10, 10, 0, 0, 0, 0, 0], // 2 populated baseline windows
        currentDayCount: 100, // would be a huge spike if baseline were ready
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("fires alert when current count exceeds mean + 6 sigma", async () => {
    const audit = makeStubAuditLog(
      backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        // mean = 8, stddev close to 1.6
        perDay: [8, 8, 8, 8, 7, 9, 8],
        currentDayCount: 47, // approx 24 sigma above mean
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const findings = await watcher.evaluate();
    const spike = findings.find((f) => f.severity === "alert");
    expect(spike).toBeDefined();
    expect(spike!.agent_id).toBe("Cline");
    expect(spike!.details.secret_id).toBe("db_admin_token");
    expect(spike!.details.current_count).toBe(47);
    expect(spike!.summary).toContain("Cline");
    expect(spike!.summary).toContain("db_admin_token");
  });

  it("fires warn when current count is between +3 sigma and +6 sigma", async () => {
    // mean = 10, variance ~= 1.14, stddev ~= 1.07.
    // warn threshold ~ 13.2, alert threshold ~ 16.4.
    // currentDayCount = 15 sits cleanly between the two.
    const audit = makeStubAuditLog(
      backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [8, 10, 10, 10, 10, 10, 12],
        currentDayCount: 15,
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const findings = await watcher.evaluate();
    const spike = findings.find((f) => f.severity === "warn");
    expect(spike).toBeDefined();
    expect(spike!.details.sigma_threshold).toBe(3);
  });

  it("stays silent at normal usage levels (within +3 sigma)", async () => {
    const audit = makeStubAuditLog(
      backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [10, 11, 9, 10, 12, 8, 10],
        currentDayCount: 11, // within 1 stddev
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    expect(await watcher.evaluate()).toEqual([]);
  });

  it("tracks each (agent, secret) pair independently", async () => {
    const entries = [
      ...backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [8, 8, 8, 8, 8, 8, 8],
        currentDayCount: 50, // alert
      }),
      ...backdatedReads({
        now: NOW,
        agent: "OpenClaw",
        secret: "stripe_secret",
        perDay: [4, 5, 4, 5, 4, 4, 5],
        currentDayCount: 5, // normal
      }),
    ];
    const audit = makeStubAuditLog(entries);
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const findings = await watcher.evaluate();
    const spikeFindings = findings.filter(
      (f) =>
        (f.severity === "warn" || f.severity === "alert") &&
        typeof f.details.secret_id === "string",
    );
    expect(spikeFindings.length).toBe(1);
    expect(spikeFindings[0]!.agent_id).toBe("Cline");
  });

  it("counts both broker_secret_read and broker_token_issued events", async () => {
    const entries: AuditEntry[] = [
      ...backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [2, 2, 2, 2, 2, 2, 2],
        currentDayCount: 0,
        operation: "broker_secret_read",
      }),
      // Layer the same number of token_issued events into the same buckets.
      ...backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [2, 2, 2, 2, 2, 2, 2],
        currentDayCount: 25, // alert when both ops counted (baseline 4)
        operation: "broker_token_issued",
      }),
    ];
    const audit = makeStubAuditLog(entries);
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const findings = await watcher.evaluate();
    const spike = findings.find((f) => f.severity === "alert");
    expect(spike).toBeDefined();
    expect(spike!.details.current_count).toBe(25);
    // Baseline counts BOTH ops in each window, so mean = 4 (2 reads + 2
    // token issues per window).
    expect(spike!.details.baseline_mean).toBe(4);
  });

  it("ignores failure-result entries (denied / expired tokens are a different signal class)", async () => {
    const entries = [
      ...backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [8, 8, 8, 8, 8, 8, 8],
        currentDayCount: 1,
      }),
      // Layer 50 failed reads on top in the current window. Should
      // NOT trigger the rate-spike path.
      ...backdatedReads({
        now: NOW,
        agent: "Cline",
        secret: "db_admin_token",
        perDay: [0, 0, 0, 0, 0, 0, 0],
        currentDayCount: 50,
        result: "failure",
      }),
    ];
    const audit = makeStubAuditLog(entries);
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    expect(await watcher.evaluate()).toEqual([]);
  });
});

// ── New-pair fingerprint path ────────────────────────────────────────────

describe("WP-V1.3-1 Phi-2 CredentialUsageWatcher: new-pair path", () => {
  it("stays silent when current window pairs all exist in baseline", async () => {
    const audit = makeStubAuditLog([
      // Historical: every day uses (A, B) together. Current uses them too.
      ...buildPairHistory({
        now: NOW,
        agent: "OpenClaw",
        secrets: ["aws_root", "stripe_secret"],
        daysBack: 7,
        currentSecretsExtra: [],
      }),
    ]);
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const newPair = (await watcher.evaluate()).find(
      (f) => typeof f.details.new_pair_count === "number",
    );
    expect(newPair).toBeUndefined();
  });

  it("fires warn when exactly one new pair surfaces in the current window", async () => {
    const audit = makeStubAuditLog(
      buildPairHistory({
        now: NOW,
        agent: "OpenClaw",
        secrets: ["aws_root"],
        daysBack: 7,
        // Current window adds a second secret -> new pair (aws_root, stripe_secret)
        currentSecretsExtra: ["stripe_secret"],
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const newPair = (await watcher.evaluate()).find(
      (f) => typeof f.details.new_pair_count === "number",
    );
    expect(newPair).toBeDefined();
    expect(newPair!.severity).toBe("warn");
    expect(newPair!.details.new_pair_count).toBe(1);
    expect(newPair!.summary).toContain("first time today");
  });

  it("escalates to alert when 3 or more new pairs surface in one window", async () => {
    // Historical: agent only ever used `aws_root` solo.
    // Current: agent uses aws_root + stripe + datadog + pagerduty in
    // the same window. That yields 6 current pairs, 0 historical pairs,
    // 6 new pairs.
    const audit = makeStubAuditLog(
      buildPairHistory({
        now: NOW,
        agent: "OpenClaw",
        secrets: ["aws_root"],
        daysBack: 7,
        currentSecretsExtra: ["stripe_secret", "datadog_key", "pagerduty"],
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const newPair = (await watcher.evaluate()).find(
      (f) => typeof f.details.new_pair_count === "number",
    );
    expect(newPair).toBeDefined();
    expect(newPair!.severity).toBe("alert");
    expect((newPair!.details.new_pair_count as number)).toBeGreaterThanOrEqual(3);
  });

  it("stays silent during warmup (fewer than 7 populated baseline windows)", async () => {
    const audit = makeStubAuditLog(
      buildPairHistory({
        now: NOW,
        agent: "OpenClaw",
        secrets: ["aws_root"],
        daysBack: 3, // only 3 baseline windows populated
        currentSecretsExtra: ["stripe_secret"],
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const newPair = (await watcher.evaluate()).find(
      (f) => typeof f.details.new_pair_count === "number",
    );
    expect(newPair).toBeUndefined();
  });

  it("requires at least 2 distinct secrets in the current window to fire", async () => {
    const audit = makeStubAuditLog(
      buildPairHistory({
        now: NOW,
        agent: "OpenClaw",
        secrets: ["aws_root", "stripe_secret"],
        daysBack: 7,
        // Current window uses just one secret -> no pairs to fingerprint
        currentSecretsExtra: [],
        currentSecretsOverride: ["aws_root"],
      }),
    );
    const watcher = new CredentialUsageWatcher();
    await watcher.subscribe(makeContext(audit));
    const newPair = (await watcher.evaluate()).find(
      (f) => typeof f.details.new_pair_count === "number",
    );
    expect(newPair).toBeUndefined();
  });
});

// ── Multi-fortress isolation ─────────────────────────────────────────────

describe("WP-V1.3-1 Phi-2 CredentialUsageWatcher: multi-fortress isolation", () => {
  it("each watcher sees only its own context's audit log", async () => {
    const fortressAEntries = backdatedReads({
      now: NOW,
      agent: "Cline",
      secret: "db_admin_token",
      perDay: [8, 8, 8, 8, 8, 8, 8],
      currentDayCount: 50,
    });
    const watcherA = new CredentialUsageWatcher();
    const watcherB = new CredentialUsageWatcher();
    await watcherA.subscribe(makeContext(makeStubAuditLog(fortressAEntries), "fortress-A"));
    await watcherB.subscribe(makeContext(makeStubAuditLog([]), "fortress-B"));
    const findingsA = await watcherA.evaluate();
    const findingsB = await watcherB.evaluate();
    expect(findingsA.some((f) => f.severity === "alert")).toBe(true);
    expect(findingsB).toEqual([]);
  });
});

// ── Phi-1 registry integration ───────────────────────────────────────────

describe("WP-V1.3-1 Phi-2 catalog + registry integration", () => {
  it("credential-usage is registered in PHI1_BASELINE_CATALOG alongside egress-volume", () => {
    const ids = PHI1_BASELINE_CATALOG.map((e) => e.sentinelId);
    expect(ids).toContain(EGRESS_VOLUME_SENTINEL_ID);
    expect(ids).toContain(CREDENTIAL_USAGE_SENTINEL_ID);
  });

  it("subscribes + unsubscribes via the Phi-1 registry surface", async () => {
    const registry = new SentinelRegistry();
    for (const entry of PHI1_BASELINE_CATALOG) registry.register(entry);

    const subscribed = await registry.subscribe(
      CREDENTIAL_USAGE_SENTINEL_ID,
      makeContext(makeStubAuditLog([])),
    );
    expect(subscribed.sentinelId).toBe(CREDENTIAL_USAGE_SENTINEL_ID);
    expect(registry.isSubscribed(CREDENTIAL_USAGE_SENTINEL_ID)).toBe(true);

    const torn = await registry.unsubscribe(CREDENTIAL_USAGE_SENTINEL_ID);
    expect(torn).toBe(true);
    expect(registry.isSubscribed(CREDENTIAL_USAGE_SENTINEL_ID)).toBe(false);
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────

interface PairHistoryOpts {
  now: Date;
  agent: string;
  /** Distinct secrets the agent has used in every baseline day. */
  secrets: string[];
  /** How many baseline days to populate. */
  daysBack: number;
  /** Extra distinct secrets to add to the CURRENT window only. */
  currentSecretsExtra: string[];
  /** Override the current window's secret set entirely. */
  currentSecretsOverride?: string[];
}

/**
 * Build an audit-log slice that exercises the pair-fingerprint path.
 * Every baseline day uses `secrets` together; the current window uses
 * `currentSecretsOverride` (if set) or `secrets + currentSecretsExtra`.
 * Two reads per (window, secret) so the rate-spike path stays well
 * below the +3 sigma trigger.
 */
function buildPairHistory(opts: PairHistoryOpts): AuditEntry[] {
  const dayMs = 24 * 60 * 60 * 1000;
  const entries: AuditEntry[] = [];
  const currentSecrets =
    opts.currentSecretsOverride ?? [...opts.secrets, ...opts.currentSecretsExtra];
  // Current window.
  for (const secret of currentSecrets) {
    for (let i = 0; i < 2; i += 1) {
      entries.push({
        timestamp: new Date(
          opts.now.getTime() - 60_000 - i * 1000 - currentSecrets.indexOf(secret) * 500,
        ).toISOString(),
        layer: "l3",
        operation: "broker_secret_read",
        identity_id: "id-1",
        result: "success",
        details: { agent: opts.agent, secret, scope: "scope" },
      });
    }
  }
  // Baseline windows.
  for (let day = 1; day <= opts.daysBack; day += 1) {
    for (const secret of opts.secrets) {
      for (let i = 0; i < 2; i += 1) {
        entries.push({
          timestamp: new Date(
            opts.now.getTime() - day * dayMs - 60_000 - i * 1000,
          ).toISOString(),
          layer: "l3",
          operation: "broker_secret_read",
          identity_id: "id-1",
          result: "success",
          details: { agent: opts.agent, secret, scope: "scope" },
        });
      }
    }
  }
  return entries;
}
