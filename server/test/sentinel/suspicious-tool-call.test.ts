/**
 * WP-V1.3-1 Phi-4 Suspicious-Tool-Call Detector regression suite.
 *
 * Coverage:
 *   - Layer A signature detection: large-payload truncation,
 *     URL-encoded blob, base64 chunk, shell metacharacters,
 *     novel signature.
 *   - Layer B frequency anomaly: warm-up suppression, baseline
 *     established info, +3σ warn, +6σ alert.
 *   - Layer C permission-combination novelty: single novel warn,
 *     multi-novel alert.
 *   - LLM-assist fallback: ambiguous match → classifier escalation;
 *     suspicious vs benign branch; substrate failure no-fire.
 *   - Multi-fortress isolation (per-instance state).
 *   - Registry integration (Phi-4 catalog entry registers and
 *     instantiates).
 *   - Cooperative-with-Phi-1 path (egress-volume + suspicious-tool-call
 *     evaluating side-by-side).
 *
 * Castle-walking: every test stubs the audit log via the same
 * pattern Phi-1 uses; no outbound surface is exercised.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import {
  SuspiciousToolCallDetector,
  SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
  countTruncatedValues,
  countUrlEncoded,
  longestBase64Run,
} from "../../src/sentinel/sentinels/suspicious-tool-call-detector.js";
import {
  EgressVolumeWatcher,
  PHI1_BASELINE_CATALOG,
} from "../../src/sentinel/sentinels/index.js";
import type { SentinelContext } from "../../src/sentinel/types.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";

function stubAuditLog(entries: AuditEntry[]): AuditLog {
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
        filtered = filtered.filter(
          (e) => Date.parse(e.timestamp) >= sinceMs,
        );
      }
      if (opts.layer) {
        filtered = filtered.filter((e) => e.layer === opts.layer);
      }
      if (opts.operation_type) {
        filtered = filtered.filter((e) => e.operation === opts.operation_type);
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

function gateEntry(opts: {
  ts: Date;
  operation: string;
  argsSummary?: Record<string, unknown>;
}): AuditEntry {
  return {
    timestamp: opts.ts.toISOString(),
    layer: "l2",
    operation: opts.operation,
    identity_id: "system",
    result: "success",
    details: {
      tier: 3,
      operation: opts.operation,
      args_summary: opts.argsSummary ?? {},
    },
  };
}

async function subscribe(
  detector: SuspiciousToolCallDetector,
  opts: {
    auditLog: AuditLog;
    now: () => Date;
    fortressId?: string;
    selector?: SentinelContext["substrateSelector"];
  },
): Promise<SentinelContext> {
  const ctx: SentinelContext = {
    fortressId: opts.fortressId ?? FORTRESS_A,
    auditLog: opts.auditLog,
    now: opts.now,
    ...(opts.selector ? { substrateSelector: opts.selector } : {}),
  };
  await detector.subscribe(ctx);
  return ctx;
}

const NOW = new Date("2026-05-09T12:00:00.000Z");
const dayMs = 24 * 60 * 60 * 1000;

function backfillHistorical(
  operation: string,
  perDay: number[],
  argsSummary: Record<string, unknown> = {},
): AuditEntry[] {
  const entries: AuditEntry[] = [];
  for (let day = 1; day <= perDay.length; day += 1) {
    const count = perDay[day - 1]!;
    for (let i = 0; i < count; i += 1) {
      entries.push(
        gateEntry({
          ts: new Date(NOW.getTime() - day * dayMs - 60_000 - i * 1000),
          operation,
          argsSummary,
        }),
      );
    }
  }
  return entries;
}

describe("WP-V1.3-1 Phi-4 SuspiciousToolCallDetector — Layer A signatures", () => {
  it("detects truncation burst (large-payload signal) with >=5 truncated values", async () => {
    const huge = "x".repeat(100) + "...";
    const detector = new SuspiciousToolCallDetector();
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_write",
        argsSummary: {
          a: huge,
          b: huge,
          c: huge,
          d: huge,
          e: huge,
        },
      }),
    ]);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const layerA = findings.filter((f) => f.details["layer"] === "A");
    expect(layerA.length).toBeGreaterThanOrEqual(1);
    expect(layerA[0]!.details["signatures"]).toContain("truncation_burst");
    expect(layerA[0]!.severity).toBe("warn");
  });

  it("detects URL-encoded blob signature", async () => {
    const detector = new SuspiciousToolCallDetector();
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_write",
        argsSummary: {
          payload: "%41%42%43%44%45%46%47%48%49%4a",
        },
      }),
    ]);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const blob = findings.find((f) =>
      Array.isArray(f.details["signatures"]) &&
      (f.details["signatures"] as string[]).includes("url_encoded_blob"),
    );
    expect(blob).toBeDefined();
  });

  it("detects base64-chunk signature and escalates to LLM-assist when ambiguous", async () => {
    const detector = new SuspiciousToolCallDetector();
    const longB64 =
      "aGVsbG93b3JsZGZyb21zYW5jdHVhcnlmcmFtZXdvcmtwaGk0c3VzcGljaW91cw==";
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_write",
        argsSummary: { token: longB64 },
      }),
    ]);
    let classifyCalls = 0;
    const selector = {
      invokeClassify: async () => {
        classifyCalls += 1;
        return {
          servedBy: "local",
          failureClass: null,
          body: {
            kind: "classify",
            results: [{ category: "suspicious", confidence: 0.9 }],
          },
          completedAt: NOW.toISOString(),
          latencyMs: 12,
        };
      },
    } as unknown as NonNullable<SentinelContext["substrateSelector"]>;
    await subscribe(detector, { auditLog: audit, now: () => NOW, selector });
    const findings = await detector.evaluate();
    expect(classifyCalls).toBe(1);
    const sig = findings.find(
      (f) =>
        Array.isArray(f.details["signatures"]) &&
        (f.details["signatures"] as string[]).includes("base64_chunk"),
    );
    expect(sig).toBeDefined();
    expect(sig!.details["detection_path"]).toBe("llm-assist");
  });

  it("LLM-assist benign verdict suppresses the ambiguous-match finding", async () => {
    const detector = new SuspiciousToolCallDetector();
    const longB64 =
      "aGVsbG93b3JsZGZyb21zYW5jdHVhcnlmcmFtZXdvcmtwaGk0c3VzcGljaW91cw==";
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_write",
        argsSummary: { token: longB64 },
      }),
    ]);
    const selector = {
      invokeClassify: async () => ({
        servedBy: "local",
        failureClass: null,
        body: {
          kind: "classify",
          results: [{ category: "benign", confidence: 0.95 }],
        },
        completedAt: NOW.toISOString(),
        latencyMs: 12,
      }),
    } as unknown as NonNullable<SentinelContext["substrateSelector"]>;
    await subscribe(detector, { auditLog: audit, now: () => NOW, selector });
    const findings = await detector.evaluate();
    const ambiguous = findings.find(
      (f) =>
        Array.isArray(f.details["signatures"]) &&
        (f.details["signatures"] as string[]).includes("base64_chunk"),
    );
    expect(ambiguous).toBeUndefined();
  });

  it("LLM-assist substrate failure does not fire a finding (degrade-silent)", async () => {
    const detector = new SuspiciousToolCallDetector();
    const longB64 =
      "aGVsbG93b3JsZGZyb21zYW5jdHVhcnlmcmFtZXdvcmtwaGk0c3VzcGljaW91cw==";
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_write",
        argsSummary: { token: longB64 },
      }),
    ]);
    const selector = {
      invokeClassify: async () => ({
        servedBy: "local",
        failureClass: "substrate_unavailable",
        body: { kind: "failure", message: "ollama down" },
        completedAt: NOW.toISOString(),
        latencyMs: 5,
      }),
    } as unknown as NonNullable<SentinelContext["substrateSelector"]>;
    await subscribe(detector, { auditLog: audit, now: () => NOW, selector });
    const findings = await detector.evaluate();
    const ambiguous = findings.find(
      (f) =>
        Array.isArray(f.details["signatures"]) &&
        (f.details["signatures"] as string[]).includes("base64_chunk"),
    );
    expect(ambiguous).toBeUndefined();
  });

  it("detects shell-metacharacter signature and elevates to alert severity", async () => {
    const detector = new SuspiciousToolCallDetector();
    const audit = stubAuditLog([
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:proxy_call",
        argsSummary: { cmd: "ls; cat /etc/passwd" },
      }),
    ]);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const sig = findings.find(
      (f) =>
        Array.isArray(f.details["signatures"]) &&
        (f.details["signatures"] as string[]).includes("shell_metachar"),
    );
    expect(sig).toBeDefined();
    expect(sig!.severity).toBe("alert");
  });

  it("detects novel-signature pattern when arg-key set differs from history", async () => {
    const detector = new SuspiciousToolCallDetector();
    const historical = backfillHistorical(
      "gate_allow:state_write",
      [3, 3, 3, 3, 3, 3, 3],
      { key: "k1", value: "v1" },
    );
    const novel = gateEntry({
      ts: new Date(NOW.getTime() - 60_000),
      operation: "gate_allow:state_write",
      argsSummary: { key: "k1", credential: "tok", endpoint: "https://x.io" },
    });
    const audit = stubAuditLog([...historical, novel]);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const novelF = findings.find(
      (f) =>
        Array.isArray(f.details["signatures"]) &&
        (f.details["signatures"] as string[]).includes("novel_signature"),
    );
    expect(novelF).toBeDefined();
    expect(novelF!.details["novel_signature"]).toBe(
      "credential,endpoint,key",
    );
  });
});

describe("WP-V1.3-1 Phi-4 SuspiciousToolCallDetector — Layer B frequency anomaly", () => {
  it("warm-up: under 7 baseline windows fires no warn/alert and stamps info on first cross", async () => {
    const detector = new SuspiciousToolCallDetector();
    // Only 3 days of history — below BASELINE_WINDOWS (7).
    const entries = backfillHistorical("gate_allow:state_read", [5, 5, 5]);
    // Add a current-day entry so the tool is observed at all.
    entries.push(
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_read",
      }),
    );
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const layerB = findings.filter((f) => f.details["layer"] === "B");
    // Warm-up suppresses both info and threshold findings until 7
    // baseline windows are populated.
    expect(layerB.length).toBe(0);
  });

  it("emits info on baseline-established for normal current-day volume", async () => {
    const detector = new SuspiciousToolCallDetector();
    const entries = backfillHistorical(
      "gate_allow:state_read",
      [10, 10, 10, 10, 10, 10, 10],
    );
    entries.push(
      gateEntry({
        ts: new Date(NOW.getTime() - 60_000),
        operation: "gate_allow:state_read",
      }),
    );
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const info = findings.find(
      (f) => f.details["layer"] === "B" && f.severity === "info",
    );
    expect(info).toBeDefined();
    expect(info!.details["tool"]).toBe("state_read");
  });

  it("fires +3σ warn when current-day count crosses baseline mean + 3σ", async () => {
    const detector = new SuspiciousToolCallDetector();
    const entries = backfillHistorical(
      "gate_allow:state_read",
      [10, 10, 10, 10, 10, 10, 10],
    );
    // Current day spike: 100 calls (3σ ≈ 0 since stddev=0; >mean
    // alone is enough — but with stddev=0 the threshold collapses
    // to just `> mean` so 11+ fires warn).
    for (let i = 0; i < 100; i += 1) {
      entries.push(
        gateEntry({
          ts: new Date(NOW.getTime() - 60_000 - i * 1000),
          operation: "gate_allow:state_read",
        }),
      );
    }
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    // First evaluate primes baselineEstablished.
    await detector.evaluate();
    const findings = await detector.evaluate();
    const anomaly = findings.find(
      (f) =>
        f.details["layer"] === "B" &&
        (f.severity === "warn" || f.severity === "alert"),
    );
    expect(anomaly).toBeDefined();
    // 100 / 10 = 10x — comfortably above +3σ for any reasonable
    // stddev; with stddev=0 the threshold is just >mean.
    expect(anomaly!.details["current_count"]).toBe(100);
  });

  it("escalates to alert on +6σ breach", async () => {
    const detector = new SuspiciousToolCallDetector();
    // Variable historical baseline so stddev > 0 and thresholds
    // are meaningful.
    const entries = backfillHistorical(
      "gate_allow:state_read",
      [10, 12, 8, 11, 9, 10, 11],
    );
    // mean=10.14, stddev≈1.25, alert threshold ≈ 17.6.
    // Current day: 50 → comfortably above +6σ ≈ 17.6.
    for (let i = 0; i < 50; i += 1) {
      entries.push(
        gateEntry({
          ts: new Date(NOW.getTime() - 60_000 - i * 1000),
          operation: "gate_allow:state_read",
        }),
      );
    }
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    await detector.evaluate();
    const findings = await detector.evaluate();
    const alert = findings.find(
      (f) => f.details["layer"] === "B" && f.severity === "alert",
    );
    expect(alert).toBeDefined();
    expect(alert!.details["sigma_threshold"]).toBe(6);
  });
});

describe("WP-V1.3-1 Phi-4 SuspiciousToolCallDetector — Layer C combination novelty", () => {
  it("fires warn on first novel tool combination", async () => {
    const detector = new SuspiciousToolCallDetector();
    const taskTs = new Date(NOW.getTime() - 60_000);
    const entries: AuditEntry[] = [
      gateEntry({
        ts: taskTs,
        operation: "gate_allow:state_read",
      }),
      gateEntry({
        ts: new Date(taskTs.getTime() + 5_000),
        operation: "gate_allow_proxy:network_post",
      }),
    ];
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const novel = findings.find(
      (f) => f.details["layer"] === "C" && f.severity === "warn",
    );
    expect(novel).toBeDefined();
    expect((novel!.details["tools"] as string[]).sort()).toEqual([
      "network_post",
      "state_read",
    ]);
  });

  it("aggregates 2+ novel combinations within 24h into an alert", async () => {
    const detector = new SuspiciousToolCallDetector();
    const taskATs = new Date(NOW.getTime() - 4 * 60 * 60 * 1000);
    const taskBTs = new Date(NOW.getTime() - 60 * 1000);
    const entries: AuditEntry[] = [
      gateEntry({ ts: taskATs, operation: "gate_allow:state_read" }),
      gateEntry({
        ts: new Date(taskATs.getTime() + 5_000),
        operation: "gate_allow_proxy:network_post",
      }),
      gateEntry({ ts: taskBTs, operation: "gate_allow:state_write" }),
      gateEntry({
        ts: new Date(taskBTs.getTime() + 5_000),
        operation: "gate_allow:credential_read",
      }),
    ];
    const audit = stubAuditLog(entries);
    await subscribe(detector, { auditLog: audit, now: () => NOW });
    const findings = await detector.evaluate();
    const alert = findings.find(
      (f) => f.details["layer"] === "C" && f.severity === "alert",
    );
    expect(alert).toBeDefined();
    expect(
      (alert!.details["novel_combinations"] as string[]).length,
    ).toBeGreaterThanOrEqual(2);
  });
});

describe("WP-V1.3-1 Phi-4 SuspiciousToolCallDetector — registry + isolation", () => {
  it("registers in the Phi-1 baseline catalog as a separate entry", () => {
    const ids = PHI1_BASELINE_CATALOG.map((e) => e.sentinelId);
    expect(ids).toContain(SUSPICIOUS_TOOL_CALL_SENTINEL_ID);
  });

  it("subscribes via the registry and produces an instance from the catalog factory", async () => {
    const registry = new SentinelRegistry();
    for (const e of PHI1_BASELINE_CATALOG) registry.register(e);
    const ctx: SentinelContext = {
      fortressId: FORTRESS_A,
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      now: () => NOW,
    };
    const sentinel = await registry.subscribe(
      SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
      ctx,
    );
    expect(sentinel.sentinelId).toBe(SUSPICIOUS_TOOL_CALL_SENTINEL_ID);
  });

  it("multi-fortress isolation: separate detector instances do not share memo state", async () => {
    const detectorA = new SuspiciousToolCallDetector();
    const detectorB = new SuspiciousToolCallDetector();
    const taskTs = new Date(NOW.getTime() - 60_000);
    const sharedEntries: AuditEntry[] = [
      gateEntry({ ts: taskTs, operation: "gate_allow:state_read" }),
      gateEntry({
        ts: new Date(taskTs.getTime() + 5_000),
        operation: "gate_allow_proxy:network_post",
      }),
    ];
    const auditA = stubAuditLog(sharedEntries);
    const auditB = stubAuditLog(sharedEntries);
    await subscribe(detectorA, {
      auditLog: auditA,
      now: () => NOW,
      fortressId: FORTRESS_A,
    });
    await subscribe(detectorB, {
      auditLog: auditB,
      now: () => NOW,
      fortressId: FORTRESS_B,
    });
    const findingsA = await detectorA.evaluate();
    const findingsB = await detectorB.evaluate();
    // Both fortresses should independently fire on the novel
    // combination — no cross-contamination of the
    // `knownCombinations` memo.
    expect(
      findingsA.find(
        (f) => f.details["layer"] === "C" && f.severity === "warn",
      ),
    ).toBeDefined();
    expect(
      findingsB.find(
        (f) => f.details["layer"] === "C" && f.severity === "warn",
      ),
    ).toBeDefined();
  });

  it("cooperative-with-Phi-1: egress watcher and suspicious-tool-call evaluate side-by-side without interference", async () => {
    const sus = new SuspiciousToolCallDetector();
    const egress = new EgressVolumeWatcher();
    // Egress watcher reads `proxy_call:*`; this detector reads
    // `gate_*:*`. They observe disjoint audit-op subsets, so
    // running them on the same log must not produce overlapping
    // findings or cross-state.
    const taskTs = new Date(NOW.getTime() - 60_000);
    const entries: AuditEntry[] = [
      gateEntry({ ts: taskTs, operation: "gate_allow:state_read" }),
      gateEntry({
        ts: new Date(taskTs.getTime() + 5_000),
        operation: "gate_allow_proxy:network_post",
      }),
      {
        timestamp: taskTs.toISOString(),
        layer: "l2",
        operation: "proxy_call:upstream_a",
        identity_id: "system",
        result: "success",
        details: { server: "api.example.com", latency_ms: 100 },
      },
    ];
    const audit = stubAuditLog(entries);
    await subscribe(sus, { auditLog: audit, now: () => NOW });
    await egress.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      now: () => NOW,
    });
    const susFindings = await sus.evaluate();
    const egressFindings = await egress.evaluate();
    expect(susFindings.every((f) => f.sentinel_id === SUSPICIOUS_TOOL_CALL_SENTINEL_ID)).toBe(true);
    // Egress watcher with only one historical day cannot establish
    // its baseline; it must remain quiet rather than fire a
    // false-positive against suspicious-tool-call.
    expect(egressFindings.length).toBe(0);
  });
});

describe("WP-V1.3-1 Phi-4 SuspiciousToolCallDetector — pure helpers", () => {
  it("countTruncatedValues counts only string values ending with '...'", () => {
    expect(
      countTruncatedValues({
        a: "short",
        b: "trunc...",
        c: 42,
        d: "another...",
      }),
    ).toBe(2);
  });

  it("countUrlEncoded counts %XX sequences and longestBase64Run finds the longest contiguous run", () => {
    expect(countUrlEncoded("%41%42%43 hello %44")).toBe(4);
    expect(longestBase64Run("hello aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8=")).toBeGreaterThanOrEqual(40);
    expect(longestBase64Run("hello world")).toBe(0);
  });
});
