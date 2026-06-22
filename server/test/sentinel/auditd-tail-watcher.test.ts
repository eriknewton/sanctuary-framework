/**
 * auditd-tail cross-platform observation sentinel tests.
 *
 * Coverage:
 *  - Subclass instantiation and sentinel ID/description.
 *  - Stub mode: returns empty findings when tailer is unavailable.
 *  - Mock tailer: findings emitted at correct severity for each event type.
 *  - Boundary cases: at/below/above warn and alert thresholds.
 *  - Empty drain returns no findings.
 *  - Multiple event types in one tick.
 *  - Normalized shape with cross-platform fields.
 *  - No duplication assertion (finding shape compatible with eBPF sentinel).
 *  - Unsubscribe tears down tailer.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  AuditdTailWatcher,
  AUDITD_TAIL_SENTINEL_ID,
  type AuditLogTailer,
  type PlatformAuditEvent,
} from "../../src/sentinel/sentinels/auditd-tail-watcher.js";
import type { SentinelContext } from "../../src/sentinel/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const FORTRESS_ID = "test-fortress";

function makeEvent(
  type: PlatformAuditEvent["type"],
  overrides?: Partial<PlatformAuditEvent>,
): PlatformAuditEvent {
  return {
    type,
    raw: `type=${type.toUpperCase()} msg=audit(1716062400.000:1234)`,
    pid: 5678,
    comm: "test-proc",
    target: type === "execve" ? "/usr/bin/ls" : type === "connect" ? "10.0.0.1:443" : "/tmp/test.txt",
    timestamp: new Date("2026-05-18T12:00:00Z"),
    ...overrides,
  };
}

function makeEvents(type: PlatformAuditEvent["type"], count: number): PlatformAuditEvent[] {
  return Array.from({ length: count }, (_, i) =>
    makeEvent(type, { pid: 2000 + i, comm: `proc-${i}` }),
  );
}

class MockAuditLogTailer implements AuditLogTailer {
  events: PlatformAuditEvent[] = [];
  started = false;
  stopped = false;

  async start(): Promise<void> {
    this.started = true;
  }
  drain(): PlatformAuditEvent[] {
    const batch = [...this.events];
    this.events = [];
    return batch;
  }
  async stop(): Promise<void> {
    this.stopped = true;
  }
}

function makeContext(nowDate?: Date): SentinelContext {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const now = nowDate ?? new Date("2026-05-18T12:00:00Z");
  return {
    fortressId: FORTRESS_ID,
    auditLog,
    now: () => now,
  };
}

describe("AuditdTailWatcher", () => {
  let watcher: AuditdTailWatcher;
  let tailer: MockAuditLogTailer;
  let ctx: SentinelContext;

  beforeEach(async () => {
    tailer = new MockAuditLogTailer();
    watcher = new AuditdTailWatcher({ tailer });
    ctx = makeContext();
    await watcher.subscribe(ctx);
  });

  it("has correct sentinel ID and description", () => {
    expect(watcher.sentinelId).toBe(AUDITD_TAIL_SENTINEL_ID);
    expect(watcher.sentinelId).toBe("auditd-tail-watcher");
    expect(watcher.description).toContain("audit log");
    expect(watcher.description).toContain("cross-platform");
  });

  it("starts tailer on subscribe", () => {
    expect(tailer.started).toBe(true);
  });

  it("returns empty findings when no events", async () => {
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("returns empty findings below warn threshold", async () => {
    // Default execve warn = 50
    tailer.events = makeEvents("execve", 30);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("returns empty findings at exactly the warn threshold", async () => {
    tailer.events = makeEvents("execve", 50);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("emits warn finding above warn threshold", async () => {
    tailer.events = makeEvents("execve", 51);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("warn");
    expect(findings[0]!.sentinel_id).toBe(AUDITD_TAIL_SENTINEL_ID);
    expect(findings[0]!.summary).toContain("execve");
    expect(findings[0]!.summary).toContain("51");
    expect(findings[0]!.details.event_type).toBe("execve");
    expect(findings[0]!.details.event_count).toBe(51);
  });

  it("emits alert finding above alert threshold", async () => {
    tailer.events = makeEvents("execve", 201);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("alert");
    expect(findings[0]!.details.event_count).toBe(201);
  });

  it("emits separate findings for different event types", async () => {
    tailer.events = [
      ...makeEvents("execve", 60),
      ...makeEvents("connect", 150),
    ];
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(2);
    const types = findings.map((f) => f.details.event_type).sort();
    expect(types).toEqual(["connect", "execve"]);
  });

  it("respects per-type thresholds", async () => {
    // open warn = 500, so 100 should not fire
    tailer.events = makeEvents("open", 100);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);

    // 501 should fire
    tailer.events = makeEvents("open", 501);
    const findings2 = await watcher.evaluate();
    expect(findings2).toHaveLength(1);
    expect(findings2[0]!.details.event_type).toBe("open");
  });

  it("handles auth event type", async () => {
    // auth warn = 20
    tailer.events = makeEvents("auth", 25);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.details.event_type).toBe("auth");
    expect(findings[0]!.severity).toBe("warn");
  });

  it("limits evidence samples to 25 entries", async () => {
    tailer.events = makeEvents("execve", 100);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    const targets = findings[0]!.details.sample_targets as string[];
    expect(targets.length).toBeLessThanOrEqual(25);
  });

  it("populates finding fields correctly", async () => {
    tailer.events = makeEvents("execve", 60);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.finding_id).toBe("");
    expect(f.fortress_id).toBe("");
    expect(f.observed_at).toBe("2026-05-18T12:00:00.000Z");
    expect(f.evidence_audit_ids).toEqual([]);
    expect(f.details.platform).toBe(process.platform);
  });

  it("drains buffer on evaluate (events consumed)", async () => {
    tailer.events = makeEvents("execve", 60);
    await watcher.evaluate();
    const findings2 = await watcher.evaluate();
    expect(findings2).toEqual([]);
  });

  it("stops tailer on unsubscribe", async () => {
    await watcher.unsubscribe();
    expect(tailer.stopped).toBe(true);
  });

  it("accepts custom thresholds", async () => {
    const custom = new AuditdTailWatcher({
      tailer,
      thresholds: { execve: { warn: 5, alert: 10 } },
    });
    await custom.subscribe(ctx);

    tailer.events = makeEvents("execve", 6);
    const findings = await custom.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("warn");

    tailer.events = makeEvents("execve", 11);
    const findings2 = await custom.evaluate();
    expect(findings2).toHaveLength(1);
    expect(findings2[0]!.severity).toBe("alert");

    await custom.unsubscribe();
  });

  it("throws when evaluate called before subscribe", async () => {
    const bare = new AuditdTailWatcher({ tailer });
    await expect(bare.evaluate()).rejects.toThrow("before subscribe");
  });

  it("finding shape is compatible with eBPF sentinel findings", async () => {
    tailer.events = makeEvents("execve", 60);
    const findings = await watcher.evaluate();
    const f = findings[0]!;
    // Same SentinelFinding fields as eBPF sentinel
    expect(f).toHaveProperty("finding_id");
    expect(f).toHaveProperty("sentinel_id");
    expect(f).toHaveProperty("severity");
    expect(f).toHaveProperty("summary");
    expect(f).toHaveProperty("details");
    expect(f).toHaveProperty("observed_at");
    expect(f).toHaveProperty("evidence_audit_ids");
    expect(f).toHaveProperty("fortress_id");
  });

  it("handles events with missing optional fields", async () => {
    tailer.events = Array.from({ length: 60 }, () => ({
      type: "execve" as const,
      raw: "type=EXECVE msg=audit(...)",
      timestamp: new Date("2026-05-18T12:00:00Z"),
      // No pid, comm, or target
    }));
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.details.sample_targets).toEqual([]);
    expect(findings[0]!.details.sample_pids).toEqual([]);
    expect(findings[0]!.details.sample_comms).toEqual([]);
  });
});

describe("AuditdTailWatcher stub mode", () => {
  it("returns empty findings with stub tailer", async () => {
    const watcher = new AuditdTailWatcher();
    const ctx = makeContext();
    await watcher.subscribe(ctx);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
    await watcher.unsubscribe();
  });
});
