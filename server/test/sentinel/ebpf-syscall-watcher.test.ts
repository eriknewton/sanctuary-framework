/**
 * eBPF Syscall Watcher sentinel tests.
 *
 * Coverage:
 *  - Subclass instantiation and sentinel ID/description.
 *  - Stub mode: returns empty findings on non-Linux.
 *  - Mock eBPF event stream: findings emitted at correct severity.
 *  - Boundary cases: exactly at warn threshold, between warn and alert,
 *    above alert threshold.
 *  - Empty drain returns no findings.
 *  - Multiple syscall types in one tick.
 *  - Unsubscribe tears down probe loader.
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  EbpfSyscallWatcher,
  EBPF_SYSCALL_SENTINEL_ID,
  type EbpfProbeLoader,
  type EbpfSyscallEvent,
  type SyscallEventType,
} from "../../src/sentinel/sentinels/ebpf-syscall-watcher.js";
import type { SentinelContext } from "../../src/sentinel/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const FORTRESS_ID = "test-fortress";

function makeEvent(
  type: SyscallEventType,
  overrides?: Partial<EbpfSyscallEvent>,
): EbpfSyscallEvent {
  return {
    type,
    pid: 1234,
    comm: "test-proc",
    target: type === "execve" ? "/usr/bin/ls" : type === "connect" ? "10.0.0.1:443" : "/tmp/test.txt",
    timestamp_ns: BigInt(Date.now()) * 1_000_000n,
    ...overrides,
  };
}

function makeEvents(type: SyscallEventType, count: number): EbpfSyscallEvent[] {
  return Array.from({ length: count }, (_, i) =>
    makeEvent(type, { pid: 1000 + i, comm: `proc-${i}` }),
  );
}

class MockProbeLoader implements EbpfProbeLoader {
  events: EbpfSyscallEvent[] = [];
  attached = false;
  detached = false;

  async attach(): Promise<void> {
    this.attached = true;
  }
  drain(): EbpfSyscallEvent[] {
    const batch = [...this.events];
    this.events = [];
    return batch;
  }
  async detach(): Promise<void> {
    this.detached = true;
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

describe("EbpfSyscallWatcher", () => {
  let watcher: EbpfSyscallWatcher;
  let loader: MockProbeLoader;
  let ctx: SentinelContext;

  beforeEach(async () => {
    loader = new MockProbeLoader();
    watcher = new EbpfSyscallWatcher({ probeLoader: loader });
    ctx = makeContext();
    await watcher.subscribe(ctx);
  });

  it("has correct sentinel ID and description", () => {
    expect(watcher.sentinelId).toBe(EBPF_SYSCALL_SENTINEL_ID);
    expect(watcher.sentinelId).toBe("ebpf-syscall-watcher");
    expect(watcher.description).toContain("eBPF");
    expect(watcher.description).toContain("Linux");
  });

  it("attaches probe loader on subscribe", () => {
    expect(loader.attached).toBe(true);
  });

  it("returns empty findings when no events in buffer", async () => {
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("returns empty findings when event count below warn threshold", async () => {
    // Default execve warn = 50; add 30 events
    loader.events = makeEvents("execve", 30);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("returns empty findings at exactly the warn threshold", async () => {
    // Default execve warn = 50; exactly 50 should NOT fire (> not >=)
    loader.events = makeEvents("execve", 50);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("emits warn finding above warn threshold", async () => {
    // Default execve warn = 50
    loader.events = makeEvents("execve", 51);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("warn");
    expect(findings[0]!.sentinel_id).toBe(EBPF_SYSCALL_SENTINEL_ID);
    expect(findings[0]!.summary).toContain("execve");
    expect(findings[0]!.summary).toContain("51");
    expect(findings[0]!.details.syscall_type).toBe("execve");
    expect(findings[0]!.details.event_count).toBe(51);
  });

  it("emits alert finding above alert threshold", async () => {
    // Default execve alert = 200
    loader.events = makeEvents("execve", 201);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("alert");
    expect(findings[0]!.details.event_count).toBe(201);
  });

  it("emits separate findings for different syscall types", async () => {
    loader.events = [
      ...makeEvents("execve", 60),
      ...makeEvents("connect", 150),
    ];
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(2);
    const types = findings.map((f) => f.details.syscall_type).sort();
    expect(types).toEqual(["connect", "execve"]);
  });

  it("respects per-type thresholds", async () => {
    // openat warn = 500, so 100 events should not fire
    loader.events = makeEvents("openat", 100);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);

    // But 501 should
    loader.events = makeEvents("openat", 501);
    const findings2 = await watcher.evaluate();
    expect(findings2).toHaveLength(1);
    expect(findings2[0]!.details.syscall_type).toBe("openat");
  });

  it("limits evidence samples to 25 entries", async () => {
    loader.events = makeEvents("execve", 100);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    const targets = findings[0]!.details.sample_targets as string[];
    expect(targets.length).toBeLessThanOrEqual(25);
  });

  it("populates finding fields correctly", async () => {
    loader.events = makeEvents("execve", 60);
    const findings = await watcher.evaluate();
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.finding_id).toBe("");
    expect(f.fortress_id).toBe("");
    expect(f.observed_at).toBe("2026-05-18T12:00:00.000Z");
    expect(f.evidence_audit_ids).toEqual([]);
  });

  it("drains buffer on evaluate (events consumed)", async () => {
    loader.events = makeEvents("execve", 60);
    await watcher.evaluate();
    // Second evaluate should be empty (buffer drained by mock)
    const findings2 = await watcher.evaluate();
    expect(findings2).toEqual([]);
  });

  it("detaches probe loader on unsubscribe", async () => {
    await watcher.unsubscribe();
    expect(loader.detached).toBe(true);
  });

  it("accepts custom thresholds", async () => {
    const custom = new EbpfSyscallWatcher({
      probeLoader: loader,
      thresholds: { execve: { warn: 5, alert: 10 } },
    });
    await custom.subscribe(ctx);

    loader.events = makeEvents("execve", 6);
    const findings = await custom.evaluate();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("warn");

    loader.events = makeEvents("execve", 11);
    const findings2 = await custom.evaluate();
    expect(findings2).toHaveLength(1);
    expect(findings2[0]!.severity).toBe("alert");

    await custom.unsubscribe();
  });

  it("throws when evaluate called before subscribe", async () => {
    const bare = new EbpfSyscallWatcher({ probeLoader: loader });
    await expect(bare.evaluate()).rejects.toThrow("before subscribe");
  });
});

describe("EbpfSyscallWatcher stub mode", () => {
  it("returns empty findings with stub probe loader", async () => {
    // No probeLoader injected; defaults to stub
    const watcher = new EbpfSyscallWatcher();
    const ctx = makeContext();
    await watcher.subscribe(ctx);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
    await watcher.unsubscribe();
  });
});
