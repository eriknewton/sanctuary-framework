/**
 * Hermetic tests for the streaming enforcement-export consumer + durable cursor.
 *
 * NEVER touches a real ~/.sanctuary, a real filesystem cursor, or a real network:
 * the verified-chain source is a fake array feeder, the cursor is in-memory, and
 * the sink's fetch is always a mock. The load-bearing properties tested here:
 *   1. The durable cursor RESUMES after a simulated mid-run crash: no gap, and
 *      no double-send of already-delivered batches.
 *   2. Retry RETRIES then FAILS CLOSED: it audits a refusal per attempt + a
 *      distinct retry-exhausted op, re-throws, never advances the cursor, never
 *      silently drops, and never sends anything but the mapped metadata.
 */

import { describe, expect, it, vi } from "vitest";

import type { AuditEntry } from "../../../src/operational/audit-log.js";
import {
  EnforcementExporter,
  EnforcementExportStreamer,
  ENFORCEMENT_EVENT_SCHEMA,
  ENFORCEMENT_EXPORT_CURSOR_ADVANCED,
  ENFORCEMENT_EXPORT_EMITTED,
  ENFORCEMENT_EXPORT_REFUSED,
  ENFORCEMENT_EXPORT_RETRY_EXHAUSTED,
  EXPORT_CURSOR_START,
  type EnforcementExportConfig,
  type ExportApprover,
  type ExportAudit,
  type ExportCursorStore,
  type VerifiedChainSource,
} from "../../../src/castle-wall/export/index.js";

// ── Test doubles ──────────────────────────────────────────────────────────────

/** An in-memory durable cursor. */
class MemoryCursorStore implements ExportCursorStore {
  constructor(public value: number = EXPORT_CURSOR_START) {}
  async read(): Promise<number> {
    return this.value;
  }
  async write(sequence: number): Promise<void> {
    this.value = sequence;
  }
}

/** A verified-chain source that feeds a fixed array of chained entries. */
function chainSource(items: Array<{ sequence: number; entry: AuditEntry }>): VerifiedChainSource {
  return {
    async streamVerifiedChain(consumer) {
      for (const item of items) consumer.onEntry(item);
    },
  };
}

function egressDeny(seq: number, host: string, extra: Record<string, unknown> = {}): {
  sequence: number;
  entry: AuditEntry;
} {
  return {
    sequence: seq,
    entry: {
      timestamp: `2026-07-10T00:00:0${seq}.000Z`,
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "system",
      result: "success",
      details: { destination: { host, port: 443, protocol: "tcp" }, rule_id: `rule-${seq}`, ...extra },
    },
  };
}

/** A non-forwarded (dropped) entry, to prove the cursor advances past a tail. */
function droppedEntry(seq: number): { sequence: number; entry: AuditEntry } {
  return {
    sequence: seq,
    entry: {
      timestamp: `2026-07-10T00:00:0${seq}.000Z`,
      layer: "l1",
      operation: "filter_started",
      identity_id: "system",
      result: "success",
      details: { pid: 1000 + seq },
    },
  };
}

const alwaysApprove: ExportApprover = async () => ({ allowed: true });
const noSleep = async (): Promise<void> => {};

async function enabledFileExporter(
  lines: string[],
  audits: Array<{ op: string; result: string; details: Record<string, unknown> }>,
): Promise<{ exporter: EnforcementExporter; audit: ExportAudit }> {
  const audit: ExportAudit = async (op, details, result) => {
    audits.push({ op, result, details });
  };
  const exporter = new EnforcementExporter({
    config: { sink: "file", enabled: false },
    approve: alwaysApprove,
    audit,
    fileWriter: (line) => {
      lines.push(line);
    },
  });
  await exporter.enable();
  return { exporter, audit };
}

// ── 1. Durable cursor: resume after a simulated crash (no gap, no double-send) ──

describe("durable cursor resumes after a mid-run crash", () => {
  it("delivers each event exactly once across a crash + restart (no gap, no double-send)", async () => {
    // Chain: four forwardable egress denies at sequences 0..3.
    const chain = [
      egressDeny(0, "a.example"),
      egressDeny(1, "b.example"),
      egressDeny(2, "c.example"),
      egressDeny(3, "d.example"),
    ];
    const cursor = new MemoryCursorStore();

    // ── Run 1: the second batch "crashes" (sink throws), so only batch 1 lands.
    const run1Lines: string[] = [];
    const run1Audits: Array<{ op: string; result: string; details: Record<string, unknown> }> = [];
    let deliverCall = 0;
    const audit1: ExportAudit = async (op, details, result) => {
      run1Audits.push({ op, result, details });
    };
    // A file-ish exporter whose sink throws on the SECOND deliver (batch 2).
    const crashingExporter = new EnforcementExporter({
      config: { sink: "file", enabled: false },
      approve: alwaysApprove,
      audit: audit1,
      fileWriter: (line) => {
        run1Lines.push(line);
      },
    });
    await crashingExporter.enable();
    const originalExport = crashingExporter.exportEvents.bind(crashingExporter);
    vi.spyOn(crashingExporter, "exportEvents").mockImplementation(async (events) => {
      deliverCall += 1;
      if (deliverCall === 2) throw new Error("simulated crash mid-run");
      return originalExport(events);
    });

    const streamer1 = new EnforcementExportStreamer({
      exporter: crashingExporter,
      cursor,
      audit: audit1,
      batchSize: 2,
      maxRetries: 0, // fail fast on the crash
      sleep: noSleep,
    });

    await expect(streamer1.runOnce(chainSource(chain))).rejects.toThrow(/simulated crash/);
    // Batch 1 (seq 0,1) landed; cursor advanced to 1. Batch 2 (seq 2,3) did NOT.
    expect(run1Lines).toHaveLength(2);
    expect(cursor.value).toBe(1);
    const run1Hosts = run1Lines.map((l) => JSON.parse(l).destination_host);
    expect(run1Hosts).toEqual(["a.example", "b.example"]);

    // ── Run 2: restart. Same cursor (1). The sink now succeeds.
    const run2Lines: string[] = [];
    const run2Audits: Array<{ op: string; result: string; details: Record<string, unknown> }> = [];
    const { exporter: healthyExporter } = await enabledFileExporter(run2Lines, run2Audits);
    const streamer2 = new EnforcementExportStreamer({
      exporter: healthyExporter,
      cursor,
      audit: async (op, details, result) => {
        run2Audits.push({ op, result, details });
      },
      batchSize: 2,
      sleep: noSleep,
    });
    const outcome = await streamer2.runOnce(chainSource(chain));

    // Run 2 delivered ONLY seq 2,3 (no re-send of 0,1), and both landed (no gap).
    const run2Hosts = run2Lines.map((l) => JSON.parse(l).destination_host);
    expect(run2Hosts).toEqual(["c.example", "d.example"]);
    expect(outcome.fromCursor).toBe(1);
    expect(outcome.toCursor).toBe(3);
    expect(cursor.value).toBe(3);

    // Union across both runs = each event exactly once.
    expect([...run1Hosts, ...run2Hosts].sort()).toEqual(
      ["a.example", "b.example", "c.example", "d.example"].sort(),
    );
  });

  it("advances the cursor past a non-forwardable tail so it is not re-scanned", async () => {
    const chain = [egressDeny(0, "a.example"), droppedEntry(1), droppedEntry(2)];
    const cursor = new MemoryCursorStore();
    const lines: string[] = [];
    const audits: Array<{ op: string; result: string; details: Record<string, unknown> }> = [];
    const { exporter } = await enabledFileExporter(lines, audits);
    const streamer = new EnforcementExportStreamer({
      exporter,
      cursor,
      audit: async (op, details, result) => {
        audits.push({ op, result, details });
      },
      batchSize: 10,
      sleep: noSleep,
    });
    const outcome = await streamer.runOnce(chainSource(chain));
    expect(outcome.delivered).toBe(1);
    // Cursor lands on the highest SCANNED sequence (2), not just the last delivered (0).
    expect(cursor.value).toBe(2);
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_CURSOR_ADVANCED)).toBe(true);

    // A second run over the same chain forwards nothing (all <= cursor).
    const outcome2 = await streamer.runOnce(chainSource(chain));
    expect(outcome2.delivered).toBe(0);
    expect(lines).toHaveLength(1);
  });

  it("re-running a fully-caught-up chain delivers nothing (no re-send storm)", async () => {
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example")];
    const cursor = new MemoryCursorStore();
    const lines: string[] = [];
    const audits: Array<{ op: string; result: string; details: Record<string, unknown> }> = [];
    const { exporter } = await enabledFileExporter(lines, audits);
    const streamer = new EnforcementExportStreamer({
      exporter,
      cursor,
      audit: async (op, details, result) => {
        audits.push({ op, result, details });
      },
      sleep: noSleep,
    });
    await streamer.runOnce(chainSource(chain));
    expect(lines).toHaveLength(2);
    await streamer.runOnce(chainSource(chain));
    expect(lines).toHaveLength(2); // unchanged: nothing re-sent
  });
});

// ── 2. Retry then fail closed (never drop, never degrade toward non-metadata) ──

describe("bounded retry then fail closed", () => {
  const httpConfig: EnforcementExportConfig = {
    sink: "http",
    enabled: true,
    destination_url: "https://collector.example/xsiam",
  };

  it("retries a transient sink failure the budgeted number of times, then re-throws", async () => {
    const SECRET = "sk-secret-that-must-never-leave";
    const bodies: string[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      bodies.push(String(init.body));
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const audits: Array<{ op: string; result: string }> = [];
    const audit: ExportAudit = async (op, _details, result) => {
      audits.push({ op, result });
    };
    const exporter = new EnforcementExporter({
      config: httpConfig,
      approve: alwaysApprove,
      audit,
      fetchImpl,
    });
    await exporter.enable();

    const cursor = new MemoryCursorStore();
    const streamer = new EnforcementExportStreamer({
      exporter,
      cursor,
      audit,
      maxRetries: 2, // 3 total attempts
      sleep: noSleep,
    });

    const chain = [egressDeny(0, "evil.example", { api_key: SECRET, reason: `threshold; ${SECRET}` })];
    await expect(streamer.runOnce(chainSource(chain))).rejects.toThrow(/delivery failed|ECONNREFUSED/);

    // Exactly maxRetries+1 attempts were made.
    expect(bodies).toHaveLength(3);
    // Each failed attempt audited a refusal; the exhaustion audited the distinct op.
    expect(audits.filter((a) => a.op === ENFORCEMENT_EXPORT_REFUSED).length).toBe(3);
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_RETRY_EXHAUSTED && a.result === "failure")).toBe(
      true,
    );
    // Never reported success.
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_EMITTED)).toBe(false);
    // Cursor NEVER advanced: the batch is re-attempted next run (no gap, no drop).
    expect(cursor.value).toBe(EXPORT_CURSOR_START);
    // Every attempt carried ONLY mapped metadata; the planted secret never left.
    for (const body of bodies) {
      expect(body).not.toContain(SECRET);
      const parsed = JSON.parse(body);
      expect(parsed.schema).toBe(ENFORCEMENT_EVENT_SCHEMA);
      for (const ev of parsed.events) expect(ev.schema).toBe(ENFORCEMENT_EVENT_SCHEMA);
    }
  });

  it("delivers on a transient failure that recovers within the retry budget", async () => {
    let attempt = 0;
    const fetchImpl = (async () => {
      attempt += 1;
      if (attempt < 3) throw new Error("ECONNREFUSED");
      return new Response(null, { status: 200 });
    }) as unknown as typeof fetch;
    const audits: Array<{ op: string; result: string }> = [];
    const audit: ExportAudit = async (op, _details, result) => {
      audits.push({ op, result });
    };
    const exporter = new EnforcementExporter({ config: httpConfig, approve: alwaysApprove, audit, fetchImpl });
    await exporter.enable();
    const cursor = new MemoryCursorStore();
    const streamer = new EnforcementExportStreamer({
      exporter,
      cursor,
      audit,
      maxRetries: 3,
      sleep: noSleep,
    });
    const outcome = await streamer.runOnce(chainSource([egressDeny(0, "a.example")]));
    expect(outcome.delivered).toBe(1);
    expect(attempt).toBe(3); // failed twice, succeeded on the third
    expect(cursor.value).toBe(0);
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_EMITTED && a.result === "success")).toBe(true);
    expect(audits.some((a) => a.op === ENFORCEMENT_EXPORT_RETRY_EXHAUSTED)).toBe(false);
  });
});
