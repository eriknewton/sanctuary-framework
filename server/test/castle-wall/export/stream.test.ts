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
import { ed25519 } from "@noble/curves/ed25519";

import type { AuditEntry } from "../../../src/operational/audit-log.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import {
  EnforcementExporter,
  EnforcementExportStreamer,
  ENFORCEMENT_EVENT_SCHEMA,
  ENFORCEMENT_EXPORT_CURSOR_ADVANCED,
  ENFORCEMENT_EXPORT_CURSOR_RESET,
  ENFORCEMENT_EXPORT_EMITTED,
  ENFORCEMENT_EXPORT_REFUSED,
  ENFORCEMENT_EXPORT_RETRY_EXHAUSTED,
  EXPORT_CURSOR_START,
  EXPORT_CURSOR_START_STATE,
  type EnforcementExportConfig,
  type ExportApprover,
  type ExportAudit,
  type ExportCursorReadResult,
  type ExportCursorReset,
  type ExportCursorState,
  type ExportCursorStore,
  type VerifiedChainSource,
} from "../../../src/castle-wall/export/index.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";

// ── Test doubles ──────────────────────────────────────────────────────────────

const PRODUCER_PRIV = ed25519.utils.randomPrivateKey();
const PRODUCER_PUB_B64 = toBase64url(ed25519.getPublicKey(PRODUCER_PRIV));
const SIGNED_AT_MS = 1_777_777_777_777;
const SUBJECT_FORTRESS_ID = "fortress:test";
const CLAUDE_AGENT_SUBJECT = `${SUBJECT_FORTRESS_ID}/uid-503`;
const SIGNED_MAP_OPTIONS = {
  pinnedProducerKeyB64url: PRODUCER_PUB_B64,
  subjectFortressId: SUBJECT_FORTRESS_ID,
};

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function withProducerSignature(entry: AuditEntry, identityId: string): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 31;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    PRODUCER_PRIV,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

/**
 * A deterministic synthetic chain hash for a sequence. The fake chain is
 * deterministic per sequence, so a re-run reads the SAME hash at the cursor and
 * the streamer's chain-identity binding passes (as a real un-mutated chain would).
 */
function chainHash(sequence: number): string {
  return `eh-${sequence}`;
}

/**
 * An in-memory, authenticated-shaped durable cursor. `read()` returns the
 * `{ state, reset }` contract; set `pendingReset` to simulate a store-level
 * DISCARD (the store always resets `state` to the start sentinel in that case).
 */
class MemoryCursorStore implements ExportCursorStore {
  state: ExportCursorState;
  pendingReset: ExportCursorReset | null = null;
  constructor(sequence: number = EXPORT_CURSOR_START, entryHash: string | null = null) {
    this.state = { sequence, entryHash };
  }
  /** Convenience: the persisted sequence (mirrors the pre-auth `value` field). */
  get value(): number {
    return this.state.sequence;
  }
  async read(): Promise<ExportCursorReadResult> {
    if (this.pendingReset) {
      return { state: { ...EXPORT_CURSOR_START_STATE }, reset: this.pendingReset };
    }
    return { state: { ...this.state }, reset: null };
  }
  async write(state: ExportCursorState): Promise<void> {
    this.state = { ...state };
  }
}

/** A verified-chain source that feeds a fixed array of chained entries. */
function chainSource(items: Array<{ sequence: number; entry: AuditEntry }>): VerifiedChainSource {
  return {
    async streamVerifiedChain(consumer) {
      for (const item of items) {
        consumer.onEntry({ sequence: item.sequence, entry_hash: chainHash(item.sequence), entry: item.entry });
      }
    },
  };
}

function egressDeny(seq: number, host: string, extra: Record<string, unknown> = {}): {
  sequence: number;
  entry: AuditEntry;
} {
  const entry: AuditEntry = {
    timestamp: `2026-07-10T00:00:0${seq}.000Z`,
    layer: "l1",
    operation: "egress_blocked",
    identity_id: CLAUDE_AGENT_SUBJECT,
    result: "failure",
    details: { destination: { host, port: 443, protocol: "tcp" }, rule_id: `rule-${seq}`, ...extra },
  };
  return {
    sequence: seq,
    entry: withProducerSignature(entry, CLAUDE_AGENT_SUBJECT),
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
      mapOptions: SIGNED_MAP_OPTIONS,
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
      mapOptions: SIGNED_MAP_OPTIONS,
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
      mapOptions: SIGNED_MAP_OPTIONS,
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
      mapOptions: SIGNED_MAP_OPTIONS,
      sleep: noSleep,
    });
    await streamer.runOnce(chainSource(chain));
    expect(lines).toHaveLength(2);
    await streamer.runOnce(chainSource(chain));
    expect(lines).toHaveLength(2); // unchanged: nothing re-sent
  });
});

// ── 1b. Cursor authentication / head-clamp / identity binding: fail LOUD, ───────
//        never a silent zero-forward, never a skip (sweep fix 1 security carve-out).

describe("cursor tamper defenses: refuse-or-reset LOUD, never silently blind", () => {
  /** Build an armed file exporter + a streamer wired to capture audits + warns. */
  async function armed(cursor: MemoryCursorStore): Promise<{
    streamer: EnforcementExportStreamer;
    lines: string[];
    audits: Array<{ op: string; result: string; details: Record<string, unknown> }>;
    warns: string[];
  }> {
    const lines: string[] = [];
    const audits: Array<{ op: string; result: string; details: Record<string, unknown> }> = [];
    const warns: string[] = [];
    const { exporter } = await enabledFileExporter(lines, audits);
    const streamer = new EnforcementExportStreamer({
      exporter,
      cursor,
      audit: async (op, details, result) => {
        audits.push({ op, result, details });
      },
      warn: (m) => warns.push(m),
      batchSize: 10,
      mapOptions: SIGNED_MAP_OPTIONS,
      sleep: noSleep,
    });
    return { streamer, lines, audits, warns };
  }

  const resetAudits = (
    audits: Array<{ op: string; result: string; details: Record<string, unknown> }>,
  ) => audits.filter((a) => a.op === ENFORCEMENT_EXPORT_CURSOR_RESET);

  it("a poisoned HIGH cursor (above the chain head) is RESET loud + re-scans; NEVER delivered:0 (the headline)", async () => {
    // The exact attack: a valid-shaped cursor far above the real chain head. The
    // pre-fix bug forwarded 0 events, advanced nothing, and emitted NOTHING.
    const cursor = new MemoryCursorStore(999999999, "eh-999999999");
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example")];
    const { streamer, lines, audits, warns } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    // NOT a silent zero-forward: the whole surviving chain was re-scanned + sent.
    expect(outcome.delivered).toBe(2);
    expect(lines.map((l) => JSON.parse(l).destination_host)).toEqual(["a.example", "b.example"]);
    // LOUD on BOTH channels: an audit record + a stderr warning naming the reason.
    const resets = resetAudits(audits);
    expect(resets).toHaveLength(1);
    expect(resets[0]!.result).toBe("failure");
    expect(resets[0]!.details.reason).toBe("cursor_above_chain_head");
    expect(warns.some((w) => w.includes("cursor_above_chain_head"))).toBe(true);
    // The cursor self-heals to a valid authenticated position bound to the head.
    expect(cursor.state).toEqual({ sequence: 1, entryHash: "eh-1" });
  });

  it("a store-level DISCARD (bad MAC / unauthenticated) is surfaced LOUD, then re-scans from start", async () => {
    const cursor = new MemoryCursorStore();
    cursor.pendingReset = { reason: "cursor_mac_invalid", detail: "forged" };
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example")];
    const { streamer, lines, audits, warns } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    expect(outcome.delivered).toBe(2); // full re-scan, never blind
    const resets = resetAudits(audits);
    expect(resets).toHaveLength(1);
    expect(resets[0]!.details.reason).toBe("cursor_mac_invalid");
    expect(warns.some((w) => w.includes("cursor_mac_invalid"))).toBe(true);
  });

  it("a cursor bound to a DIFFERENT chain identity (wipe+recreate) RESETS; never skips the new prefix", async () => {
    // Same sequence exists on the new chain, but its entry hash differs → a
    // regrown/different chain. Must NOT trust the position; re-scan from start.
    const cursor = new MemoryCursorStore(1, "eh-from-an-old-wiped-chain");
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example"), egressDeny(2, "c.example")];
    const { streamer, lines, audits } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    // The prefix (seq 0,1) the stale cursor would have skipped IS delivered.
    expect(outcome.delivered).toBe(3);
    expect(lines.map((l) => JSON.parse(l).destination_host)).toEqual([
      "a.example",
      "b.example",
      "c.example",
    ]);
    expect(resetAudits(audits)[0]!.details.reason).toBe("cursor_chain_identity_mismatch");
  });

  it("a non-start cursor with NO chain-identity hash (null boundHash) RESETS; never skips the prefix", async () => {
    // Belt-and-suspenders for the cursor.ts null-hash guard: a store that hands
    // back a real sequence but a NULL identity anchor. The store layer rejects
    // this shape, but the streamer must defend it independently — without a bound
    // hash, the sequence-absent / identity-mismatch checks can never fire, so a
    // naive streamer would forward only seq > 1 and SILENTLY SKIP the prefix.
    const cursor = new MemoryCursorStore(1, null);
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example"), egressDeny(2, "c.example")];
    const { streamer, lines, audits, warns } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    // The prefix (seq 0,1) a naive skip would have dropped IS delivered.
    expect(outcome.delivered).toBe(3);
    expect(lines.map((l) => JSON.parse(l).destination_host)).toEqual([
      "a.example",
      "b.example",
      "c.example",
    ]);
    const resets = resetAudits(audits);
    expect(resets).toHaveLength(1);
    expect(resets[0]!.details.reason).toBe("cursor_identity_binding_absent");
    expect(warns.some((w) => w.includes("cursor_identity_binding_absent"))).toBe(true);
    // Self-heals to a proper bound position at the head.
    expect(cursor.state).toEqual({ sequence: 2, entryHash: "eh-2" });
  });

  it("a cursor whose sequence is ABSENT from the surviving chain RESETS (pruned / different chain)", async () => {
    // Bound to seq 1, but the surviving chain has no seq-1 entry (e.g. FIFO-pruned
    // under it, or a different chain). Identity cannot be re-verified → re-scan.
    const cursor = new MemoryCursorStore(1, "eh-1");
    const chain = [egressDeny(0, "a.example"), egressDeny(2, "c.example")]; // no seq 1
    const { streamer, audits } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    expect(outcome.delivered).toBe(2); // 0 and 2 both re-sent, nothing skipped
    expect(resetAudits(audits)[0]!.details.reason).toBe("cursor_sequence_absent");
  });

  it("a LEGITIMATE advance (matching identity) round-trips with NO reset (no false positive)", async () => {
    // Bound to seq 1 with the correct hash; the chain grew to seq 2. Only seq 2 is
    // new. No reset, no re-send of 0/1, no warn.
    const cursor = new MemoryCursorStore(1, "eh-1");
    const chain = [egressDeny(0, "a.example"), egressDeny(1, "b.example"), egressDeny(2, "c.example")];
    const { streamer, lines, audits, warns } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource(chain));

    expect(outcome.delivered).toBe(1);
    expect(lines.map((l) => JSON.parse(l).destination_host)).toEqual(["c.example"]);
    expect(resetAudits(audits)).toHaveLength(0);
    expect(warns).toHaveLength(0);
    expect(cursor.state).toEqual({ sequence: 2, entryHash: "eh-2" });
  });

  it("an EMPTY chain with a real cursor neither resets nor delivers (no false overshoot)", async () => {
    // Nothing on the chain this run: actualChainHead is null, so the head-clamp is
    // NOT triggered (an empty read is not evidence the cursor overshot). Idempotent.
    const cursor = new MemoryCursorStore(5, "eh-5");
    const { streamer, lines, audits } = await armed(cursor);

    const outcome = await streamer.runOnce(chainSource([]));

    expect(outcome.delivered).toBe(0);
    expect(lines).toHaveLength(0);
    expect(resetAudits(audits)).toHaveLength(0);
    expect(cursor.state).toEqual({ sequence: 5, entryHash: "eh-5" }); // unchanged
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
      mapOptions: SIGNED_MAP_OPTIONS,
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
      mapOptions: SIGNED_MAP_OPTIONS,
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
