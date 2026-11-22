/**
 * Every denial ledger row of one kind has one stored size: the bytes the real
 * audit log hands to encryption are the same length for every first row and
 * for every summary row, whatever the cause, tool, origin or message.
 */
import { describe, expect, it, vi } from "vitest";

const captured = vi.hoisted(() => ({ plaintexts: [] as Uint8Array[] }));

vi.mock("../../src/core/encryption.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/core/encryption.js")>();
  return {
    ...actual,
    // The real cipher, after keeping a copy of exactly what it was given.
    encrypt: (...args: Parameters<typeof actual.encrypt>) => {
      captured.plaintexts.push(args[0].slice());
      return actual.encrypt(...args);
    },
  };
});

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES,
  DENIAL_WINDOW_MS,
  DenialLedger,
  truncateStoredString,
} from "../../src/agent-native/denial-ledger.js";

const START_MS = Date.parse("2026-01-01T00:00:00.000Z");

function storedRows(operation: string): Array<{ bytes: number; entry: Record<string, any> }> {
  const decoder = new TextDecoder();
  return captured.plaintexts
    .map((bytes) => ({ bytes: bytes.byteLength, text: decoder.decode(bytes) }))
    .filter(({ text }) => text.startsWith("{") && text.includes(`"operation":"${operation}"`))
    .map(({ bytes, text }) => ({ bytes, entry: JSON.parse(text) as Record<string, any> }));
}

describe("denial ledger row size", () => {
  it("first rows for different causes and messages, and summaries of different windows, each store one size", async () => {
    captured.plaintexts.length = 0;
    const audit = new AuditLog(new MemoryStorage(), generateRandomKey());
    let now = START_MS;
    const ledger = new DenialLedger(audit, () => now, { warn: () => undefined });

    // Each message is a different stored length; the last mixes two-, three- and
    // four-byte characters and is longer than the cap, so it is cut mid-text.
    const multiByte = "Zugriff verweigert: ß € 😀 ".repeat(12);
    ledger.record("gate_denied", { tool: "state_export", origin: "agent:unknown", linked_ref: `gate-approval-${"a".repeat(32)}` });
    ledger.record("handler_error", { tool: "memory_insert", origin: "agent:a", error_name: "TypeError", error_message: "x" });
    ledger.record("export_capacity", { tool: "sanctuary_recall", origin: "agent:b", error_name: "Error", error_message: "y".repeat(150) });
    ledger.record("post_allow_refusal", {
      tool: "sdw_memory_provenance_repair_completion_marker",
      origin: `agent:${"long-agent-id-".repeat(20)}`,
      error_name: "error",
      error_message: multiByte,
      facts: { committed: true, audited: false },
    });
    ledger.record("pre_gate_argument_refused", { tool: `proxy/upstream/${"t".repeat(200)}`, origin: "agent:c" });
    // More refusals in three of the windows, so their summaries differ.
    ledger.record("gate_fault", { tool: "state_export", origin: "agent:unknown", linked_ref: "audit:tool_error:0123456789abcdef" });
    ledger.record("handler_error", { tool: "memory_insert", origin: "agent:a" });
    ledger.record("handler_error", { tool: "memory_insert", origin: "agent:a" });
    for (let i = 0; i < 12; i += 1) {
      ledger.record("post_allow_refusal", { tool: "sanctuary_recall", origin: "agent:b", linked_ref: `ref-${i}` });
    }

    now += DENIAL_WINDOW_MS;
    ledger.record("other", { tool: "after_window", origin: "agent:d", error_message: "z" });
    await ledger.close();
    await audit.flush();

    const firstRows = storedRows("denial_cause");
    const summaries = storedRows("denial_cause_summary");
    expect(new Set(firstRows.map((row) => row.entry.details.cause)).size).toBeGreaterThanOrEqual(4);
    expect(new Set(firstRows.map((row) => row.entry.details.error_message ?? "")).size).toBeGreaterThanOrEqual(4);
    expect(firstRows).toHaveLength(6);
    expect(new Set(firstRows.map((row) => row.bytes)).size).toBe(1);
    expect(summaries).toHaveLength(3);
    expect(new Set(summaries.map((row) => JSON.stringify(row.entry.details.causes))).size).toBe(3);
    expect(new Set(summaries.map((row) => row.bytes)).size).toBe(1);

    // The multi-byte message was cut between whole characters, within the cap.
    const cut = firstRows.find((row) => row.entry.details.cause === "post_allow_refusal")!.entry.details;
    expect(Buffer.byteLength(cut.error_message, "utf8")).toBeLessThanOrEqual(DENIAL_FIRST_ROW_MESSAGE_MAX_BYTES);
    expect(cut.error_message.length).toBeGreaterThan(0);
    expect(multiByte.startsWith(cut.error_message)).toBe(true);
    expect(cut.error_message).not.toContain("�");
    expect(cut).toMatchObject({ committed: true, audited: false });
  });

  it("truncation counts stored bytes and never splits a code point", () => {
    expect(truncateStoredString("€€€", 7)).toBe("€€");
    expect(truncateStoredString("😀😀", 5)).toBe("😀");
    expect(truncateStoredString("😀", 3)).toBe("");
    // A quote is stored escaped, so it costs two bytes.
    expect(truncateStoredString('a"b', 2)).toBe("a");
    expect(truncateStoredString("short", 200)).toBe("short");
  });
});
