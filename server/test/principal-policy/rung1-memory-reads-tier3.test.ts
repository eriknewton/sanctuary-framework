/**
 * Rung 1 hands-free restart read: `memory_get` and `memory_search` are
 * Tier-3 auto-allow under the default policy so the documented acceptance
 * step (store a marker, restart, read it back with no secret typed and no
 * human at the approval prompt) is true on a stdio server with the default
 * approval channel. The vault is one operator-owned memory scope shared by
 * every agent connected to the fortress; the one-owner guard refuses a
 * second distinct wrapped identity where an identity resolver is wired.
 * Writes (`memory_insert`, `memory_delete`) and every plaintext-crossing
 * verb (`memory_ingest`, `memory_emit`) stay Tier 1.
 *
 * An unattended read carries its own ceiling on the work one call can buy.
 * This file pins, behaviorally: the default tiers and the gate's live
 * classification; that `memory_search` always hands the adapter an explicit
 * capped limit (default when absent, clamped when oversize), refuses an
 * empty or oversize needle and a tag outside the identifier grammar, and
 * audits each refusal; and that a guard refusal reaches no adapter method.
 */

import { describe, expect, it } from "vitest";

import { AutoApproveChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { ToolDefinition } from "../../src/router.js";
import type {
  MemoryBackendAdapter,
  MemorySearchQuery,
} from "../../src/sdw/adapters/memory-backend.js";
import {
  DEFAULT_MAX_CHUNK_CHARS,
  MEMORY_LIST_MAX_LIMIT,
  MEMORY_SEARCH_DEFAULT_LIMIT,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createSdwMemoryTools } from "../../src/sdw/memory-tools.js";

/** The two reads the Rung 1 restart acceptance step performs unattended. */
const HANDS_FREE_MEMORY_READS = ["memory_get", "memory_search"] as const;

/** Memory verbs that commit, destroy, or materialize plaintext: never unattended by default. */
const APPROVAL_GATED_MEMORY_VERBS = [
  "memory_insert",
  "memory_delete",
  "memory_ingest",
  "memory_emit",
] as const;

function defaultGate(): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new ApprovalGate(
    DEFAULT_POLICY,
    new BaselineTracker(storage, masterKey),
    new AutoApproveChannel(),
    new AuditLog(storage, masterKey),
  );
}

interface AuditCall {
  operation: string;
  result: "success" | "failure";
  details?: Record<string, unknown>;
}

/**
 * A recording adapter: every method the two read handlers can reach is
 * counted, and the search query is captured, so a test can assert what the
 * handler handed the adapter (or that it handed it nothing at all).
 */
function recordingHarness(options: { ownerIdentity?: () => string | undefined } = {}): {
  tools: Map<string, ToolDefinition>;
  searches: MemorySearchQuery[];
  adapterCalls: string[];
  audits: AuditCall[];
} {
  const searches: MemorySearchQuery[] = [];
  const adapterCalls: string[] = [];
  const audits: AuditCall[] = [];
  const adapter = {
    async searchPassages(query: MemorySearchQuery) {
      adapterCalls.push("searchPassages");
      searches.push(query);
      return [];
    },
    async getPassage(_passageId: string) {
      adapterCalls.push("getPassage");
      return null;
    },
  } as unknown as MemoryBackendAdapter;
  const auditLog = {
    async appendCritical(entry: AuditCall): Promise<void> {
      audits.push({ operation: entry.operation, result: entry.result, details: entry.details });
    },
  } as unknown as AuditLog;
  const defs = createSdwMemoryTools({ adapter, auditLog, ownerIdentity: options.ownerIdentity });
  return { tools: new Map(defs.map((tool) => [tool.name, tool])), searches, adapterCalls, audits };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function denialClasses(audits: AuditCall[], operation: string): unknown[] {
  return audits
    .filter((a) => a.operation === `${operation}_denied` && a.result === "failure")
    .map((a) => a.details?.denial_class);
}

describe("Rung 1: memory_get / memory_search are Tier 3 under the default policy", () => {
  it("DEFAULT_POLICY lists both reads under tier3_always_allow and neither under Tier 1", () => {
    for (const op of HANDS_FREE_MEMORY_READS) {
      expect(DEFAULT_POLICY.tier3_always_allow, op).toContain(op);
      expect(DEFAULT_POLICY.tier1_always_approve, op).not.toContain(op);
    }
  });

  it("DEFAULT_POLICY keeps the write and plaintext-crossing verbs under Tier 1, not Tier 3", () => {
    for (const op of APPROVAL_GATED_MEMORY_VERBS) {
      expect(DEFAULT_POLICY.tier1_always_approve, op).toContain(op);
      expect(DEFAULT_POLICY.tier3_always_allow, op).not.toContain(op);
    }
  });

  it("the gate classifies both reads as Tier 3 with no approval required", async () => {
    const gate = defaultGate();
    const get = await gate.evaluate("memory_get", { passage_id: "marker-1" });
    expect(get.tier).toBe(3);
    expect(get.approval_required).toBe(false);
    expect(get.allowed).toBe(true);

    const search = await gate.evaluate("memory_search", { text: "marker" });
    expect(search.tier).toBe(3);
    expect(search.approval_required).toBe(false);
    expect(search.allowed).toBe(true);
  });

  it("the gate classifies insert, delete, ingest, and emit as Tier 1", async () => {
    const gate = defaultGate();
    const args: Record<(typeof APPROVAL_GATED_MEMORY_VERBS)[number], Record<string, unknown>> = {
      memory_insert: { text: "marker", taint: "user_content" },
      memory_delete: { passage_id: "marker-1" },
      memory_ingest: { harness: "claude-code", dir: "/tmp/source" },
      memory_emit: { format: "markdown", out_dir: "/tmp/out" },
    };
    for (const op of APPROVAL_GATED_MEMORY_VERBS) {
      const result = await gate.evaluate(op, args[op]);
      expect(result.tier, op).toBe(1);
    }
  });
});

describe("Rung 1: the unattended memory_search carries its own bounds at the tool boundary", () => {
  it("with no limit, the adapter receives the explicit default limit", async () => {
    const { tools, searches } = recordingHarness();
    const result = parse(await tools.get("memory_search")!.handler({ text: "marker" }));
    expect(result.results).toEqual([]);
    expect(searches).toHaveLength(1);
    expect(searches[0]!.limit).toBe(MEMORY_SEARCH_DEFAULT_LIMIT);
  });

  it("an in-range limit is passed through unchanged", async () => {
    const { tools, searches } = recordingHarness();
    await tools.get("memory_search")!.handler({ text: "marker", limit: 3 });
    expect(searches[0]!.limit).toBe(3);
  });

  it("an over-maximum limit is clamped to the maximum and the clamp is audited", async () => {
    const { tools, searches, audits } = recordingHarness();
    await tools.get("memory_search")!.handler({
      text: "marker",
      limit: MEMORY_LIST_MAX_LIMIT * 10,
    });
    expect(searches[0]!.limit).toBe(MEMORY_LIST_MAX_LIMIT);
    const success = audits.find((a) => a.operation === "memory_search" && a.result === "success");
    expect(success?.details?.limited).toBe(MEMORY_LIST_MAX_LIMIT);
    expect(success?.details?.limit_clamped).toBe(true);
  });

  it("empty text is refused before the adapter is reached, with an audited denial class", async () => {
    const { tools, adapterCalls, audits } = recordingHarness();
    const result = parse(await tools.get("memory_search")!.handler({ text: "" }));
    expect(result.denied).toBe(true);
    expect(adapterCalls).toEqual([]);
    expect(denialClasses(audits, "memory_search")).toEqual(["empty_text"]);
  });

  it("text over the byte cap is refused before the adapter is reached; text at the cap is not", async () => {
    const { tools, adapterCalls, audits, searches } = recordingHarness();
    const atCap = "a".repeat(DEFAULT_MAX_CHUNK_CHARS);
    await tools.get("memory_search")!.handler({ text: atCap });
    expect(searches).toHaveLength(1);

    const overCap = `${atCap}a`;
    const result = parse(await tools.get("memory_search")!.handler({ text: overCap }));
    expect(result.denied).toBe(true);
    expect(adapterCalls).toEqual(["searchPassages"]);
    expect(denialClasses(audits, "memory_search")).toEqual(["text_too_large"]);
  });

  it("a multi-byte needle is capped by UTF-8 bytes, not code points", async () => {
    const { tools, adapterCalls } = recordingHarness();
    // 4 bytes per code point in UTF-8; well under the cap in code points but over it in bytes.
    const fourByte = "\u{1F512}".repeat(Math.ceil(DEFAULT_MAX_CHUNK_CHARS / 4) + 1);
    const result = parse(await tools.get("memory_search")!.handler({ text: fourByte }));
    expect(result.denied).toBe(true);
    expect(adapterCalls).toEqual([]);
  });

  it("a tag outside the SDW identifier grammar is refused before the adapter is reached", async () => {
    const { tools, adapterCalls, audits } = recordingHarness();
    const result = parse(
      await tools.get("memory_search")!.handler({ text: "marker", tag: "not a valid tag" }),
    );
    expect(result.denied).toBe(true);
    expect(adapterCalls).toEqual([]);
    expect(denialClasses(audits, "memory_search")).toEqual(["invalid_tag"]);
  });

  it("a valid tag filter reaches the adapter", async () => {
    const { tools, searches } = recordingHarness();
    await tools.get("memory_search")!.handler({ text: "marker", tag: "restart-drill" });
    expect(searches[0]!.tag).toBe("restart-drill");
  });
});

describe("Rung 1: a one-owner guard refusal reaches no adapter method", () => {
  it("a second distinct identity is refused on memory_get and memory_search with zero adapter calls", async () => {
    let current = "agent-alpha";
    const { tools, adapterCalls, audits } = recordingHarness({ ownerIdentity: () => current });
    // First caller pins the shared scope.
    await tools.get("memory_search")!.handler({ text: "marker" });
    expect(adapterCalls).toEqual(["searchPassages"]);

    current = "agent-beta";
    const search = parse(await tools.get("memory_search")!.handler({ text: "marker" }));
    const get = parse(await tools.get("memory_get")!.handler({ passage_id: "marker-1" }));
    expect(search.denied).toBe(true);
    expect(get.denied).toBe(true);
    // Neither refused call touched the adapter.
    expect(adapterCalls).toEqual(["searchPassages"]);
    expect(denialClasses(audits, "memory_search")).toEqual([
      "sdw_memory_multi_agent_isolation_required",
    ]);
    expect(denialClasses(audits, "memory_get")).toEqual([
      "sdw_memory_multi_agent_isolation_required",
    ]);
  });
});
