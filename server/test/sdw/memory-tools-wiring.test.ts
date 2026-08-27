/**
 * Registration-time regression tests for wiring the SDW sovereign-memory
 * substrate into the live MCP catalog (company-brain phase 1, 2026-06-18).
 *
 * These guard the WIRING invariants the unit-level memory-tools tests do not
 * reach: that the irreversible delete cannot be relaxed by a hand-authored
 * policy at the LOADER layer, that the passage body is redacted from the
 * approval channel (Hard Constraint #1 / C4) end-to-end through the router
 * order, that the live catalog actually exposes all seven tools with the
 * correct read/write class, and that the live handlers honor the core
 * audit-BEFORE-commit invariant against the SHIPPED adapter: with a failing
 * audit sink injected, memory_insert / memory_delete deny AND do not mutate
 * the real backend (no persisted passage / no delete without a preceding
 * durable operation record), mirroring state_write / state_delete.
 */

import { describe, expect, it } from "vitest";
import { parsePolicy, DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  CallbackApprovalChannel,
  type ApprovalRequest,
} from "../../src/principal-policy/approval-channel.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  createSdwMemoryTools,
  memoryInsertApprovalArgs,
} from "../../src/sdw/memory-tools.js";
import { createSdwMemoryProvenanceTool } from "../../src/sdw/memory-provenance-tool.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import { assertToolClasses } from "../../src/router.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import type { ToolDefinition } from "../../src/router.js";
const FORTRESS_ID = "fortress:memwiring";
const MASTER_KEY = new Uint8Array(32).fill(7);

// A write-gate-honest in-memory backend (mirrors the memory-tools.test.ts one).
class WiringStorage implements StorageBackend {
  readonly data = new Map<string, Uint8Array>();
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const checked = assertSdwRawWriteAuthorized(namespace, key, data);
    this.data.set(`${namespace}\0${key}`, new Uint8Array(checked));
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(`${namespace}\0${key}`) ?? null;
  }
  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(`${namespace}\0${key}`);
  }
  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, value] of this.data) {
      const sep = composite.indexOf("\0");
      const ns = composite.slice(0, sep);
      const key = composite.slice(sep + 1);
      if (ns !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: value.byteLength, modified_at: "2026-06-18T00:00:00.000Z" });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }
  async totalSize(): Promise<number> {
    let total = 0;
    for (const v of this.data.values()) total += v.byteLength;
    return total;
  }
}

function makeWiredTools(): ToolDefinition[] {
  return buildWiredTools().tools;
}

/**
 * Build the wired tools against the SHIPPED adapter (real encryption + storage),
 * optionally with an audit sink that THROWS on the named operations. Returns the
 * adapter so a test can assert the real backend state after a denial.
 */
function buildWiredTools(failAuditOperations: readonly string[] = []): {
  tools: ToolDefinition[];
  adapter: SdwMemoryBackendAdapter;
} {
  const storage = new WiringStorage();
  const adapter = new TestSdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: "fleet-self",
  });
  let auditLog: AuditLog;
  if (failAuditOperations.length === 0) {
    auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  } else {
    const failSet = new Set(failAuditOperations);
    auditLog = {
      async appendCritical(entry: { operation: string }): Promise<void> {
        if (failSet.has(entry.operation)) {
          throw new Error(`audit sink down for ${entry.operation}`);
        }
      },
    } as unknown as AuditLog;
  }
  // Mirror the index.ts wiring: attach the redaction projection to memory_insert.
  const memoryTools = createSdwMemoryTools({ adapter, auditLog }).map((tool) =>
    tool.name === "memory_insert"
      ? { ...tool, approvalTargetArgs: memoryInsertApprovalArgs }
      : tool,
  );
  return {
    tools: [...memoryTools, createSdwMemoryProvenanceTool({ adapter, auditLog })],
    adapter,
  };
}

function parseToolResult(result: {
  content: Array<{ type: "text"; text: string }>;
}): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("company-brain wiring: irreversible delete is un-relaxable at the loader", () => {
  it("DEFAULT_POLICY pins both memory_insert and memory_delete to Tier 1", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("memory_insert");
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("memory_delete");
  });

  it("a hand-authored policy that lists memory_delete under Tier 3 is forced back to Tier 1", () => {
    const policy = parsePolicy(
      JSON.stringify({
        version: 1,
        // Operator tries to relax the irreversible delete to auto-allow.
        tier1_always_approve: [],
        tier3_always_allow: ["memory_delete", "state_read"],
        approval_channel: {},
      }),
    );
    // FORCED_TIER1_OPERATIONS force-adds memory_delete to Tier 1 and prunes it
    // from Tier 3 on load — the operator's downgrade cannot take effect.
    expect(policy.tier1_always_approve).toContain("memory_delete");
    expect(policy.tier3_always_allow).not.toContain("memory_delete");
  });

  it("the gate classifies memory_delete as Tier 1 even under that relaxed policy", async () => {
    const policy = parsePolicy(
      JSON.stringify({
        version: 1,
        tier1_always_approve: [],
        tier3_always_allow: ["memory_delete"],
        approval_channel: {},
      }),
    );
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const baseline = new BaselineTracker(new MemoryStorage(), generateRandomKey());
    const channel = new CallbackApprovalChannel(async (_req: ApprovalRequest) => ({
      decision: "deny" as const,
      decided_at: new Date().toISOString(),
      decided_by: "human" as const,
    }));
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);
    const result = await gate.evaluate("memory_delete", { passage_id: "p1" });
    expect(result.tier).toBe(1);
    expect(result.allowed).toBe(false);
    expect(result.approval_required).toBe(true);
  });
});

describe("company-brain wiring: memory_insert body is redacted from the approval channel (C4)", () => {
  const SECRET_BODY = "BOARD-MEETING-NOTES-CONFIDENTIAL-PROJECT-ATLAS-2026";

  it("the projection drops the body and taint, keeps only metadata", () => {
    const projected = memoryInsertApprovalArgs({
      text: SECRET_BODY,
      taint: "user_content",
      tags: ["a", "b"],
      passage_id: "pid1",
    });
    expect(projected.text).toBeUndefined();
    expect(projected.taint).toBeUndefined();
    expect(projected.text_redacted).toBe(true);
    expect(projected.text_bytes).toBe(Buffer.byteLength(SECRET_BODY, "utf8"));
    expect(projected.tag_count).toBe(2);
    expect(projected.passage_id).toBe("pid1");
    expect(JSON.stringify(projected)).not.toContain(SECRET_BODY);
  });

  it("the wired memory_insert tool exposes the redacting approvalTargetArgs", () => {
    const insert = makeWiredTools().find((t) => t.name === "memory_insert")!;
    expect(insert.approvalTargetArgs).toBe(memoryInsertApprovalArgs);
  });

  it("end-to-end (router order): the approval request carries no body to the channel", async () => {
    const insert = makeWiredTools().find((t) => t.name === "memory_insert")!;
    const policy = parsePolicy(
      JSON.stringify({
        version: 1,
        tier1_always_approve: ["memory_insert"],
        tier3_always_allow: [],
        approval_channel: {},
      }),
    );
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const baseline = new BaselineTracker(new MemoryStorage(), generateRandomKey());
    let captured: ApprovalRequest | undefined;
    const channel = new CallbackApprovalChannel(async (req: ApprovalRequest) => {
      captured = req;
      return {
        decision: "deny" as const,
        decided_at: new Date().toISOString(),
        decided_by: "human" as const,
      };
    });
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);

    // Mirror src/router.ts: approvalTargetArgs runs first, then the gate sees
    // ONLY the projected args.
    const gateArgs = insert.approvalTargetArgs!({
      text: SECRET_BODY,
      taint: "user_content",
      tags: ["meeting"],
    });
    await gate.evaluate("memory_insert", gateArgs);

    expect(captured).toBeDefined();
    const serialized = JSON.stringify(captured);
    // The full body must appear NOWHERE in the outbound approval request,
    // including the truncated-to-100-chars summarizeArgs path.
    expect(serialized).not.toContain(SECRET_BODY);
    expect(serialized).not.toContain("BOARD-MEETING-NOTES");
    const summary = captured!.context.args_summary as Record<string, unknown>;
    expect(summary.text).toBeUndefined();
    expect(summary.text_redacted).toBe(true);
  });
});

describe("company-brain wiring: catalog surface + classification", () => {
  it("exposes exactly the six memory tools + provenance, classes assignable", () => {
    const tools = makeWiredTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        "memory_count",
        "memory_delete",
        "memory_get",
        "memory_insert",
        "memory_list",
        "memory_search",
        "sdw_memory_provenance",
      ].sort(),
    );
    // assertToolClasses throws if any tool lacks read|write (the index.ts
    // registration would throw at startup otherwise).
    expect(() => assertToolClasses(tools)).not.toThrow();
    const writes = tools.filter((t) => t.tool_class === "write").map((t) => t.name).sort();
    expect(writes).toEqual(["memory_delete", "memory_insert"]);
  });
});

describe("company-brain wiring: audit-before-commit holds against the shipped adapter", () => {
  it("memory_insert with a failing audit sink denies AND persists nothing (fail closed)", async () => {
    // Stub the durable critical-audit sink to THROW for the operation record.
    const { tools, adapter } = buildWiredTools(["memory_insert"]);
    const insert = tools.find((t) => t.name === "memory_insert")!;

    const result = parseToolResult(
      await insert.handler({
        text: "must never persist without a durable audit",
        taint: "agent_derived_clean",
        passage_id: "wiring-audit-fail-insert",
      }),
    );

    // (a) the handler returns a denial...
    expect(result.denied).toBe(true);
    // (b) ...and the SHIPPED backend holds no passage: the mutation was never
    //     attempted because the pre-commit audit threw first.
    await expect(adapter.getPassage("wiring-audit-fail-insert")).resolves.toBeNull();
    await expect(adapter.countPassages()).resolves.toBe(0);
  });

  it("memory_delete with a failing audit sink denies AND leaves the passage intact (fail closed)", async () => {
    // First seed a real passage with a working audit sink, then re-wire the
    // SAME shipped adapter behind a sink that throws only on memory_delete.
    const storage = new WiringStorage();
    const adapter = new TestSdwMemoryBackendAdapter({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
      ownerRef: "fleet-self",
    });
    await adapter.insertPassage(
      { passage_id: "wiring-audit-fail-delete", text: "must survive a downed audit" },
      "user_content",
    );

    const failingAudit = {
      async appendCritical(entry: { operation: string }): Promise<void> {
        if (entry.operation === "memory_delete") {
          throw new Error("audit sink down for memory_delete");
        }
      },
    } as unknown as AuditLog;
    const del = createSdwMemoryTools({ adapter, auditLog: failingAudit }).find(
      (t) => t.name === "memory_delete",
    )!;

    const result = parseToolResult(
      await del.handler({ passage_id: "wiring-audit-fail-delete" }),
    );

    // (a) denial, and (b) the irreversible delete never ran against the backend.
    expect(result.denied).toBe(true);
    await expect(adapter.getPassage("wiring-audit-fail-delete")).resolves.toMatchObject({
      text: "must survive a downed audit",
    });
  });
});
