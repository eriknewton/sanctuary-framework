import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createSdwMemoryTools } from "../../src/sdw/memory-tools.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import type { ToolDefinition } from "../../src/router.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

const FORTRESS_ID = "fortress:memtools";
const MASTER_KEY = new Uint8Array(32).fill(9);
const NOW = "2026-06-16T00:00:00.000Z";

class MemoryStorage implements StorageBackend {
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
    for (const [composite, data] of this.data) {
      const separator = composite.indexOf("\0");
      const ns = composite.slice(0, separator);
      const key = composite.slice(separator + 1);
      if (ns !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: data.byteLength, modified_at: NOW });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }
  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }
}

interface AuditCall {
  operation: string;
  result: "success" | "failure";
  details?: Record<string, unknown>;
}

function makeAuditLog(failOperations: readonly string[] = []): { log: AuditLog; calls: AuditCall[] } {
  const calls: AuditCall[] = [];
  const failSet = new Set(failOperations);
  const log = {
    async appendCritical(entry: {
      operation: string;
      result: "success" | "failure";
      details?: Record<string, unknown>;
    }): Promise<void> {
      if (failSet.has(entry.operation)) {
        throw new Error(`audit failed for ${entry.operation}`);
      }
      calls.push({ operation: entry.operation, result: entry.result, details: entry.details });
    },
  } as unknown as AuditLog;
  return { log, calls };
}

function makeTools(options: { failAuditOperations?: readonly string[] } = {}): {
  tools: Map<string, ToolDefinition>;
  storage: MemoryStorage;
  adapter: SdwMemoryBackendAdapter;
  calls: AuditCall[];
} {
  const storage = new MemoryStorage();
  const adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: "tools-archive",
    now: () => NOW,
  });
  const { log, calls } = makeAuditLog(options.failAuditOperations);
  const defs = createSdwMemoryTools({ adapter, auditLog: log });
  return { tools: new Map(defs.map((tool) => [tool.name, tool])), storage, adapter, calls };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("SDW memory tools: surface + tier classification", () => {
  it("registers exactly the six memory tools with correct read/write classes", () => {
    const { tools } = makeTools();
    expect([...tools.keys()].sort()).toEqual([
      "memory_count",
      "memory_delete",
      "memory_get",
      "memory_insert",
      "memory_list",
      "memory_search",
    ]);
    expect(tools.get("memory_insert")!.tool_class).toBe("write");
    expect(tools.get("memory_delete")!.tool_class).toBe("write");
    expect(tools.get("memory_get")!.tool_class).toBe("read");
    expect(tools.get("memory_search")!.tool_class).toBe("read");
    expect(tools.get("memory_list")!.tool_class).toBe("read");
    expect(tools.get("memory_count")!.tool_class).toBe("read");
  });

  it("memory_delete is described as Tier 1 / irreversible (MUST-NEVER #3)", () => {
    const { tools } = makeTools();
    const desc = tools.get("memory_delete")!.description.toLowerCase();
    expect(desc).toContain("tier 1");
    expect(desc).toContain("irreversible");
  });

  it("descriptions name the honest primitive (passage store), not lossless interchange", () => {
    const { tools } = makeTools();
    const insert = tools.get("memory_insert")!.description.toLowerCase();
    expect(insert).toContain("passage store");
    expect(insert).not.toContain("lossless");
    expect(insert).not.toContain("brain-agnostic interface");
  });
});

describe("SDW memory tools: end-to-end loop", () => {
  it("insert -> get -> search -> list -> count -> delete", async () => {
    const { tools } = makeTools();

    const inserted = parse(
      await tools.get("memory_insert")!.handler({
        text: "the deploy host of record is mini1",
        taint: "agent_derived_clean",
        tags: ["deploy"],
        passage_id: "p1",
      }),
    );
    expect(inserted.inserted).toBe(true);
    expect((inserted.passage as Record<string, unknown>).passage_id).toBe("p1");

    const got = parse(await tools.get("memory_get")!.handler({ passage_id: "p1" }));
    expect(got.found).toBe(true);
    expect((got.passage as Record<string, unknown>).text).toBe(
      "the deploy host of record is mini1",
    );

    const searched = parse(await tools.get("memory_search")!.handler({ text: "deploy host" }));
    expect((searched.results as unknown[]).length).toBe(1);

    const listed = parse(await tools.get("memory_list")!.handler({}));
    expect((listed.passages as unknown[]).length).toBe(1);

    const counted = parse(await tools.get("memory_count")!.handler({}));
    expect(counted.count).toBe(1);

    const deleted = parse(await tools.get("memory_delete")!.handler({ passage_id: "p1" }));
    expect(deleted.deleted).toBe(true);

    const countAfter = parse(await tools.get("memory_count")!.handler({}));
    expect(countAfter.count).toBe(0);
  });

  it("memory_get returns found:false for a missing passage (no leak)", async () => {
    const { tools } = makeTools();
    const got = parse(await tools.get("memory_get")!.handler({ passage_id: "nope" }));
    expect(got.found).toBe(false);
  });
});

describe("SDW memory tools: custody + denial discipline", () => {
  it("memory_insert inherits the write-gate: a planted private key is denied, not stored (Crux 7)", async () => {
    const { tools, storage } = makeTools();
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text:
          "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----",
        taint: "agent_derived_clean",
      }),
    );
    // Fixed-denial schema only - no policy detail, no record body.
    expect(result.denied).toBe(true);
    expect(result).not.toHaveProperty("denial_class");
    // Nothing was written.
    expect(storage.data.size).toBe(0);
  });

  it("a duplicate insert is denied (no silent overwrite) and audited", async () => {
    const { tools, calls } = makeTools();
    await tools.get("memory_insert")!.handler({
      text: "v1",
      taint: "agent_derived_clean",
      passage_id: "dup",
    });
    const second = parse(
      await tools.get("memory_insert")!.handler({
        text: "v2",
        taint: "agent_derived_clean",
        passage_id: "dup",
      }),
    );
    expect(second.denied).toBe(true);
    expect(calls.some((c) => c.operation === "memory_insert_denied" && c.result === "failure")).toBe(
      true,
    );
  });

  it("does not insert when the pre-commit intent audit write fails", async () => {
    const { tools, storage } = makeTools({ failAuditOperations: ["memory_insert_intent"] });
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text: "must not persist",
        taint: "agent_derived_clean",
        passage_id: "audit-fail-insert",
      }),
    );
    expect(result.denied).toBe(true);
    expect(storage.data.size).toBe(0);
  });

  it("pre-audits generated passage ids with the id that is actually persisted", async () => {
    const { tools, calls } = makeTools();
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text: "generated id audit trail",
        taint: "agent_derived_clean",
      }),
    );
    const passageId = (result.passage as Record<string, unknown>).passage_id;
    const insertAudit = calls.find((c) => c.operation === "memory_insert_intent");
    expect(result.inserted).toBe(true);
    expect(typeof passageId).toBe("string");
    expect(insertAudit?.details?.passage_id).toBe(passageId);
  });

  it("does not leave a success outcome audit when insert mutation fails", async () => {
    const { tools, adapter, calls } = makeTools();
    await adapter.insertPassage(
      { passage_id: "duplicate-outcome", text: "already here" },
      "user_content",
    );
    calls.length = 0;
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text: "must fail",
        taint: "agent_derived_clean",
        passage_id: "duplicate-outcome",
      }),
    );
    expect(result.denied).toBe(true);
    expect(calls.find((c) => c.operation === "memory_insert_intent")).toMatchObject({
      result: "success",
    });
    expect(calls.some((c) => c.operation === "memory_insert" && c.result === "success")).toBe(
      false,
    );
    expect(calls.find((c) => c.operation === "memory_insert_denied")).toMatchObject({
      result: "failure",
    });
  });

  it("does not delete when the pre-commit intent audit write fails", async () => {
    const { tools, adapter } = makeTools({ failAuditOperations: ["memory_delete_intent"] });
    await adapter.insertPassage(
      { passage_id: "audit-fail-delete", text: "must survive" },
      "user_content",
    );
    const result = parse(
      await tools.get("memory_delete")!.handler({ passage_id: "audit-fail-delete" }),
    );
    expect(result.denied).toBe(true);
    await expect(adapter.getPassage("audit-fail-delete")).resolves.toMatchObject({
      text: "must survive",
    });
  });

  it("audits a missing delete as not found after the pre-delete intent", async () => {
    const { tools, calls } = makeTools();
    const result = parse(await tools.get("memory_delete")!.handler({ passage_id: "missing-delete" }));
    const intent = calls.find((c) => c.operation === "memory_delete_intent");
    const notFound = calls.find((c) => c.operation === "memory_delete_denied");
    expect(result).toMatchObject({ deleted: false, found: false });
    expect(intent?.details?.passage_id).toBe("missing-delete");
    expect(notFound?.details).toMatchObject({
      denial_class: "not_found",
      passage_id: "missing-delete",
    });
    expect(calls.some((c) => c.operation === "memory_delete" && c.result === "success")).toBe(
      false,
    );
  });

  it("an invalid taint is denied with the fixed schema, details go to audit only (MUST-NEVER #7)", async () => {
    const { tools, calls } = makeTools();
    const result = parse(
      await tools.get("memory_insert")!.handler({ text: "x", taint: "secret" }),
    );
    expect(result.denied).toBe(true);
    expect(result).not.toHaveProperty("denial_class");
    const denial = calls.find((c) => c.operation === "memory_insert_denied");
    expect(denial?.details?.denial_class).toBe("invalid_taint");
  });

  it("an empty search string returns no results without throwing", async () => {
    const { tools } = makeTools();
    await tools.get("memory_insert")!.handler({
      text: "hello world",
      taint: "agent_derived_clean",
    });
    const searched = parse(await tools.get("memory_search")!.handler({ text: "" }));
    expect((searched.results as unknown[]).length).toBe(0);
  });

  it("audits successful read paths with result counts", async () => {
    const { tools, calls } = makeTools();
    await tools.get("memory_insert")!.handler({
      text: "hello searchable world",
      taint: "agent_derived_clean",
      passage_id: "read-audit",
    });
    calls.length = 0;

    await tools.get("memory_get")!.handler({ passage_id: "read-audit" });
    await tools.get("memory_search")!.handler({ text: "searchable" });
    await tools.get("memory_list")!.handler({});
    await tools.get("memory_count")!.handler({});

    expect(calls.find((c) => c.operation === "memory_get")?.details?.result_count).toBe(1);
    expect(calls.find((c) => c.operation === "memory_search")?.details?.result_count).toBe(1);
    expect(calls.find((c) => c.operation === "memory_list")?.details?.result_count).toBe(1);
    expect(calls.find((c) => c.operation === "memory_count")?.details?.count).toBe(1);
  });
});
