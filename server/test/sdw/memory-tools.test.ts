import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createSdwMemoryTools } from "../../src/sdw/memory-tools.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import { COOPERATIVE_DENIAL_DISCOVERY_HINT } from "../../src/agent-native/safety-base.js";
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

function makeTools(
  options: {
    failAuditOperations?: readonly string[];
    ownerIdentity?: () => string | undefined;
  } = {},
): {
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
  const defs = createSdwMemoryTools({
    adapter,
    auditLog: log,
    ownerIdentity: options.ownerIdentity,
  });
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
    expect(
      tools.get("memory_search")!.inputSchema.properties as Record<string, unknown>,
    ).not.toHaveProperty("include_text");
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

  it("insert and list return metadata only, while explicit get returns the full body", async () => {
    const { tools } = makeTools();
    const body =
      "projection guard unique body " +
      "alpha ".repeat(80) +
      "bulk memory dump sentinel";

    const inserted = parse(
      await tools.get("memory_insert")!.handler({
        text: body,
        taint: "agent_derived_clean",
        tags: ["projection", "guard"],
        passage_id: "projection-guard",
      }),
    );
    const insertedPassage = inserted.passage as Record<string, unknown>;
    expect(insertedPassage).toMatchObject({
      passage_id: "projection-guard",
      owner_ref: "tools-archive",
      created_at: NOW,
      chunk_count: 1,
      tag_count: 2,
    });
    expect(insertedPassage.content_hash).toEqual(expect.any(String));
    expect(insertedPassage).not.toHaveProperty("text");
    expect(insertedPassage).not.toHaveProperty("tags");
    expect(JSON.stringify(inserted)).not.toContain(body);

    const listed = parse(await tools.get("memory_list")!.handler({}));
    const listedPassage = (listed.passages as Array<Record<string, unknown>>)[0]!;
    expect(listedPassage).toMatchObject({
      passage_id: "projection-guard",
      owner_ref: "tools-archive",
      created_at: NOW,
      chunk_count: 1,
      tag_count: 2,
    });
    expect(listedPassage.content_hash).toEqual(expect.any(String));
    expect(listedPassage).not.toHaveProperty("text");
    expect(listedPassage).not.toHaveProperty("tags");
    expect(JSON.stringify(listed)).not.toContain(body);

    const got = parse(await tools.get("memory_get")!.handler({ passage_id: "projection-guard" }));
    expect(got.found).toBe(true);
    expect((got.passage as Record<string, unknown>).text).toBe(body);
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

  it("does not insert when the pre-commit operation audit write fails (fail closed)", async () => {
    const { tools, storage } = makeTools({ failAuditOperations: ["memory_insert"] });
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
    // The single durable operation record is written BEFORE the mutation
    // (core state_write invariant); it carries the id that is actually persisted.
    const insertAudit = calls.find(
      (c) => c.operation === "memory_insert" && c.result === "success",
    );
    expect(result.inserted).toBe(true);
    expect(typeof passageId).toBe("string");
    expect(insertAudit?.details?.passage_id).toBe(passageId);
  });

  it("records the operation audit before a failed mutation, then a denial (no double success)", async () => {
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
    // Exactly ONE success operation record (the pre-mutation one). The reordered
    // handler does NOT write a second post-commit success audit, so a failed
    // mutation leaves the pre-mutation record + a denial, never two successes.
    const successes = calls.filter((c) => c.operation === "memory_insert" && c.result === "success");
    expect(successes).toHaveLength(1);
    expect(calls.find((c) => c.operation === "memory_insert_denied")).toMatchObject({
      result: "failure",
    });
  });

  it("does not delete when the pre-commit operation audit write fails (fail closed)", async () => {
    const { tools, adapter } = makeTools({ failAuditOperations: ["memory_delete"] });
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

  it("audits a missing delete as not found after the pre-delete operation record", async () => {
    const { tools, calls } = makeTools();
    const result = parse(await tools.get("memory_delete")!.handler({ passage_id: "missing-delete" }));
    // One pre-mutation success operation record, then a not-found failure.
    const op = calls.find((c) => c.operation === "memory_delete" && c.result === "success");
    const notFound = calls.find((c) => c.operation === "memory_delete_denied");
    expect(result).toMatchObject({ deleted: false, found: false });
    expect(op?.details?.passage_id).toBe("missing-delete");
    expect(notFound?.details).toMatchObject({
      denial_class: "not_found",
      passage_id: "missing-delete",
    });
    const successes = calls.filter((c) => c.operation === "memory_delete" && c.result === "success");
    expect(successes).toHaveLength(1);
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

  it("memory_search returns metadata only by default, even for short matched bodies", async () => {
    const { tools } = makeTools();
    const body = "short body with needle-safe-marker and walkable-unique-suffix";
    await tools.get("memory_insert")!.handler({
      text: body,
      taint: "agent_derived_clean",
      tags: ["search"],
      passage_id: "short-search-projection",
    });

    const searched = parse(
      await tools.get("memory_search")!.handler({ text: "needle-safe-marker" }),
    );
    const [result] = searched.results as Array<Record<string, unknown>>;
    expect(result).toBeDefined();
    expect(JSON.stringify(searched)).not.toContain(body);
    expect(JSON.stringify(searched)).not.toContain("needle-safe-marker");
    expect(JSON.stringify(searched)).not.toContain("walkable-unique-suffix");
    expect((result.passage as Record<string, unknown>).passage_id).toBe(
      "short-search-projection",
    );
    expect(result.passage as Record<string, unknown>).not.toHaveProperty("text");
    expect(result).not.toHaveProperty("snippet");
  });

  it("memory_search stays metadata-only even if legacy include_text input is supplied", async () => {
    const { tools } = makeTools();
    const body =
      "explicit search body " +
      "left context ".repeat(40) +
      "include-text-marker " +
      "right context ".repeat(40);
    await tools.get("memory_insert")!.handler({
      text: body,
      taint: "agent_derived_clean",
      passage_id: "search-include-text",
    });

    const searched = parse(
      await tools.get("memory_search")!.handler({
        text: "include-text-marker",
        include_text: true,
      }),
    );
    const [result] = searched.results as Array<Record<string, unknown>>;
    expect(JSON.stringify(searched)).not.toContain(body);
    expect(JSON.stringify(searched)).not.toContain("include-text-marker");
    expect(result.passage as Record<string, unknown>).not.toHaveProperty("text");
    expect(result).not.toHaveProperty("snippet");
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

describe("SDW memory tools: fail-closed multi-agent isolation guard", () => {
  const ALL_OPS: ReadonlyArray<{ name: string; args: Record<string, unknown> }> = [
    { name: "memory_insert", args: { text: "x", taint: "agent_derived_clean" } },
    { name: "memory_get", args: { passage_id: "p" } },
    { name: "memory_search", args: { text: "x" } },
    { name: "memory_list", args: {} },
    { name: "memory_count", args: {} },
    { name: "memory_delete", args: { passage_id: "p" } },
  ];

  it("NO-OP when no ownerIdentity resolver is wired (single-coordinator default)", async () => {
    const { tools } = makeTools();
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text: "single-agent passage",
        taint: "agent_derived_clean",
        passage_id: "noop-1",
      }),
    );
    expect(result.inserted).toBe(true);
  });

  it("NO-OP for a stable single identity: every op proceeds, none refused", async () => {
    const { tools, calls } = makeTools({ ownerIdentity: () => "agent-alpha" });
    // Insert one passage so reads/search/list/count/delete have a real target.
    await tools.get("memory_insert")!.handler({
      text: "alpha searchable passage",
      taint: "agent_derived_clean",
      passage_id: "alpha-1",
    });
    for (const op of ALL_OPS) {
      const result = parse(
        await tools
          .get(op.name)!
          .handler(op.name === "memory_get" || op.name === "memory_delete"
            ? { passage_id: "alpha-1" }
            : op.args),
      );
      // None of these should be the isolation refusal.
      expect(result.message).not.toBe("This action is not available in the current context.");
    }
    expect(
      calls.some(
        (c) => c.details?.denial_class === "sdw_memory_multi_agent_isolation_required",
      ),
    ).toBe(false);
  });

  it("NO-OP for a stable undefined identity (no SANCTUARY_AGENT_ID configured)", async () => {
    const { tools } = makeTools({ ownerIdentity: () => undefined });
    const result = parse(
      await tools.get("memory_insert")!.handler({
        text: "undefined-identity passage",
        taint: "agent_derived_clean",
        passage_id: "undef-1",
      }),
    );
    expect(result.inserted).toBe(true);
  });

  it("REFUSES a second, distinct agent identity with the typed isolation reason", async () => {
    let current = "agent-alpha";
    const { tools, calls } = makeTools({ ownerIdentity: () => current });
    // First caller pins the bound identity.
    const first = parse(
      await tools.get("memory_insert")!.handler({
        text: "alpha owns this scope",
        taint: "agent_derived_clean",
        passage_id: "alpha-pin",
      }),
    );
    expect(first.inserted).toBe(true);

    // A different agent now reaches the SAME shared fleet-self scope -> refuse.
    current = "agent-beta";
    const denied = parse(await tools.get("memory_search")!.handler({ text: "alpha" }));
    expect(denied.denied).toBe(true);
    // Typed reason is audit-only.
    expect(
      calls.some(
        (c) =>
          c.operation === "memory_search_denied" &&
          c.result === "failure" &&
          c.details?.denial_class === "sdw_memory_multi_agent_isolation_required",
      ),
    ).toBe(true);
  });

  it("refusal is fail-closed and leaks no scope detail (fixed denial only)", async () => {
    let current = "agent-alpha";
    const { tools } = makeTools({ ownerIdentity: () => current });
    await tools.get("memory_insert")!.handler({
      text: "alpha owns this scope",
      taint: "agent_derived_clean",
      passage_id: "alpha-leak",
    });
    current = "agent-beta";
    const denied = parse(await tools.get("memory_get")!.handler({ passage_id: "alpha-leak" }));
    // The fixed denial shape: no owner_ref, no observed/bound identities, no passage body.
    expect(denied).toEqual({
      denied: true,
      message: "This action is not available in the current context.",
      remediation_class: "request_review",
      retry_after: null,
      audit_ref: "audit:memory_get",
      discovery_hint: COOPERATIVE_DENIAL_DISCOVERY_HINT,
    });
    const serialized = JSON.stringify(denied);
    expect(serialized).not.toContain("agent-alpha");
    expect(serialized).not.toContain("agent-beta");
    expect(serialized).not.toContain("fleet-self");
    expect(serialized).not.toContain("tools-archive");
  });

  it("blocks writes from a second identity BEFORE any mutation (no leak into the shared scope)", async () => {
    let current = "agent-alpha";
    const { tools } = makeTools({ ownerIdentity: () => current });
    // Alpha pins the scope.
    await tools.get("memory_count")!.handler({});

    // Beta tries to write; the guard fires before insertPassage.
    current = "agent-beta";
    const denied = parse(
      await tools.get("memory_insert")!.handler({
        text: "beta should never land in alpha's scope",
        taint: "agent_derived_clean",
        passage_id: "beta-write",
      }),
    );
    expect(denied.denied).toBe(true);

    // Confirm nothing was written: alpha re-takes the scope and the count is 0.
    current = "agent-alpha";
    const count = parse(await tools.get("memory_count")!.handler({}));
    expect(count.count).toBe(0);
  });

  it("does not advance the pin: alternating callers cannot walk the guard forward", async () => {
    let current = "agent-alpha";
    const { tools } = makeTools({ ownerIdentity: () => current });
    await tools.get("memory_count")!.handler({}); // pin alpha

    current = "agent-beta";
    const betaDenied = parse(await tools.get("memory_count")!.handler({}));
    expect(betaDenied.denied).toBe(true);

    // Back to alpha: still allowed (the pin never moved to beta).
    current = "agent-alpha";
    const alphaAllowed = parse(await tools.get("memory_count")!.handler({}));
    expect(alphaAllowed.count).toBe(0);
  });
});
