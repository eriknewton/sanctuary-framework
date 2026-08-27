import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import type { MemoryBackendAdapter } from "../../src/sdw/adapters/memory-backend.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";
import {
  SDW_MEMORY_PROVENANCE_AUDIT_OPS,
  createSdwMemoryProvenanceTool,
} from "../../src/sdw/memory-provenance-tool.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { documentProvenanceKey } from "../../src/sdw/grammar.js";

const FORTRESS_ID = "fortress:prov";
const MASTER_KEY = new Uint8Array(32).fill(5);
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

type AuditCall = { operation: string; result?: string; details?: Record<string, unknown> };

function makeAuditLog(failOn?: string): { log: AuditLog; calls: AuditCall[] } {
  const calls: AuditCall[] = [];
  const log = {
    async appendCritical(entry: AuditCall): Promise<void> {
      if (failOn !== undefined && entry.operation === failOn) {
        throw new Error(`audit sink down for ${entry.operation}`);
      }
      calls.push({ operation: entry.operation, result: entry.result, details: entry.details });
    },
  } as unknown as AuditLog;
  return { log, calls };
}

function setup(failOn?: string) {
  const storage = new MemoryStorage();
  const adapter = new TestSdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: "prov-archive",
    now: () => NOW,
  });
  const { log, calls } = makeAuditLog(failOn);
  const tool = createSdwMemoryProvenanceTool({ adapter, auditLog: log });
  return { adapter, tool, calls, storage };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("sdw_memory_provenance: honesty + public-safety", () => {
  it("is a read tool named honestly (does not claim to prove authorship)", () => {
    const { tool } = setup();
    expect(tool.name).toBe("sdw_memory_provenance");
    expect(tool.tool_class).toBe("read");
    const desc = tool.description.toLowerCase();
    expect(desc).toContain("does not prove true authorship");
    expect(desc).toContain("content truth");
    expect(desc).toContain("safety");
    expect(desc).toContain("remote identity");
    expect(desc).not.toContain("signer-bound");
  });

  it("returns verified per-record provenance without overclaiming truth or safety", async () => {
    const { adapter, tool } = setup();
    await adapter.insertPassage(
      { passage_id: "e1", text: "company brain note" },
      "agent_derived_clean",
    );
    const out = parse(await tool.handler({ passage_id: "e1" }));
    expect(out.found).toBe(true);

    const prov = out.provenance as Record<string, unknown>;
    expect(prov.passage_id).toBe("e1");
    expect(prov.owner_ref).toBe("prov-archive");
    expect(typeof prov.content_hash).toBe("string");
    expect(prov.content_hash_verified_on_read).toBe(true);
    expect(prov.created_at).toBe(NOW);

    // C2 populates only the bounded, public-safe binding projection.
    const gaps = out.provenance_gaps as Record<string, unknown>;
    expect(out.provenance_status).toBe("verified");
    expect(gaps.per_writer_signature).toBe("verified");
    expect(gaps.signing_status).toBe("verified");
    expect(gaps.taint_retrievable).toBe(false);
    expect(gaps.automatic_provenance_event).toBe(true);
    expect(gaps).toMatchObject({
      ingress_channel: "memory_insert",
      source_class: "system_generated",
      recorded_at: NOW,
      admission_channel: "local_write",
      origin_trust_tier: "local_attested",
      verification_basis: "local_primary_identity",
      admitted_at: NOW,
    });
    expect(Object.keys(gaps).sort()).toEqual([
      "admission_channel",
      "admitted_at",
      "automatic_provenance_event",
      "ingress_channel",
      "note",
      "origin_trust_tier",
      "per_writer_signature",
      "recorded_at",
      "signing_status",
      "source_class",
      "taint_retrievable",
      "verification_basis",
    ]);
    for (const forbidden of [
      "author_agent_id", "identity_id", "signer_did", "destination_fortress_id",
      "destination_owner_ref", "signature", "companion",
    ]) expect(gaps).not.toHaveProperty(forbidden);
    expect(JSON.stringify(out)).not.toContain("test-primary");
    expect(JSON.stringify(out)).not.toContain("did:key:");
  });

  it("keeps PRE_MIGRATION unsigned output explicit and does not synthesize verified fields", async () => {
    const { adapter, tool, storage } = setup();
    await adapter.insertPassage({ passage_id: "legacy", text: "unsigned legacy" }, "agent_derived_clean");
    storage.data.delete(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${documentProvenanceKey("mem.prov-archive.legacy")}`);
    const out = parse(await tool.handler({ passage_id: "legacy" }));
    expect(out.provenance_status).toBe("unsigned");
    const gaps = out.provenance_gaps as Record<string, unknown>;
    expect(Object.keys(gaps).sort()).toEqual([
      "automatic_provenance_event", "note", "per_writer_signature", "signing_status", "taint_retrievable",
    ]);
    expect(gaps).toMatchObject({
      per_writer_signature: null,
      signing_status: "not_bound",
      taint_retrievable: false,
      automatic_provenance_event: false,
    });
    expect(String(gaps.note)).toContain("PRE_MIGRATION");
  });

  it("denies rather than mixing old provenance with a replacement passage", async () => {
    const { adapter } = setup();
    await adapter.insertPassage({ passage_id: "racing", text: "old version" }, "agent_derived_clean");
    let provenanceReads = 0;
    const racingAdapter = new Proxy(adapter, {
      get(target, property, receiver): unknown {
        if (property === "getPassageProvenance") {
          return async (passageId: string) => {
            const observed = await target.getPassageProvenance(passageId);
            provenanceReads++;
            if (provenanceReads === 1) {
              await target.putPassages(
                [{ passage_id: passageId, text: "replacement version" }],
                "agent_derived_clean",
              );
            }
            return observed;
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as MemoryBackendAdapter;
    const { log } = makeAuditLog();
    const tool = createSdwMemoryProvenanceTool({ adapter: racingAdapter, auditLog: log });
    const out = parse(await tool.handler({ passage_id: "racing" }));
    expect(provenanceReads).toBe(2);
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });

  it("does NOT leak the passage body or any sensitive field in the provenance (MUST-NEVER #7)", async () => {
    const { adapter, tool } = setup();
    const bodyText = "the private notes for this passage live only in the vault";
    await adapter.insertPassage(
      { passage_id: "e2", text: bodyText },
      "agent_derived_clean",
    );
    const out = parse(await tool.handler({ passage_id: "e2" }));
    const prov = out.provenance as Record<string, unknown>;
    // The body text is never echoed back in a provenance read.
    expect(JSON.stringify(out)).not.toContain(bodyText);
    expect(prov).not.toHaveProperty("text");
    expect(prov).not.toHaveProperty("identity_id");
  });

  it("returns found:false for a missing passage", async () => {
    const { tool } = setup();
    const out = parse(await tool.handler({ passage_id: "missing" }));
    expect(out.found).toBe(false);
  });

  it("denies an invalid passage_id with the fixed schema and audits it", async () => {
    const { tool, calls } = setup();
    const out = parse(await tool.handler({ passage_id: "" }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("denial_class");
    expect(calls.some((c) => c.operation === "sdw_memory_provenance_denied")).toBe(true);
  });

  it("fails closed (fixed denial) when a stored chunk is corrupted, never returning the entry (the tamper-evidence path)", async () => {
    const { adapter, tool, calls } = setup();
    await adapter.insertPassage(
      { passage_id: "e3", text: "trustworthy original content" },
      "agent_derived_clean",
    );
    // Corrupt the underlying storage so the on-read content-hash check fails.
    // The adapter writes through the gate, so we corrupt the raw stored bytes
    // directly: find the document-corpus entries and overwrite one chunk.
    const adapterAny = adapter as unknown as { storage: { data: Map<string, Uint8Array> } };
    let corrupted = false;
    for (const key of adapterAny.storage.data.keys()) {
      if (key.includes(".c000000")) {
        adapterAny.storage.data.set(key, new Uint8Array([1, 2, 3, 4]));
        corrupted = true;
        break;
      }
    }
    expect(corrupted).toBe(true);

    const out = parse(await tool.handler({ passage_id: "e3" }));
    // The corrupted entry must NOT be surfaced; the tool fails closed.
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
    expect(calls.some((c) => c.operation === "sdw_memory_provenance_denied")).toBe(true);
  });
});

describe("IC-28: successful provenance reads are audited (one record per read, through the catalog)", () => {
  const readOp = SDW_MEMORY_PROVENANCE_AUDIT_OPS.read;
  const readRecords = (calls: AuditCall[]) => calls.filter((c) => c.operation === readOp);

  it("a found passage appends exactly one read record naming the passage, with result success", async () => {
    const { adapter, tool, calls } = setup();
    await adapter.insertPassage({ passage_id: "r1", text: "audited read" }, "agent_derived_clean");
    const out = parse(await tool.handler({ passage_id: "r1" }));
    expect(out.found).toBe(true);
    expect(readRecords(calls)).toEqual([
      { operation: readOp, result: "success", details: { passage_id: "r1", found: true } },
    ]);
    // The record carries no passage body (MUST-NEVER #7 projection).
    expect(JSON.stringify(calls)).not.toContain("audited read");
  });

  it("a missing passage is still a read: exactly one record with found:false", async () => {
    const { tool, calls } = setup();
    expect(parse(await tool.handler({ passage_id: "absent" })).found).toBe(false);
    expect(readRecords(calls)).toEqual([
      { operation: readOp, result: "success", details: { passage_id: "absent", found: false } },
    ]);
  });

  it("a denied call writes a denial record and NO read record", async () => {
    const { tool, calls } = setup();
    expect(parse(await tool.handler({ passage_id: "" })).denied).toBe(true);
    expect(readRecords(calls)).toEqual([]);
    expect(calls.map((c) => c.operation)).toEqual([SDW_MEMORY_PROVENANCE_AUDIT_OPS.denied]);
  });

  it("audit-before-return: a downed audit sink denies instead of answering unlogged", async () => {
    const { adapter, tool } = setup(readOp);
    await adapter.insertPassage({ passage_id: "r2", text: "never answered unlogged" }, "agent_derived_clean");
    const out = parse(await tool.handler({ passage_id: "r2" }));
    expect(out.denied).toBe(true);
    expect(out).not.toHaveProperty("provenance");
  });
});
