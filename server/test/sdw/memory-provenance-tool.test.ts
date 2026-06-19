import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createSdwMemoryProvenanceTool } from "../../src/sdw/memory-provenance-tool.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

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

function makeAuditLog(): { log: AuditLog; calls: Array<{ operation: string }> } {
  const calls: Array<{ operation: string }> = [];
  const log = {
    async appendCritical(entry: { operation: string }): Promise<void> {
      calls.push({ operation: entry.operation });
    },
  } as unknown as AuditLog;
  return { log, calls };
}

function setup() {
  const storage = new MemoryStorage();
  const adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: "prov-archive",
    now: () => NOW,
  });
  const { log, calls } = makeAuditLog();
  const tool = createSdwMemoryProvenanceTool({ adapter, auditLog: log });
  return { adapter, tool, calls };
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
    expect(desc).toContain("not claim to prove who wrote");
    expect(desc).not.toContain("signer-bound");
  });

  it("returns the shipped provenance plus an HONEST gaps block (no overclaim)", async () => {
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

    // The honest gaps block: per-writer signing is NOT bound, taint is NOT
    // retrievable, and there is NO automatic provenance event. These must be
    // present so a reader is never misled into trusting unproven authorship.
    const gaps = out.provenance_gaps as Record<string, unknown>;
    expect(gaps.per_writer_signature).toBeNull();
    expect(gaps.signing_status).toBe("not_bound");
    expect(gaps.taint_retrievable).toBe(false);
    expect(gaps.automatic_provenance_event).toBe(false);
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
