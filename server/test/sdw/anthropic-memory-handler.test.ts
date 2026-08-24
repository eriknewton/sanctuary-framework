import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";
import {
  applyAnthropicMemoryCommand,
  passageIdForPath,
} from "../../src/sdw/anthropic-memory-handler.js";
import { assertSdwRawWriteAuthorized } from "../../src/sdw/write-gate.js";

const FORTRESS_ID = "fortress:am";
const MASTER_KEY = new Uint8Array(32).fill(3);
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

function makeAdapterWithStorage(): { adapter: SdwMemoryBackendAdapter; storage: MemoryStorage } {
  const storage = new MemoryStorage();
  return {
    storage,
    adapter: new TestSdwMemoryBackendAdapter({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
      ownerRef: "am-worker",
      now: () => NOW,
    }),
  };
}

function makeAdapter(): SdwMemoryBackendAdapter {
  return makeAdapterWithStorage().adapter;
}

function parseResultTextSize(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

describe("Anthropic Memory-tool -> SDW handler (local, synthetic)", () => {
  it("binds the code-owned wrapped caller rather than a system-author literal", async () => {
    const adapter = makeAdapter();
    const path = "/memories/caller.md";
    await applyAnthropicMemoryCommand(adapter, {
      command: "create", path, file_text: "caller-originated text",
    }, () => "wrapped-anthropic-agent");
    const provenance = await adapter.getPassageProvenance(passageIdForPath(path));
    expect(provenance.status).toBe("verified");
    if (provenance.status !== "verified") throw new Error("expected verified provenance");
    expect(provenance.companion.origin.body.author_agent_id).toBe("wrapped-anthropic-agent");
    expect(provenance.companion.origin.body.author_agent_id).not.toBe("system:anthropic-memory-tool");
  });

  it("path -> passage_id is deterministic and SDW-identifier-safe", () => {
    const a = passageIdForPath("/memories/project.md");
    const b = passageIdForPath("/memories/project.md");
    expect(a).toBe(b);
    expect(a.startsWith("am.")).toBe(true);
  });

  it("create -> view round-trips file content into the sovereign vault", async () => {
    const adapter = makeAdapter();
    const created = await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/notes.md",
      file_text: "the company brain dogfoods on SDW",
    });
    expect(created.ok).toBe(true);

    const viewed = await applyAnthropicMemoryCommand(adapter, {
      command: "view",
      path: "/memories/notes.md",
    });
    expect(viewed.ok).toBe(true);
    expect(viewed.content).toBe("the company brain dogfoods on SDW");
  });

  it("rejects oversized multi-chunk creates before writing storage", async () => {
    const { adapter, storage } = makeAdapterWithStorage();
    const oversized = "x".repeat(1024 * 1024 + 1);
    expect(parseResultTextSize(oversized)).toBeGreaterThan(1024 * 1024);
    const created = await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/huge.md",
      file_text: oversized,
    });
    expect(created.ok).toBe(false);
    expect(created.error_code).toBe("too_large");
    expect(storage.data.size).toBe(0);
  });

  it("does not echo raw caller paths in model-visible errors", async () => {
    const adapter = makeAdapter();
    const path = "/memories/-----BEGIN PRIVATE KEY-----.md";
    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path });
    expect(viewed.ok).toBe(false);
    expect(viewed.content).not.toContain(path);
    expect(viewed.content).not.toContain("PRIVATE KEY");
  });

  it("does not echo write-gate categories in model-visible errors", async () => {
    const adapter = makeAdapter();
    const created = await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/leak-category.md",
      file_text:
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----",
    });
    expect(created.ok).toBe(false);
    expect(created.error_code).toBe("write_rejected");
    expect(created.content).not.toContain("classifier_reject");
    expect(created.content).not.toContain("PRIVATE KEY");
  });
});

/*
 * Keep the behavioral coverage below in a separate describe so the new safety
 * checks above can stay focused and small.
 */
describe("Anthropic Memory-tool -> SDW handler operations", () => {
  function makeAdapter(): SdwMemoryBackendAdapter {
    return new TestSdwMemoryBackendAdapter({
      storage: new MemoryStorage(),
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
      ownerRef: "am-worker",
      now: () => NOW,
    });
  }

  it("create on an existing path is a conflict, not a silent overwrite", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/x.md",
      file_text: "v1",
    });
    const again = await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/x.md",
      file_text: "v2",
    });
    expect(again.ok).toBe(false);
    expect(again.error_code).toBe("exists");
    // v1 survives.
    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/x.md" });
    expect(viewed.content).toBe("v1");
  });

  it("str_replace is realized as a NON-ATOMIC delete+insert (the honest Crux-4 mismatch)", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/host.md",
      file_text: "deploy host: mini1",
    });
    const replaced = await applyAnthropicMemoryCommand(adapter, {
      command: "str_replace",
      path: "/memories/host.md",
      old_str: "mini1",
      new_str: "mini1-of-record",
    });
    expect(replaced.ok).toBe(true);
    // The handler does NOT pretend this was an in-place edit; it names the
    // non-atomic strategy explicitly.
    expect(replaced.mutation_strategy).toBe("delete_then_insert");

    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/host.md" });
    expect(viewed.content).toBe("deploy host: mini1-of-record");
  });

  it("str_replace with no match does not mutate", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/y.md",
      file_text: "unchanged",
    });
    const replaced = await applyAnthropicMemoryCommand(adapter, {
      command: "str_replace",
      path: "/memories/y.md",
      old_str: "absent",
      new_str: "x",
    });
    expect(replaced.ok).toBe(false);
    expect(replaced.error_code).toBe("no_match");
    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/y.md" });
    expect(viewed.content).toBe("unchanged");
  });

  it("insert at a line is realized as a non-atomic delete+insert", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/list.md",
      file_text: "line0\nline1",
    });
    const inserted = await applyAnthropicMemoryCommand(adapter, {
      command: "insert",
      path: "/memories/list.md",
      insert_line: 1,
      insert_text: "INSERTED",
    });
    expect(inserted.ok).toBe(true);
    expect(inserted.mutation_strategy).toBe("delete_then_insert");
    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/list.md" });
    expect(viewed.content).toBe("line0\nINSERTED\nline1");
  });

  it("rename moves content to a new path (non-atomic), old path gone", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/old.md",
      file_text: "movable",
    });
    const renamed = await applyAnthropicMemoryCommand(adapter, {
      command: "rename",
      old_path: "/memories/old.md",
      new_path: "/memories/new.md",
    });
    expect(renamed.ok).toBe(true);
    expect(renamed.mutation_strategy).toBe("insert_then_delete");
    const oldView = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/old.md" });
    expect(oldView.ok).toBe(false);
    const newView = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/new.md" });
    expect(newView.content).toBe("movable");
  });

  it("delete removes the passage; deleting a missing path is not_found", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/z.md",
      file_text: "bye",
    });
    const del = await applyAnthropicMemoryCommand(adapter, { command: "delete", path: "/memories/z.md" });
    expect(del.ok).toBe(true);
    const delAgain = await applyAnthropicMemoryCommand(adapter, { command: "delete", path: "/memories/z.md" });
    expect(delAgain.ok).toBe(false);
    expect(delAgain.error_code).toBe("not_found");
  });

  it("create inherits the SDW write-gate: a secret in file_text is rejected (Crux 7)", async () => {
    const adapter = makeAdapter();
    const created = await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/leak.md",
      file_text:
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----",
    });
    expect(created.ok).toBe(false);
    expect(created.error_code).toBe("write_rejected");
    // The rejected content is never echoed back.
    expect(created.content).not.toContain("PRIVATE KEY");
    // Nothing was stored.
    const viewed = await applyAnthropicMemoryCommand(adapter, { command: "view", path: "/memories/leak.md" });
    expect(viewed.ok).toBe(false);
  });

  it("str_replace inserts new_str LITERALLY (no $-pattern interpretation, no silent corruption) [F1 regression]", async () => {
    const adapter = makeAdapter();
    await applyAnthropicMemoryCommand(adapter, {
      command: "create",
      path: "/memories/dollar.md",
      file_text: "alpha OLD omega",
    });
    // new_str carries every JS String.replace special: $&, $`, $', $$, $1.
    // A plain string replacer would expand them ($& -> "OLD", $` -> "alpha ",
    // $' -> " omega", $$ -> "$") and silently corrupt the stored content while
    // the original was securely overwritten. They must survive verbatim.
    const newStr = "$& $` $' $$ $1 NEW";
    const replaced = await applyAnthropicMemoryCommand(adapter, {
      command: "str_replace",
      path: "/memories/dollar.md",
      old_str: "OLD",
      new_str: newStr,
    });
    expect(replaced.ok).toBe(true);
    const viewed = await applyAnthropicMemoryCommand(adapter, {
      command: "view",
      path: "/memories/dollar.md",
    });
    expect(viewed.content).toBe("alpha " + newStr + " omega");
  });
});
