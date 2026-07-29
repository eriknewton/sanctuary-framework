/**
 * Fleet control plane PR-3: the OPERATOR-VISIBLE DOWNGRADE LOG tests.
 *
 * Definition-of-Done:
 *  1. appendDowngradeLog persists a master-MAC'd, oldest-first entry list;
 *     readDowngradeLog round-trips it and reports `readable: true`.
 *  2. A wrong-master / tampered read reports `{ entries: [], readable: false }`
 *     (never throws, never bricks the read path).
 *  3. The log is BOUNDED to MAX_DOWNGRADE_LOG_ENTRIES (oldest roll off).
 *  4. A malformed entry is refused by append; a corrupt existing log is NOT
 *     extended (a fresh log starts) so the append path is always total.
 *  5. Entries carry node ids + reasons, never secrets.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { randomBytes } from "../../src/core/random.js";
import { stringToBytes } from "../../src/core/encoding.js";
import {
  DOWNGRADE_LOG_META_KEY,
  MAX_DOWNGRADE_LOG_ENTRIES,
  readDowngradeLog,
  appendDowngradeLog,
  type DowngradeLogEntry,
} from "../../src/entitlement/downgrade-log.js";

const master = randomBytes(32);
const wrongMaster = randomBytes(32);

function entry(overrides: Partial<DowngradeLogEntry> = {}): DowngradeLogEntry {
  return {
    at: "2026-07-06T00:00:00.000Z",
    kind: "downgrade",
    fromTier: "team",
    toTier: "community",
    fromMaxNodes: 25,
    toMaxNodes: 5,
    reason: "expired",
    droppedNodeIds: ["node-6", "node-7"],
    message: "Team plan expired; 2 nodes left the console. Walls unaffected.",
    ...overrides,
  };
}

describe("appendDowngradeLog + readDowngradeLog", () => {
  it("reads an empty, readable log before anything is appended", async () => {
    const storage = new MemoryStorage();
    expect(await readDowngradeLog(storage, master)).toEqual({
      entries: [],
      readable: true,
    });
  });

  it("appends and round-trips entries oldest-first under the master", async () => {
    const storage = new MemoryStorage();
    await appendDowngradeLog(storage, master, entry({ at: "2026-07-06T01:00:00.000Z" }));
    await appendDowngradeLog(storage, master, entry({ at: "2026-07-06T02:00:00.000Z" }));
    const read = await readDowngradeLog(storage, master);
    expect(read.readable).toBe(true);
    expect(read.entries.map((e) => e.at)).toEqual([
      "2026-07-06T01:00:00.000Z",
      "2026-07-06T02:00:00.000Z",
    ]);
  });

  it("reports readable:false under the WRONG master (never throws, never bricks)", async () => {
    const storage = new MemoryStorage();
    await appendDowngradeLog(storage, master, entry());
    const read = await readDowngradeLog(storage, wrongMaster);
    expect(read).toEqual({ entries: [], readable: false });
  });

  it("reports readable:false when the stored bytes are tampered", async () => {
    const storage = new MemoryStorage();
    await appendDowngradeLog(storage, master, entry());
    const raw = await storage.read("_meta", DOWNGRADE_LOG_META_KEY);
    const obj = JSON.parse(new TextDecoder().decode(raw!));
    obj.data.entries[0].toTier = "enterprise"; // tamper without re-MAC
    await storage.write(
      "_meta",
      DOWNGRADE_LOG_META_KEY,
      stringToBytes(JSON.stringify(obj)),
    );
    expect((await readDowngradeLog(storage, master)).readable).toBe(false);
  });

  it("is BOUNDED to MAX_DOWNGRADE_LOG_ENTRIES (oldest roll off)", async () => {
    const storage = new MemoryStorage();
    const total = MAX_DOWNGRADE_LOG_ENTRIES + 5;
    for (let i = 0; i < total; i += 1) {
      await appendDowngradeLog(storage, master, entry({ message: `m${i}` }));
    }
    const read = await readDowngradeLog(storage, master);
    expect(read.entries.length).toBe(MAX_DOWNGRADE_LOG_ENTRIES);
    // The oldest 5 rolled off; the newest is the last appended.
    expect(read.entries[read.entries.length - 1]!.message).toBe(`m${total - 1}`);
    expect(read.entries[0]!.message).toBe("m5");
  });

  it("refuses a malformed entry", async () => {
    const storage = new MemoryStorage();
    await expect(
      // @ts-expect-error deliberately malformed
      appendDowngradeLog(storage, master, { kind: "downgrade" }),
    ).rejects.toThrow();
  });

  it("does NOT extend a corrupt existing log; it starts fresh (append is total)", async () => {
    const storage = new MemoryStorage();
    await appendDowngradeLog(storage, master, entry({ message: "old" }));
    // Corrupt the stored log.
    const raw = await storage.read("_meta", DOWNGRADE_LOG_META_KEY);
    const obj = JSON.parse(new TextDecoder().decode(raw!));
    obj.data.entries[0].toTier = "enterprise";
    await storage.write(
      "_meta",
      DOWNGRADE_LOG_META_KEY,
      stringToBytes(JSON.stringify(obj)),
    );
    // Append still succeeds and the new log has exactly the new entry.
    await appendDowngradeLog(storage, master, entry({ message: "fresh" }));
    const read = await readDowngradeLog(storage, master);
    expect(read.readable).toBe(true);
    expect(read.entries.map((e) => e.message)).toEqual(["fresh"]);
  });

  it("accepts every transition kind + an unlimited (null) cap", async () => {
    const storage = new MemoryStorage();
    await appendDowngradeLog(
      storage,
      master,
      entry({ kind: "upgrade", fromMaxNodes: 5, toMaxNodes: null, droppedNodeIds: [] }),
    );
    await appendDowngradeLog(
      storage,
      master,
      entry({ kind: "grandfather_capture", droppedNodeIds: [] }),
    );
    await appendDowngradeLog(
      storage,
      master,
      entry({ kind: "revocation_list_unreadable", droppedNodeIds: [] }),
    );
    const read = await readDowngradeLog(storage, master);
    expect(read.entries.map((e) => e.kind)).toEqual([
      "upgrade",
      "grandfather_capture",
      "revocation_list_unreadable",
    ]);
    expect(read.entries[0]!.toMaxNodes).toBeNull();
  });
});
