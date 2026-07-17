/**
 * Hermetic tests for the on-disk, MASTER-KEY-AUTHENTICATED durable export cursor
 * (`FileExportCursorStore`).
 *
 * Uses a throwaway temp fortress dir (never a real ~/.sanctuary). Proves:
 *   - the crash/restart durability contract at the FILE level: a persisted,
 *     authenticated cursor is read back by a FRESH store instance (a simulated
 *     process restart), bound to its chain-identity `entryHash`;
 *   - a missing cursor fail-safes to the start sentinel with NO reset (first run);
 *   - the TAMPER class the authentication closes: a hand-written / legacy /
 *     MAC-tampered / wrong-key / entry-hash-tampered cursor is DISCARDED with a
 *     loud reset reason and the start sentinel, never trusted for its value;
 *   - a non-ENOENT read error is LOUD (a reset reason), not a silent re-scan.
 */

import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  EXPORT_CURSOR_FILENAME,
  EXPORT_CURSOR_START,
  FileExportCursorStore,
} from "../../../src/castle-wall/export/index.js";
import { generateRandomKey } from "../../../src/core/random.js";

let fortress: string;
let masterKey: Uint8Array;

beforeEach(async () => {
  fortress = await mkdtemp(join(tmpdir(), "cortex-export-cursor-"));
  masterKey = generateRandomKey();
});

afterEach(async () => {
  await rm(fortress, { recursive: true, force: true });
});

const cursorPath = (): string => join(fortress, "state", EXPORT_CURSOR_FILENAME);

async function writeRawCursor(value: unknown): Promise<void> {
  await mkdir(join(fortress, "state"), { recursive: true });
  await writeFile(cursorPath(), typeof value === "string" ? value : JSON.stringify(value));
}

async function readRawCursor(): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(cursorPath(), "utf8")) as Record<string, unknown>;
}

describe("FileExportCursorStore: authenticated round-trip", () => {
  it("reads the start sentinel with NO reset when no cursor file exists (first run)", async () => {
    const store = new FileExportCursorStore(fortress, masterKey);
    const read = await store.read();
    expect(read.state).toEqual({ sequence: EXPORT_CURSOR_START, entryHash: null });
    expect(read.reset).toBeNull();
  });

  it("persists an authenticated cursor a FRESH store instance reads back (restart resume)", async () => {
    const writer = new FileExportCursorStore(fortress, masterKey);
    await writer.write({ sequence: 42, entryHash: "abc123" });
    // A brand-new instance simulates a process restart: it resumes at 42, bound.
    const afterRestart = new FileExportCursorStore(fortress, masterKey);
    const read = await afterRestart.read();
    expect(read.state).toEqual({ sequence: 42, entryHash: "abc123" });
    expect(read.reset).toBeNull();
  });

  it("advances monotonically as later authenticated writes land", async () => {
    const store = new FileExportCursorStore(fortress, masterKey);
    await store.write({ sequence: 3, entryHash: "h3" });
    expect((await store.read()).state.sequence).toBe(3);
    await store.write({ sequence: 10, entryHash: "h10" });
    expect((await store.read()).state.sequence).toBe(10);
  });

  it("writes an authenticated v2 envelope (schema + data + mac; no bare top-level sequence)", async () => {
    const store = new FileExportCursorStore(fortress, masterKey);
    await store.write({ sequence: 7, entryHash: "h7" });
    const raw = await readRawCursor();
    expect(raw.schema).toBe("sanctuary.enforcement-export-cursor.v2");
    expect(raw.data).toEqual({ last_sequence: 7, entry_hash: "h7" });
    expect(typeof raw.mac).toBe("string");
    // The value is NOT at the top level anymore (it lives under the MAC'd `data`).
    expect(raw.last_sequence).toBeUndefined();
  });
});

describe("FileExportCursorStore: fail-LOUD on an un-authenticatable cursor", () => {
  it("DISCARDS a hand-written bare cursor (no MAC) as unauthenticated + loud", async () => {
    await writeRawCursor({ last_sequence: 999999999 });
    const store = new FileExportCursorStore(fortress, masterKey);
    const read = await store.read();
    expect(read.state).toEqual({ sequence: EXPORT_CURSOR_START, entryHash: null });
    expect(read.reset?.reason).toBe("cursor_unauthenticated");
  });

  it("DISCARDS a legacy v1 record (schema present, no MAC) as unauthenticated", async () => {
    await writeRawCursor({ schema: "sanctuary.enforcement-export-cursor.v1", last_sequence: 500 });
    const store = new FileExportCursorStore(fortress, masterKey);
    const read = await store.read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_unauthenticated");
  });

  it("DISCARDS a poisoned high cursor whose MAC does not verify (the headline attack)", async () => {
    // Author a plausible-looking authenticated envelope but with a forged MAC.
    await writeRawCursor({
      schema: "sanctuary.enforcement-export-cursor.v2",
      data: { last_sequence: 999999999, entry_hash: "deadbeef" },
      mac: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    const store = new FileExportCursorStore(fortress, masterKey);
    const read = await store.read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_mac_invalid");
  });

  it("DISCARDS a cursor written under a DIFFERENT master key (cross-fortress MAC rejection)", async () => {
    const otherKey = generateRandomKey();
    await new FileExportCursorStore(fortress, otherKey).write({ sequence: 5, entryHash: "h5" });
    // Reading with the real fortress key must reject the foreign MAC.
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_mac_invalid");
  });

  it("DISCARDS a cursor whose entry_hash was tampered while keeping the old MAC", async () => {
    // A legit write, then flip the authenticated entry_hash but keep the old MAC:
    // the MAC covers entry_hash, so this is a mismatch (identity anchor is bound).
    await new FileExportCursorStore(fortress, masterKey).write({ sequence: 8, entryHash: "goodhash" });
    const raw = await readRawCursor();
    (raw.data as Record<string, unknown>).entry_hash = "eviltamperedhash";
    await writeRawCursor(raw);
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_mac_invalid");
  });

  it("DISCARDS a cursor whose last_sequence was tampered while keeping the old MAC", async () => {
    await new FileExportCursorStore(fortress, masterKey).write({ sequence: 8, entryHash: "goodhash" });
    const raw = await readRawCursor();
    (raw.data as Record<string, unknown>).last_sequence = 999999999;
    await writeRawCursor(raw);
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_mac_invalid");
  });

  it("DISCARDS a garbage (non-JSON) cursor file as corrupt + loud", async () => {
    await writeRawCursor("not json at all");
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_corrupt");
  });

  it("DISCARDS an authenticated envelope with a wrong-typed last_sequence as malformed", async () => {
    // Shape check fires before MAC verification; the data type is wrong.
    await writeRawCursor({
      schema: "sanctuary.enforcement-export-cursor.v2",
      data: { last_sequence: "not-a-number", entry_hash: "h" },
      mac: "AAAA",
    });
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_malformed");
  });

  it("is LOUD (reset, not silent) on a non-ENOENT read error", async () => {
    // Make `<fortress>/state` a regular FILE so the cursor path resolves under a
    // non-directory: readFile then throws ENOTDIR (a non-ENOENT error), which must
    // fail-safe to start WITH a loud reset — never a silent re-scan storm. This is
    // deterministic across environments (no reliance on chmod, which root bypasses).
    await writeFile(join(fortress, "state"), "i am a file, not a directory");
    const read = await new FileExportCursorStore(fortress, masterKey).read();
    expect(read.state.sequence).toBe(EXPORT_CURSOR_START);
    expect(read.reset?.reason).toBe("cursor_unreadable");
  });

  it("a re-authored valid cursor after a reset round-trips cleanly (self-heal)", async () => {
    await writeRawCursor({ last_sequence: 5 }); // unauthenticated
    const store = new FileExportCursorStore(fortress, masterKey);
    expect((await store.read()).reset?.reason).toBe("cursor_unauthenticated");
    // Writing a fresh authenticated cursor heals it: the next read is clean.
    await store.write({ sequence: 12, entryHash: "h12" });
    const healed = await store.read();
    expect(healed.state).toEqual({ sequence: 12, entryHash: "h12" });
    expect(healed.reset).toBeNull();
  });
});
