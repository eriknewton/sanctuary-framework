/**
 * Hermetic tests for the on-disk durable export cursor (`FileExportCursorStore`).
 *
 * Uses a throwaway temp fortress dir (never a real ~/.sanctuary). Proves the
 * crash/restart durability contract at the FILE level: a persisted cursor is read
 * back by a FRESH store instance (a simulated process restart), a missing cursor
 * fail-safes to the start sentinel (re-scan, never skip), and a garbage/tampered
 * cursor file also fail-safes to start rather than trusting a bad value.
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

let fortress: string;

beforeEach(async () => {
  fortress = await mkdtemp(join(tmpdir(), "cortex-export-cursor-"));
});

afterEach(async () => {
  await rm(fortress, { recursive: true, force: true });
});

describe("FileExportCursorStore", () => {
  it("reads the start sentinel when no cursor file exists yet (first run)", async () => {
    const store = new FileExportCursorStore(fortress);
    expect(await store.read()).toBe(EXPORT_CURSOR_START);
  });

  it("persists a cursor that a FRESH store instance reads back (restart resume)", async () => {
    const writer = new FileExportCursorStore(fortress);
    await writer.write(42);
    // A brand-new instance simulates a process restart: it must resume at 42.
    const afterRestart = new FileExportCursorStore(fortress);
    expect(await afterRestart.read()).toBe(42);
  });

  it("advances monotonically as later writes land", async () => {
    const store = new FileExportCursorStore(fortress);
    await store.write(3);
    expect(await store.read()).toBe(3);
    await store.write(10);
    expect(await store.read()).toBe(10);
  });

  it("writes a versioned JSON payload (no torn/partial file left behind)", async () => {
    const store = new FileExportCursorStore(fortress);
    await store.write(7);
    const raw = await readFile(join(fortress, "state", EXPORT_CURSOR_FILENAME), "utf8");
    const parsed = JSON.parse(raw);
    expect(parsed.schema).toBe("sanctuary.enforcement-export-cursor.v1");
    expect(parsed.last_sequence).toBe(7);
  });

  it("fail-safes to the start sentinel on a garbage cursor file (re-scan, never trust a bad value)", async () => {
    await mkdir(join(fortress, "state"), { recursive: true });
    await writeFile(join(fortress, "state", EXPORT_CURSOR_FILENAME), "not json at all");
    const store = new FileExportCursorStore(fortress);
    expect(await store.read()).toBe(EXPORT_CURSOR_START);
  });

  it("fail-safes to the start sentinel on a wrong-schema cursor file", async () => {
    await mkdir(join(fortress, "state"), { recursive: true });
    await writeFile(
      join(fortress, "state", EXPORT_CURSOR_FILENAME),
      JSON.stringify({ schema: "some.other.schema", last_sequence: 999 }),
    );
    const store = new FileExportCursorStore(fortress);
    expect(await store.read()).toBe(EXPORT_CURSOR_START);
  });
});
