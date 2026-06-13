/**
 * Phase S1 — Rotation safety guard (review M3).
 *
 * `isRotationInProgress` is the gate the supervisor consults before launching:
 * while a master-rotation journal exists the fortress is split between old and
 * new masters, so a supervised child must NOT launch under the resident old
 * master. Mirrors the `establishMaster` / `rotateMaster` journal check.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { ROTATION_JOURNAL_KEY } from "../../src/core/master-custody.js";
import { isRotationInProgress } from "../../src/supervisor/rotation-guard.js";

describe("isRotationInProgress", () => {
  it("is false on a clean fortress (no journal)", async () => {
    const storage = new MemoryStorage();
    expect(await isRotationInProgress(storage)).toBe(false);
  });

  it("is true while a rotation journal exists", async () => {
    const storage = new MemoryStorage();
    await storage.write("_meta", ROTATION_JOURNAL_KEY, new Uint8Array([1]));
    expect(await isRotationInProgress(storage)).toBe(true);
  });

  it("fails closed (true) when the journal read throws", async () => {
    const storage = {
      read: async () => {
        throw new Error("storage down");
      },
    } as unknown as MemoryStorage;
    expect(await isRotationInProgress(storage)).toBe(true);
  });
});
