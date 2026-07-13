import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { writeGlobalPinIfUnestablished } from "../../../src/castle-wall/global-pin/index.js";

/**
 * Direct unit tests for the global-pin immutability chokepoint. This is the ONE
 * enforced guard both global-pin writers (provision-pin in cli/castle-wall.ts
 * and the local-sign daemon in runtime/macos-daemon.ts) route through, so a
 * third writer cannot reintroduce the root-euid clobber fail-open. Testing it
 * directly - not only through its two callers - pins the invariant itself.
 */
describe("writeGlobalPinIfUnestablished (global-pin immutability chokepoint)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function tempPinPath() {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-globalpin-guard-"));
    tempDirs.push(dir);
    return join(dir, "castle-pinned-pubkey.bin");
  }

  const keyA = new Uint8Array(32).fill(0xaa);
  const keyB = new Uint8Array(32).fill(0xbb);

  it("no pin exists (ENOENT read) -> calls freshWrite and returns 'written'", async () => {
    const path = await tempPinPath();
    const freshWrite = vi.fn(async (p: string, k: Uint8Array) => {
      await writeFile(p, k);
    });
    const onRefuse = vi.fn();

    const outcome = await writeGlobalPinIfUnestablished(keyB, { path, freshWrite, onRefuse });

    expect(outcome).toBe("written");
    expect(freshWrite).toHaveBeenCalledOnce();
    expect(onRefuse).not.toHaveBeenCalled();
    expect(Buffer.compare(await readFile(path), Buffer.from(keyB))).toBe(0);
  });

  it("existing pin EQUALS incoming key -> 'idempotent', no write, no refusal", async () => {
    const path = await tempPinPath();
    await writeFile(path, Buffer.from(keyA));
    const freshWrite = vi.fn(async () => {});
    const onRefuse = vi.fn();

    const outcome = await writeGlobalPinIfUnestablished(keyA, { path, freshWrite, onRefuse });

    expect(outcome).toBe("idempotent");
    expect(freshWrite).not.toHaveBeenCalled();
    expect(onRefuse).not.toHaveBeenCalled();
  });

  it("existing pin DIFFERS from incoming key -> 'refused', never overwritten, onRefuse fired", async () => {
    const path = await tempPinPath();
    await writeFile(path, Buffer.from(keyA));
    const freshWrite = vi.fn(async () => {});
    const onRefuse = vi.fn();

    const outcome = await writeGlobalPinIfUnestablished(keyB, { path, freshWrite, onRefuse });

    expect(outcome).toBe("refused");
    expect(freshWrite).not.toHaveBeenCalled();
    expect(onRefuse).toHaveBeenCalledOnce();
    // The differing pin must be byte-for-byte intact.
    expect(Buffer.compare(await readFile(path), Buffer.from(keyA))).toBe(0);
  });

  it("INJECTED non-ENOENT read error -> fails CLOSED ('refused'), no write, regardless of euid", async () => {
    // Codex caveat fix: a real `chmod 000` file is still readable by root, so it
    // cannot exercise the present-but-unreadable fail-closed branch on a root CI
    // runner. An injected reader that throws EACCES exercises it deterministically
    // at ANY euid.
    const path = await tempPinPath();
    const eacces = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    const readExisting = vi.fn(async () => {
      throw eacces;
    });
    const freshWrite = vi.fn(async () => {});
    const onRefuse = vi.fn();

    const outcome = await writeGlobalPinIfUnestablished(keyB, {
      path,
      freshWrite,
      onRefuse,
      readExisting,
    });

    expect(outcome).toBe("refused");
    expect(freshWrite).not.toHaveBeenCalled(); // never write when we cannot prove safety
    expect(onRefuse).toHaveBeenCalledOnce();
  });

  it("freshWrite loses the create race (EEXIST) -> 'refused', treated as established", async () => {
    const path = await tempPinPath();
    // Read sees no pin (ENOENT), but the fresh write races and throws EEXIST.
    const eexist = Object.assign(new Error("EEXIST: file already exists"), { code: "EEXIST" });
    const freshWrite = vi.fn(async () => {
      throw eexist;
    });
    const onRefuse = vi.fn();

    const outcome = await writeGlobalPinIfUnestablished(keyB, { path, freshWrite, onRefuse });

    expect(outcome).toBe("refused");
    expect(freshWrite).toHaveBeenCalledOnce();
    expect(onRefuse).toHaveBeenCalledOnce();
  });

  it("freshWrite throws a NON-EEXIST error -> rethrown for the caller's own diagnostic", async () => {
    const path = await tempPinPath();
    const eacces = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    const freshWrite = vi.fn(async () => {
      throw eacces;
    });
    const onRefuse = vi.fn();

    await expect(
      writeGlobalPinIfUnestablished(keyB, { path, freshWrite, onRefuse }),
    ).rejects.toThrow("EACCES");
    // A rethrown fresh-write error is NOT a refusal (the caller emits its own
    // ENOENT/EACCES guidance), so onRefuse must not fire here.
    expect(onRefuse).not.toHaveBeenCalled();
  });
});
