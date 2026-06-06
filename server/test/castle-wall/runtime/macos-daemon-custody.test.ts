/**
 * Fix-round coverage (gauntlet F-A2-1) for the A2/B2 root-ownership custody
 * change on the daemon side:
 *
 *  - evaluateGlobalPinTrust: the F-A2-1 #4 defense-in-depth decision — only a
 *    ROOT-OWNED pin is authoritative, and a root-owned pin that does NOT match
 *    the live helper key is a "mismatch" (fail closed). An operator-owned or
 *    absent pin is ignored (the sysext owner-gate handles it independently).
 *
 *  - writeActiveConfig: under helper-as-signer the custody directory is
 *    root-owned, so the operator-UID daemon cannot write its discovery file
 *    there. It must fall back to the operator-writable discovery path instead of
 *    crashing the daemon (a regression this change must NOT introduce).
 */

import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  evaluateGlobalPinTrust,
  writeActiveConfig,
} from "../../../src/castle-wall/runtime/macos-daemon.js";

describe("evaluateGlobalPinTrust (F-A2-1 #4 defense-in-depth)", () => {
  const live = new Uint8Array(32).fill(7);

  it("skips when no pin is on disk", () => {
    expect(evaluateGlobalPinTrust(null, live)).toBe("skip");
  });

  it("skips a non-root-owned pin even when the bytes differ", () => {
    // An operator-owned pin is NOT trusted here; the sysext owner-gate rejects it.
    const pin = { uid: 501, bytes: new Uint8Array(32).fill(9) };
    expect(evaluateGlobalPinTrust(pin, live)).toBe("skip");
  });

  it("matches a root-owned pin equal to the live key", () => {
    const pin = { uid: 0, bytes: new Uint8Array(32).fill(7) };
    expect(evaluateGlobalPinTrust(pin, live)).toBe("match");
  });

  it("flags a root-owned pin that differs (coordinated swap / stale)", () => {
    const pin = { uid: 0, bytes: new Uint8Array(32).fill(9) };
    expect(evaluateGlobalPinTrust(pin, live)).toBe("mismatch");
  });

  it("flags a root-owned pin of the wrong length", () => {
    const pin = { uid: 0, bytes: new Uint8Array(16).fill(7) };
    expect(evaluateGlobalPinTrust(pin, live)).toBe("mismatch");
  });
});

describe("writeActiveConfig — root-owned custody dir fallback (F-A2-1)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await chmod(dir, 0o700).catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  });

  const config = {
    socket_path: "/tmp/x.sock",
    fortress_id: "fort-1",
    pid: process.pid,
    started_at: "2026-06-05T00:00:00Z",
    pinned_pubkey_sha256: "abc",
  };

  it("falls back to the operator-writable path when the primary dir is unwritable", async () => {
    // Simulate the root-owned custody dir: a directory the daemon cannot write
    // into (no write bit). The primary write must EACCES and fall back.
    const lockedDir = await mkdtemp(join(tmpdir(), "cw-locked-"));
    const fallbackDir = await mkdtemp(join(tmpdir(), "cw-fallback-"));
    tempDirs.push(lockedDir, fallbackDir);

    const primary = join(lockedDir, "castle-active.json");
    const fallback = join(fallbackDir, "castle-active.json");
    await chmod(lockedDir, 0o500); // r-x, no write -> cannot create entries

    const written = await writeActiveConfig(primary, config, fallback);

    expect(written).toBe(fallback);
    const body = JSON.parse(await readFile(fallback, "utf8"));
    expect(body.fortress_id).toBe("fort-1");
  });

  it("writes the primary path when it is writable (no fallback needed)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-primary-"));
    tempDirs.push(dir);
    const primary = join(dir, "castle-active.json");
    const fallback = join(dir, "fallback.json");

    const written = await writeActiveConfig(primary, config, fallback);

    expect(written).toBe(primary);
    await expect(stat(fallback)).rejects.toThrow(); // fallback not used
  });
});
