import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  writeSystemPinnedPublicKey,
  type DaemonSigner,
} from "../../../src/castle-wall/runtime/index.js";

/**
 * Second global-pin clobber path (Codex two-family gate P1): the local/dev-sign
 * branch of the daemon's `writeSystemPinnedPublicKey` previously rename-over-wrote
 * the global pin unconditionally, so a root local-sign daemon would silently
 * clobber an existing DIFFERING signer-owned pin - the same fail-open as
 * provision-pin, on a different path. It now routes through the shared
 * `writeGlobalPinIfUnestablished` chokepoint. These tests inject the global-pin
 * path (the existing `globalPinnedPublicKeyPath` seam) so no real `/Library`
 * path or root is needed. Helper mode must STILL early-return without writing.
 */
describe("writeSystemPinnedPublicKey (daemon global-pin write, P1 clobber path)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function tempPinPath() {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-system-pin-"));
    tempDirs.push(dir);
    // Nested subdir so the chokepoint's freshWrite mkdir(dirname) is exercised.
    return join(dir, "Sanctuary", "castle-pinned-pubkey.bin");
  }

  function localSigner(publicKey: Uint8Array): DaemonSigner {
    return {
      mode: "local",
      signingKeyId: "castle-wall:test-local",
      publicKey,
      signManifest: async (b) => b,
      signNonce: async (n) => n,
    };
  }

  function helperSigner(publicKey: Uint8Array): DaemonSigner {
    return {
      mode: "helper",
      signingKeyId: "castle-wall:test-helper",
      publicKey,
      signManifest: async (b) => b,
      signNonce: async (n) => n,
    };
  }

  const keyA = new Uint8Array(32).fill(0xaa);
  const keyB = new Uint8Array(32).fill(0xbb);

  it("REGRESSION: local-sign mode leaves an existing DIFFERING global pin byte-for-byte intact", async () => {
    const path = await tempPinPath();
    // A signer-owned pin (keyA) already exists; the local-sign daemon carries a
    // different key (keyB). Pre-fix, keyB would clobber keyA under root.
    await writeFile(await ensureDir(path), Buffer.from(keyA), { mode: 0o644 });

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await writeSystemPinnedPublicKey(localSigner(keyB), path);
      expect(Buffer.compare(await readFile(path), Buffer.from(keyA))).toBe(0);
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join("\n");
      expect(warned).toContain("already exists with a different key owned by the root signer helper");
      expect(warned).toContain("sanctuary castle-wall re-pin");
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("local-sign mode writes the pin when none exists yet (ENOENT), mode 0644", async () => {
    const path = await tempPinPath();
    await writeSystemPinnedPublicKey(localSigner(keyB), path);
    expect(Buffer.compare(await readFile(path), Buffer.from(keyB))).toBe(0);
    expect((await stat(path)).mode & 0o777).toBe(0o644);
  });

  it("local-sign mode is a no-op when the existing pin already equals the signer key", async () => {
    const path = await tempPinPath();
    await writeFile(await ensureDir(path), Buffer.from(keyA), { mode: 0o644 });
    const statBefore = await stat(path);

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await writeSystemPinnedPublicKey(localSigner(keyA), path);
      expect(Buffer.compare(await readFile(path), Buffer.from(keyA))).toBe(0);
      // Idempotent: no write, so mtime is untouched.
      expect((await stat(path)).mtimeMs).toBe(statBefore.mtimeMs);
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join("\n");
      expect(warned).not.toContain("re-pin");
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("helper mode NEVER writes the global pin (unchanged early-return)", async () => {
    const path = await tempPinPath();
    // Seed a differing pin to prove helper mode leaves it fully alone AND does
    // not even create the file when absent.
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await writeSystemPinnedPublicKey(helperSigner(keyB), path);
      // Nothing written: the file must not exist.
      await expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" });
      const errored = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
      expect(errored).toContain("owned by the root signer helper");
      expect(errored).toContain("daemon does not write it");
    } finally {
      errSpy.mockRestore();
    }
  });
});

/**
 * Create the parent directory for a nested pin path so a test can pre-seed the
 * pin file, then return the path unchanged.
 */
async function ensureDir(pinPath: string): Promise<string> {
  const { mkdir } = await import("node:fs/promises");
  const { dirname } = await import("node:path");
  await mkdir(dirname(pinPath), { recursive: true, mode: 0o755 });
  return pinPath;
}
