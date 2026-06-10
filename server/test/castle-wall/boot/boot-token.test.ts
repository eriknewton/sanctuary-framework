import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  BOOT_TOKEN_LENGTH,
  deriveSafeModeAuditKey,
  generateBootToken,
  persistBootToken,
  readBootToken,
} from "../../../src/castle-wall/boot/boot-token.js";

describe("castle-wall boot token (F1 Option C)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeTemp(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "boot-token-"));
    tempDirs.push(dir);
    return dir;
  }

  describe("generateBootToken", () => {
    it("returns exactly 32 random bytes that differ across calls", () => {
      const a = generateBootToken();
      const b = generateBootToken();
      expect(a.length).toBe(BOOT_TOKEN_LENGTH);
      expect(b.length).toBe(BOOT_TOKEN_LENGTH);
      expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });
  });

  describe("persistBootToken", () => {
    it("writes the token 0600 and round-trips it", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      const token = generateBootToken();

      const written = await persistBootToken(token, { path });
      expect(written).toBe(path);

      const info = await stat(path);
      expect(info.mode & 0o777).toBe(0o600);
      const raw = await readFile(path);
      expect(Buffer.from(raw).equals(Buffer.from(token))).toBe(true);
    });

    it("calls chownFn with root:wheel when provided (the root provision path)", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      const calls: Array<{ cmd: string; args: string[] }> = [];
      await persistBootToken(generateBootToken(), {
        path,
        chownFn: (cmd, args) => {
          calls.push({ cmd, args });
          return { code: 0, stderr: "" };
        },
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]!.cmd).toBe("chown");
      expect(calls[0]!.args[0]).toBe("root:wheel");
    });

    it("throws if chown fails (refuses an operator-rewritable token)", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      await expect(
        persistBootToken(generateBootToken(), {
          path,
          chownFn: () => ({ code: 1, stderr: "Operation not permitted" }),
        }),
      ).rejects.toThrow(/chown the boot token/);
    });

    it("rejects a token that is not 32 bytes", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      await expect(
        persistBootToken(new Uint8Array(16), { path }),
      ).rejects.toThrow(/32 bytes/);
    });
  });

  describe("readBootToken", () => {
    it("reads back a well-formed 0600 token", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      const token = generateBootToken();
      await persistBootToken(token, { path });

      const result = await readBootToken({ path });
      expect(result.status).toBe("ok");
      if (result.status === "ok") {
        expect(Buffer.from(result.token).equals(Buffer.from(token))).toBe(true);
      }
    });

    it("returns not-found when the token is absent", async () => {
      const dir = await makeTemp();
      const result = await readBootToken({ path: join(dir, "absent.bin") });
      expect(result.status).toBe("not-found");
    });

    it("fails closed when the token is group/other-readable (bad mode)", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      await writeFile(path, Buffer.from(generateBootToken()), { mode: 0o600 });
      await chmod(path, 0o644);

      const result = await readBootToken({ path });
      expect(result.status).toBe("bad-mode");
      if (result.status === "bad-mode") {
        expect(result.mode & 0o077).not.toBe(0);
      }
    });

    it("fails closed when the token is the wrong length", async () => {
      const dir = await makeTemp();
      const path = join(dir, "castle-wall-boot-token.bin");
      await writeFile(path, Buffer.alloc(10, 9), { mode: 0o600 });

      const result = await readBootToken({ path });
      expect(result.status).toBe("bad-length");
      if (result.status === "bad-length") {
        expect(result.length).toBe(10);
      }
    });
  });

  describe("deriveSafeModeAuditKey", () => {
    it("derives a deterministic 32-byte key, distinct per token", () => {
      const tokenA = generateBootToken();
      const tokenB = generateBootToken();
      const keyA1 = deriveSafeModeAuditKey(tokenA);
      const keyA2 = deriveSafeModeAuditKey(tokenA);
      const keyB = deriveSafeModeAuditKey(tokenB);

      expect(keyA1.length).toBe(32);
      expect(Buffer.from(keyA1).equals(Buffer.from(keyA2))).toBe(true);
      expect(Buffer.from(keyA1).equals(Buffer.from(keyB))).toBe(false);
      // The audit key is NOT the raw token (domain-separated derivation).
      expect(Buffer.from(keyA1).equals(Buffer.from(tokenA))).toBe(false);
    });

    it("rejects a token that is not 32 bytes", () => {
      expect(() => deriveSafeModeAuditKey(new Uint8Array(8))).toThrow(/32 bytes/);
    });
  });
});
