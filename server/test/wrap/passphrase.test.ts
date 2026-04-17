/**
 * Passphrase storage tests.
 *
 * Covers the three paths:
 *   - macOS Keychain read/write (mocked via the exec injector)
 *   - Encrypted fallback file (real I/O against a temp HOME)
 *   - Generation when nothing is stored
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  readStoredPassphrase,
  generatePassphrase,
  fallbackFilePath,
  type ExecResult,
} from "../../src/cocoon/passphrase.js";

type ExecCall = { cmd: string; args: string[]; input?: string };

function makeExec(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  calls: ExecCall[];
  stored: Map<string, string>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const key = "sanctuary:sanctuary-passphrase";

  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    if (input !== undefined) calls.push({ cmd, args, input });
    else calls.push({ cmd, args });

    if (cmd === "security" && args[0] === "find-generic-password") {
      const value = stored.get(key);
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    if (cmd === "security" && args[0] === "add-generic-password") {
      const wIdx = args.indexOf("-w");
      if (wIdx < 0 || !args[wIdx + 1]) {
        return { stdout: "", stderr: "missing -w", code: 1 };
      }
      stored.set(key, args[wIdx + 1]!);
      return { stdout: "", stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };

  return { exec, calls, stored };
}

describe("passphrase", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-passphrase-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("generates a 32-byte base64 passphrase", () => {
    const v = generatePassphrase();
    // 32 bytes base64 → 44 chars with padding ('='); our helper keeps the padding.
    expect(v.length).toBeGreaterThanOrEqual(43);
    const v2 = generatePassphrase();
    expect(v).not.toBe(v2);
  });

  it("stores in Keychain on first run and reads it back on the second (darwin)", async () => {
    const { exec, stored } = makeExec();

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "darwin",
      exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe("macOS Keychain");
    expect(stored.size).toBe(1);

    const second = await getOrCreatePassphrase({
      home,
      platformOverride: "darwin",
      exec,
    });
    expect(second.source).toBe("keychain");
    expect(second.value).toBe(first.value);
    expect(second.location).toBe("macOS Keychain");
  });

  it("falls back to the encrypted file on non-darwin platforms", async () => {
    const { exec } = makeExec();

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe(fallbackFilePath(home));

    // File exists, has restricted mode (best-effort — vitest runs as user).
    const fallbackPath = fallbackFilePath(home);
    await access(fallbackPath);
    const raw = await readFile(fallbackPath);
    // Must NOT contain the plaintext passphrase.
    expect(raw.toString("utf-8")).not.toContain(first.value);

    const second = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    expect(second.source).toBe("fallback-file");
    expect(second.value).toBe(first.value);
  });

  it("falls back to file if Keychain write fails on darwin", async () => {
    const exec = async (
      cmd: string,
      args: string[]
    ): Promise<ExecResult> => {
      if (cmd === "security" && args[0] === "find-generic-password") {
        return { stdout: "", stderr: "not found", code: 44 };
      }
      // Simulate Keychain being unreachable (e.g., CI sandbox).
      return { stdout: "", stderr: "keychain unreachable", code: 1 };
    };

    const result = await getOrCreatePassphrase({
      home,
      platformOverride: "darwin",
      exec,
    });
    expect(result.source).toBe("generated");
    expect(result.location).toBe(fallbackFilePath(home));
  });

  it("readStoredPassphrase returns null when nothing is stored", async () => {
    const { exec } = makeExec();
    const result = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    expect(result).toBeNull();
  });

  it("readStoredPassphrase returns the stored value after wrap", async () => {
    const { exec } = makeExec();
    const created = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    const read = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    expect(read).not.toBeNull();
    expect(read!.value).toBe(created.value);
    expect(read!.source).toBe("fallback-file");
  });
});
