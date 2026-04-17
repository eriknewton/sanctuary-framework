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
  persistUserProvidedPassphrase,
  generatePassphrase,
  fallbackFilePath,
  PassphraseUnreadableError,
  type ExecResult,
} from "../../src/cocoon/passphrase.js";

/**
 * Deterministic key deriver with a caller-chosen seed — used by the SEC-062
 * tests to simulate a machine-key mismatch without touching real hostname /
 * uid / username. Same seed = same key (readable); different seed = different
 * key (unreadable by design).
 */
function makeDeterministicDeriver(seed: string): (home: string) => Uint8Array {
  return (_home: string) => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = (seed.charCodeAt(i % seed.length) ^ (i * 31)) & 0xff;
    }
    return bytes;
  };
}

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

// ── SEC-062 regression: fallback file must distinguish NOT_FOUND from
//    UNREADABLE and never silently regenerate over the latter. ────────────

describe("passphrase — SEC-062 unreadable-file handling", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-passphrase-sec062-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("throws PassphraseUnreadableError when the fallback file exists but cannot be decrypted", async () => {
    const { exec } = makeExec();
    const originalDeriver = makeDeterministicDeriver("original-machine-key");
    const migratedDeriver = makeDeterministicDeriver("migrated-machine-key");

    // Seed the fallback file under the ORIGINAL deriver.
    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: originalDeriver,
    });
    expect(first.source).toBe("generated");
    const fallback = fallbackFilePath(home);
    const originalBytes = await readFile(fallback);

    // Now simulate a machine migration — same file, different deriver.
    await expect(
      getOrCreatePassphrase({
        home,
        platformOverride: "linux",
        exec,
        deriveMachineKey: migratedDeriver,
      })
    ).rejects.toThrow(PassphraseUnreadableError);

    // Critical: the fallback file contents MUST NOT have been overwritten.
    const afterBytes = await readFile(fallback);
    expect(afterBytes.equals(originalBytes)).toBe(true);
  });

  it("readStoredPassphrase also throws on an unreadable fallback file", async () => {
    const { exec } = makeExec();
    const originalDeriver = makeDeterministicDeriver("original-machine-key");
    const migratedDeriver = makeDeterministicDeriver("migrated-machine-key");

    await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: originalDeriver,
    });

    await expect(
      readStoredPassphrase({
        home,
        platformOverride: "linux",
        exec,
        deriveMachineKey: migratedDeriver,
      })
    ).rejects.toThrow(PassphraseUnreadableError);
  });

  it("generates fresh passphrase only when fallback file does not exist; a second call reads it back without regenerating", async () => {
    const { exec } = makeExec();
    const deriver = makeDeterministicDeriver("stable-machine-key");

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: deriver,
    });
    expect(first.source).toBe("generated");

    const second = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: deriver,
    });
    expect(second.source).toBe("fallback-file");
    expect(second.value).toBe(first.value);
  });

  it("PassphraseUnreadableError message names the file path and lists recovery options", async () => {
    const { exec } = makeExec();
    const originalDeriver = makeDeterministicDeriver("original-machine-key");
    const migratedDeriver = makeDeterministicDeriver("migrated-machine-key");

    await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: originalDeriver,
    });

    try {
      await getOrCreatePassphrase({
        home,
        platformOverride: "linux",
        exec,
        deriveMachineKey: migratedDeriver,
      });
      throw new Error("expected PassphraseUnreadableError");
    } catch (err) {
      expect(err).toBeInstanceOf(PassphraseUnreadableError);
      const msg = (err as Error).message;
      expect(msg).toContain(fallbackFilePath(home));
      expect(msg).toContain("SANCTUARY_PASSPHRASE");
      expect(msg.toLowerCase()).toContain("backup");
    }
  });

  it("Keychain wins when it has a valid value even if the fallback file is unreadable (darwin)", async () => {
    // Seed Keychain with a known value.
    const { exec, stored } = makeExec();
    stored.set("sanctuary:sanctuary-passphrase", "known-keychain-value");

    // Write a fallback file with one deriver, then try to read with another —
    // but since Keychain is populated, the fallback should never be touched.
    const originalDeriver = makeDeterministicDeriver("original-machine-key");
    const migratedDeriver = makeDeterministicDeriver("migrated-machine-key");

    // Seed fallback file too (to exercise the "both present" branch).
    await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec,
      deriveMachineKey: originalDeriver,
    });

    const result = await getOrCreatePassphrase({
      home,
      platformOverride: "darwin",
      exec,
      deriveMachineKey: migratedDeriver,
    });
    expect(result.source).toBe("keychain");
    expect(result.value).toBe("known-keychain-value");
  });
});

// ── persistUserProvidedPassphrase: one-time setter for --passphrase flag ───

describe("persistUserProvidedPassphrase", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-persist-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("writes to Keychain on darwin and returns source=keychain", async () => {
    const { exec, stored } = makeExec();
    const result = await persistUserProvidedPassphrase("user-supplied-value", {
      home,
      platformOverride: "darwin",
      exec,
    });
    expect(result.source).toBe("keychain");
    expect(result.location).toBe("macOS Keychain");
    expect(stored.get("sanctuary:sanctuary-passphrase")).toBe(
      "user-supplied-value"
    );
  });

  it("writes to fallback file on linux and returns source=fallback-file", async () => {
    const { exec } = makeExec();
    const result = await persistUserProvidedPassphrase("user-supplied-value", {
      home,
      platformOverride: "linux",
      exec,
    });
    expect(result.source).toBe("fallback-file");
    expect(result.location).toBe(fallbackFilePath(home));
    // And the value round-trips through the store.
    const readBack = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec,
    });
    expect(readBack?.value).toBe("user-supplied-value");
  });

  it("falls back to the file when Keychain write fails on darwin", async () => {
    const exec = async (
      cmd: string,
      args: string[]
    ): Promise<ExecResult> => {
      if (cmd === "security" && args[0] === "add-generic-password") {
        return { stdout: "", stderr: "keychain locked", code: 1 };
      }
      return { stdout: "", stderr: "", code: 0 };
    };
    const result = await persistUserProvidedPassphrase("user-supplied-value", {
      home,
      platformOverride: "darwin",
      exec,
    });
    expect(result.source).toBe("fallback-file");
  });
});
