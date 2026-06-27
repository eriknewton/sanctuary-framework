/**
 * Wrap-passphrase locked-keyring fail-closed break-tests (Finding 1, HIGH).
 *
 * Regression target (fortress-key-root-cause-2026-06-23 class, live in the
 * `sanctuary wrap --hermes` critical path): `readFromKeychain` /
 * `readFromSecretService` collapsed a LOCKED keyring (macOS error 36 /
 * errSecInteractionNotAllowed over SSH, -25308, or a Linux D-Bus failure) into
 * "passphrase absent". The caller then GENERATED a new passphrase and wrote it
 * with `add-generic-password -U`, CLOBBERING the existing entry and stranding
 * the fortress, while reporting a misleading "Custody Establishment Failed".
 *
 * The fix reuses the keychain-custody.ts classifier to give the passphrase read
 * three-state semantics and treats "unreachable" as a HARD fail-closed: the
 * read THROWS PassphraseKeyringUnreachableError and NO add/`-U` write is ever
 * attempted (the original keyring entry is untouched). A genuine
 * errSecItemNotFound (exit 44) still drives the first-wrap generate path.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  readStoredPassphrase,
  PassphraseKeyringUnreachableError,
  type ExecResult,
} from "../../src/wrap/passphrase.js";

type ExecCall = { cmd: string; args: string[]; input?: string };

/** A "find" call is a keyring READ; a `security -i` / `secret-tool store` is a WRITE. */
function isWriteCall(c: ExecCall): boolean {
  if (c.cmd === "security" && c.args[0] === "-i") return true;
  if (c.cmd === "secret-tool" && c.args[0] === "store") return true;
  return false;
}

/**
 * Mock exec whose keyring READS return a caller-chosen reply, recording every
 * call so a test can assert that NO write was attempted. An accidental write
 * would mutate `stored` (the keyring's pre-existing entry); we never let that
 * happen on the unreachable path, so `stored` is read-only here.
 */
function makeReadReplyExec(reply: {
  stdout?: string;
  stderr?: string;
  code: number | null;
}): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  calls: ExecCall[];
} {
  const calls: ExecCall[] = [];
  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    calls.push(input !== undefined ? { cmd, args, input } : { cmd, args });
    const isRead =
      (cmd === "security" && args[0] === "find-generic-password") ||
      (cmd === "secret-tool" && args[0] === "lookup");
    if (isRead) {
      return {
        stdout: reply.stdout ?? "",
        stderr: reply.stderr ?? "",
        code: reply.code,
      };
    }
    // Any write reaching here is the bug under test; surface it loudly so the
    // assertion below has something to catch, but record it in `calls` too.
    return { stdout: "", stderr: "unexpected write on a locked keyring", code: 0 };
  };
  return { exec, calls };
}

describe("wrap passphrase — locked/unreachable keyring fails closed (no clobber)", () => {
  let home: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-pp-locked-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("macOS error 36 (locked keychain) THROWS and attempts NO write", async () => {
    const { exec, calls } = makeReadReplyExec({
      code: 36,
      stderr: "User interaction is not allowed.",
    });
    await expect(
      getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "darwin",
        exec,
      })
    ).rejects.toBeInstanceOf(PassphraseKeyringUnreachableError);
    // The make-or-break invariant: the original entry was never overwritten.
    expect(calls.some(isWriteCall)).toBe(false);
  });

  it("macOS -25308 marker (interaction not allowed) THROWS and attempts NO write", async () => {
    const { exec, calls } = makeReadReplyExec({
      code: 1,
      stderr: "SecKeychainSearchCopyNext: -25308",
    });
    await expect(
      getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "darwin",
        exec,
      })
    ).rejects.toBeInstanceOf(PassphraseKeyringUnreachableError);
    expect(calls.some(isWriteCall)).toBe(false);
  });

  it("the thrown error names the keyring + remediation but NEVER any secret (constraint 6)", async () => {
    const { exec } = makeReadReplyExec({
      code: 36,
      stderr: "User interaction is not allowed.",
    });
    let thrown: unknown;
    try {
      await getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "darwin",
        exec,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(PassphraseKeyringUnreachableError);
    const msg = (thrown as Error).message;
    expect(msg).toContain("LOCKED");
    expect(msg).toContain("did NOT modify your stored passphrase");
    expect(msg).toContain("SANCTUARY_PASSPHRASE=");
    // No key bytes: the only base64-ish token allowed is the literal example.
    expect(msg).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);
  });

  it("readStoredPassphrase also fails closed on a locked keychain", async () => {
    const { exec, calls } = makeReadReplyExec({
      code: 36,
      stderr: "User interaction is not allowed.",
    });
    await expect(
      readStoredPassphrase({
        home,
        storagePath: home,
        platformOverride: "darwin",
        exec,
      })
    ).rejects.toBeInstanceOf(PassphraseKeyringUnreachableError);
    expect(calls.some(isWriteCall)).toBe(false);
  });

  it("Linux D-Bus / locked-collection failure THROWS and attempts NO write", async () => {
    const { exec, calls } = makeReadReplyExec({
      code: 1,
      stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY",
    });
    await expect(
      getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec,
      })
    ).rejects.toBeInstanceOf(PassphraseKeyringUnreachableError);
    expect(calls.some(isWriteCall)).toBe(false);
  });

  it("macOS errSecItemNotFound (exit 44) is a GENUINE miss: generates + stores (first-wrap path unchanged)", async () => {
    // A keyring that is reachable-but-empty must still drive first-wrap
    // generation, exactly as before. This proves the fail-closed path did NOT
    // swallow the legitimate not-found case.
    const stored = new Map<string, string>();
    const key = "sanctuary:sanctuary-passphrase";
    const calls: ExecCall[] = [];
    const exec = async (
      cmd: string,
      args: string[],
      input?: string
    ): Promise<ExecResult> => {
      calls.push(input !== undefined ? { cmd, args, input } : { cmd, args });
      if (cmd === "security" && args[0] === "find-generic-password") {
        const v = stored.get(key);
        return v
          ? { stdout: v + "\n", stderr: "", code: 0 }
          : { stdout: "", stderr: "could not be found", code: 44 };
      }
      if (cmd === "security" && args[0] === "-i") {
        const m = input?.match(/-w "((?:[^"\\]|\\.)*)"/);
        if (!m) return { stdout: "", stderr: "missing -w", code: 1 };
        stored.set(key, m[1].replace(/\\(.)/g, "$1"));
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "unknown", code: 1 };
    };

    const result = await getOrCreatePassphrase({
      home,
      storagePath: home,
      platformOverride: "darwin",
      exec,
    });
    expect(result.source).toBe("generated");
    // The genuine not-found path DOES write (stores the freshly generated value).
    expect(calls.some(isWriteCall)).toBe(true);
    expect(stored.get(key)).toBe(result.value);
  });

  it("Linux empty-stderr miss (exit 1) is a GENUINE miss, not unreachable", async () => {
    // secret-tool exits 1 with empty stderr for a clean "no such item"; this
    // must NOT be misread as a locked keyring (that would block the first wrap
    // on every fresh Linux host).
    const stored = new Map<string, string>();
    const key = "sanctuary:sanctuary-passphrase";
    const calls: ExecCall[] = [];
    const exec = async (
      cmd: string,
      args: string[],
      input?: string
    ): Promise<ExecResult> => {
      calls.push(input !== undefined ? { cmd, args, input } : { cmd, args });
      if (cmd === "secret-tool" && args[0] === "lookup") {
        const v = stored.get(key);
        return v
          ? { stdout: v, stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 1 };
      }
      if (cmd === "secret-tool" && args[0] === "store") {
        stored.set(key, (input ?? "").replace(/\r?\n$/, ""));
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "unknown", code: 1 };
    };

    const result = await getOrCreatePassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec,
    });
    expect(result.source).toBe("generated");
    expect(calls.some(isWriteCall)).toBe(true);
  });
});
