/**
 * Linux Secret Service keychain backend regression tests.
 *
 * These tests exercise the branch added in the v0.10.1 Linux keychain
 * backlog item: on Linux hosts with a D-Bus session bus and a libsecret-
 * compatible Secret Service provider (GNOME Keyring, KDE Wallet 6,
 * KeePassXC, etc.), Sanctuary stores the per-tenant passphrase in the OS
 * keyring instead of the machine-local encrypted fallback file.
 *
 * Test isolation rules:
 *   - Every test injects a mock `exec` function so the real `secret-tool`
 *     binary is never invoked. Running these against a live Secret Service
 *     would pollute the developer's keyring with test passphrases.
 *   - `platformOverride: "linux"` forces the Linux branch regardless of
 *     `process.platform`, so the tests run identically on macOS CI and
 *     Linux CI.
 *   - A separate mock per test; no shared global state between tests.
 *
 * See server/docs/keychain-schema.md for the canonical schema; this test
 * file is the executable contract.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getOrCreatePassphrase,
  readStoredPassphrase,
  persistUserProvidedPassphrase,
  fallbackFilePath,
  keychainServiceFor,
  isOsKeyringLocation,
  OS_KEYRING_LOCATION_LINUX,
  type ExecResult,
} from "../src/cocoon/passphrase.js";

type ExecCall = { cmd: string; args: string[]; input?: string };

interface MockHarness {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  calls: ExecCall[];
  /** Map from `service + "|" + account` to the stored passphrase. */
  stored: Map<string, string>;
  /** Switchable failure modes for individual tests. */
  mode: {
    lookupFailure: "none" | "not-found" | "dbus-unavailable" | "enoent";
    storeFailure: "none" | "dbus-unavailable" | "enoent" | "user-cancelled";
  };
}

/**
 * Create a fresh Secret Service mock. The mock's default behavior models a
 * healthy `secret-tool` + D-Bus session bus + keyring daemon combination:
 * `lookup` returns what was `store`d; unknown entries return exit 1 with no
 * stdout (matching `secret-tool lookup` behavior for a missing attribute
 * set).
 */
function makeSecretServiceMock(): MockHarness {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const harness = {
    calls,
    stored,
    mode: {
      lookupFailure: "none",
      storeFailure: "none",
    } as MockHarness["mode"],
    exec: null as unknown as MockHarness["exec"],
  };

  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    calls.push(input !== undefined ? { cmd, args, input } : { cmd, args });

    // Only secret-tool is routed here. Any other command is unknown and
    // treated as an unexpected shell-out that the Linux branch should never
    // make; the test asserts against calls to catch drift.
    if (cmd !== "secret-tool") {
      return { stdout: "", stderr: `unexpected command: ${cmd}`, code: 127 };
    }

    if (args[0] === "lookup") {
      if (harness.mode.lookupFailure === "enoent") {
        // Simulate `spawn` firing ENOENT for a missing binary. The mock
        // does not actually throw because the production code's exec
        // wrapper converts the spawn error into a rejected promise; our
        // mock models this with a synthetic ENOENT code so the call site
        // can observe the failure mode without needing a real ENOENT.
        throw Object.assign(new Error("secret-tool not found"), {
          code: "ENOENT",
        });
      }
      if (harness.mode.lookupFailure === "dbus-unavailable") {
        return {
          stdout: "",
          stderr:
            "Cannot autolaunch D-Bus without X11 $DISPLAY\n",
          code: 1,
        };
      }
      const service = getAttr(args, "service");
      const account = getAttr(args, "account");
      const key = `${service}|${account}`;
      const value = stored.get(key);
      if (value === undefined || harness.mode.lookupFailure === "not-found") {
        // `secret-tool lookup` with no match exits 1 and prints nothing to
        // stdout (confirmed against libsecret 0.20.5).
        return { stdout: "", stderr: "", code: 1 };
      }
      return { stdout: value, stderr: "", code: 0 };
    }

    if (args[0] === "store") {
      if (harness.mode.storeFailure === "enoent") {
        throw Object.assign(new Error("secret-tool not found"), {
          code: "ENOENT",
        });
      }
      if (harness.mode.storeFailure === "dbus-unavailable") {
        return {
          stdout: "",
          stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY\n",
          code: 1,
        };
      }
      if (harness.mode.storeFailure === "user-cancelled") {
        // `secret-tool store` returns 1 and prints "prompt dismissed" when
        // the unlock prompt is cancelled in GNOME Keyring.
        return { stdout: "", stderr: "prompt dismissed\n", code: 1 };
      }
      const value = (input ?? "").replace(/\r?\n$/, "");
      if (value.length === 0) {
        // Empty value is a programming error; mimic libsecret rejecting it.
        return { stdout: "", stderr: "empty value\n", code: 1 };
      }
      const service = getAttr(args, "service");
      const account = getAttr(args, "account");
      stored.set(`${service}|${account}`, value);
      return { stdout: "", stderr: "", code: 0 };
    }

    return { stdout: "", stderr: `unknown subcommand: ${args[0]}`, code: 2 };
  };
  harness.exec = exec;
  return harness;
}

/**
 * `secret-tool` takes attributes as alternating `key value` positional
 * arguments after the subcommand flags. Helper parses that back out.
 */
function getAttr(args: string[], key: string): string | undefined {
  // Skip subcommand + any -- flags until we hit the attributes.
  for (let i = 1; i < args.length - 1; i++) {
    if (args[i] === key) return args[i + 1];
  }
  return undefined;
}

describe("Linux Secret Service keychain backend", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-linux-ss-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  // ── Basic happy-path ────────────────────────────────────────────────

  it("stores the passphrase in Secret Service on first run and reads it back on the second", async () => {
    const h = makeSecretServiceMock();

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe(OS_KEYRING_LOCATION_LINUX);
    expect(isOsKeyringLocation(first.location)).toBe(true);
    expect(h.stored.size).toBe(1);

    const second = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(second.source).toBe("keychain");
    expect(second.value).toBe(first.value);
    expect(second.location).toBe(OS_KEYRING_LOCATION_LINUX);
  });

  it("invokes secret-tool with service, account, and label attributes matching the macOS schema", async () => {
    const h = makeSecretServiceMock();
    await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });

    const storeCall = h.calls.find(
      (c) => c.cmd === "secret-tool" && c.args[0] === "store"
    );
    expect(storeCall).toBeDefined();
    expect(getAttr(storeCall!.args, "service")).toBe("sanctuary-passphrase");
    expect(getAttr(storeCall!.args, "account")).toBe("sanctuary");
    // Label is a positional argument after --label.
    const labelIdx = storeCall!.args.indexOf("--label");
    expect(labelIdx).toBeGreaterThanOrEqual(0);
    expect(storeCall!.args[labelIdx + 1]).toBe("Sanctuary Passphrase");
    // Value is on stdin, not in argv.
    expect(storeCall!.input).toBeDefined();
    expect(storeCall!.args).not.toContain(storeCall!.input!.trim());
  });

  it("uses per-tenant service suffix derived from storage path (not default) when storagePath is non-default", async () => {
    const h = makeSecretServiceMock();
    const tenantPath = join(home, "tenant-alpha");

    const first = await getOrCreatePassphrase({
      home,
      storagePath: tenantPath,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(first.source).toBe("generated");

    const expectedService = keychainServiceFor(tenantPath, home);
    expect(expectedService).not.toBe("sanctuary-passphrase");
    expect(expectedService).toMatch(/^sanctuary-passphrase-[0-9a-f]{16}$/);

    // The stored item must be keyed by the per-tenant service.
    expect(h.stored.has(`${expectedService}|sanctuary`)).toBe(true);
    expect(h.stored.has(`sanctuary-passphrase|sanctuary`)).toBe(false);
  });

  it("two tenants with distinct storage paths get distinct Secret Service entries", async () => {
    const h = makeSecretServiceMock();
    const tenantA = join(home, "alpha");
    const tenantB = join(home, "beta");

    const a = await getOrCreatePassphrase({
      home,
      storagePath: tenantA,
      platformOverride: "linux",
      exec: h.exec,
    });
    const b = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "linux",
      exec: h.exec,
    });

    expect(a.value).not.toBe(b.value);
    expect(h.stored.size).toBe(2);

    // Reading B back must surface B's value, never A's.
    const reReadB = await getOrCreatePassphrase({
      home,
      storagePath: tenantB,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(reReadB.value).toBe(b.value);
    expect(reReadB.source).toBe("keychain");
  });

  // ── Fall-through to fallback file ───────────────────────────────────

  it("falls through to the encrypted fallback file when secret-tool is not installed", async () => {
    const h = makeSecretServiceMock();
    h.mode.storeFailure = "enoent";
    h.mode.lookupFailure = "enoent";

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe(fallbackFilePath(home));
    expect(h.stored.size).toBe(0);

    // File exists with non-plaintext content.
    await access(fallbackFilePath(home));
    const raw = await readFile(fallbackFilePath(home));
    expect(raw.toString("utf-8")).not.toContain(first.value);
  });

  it("falls through to the fallback file when the D-Bus session bus is unavailable", async () => {
    const h = makeSecretServiceMock();
    h.mode.storeFailure = "dbus-unavailable";
    h.mode.lookupFailure = "dbus-unavailable";

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe(fallbackFilePath(home));
    expect(isOsKeyringLocation(first.location)).toBe(false);
  });

  it("falls through to the fallback file when the keyring unlock prompt is cancelled", async () => {
    const h = makeSecretServiceMock();
    h.mode.storeFailure = "user-cancelled";

    const first = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(first.source).toBe("generated");
    expect(first.location).toBe(fallbackFilePath(home));
  });

  it("prefers Secret Service when it holds a value even if a fallback file also exists", async () => {
    const h = makeSecretServiceMock();
    // Seed the fallback file first under linux fallback behavior (force a
    // store failure on the initial call to force fallback-file write).
    h.mode.storeFailure = "dbus-unavailable";
    const seeded = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(seeded.location).toBe(fallbackFilePath(home));
    await access(fallbackFilePath(home));

    // Now "repair" Secret Service and seed a DIFFERENT value in it.
    h.mode.storeFailure = "none";
    h.mode.lookupFailure = "none";
    h.stored.set(
      `sanctuary-passphrase|sanctuary`,
      "keychain-holds-the-canonical-value"
    );

    const resolved = await getOrCreatePassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(resolved.source).toBe("keychain");
    expect(resolved.value).toBe("keychain-holds-the-canonical-value");
    expect(resolved.location).toBe(OS_KEYRING_LOCATION_LINUX);
    // Critically: the resolved value is NOT the one in the fallback file.
    expect(resolved.value).not.toBe(seeded.value);
  });

  // ── persistUserProvidedPassphrase ───────────────────────────────────

  it("persistUserProvidedPassphrase writes to Secret Service on linux and returns source=keychain", async () => {
    const h = makeSecretServiceMock();

    const result = await persistUserProvidedPassphrase("user-provided-val", {
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(result.source).toBe("keychain");
    expect(result.location).toBe(OS_KEYRING_LOCATION_LINUX);
    expect(h.stored.get(`sanctuary-passphrase|sanctuary`)).toBe(
      "user-provided-val"
    );
  });

  it("persistUserProvidedPassphrase falls through to fallback file when Secret Service store fails", async () => {
    const h = makeSecretServiceMock();
    h.mode.storeFailure = "dbus-unavailable";

    const result = await persistUserProvidedPassphrase("user-provided-val", {
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(result.source).toBe("fallback-file");
    expect(result.location).toBe(fallbackFilePath(home));

    // And the value round-trips through the file after the failure.
    h.mode.lookupFailure = "dbus-unavailable";
    const readBack = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(readBack?.value).toBe("user-provided-val");
    expect(readBack?.source).toBe("fallback-file");
  });

  // ── readStoredPassphrase without generating ─────────────────────────

  it("readStoredPassphrase returns null when Secret Service has nothing and no fallback file exists", async () => {
    const h = makeSecretServiceMock();

    const result = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(result).toBeNull();
    // The lookup call MUST have gone out, so we know the Linux branch was
    // actually exercised.
    const lookupCalls = h.calls.filter(
      (c) => c.cmd === "secret-tool" && c.args[0] === "lookup"
    );
    expect(lookupCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("readStoredPassphrase returns the Secret Service value when one is stored", async () => {
    const h = makeSecretServiceMock();
    h.stored.set(`sanctuary-passphrase|sanctuary`, "pre-seeded-passphrase-val");

    const result = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(result).not.toBeNull();
    expect(result!.source).toBe("keychain");
    expect(result!.location).toBe(OS_KEYRING_LOCATION_LINUX);
    expect(result!.value).toBe("pre-seeded-passphrase-val");
  });

  // ── Value hygiene ───────────────────────────────────────────────────

  it("never passes the passphrase value in argv, only on stdin", async () => {
    const h = makeSecretServiceMock();
    const result = await persistUserProvidedPassphrase("secret-value-xyz", {
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(result.source).toBe("keychain");

    // Scan every recorded call's argv: the value must not appear anywhere.
    for (const c of h.calls) {
      for (const arg of c.args) {
        expect(arg).not.toContain("secret-value-xyz");
      }
    }
  });

  it("round-trips values that contain base64 special characters (/ + =)", async () => {
    const h = makeSecretServiceMock();
    // A 32-byte random value encoded as base64 typically includes /, +, =.
    const tricky = "abc+def/ghi+jkl/mno+pqr/stu+vwx/yz0+123/456=";

    const persisted = await persistUserProvidedPassphrase(tricky, {
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(persisted.source).toBe("keychain");

    const read = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec: h.exec,
    });
    expect(read?.value).toBe(tricky);
  });

  it("tolerates a trailing newline in the value returned by secret-tool lookup", async () => {
    // Some Secret Service backends or shim implementations may echo a
    // trailing newline. The read helper strips it defensively.
    const mockH = makeSecretServiceMock();
    const trailingNewlineExec = async (
      cmd: string,
      args: string[],
      input?: string
    ): Promise<ExecResult> => {
      if (cmd === "secret-tool" && args[0] === "lookup") {
        return {
          stdout: "canonical-value-from-keyring\n",
          stderr: "",
          code: 0,
        };
      }
      return mockH.exec(cmd, args, input);
    };

    const read = await readStoredPassphrase({
      home,
      platformOverride: "linux",
      exec: trailingNewlineExec,
    });
    expect(read?.value).toBe("canonical-value-from-keyring");
    expect(read?.value.endsWith("\n")).toBe(false);
  });

  // ── Linux branch does not fire on darwin ────────────────────────────

  it("does not invoke secret-tool when platformOverride is darwin", async () => {
    const h = makeSecretServiceMock();
    // Route /usr/bin/security calls to the same mock so we can count.
    const hybridExec = async (
      cmd: string,
      args: string[],
      input?: string
    ): Promise<ExecResult> => {
      if (cmd === "security") {
        // Simulate no entry and a successful add.
        if (args[0] === "find-generic-password") {
          return { stdout: "", stderr: "not found", code: 44 };
        }
        if (args[0] === "add-generic-password") {
          return { stdout: "", stderr: "", code: 0 };
        }
      }
      return h.exec(cmd, args, input);
    };

    await getOrCreatePassphrase({
      home,
      platformOverride: "darwin",
      exec: hybridExec,
    });

    // No secret-tool calls should have been recorded in the Linux mock.
    const ssCalls = h.calls.filter((c) => c.cmd === "secret-tool");
    expect(ssCalls).toHaveLength(0);
  });
});
