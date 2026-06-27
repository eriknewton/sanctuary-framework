/**
 * sanctuary init — fortress isolation tests (v1.1.1 hotfix Findings S + T)
 *
 * Findings S + T together meant the tooling had no working primitive for
 * "stand up a side-by-side fresh fortress" on v1.1.0. The init command
 * is the new primitive for that workflow. These tests pin:
 *
 *   - resolveFortressPath honors --fortress flag, SANCTUARY_FORTRESS_PATH
 *     env var, and SANCTUARY_STORAGE_PATH env var in the documented
 *     precedence order.
 *   - runInit creates the fortress directory at the resolved path,
 *     persists the recovery-key hash, and writes recovery-key.txt with
 *     the full plaintext key.
 *   - runInit refuses to overwrite a non-empty directory unless --force.
 *   - parseInitArgs round-trips every flag.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
  stat,
  symlink,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import {
  parseInitArgs,
  printInitHelp,
  resolveFortressPath,
  resolveNoPin,
  resolveNoIdentity,
  runInit as runInitRaw,
  type InitOptions,
  type RunInitDeps,
} from "../../src/wrap/init.js";
import {
  RECOVERY_KEY_FILENAME,
  RecoveryKeyOutputPathExistsError,
  RecoveryKeyOutputPathSymlinkError,
} from "../../src/wrap/recovery-key-disclosure.js";
import {
  RecoveryKeyKeychainStoreError,
  recoveryKeyServiceFor,
} from "../../src/wrap/keychain-custody.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

type ExecCall = { cmd: string; args: string[]; input?: string };

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`)
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}

function makeRecoveryKeychainMock(opts: {
  writeFails?: boolean;
  readBackOverride?: string;
} = {}): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  calls: ExecCall[];
  stored: Map<string, string>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();

  function keyFor(account: string, service: string): string {
    return `${account}:${service}`;
  }

  const exec = async (
    cmd: string,
    args: string[],
    input?: string
  ): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") {
      return { stdout: "", stderr: "unknown", code: 1 };
    }
    if (args[0] === "-i") {
      if (opts.writeFails) {
        return { stdout: "", stderr: "write failed", code: 1 };
      }
      const account = readSecurityToken(input, "-a");
      const service = readSecurityToken(input, "-s");
      const value = readSecurityToken(input, "-w");
      stored.set(keyFor(account, service), value);
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = opts.readBackOverride ?? stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };

  return { exec, calls, stored };
}

async function runInit(
  options: InitOptions,
  deps: RunInitDeps = {}
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    ...deps,
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}

async function runInitWithRecoveryKeychain(
  options: InitOptions,
  keychain = makeRecoveryKeychainMock(),
  deps: RunInitDeps = {}
): Promise<{
  result: Awaited<ReturnType<typeof runInitRaw>>;
  keychain: ReturnType<typeof makeRecoveryKeychainMock>;
}> {
  const result = await runInitRaw(options, {
    ...deps,
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
  return { result, keychain };
}

function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}

describe("resolveFortressPath", () => {
  it("returns ~/.sanctuary when no flag or env var is set", () => {
    const path = resolveFortressPath({}, {}, "/tmp/test-home");
    expect(path).toBe("/tmp/test-home/.sanctuary");
  });

  it("honors the --fortress flag over env vars", () => {
    const path = resolveFortressPath(
      { fortress: "/tmp/explicit-fortress" },
      {
        SANCTUARY_FORTRESS_PATH: "/tmp/from-fortress-env",
        SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env",
      },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/explicit-fortress");
  });

  it("honors SANCTUARY_FORTRESS_PATH over SANCTUARY_STORAGE_PATH", () => {
    const path = resolveFortressPath(
      {},
      {
        SANCTUARY_FORTRESS_PATH: "/tmp/from-fortress-env",
        SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env",
      },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/from-fortress-env");
  });

  it("falls back to SANCTUARY_STORAGE_PATH when only that is set", () => {
    const path = resolveFortressPath(
      {},
      { SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env" },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/from-storage-env");
  });

  it("resolves relative paths against cwd", () => {
    const path = resolveFortressPath(
      { fortress: "./relative-fortress" },
      {},
      "/tmp/test-home",
    );
    expect(path.endsWith("/relative-fortress")).toBe(true);
    expect(path.startsWith("/")).toBe(true);
  });
});

describe("runInit", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-test-"));
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_RECOVERY_OUT;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  it("creates the fortress at --fortress <path>, NOT ~/.sanctuary", async () => {
    const fortressPath = join(tmp, "isolated-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
    });
    expect(result.fortressPath).toBe(fortressPath);

    // Recovery key file landed at the fortress path, not at HOME.
    expect(result.recoveryKeyDisclosurePath).toBe(
      join(fortressPath, RECOVERY_KEY_FILENAME),
    );
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(recoveryFile).toContain("Recovery key:");
    expect(recoveryFile).toContain(
      "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY",
    );

    // Crucially: ~/.sanctuary was NOT touched. We can't safely assert this
    // on a developer machine (it might already exist), but we CAN assert
    // the fortress isn't at the default location.
    expect(result.fortressPath).not.toBe(join(homedir(), ".sanctuary"));
  });

  it("stores the minted recovery key in a read-back-verified Keychain item", async () => {
    const fortressPath = join(tmp, "keychain-recovery-fortress");
    const { result, keychain } = await runInitWithRecoveryKeychain({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
    });

    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    const recoveryKey = extractRecoveryKey(recoveryFile);
    const service = recoveryKeyServiceFor(
      fortressPath,
      "/tmp/sanctuary-test-home",
    );

    expect(keychain.stored.get(`sanctuary:${service}`)).toBe(recoveryKey);

    const writeIndex = keychain.calls.findIndex(
      (call) => call.cmd === "security" && call.args[0] === "-i",
    );
    const readIndex = keychain.calls.findIndex(
      (call) =>
        call.cmd === "security" &&
        call.args[0] === "find-generic-password" &&
        call.args.includes(service),
    );
    expect(writeIndex).toBeGreaterThanOrEqual(0);
    expect(readIndex).toBeGreaterThan(writeIndex);
    expect(
      keychain.calls.some((call) => call.args.includes(recoveryKey)),
    ).toBe(false);
  });

  it("fails closed before custody state when recovery-key Keychain write fails", async () => {
    const fortressPath = join(tmp, "keychain-write-fails-fortress");
    const keychain = makeRecoveryKeychainMock({ writeFails: true });
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    let thrown: unknown;
    let consoleOutput = "";
    try {
      await runInitRaw(
        {
          fortress: fortressPath,
          noConfirm: true,
          noPin: true,
        },
        {
          recoveryKeychain: {
            home: "/tmp/sanctuary-test-home",
            platformOverride: "darwin",
            exec: keychain.exec,
          },
        },
      );
    } catch (err) {
      thrown = err;
    } finally {
      consoleOutput = consoleSpy.mock.calls
        .map((args) => args.join(" "))
        .join("\n");
      consoleSpy.mockRestore();
    }

    expect(thrown).toBeInstanceOf(RecoveryKeyKeychainStoreError);
    const writeInput = keychain.calls.find(
      (call) => call.cmd === "security" && call.args[0] === "-i",
    )?.input;
    const recoveryKey = readSecurityToken(writeInput, "-w");
    expect(recoveryKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect((thrown as Error).message).not.toContain(recoveryKey);
    expect(consoleOutput).not.toContain(recoveryKey);
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toThrow();
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });

  it("fails closed before custody state when recovery-key Keychain read-back mismatches", async () => {
    const fortressPath = join(tmp, "keychain-readback-fails-fortress");
    const keychain = makeRecoveryKeychainMock({
      readBackOverride: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });

    await expect(
      runInitRaw(
        {
          fortress: fortressPath,
          noConfirm: true,
          noPin: true,
        },
        {
          recoveryKeychain: {
            home: "/tmp/sanctuary-test-home",
            platformOverride: "darwin",
            exec: keychain.exec,
          },
        },
      ),
    ).rejects.toThrow(RecoveryKeyKeychainStoreError);

    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toThrow();
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });

  it("--recovery-out writes the recovery key to an external durable path without touching Keychain", async () => {
    const fortressPath = join(tmp, "external-recovery-fortress");
    const recoveryOut = join(tmp, "durable", "recovery-key.txt");
    const keychain = makeRecoveryKeychainMock({ writeFails: true });
    const { result } = await runInitWithRecoveryKeychain(
      {
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
      },
      keychain,
    );

    expect(result.fortressPath).toBe(fortressPath);
    expect(result.recoveryKeyDisclosurePath).toBe(recoveryOut);
    expect(keychain.calls).toHaveLength(0);
    const recoveryFile = await readFile(recoveryOut, "utf-8");
    expect(recoveryFile).toContain("Recovery key:");
    expect(recoveryFile).toContain(
      "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY",
    );
    const st = await stat(recoveryOut);
    expect(st.mode & 0o777).toBe(0o600);
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });

  it("SANCTUARY_RECOVERY_OUT writes to an external durable path without touching Keychain when the flag is absent", async () => {
    const fortressPath = join(tmp, "env-recovery-fortress");
    const recoveryOut = join(tmp, "env-durable", "recovery-key.txt");
    process.env.SANCTUARY_RECOVERY_OUT = recoveryOut;
    const keychain = makeRecoveryKeychainMock({ writeFails: true });

    const { result } = await runInitWithRecoveryKeychain(
      {
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
      },
      keychain,
    );

    expect(result.recoveryKeyDisclosurePath).toBe(recoveryOut);
    expect(keychain.calls).toHaveLength(0);
    const recoveryFile = await readFile(recoveryOut, "utf-8");
    expect(recoveryFile).toContain("Recovery key:");
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });

  it("refuses --recovery-out paths inside the fortress before init writes state", async () => {
    const fortressPath = join(tmp, "inside-recovery-fortress");
    const recoveryOut = join(fortressPath, "backup", "recovery-key.txt");

    await expect(
      runInit({
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
      }),
    ).rejects.toThrow(/outside the fortress/);

    await expect(stat(fortressPath)).rejects.toThrow();
    await expect(stat(recoveryOut)).rejects.toThrow();
  });

  it("refuses an existing --recovery-out file before init writes state", async () => {
    const fortressPath = join(tmp, "existing-recovery-out-fortress");
    const durableDir = join(tmp, "existing-durable");
    const recoveryOut = join(durableDir, "recovery-key.txt");
    await mkdir(durableDir, { recursive: true });
    await writeFile(recoveryOut, "old key", { mode: 0o600 });

    await expect(
      runInit({
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
      }),
    ).rejects.toThrow(RecoveryKeyOutputPathExistsError);

    await expect(stat(fortressPath)).rejects.toThrow();
    await expect(readFile(recoveryOut, "utf-8")).resolves.toBe("old key");
  });

  it("aborts without custody state when --recovery-out appears after preflight", async () => {
    const fortressPath = join(tmp, "raced-recovery-out-fortress");
    const durableDir = join(tmp, "raced-durable");
    const recoveryOut = join(durableDir, "recovery-key.txt");
    await mkdir(durableDir, { recursive: true });

    await expect(
      runInit(
        {
          fortress: fortressPath,
          recoveryOut,
          noConfirm: true,
          noPin: true,
        },
        {
          beforeRecoveryKeyOutputWrite: async (filePath) => {
            expect(filePath).toBe(recoveryOut);
            await writeFile(filePath, "raced key", { mode: 0o600 });
          },
        },
      ),
    ).rejects.toThrow(RecoveryKeyOutputPathExistsError);

    await expect(readFile(recoveryOut, "utf-8")).resolves.toBe("raced key");
    await expect(stat(join(fortressPath, "state"))).rejects.toThrow();
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toThrow();
  });

  it("refuses a dangling --recovery-out symlink before init writes state", async () => {
    const fortressPath = join(tmp, "dangling-recovery-out-fortress");
    const durableDir = join(tmp, "dangling-durable");
    const recoveryOut = join(durableDir, "recovery-key.txt");
    const symlinkTarget = join(tmp, "outside-target.txt");
    await mkdir(durableDir, { recursive: true });
    await symlink(symlinkTarget, recoveryOut);

    await expect(
      runInit({
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
      }),
    ).rejects.toThrow(RecoveryKeyOutputPathSymlinkError);

    await expect(stat(fortressPath)).rejects.toThrow();
    await expect(stat(symlinkTarget)).rejects.toThrow();
  });

  it("persists a custody envelope whose recovery wrap unlocks the master on subsequent boots", async () => {
    const fortressPath = join(tmp, "fortress-with-envelope");
    const result = await runInit({ fortress: fortressPath, noConfirm: true });

    // Sovereign-custody build: the envelope replaces recovery-key-hash. It
    // lives under <fortress>/state/_meta/custody-envelope.enc and holds the
    // master ONLY as wraps; the recovery key is a wrap of the true master.
    const envelopeFile = join(
      fortressPath,
      "state",
      "_meta",
      "custody-envelope.enc",
    );
    const st = await stat(envelopeFile);
    expect(st.isFile()).toBe(true);
    expect(st.size).toBeGreaterThan(0);

    // End-to-end: the recovery key captured in recovery-key.txt actually
    // unwraps the master (the 2026-06-12 incident regression check).
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    const keyLine = recoveryFile
      .split("\n")
      .map((l) => l.trim())
      .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
    expect(keyLine).toBeDefined();

    const { FilesystemStorage } = await import(
      "../../src/storage/filesystem.js"
    );
    const { establishMaster } = await import(
      "../../src/core/master-custody.js"
    );
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const unlocked = await establishMaster({
      storage,
      recoveryKey: keyLine!,
    });
    expect(unlocked.masterKey.length).toBe(32);
    expect(unlocked.origin).toBe("envelope");
    // --no-confirm is an explicit, audited headless install mode (F13).
    expect(unlocked.envelope.install_mode).toBe("headless");
  });

  it("creates the fortress directory with mode 0700", async () => {
    const fortressPath = join(tmp, "mode-test-fortress");
    await runInit({ fortress: fortressPath, noConfirm: true });
    const st = await stat(fortressPath);
    // Mask off file-type bits; only permission bits matter.
    expect(st.mode & 0o777).toBe(0o700);
  });

  it("refuses to overwrite a non-empty fortress directory without --force", async () => {
    const fortressPath = join(tmp, "non-empty-fortress");
    await mkdir(fortressPath, { recursive: true });
    await writeFile(join(fortressPath, "operator-data.txt"), "important", {
      mode: 0o600,
    });

    await expect(
      runInit({ fortress: fortressPath, noConfirm: true }),
    ).rejects.toThrow(/not empty/);

    // Original file still present.
    const operatorData = await readFile(
      join(fortressPath, "operator-data.txt"),
      "utf-8",
    );
    expect(operatorData).toBe("important");
  });

  it("succeeds against a non-empty directory when --force is set", async () => {
    const fortressPath = join(tmp, "forced-fortress");
    await mkdir(fortressPath, { recursive: true });
    await writeFile(join(fortressPath, "stale-marker.txt"), "old", {
      mode: 0o600,
    });

    const result = await runInit({
      fortress: fortressPath,
      force: true,
      noConfirm: true,
    });
    expect(result.fortressPath).toBe(fortressPath);

    // recovery-key.txt was written despite the pre-existing content.
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(recoveryFile).toContain("Recovery key:");
  });

  it("recovery-key.txt is single-issuance: re-init with --force does NOT overwrite", async () => {
    const fortressPath = join(tmp, "single-issuance-fortress");
    const first = await runInit({ fortress: fortressPath, noConfirm: true });
    const firstContent = await readFile(
      first.recoveryKeyDisclosurePath,
      "utf-8",
    );

    // Second init under --force should NOT overwrite recovery-key.txt
    // (the disclosure helper enforces single-issuance regardless of caller).
    await runInit({ fortress: fortressPath, force: true, noConfirm: true });
    const afterSecond = await readFile(
      first.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(afterSecond).toBe(firstContent);
  });
});

describe("--no-pin (Castle Wall global-pin skip)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-nopin-test-"));
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_INIT_NO_PIN;
    delete process.env.SANCTUARY_RECOVERY_OUT;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  async function readSkipAudit(
    fortressPath: string,
    recoveryKeyDisclosurePath: string,
  ): Promise<Array<{ operation: string; details?: Record<string, unknown> }>> {
    const recoveryFile = await readFile(recoveryKeyDisclosurePath, "utf-8");
    const recoveryKey = recoveryFile
      .split("\n")
      .map((l) => l.trim())
      .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l))!;
    const { FilesystemStorage } = await import(
      "../../src/storage/filesystem.js"
    );
    const { establishMaster } = await import(
      "../../src/core/master-custody.js"
    );
    const { AuditLog } = await import(
      "../../src/operational/audit-log.js"
    );
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, recoveryKey });
    const reader = new AuditLog(storage, masterKey, {
      integrityMode: "lenient",
    });
    const result = await reader.query({ limit: 1000 });
    return result.entries as Array<{
      operation: string;
      details?: Record<string, unknown>;
    }>;
  }

  it("--no-pin NEVER invokes provision-pin (the global-anchor write path)", async () => {
    // Directly prove the invariant: the provision-pin call (which is what
    // writes the machine-wide /Library/Application Support/Sanctuary anchor)
    // is never reached. A spy is more robust than checking a per-fortress
    // file path, since it pins the actual code path that touches the anchor.
    const fortressPath = join(tmp, "no-pin-spy-fortress");
    let calls = 0;
    await runInit(
      { fortress: fortressPath, noConfirm: true, noPin: true },
      {
        provisionPin: async () => {
          calls++;
          return 0;
        },
      },
    );
    expect(calls).toBe(0);

    // And no per-fortress pinned key is written either.
    await expect(
      stat(join(fortressPath, "castle-pinned-pubkey.bin")),
    ).rejects.toThrow();
  });

  it("default init (no flag) DOES invoke provision-pin and writes the per-fortress key", async () => {
    const fortressPath = join(tmp, "default-pin-spy-fortress");
    let calls = 0;
    let sawStoragePath: string | undefined;
    await runInit(
      { fortress: fortressPath, noConfirm: true },
      {
        provisionPin: async (_argv, ctx) => {
          calls++;
          sawStoragePath = ctx?.env?.SANCTUARY_STORAGE_PATH;
          return 0;
        },
      },
    );
    expect(calls).toBe(1);
    expect(sawStoragePath).toBe(fortressPath);
  });

  it("default init with the REAL provision-pin writes the per-fortress pinned key", async () => {
    const fortressPath = join(tmp, "default-pin-real-fortress");
    await runInit({ fortress: fortressPath, noConfirm: true });

    const st = await stat(join(fortressPath, "castle-pinned-pubkey.bin"));
    expect(st.isFile()).toBe(true);
    expect(st.size).toBe(32);
  });

  it("--no-pin records an audited castle_pin_provision_skipped entry", async () => {
    const fortressPath = join(tmp, "no-pin-audit-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
    });

    const entries = await readSkipAudit(
      fortressPath,
      result.recoveryKeyDisclosurePath,
    );
    const skip = entries.find(
      (e) => e.operation === "castle_pin_provision_skipped",
    );
    expect(skip).toBeDefined();
    expect(skip!.details?.reason).toBe("--no-pin");
  });

  it("default init does NOT record a skip entry", async () => {
    const fortressPath = join(tmp, "default-no-skip-fortress");
    const result = await runInit({ fortress: fortressPath, noConfirm: true });

    const entries = await readSkipAudit(
      fortressPath,
      result.recoveryKeyDisclosurePath,
    );
    expect(
      entries.find((e) => e.operation === "castle_pin_provision_skipped"),
    ).toBeUndefined();
  });

  it("SANCTUARY_INIT_NO_PIN=1 skips provision-pin for non-interactive harnesses", async () => {
    const fortressPath = join(tmp, "env-no-pin-fortress");
    process.env.SANCTUARY_INIT_NO_PIN = "1";
    const result = await runInit({ fortress: fortressPath, noConfirm: true });

    await expect(
      stat(join(fortressPath, "castle-pinned-pubkey.bin")),
    ).rejects.toThrow();

    const entries = await readSkipAudit(
      fortressPath,
      result.recoveryKeyDisclosurePath,
    );
    const skip = entries.find(
      (e) => e.operation === "castle_pin_provision_skipped",
    );
    expect(skip).toBeDefined();
    expect(skip!.details?.reason).toBe("SANCTUARY_INIT_NO_PIN");
  });

  it("resolveNoPin uses an allowlist for the env var, not 'anything truthy'", () => {
    expect(resolveNoPin({ noPin: true }, {})).toBe(true);
    expect(resolveNoPin({}, {})).toBe(false);
    // Explicit opt-in values (case-insensitive, trimmed).
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "1" })).toBe(true);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "true" })).toBe(true);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "TRUE" })).toBe(true);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "yes" })).toBe(true);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: " on " })).toBe(true);
    // Anything NOT on the allowlist does NOT opt out (downgrade safety):
    // typos, inherited values, and ambiguous words are all ignored.
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "0" })).toBe(false);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "false" })).toBe(false);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "" })).toBe(false);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "no" })).toBe(false);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "off" })).toBe(false);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "flase" })).toBe(false);
    // Flag wins regardless of env.
    expect(resolveNoPin({ noPin: true }, { SANCTUARY_INIT_NO_PIN: "0" })).toBe(
      true,
    );
  });
});

describe("--no-identity (default operator-identity seed)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-noidentity-test-"));
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_INIT_NO_IDENTITY;
    delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  async function recoveryKeyFor(
    recoveryKeyDisclosurePath: string,
  ): Promise<string> {
    const recoveryFile = await readFile(recoveryKeyDisclosurePath, "utf-8");
    return extractRecoveryKey(recoveryFile);
  }

  it("default init seeds a default operator identity findable by IdentityManager", async () => {
    const fortressPath = join(tmp, "seeded-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
    });
    const recoveryKey = await recoveryKeyFor(result.recoveryKeyDisclosurePath);

    const { FilesystemStorage } = await import(
      "../../src/storage/filesystem.js"
    );
    const { establishMaster } = await import(
      "../../src/core/master-custody.js"
    );
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, recoveryKey });
    const im = new IdentityManager(storage, masterKey);
    await im.load();
    const def = im.getDefault();
    expect(def).toBeDefined();
    expect(def!.label).toBe("operator");
    masterKey.fill(0);
  });

  it("a federation operator-signing call finds the seeded identity", async () => {
    const fortressPath = join(tmp, "fed-signer-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
    });
    const recoveryKey = await recoveryKeyFor(result.recoveryKeyDisclosurePath);

    const { openOperatorSigner } = await import(
      "../../src/cli/federation-operator-signing.js"
    );
    const signer = await openOperatorSigner({
      recoveryKey,
      fortressPath,
    });
    try {
      expect(signer.operatorPublicKey.length).toBe(32);
      // The signer can actually produce an operator signature.
      const sig = signer.signPayload("federation_enable", { fortress_id: "x" });
      expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    } finally {
      signer.masterKey.fill(0);
    }
  });

  it("--no-identity leaves NO operator identity in the fortress", async () => {
    const fortressPath = join(tmp, "no-identity-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });
    const recoveryKey = await recoveryKeyFor(result.recoveryKeyDisclosurePath);

    const { FilesystemStorage } = await import(
      "../../src/storage/filesystem.js"
    );
    const { establishMaster } = await import(
      "../../src/core/master-custody.js"
    );
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, recoveryKey });
    const im = new IdentityManager(storage, masterKey);
    const loadResult = await im.load();
    expect(loadResult.total).toBe(0);
    expect(im.getDefault()).toBeUndefined();
    masterKey.fill(0);
  });

  it("seeds EXACTLY ONE operator identity (no double-seed) and the guard's predicate holds under a reused master", async () => {
    // A default init seeds exactly one identity (never two). We then assert
    // the idempotency guard's PREDICATE directly: under the SAME master, an
    // IdentityManager that already has a default identity reports it via
    // getDefault() — the exact check init runs before minting. Note this is
    // NOT reachable through a normal runInit (a fresh init has an empty
    // fortress and a --force re-init derives a new random master under which
    // the prior identity is invisible, not skipped); the guard is defensive
    // for any future caller that seeds under an already-established master,
    // and this asserts that predicate without exercising it via init itself.
    const fortressPath = join(tmp, "idempotent-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
    });
    const recoveryKey = await recoveryKeyFor(result.recoveryKeyDisclosurePath);

    const { FilesystemStorage } = await import(
      "../../src/storage/filesystem.js"
    );
    const { establishMaster } = await import(
      "../../src/core/master-custody.js"
    );
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, recoveryKey });

    // Default init left exactly one identity — never two.
    const im = new IdentityManager(storage, masterKey);
    const loadResult = await im.load();
    expect(loadResult.loaded).toBe(1);
    const seededId = im.getDefault()!.identity_id;

    // The guard's exact predicate: re-loading under the same master surfaces
    // the existing default via getDefault(). When that predicate is true the
    // seed step short-circuits (no second mint); here we assert the predicate
    // itself, not init's branch selection.
    const im2 = new IdentityManager(storage, masterKey);
    await im2.load();
    expect(im2.getDefault()).toBeDefined();
    expect(im2.getDefault()!.identity_id).toBe(seededId);
    masterKey.fill(0);
  });

  it("fails closed (and provisions no pin) when identity minting fails and --no-identity was NOT passed", async () => {
    // Inject a saveNew that throws, simulating an identity-mint failure on a
    // default (no --no-identity) init. init must FAIL and must NOT proceed to
    // the pin step — never a half-provisioned fortress.
    const fortressPath = join(tmp, "fail-closed-fortress");
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const saveNewSpy = vi
      .spyOn(IdentityManager.prototype, "saveNew")
      .mockRejectedValue(new Error("injected mint failure"));
    let pinCalls = 0;
    try {
      await expect(
        runInit(
          { fortress: fortressPath, noConfirm: true, noPin: true },
          {
            provisionPin: async () => {
              pinCalls++;
              return 0;
            },
          },
        ),
      ).rejects.toThrow(/operator identity seed failed/);
    } finally {
      saveNewSpy.mockRestore();
    }
    // Fail-closed: the pin step was never reached.
    expect(pinCalls).toBe(0);
  });

  it("the seed-failure remediation message is honest: identity create OR --force, never the broken 'Re-run init'", async () => {
    // Finding 2 (2026-06-25): the old message said "Re-run init", but a plain
    // `init` re-run REFUSES the now-non-empty fortress and `--force` mints a NEW
    // master that orphans the recovery key just shown. The corrected message
    // must point at the two remediations that actually work and must NOT print
    // the broken literal.
    const fortressPath = join(tmp, "honest-message-fortress");
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const saveNewSpy = vi
      .spyOn(IdentityManager.prototype, "saveNew")
      .mockRejectedValue(new Error("injected mint failure"));
    const consoleSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    let consoleOutput = "";
    try {
      await expect(
        runInit(
          { fortress: fortressPath, noConfirm: true, noPin: true },
          { provisionPin: async () => 0 },
        ),
      ).rejects.toThrow(/operator identity seed failed/);
      consoleOutput = consoleSpy.mock.calls
        .map((c) => c.join(" "))
        .join("\n");
    } finally {
      consoleSpy.mockRestore();
      saveNewSpy.mockRestore();
    }
    // The accurate remediations, both naming the existing fortress path.
    expect(consoleOutput).toContain(
      `sanctuary identity create --fortress ${fortressPath}`,
    );
    expect(consoleOutput).toContain(
      `sanctuary init --force --fortress ${fortressPath}`,
    );
    // It tells the operator custody is intact and warns --force discards the key.
    expect(consoleOutput).toContain("recovery key shown above");
    // The broken instruction is GONE.
    expect(consoleOutput).not.toMatch(/Re-run init/);
  });

  it("resolveNoIdentity uses an allowlist for the env var, not 'anything truthy'", () => {
    expect(resolveNoIdentity({ noIdentity: true }, {})).toBe(true);
    expect(resolveNoIdentity({}, {})).toBe(false);
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: "1" })).toBe(true);
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: "TRUE" })).toBe(
      true,
    );
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: " on " })).toBe(
      true,
    );
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: "0" })).toBe(
      false,
    );
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: "no" })).toBe(
      false,
    );
    expect(resolveNoIdentity({}, { SANCTUARY_INIT_NO_IDENTITY: "" })).toBe(
      false,
    );
    expect(
      resolveNoIdentity({ noIdentity: true }, { SANCTUARY_INIT_NO_IDENTITY: "0" }),
    ).toBe(true);
  });
});

describe("parseInitArgs", () => {
  it("recognizes --fortress, --force, --no-confirm, --no-pin, --no-identity, --recovery-out, --help", () => {
    const opts = parseInitArgs([
      "--fortress",
      "/tmp/x",
      "--force",
      "--no-confirm",
      "--no-pin",
      "--no-identity",
      "--recovery-out",
      "/tmp/recovery-key.txt",
    ]);
    expect(opts.fortress).toBe("/tmp/x");
    expect(opts.force).toBe(true);
    expect(opts.noConfirm).toBe(true);
    expect(opts.noPin).toBe(true);
    expect(opts.noIdentity).toBe(true);
    expect(opts.recoveryOut).toBe("/tmp/recovery-key.txt");

    const helpOpts = parseInitArgs(["--help"]);
    expect(helpOpts.helpRequested).toBe(true);

    const shortHelp = parseInitArgs(["-h"]);
    expect(shortHelp.helpRequested).toBe(true);
  });

  it("rejects --recovery-out without a path value", () => {
    expect(() => parseInitArgs(["--recovery-out"])).toThrow(
      "--recovery-out requires a path value",
    );
    expect(() => parseInitArgs(["--recovery-out", "--no-pin"])).toThrow(
      "--recovery-out requires a path value",
    );
  });

  it("printInitHelp does not throw", () => {
    expect(() => printInitHelp()).not.toThrow();
  });
});
