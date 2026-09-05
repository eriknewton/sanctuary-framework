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
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
  stat,
  lstat,
  realpath,
  symlink,
  link,
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
  canonicalRecoveryKeyServiceFor,
  RecoveryKeyKeychainStoreError,
} from "../../src/wrap/keychain-custody.js";
import { agentGuidedRecoveryOutputPath } from "../../src/wrap/custody-flow.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import { runProvisionPinAlreadyLocked } from "../../src/cli/castle-wall.js";

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
    if (args[0] === "delete-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const deleted = stored.delete(keyFor(account, service));
      return deleted
        ? { stdout: "", stderr: "", code: 0 }
        : { stdout: "", stderr: "not found", code: 44 };
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
    provisionPin: async () => 0,
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
    provisionPin: async () => 0,
    ...deps,
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
  return { result, keychain };
}

async function withStdinTty<T>(run: () => Promise<T>): Promise<T> {
  const ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  const stderrWrite = vi.spyOn(process.stderr, "write").mockImplementation(
    (() => true) as typeof process.stderr.write,
  );
  Object.defineProperty(process.stdin, "isTTY", {
    configurable: true,
    value: true,
  });
  try {
    return await run();
  } finally {
    stderrWrite.mockRestore();
    if (ttyDescriptor) {
      Object.defineProperty(process.stdin, "isTTY", ttyDescriptor);
    } else {
      Reflect.deleteProperty(process.stdin, "isTTY");
    }
  }
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

    // Fresh init seeds the one true Castle Wall rule-source directory while
    // still running as the fortress owner. The root boot daemon must never
    // need to recursively mkdir through this operator-mutable tree.
    const rulesDirStats = await stat(
      join(fortressPath, "policy", "egress", "rules"),
    );
    expect(rulesDirStats.isDirectory()).toBe(true);
    expect(rulesDirStats.mode & 0o777).toBe(0o700);

    // Headless init: recovery key goes to the agent-guided external path
    // (beside the fortress, never inside it) — not at HOME, not inside the
    // fortress directory itself.
    const expectedOut = agentGuidedRecoveryOutputPath(fortressPath);
    expect(result.recoveryKeyDisclosurePath).toBe(expectedOut);
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(recoveryFile).toContain("Recovery key:");
    expect(recoveryFile).toContain(
      "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY",
    );
    // No plaintext copy inside the fortress directory.
    await expect(stat(join(fortressPath, RECOVERY_KEY_FILENAME))).rejects.toThrow();

    // Crucially: ~/.sanctuary was NOT touched. We can't safely assert this
    // on a developer machine (it might already exist), but we CAN assert
    // the fortress isn't at the default location.
    expect(result.fortressPath).not.toBe(join(homedir(), ".sanctuary"));
  });

  it("stores the minted recovery key in a read-back-verified Keychain item during interactive init", async () => {
    const fortressPath = join(tmp, "keychain-recovery-fortress");
    const keychain = makeRecoveryKeychainMock();
    const service = canonicalRecoveryKeyServiceFor(
      fortressPath,
      "/tmp/sanctuary-test-home",
    );
    const { result } = await withStdinTty(() =>
      runInitWithRecoveryKeychain(
        { fortress: fortressPath, noPin: true, noIdentity: true },
        keychain,
        {
          runLocalIntelligenceSetup: async () => ({ kind: "not-requested" }),
          verifyRecoveryKeyReentry: async ({ check }) => {
            const stored = keychain.stored.get(`sanctuary:${service}`);
            expect(stored).toMatch(/^[A-Za-z0-9_-]{43}$/);
            expect(await check(stored!)).toBe(true);
          },
        },
      ),
    );

    const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
    const recoveryKey = extractRecoveryKey(recoveryFile);
    expect(result.recoveryKeyDisclosurePath).toBe(
      join(fortressPath, RECOVERY_KEY_FILENAME),
    );
    expect(keychain.stored.get(`sanctuary:${service}`)).toBe(recoveryKey);

    const writeIndex = keychain.calls.findIndex(
      (call) => call.cmd === "security" && call.args[0] === "-i",
    );
    const readIndex = keychain.calls.findIndex(
      (call, index) =>
        index > writeIndex &&
        call.cmd === "security" &&
        call.args[0] === "find-generic-password" &&
        call.args.includes(service),
    );
    expect(writeIndex).toBeGreaterThanOrEqual(0);
    expect(readIndex).toBeGreaterThan(writeIndex);
    expect(keychain.calls.some((call) => call.args.includes(recoveryKey))).toBe(false);
  });

  it("fails closed before custody state when interactive recovery-key Keychain write fails", async () => {
    const fortressPath = join(tmp, "keychain-write-fails-fortress");
    const keychain = makeRecoveryKeychainMock({ writeFails: true });
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    let thrown: unknown;
    let consoleOutput = "";
    try {
      await withStdinTty(() =>
        runInitRaw(
          { fortress: fortressPath, noPin: true, noIdentity: true },
          {
            recoveryKeychain: {
              home: "/tmp/sanctuary-test-home",
              platformOverride: "darwin",
              exec: keychain.exec,
            },
          },
        ),
      );
    } catch (err) {
      thrown = err;
    } finally {
      consoleOutput = consoleSpy.mock.calls.map((args) => args.join(" ")).join("\n");
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

  it("fails closed before custody state and scrubs key buffers when interactive recovery-key Keychain read-back mismatches", async () => {
    const fortressPath = join(tmp, "keychain-readback-fails-fortress");
    const keychain = makeRecoveryKeychainMock({
      readBackOverride: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    const observed: Uint8Array[] = [];

    await expect(
      withStdinTty(() =>
        runInitRaw(
          { fortress: fortressPath, noPin: true, noIdentity: true },
          {
            recoveryKeychain: {
              home: "/tmp/sanctuary-test-home",
              platformOverride: "darwin",
              exec: keychain.exec,
            },
            observeSecretBuffer: (_label, buffer) => observed.push(buffer),
          },
        ),
      ),
    ).rejects.toThrow(RecoveryKeyKeychainStoreError);

    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toThrow();
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    expect(observed).toHaveLength(2);
    for (const buffer of observed) {
      expect([...buffer].every((byte) => byte === 0)).toBe(true);
    }
  });

  it("headless default writes externally and never touches recovery-key Keychain escrow", async () => {
    const fortressPath = join(tmp, "headless-default-external-fortress");
    const keychain = makeRecoveryKeychainMock({ writeFails: true });
    const { result } = await runInitWithRecoveryKeychain(
      {
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      },
      keychain,
    );

    expect(result.recoveryKeyDisclosurePath).toBe(
      agentGuidedRecoveryOutputPath(fortressPath),
    );
    expect(keychain.calls).toHaveLength(0);
    expect(extractRecoveryKey(
      await readFile(result.recoveryKeyDisclosurePath, "utf8"),
    )).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(stat(join(fortressPath, RECOVERY_KEY_FILENAME)))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("headless default collision during O_EXCL capture fails closed and scrubs key buffers", async () => {
    const fortressPath = join(tmp, "headless-default-race-fortress");
    const expectedOut = agentGuidedRecoveryOutputPath(fortressPath);
    const observed: Uint8Array[] = [];

    await expect(runInit(
      {
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      },
      {
        beforeRecoveryKeyOutputWrite: async (filePath) => {
          expect(filePath).toBe(expectedOut);
          await writeFile(filePath, "raced key", { mode: 0o600 });
        },
        observeSecretBuffer: (_label, buffer) => observed.push(buffer),
      },
    )).rejects.toThrow(RecoveryKeyOutputPathExistsError);

    await expect(readFile(expectedOut, "utf8")).resolves.toBe("raced key");
    await expect(stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(observed).toHaveLength(2);
    for (const buffer of observed) {
      expect([...buffer].every((byte) => byte === 0)).toBe(true);
    }
  });

  it("scrubs generated master, recovery, and keychain buffers when a later custody write throws", async () => {
    const fortressPath = join(tmp, "late-custody-write-failure");
    const keychain = makeRecoveryKeychainMock();
    const observed = new Map<string, Uint8Array[]>();
    const ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: true,
    });
    try {
      await expect(runInitRaw({
        fortress: fortressPath,
        noPin: true,
        noIdentity: true,
      }, {
        recoveryKeychain: {
          home: "/tmp/sanctuary-test-home",
          platformOverride: "darwin",
          exec: keychain.exec,
        },
        observeSecretBuffer: (label, buffer) => {
          const seen = observed.get(label) ?? [];
          seen.push(buffer);
          observed.set(label, seen);
        },
        beforeDurableMutation: (label) => {
          if (label === "custody-envelope") {
            throw new Error("injected late custody write failure");
          }
        },
      })).rejects.toThrow("injected late custody write failure");
    } finally {
      if (ttyDescriptor) {
        Object.defineProperty(process.stdin, "isTTY", ttyDescriptor);
      } else {
        Reflect.deleteProperty(process.stdin, "isTTY");
      }
    }

    expect([...observed.keys()]).toEqual(expect.arrayContaining([
      "master",
      "recovery-key",
      "keychain",
    ]));
    for (const buffers of observed.values()) {
      for (const buffer of buffers) {
        expect([...buffer].every((byte) => byte === 0)).toBe(true);
      }
    }
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(join(fortressPath, "policy")))
      .rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(join(fortressPath, RECOVERY_KEY_FILENAME)))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(keychain.stored.size).toBe(0);

    await expect(runInitRaw({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    }, {
      recoveryKeychain: {
        home: "/tmp/sanctuary-test-home",
        platformOverride: "darwin",
        exec: keychain.exec,
      },
    })).resolves.toMatchObject({ fortressPath });
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

  it("--recovery-out takes precedence over SANCTUARY_RECOVERY_OUT in headless init", async () => {
    const fortressPath = join(tmp, "flag-over-env-recovery-fortress");
    const flagOut = join(tmp, "flag-durable", "recovery-key.txt");
    const envOut = join(tmp, "env-must-not-win", "recovery-key.txt");
    process.env.SANCTUARY_RECOVERY_OUT = envOut;

    const result = await runInit({
      fortress: fortressPath,
      recoveryOut: flagOut,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });

    expect(result.recoveryKeyDisclosurePath).toBe(flagOut);
    expect(extractRecoveryKey(await readFile(flagOut, "utf8")))
      .toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(stat(envOut)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(join(fortressPath, RECOVERY_KEY_FILENAME)))
      .rejects.toMatchObject({ code: "ENOENT" });
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
    const observed: Uint8Array[] = [];

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
          observeSecretBuffer: (_label, buffer) => observed.push(buffer),
        },
      ),
    ).rejects.toThrow(RecoveryKeyOutputPathExistsError);

    await expect(readFile(recoveryOut, "utf-8")).resolves.toBe("raced key");
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toThrow();
    expect(observed).toHaveLength(2);
    for (const buffer of observed) {
      expect([...buffer].every((byte) => byte === 0)).toBe(true);
    }
  });

  it("rechecks fresh state under the shared lock after two inits pass preflight", async () => {
    const fortressPath = join(tmp, "concurrent-init-fortress");
    const recoveryA = join(tmp, "concurrent-a.recovery");
    const recoveryB = join(tmp, "concurrent-b.recovery");
    let releasePreflightA!: () => void;
    const preflightA = new Promise<void>((resolve) => { releasePreflightA = resolve; });
    let releasePreflightB!: () => void;
    const preflightB = new Promise<void>((resolve) => { releasePreflightB = resolve; });
    let sawPreflightA!: () => void;
    const atPreflightA = new Promise<void>((resolve) => { sawPreflightA = resolve; });
    let sawPreflightB!: () => void;
    const atPreflightB = new Promise<void>((resolve) => { sawPreflightB = resolve; });
    let releaseWinner!: () => void;
    const holdWinner = new Promise<void>((resolve) => { releaseWinner = resolve; });
    let winnerHasLock!: () => void;
    const winnerLocked = new Promise<void>((resolve) => { winnerHasLock = resolve; });

    const winner = runInit(
      {
        fortress: fortressPath,
        recoveryOut: recoveryA,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      },
      {
        beforeCustodyLockAcquire: async () => {
          sawPreflightA();
          await preflightA;
        },
        beforeRecoveryKeyOutputWrite: async () => {
          winnerHasLock();
          await holdWinner;
        },
      },
    );
    await atPreflightA;

    const loser = runInit(
      {
        fortress: fortressPath,
        recoveryOut: recoveryB,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      },
      {
        beforeCustodyLockAcquire: async () => {
          sawPreflightB();
          await preflightB;
        },
      },
    );
    // Attach the expected rejection observer immediately. The custody lock can
    // now release before the winner's deliberately post-lock local setup ends,
    // so delaying this handler until after awaiting the winner is a real
    // unhandled-rejection race in the test rather than a product failure.
    const loserRefusal = expect(loser).rejects.toThrow(
      "fortress state changed during init preflight",
    );
    await atPreflightB;

    releasePreflightA();
    await winnerLocked;
    releasePreflightB();
    // The loser is now contending while the winner is still inside the full
    // ceremony. It must neither produce a recovery key nor mutate custody.
    await new Promise((resolve) => setTimeout(resolve, 75));
    await expect(stat(recoveryB)).rejects.toThrow();

    releaseWinner();
    await expect(winner).resolves.toMatchObject({ fortressPath });
    await loserRefusal;
    await expect(stat(recoveryA)).resolves.toBeDefined();
    await expect(stat(recoveryB)).rejects.toThrow();
    // The loser observed winner state before its own mutation scope. Its
    // refusal must not enter fresh-init rollback and erase the winner.
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).resolves.toBeDefined();
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

  it("scrubs the deferred local-setup master copy when a late lock-phase failure prevents invocation", async () => {
    const fortressPath = join(tmp, "late-pin-failure-fortress");
    let localSetupMaster: Uint8Array | undefined;
    let localSetupInvoked = false;

    await expect(
      runInit(
        {
          fortress: fortressPath,
          noConfirm: true,
          noIdentity: true,
        },
        {
          provisionPin: async () => 1,
          runLocalIntelligenceSetup: async () => {
            localSetupInvoked = true;
            throw new Error("post-lock setup must not run after pin failure");
          },
          observeSecretBuffer: (label, buffer) => {
            if (label === "local-setup-master") localSetupMaster = buffer;
          },
        },
      ),
    ).rejects.toThrow("Castle Wall provision-pin auto-bootstrap failed");

    expect(localSetupInvoked).toBe(false);
    expect(localSetupMaster).toBeDefined();
    expect([...localSetupMaster!].every((byte) => byte === 0)).toBe(true);
  });

  it("creates the fortress directory with mode 0700", async () => {
    const fortressPath = join(tmp, "mode-test-fortress");
    await runInit({ fortress: fortressPath, noConfirm: true });
    const st = await stat(fortressPath);
    // Mask off file-type bits; only permission bits matter.
    expect(st.mode & 0o777).toBe(0o700);
  });

  it.skipIf(process.platform === "win32")(
    "recovers after the actual init mutator is killed before its blocked write",
    async () => {
      const { spawn } = await import("node:child_process");
      const fortressPath = join(tmp, "holder-death-fortress");
      const recoveryOut = join(tmp, "holder-death.recovery");
      const initModuleUrl = new URL("../../src/wrap/init.ts", import.meta.url).href;
      const childScript = `
        const { runInit } = await import(process.argv[1]);
        await runInit({
          fortress: process.argv[2],
          recoveryOut: process.argv[3],
          noConfirm: true,
          noPin: true,
          noIdentity: true,
        }, {
          beforeDurableMutation: async (label) => {
            if (label !== "recovery-key-file") return;
            process.stdout.write("BLOCKED_BEFORE_WRITE\\n");
            await new Promise(() => setInterval(() => undefined, 1000));
          },
        });
      `;
      const child = spawn(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "-e", childScript,
          initModuleUrl, fortressPath, recoveryOut],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let diagnostics = "";
      child.stderr.on("data", (chunk: Buffer) => {
        diagnostics += chunk.toString("utf8");
      });
      await new Promise<void>((resolve, reject) => {
        let stdout = "";
        child.once("error", reject);
        child.once("exit", (code, signal) => {
          reject(new Error(
            `init mutator exited before block (code=${code}, signal=${signal}): ${diagnostics}`,
          ));
        });
        child.stdout.on("data", (chunk: Buffer) => {
          stdout += chunk.toString("utf8");
          if (stdout.includes("BLOCKED_BEFORE_WRITE\n")) resolve();
        });
      });
      const death = new Promise<void>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", () => resolve());
      });
      child.kill("SIGKILL");
      await death;

      const lockPath = join(
        fortressPath,
        "state",
        "_meta",
        "custody-master.lock",
      );
      const scaffold = await stat(lockPath);
      expect(scaffold.isFile()).toBe(true);
      expect(scaffold.size).toBe(0);
      await expect(stat(recoveryOut)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(
        stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
      ).rejects.toMatchObject({ code: "ENOENT" });

      await expect(runInit({
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      })).resolves.toMatchObject({ fortressPath });
      await expect(stat(recoveryOut)).resolves.toBeDefined();
      await expect(
        stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
      ).resolves.toBeDefined();
    },
  );

  it.skipIf(process.platform === "win32")(
    "fails closed without touching a replacement when the fortress root is swapped after lock acquisition",
    async () => {
      const fortressPath = join(tmp, "post-acquire-root-swap");
      const displaced = join(tmp, "post-acquire-root-swap.displaced");
      const replacementMarker = join(fortressPath, "replacement-marker");
      let swapped = false;

      await expect(runInit({
        fortress: fortressPath,
        recoveryOut: join(tmp, "post-acquire-root-swap.recovery"),
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      }, {
        __testAfterKernelHolderAcquired: () => {
          renameSync(fortressPath, displaced);
          mkdirSync(fortressPath, { recursive: true, mode: 0o700 });
          writeFileSync(replacementMarker, "replacement", { mode: 0o600 });
          swapped = true;
        },
      })).rejects.toThrow(/root.*changed|identity changed/i);

      expect(swapped).toBe(true);
      await expect(readFile(replacementMarker, "utf8")).resolves.toBe("replacement");
      await expect(stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")))
        .rejects.toMatchObject({ code: "ENOENT" });
      await expect(stat(join(displaced, "state", "_meta", "custody-envelope.enc")))
        .rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it.skipIf(process.platform === "win32")(
    "a killed non-owning helper cannot admit an external contender during init",
    async () => {
      const { spawn } = await import("node:child_process");
      const fortressPath = join(tmp, "in-flight-holder-loss-fortress");
      const recoveryOut = join(tmp, "in-flight-holder-loss.recovery");
      const observed: Uint8Array[] = [];
      let helperPid: number | undefined;
      let killed = false;
      let contenderObservedContention = false;

      await expect(runInit({
        fortress: fortressPath,
        recoveryOut,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      }, {
        __testAfterKernelHolderAcquired: (pid) => {
          helperPid = pid;
        },
        beforeDurableMutation: async (label) => {
          if (label !== "recovery-key-file" || killed) return;
          if (helperPid === undefined) throw new Error("helper pid was not observed");
          killed = true;
          process.kill(helperPid, "SIGKILL");

          const filesystemUrl = new URL(
            "../../src/storage/filesystem.ts",
            import.meta.url,
          ).href;
          const custodyUrl = new URL(
            "../../src/core/master-custody.ts",
            import.meta.url,
          ).href;
          const contenderScript = `
            const { FilesystemStorage } = await import(process.argv[1]);
            const { withCustodyWriteLock } = await import(process.argv[2]);
            const storage = new FilesystemStorage(process.argv[3] + "/state");
            await withCustodyWriteLock(storage, async () => {
              process.stdout.write("UNSAFE_CONTENDER_ENTRY\\n");
            }, { timeoutMs: 80 });
          `;
          const contender = spawn(
            process.execPath,
            ["--import", "tsx", "--input-type=module", "-e", contenderScript,
              filesystemUrl, custodyUrl, fortressPath],
            { stdio: ["ignore", "pipe", "pipe"] },
          );
          const result = await new Promise<{
            code: number | null;
            stdout: string;
            stderr: string;
          }>((resolve, reject) => {
            let stdout = "";
            let stderr = "";
            contender.stdout.on("data", (chunk: Buffer) => {
              stdout += chunk.toString("utf8");
            });
            contender.stderr.on("data", (chunk: Buffer) => {
              stderr += chunk.toString("utf8");
            });
            contender.once("error", reject);
            contender.once("close", (code) => resolve({ code, stdout, stderr }));
          });
          expect(result.code).not.toBe(0);
          expect(result.stdout).not.toContain("UNSAFE_CONTENDER_ENTRY");
          expect(result.stderr).toMatch(/held|contention|custody lock/i);
          contenderObservedContention = true;
        },
        observeSecretBuffer: (_label, buffer) => observed.push(buffer),
      })).resolves.toMatchObject({ fortressPath });

      expect(killed).toBe(true);
      expect(contenderObservedContention).toBe(true);
      expect(observed.length).toBeGreaterThanOrEqual(2);
      expect(observed.every((buffer) => [...buffer].every((byte) => byte === 0))).toBe(true);
      await expect(stat(recoveryOut)).resolves.toBeDefined();
      await expect(stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")))
        .resolves.toBeDefined();
    },
  );

  it.skipIf(process.platform === "win32")(
    "scrubs a resolved keychain key on post-provider failure after non-owning helper death",
    async () => {
      const fortressPath = join(tmp, "keychain-post-provider-failure-fortress");
      const recoveryOut = join(tmp, "keychain-post-provider-failure.recovery");
      const keychain = makeRecoveryKeychainMock();
      const ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
      let helperPid: number | undefined;
      let observedKeychainKey: Uint8Array | undefined;
      let killed = false;
      Object.defineProperty(process.stdin, "isTTY", {
        configurable: true,
        value: true,
      });

      try {
        await expect(runInitRaw({
          fortress: fortressPath,
          recoveryOut,
          noPin: true,
          noIdentity: true,
        }, {
          recoveryKeychain: {
            home: "/tmp/sanctuary-test-home",
            platformOverride: "darwin",
            exec: keychain.exec,
          },
          __testAfterKernelHolderAcquired: (pid) => {
            helperPid = pid;
          },
          observeSecretBuffer: (label, buffer) => {
            if (label === "keychain") observedKeychainKey = buffer;
          },
          __testAfterKeychainCustodyKeyResolved: async () => {
            if (helperPid === undefined) throw new Error("helper pid was not observed");
            killed = true;
            process.kill(helperPid, "SIGKILL");
            throw new Error("injected post-provider failure");
          },
        })).rejects.toThrow("injected post-provider failure");
      } finally {
        if (ttyDescriptor) {
          Object.defineProperty(process.stdin, "isTTY", ttyDescriptor);
        } else {
          Reflect.deleteProperty(process.stdin, "isTTY");
        }
      }

      expect(killed).toBe(true);
      expect(observedKeychainKey).toBeDefined();
      expect([...observedKeychainKey!].every((byte) => byte === 0)).toBe(true);
      await expect(stat(recoveryOut)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")))
        .rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it("does not mistake a lock scaffold plus any other entry for a fresh fortress", async () => {
    const fortressPath = join(tmp, "near-miss-lock-scaffold");
    const lockDir = join(fortressPath, "state", "_meta");
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    await writeFile(join(lockDir, "custody-master.lock"), "", { mode: 0o600 });
    await writeFile(join(lockDir, "operator-state"), "preserve", { mode: 0o600 });

    await expect(runInit({
      fortress: fortressPath,
      recoveryOut: join(tmp, "near-miss.recovery"),
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    })).rejects.toThrow(/not empty/);
  });

  it("recovers an exact post-nuke scaffold plus crash-left default recovery output without --force", async () => {
    const fortressPath = join(tmp, "post-nuke-crash-residue");
    const lockDir = join(fortressPath, "state", "_meta");
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    await writeFile(join(lockDir, "custody-master.lock"), "", { mode: 0o600 });
    await writeFile(join(fortressPath, ".reset-history.log"), "{}\n", { mode: 0o600 });
    await writeFile(
      join(fortressPath, "recovery-key.txt"),
      "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.\n" +
        "Generated: 2026-09-01T00:00:00.000Z\n\nRecovery key:\n" +
        `${"A".repeat(43)}\n\n` +
        "This file was created on first init. Sanctuary will NOT regenerate this file on\n" +
        "subsequent runs and will NOT display the key again. After moving this file off\n" +
        "the host (encrypted backup, password manager, paper safe), delete it from the\n" +
        "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses\n" +
        "the fortress passphrase by design.\n",
      { mode: 0o600 },
    );

    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });
    const replacement = await readFile(result.recoveryKeyDisclosurePath, "utf8");
    expect(extractRecoveryKey(replacement)).not.toBe("A".repeat(43));
  });

  it("recovers an exact staging-only recovery residue without --force", async () => {
    const fortressPath = join(tmp, "staging-only-crash-residue");
    const lockDir = join(fortressPath, "state", "_meta");
    const stageName = `.recovery-key.txt.sanctuary-recovery-stage-4242-${"a".repeat(24)}`;
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    await writeFile(join(lockDir, "custody-master.lock"), "", { mode: 0o600 });
    await writeFile(
      join(fortressPath, stageName),
      "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.\n" +
        "Generated: 2026-09-01T00:00:00.000Z\n\nRecovery key:\n" +
        `${"A".repeat(43)}\n\n` +
        "This file was created on first init. Sanctuary will NOT regenerate this file on\n" +
        "subsequent runs and will NOT display the key again. After moving this file off\n" +
        "the host (encrypted backup, password manager, paper safe), delete it from the\n" +
        "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses\n" +
        "the fortress passphrase by design.\n",
      { mode: 0o600 },
    );

    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });
    await expect(lstat(join(fortressPath, stageName)))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(extractRecoveryKey(await readFile(result.recoveryKeyDisclosurePath, "utf8")))
      .not.toBe("A".repeat(43));
  });

  it("does not treat a staging-prefix lookalike as recoverable fresh residue", async () => {
    const fortressPath = join(tmp, "staging-lookalike");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    await writeFile(
      join(fortressPath, ".recovery-key.txt.sanctuary-recovery-stage-attacker"),
      "preserve",
      { mode: 0o600 },
    );
    await expect(runInit({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    })).rejects.toThrow(/not empty/);
  });

  it("preserves an exact quarantined symlink without following it outside the fortress", async () => {
    const fortressPath = join(tmp, "reset-quarantine-fresh-init");
    const outside = join(tmp, "quarantine-outside");
    const quarantine = join(
      fortressPath,
      `.reset-history.log.quarantine.1756684800000.${"b".repeat(16)}`,
    );
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o755 });
    await writeFile(join(outside, "must-not-chmod"), "outside", { mode: 0o644 });
    await symlink(outside, quarantine);

    await expect(runInit({
      fortress: fortressPath,
      recoveryOut: join(tmp, "quarantine.recovery"),
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    })).resolves.toMatchObject({ fortressPath });
    expect((await lstat(quarantine)).isSymbolicLink()).toBe(true);
    expect((await stat(outside)).mode & 0o777).toBe(0o755);
    expect((await stat(join(outside, "must-not-chmod"))).mode & 0o777).toBe(0o644);
  });

  it("rejects a hard-linked lock scaffold before permission tightening can chmod its outside inode", async () => {
    const fortressPath = join(tmp, "hardlinked-lock-scaffold");
    const lockDir = join(fortressPath, "state", "_meta");
    const outside = join(tmp, "outside-lock-inode");
    const lockPath = join(lockDir, "custody-master.lock");
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    await writeFile(outside, "", { mode: 0o644 });
    await link(outside, lockPath);
    const before = await stat(outside);

    await expect(runInit({
      fortress: fortressPath,
      recoveryOut: join(tmp, "hardlinked-lock.recovery"),
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    })).rejects.toThrow(/not empty/);

    const after = await stat(outside);
    expect(after.mode & 0o777).toBe(before.mode & 0o777);
    expect(after.nlink).toBe(2);
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

  it("refuses --force before mutation when canonical keychain recovery escrow exists", async () => {
    const fortressPath = join(tmp, "forced-canonical-recovery-escrow");
    const keychain = makeRecoveryKeychainMock();
    const service = canonicalRecoveryKeyServiceFor(
      fortressPath,
      "/tmp/sanctuary-test-home",
    );
    await withStdinTty(() => runInitWithRecoveryKeychain(
      {
        fortress: fortressPath,
        noPin: true,
        noIdentity: true,
      },
      keychain,
      {
        runLocalIntelligenceSetup: async () => ({ kind: "not-requested" }),
        verifyRecoveryKeyReentry: async ({ check }) => {
          const stored = keychain.stored.get(`sanctuary:${service}`);
          expect(stored).toBeDefined();
          expect(await check(stored!)).toBe(true);
        },
      },
    ));
    const marker = join(fortressPath, "preserve-through-refusal.txt");
    await writeFile(marker, "preserve", { mode: 0o600 });

    await expect(runInitWithRecoveryKeychain({
      fortress: fortressPath,
      force: true,
      recoveryOut: join(tmp, "must-not-bypass-canonical-escrow.recovery"),
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    }, keychain)).rejects.toThrow(/--force refused.*recovery escrow/i);
    expect(await readFile(marker, "utf8")).toBe("preserve");
  });

  it("refuses a symlinked policy ancestor under --force without writing outside the fortress", async () => {
    const fortressPath = join(tmp, "symlinked-policy-fortress");
    const outside = join(tmp, "outside-policy-target");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await symlink(outside, join(fortressPath, "policy"));

    await expect(
      runInit({
        fortress: fortressPath,
        force: true,
        noConfirm: true,
        noPin: true,
      }),
    ).rejects.toThrow(/symlink.*refusing to mkdir/i);

    await expect(stat(join(outside, "egress"))).rejects.toThrow();
    await expect(stat(join(fortressPath, "state"))).rejects.toThrow();
  });

  it("recovery-key.txt is single-issuance: re-init with --force does NOT overwrite", async () => {
    // Headless init writes the recovery key to the agent-guided external path.
    // A second --force --no-confirm re-init on the same fortress produces the
    // same agent-guided path (path-derived, not random). preflightRecoveryKeyOutputFile
    // refuses that path because it already holds the first init's key, aborting
    // before any fortress mutation — single-issuance is enforced at the preflight
    // layer, not at the write layer.
    const fortressPath = join(tmp, "single-issuance-fortress");
    const first = await runInit({ fortress: fortressPath, noConfirm: true });
    const agentGuidedPath = agentGuidedRecoveryOutputPath(fortressPath);
    expect(first.recoveryKeyDisclosurePath).toBe(agentGuidedPath);
    const firstContent = await readFile(agentGuidedPath, "utf-8");

    // Second init under --force is refused at preflight before any mutation.
    await expect(
      runInit({ fortress: fortressPath, force: true, noConfirm: true }),
    ).rejects.toThrow(RecoveryKeyOutputPathExistsError);

    // File unchanged: the refusal happened before any mutation.
    const afterSecond = await readFile(agentGuidedPath, "utf-8");
    expect(afterSecond).toBe(firstContent);
  });

  it.each(["default", "explicit"] as const)(
    "headless init (%s output): full process transcript shows the path, never the recovery key",
    async (outputKind) => {
      // When --no-confirm is set, discloseRecoveryKey is never called. Only the
      // destination path is printed — the key value itself never appears in the
      // process transcript captured by an MCP harness.
      const fortressPath = join(
        tmp,
        `transcript-absence-${outputKind}-fortress`,
      );
      const explicitOut = join(tmp, "transcript-explicit", "recovery-key.txt");
      const consoleLines: string[] = [];
      const stderrWrites: string[] = [];
      const stdoutWrites: string[] = [];
      const consoleSpy = vi.spyOn(console, "error").mockImplementation(
        (...args: unknown[]) => { consoleLines.push(args.join(" ")); },
      );
      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(
        ((chunk: string | Uint8Array) => {
          stderrWrites.push(String(chunk));
          return true;
        }) as typeof process.stderr.write,
      );
      const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(
        ((chunk: string | Uint8Array) => {
          stdoutWrites.push(String(chunk));
          return true;
        }) as typeof process.stdout.write,
      );
      let recoveryKey: string | undefined;
      let disclosurePath: string | undefined;
      try {
        const result = await runInit({
          fortress: fortressPath,
          ...(outputKind === "explicit" ? { recoveryOut: explicitOut } : {}),
          noConfirm: true,
          noPin: true,
        });
        disclosurePath = result.recoveryKeyDisclosurePath;
        const recoveryFile = await readFile(
          result.recoveryKeyDisclosurePath,
          "utf-8",
        );
        recoveryKey = extractRecoveryKey(recoveryFile);
      } finally {
        stdoutSpy.mockRestore();
        stderrSpy.mockRestore();
        consoleSpy.mockRestore();
      }

      expect(recoveryKey).toBeDefined();
      expect(disclosurePath).toBe(
        outputKind === "explicit"
          ? explicitOut
          : agentGuidedRecoveryOutputPath(fortressPath),
      );
      const transcript = [
        ...consoleLines,
        ...stderrWrites,
        ...stdoutWrites,
      ].join("\n");
      // This includes the original leak channel: printSecretBanner writes
      // directly to process.stderr instead of through console.error.
      expect(transcript).toContain(disclosurePath!);
      expect(transcript).not.toContain(recoveryKey!);
    },
  );

  it("headless init rollback removes the agent-guided recovery file when a later mutation fails", async () => {
    // If a custody mutation fails after the external recovery file was written,
    // rollback must delete the file so a clean retry can proceed. The fortress
    // is left in the inert lock-scaffold state with no custody state.
    const fortressPath = join(tmp, "rollback-agent-guided-fortress");
    const agentGuidedPath = agentGuidedRecoveryOutputPath(fortressPath);
    const observed: Uint8Array[] = [];

    await expect(
      runInit(
        {
          fortress: fortressPath,
          noConfirm: true,
          noPin: true,
          noIdentity: true,
        },
        {
          beforeDurableMutation: (label) => {
            if (label === "custody-envelope") {
              throw new Error("injected custody-envelope write failure");
            }
          },
          observeSecretBuffer: (_label, buffer) => observed.push(buffer),
        },
      ),
    ).rejects.toThrow("injected custody-envelope write failure");

    // Rollback must remove the agent-guided file written before the failure.
    await expect(stat(agentGuidedPath)).rejects.toMatchObject({ code: "ENOENT" });
    // Custody state absent — init did not complete.
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    // Key buffers zeroed.
    for (const buffer of observed) {
      expect([...buffer].every((byte) => byte === 0)).toBe(true);
    }
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
    let sawStorageRealPath: string | undefined;
    await runInit(
      { fortress: fortressPath, noConfirm: true },
      {
        provisionPin: async (_argv, ctx) => {
          calls++;
          sawStoragePath = ctx?.env?.SANCTUARY_STORAGE_PATH;
          if (sawStoragePath) sawStorageRealPath = await realpath(sawStoragePath);
          return 0;
        },
      },
    );
    expect(calls).toBe(1);
    expect(sawStoragePath).toBeDefined();
    // Linux intentionally exposes the already-open fortress descriptor here;
    // Darwin uses the lexical path plus its cwd-bound capability worker. Both
    // must resolve to the exact requested fortress inode.
    expect(sawStorageRealPath).toBe(await realpath(fortressPath));
  });

  it("default init with the REAL provision-pin writes the per-fortress pinned key", async () => {
    const fortressPath = join(tmp, "default-pin-real-fortress");
    const globalPinPath = join(tmp, "default-pin-real-global", "castle-pinned-pubkey.bin");
    await mkdir(join(tmp, "default-pin-real-global"), { recursive: true });
    await runInit(
      { fortress: fortressPath, noConfirm: true },
      {
        provisionPin: (argv, ctx) => runProvisionPinAlreadyLocked(argv, {
          ...ctx,
          globalPinnedPublicKeyPath: globalPinPath,
        }),
      },
    );

    const st = await stat(join(fortressPath, "castle-pinned-pubkey.bin"));
    expect(st.isFile()).toBe(true);
    expect(st.size).toBe(32);
    expect((await stat(globalPinPath)).size).toBe(32);
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
  it("recognizes fortress, custody, and local-intelligence setup flags", () => {
    const opts = parseInitArgs([
      "--fortress",
      "/tmp/x",
      "--force",
      "--no-confirm",
      "--no-pin",
      "--no-identity",
      "--provision-local-intelligence",
      "--recovery-out",
      "/tmp/recovery-key.txt",
    ]);
    expect(opts.fortress).toBe("/tmp/x");
    expect(opts.force).toBe(true);
    expect(opts.noConfirm).toBe(true);
    expect(opts.noPin).toBe(true);
    expect(opts.noIdentity).toBe(true);
    expect(opts.provisionLocalIntelligence).toBe(true);
    expect(opts.recoveryOut).toBe("/tmp/recovery-key.txt");

    const helpOpts = parseInitArgs(["--help"]);
    expect(helpOpts.helpRequested).toBe(true);

    const shortHelp = parseInitArgs(["-h"]);
    expect(shortHelp.helpRequested).toBe(true);
  });

  it("parses an explicit local-intelligence decline", () => {
    expect(
      parseInitArgs(["--no-provision-local-intelligence"]).provisionLocalIntelligence,
    ).toBe(false);
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
