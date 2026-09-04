/**
 * `sanctuary reset-passphrase --mode recovery-key` — durability, concurrency,
 * and secret-zeroization of the rekey transaction (findings 3 & 4).
 *
 * The rekey runs under a cross-process exclusive lock and a durable journal, so
 * that:
 *  - a second concurrent process cannot race the stored credential against the
 *    envelope (it fails closed on a held lock; two serialized runs still end
 *    consistent), and
 *  - a crash at ANY write boundary is idempotently recoverable on the next run,
 *    always converging to a fortress whose stored credential opens its envelope
 *    (never "publish envelope A with stored credential B"), with the recovery
 *    key always valid and no unusable-wrap accretion.
 *
 * F4: the decoded recovery key and the unlocked master are owned by an OUTER
 * `finally`, so both are zeroed on every exit — success, wrong key, lock
 * contention, and an injected crash — proven here by capturing the live buffer
 * references and asserting they are all-zero afterward (never printing them).
 *
 * A per-run temp fortress and an in-memory `security` stub keep the operator's
 * real keyring untouched, on Linux CI as well as macOS.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, rm, mkdir, symlink, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import {
  runResetPassphraseCommand,
  type RekeyStage,
} from "../../src/cli/reset-passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  establishMaster,
  readCustodyEnvelope,
  unwrapMaster,
  withCustodyWriteLock,
} from "../../src/core/master-custody.js";
import { fromBase64url } from "../../src/core/encoding.js";
import {
  legacyKeychainServiceFor,
  PassphraseUnreadableError,
  persistUserProvidedPassphrase,
  readStoredPassphrase,
} from "../../src/wrap/passphrase.js";

const OLD_PASSPHRASE = "reset-rk-dur-OLD-correct-horse-not-a-real-secret";

function nonTtyStdin(): NodeJS.ReadableStream & { isTTY?: boolean } {
  const s = Readable.from([Buffer.from("")]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  s.isTTY = false;
  return s;
}

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}
function capture(): { out: StringWritable; err: StringWritable } {
  return { out: new StringWritable(), err: new StringWritable() };
}

type Exec = (
  cmd: string,
  args: string[],
  input?: string,
) => Promise<{ stdout: string; stderr: string; code: number | null }>;

/** In-memory macOS `security` stub shared across a crash + recovery rerun. */
function fakeKeychain(): { exec: Exec; store: Map<string, string> } {
  const store = new Map<string, string>();
  const exec: Exec = async (cmd, args, input) => {
    if (cmd !== "security") return { stdout: "", stderr: "unhandled", code: 1 };
    if (args[0] === "-i" && input) {
      const svc = /-s "([^"]*)"/.exec(input)?.[1];
      const val = /-w "([^"]*)"/.exec(input)?.[1];
      if (svc !== undefined && val !== undefined) {
        store.set(svc, val);
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "bad batch", code: 1 };
    }
    if (args[0] === "find-generic-password") {
      const i = args.indexOf("-s");
      const svc = i >= 0 ? args[i + 1]! : "";
      if (store.has(svc)) return { stdout: store.get(svc)! + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "could not be found", code: 44 };
    }
    if (args[0] === "delete-generic-password") {
      const i = args.indexOf("-s");
      const svc = i >= 0 ? args[i + 1]! : "";
      const had = store.delete(svc);
      return { stdout: "", stderr: "", code: had ? 0 : 44 };
    }
    return { stdout: "", stderr: "unhandled", code: 1 };
  };
  return { exec, store };
}

interface Seeded {
  storagePath: string;
  home: string;
  recoveryKey: string;
  cleanup: () => Promise<void>;
}

async function seed(fortressName = ".sanctuary"): Promise<Seeded> {
  const home = await mkdtemp(join(tmpdir(), "reset-rk-dur-"));
  const storagePath = join(home, fortressName);
  const statePath = join(storagePath, "state");
  await mkdir(statePath, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(statePath);
  const custody = await establishMaster({
    storage,
    passphrase: OLD_PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: true },
    storagePathHint: storagePath,
  });
  const recoveryKey = custody.mintedRecoveryKey ?? "";
  custody.masterKey.fill(0);
  await custody.masterWriteBarrier?.release();
  return {
    storagePath,
    home,
    recoveryKey,
    cleanup: () => rm(home, { recursive: true, force: true }),
  };
}

function storageOf(storagePath: string): FilesystemStorage {
  return new FilesystemStorage(join(storagePath, "state"));
}
async function envelopeOf(storagePath: string) {
  return readCustodyEnvelope(storageOf(storagePath));
}
async function rawEnvelope(storagePath: string): Promise<Uint8Array | null> {
  return storageOf(storagePath).read("_meta", "custody-envelope");
}
async function unlockableBy(
  storagePath: string,
  cred: { passphrase: string } | { recoveryKey: Uint8Array },
): Promise<boolean> {
  const env = await envelopeOf(storagePath);
  if (!env) return false;
  try {
    const m = await unwrapMaster(env, cred);
    m.fill(0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Assert the fortress is CONSISTENT and hands-free-openable: exactly one
 * passphrase wrap, the recovery key still works, and the single stored
 * credential opens the on-disk envelope (never "envelope A with credential B").
 */
async function assertConsistentAndOpenable(f: Seeded, store: Map<string, string>) {
  const env = await envelopeOf(f.storagePath);
  expect(env).not.toBeNull();
  expect(env!.wraps.filter((w) => w.type === "passphrase")).toHaveLength(1);
  expect(env!.wraps.some((w) => w.type === "recovery-key")).toBe(true);
  // Recovery key always survives.
  expect(await unlockableBy(f.storagePath, { recoveryKey: fromBase64url(f.recoveryKey) })).toBe(true);
  // The old passphrase is gone.
  expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(false);
  // The stored credential opens the on-disk envelope.
  const stored = [...store.values()][0];
  expect(stored).toBeDefined();
  expect(await unlockableBy(f.storagePath, { passphrase: stored! })).toBe(true);
  // No journal is left behind once healed.
  expect(await storageOf(f.storagePath).read("_meta", "custody-rekey-journal")).toBeNull();
}

describe("recovery-key rekey durability (F3)", () => {
  let f: Seeded;
  beforeEach(async () => {
    f = await seed();
  });
  afterEach(async () => {
    await f.cleanup();
  });

  it("fails closed when the exclusive rekey lock is already held, mutating nothing", async () => {
    // Hold the exact KERNEL lock the recovery transaction uses. Mere lockfile
    // existence is intentionally irrelevant and cannot simulate contention.
    let releaseHolder!: () => void;
    let markAcquired!: () => void;
    const release = new Promise<void>((resolve) => { releaseHolder = resolve; });
    const acquired = new Promise<void>((resolve) => { markAcquired = resolve; });
    const holder = withCustodyWriteLock(
      storageOf(f.storagePath),
      async () => {
        markAcquired();
        await release;
      },
      { metadata: { owner: "test-holder" } },
    );
    await acquired;

    const before = await rawEnvelope(f.storagePath);
    const kc = fakeKeychain();
    const { out, err } = capture();
    try {
      const code = await runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out,
        err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        lockTimeoutMs: 200, // fail closed fast instead of the production budget
      });
      expect(code).toBe(1);
      expect(err.text).toContain("another custody operation is in progress");
      // Nothing mutated.
      const after = await rawEnvelope(f.storagePath);
      expect(Buffer.from(after!).equals(Buffer.from(before!))).toBe(true);
      expect(kc.store.size).toBe(0);
    } finally {
      releaseHolder();
      await holder;
    }
  });

  it("two concurrent rekeys serialize and leave the fortress consistent", async () => {
    const kc = fakeKeychain(); // shared store across both processes
    const run = () =>
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        lockTimeoutMs: 5000,
      });
    const [a, b] = await Promise.all([run(), run()]);
    // Both serialized runs succeed (the lock never double-acquires).
    expect(a).toBe(0);
    expect(b).toBe(0);
    // Exactly one stored credential, and it opens the envelope.
    expect(kc.store.size).toBe(1);
    await assertConsistentAndOpenable(f, kc.store);
  });

  it("deletes retired service aliases only after committed canonical readback", async () => {
    await f.cleanup();
    f = await seed("custom-fortress");
    const kc = fakeKeychain();
    const retired = legacyKeychainServiceFor(f.storagePath, f.home);
    let mirrored = false;
    const exec: Exec = async (cmd, args, input) => {
      const result = await kc.exec(cmd, args, input);
      if (!mirrored && args[0] === "-i" && result.code === 0 && input) {
        const value = /-w "([^"]*)"/.exec(input)?.[1];
        if (value !== undefined) {
          kc.store.set(retired, value);
          mirrored = true;
        }
      }
      return result;
    };
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    expect(mirrored).toBe(true);
    expect(kc.store.has(retired)).toBe(false);
    expect(kc.store.size).toBe(1);
    await assertConsistentAndOpenable(f, kc.store);
  });

  const STAGES: RekeyStage[] = [
    "journal-prepared",
    "augmented-written",
    "stored-persisted",
    "custody-committed",
    "final-written",
    "journal-clear-before-unlink",
    "journal-cleared",
    "marker-written",
  ];

  for (const stage of STAGES) {
    it(`recovers idempotently after a crash at "${stage}"`, async () => {
      const kc = fakeKeychain(); // persists across the crash + recovery rerun

      // First run crashes right after `stage`.
      await expect(
        runResetPassphraseCommand({
          argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
          out: capture().out,
          err: capture().err,
          stdin: nonTtyStdin(),
          home: f.home,
          platformOverride: "darwin",
          exec: kc.exec,
          recoveryKeyOverride: f.recoveryKey,
          faultAfterRekeyStage: (s) => {
            if (s === stage) throw new Error(`injected crash at ${s}`);
          },
        }),
      ).rejects.toThrow(/injected crash/);

      // At every crash point the recovery key still opens the fortress.
      expect(
        await unlockableBy(f.storagePath, { recoveryKey: fromBase64url(f.recoveryKey) }),
      ).toBe(true);
      const completedPriorCredential = stage === "final-written"
        ? [...kc.store.values()][0]
        : undefined;

      // Recovery rerun heals and finishes.
      const code = await runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
      });
      expect(code).toBe(0);
      await assertConsistentAndOpenable(f, kc.store);
      if (completedPriorCredential !== undefined) {
        expect([...kc.store.values()][0]).not.toBe(completedPriorCredential);
      }
    });
  }

  it("reports a retry-safe committed state when journal deletion fails", async () => {
    const kc = fakeKeychain();
    const io = capture();
    const metadataDir = join(f.storagePath, "state", "_meta");
    let madeReadOnly = false;
    try {
      const code = await runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: io.out,
        err: io.err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: async (stage) => {
          if (stage !== "journal-clear-before-unlink") return;
          await chmod(metadataDir, 0o500);
          madeReadOnly = true;
        },
      });
      expect(code).toBe(1);
      expect(io.err.text).toContain("custody is already committed");
      expect(io.err.text).toContain("journal was preserved");
      expect(await storageOf(f.storagePath).read("_meta", "custody-rekey-journal"))
        .not.toBeNull();
      expect(await unlockableBy(f.storagePath, { recoveryKey: fromBase64url(f.recoveryKey) }))
        .toBe(true);
    } finally {
      if (madeReadOnly) await chmod(metadataDir, 0o700);
    }

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    await assertConsistentAndOpenable(f, kc.store);
  });

  it("supersedes authenticated final-written custody on a copied host with no local credential", async () => {
    const sourceHost = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: sourceHost.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "final-written") throw new Error("copied after final write");
        },
      }),
    ).rejects.toThrow("copied after final write");
    expect(await storageOf(f.storagePath).read("_meta", "custody-rekey-journal"))
      .not.toBeNull();

    // The copied host has the fortress bytes but none of the source host's
    // exact-fortress credential. The human-held recovery key authenticates the
    // current final envelope and journal; recovery must never replay old wraps.
    const copiedHost = fakeKeychain();
    const { out, err } = capture();
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: copiedHost.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    expect(out.text).toContain("without replaying retired passphrase wraps");
    expect(err.text).toBe("");
    await assertConsistentAndOpenable(f, copiedHost.store);
  });

  for (const phase of ["augmented-written", "final-written"] as const) {
    it(`heals ${phase} on a copied host whose machine-bound fallback is unreadable`, async () => {
      if (phase === "augmented-written") {
        await persistUserProvidedPassphrase(OLD_PASSPHRASE, {
          storagePath: f.storagePath,
          home: f.home,
          platformOverride: "freebsd",
        });
      }
      await expect(
        runResetPassphraseCommand({
          // freebsd has no keyring: opt into the machine-local fallback (S3) so
          // the rekey can reach the post-persist fault stage under test.
          argv: [
            "--mode",
            "recovery-key",
            "--fortress",
            f.storagePath,
            "--allow-machine-local-passphrase",
          ],
          out: capture().out,
          err: capture().err,
          stdin: nonTtyStdin(),
          home: f.home,
          platformOverride: "freebsd",
          recoveryKeyOverride: f.recoveryKey,
          faultAfterRekeyStage: (stage) => {
            if (stage === phase) throw new Error(`copied after ${phase}`);
          },
        }),
      ).rejects.toThrow(`copied after ${phase}`);

      const copiedHome = join(f.home, "copied-host-home");
      await mkdir(copiedHome, { recursive: true, mode: 0o700 });
      await expect(readStoredPassphrase({
        storagePath: f.storagePath,
        home: copiedHome,
        platformOverride: "freebsd",
        readOnly: true,
      })).rejects.toBeInstanceOf(PassphraseUnreadableError);

      const { out, err } = capture();
      expect(await runResetPassphraseCommand({
        argv: [
          "--mode",
          "recovery-key",
          "--fortress",
          f.storagePath,
          "--allow-machine-local-passphrase",
        ],
        out,
        err,
        stdin: nonTtyStdin(),
        home: copiedHome,
        platformOverride: "freebsd",
        recoveryKeyOverride: f.recoveryKey,
      })).toBe(0);
      // The recovery run must not report an error. When it RE-PERSISTS a fresh
      // passphrase (the rolled-back augmented-written path), the freebsd fallback
      // opt-in prints the SEC-063-style downgrade warning; the roll-forward
      // final-written path re-persists nothing and stays silent.
      expect(err.text).not.toMatch(/Refusing|failed|could not/);
      if (phase === "augmented-written") {
        expect(err.text).toContain("machine-local");
      }
      expect(out.text).toContain(
        phase === "final-written"
          ? "without replaying retired passphrase wraps"
          : "restoring the prior custody",
      );

      const env = await envelopeOf(f.storagePath);
      expect(env!.wraps.filter((w) => w.type === "passphrase")).toHaveLength(1);
      expect(await unlockableBy(f.storagePath, {
        recoveryKey: fromBase64url(f.recoveryKey),
      })).toBe(true);
      expect(await unlockableBy(f.storagePath, {
        passphrase: OLD_PASSPHRASE,
      })).toBe(false);
      const stored = await readStoredPassphrase({
        storagePath: f.storagePath,
        home: copiedHome,
        platformOverride: "freebsd",
        readOnly: true,
      });
      expect(stored).not.toBeNull();
      expect(await unlockableBy(f.storagePath, {
        passphrase: stored!.value,
      })).toBe(true);
      expect(await storageOf(f.storagePath).read(
        "_meta",
        "custody-rekey-journal",
      )).toBeNull();
    });
  }

  it("preserves authenticated final custody when the local credential is indeterminate", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "final-written") throw new Error("retain final journal");
        },
      }),
    ).rejects.toThrow("retain final journal");
    const before = await rawEnvelope(f.storagePath);
    const storage = storageOf(f.storagePath);
    const journalBefore = await storage.read("_meta", "custody-rekey-journal");
    expect(journalBefore).not.toBeNull();

    const unavailable: Exec = async (cmd, args, input) => {
      if (cmd === "security" && args[0] === "find-generic-password") {
        return { stdout: "", stderr: "User interaction is not allowed", code: 36 };
      }
      return kc.exec(cmd, args, input);
    };
    const { err } = capture();
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: unavailable,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(1);
    expect(err.text).toMatch(/indeterminate|preserved/i);
    expect(Buffer.from((await rawEnvelope(f.storagePath))!).equals(Buffer.from(before!))).toBe(true);
    expect(Buffer.from((await storage.read("_meta", "custody-rekey-journal"))!).equals(Buffer.from(journalBefore!))).toBe(true);

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    await assertConsistentAndOpenable(f, kc.store);
  });

  it("does not replay retired wraps when keyring is unreachable and a readable fallback is stale", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "final-written") throw new Error("retain mixed-source journal");
        },
      }),
    ).rejects.toThrow("retain mixed-source journal");

    // The fallback is readable but stale. It is not negative proof that the
    // temporarily unreachable keyring lacks the committed final credential.
    await persistUserProvidedPassphrase(OLD_PASSPHRASE, {
      storagePath: f.storagePath,
      home: f.home,
      platformOverride: "freebsd",
    });
    const before = await rawEnvelope(f.storagePath);
    const storage = storageOf(f.storagePath);
    const journalBefore = await storage.read("_meta", "custody-rekey-journal");
    const unavailable: Exec = async (cmd, args, input) => {
      if (cmd === "security" && args[0] === "find-generic-password") {
        return { stdout: "", stderr: "User interaction is not allowed", code: 36 };
      }
      return kc.exec(cmd, args, input);
    };
    const { err } = capture();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: unavailable,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(1);
    expect(err.text).toMatch(/indeterminate|preserved/i);
    expect(Buffer.from((await rawEnvelope(f.storagePath))!).equals(Buffer.from(before!))).toBe(true);
    expect(Buffer.from((await storage.read("_meta", "custody-rekey-journal"))!).equals(
      Buffer.from(journalBefore!),
    )).toBe(true);
    expect(await unlockableBy(f.storagePath, {
      passphrase: OLD_PASSPHRASE,
    })).toBe(false);
  });

  it("preserves final custody when keyring is unreachable and fallback ciphertext is unreadable", async () => {
    const kc = fakeKeychain();
    await expect(runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
      faultAfterRekeyStage: (stage) => {
        if (stage === "final-written") throw new Error("retain unreadable-source journal");
      },
    })).rejects.toThrow("retain unreadable-source journal");
    await writeFile(join(f.storagePath, "passphrase.enc"), "not-an-envelope", {
      mode: 0o600,
    });
    const before = await rawEnvelope(f.storagePath);
    const storage = storageOf(f.storagePath);
    const journalBefore = await storage.read("_meta", "custody-rekey-journal");
    const unavailable: Exec = async (cmd, args, input) => {
      if (cmd === "security" && args[0] === "find-generic-password") {
        return { stdout: "", stderr: "User interaction is not allowed", code: 36 };
      }
      return kc.exec(cmd, args, input);
    };
    const { err } = capture();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: unavailable,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(1);
    expect(err.text).toMatch(/indeterminate|preserved/i);
    expect(Buffer.from((await rawEnvelope(f.storagePath))!).equals(Buffer.from(before!))).toBe(true);
    expect(Buffer.from((await storage.read("_meta", "custody-rekey-journal"))!).equals(
      Buffer.from(journalBefore!),
    )).toBe(true);
  });

  it("preserves augmented custody and its journal when stored-credential truth is indeterminate", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "stored-persisted") throw new Error("result lost after store");
        },
      }),
    ).rejects.toThrow("result lost after store");
    const before = await rawEnvelope(f.storagePath);
    const storage = storageOf(f.storagePath);
    expect(await storage.read("_meta", "custody-rekey-journal")).not.toBeNull();

    const unavailable: Exec = async (cmd, args, input) => {
      if (cmd === "security" && args[0] === "find-generic-password") {
        return { stdout: "", stderr: "User interaction is not allowed", code: 36 };
      }
      return kc.exec(cmd, args, input);
    };
    const { err } = capture();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: unavailable,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/indeterminate|preserved/i);
    expect(Buffer.from((await rawEnvelope(f.storagePath))!).equals(Buffer.from(before!))).toBe(true);
    expect(await storage.read("_meta", "custody-rekey-journal")).not.toBeNull();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    await assertConsistentAndOpenable(f, kc.store);
  });

  it("heals committed custody before quarantining corrupt non-authoritative history", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "stored-persisted") throw new Error("crash before commit label");
        },
      }),
    ).rejects.toThrow("crash before commit label");
    await writeFile(
      join(f.storagePath, ".reset-history.log"),
      '{"partial":true',
      { mode: 0o600, flag: "wx" },
    );

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    await assertConsistentAndOpenable(f, kc.store);
    expect((await readdir(f.storagePath)).some((name) =>
      name.startsWith(".reset-history.log.quarantine."),
    )).toBe(true);
  });

  it("refuses a tampered authenticated-journal shape without replacing custody", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "augmented-written") throw new Error("bounded injected failure");
        },
      }),
    ).rejects.toThrow(/bounded injected failure/);

    const storage = storageOf(f.storagePath);
    const before = await rawEnvelope(f.storagePath);
    const rawJournal = await storage.read("_meta", "custody-rekey-journal");
    expect(rawJournal).not.toBeNull();
    const forged = JSON.parse(Buffer.from(rawJournal!).toString("utf8")) as Record<string, unknown>;
    forged.prior_envelope = Buffer.from("foreign custody bytes").toString("base64url");
    await storage.write(
      "_meta",
      "custody-rekey-journal",
      Buffer.from(JSON.stringify(forged), "utf8"),
    );
    const canonicalValue = [...kc.store.values()][0]!;
    const legacyService = legacyKeychainServiceFor(f.storagePath, f.home);
    kc.store.set(legacyService, canonicalValue);

    const { out, err } = capture();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("authentication tag does not verify");
    const after = await rawEnvelope(f.storagePath);
    expect(Buffer.from(after!).equals(Buffer.from(before!))).toBe(true);
    expect(await storage.read("_meta", "custody-rekey-journal")).not.toBeNull();
    // Journal refusal precedes even authenticated keyring consolidation.
    expect(kc.store.get(legacyService)).toBe(canonicalValue);
  });

  it("refuses replay of an authentic journal from an older completed rekey", async () => {
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        faultAfterRekeyStage: (stage) => {
          if (stage === "final-written") throw new Error("retain old journal");
        },
      }),
    ).rejects.toThrow(/retain old journal/);
    const storage = storageOf(f.storagePath);
    const oldJournal = await storage.read("_meta", "custody-rekey-journal");
    expect(oldJournal).not.toBeNull();

    // Finish that transaction, then complete a newer one with a different wrap.
    for (let i = 0; i < 2; i++) {
      expect(await runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
      })).toBe(0);
    }
    const beforeReplay = await rawEnvelope(f.storagePath);
    await storage.write("_meta", "custody-rekey-journal", oldJournal!);

    const { err } = capture();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("does not describe the current custody transaction");
    const afterReplay = await rawEnvelope(f.storagePath);
    expect(Buffer.from(afterReplay!).equals(Buffer.from(beforeReplay!))).toBe(true);
    expect(await storage.read("_meta", "custody-rekey-journal")).not.toBeNull();
  });
});

describe.skipIf(process.platform === "win32")("real SIGKILL recovery", () => {
  let f: Seeded;
  beforeEach(async () => { f = await seed(); });
  afterEach(async () => { await f.cleanup(); });

  for (const stage of [
    "augmented-written",
    "custody-committed",
    "journal-clear-before-unlink",
    "journal-cleared",
  ] as const) {
    it(`releases the kernel lock and heals after actual process death at ${stage}`, async () => {
      const recoveryFile = join(f.home, "recovery-input");
      await writeFile(recoveryFile, f.recoveryKey, { mode: 0o600, flag: "wx" });
      const tsxCli = fileURLToPath(
        new URL("../../node_modules/tsx/dist/cli.mjs", import.meta.url),
      );
      const childFixture = fileURLToPath(
        new URL("./reset-passphrase-sigkill-child.ts", import.meta.url),
      );
      const child = spawn(process.execPath, [
        tsxCli,
        childFixture,
        f.storagePath,
        f.home,
        recoveryFile,
        stage,
      ], { stdio: ["ignore", "ignore", "pipe"] });
      let childDiagnostics = "";
      child.stderr.on("data", (chunk: Buffer) => {
        childDiagnostics += chunk.toString("utf8");
      });
      const death = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolve, reject) => {
          child.once("error", reject);
          child.once("close", (code, signal) => resolve({ code, signal }));
        },
      );
      // tsx's launcher reports its killed worker as the conventional shell
      // status 128 + SIGKILL(9), rather than forwarding ChildProcess.signal.
      expect(death, childDiagnostics.slice(0, 1_000)).toEqual({
        code: 137,
        signal: null,
      });

      const code = await runResetPassphraseCommand({
        // freebsd has no keyring; the recovery run re-persists to the machine-local
        // fallback, so it opts in (matching the killed child fixture).
        argv: [
          "--mode",
          "recovery-key",
          "--fortress",
          f.storagePath,
          "--allow-machine-local-passphrase",
        ],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "freebsd",
        recoveryKeyOverride: f.recoveryKey,
      });
      expect(code).toBe(0);
      expect(await unlockableBy(f.storagePath, {
        recoveryKey: fromBase64url(f.recoveryKey),
      })).toBe(true);
      expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(false);
      const stored = await readStoredPassphrase({
        storagePath: f.storagePath,
        home: f.home,
        platformOverride: "freebsd",
        readOnly: true,
      });
      expect(stored).not.toBeNull();
      expect(await unlockableBy(f.storagePath, { passphrase: stored!.value })).toBe(true);
      expect(await storageOf(f.storagePath).read("_meta", "custody-rekey-journal")).toBeNull();
    }, 30_000);
  }
});

describe("two-path (alias + real) concurrent rekey converges on one canonical credential (F5)", () => {
  let parent: string;
  afterEach(async () => {
    if (parent) await rm(parent, { recursive: true, force: true });
  });

  it("a rekey via a symlink alias and via the real path serialize on the shared lock and leave ONE consistent credential", async () => {
    parent = await mkdtemp(join(tmpdir(), "f5-twopath-"));
    const realFortress = join(parent, "real", ".sanctuary");
    await mkdir(join(realFortress, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(realFortress, "state"));
    const custody = await establishMaster({
      storage,
      passphrase: OLD_PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: true },
      storagePathHint: realFortress,
    });
    custody.masterKey.fill(0);
    const recoveryKey = custody.mintedRecoveryKey ?? "";

    // A symlink alias to the exact same physical fortress directory.
    const aliasFortress = join(parent, "alias-fortress");
    await symlink(realFortress, aliasFortress);

    // ONE shared in-memory keyring: both runs' persist/read route through it, and
    // canonicalKeychainServiceFor collapses alias + real onto the SAME service.
    const kc = fakeKeychain();
    const run = (fortressPath: string) =>
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", fortressPath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: recoveryKey,
        lockTimeoutMs: 5000,
      });
    const [a, b] = await Promise.all([run(realFortress), run(aliasFortress)]);
    // Serialized on the shared physical lockfile — no double-acquire, both succeed.
    expect(a).toBe(0);
    expect(b).toBe(0);

    // Exactly one credential survives (realpath collapses the two paths).
    expect(kc.store.size).toBe(1);
    const stored = [...kc.store.values()][0]!;
    // It opens the fortress; the old passphrase is gone; the recovery key works;
    // exactly one passphrase wrap remains.
    expect(await unlockableBy(realFortress, { passphrase: stored })).toBe(true);
    expect(await unlockableBy(realFortress, { passphrase: OLD_PASSPHRASE })).toBe(false);
    expect(await unlockableBy(realFortress, { recoveryKey: fromBase64url(recoveryKey) })).toBe(true);
    const env = await envelopeOf(realFortress);
    expect(env!.wraps.filter((w) => w.type === "passphrase")).toHaveLength(1);
  });
});

describe("recovery-key rekey secret zeroization (F4)", () => {
  let f: Seeded;
  beforeEach(async () => {
    f = await seed();
  });
  afterEach(async () => {
    await f.cleanup();
  });

  function allZero(buf: Uint8Array): boolean {
    return buf.every((b) => b === 0);
  }

  it("zeroes the recovery-key and master buffers on the success path", async () => {
    const captured: Array<{ label: string; buf: Uint8Array }> = [];
    const kc = fakeKeychain();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
      observeSecretBuffer: (label, buf) => captured.push({ label, buf }),
    });
    expect(code).toBe(0);
    expect(captured.map((c) => c.label).sort()).toEqual(["master", "recovery-key"]);
    for (const c of captured) expect(allZero(c.buf)).toBe(true);
  });

  it("zeroes the recovery-key buffer when the key is wrong (unwrap throws)", async () => {
    const captured: Array<{ label: string; buf: Uint8Array }> = [];
    const kc = fakeKeychain();
    const wrongKey = Buffer.alloc(32).toString("base64url"); // valid shape, wrong key
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: capture().out,
      err: capture().err,
      stdin: nonTtyStdin(),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: wrongKey,
      observeSecretBuffer: (label, buf) => captured.push({ label, buf }),
    });
    expect(code).toBe(1);
    // The recovery-key buffer was captured and zeroed; master was never created.
    expect(captured.some((c) => c.label === "recovery-key")).toBe(true);
    expect(captured.some((c) => c.label === "master")).toBe(false);
    for (const c of captured) expect(allZero(c.buf)).toBe(true);
  });

  it("zeroes both buffers when a crash is injected mid-transaction", async () => {
    const captured: Array<{ label: string; buf: Uint8Array }> = [];
    const kc = fakeKeychain();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
        out: capture().out,
        err: capture().err,
        stdin: nonTtyStdin(),
        home: f.home,
        platformOverride: "darwin",
        exec: kc.exec,
        recoveryKeyOverride: f.recoveryKey,
        observeSecretBuffer: (label, buf) => captured.push({ label, buf }),
        faultAfterRekeyStage: (s) => {
          if (s === "augmented-written") throw new Error("injected crash");
        },
      }),
    ).rejects.toThrow(/injected crash/);
    expect(captured.map((c) => c.label).sort()).toEqual(["master", "recovery-key"]);
    for (const c of captured) expect(allZero(c.buf)).toBe(true);
  });
});
