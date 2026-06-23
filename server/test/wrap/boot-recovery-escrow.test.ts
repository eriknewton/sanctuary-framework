/**
 * Boot-path recovery-key escrow tests (the durable fortress-key fix).
 *
 * Regression target: the MCP-server and standalone-dashboard boot paths used
 * to mint a recovery key and write `recovery-key.txt` INSIDE the fortress dir
 * (which gets scratch-cleared / orphaned), and never escrow it off-host. These
 * tests pin the durable-fix contract:
 *  - the key is NEVER written inside the fortress directory,
 *  - the key NEVER lands in a captured stream / log / exception message,
 *  - the provisioning gate refuses to finish without confirmed off-host
 *    capture (interactive) or an explicit escrow target (non-interactive),
 *  - non-interactive + no escrow target fails closed.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import {
  escrowBootRecoveryKey,
  BootRecoveryKeyEscrowRequiredError,
  BootRecoveryKeyCaptureDeclinedError,
} from "../../src/wrap/boot-recovery-escrow.js";
import type { KeychainCustodyOptions } from "../../src/wrap/keychain-custody.js";

// 32-byte base64url fixture recovery key.
const FIXTURE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/** A keychain backend that always fails (no keyring) — keeps tests hermetic. */
const NO_KEYRING: KeychainCustodyOptions = {
  platformOverride: "linux",
  exec: async () => ({ stdout: "", stderr: "no keyring", code: 1 }),
};

/** A keychain backend that accepts writes and reads them back. */
function memoryKeyring(): KeychainCustodyOptions {
  const store = new Map<string, string>();
  return {
    platformOverride: "linux",
    exec: async (cmd, args, input) => {
      if (cmd === "secret-tool" && args[0] === "store") {
        const svcIdx = args.indexOf("service");
        const svc = args[svcIdx + 1]!;
        store.set(svc, (input ?? "").replace(/\n$/, ""));
        return { stdout: "", stderr: "", code: 0 };
      }
      if (cmd === "secret-tool" && args[0] === "lookup") {
        const svcIdx = args.indexOf("service");
        const svc = args[svcIdx + 1]!;
        const v = store.get(svc);
        return v
          ? { stdout: v + "\n", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 1 };
      }
      return { stdout: "", stderr: "unexpected", code: 1 };
    },
  };
}

describe("escrowBootRecoveryKey — durable boot-path escrow", () => {
  let fortress: string;
  let tty: { writes: string[]; write: (t: string) => void };

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "sanctuary-boot-escrow-"));
    const writes: string[] = [];
    tty = { writes, write: (t: string) => writes.push(t) };
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  it("discloses on the tty and never writes recovery-key.txt in the fortress", async () => {
    // A durable off-host target satisfies the gate under noConfirm; the key is
    // still disclosed on the tty for the human, and never co-located inside the
    // fortress dir.
    const outDir = await mkdtemp(join(tmpdir(), "sanctuary-recovery-out-"));
    const outPath = join(outDir, "recovery.txt");
    try {
      const result = await escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryOut: outPath,
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write },
      });

      // Key appears on the tty channel and the off-host target, never the fortress.
      expect(tty.writes.join("")).toContain(FIXTURE_KEY);
      expect(result.disclosedOnTty).toBe(true);

      // No recovery-key.txt anywhere under the fortress directory.
      const entries = await readdir(fortress);
      expect(entries).not.toContain("recovery-key.txt");
      await expect(stat(join(fortress, "recovery-key.txt"))).rejects.toThrow();
      await expect(
        stat(join(fortress, "state", "recovery-key.txt")),
      ).rejects.toThrow();
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("fails closed under noConfirm even WITH a controlling terminal when no durable target exists (orphaning regression)", async () => {
    // The dangerous case the durable fix must close: noConfirm + a tty present
    // (interactive seam, no nonInteractive flag) + NO off-host target. An
    // unconfirmed one-shot tty flash is NOT proof of capture, so the gate must
    // fail closed rather than mint an uncaptured sole-factor recovery key.
    let threw: unknown;
    try {
      await escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write },
      });
    } catch (err) {
      threw = err;
    }
    expect(threw).toBeInstanceOf(BootRecoveryKeyEscrowRequiredError);
    expect((threw as Error).message).not.toContain(FIXTURE_KEY);
    // Nothing precious survives: no in-fortress recovery copy was written.
    await expect(stat(join(fortress, "recovery-key.txt"))).rejects.toThrow();
  });

  it("never leaks the recovery key into the return value or an exception", async () => {
    // No tty + no escrow target: must fail closed, and the error must not
    // contain the key.
    let threw: unknown;
    try {
      await escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write, nonInteractive: true },
      });
    } catch (err) {
      threw = err;
    }
    expect(threw).toBeInstanceOf(BootRecoveryKeyEscrowRequiredError);
    expect((threw as Error).message).not.toContain(FIXTURE_KEY);
    // Nothing disclosed on the tty in the no-tty branch.
    expect(tty.writes.join("")).not.toContain(FIXTURE_KEY);
  });

  it("fails closed: non-interactive AND no escrow target", async () => {
    await expect(
      escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write, nonInteractive: true },
      }),
    ).rejects.toBeInstanceOf(BootRecoveryKeyEscrowRequiredError);
  });

  it("passes the gate non-interactively when --recovery-out target is given (off-host, outside fortress)", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "sanctuary-recovery-out-"));
    const outPath = join(outDir, "recovery.txt");
    try {
      const result = await escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryOut: outPath,
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write, nonInteractive: true },
      });
      expect(result.recoveryOutPath).toBe(outPath);
      const content = await readFile(outPath, "utf-8");
      expect(content).toContain(FIXTURE_KEY);
      // Still nothing inside the fortress.
      await expect(
        stat(join(fortress, "recovery-key.txt")),
      ).rejects.toThrow();
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("refuses a --recovery-out path INSIDE the fortress (no co-located secret)", async () => {
    await expect(
      escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryOut: join(fortress, "inside.txt"),
        recoveryKeychain: NO_KEYRING,
        noConfirm: true,
        ttyChannel: { write: tty.write, nonInteractive: true },
      }),
    ).rejects.toThrow();
  });

  it("escrows to the OS keyring when a keyring is available, satisfying the gate", async () => {
    const result = await escrowBootRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      storagePath: fortress,
      attemptKeychainEscrow: true,
      recoveryKeychain: memoryKeyring(),
      noConfirm: true,
      ttyChannel: { write: tty.write, nonInteractive: true },
    });
    expect(result.keychainService).toBeTruthy();
    // Key never written to disk inside the fortress.
    await expect(stat(join(fortress, "recovery-key.txt"))).rejects.toThrow();
  });

  it("interactive: confirms off-host capture at the tty (y)", async () => {
    const result = await escrowBootRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      storagePath: fortress,
      recoveryKeychain: NO_KEYRING,
      ttyChannel: {
        write: tty.write,
        input: Readable.from(["y\n"]),
      },
    });
    expect(result.confirmed).toBe(true);
    expect(tty.writes.join("")).toContain(FIXTURE_KEY);
  });

  it("interactive: declining capture (n) throws and aborts", async () => {
    await expect(
      escrowBootRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortress,
        recoveryKeychain: NO_KEYRING,
        ttyChannel: {
          write: tty.write,
          input: Readable.from(["n\n"]),
        },
      }),
    ).rejects.toBeInstanceOf(BootRecoveryKeyCaptureDeclinedError);
  });
});
