import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  establishMaster,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
} from "../../src/core/master-custody.js";
import {
  PENDING_RECOVERY_KEY,
  rotateMaster,
} from "../../src/core/master-rotation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  canonicalRecoveryKeyServiceFor,
  reconcilePendingRecoveryKeyRotationInKeychain,
  stageRecoveryKeyRotationInKeychain,
} from "../../src/wrap/keychain-custody.js";
import {
  reconcileRotationRecoveryKeyFile,
  writeRotationRecoveryKeyFileTransactional,
} from "../../src/wrap/recovery-key-disclosure.js";
import type { ExecResult } from "../../src/wrap/exec-result.js";

const supported = process.platform === "darwin" || process.platform === "linux";

describe.skipIf(!supported)("pre-journal recovery escrow process-death recovery", () => {
  const cleanup: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map((path) =>
      rm(path, { recursive: true, force: true })));
  });

  async function readItems(path: string): Promise<Record<string, string>> {
    return JSON.parse(await readFile(path, "utf8")) as Record<string, string>;
  }

  function fileKeyringExec(path: string) {
    return async (_cmd: string, args: string[], input?: string): Promise<ExecResult> => {
      const service = args[args.indexOf("service") + 1];
      if (!service) throw new Error("fake keyring command omitted service");
      const items = await readItems(path);
      if (args[0] === "lookup") {
        const value = items[service];
        return value === undefined
          ? { stdout: "", stderr: "not found", code: 1 }
          : { stdout: `${value}\n`, stderr: "", code: 0 };
      }
      if (args[0] === "store") {
        items[service] = (input ?? "").trim();
        await writeFile(path, JSON.stringify(items), { mode: 0o600 });
        return { stdout: "", stderr: "", code: 0 };
      }
      if (args[0] === "clear") {
        delete items[service];
        await writeFile(path, JSON.stringify(items), { mode: 0o600 });
        return { stdout: "", stderr: "", code: 0 };
      }
      throw new Error("unexpected fake keyring command");
    };
  }

  for (const mode of ["file", "keyring"] as const) {
    it(`reconciles ${mode}-only SIGKILL residue and a failed re-entry can retry`, async () => {
      const root = await mkdtemp(join(tmpdir(), `sanctuary-prejournal-${mode}-`));
      cleanup.push(root);
      const fortressPath = join(root, "fortress");
      const home = join(root, "home");
      const recoveryOut = join(root, "rotated-recovery.txt");
      const keyringState = join(root, "keyring.json");
      await writeFile(keyringState, "{}", { mode: 0o600 });
      const passphrase = `prejournal-${mode}-passphrase`;
      const storage = new FilesystemStorage(join(fortressPath, "state"));
      const initialized = await establishMaster({
        storage,
        passphrase,
        firstRun: { installMode: "interactive", mintRecoveryKey: true },
      });
      const oldRecoveryKey = initialized.mintedRecoveryKey!;
      await initialized.masterWriteBarrier?.release();
      initialized.masterKey.fill(0);

      const canonical = canonicalRecoveryKeyServiceFor(fortressPath, home);
      if (mode === "keyring") {
        await writeFile(
          keyringState,
          JSON.stringify({ [canonical]: oldRecoveryKey }),
          { mode: 0o600 },
        );
      }
      const fixture = fileURLToPath(
        new URL("./master-rotation-prejournal-sigkill-child.ts", import.meta.url),
      );
      const child = spawn(process.execPath, [
        "--import", "tsx", fixture, fortressPath, passphrase, mode,
        recoveryOut, keyringState, home,
      ], { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
      const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolve, reject) => {
          child.once("error", reject);
          child.once("close", (code, signal) => resolve({ code, signal }));
        },
      );
      expect(exit, stderr).toEqual({ code: null, signal: "SIGKILL" });
      expect(await storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
      expect(await storage.read("_meta", PENDING_RECOVERY_KEY)).not.toBeNull();
      expect(await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)).not.toBeNull();
      if (mode === "file") {
        expect((await stat(recoveryOut)).mode & 0o777).toBe(0o600);
      } else {
        const items = await readItems(keyringState);
        expect(items[canonical]).toBe(oldRecoveryKey);
        expect(Object.keys(items).some((key) => key.includes(":rotation:"))).toBe(true);
      }

      const exec = fileKeyringExec(keyringState);
      // First re-entry deliberately fails after new escrow publication. The
      // engine must roll it back together with pending metadata, so a second
      // attempt can use the exact same output authority.
      await expect(rotateMaster({
        storage,
        fortressPath,
        fortressId: "prejournal-sigkill",
        passphrase,
        approve: async () => true,
        reconcilePendingRecoveryEscrow: async (pending, verify) => {
          for (const authority of pending.authorities) {
            if (authority.kind === "recovery-file") {
              await reconcileRotationRecoveryKeyFile(authority, verify);
            } else {
              await reconcilePendingRecoveryKeyRotationInKeychain(
                fortressPath,
                pending.rotation_id,
                authority,
                verify,
                { home, platformOverride: "linux", exec },
              );
            }
          }
        },
        captureRecoveryKey: async (key, verify, rotationId, register) => {
          expect(await verify(key)).toBe(true);
          if (mode === "file") {
            const mutation = await writeRotationRecoveryKeyFileTransactional({
              storagePath: fortressPath,
              recoveryKeyFilePath: recoveryOut,
              recoveryKey: key,
              fortressId: "prejournal-sigkill",
              registerPendingAuthority: register,
            });
            await mutation.rollback();
            return false;
          }
          const mutation = await stageRecoveryKeyRotationInKeychain(
            fortressPath,
            key,
            rotationId,
            { home, platformOverride: "linux", exec },
            register,
          );
          await mutation.rollback();
          return false;
        },
      })).rejects.toThrow(/capture was not completed/);
      expect(await storage.read("_meta", PENDING_RECOVERY_KEY)).toBeNull();
      if (mode === "file") {
        await expect(access(recoveryOut)).rejects.toThrow();
      } else {
        expect(await readItems(keyringState)).toEqual({ [canonical]: oldRecoveryKey });
      }

      let activeRecoveryKey = "";
      await rotateMaster({
        storage,
        fortressPath,
        fortressId: "prejournal-sigkill",
        passphrase,
        approve: async () => true,
        reconcilePendingRecoveryEscrow: async () => {
          throw new Error("the failed re-entry left unexpected reconciliation residue");
        },
        captureRecoveryKey: async (key, verify, rotationId, register) => {
          activeRecoveryKey = key;
          expect(await verify(key)).toBe(true);
          if (mode === "file") {
            const mutation = await writeRotationRecoveryKeyFileTransactional({
              storagePath: fortressPath,
              recoveryKeyFilePath: recoveryOut,
              recoveryKey: key,
              fortressId: "prejournal-sigkill",
              registerPendingAuthority: register,
            });
            return {
              captured: true,
              commit: async () => mutation.commit(),
              rollback: () => mutation.rollback(),
            };
          }
          return stageRecoveryKeyRotationInKeychain(
            fortressPath,
            key,
            rotationId,
            { home, platformOverride: "linux", exec },
            register,
          );
        },
      });
      expect(await storage.read("_meta", PENDING_RECOVERY_KEY)).toBeNull();
      const viaRecovery = await establishMaster({ storage, recoveryKey: activeRecoveryKey });
      await viaRecovery.masterWriteBarrier?.release();
      viaRecovery.masterKey.fill(0);
      if (mode === "keyring") {
        expect(await readItems(keyringState)).toEqual({ [canonical]: activeRecoveryKey });
      }
    }, 30_000);
  }
});
