/** Hard-kill fixture for pre-journal recovery escrow reconciliation. */

import { readFile, writeFile } from "node:fs/promises";

import { rotateMaster } from "../../src/core/master-rotation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { stageRecoveryKeyRotationInKeychain } from "../../src/wrap/keychain-custody.js";
import { writeRotationRecoveryKeyFileTransactional } from "../../src/wrap/recovery-key-disclosure.js";
import type { ExecResult } from "../../src/wrap/exec-result.js";

const [fortressPath, passphrase, mode, recoveryOut, keyringState, home] =
  process.argv.slice(2);
if (!fortressPath || !passphrase || !mode || !recoveryOut || !keyringState || !home) {
  throw new Error("missing pre-journal SIGKILL fixture arguments");
}

async function readItems(): Promise<Record<string, string>> {
  return JSON.parse(await readFile(keyringState, "utf8")) as Record<string, string>;
}

const keyringExec = async (
  _cmd: string,
  args: string[],
  input?: string,
): Promise<ExecResult> => {
  const service = args[args.indexOf("service") + 1];
  if (!service) throw new Error("fake keyring command omitted service");
  const items = await readItems();
  if (args[0] === "lookup") {
    const value = items[service];
    return value === undefined
      ? { stdout: "", stderr: "not found", code: 1 }
      : { stdout: `${value}\n`, stderr: "", code: 0 };
  }
  if (args[0] === "store") {
    items[service] = (input ?? "").trim();
    await writeFile(keyringState, JSON.stringify(items), { mode: 0o600 });
    return { stdout: "", stderr: "", code: 0 };
  }
  if (args[0] === "clear") {
    delete items[service];
    await writeFile(keyringState, JSON.stringify(items), { mode: 0o600 });
    return { stdout: "", stderr: "", code: 0 };
  }
  throw new Error("unexpected fake keyring command");
};

await rotateMaster({
  storage: new FilesystemStorage(`${fortressPath}/state`),
  fortressPath,
  fortressId: "prejournal-sigkill",
  passphrase,
  approve: async () => true,
  captureRecoveryKey: async (key, verify, rotationId, register) => {
    if (!(await verify(key))) return false;
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
    if (mode === "keyring") {
      return stageRecoveryKeyRotationInKeychain(
        fortressPath,
        key,
        rotationId,
        { home, platformOverride: "linux", exec: keyringExec },
        register,
      );
    }
    throw new Error(`unexpected SIGKILL mode ${mode}`);
  },
  failpoint: (point) => {
    if (point === "recovery-escrow-captured-pre-journal") {
      process.kill(process.pid, "SIGKILL");
    }
  },
});

process.exit(3);
