/**
 * Subprocess fixture for the real process-death rekey test.
 *
 * It runs the production recovery-key transaction against a temp fortress and
 * kills itself with SIGKILL immediately after the requested durable boundary.
 * The recovery key is read from a mode-restricted temp file, never argv/output.
 */

import { readFile } from "node:fs/promises";
import { Writable, Readable } from "node:stream";

import {
  runResetPassphraseCommand,
  type RekeyStage,
} from "../../src/cli/reset-passphrase.js";

class Sink extends Writable {
  override _write(
    _chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    callback();
  }
}

const [storagePath, home, recoveryFile, killStage] = process.argv.slice(2);
if (!storagePath || !home || !recoveryFile || !killStage) process.exit(2);

const recoveryKey = (await readFile(recoveryFile, "utf8")).trim();
const stdin = Readable.from([]) as Readable & { isTTY?: boolean };
stdin.isTTY = false;

await runResetPassphraseCommand({
  // freebsd has no OS keyring, so the fresh passphrase lands in the machine-local
  // fallback file; S3 refuses that by default, so this durability fixture opts in.
  argv: [
    "--mode",
    "recovery-key",
    "--fortress",
    storagePath,
    "--allow-machine-local-passphrase",
  ],
  out: new Sink(),
  err: new Sink(),
  stdin,
  home,
  platformOverride: "freebsd",
  recoveryKeyOverride: recoveryKey,
  faultAfterRekeyStage: (stage) => {
    if (stage === (killStage as RekeyStage)) process.kill(process.pid, "SIGKILL");
  },
});

process.exit(3);
