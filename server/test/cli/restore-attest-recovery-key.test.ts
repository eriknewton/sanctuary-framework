/**
 * `sanctuary restore-attest --recovery-key-prompt` — attest a restore with the
 * human-held recovery key instead of the passphrase (the second-host case).
 *
 * Verifies the recovery key unlocks and re-baselines the epoch witness, and that
 * the flag refuses a non-interactive session when no test override is supplied.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";

import { runRestoreAttestCommand } from "../../src/cli/restore-attest.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  establishMaster,
  withCustodyWriteLock,
} from "../../src/core/master-custody.js";

const PASSPHRASE = "restore-rk-correct-horse-not-a-real-secret";

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

function nonTtyStdin(isTTY = false): NodeJS.ReadableStream & { isTTY?: boolean } {
  const s = Readable.from([Buffer.from("")]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  s.isTTY = isTTY;
  return s;
}

interface Seeded {
  storagePath: string;
  home: string;
  recoveryKey: string;
  cleanup: () => Promise<void>;
}

async function seed(): Promise<Seeded> {
  const home = await mkdtemp(join(tmpdir(), "restore-rk-"));
  const storagePath = join(home, ".sanctuary");
  await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const custody = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: true },
    storagePathHint: storagePath,
  });
  custody.masterKey.fill(0);
  return {
    storagePath,
    home,
    recoveryKey: custody.mintedRecoveryKey!,
    cleanup: () => rm(home, { recursive: true, force: true }),
  };
}

describe("restore-attest --recovery-key-prompt", () => {
  let f: Seeded;
  beforeEach(async () => {
    f = await seed();
  });
  afterEach(async () => {
    await f.cleanup();
  });

  it("attests using the recovery key and re-baselines the epoch witness", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runRestoreAttestCommand({
      argv: ["--fortress", f.storagePath, "--recovery-key-prompt"],
      out,
      err,
      stdin: nonTtyStdin(false),
      home: f.home,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(0);
    expect(out.text).toMatch(/re-baselined|Attested/);
  });

  it("holds the shared custody writer lock from authentication through attestation", async () => {
    let entered!: () => void;
    const authenticated = new Promise<void>((resolve) => { entered = resolve; });
    let release!: () => void;
    const hold = new Promise<void>((resolve) => { release = resolve; });
    const restore = runRestoreAttestCommand({
      argv: ["--fortress", f.storagePath, "--recovery-key-prompt"],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      recoveryKeyOverride: f.recoveryKey,
      beforeAttestationCommit: async () => {
        entered();
        await hold;
      },
    });
    await authenticated;

    const storage = new FilesystemStorage(join(f.storagePath, "state"));
    let contenderEntered = false;
    const contender = withCustodyWriteLock(storage, async () => {
      contenderEntered = true;
    }, { timeoutMs: 2_000, metadata: { owner: "test-contender" } });
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(contenderEntered).toBe(false);

    release();
    expect(await restore).toBe(0);
    await contender;
    expect(contenderEntered).toBe(true);
  });

  it("refuses a non-interactive session when no override is supplied", async () => {
    const err = new StringWritable();
    const code = await runRestoreAttestCommand({
      argv: ["--fortress", f.storagePath, "--recovery-key-prompt"],
      out: new StringWritable(),
      err,
      stdin: nonTtyStdin(false),
      home: f.home,
      // no recoveryKeyOverride → the real TTY guard fires
    });
    expect(code).toBe(1);
    expect(err.text).toContain("interactive terminal");
  });

  it("refuses a piped default passphrase instead of reading it visibly", async () => {
    const err = new StringWritable();
    const piped = Readable.from([Buffer.from(`${PASSPHRASE}\n`)]) as unknown as
      NodeJS.ReadableStream & { isTTY?: boolean };
    piped.isTTY = false;
    const code = await runRestoreAttestCommand({
      argv: ["--fortress", f.storagePath],
      out: new StringWritable(),
      err,
      stdin: piped,
      home: f.home,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("interactive terminal");
  });
});
