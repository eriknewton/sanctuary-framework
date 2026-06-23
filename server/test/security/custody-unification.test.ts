/**
 * Custody unification — server-level incident regression
 * (sovereign-custody build, 2026-06-12; durable-escrow fix, 2026-06-23).
 *
 * The D4 Hermes drill nearly lost a fortress because the printed
 * recovery-key.txt held a PARALLEL master that did not reconstruct the
 * passphrase-derived master the data actually lived under. These tests boot
 * the real MCP server twice against a real filesystem fortress and prove the
 * disclosed recovery key now unlocks the same master the passphrase does — for
 * both first-run modes.
 *
 * Durable-escrow fix: the boot path NO LONGER writes recovery-key.txt inside
 * the fortress (the orphaning bug). The freshly minted key is escrowed to an
 * OFF-HOST path via SANCTUARY_RECOVERY_OUT, which is how these tests now
 * recover the disclosed key. The invariant under test is unchanged: the
 * disclosed key reconstructs the same master, with no parallel master.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createSanctuaryServer } from "../../src/index.js";
import { toBase64url } from "../../src/core/encoding.js";

const RECOVERY_KEY_FILENAME = "recovery-key.txt";

function extractRecoveryKey(fileContent: string): string {
  const line = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!line) throw new Error("no recovery key found in disclosure file");
  return line;
}

let savedPassphrase: string | undefined;
let savedRecoveryKey: string | undefined;
let savedStoragePath: string | undefined;
let savedRecoveryOut: string | undefined;
let fortress: string;
let escrowDir: string;
let escrowPath: string;

beforeEach(async () => {
  savedPassphrase = process.env.SANCTUARY_PASSPHRASE;
  savedRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
  savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  savedRecoveryOut = process.env.SANCTUARY_RECOVERY_OUT;
  delete process.env.SANCTUARY_PASSPHRASE;
  delete process.env.SANCTUARY_RECOVERY_KEY;
  fortress = await mkdtemp(join(tmpdir(), "sanctuary-custody-unify-"));
  escrowDir = await mkdtemp(join(tmpdir(), "sanctuary-custody-unify-escrow-"));
  escrowPath = join(escrowDir, "recovery.txt");
  process.env.SANCTUARY_STORAGE_PATH = fortress;
  // Durable off-host escrow target (replaces the orphaning in-fortress file).
  process.env.SANCTUARY_RECOVERY_OUT = escrowPath;
});

afterEach(async () => {
  if (savedPassphrase !== undefined) process.env.SANCTUARY_PASSPHRASE = savedPassphrase;
  else delete process.env.SANCTUARY_PASSPHRASE;
  if (savedRecoveryKey !== undefined) process.env.SANCTUARY_RECOVERY_KEY = savedRecoveryKey;
  else delete process.env.SANCTUARY_RECOVERY_KEY;
  if (savedStoragePath !== undefined) process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
  else delete process.env.SANCTUARY_STORAGE_PATH;
  if (savedRecoveryOut !== undefined) process.env.SANCTUARY_RECOVERY_OUT = savedRecoveryOut;
  else delete process.env.SANCTUARY_RECOVERY_OUT;
  await rm(fortress, { recursive: true, force: true });
  await rm(escrowDir, { recursive: true, force: true });
});

describe("custody unification (incident regression)", () => {
  it("a passphrase-mode fortress's disclosed recovery key unlocks the SAME master the passphrase does", async () => {
    process.env.SANCTUARY_PASSPHRASE = "drill-fortress-passphrase";
    const first = await createSanctuaryServer({});
    const firstMaster = toBase64url(first.masterKey);

    // The server escrowed a recovery key off-host on first run — for the
    // passphrase mode too (the drill gap: passphrase fortresses had no
    // working recovery artifact at all). It is NOT inside the fortress.
    await expect(
      stat(join(fortress, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    const fileContent = await readFile(escrowPath, "utf-8");
    const recoveryKey = extractRecoveryKey(fileContent);

    // Boot 2: recovery key ONLY (passphrase lost — the T1 scenario).
    delete process.env.SANCTUARY_PASSPHRASE;
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const second = await createSanctuaryServer({});
    expect(toBase64url(second.masterKey)).toBe(firstMaster);

    // Boot 3: passphrase again — same master, no divergence.
    delete process.env.SANCTUARY_RECOVERY_KEY;
    process.env.SANCTUARY_PASSPHRASE = "drill-fortress-passphrase";
    const third = await createSanctuaryServer({});
    expect(toBase64url(third.masterKey)).toBe(firstMaster);
  });

  it("a recovery-key-mode fortress restarts on its disclosed key (stdio first-run)", async () => {
    const first = await createSanctuaryServer({});
    const firstMaster = toBase64url(first.masterKey);

    // Escrowed off-host, never inside the fortress.
    await expect(
      stat(join(fortress, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    const fileContent = await readFile(escrowPath, "utf-8");
    const recoveryKey = extractRecoveryKey(fileContent);

    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const second = await createSanctuaryServer({});
    expect(toBase64url(second.masterKey)).toBe(firstMaster);
  });

  it("a wrong credential fails closed at boot (no silent wrong-master start)", async () => {
    process.env.SANCTUARY_PASSPHRASE = "right-passphrase";
    await createSanctuaryServer({});

    process.env.SANCTUARY_PASSPHRASE = "wrong-passphrase";
    await expect(createSanctuaryServer({})).rejects.toThrow(
      /does not unlock/
    );
  });

  it("boot first-run FAILS CLOSED with no off-host escrow target (durable-fix gate)", async () => {
    // No SANCTUARY_RECOVERY_OUT, no passphrase, no tty: the boot must refuse
    // to finish rather than leave the freshly minted key uncaptured.
    delete process.env.SANCTUARY_RECOVERY_OUT;
    delete process.env.SANCTUARY_PASSPHRASE;
    await expect(createSanctuaryServer({})).rejects.toThrow(
      /no way to hand it to you safely|off-host escrow target/i,
    );
    // And nothing was written inside the fortress.
    await expect(
      stat(join(fortress, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });
});
