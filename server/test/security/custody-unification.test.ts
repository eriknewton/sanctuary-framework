/**
 * Custody unification — server-level incident regression
 * (sovereign-custody build, 2026-06-12).
 *
 * The D4 Hermes drill nearly lost a fortress because the printed
 * recovery-key.txt held a PARALLEL master that did not reconstruct the
 * passphrase-derived master the data actually lived under. These tests
 * boot the real MCP server twice against a real filesystem fortress and
 * prove the disclosed recovery key now unlocks the same master the
 * passphrase does — for both first-run modes.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
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
let fortress: string;

beforeEach(async () => {
  savedPassphrase = process.env.SANCTUARY_PASSPHRASE;
  savedRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
  savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  delete process.env.SANCTUARY_PASSPHRASE;
  delete process.env.SANCTUARY_RECOVERY_KEY;
  fortress = await mkdtemp(join(tmpdir(), "sanctuary-custody-unify-"));
  process.env.SANCTUARY_STORAGE_PATH = fortress;
});

afterEach(async () => {
  if (savedPassphrase !== undefined) process.env.SANCTUARY_PASSPHRASE = savedPassphrase;
  else delete process.env.SANCTUARY_PASSPHRASE;
  if (savedRecoveryKey !== undefined) process.env.SANCTUARY_RECOVERY_KEY = savedRecoveryKey;
  else delete process.env.SANCTUARY_RECOVERY_KEY;
  if (savedStoragePath !== undefined) process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
  else delete process.env.SANCTUARY_STORAGE_PATH;
  await rm(fortress, { recursive: true, force: true });
});

describe("custody unification (incident regression)", () => {
  it("a passphrase-mode fortress's disclosed recovery key unlocks the SAME master the passphrase does", async () => {
    process.env.SANCTUARY_PASSPHRASE = "drill-fortress-passphrase";
    const first = await createSanctuaryServer({});
    const firstMaster = toBase64url(first.masterKey);

    // The server disclosed a recovery key on first run — for the
    // passphrase mode too (the drill gap: passphrase fortresses had no
    // working recovery artifact at all).
    const fileContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );
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

    const fileContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );
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
});
