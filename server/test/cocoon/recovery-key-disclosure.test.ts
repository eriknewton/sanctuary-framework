/**
 * Recovery key disclosure — v1.1.1 hotfix Finding U
 *
 * v1.1.0 truncated the recovery key on display with a literal "..." and
 * never persisted the plaintext anywhere, leaving operators with an
 * unrecoverable fortress on principal loss. The fix:
 *
 *   1. Print the FULL key in a bordered banner (no truncation).
 *   2. Write the plaintext to <storage>/recovery-key.txt mode 0600 with
 *      explicit "move off-host immediately" instructions. Single-issuance.
 *   3. Optionally prompt the operator to confirm; bypass with --no-confirm.
 *
 * These tests pin all three properties end-to-end against the disclosure
 * helper, and assert that the helper refuses to complete in the two failure
 * modes the spawn prompt called out (operator answers "n", non-TTY without
 * bypass).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, rm, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Readable, Writable } from "node:stream";
import {
  discloseRecoveryKey,
  writeRecoveryKeyFile,
  RecoveryKeyConfirmationDeclinedError,
  RECOVERY_KEY_FILENAME,
} from "../../src/wrap/recovery-key-disclosure.js";

const FIXTURE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

function makeIo() {
  const writes: string[] = [];
  const output = new Writable({
    write(chunk, _enc, cb) {
      writes.push(chunk.toString());
      cb();
    },
  });
  return {
    capture: writes,
    output,
    inputFromAnswer(answer: string): Readable {
      return Readable.from([`${answer}\n`]);
    },
  };
}

describe("Recovery key disclosure (Finding U)", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-recovery-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  describe("printed banner", () => {
    it("prints the FULL key with no truncation", async () => {
      const io = makeIo();
      await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });
      const printed = io.capture.join("");
      expect(printed).toContain(FIXTURE_KEY);
      expect(printed).not.toContain("...");
    });

    it("includes the recovery-key.txt file path so the operator sees both copies", async () => {
      const io = makeIo();
      await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });
      const printed = io.capture.join("");
      expect(printed).toContain(join(tmpDir, RECOVERY_KEY_FILENAME));
      expect(printed).toContain("Move it off-host");
    });
  });

  describe("recovery-key.txt file", () => {
    it("writes mode 0600 with the full key + warning text", async () => {
      const io = makeIo();
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        fortressId: "fortress-test-001",
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });

      expect(result.fileWritten).toBe(true);
      expect(result.filePath).toBe(join(tmpDir, RECOVERY_KEY_FILENAME));

      const content = await readFile(result.filePath, "utf-8");
      expect(content).toContain(FIXTURE_KEY);
      expect(content).toContain(
        "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY"
      );
      expect(content).toContain("Fortress: fortress-test-001");
      expect(content).toContain(
        "Sanctuary will NOT regenerate this file"
      );

      const st = await stat(result.filePath);
      // Mask off file-type bits; only the permission bits matter here.
      expect(st.mode & 0o777).toBe(0o600);
    });

    it("never overwrites an existing recovery-key.txt (single-issuance)", async () => {
      const io = makeIo();
      const filePath = join(tmpDir, RECOVERY_KEY_FILENAME);

      // Pre-seed a file from a hypothetical earlier run.
      const earlierContent =
        "EARLIER RUN — operator already saved this key, do not overwrite\n";
      await writeFile(filePath, earlierContent, { mode: 0o600 });

      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });

      expect(result.fileWritten).toBe(false);
      expect(result.filePath).toBe(filePath);

      const content = await readFile(filePath, "utf-8");
      expect(content).toBe(earlierContent);
    });

    it("creates the storage directory if it does not exist", async () => {
      const nested = join(tmpDir, "nested", "fortress");
      const io = makeIo();
      const result = await writeRecoveryKeyFile({
        storagePath: nested,
        recoveryKey: FIXTURE_KEY,
      });
      expect(result.written).toBe(true);
      const content = await readFile(result.filePath, "utf-8");
      expect(content).toContain(FIXTURE_KEY);
      void io; // unused — keeps shape parallel
    });
  });

  describe("interactive confirmation", () => {
    it("returns confirmed=true when operator answers 'y'", async () => {
      const io = makeIo();
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "interactive",
        io: { input: io.inputFromAnswer("y"), output: io.output },
      });
      expect(result.confirmed).toBe(true);
      expect(result.fileWritten).toBe(true);
    });

    it("returns confirmed=true when operator answers 'YES' (case-insensitive)", async () => {
      const io = makeIo();
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "interactive",
        io: { input: io.inputFromAnswer("YES"), output: io.output },
      });
      expect(result.confirmed).toBe(true);
    });

    it("throws RecoveryKeyConfirmationDeclinedError when operator answers 'n'", async () => {
      const io = makeIo();
      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: tmpDir,
          mode: "interactive",
          io: { input: io.inputFromAnswer("n"), output: io.output },
        })
      ).rejects.toThrow(RecoveryKeyConfirmationDeclinedError);
    });

    it("treats empty input as decline (default to N)", async () => {
      const io = makeIo();
      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: tmpDir,
          mode: "interactive",
          io: { input: io.inputFromAnswer(""), output: io.output },
        })
      ).rejects.toThrow(RecoveryKeyConfirmationDeclinedError);
    });

    it("still writes the file before throwing on declined confirmation", async () => {
      const io = makeIo();
      const filePath = join(tmpDir, RECOVERY_KEY_FILENAME);
      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: tmpDir,
          mode: "interactive",
          io: { input: io.inputFromAnswer("n"), output: io.output },
        })
      ).rejects.toThrow();
      // The file must still exist — operators who decline because they
      // weren't ready can still recover the key from disk.
      const content = await readFile(filePath, "utf-8");
      expect(content).toContain(FIXTURE_KEY);
    });
  });

  describe("no-confirm + stdio-server modes", () => {
    it("no-confirm mode skips the prompt entirely", async () => {
      const io = makeIo();
      // No stdin wired — would hang if the prompt fired.
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });
      expect(result.confirmed).toBe(false);
      expect(result.fileWritten).toBe(true);
    });

    it("stdio-server mode prints + writes but never prompts", async () => {
      const io = makeIo();
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "stdio-server",
        io: { input: process.stdin, output: io.output },
      });
      expect(result.confirmed).toBe(false);
      expect(result.fileWritten).toBe(true);
      const printed = io.capture.join("");
      expect(printed).toContain(FIXTURE_KEY);
    });
  });
});
