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
import {
  mkdir,
  readdir,
  rm,
  readFile,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { Readable, Writable } from "node:stream";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { cleanupFreshInitRecoveryResidue } from "../../src/storage/fresh-fortress.js";
import {
  discloseRecoveryKey,
  resolveRecoveryKeyOutputPath,
  writeRecoveryKeyFile,
  RecoveryKeyConfirmationDeclinedError,
  RecoveryKeyOutputPathExistsError,
  RecoveryKeyOutputPathSymlinkError,
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
  // Power-cut fixture children spawned by the "recovery-key.txt file" cases
  // below. Each is SIGKILLed on its own happy path once the assertion on its
  // READY line passes, but that assertion runs inside an async stdout
  // "data" handler: if it throws (a real regression, a slow host), the kill
  // below it never runs and the child is orphaned. Tracked here so teardown
  // reaps it regardless of how the test exited.
  const spawnedChildren: ChildProcess[] = [];

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-recovery-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpDir, { recursive: true, mode: 0o700 });
    spawnedChildren.length = 0;
  });

  afterEach(async () => {
    for (const child of spawnedChildren) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }
    spawnedChildren.length = 0;
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

    it("writes to a custom off-fortress path with mode 0600", async () => {
      const io = makeIo();
      const fortressPath = join(tmpDir, "fortress");
      const externalPath = join(tmpDir, "durable", "recovery.txt");
      const result = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: fortressPath,
        recoveryKeyFilePath: externalPath,
        mode: "no-confirm",
        io: { input: process.stdin, output: io.output },
      });

      expect(result.fileWritten).toBe(true);
      expect(result.filePath).toBe(externalPath);
      const content = await readFile(externalPath, "utf-8");
      expect(content).toContain(FIXTURE_KEY);
      expect(content).toContain(
        "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY"
      );
      const st = await stat(externalPath);
      expect(st.mode & 0o777).toBe(0o600);
      await expect(
        stat(join(fortressPath, RECOVERY_KEY_FILENAME))
      ).rejects.toThrow();
    });

    it.each(["stage-synced", "final-linked", "directory-synced"] as const)(
      "power cut after %s leaves only recoverable complete artifacts and blocks overwrite",
      async (cutStage) => {
        const caseDir = join(tmpDir, cutStage);
        const fortressPath = join(caseDir, "fortress");
        const externalPath = join(caseDir, "durable", "recovery.txt");
        const fixture = fileURLToPath(
          new URL("./recovery-output-power-cut-child.ts", import.meta.url),
        );
        const child = spawn(
          process.execPath,
          ["--import", "tsx", fixture, fortressPath, externalPath, cutStage],
          { stdio: ["ignore", "pipe", "pipe"] },
        );
        spawnedChildren.push(child);
        await new Promise<void>((resolve, reject) => {
          child.once("error", reject);
          child.stdout.once("data", (chunk) => {
            expect(chunk.toString("utf8")).toContain(`READY:${cutStage}`);
            resolve();
          });
        });
        const closed = new Promise<void>((resolve) =>
          child.once("close", () => resolve()),
        );
        child.kill("SIGKILL");
        await closed;

        const durableDir = dirname(externalPath);
        const entries = await (await import("node:fs/promises")).readdir(durableDir);
        const stages = entries.filter((name) => name.includes("sanctuary-recovery-stage"));
        expect(stages).toHaveLength(1);
        const stagedContent = await readFile(join(durableDir, stages[0]!), "utf8");
        expect(stagedContent).toContain(FIXTURE_KEY);
        if (cutStage === "stage-synced") {
          await expect(stat(externalPath)).rejects.toThrow();
        } else {
          await expect(readFile(externalPath, "utf8")).resolves.toBe(stagedContent);
        }
        await expect(writeRecoveryKeyFile({
          storagePath: fortressPath,
          recoveryKeyFilePath: externalPath,
          recoveryKey: FIXTURE_KEY,
        })).rejects.toThrow();
      },
    );

    it.each(["stage-synced", "final-linked", "directory-synced"] as const)(
      "default output power cut after %s leaves complete, idempotently cleanable residue",
      async (cutStage) => {
        const fortressPath = join(tmpDir, `default-${cutStage}`);
        await mkdir(join(fortressPath, "state", "_meta"), { recursive: true });
        await writeFile(
          join(fortressPath, "state", "_meta", ".custody-write.lock"),
          "",
          { mode: 0o600 },
        );
        const fixture = fileURLToPath(
          new URL("./recovery-output-power-cut-child.ts", import.meta.url),
        );
        const child = spawn(
          process.execPath,
          ["--import", "tsx", fixture, fortressPath, "DEFAULT", cutStage],
          { stdio: ["ignore", "pipe", "pipe"] },
        );
        spawnedChildren.push(child);
        await new Promise<void>((resolve, reject) => {
          child.once("error", reject);
          child.stdout.once("data", (chunk) => {
            expect(chunk.toString("utf8")).toContain(`READY:${cutStage}`);
            resolve();
          });
        });
        const closed = new Promise<void>((resolve) =>
          child.once("close", () => resolve()),
        );
        child.kill("SIGKILL");
        await closed;

        for (const name of await readdir(fortressPath)) {
          if (name === "state") continue;
          expect(await readFile(join(fortressPath, name), "utf8")).toContain(FIXTURE_KEY);
        }
        if (cutStage !== "stage-synced") {
          // Model a second power cut after cleanup durably removed the final
          // alias but before it removed the authenticated staging alias.
          await unlink(join(fortressPath, RECOVERY_KEY_FILENAME));
        }
        expect(await cleanupFreshInitRecoveryResidue(
          fortressPath,
          ".custody-write.lock",
          process.getuid!(),
        )).toBe(true);
        expect(await readdir(fortressPath)).toEqual(["state"]);
        expect(await cleanupFreshInitRecoveryResidue(
          fortressPath,
          ".custody-write.lock",
          process.getuid!(),
        )).toBe(false);
      },
    );

    it("refuses a custom recovery-key path inside the fortress", async () => {
      const io = makeIo();
      const insidePath = join(tmpDir, "nested", RECOVERY_KEY_FILENAME);
      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: tmpDir,
          recoveryKeyFilePath: insidePath,
          mode: "no-confirm",
          io: { input: process.stdin, output: io.output },
        })
      ).rejects.toThrow(/outside the fortress/);
      await expect(stat(insidePath)).rejects.toThrow();
    });

    it("refuses a custom recovery-key path whose parent symlinks into the fortress", async () => {
      const io = makeIo();
      const fortressPath = join(tmpDir, "fortress");
      const outsidePath = join(tmpDir, "outside");
      const symlinkedParent = join(outsidePath, "link-to-fortress");
      const recoveryOut = join(symlinkedParent, RECOVERY_KEY_FILENAME);
      await mkdir(fortressPath, { recursive: true });
      await mkdir(outsidePath, { recursive: true });
      await symlink(fortressPath, symlinkedParent, "dir");

      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: fortressPath,
          recoveryKeyFilePath: recoveryOut,
          mode: "no-confirm",
          io: { input: process.stdin, output: io.output },
        })
      ).rejects.toThrow(/outside the fortress/);
      await expect(
        stat(join(fortressPath, RECOVERY_KEY_FILENAME))
      ).rejects.toThrow();
    });

    it("refuses a custom recovery-key path that is a dangling symlink", async () => {
      const io = makeIo();
      const fortressPath = join(tmpDir, "fortress");
      const durableDir = join(tmpDir, "durable");
      const recoveryOut = join(durableDir, "recovery-key.txt");
      const symlinkTarget = join(tmpDir, "outside-target.txt");
      await mkdir(durableDir, { recursive: true });
      await symlink(symlinkTarget, recoveryOut);

      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: fortressPath,
          recoveryKeyFilePath: recoveryOut,
          mode: "no-confirm",
          io: { input: process.stdin, output: io.output },
        })
      ).rejects.toThrow(RecoveryKeyOutputPathSymlinkError);
      await expect(stat(symlinkTarget)).rejects.toThrow();
      expect(io.capture.join("")).not.toContain(FIXTURE_KEY);
    });

    it("refuses a custom recovery-key path that is a non-dangling symlink", async () => {
      const fortressPath = join(tmpDir, "fortress");
      const durableDir = join(tmpDir, "durable");
      const recoveryOut = join(durableDir, "recovery-key.txt");
      const symlinkTarget = join(tmpDir, "outside-target.txt");
      await mkdir(durableDir, { recursive: true });
      await writeFile(symlinkTarget, "existing target", { mode: 0o600 });
      await symlink(symlinkTarget, recoveryOut);

      await expect(
        writeRecoveryKeyFile({
          storagePath: fortressPath,
          recoveryKeyFilePath: recoveryOut,
          recoveryKey: FIXTURE_KEY,
        })
      ).rejects.toThrow(RecoveryKeyOutputPathSymlinkError);
      await expect(readFile(symlinkTarget, "utf-8")).resolves.toBe(
        "existing target"
      );
    });

    it("refuses a custom recovery-key path that already exists as a file", async () => {
      const io = makeIo();
      const fortressPath = join(tmpDir, "fortress");
      const recoveryOut = join(tmpDir, "durable", "recovery-key.txt");
      await mkdir(dirname(recoveryOut), { recursive: true });
      await writeFile(recoveryOut, "stale recovery key", { mode: 0o600 });

      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: fortressPath,
          recoveryKeyFilePath: recoveryOut,
          mode: "no-confirm",
          io: { input: process.stdin, output: io.output },
        })
      ).rejects.toThrow(RecoveryKeyOutputPathExistsError);
      await expect(readFile(recoveryOut, "utf-8")).resolves.toBe(
        "stale recovery key"
      );
      expect(io.capture.join("")).not.toContain(FIXTURE_KEY);
    });

    it("refuses a custom recovery-key path that already exists as a directory", async () => {
      const io = makeIo();
      const fortressPath = join(tmpDir, "fortress");
      const directoryPath = join(tmpDir, "durable-dir");
      await mkdir(directoryPath, { recursive: true });

      await expect(
        discloseRecoveryKey({
          recoveryKey: FIXTURE_KEY,
          storagePath: fortressPath,
          recoveryKeyFilePath: directoryPath,
          mode: "no-confirm",
          io: { input: process.stdin, output: io.output },
        })
      ).rejects.toThrow(RecoveryKeyOutputPathExistsError);
    });

    it("keeps default recovery-key.txt content byte-for-byte without a custom path", async () => {
      const result = await writeRecoveryKeyFile({
        storagePath: tmpDir,
        recoveryKey: FIXTURE_KEY,
        fortressId: "fortress-test-001",
        now: () => new Date("2026-06-20T00:00:00.000Z"),
      });

      const content = await readFile(result.filePath, "utf-8");
      expect(content).toBe(
        "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.\n" +
          "Generated: 2026-06-20T00:00:00.000Z\n" +
          "Fortress: fortress-test-001\n" +
          "\n" +
          "Recovery key:\n" +
          `${FIXTURE_KEY}\n` +
          "\n" +
          "This file was created on first init. Sanctuary will NOT regenerate this file on\n" +
          "subsequent runs and will NOT display the key again. After moving this file off\n" +
          "the host (encrypted backup, password manager, paper safe), delete it from the\n" +
          "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses\n" +
          "the fortress passphrase by design.\n"
      );
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

    it("prints different guidance when default recovery-key.txt already exists", async () => {
      const firstIo = makeIo();
      const first = await discloseRecoveryKey({
        recoveryKey: FIXTURE_KEY,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: firstIo.output },
      });
      expect(first.fileWritten).toBe(true);
      expect(firstIo.capture.join("")).toContain("Plaintext copy written to:");
      expect(firstIo.capture.join("")).toContain("Move it off-host");

      const secondIo = makeIo();
      const second = await discloseRecoveryKey({
        recoveryKey: `${FIXTURE_KEY}x`,
        storagePath: tmpDir,
        mode: "no-confirm",
        io: { input: process.stdin, output: secondIo.output },
      });
      expect(second.fileWritten).toBe(false);
      const secondBanner = secondIo.capture.join("");
      expect(secondBanner).toContain(
        "Plaintext copy was NOT written this run:"
      );
      expect(secondBanner).toContain("may hold a prior key");
      expect(secondBanner).not.toContain("Move it off-host");
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

  describe("recovery output path resolution", () => {
    it("uses an explicit non-empty env path and ignores blank env values", () => {
      expect(
        resolveRecoveryKeyOutputPath({
          storagePath: "/tmp/fortress",
          env: {},
          cwd: "/tmp",
        })
      ).toBeUndefined();
      expect(
        resolveRecoveryKeyOutputPath({
          storagePath: "/tmp/fortress",
          env: { SANCTUARY_RECOVERY_OUT: "   " },
          cwd: "/tmp",
        })
      ).toBeUndefined();
      expect(
        resolveRecoveryKeyOutputPath({
          storagePath: "/tmp/fortress",
          env: { SANCTUARY_RECOVERY_OUT: " durable/recovery-key.txt " },
          cwd: "/tmp",
        })
      ).toBe("/tmp/durable/recovery-key.txt");
    });

    it("lets the flag path win over SANCTUARY_RECOVERY_OUT", () => {
      expect(
        resolveRecoveryKeyOutputPath({
          recoveryOut: "flag/recovery-key.txt",
          storagePath: "/tmp/fortress",
          env: { SANCTUARY_RECOVERY_OUT: "/tmp/env/recovery-key.txt" },
          cwd: "/tmp",
        })
      ).toBe("/tmp/flag/recovery-key.txt");
    });

    it("refuses resolved paths inside the fortress", () => {
      expect(() =>
        resolveRecoveryKeyOutputPath({
          recoveryOut: "../fortress/recovery-key.txt",
          storagePath: "/tmp/fortress",
          env: {},
          cwd: "/tmp/outside",
        })
      ).toThrow(/outside the fortress/);
    });

    it("refuses case-variant paths that would land inside the fortress on case-insensitive filesystems", () => {
      expect(() =>
        resolveRecoveryKeyOutputPath({
          recoveryOut: join(tmpDir, "fortress", RECOVERY_KEY_FILENAME),
          storagePath: join(tmpDir, "Fortress"),
          env: {},
        })
      ).toThrow(/outside the fortress/);
    });
  });
});
