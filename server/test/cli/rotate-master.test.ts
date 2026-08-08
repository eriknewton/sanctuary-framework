import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Readable, Writable } from "node:stream";

import {
  captureRotatedRecoveryKey,
  runRotateMasterCommand,
} from "../../src/cli/rotate-master.js";
import { RECOVERY_KEY_FILENAME } from "../../src/wrap/recovery-key-disclosure.js";

const FIXTURE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

function captureStream() {
  const writes: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      writes.push(chunk.toString());
      cb();
    },
  });
  return { writes, stream };
}

describe("rotate-master --recovery-out", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-rotate-cli-test-"));
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_RECOVERY_OUT;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  });

  it("captures the rotated recovery key to an external path with mode 0600", async () => {
    const fortressPath = join(tmp, "fortress");
    const recoveryOut = join(tmp, "durable", "rotated-recovery-key.txt");
    const output = captureStream();

    const captured = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async (entered) => entered === FIXTURE_KEY,
      storagePath: fortressPath,
      fortressId: "fortress-test-001",
      recoveryKeyFilePath: recoveryOut,
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: output.stream,
      },
      err: output.stream,
      // Hermetic: never touch the real OS keyring. --recovery-out already
      // satisfies the off-host escrow precondition.
      recoveryKeychain: {
        platformOverride: "linux",
        exec: async () => ({ stdout: "", stderr: "no keyring", code: 1 }),
      },
    });

    expect(captured).toBe(true);
    const content = await readFile(recoveryOut, "utf-8");
    expect(content).toContain(FIXTURE_KEY);
    expect(content).toContain(
      "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY",
    );
    const st = await stat(recoveryOut);
    expect(st.mode & 0o777).toBe(0o600);
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    expect(output.writes.join("")).toContain("Recovery key verified.");
  });

  it("refuses a recovery-out path inside the fortress before rotation prompts", async () => {
    const fortressPath = join(tmp, "fortress");
    const err = captureStream();
    const out = captureStream();
    const code = await runRotateMasterCommand({
      argv: ["--recovery-out", join(fortressPath, RECOVERY_KEY_FILENAME)],
      storagePath: fortressPath,
      out: out.stream,
      err: err.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "unused",
    });

    expect(code).toBe(1);
    expect(err.writes.join("")).toContain("outside the fortress");
    expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
  });

  it("honors SANCTUARY_RECOVERY_OUT when no --recovery-out flag is supplied", async () => {
    const fortressPath = join(tmp, "fortress");
    const recoveryOutDir = join(tmp, "env-durable");
    const recoveryOut = join(recoveryOutDir, "rotated-recovery-key.txt");
    await mkdir(recoveryOutDir, { recursive: true });
    await writeFile(recoveryOut, "stale rotated key", { mode: 0o600 });
    process.env.SANCTUARY_RECOVERY_OUT = recoveryOut;

    const err = captureStream();
    const out = captureStream();
    const code = await runRotateMasterCommand({
      argv: [],
      storagePath: fortressPath,
      out: out.stream,
      err: err.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "unused",
    });

    expect(code).toBe(1);
    expect(err.writes.join("")).toContain("refusing to reuse");
    expect(err.writes.join("")).toContain(recoveryOut);
    expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
    await expect(readFile(recoveryOut, "utf-8")).resolves.toBe(
      "stale rotated key"
    );
  });

  it("rejects --recovery-out without a path value", async () => {
    const fortressPath = join(tmp, "fortress");
    const err = captureStream();
    const out = captureStream();
    const code = await runRotateMasterCommand({
      argv: ["--recovery-out", "--resume"],
      storagePath: fortressPath,
      out: out.stream,
      err: err.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "unused",
    });

    expect(code).toBe(1);
    expect(err.writes.join("")).toContain(
      "--recovery-out requires a path value"
    );
    expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
  });

  it("honors --fortress= when resolving recovery-output bounds", async () => {
    const fortressPath = join(tmp, "flag-fortress");
    const err = captureStream();
    const out = captureStream();
    const code = await runRotateMasterCommand({
      argv: [
        `--fortress=${fortressPath}`,
        "--recovery-out",
        join(fortressPath, RECOVERY_KEY_FILENAME),
      ],
      home: tmp,
      out: out.stream,
      err: err.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "unused",
    });

    expect(code).toBe(1);
    expect(err.writes.join("")).toContain("outside the fortress");
    expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
  });

  it("honors --storage= when resolving recovery-output bounds", async () => {
    const fortressPath = join(tmp, "storage-fortress");
    const err = captureStream();
    const out = captureStream();
    const code = await runRotateMasterCommand({
      argv: [
        `--storage=${fortressPath}`,
        "--recovery-out",
        join(fortressPath, RECOVERY_KEY_FILENAME),
      ],
      home: tmp,
      out: out.stream,
      err: err.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "unused",
    });

    expect(code).toBe(1);
    expect(err.writes.join("")).toContain("outside the fortress");
    expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
  });

  it("rejects missing fortress and storage values before rotation prompts", async () => {
    for (const flag of ["--fortress", "--storage"]) {
      const err = captureStream();
      const out = captureStream();
      const code = await runRotateMasterCommand({
        argv: [flag],
        storagePath: join(tmp, "fallback-fortress"),
        out: out.stream,
        err: err.stream,
        stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
        passphraseOverride: "unused",
      });

      expect(code).toBe(1);
      expect(err.writes.join("")).toContain(`${flag} requires a value`);
      expect(out.writes.join("")).not.toContain("Sanctuary rotate-master");
    }
  });
});

describe("rotate-master anti-strand: refuse without off-host capture (element 4)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-rotate-antistrand-"));
  });

  afterEach(async () => {
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it("refuses capture (so the rotation aborts) when there is no off-host target", async () => {
    const fortressPath = join(tmp, "fortress");
    const output = captureStream();

    const captured = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async () => true,
      storagePath: fortressPath,
      fortressId: "fortress-test-002",
      // NO recoveryKeyFilePath, and the keyring is unavailable:
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: output.stream,
      },
      err: output.stream,
      recoveryKeychain: {
        platformOverride: "linux",
        exec: async () => ({ stdout: "", stderr: "no keyring", code: 1 }),
      },
    });

    expect(captured).toBe(false);
    expect(output.writes.join("")).toContain("Refusing to rotate");
    // The new key was NOT written inside the fortress directory.
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
  });

  it("never writes the new recovery key inside the fortress, even on success", async () => {
    const fortressPath = join(tmp, "fortress");
    const recoveryOut = join(tmp, "external", "rotated.txt");
    const output = captureStream();

    const captured = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async (entered) => entered === FIXTURE_KEY,
      storagePath: fortressPath,
      fortressId: "fortress-test-003",
      recoveryKeyFilePath: recoveryOut,
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: output.stream,
      },
      err: output.stream,
      recoveryKeychain: {
        platformOverride: "linux",
        exec: async () => ({ stdout: "", stderr: "no keyring", code: 1 }),
      },
    });

    expect(captured).toBe(true);
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    expect(await readFile(recoveryOut, "utf-8")).toContain(FIXTURE_KEY);
  });
});
