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
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  adoptRecoveryKeyRotationInKeychain,
  canonicalRecoveryKeyServiceFor,
} from "../../src/wrap/keychain-custody.js";

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
      rotationId: "rotation-test-001",
      registerPendingAuthority: async () => undefined,
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

    expect(typeof captured).toBe("object");
    await (captured as Exclude<typeof captured, boolean>).commit();
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

  it("scrubs the acquired custody key when rotation throws", async () => {
    const fortressPath = join(tmp, "throwing-rotation");
    await mkdir(join(fortressPath, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const originalKey = new Uint8Array(32).fill(0x4d);
    const established = await establishMaster({
      storage,
      passphrase: "rotation-test-passphrase",
      keychainKey: originalKey,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
      storagePathHint: fortressPath,
    });
    await established.masterWriteBarrier?.release();
    established.masterKey.fill(0);
    const observed = originalKey.slice();
    const output = captureStream();
    const code = await runRotateMasterCommand({
      argv: [],
      storagePath: fortressPath,
      out: output.stream,
      err: output.stream,
      stdin: Readable.from([]) as NodeJS.ReadableStream & { isTTY?: boolean },
      passphraseOverride: "rotation-test-passphrase",
      getKeychainCustodyKey: async () => observed,
      rotateMasterImpl: async () => {
        throw new Error("injected post-key failure");
      },
    });
    expect(code).toBe(1);
    expect([...observed]).toEqual(new Array(32).fill(0));
    originalKey.fill(0);
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
      rotationId: "rotation-test-002",
      registerPendingAuthority: async () => undefined,
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
      rotationId: "rotation-test-003",
      registerPendingAuthority: async () => undefined,
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

    expect(typeof captured).toBe("object");
    await (captured as Exclude<typeof captured, boolean>).commit();
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toThrow();
    expect(await readFile(recoveryOut, "utf-8")).toContain(FIXTURE_KEY);
  });

  it("preserves old canonical recovery escrow until verified capture commits", async () => {
    const fortressPath = join(tmp, "fortress");
    const home = join(tmp, "home");
    const canonical = canonicalRecoveryKeyServiceFor(fortressPath, home);
    const oldKey = Buffer.alloc(32, 0x44).toString("base64url");
    const items = new Map<string, string>([[canonical, oldKey]]);
    let failNextStagingDelete = false;
    const exec = async (_cmd: string, args: string[], input?: string) => {
      const service = args[args.indexOf("service") + 1]!;
      if (args[0] === "lookup") {
        const value = items.get(service);
        return value === undefined
          ? { stdout: "", stderr: "not found", code: 1 }
          : { stdout: `${value}\n`, stderr: "", code: 0 };
      }
      if (args[0] === "store") {
        items.set(service, (input ?? "").trim());
        return { stdout: "", stderr: "", code: 0 };
      }
      if (args[0] === "clear") {
        if (service !== canonical && failNextStagingDelete) {
          failNextStagingDelete = false;
          return { stdout: "", stderr: "injected delete failure", code: 1 };
        }
        const existed = items.delete(service);
        return existed
          ? { stdout: "", stderr: "", code: 0 }
          : { stdout: "", stderr: "not found", code: 1 };
      }
      throw new Error("unexpected secret-tool invocation");
    };

    let rejectedVerifyCalls = 0;
    const rejected = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      // The engine first binds the generated key to the staged envelope; the
      // later human re-entry attempts are deliberately wrong/refused.
      verify: async () => ++rejectedVerifyCalls === 1,
      storagePath: fortressPath,
      fortressId: "fortress-transaction-test",
      rotationId: "rotation-rejected",
      registerPendingAuthority: async () => undefined,
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n${FIXTURE_KEY}\n${FIXTURE_KEY}\n`]),
        output: captureStream().stream,
      },
      err: captureStream().stream,
      recoveryKeychain: { home, platformOverride: "linux", exec },
    });
    expect(rejected).toBe(false);
    expect(items.get(canonical)).toBe(oldKey);
    expect([...items.keys()]).toEqual([canonical]);

    const observedReadbacks: Uint8Array[] = [];
    const accepted = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async (entered) => entered === FIXTURE_KEY,
      storagePath: fortressPath,
      fortressId: "fortress-transaction-test",
      rotationId: "rotation-accepted",
      registerPendingAuthority: async () => undefined,
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: captureStream().stream,
      },
      err: captureStream().stream,
      recoveryKeychain: {
        home,
        platformOverride: "linux",
        exec,
        __testObserveSecretBuffer: (_label, buffer) => {
          observedReadbacks.push(buffer);
        },
      },
    });
    expect(typeof accepted).toBe("object");
    expect(items.get(canonical)).toBe(oldKey);
    await (accepted as Exclude<typeof accepted, boolean>).commit();
    expect(items.get(canonical)).toBe(FIXTURE_KEY);
    expect([...items.keys()]).toEqual([canonical]);
    expect(observedReadbacks.length).toBeGreaterThan(0);
    for (const buffer of observedReadbacks) {
      expect([...buffer]).toEqual(new Array(buffer.length).fill(0));
    }

    items.set(canonical, oldKey);
    const commitFailure = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async (entered) => entered === FIXTURE_KEY,
      storagePath: fortressPath,
      fortressId: "fortress-transaction-test",
      rotationId: "rotation-commit-failure",
      registerPendingAuthority: async () => undefined,
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: captureStream().stream,
      },
      err: captureStream().stream,
      recoveryKeychain: { home, platformOverride: "linux", exec },
    });
    expect(typeof commitFailure).toBe("object");
    failNextStagingDelete = true;
    await expect(
      (commitFailure as Exclude<typeof commitFailure, boolean>).commit(),
    ).rejects.toThrow("could not remove staged OS keyring service");
    // Conversion has reached its commit boundary: canonical promotion is
    // intentionally final even if staging cleanup fails.
    expect(items.get(canonical)).toBe(FIXTURE_KEY);
    await (commitFailure as Exclude<typeof commitFailure, boolean>).rollback();
    expect([...items.keys()]).toEqual([canonical]);
  });

  it("re-adopts a deterministic staged keyring escrow after process loss and promotes idempotently", async () => {
    const fortressPath = join(tmp, "fortress");
    const home = join(tmp, "home");
    const rotationId = "rotation-resume-adoption";
    const canonical = canonicalRecoveryKeyServiceFor(fortressPath, home);
    const items = new Map<string, string>([[canonical, Buffer.alloc(32, 0x55).toString("base64url")]]);
    const exec = async (_cmd: string, args: string[], input?: string) => {
      const service = args[args.indexOf("service") + 1]!;
      if (args[0] === "lookup") {
        const value = items.get(service);
        return value === undefined
          ? { stdout: "", stderr: "not found", code: 1 }
          : { stdout: `${value}\n`, stderr: "", code: 0 };
      }
      if (args[0] === "store") {
        items.set(service, (input ?? "").trim());
        return { stdout: "", stderr: "", code: 0 };
      }
      if (args[0] === "clear") {
        const existed = items.delete(service);
        return existed
          ? { stdout: "", stderr: "", code: 0 }
          : { stdout: "", stderr: "not found", code: 1 };
      }
      throw new Error("unexpected secret-tool invocation");
    };
    let registeredAuthority: Parameters<typeof adoptRecoveryKeyRotationInKeychain>[2] | undefined;
    const capture = await captureRotatedRecoveryKey({
      recoveryKey: FIXTURE_KEY,
      verify: async (candidate) => candidate === FIXTURE_KEY,
      storagePath: fortressPath,
      fortressId: "fortress-resume-test",
      rotationId,
      registerPendingAuthority: async (authority) => {
        if (authority.kind === "os-keyring") registeredAuthority = authority;
      },
      io: {
        input: Readable.from([`${FIXTURE_KEY}\n`]),
        output: captureStream().stream,
      },
      err: captureStream().stream,
      recoveryKeychain: { home, platformOverride: "linux", exec },
    });
    expect(typeof capture).toBe("object");
    const mutation = capture as Exclude<typeof capture, boolean>;
    expect(items.get(canonical)).not.toBe(FIXTURE_KEY);

    // Drop the in-memory mutation handle, as a hard process exit would. The
    // authenticated journal retains only this non-secret authority object.
    const adopted = await adoptRecoveryKeyRotationInKeychain(
      fortressPath,
      rotationId,
      registeredAuthority!,
      async (candidate) => candidate === FIXTURE_KEY,
      { home, platformOverride: "linux", exec },
    );
    await adopted.commit();
    expect(items.get(canonical)).toBe(FIXTURE_KEY);
    expect([...items.keys()]).toEqual([canonical]);

    // Crash after canonical promotion + staging deletion: a second resume
    // adopts canonical itself and converges without rewriting or deleting it.
    const adoptedAgain = await adoptRecoveryKeyRotationInKeychain(
      fortressPath,
      rotationId,
      registeredAuthority!,
      async (candidate) => candidate === FIXTURE_KEY,
      { home, platformOverride: "linux", exec },
    );
    await adoptedAgain.commit();
    expect(items.get(canonical)).toBe(FIXTURE_KEY);
  });
});
