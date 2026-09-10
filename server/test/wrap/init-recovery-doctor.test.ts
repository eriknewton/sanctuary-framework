/**
 * `sanctuary init`: recovery-key custody, doctor agreement, honest failure,
 * and a pre-existing machine-wide Castle Wall pin.
 *
 * Capability bounds these pin (register rows
 * defect.a73-default-recovery-key-written-inside-fortress,
 * defect.a73-init-no-pin-fortress-unopenable-and-incomplete,
 * defect.a73-doctor-fails-freshly-initialized-fortress,
 * defect.a73-default-init-fails-on-pre-existing-global-pin,
 * defect.a73-failed-init-prints-recovery-verified-and-leaves-partial-state):
 *
 *   1. The plaintext recovery key is never written inside the fortress it
 *      protects, on the default path as well as the explicit one, and a
 *      destination that resolves inside the fortress is refused.
 *   2. A fresh `init` produces a fortress `doctor` does not FAIL: init writes
 *      the principal policy the runtime loads.
 *   3. A failed init claims nothing it has not done, keeps a recovery file it
 *      already announced, cleans up what it created, and says so.
 *   4. A pre-existing global pin with no installed Castle Wall app finishes
 *      the init without a pin instead of failing, and never mutates the pin.
 *
 * Isolation: every fortress is a per-test temp directory and every keyring
 * touch goes through the injected in-memory `security` store below. Nothing
 * here reads or writes the operator's login keychain or real `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  resolveFortressPath,
  printInitHelp,
  runInit,
  type InitOptions,
  type RunInitDeps,
} from "../../src/wrap/init.js";
import {
  RECOVERY_KEY_FILE_BODY_LINES,
  RECOVERY_KEY_FILENAME,
  RecoveryKeyOutputPathInsideFortressError,
} from "../../src/wrap/recovery-key-disclosure.js";
import { agentGuidedRecoveryOutputPath } from "../../src/wrap/custody-flow.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";
import { PRINCIPAL_POLICY_FILENAME } from "../../src/principal-policy/loader.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";

/**
 * In-memory stand-in for the macOS `security` binary. The whole point is that
 * no test in this file can reach the operator's real login keychain: the
 * keychain chokepoint is handed this exec, so no subprocess is spawned.
 */
function inMemoryKeychain(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  stored: Map<string, string>;
} {
  const stored = new Map<string, string>();
  const token = (input: string | undefined, flag: string): string => {
    const match = input?.match(
      new RegExp(`${flag} "((?:[^"\\\\]|\\\\.)*)"`),
    );
    return match ? match[1]!.replace(/\\(.)/g, "$1") : "";
  };
  const exec = async (
    cmd: string,
    args: string[],
    input?: string,
  ): Promise<ExecResult> => {
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        `${token(input, "-a")}:${token(input, "-s")}`,
        token(input, "-w"),
      );
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const key = `${args[args.indexOf("-a") + 1] ?? ""}:${args[args.indexOf("-s") + 1] ?? ""}`;
      const value = stored.get(key);
      return value
        ? { stdout: `${value}\n`, stderr: "", code: 0 }
        : { stdout: "", stderr: "not found", code: 44 };
    }
    if (args[0] === "delete-generic-password") {
      const key = `${args[args.indexOf("-a") + 1] ?? ""}:${args[args.indexOf("-s") + 1] ?? ""}`;
      stored.delete(key);
      return { stdout: "", stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec, stored };
}

function init(
  options: InitOptions,
  deps: RunInitDeps = {},
): ReturnType<typeof runInit> {
  return runInit(options, {
    provisionPin: async () => 0,
    runLocalIntelligenceSetup: async () => ({ kind: "not-requested" }),
    ...deps,
    recoveryKeychain: {
      home: "/tmp/sanctuary-init-recovery-doctor-home",
      platformOverride: "darwin",
      exec: inMemoryKeychain().exec,
    },
  });
}

/** Drive an attended run without a real terminal, capturing every line. */
async function attended<T>(run: (lines: string[]) => Promise<T>): Promise<T> {
  const lines: string[] = [];
  const ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  const stderrWrite = vi
    .spyOn(process.stderr, "write")
    .mockImplementation(((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stderr.write);
  const consoleError = vi
    .spyOn(console, "error")
    .mockImplementation((...args: unknown[]) => {
      lines.push(args.map((a) => String(a)).join(" "));
    });
  Object.defineProperty(process.stdin, "isTTY", {
    configurable: true,
    value: true,
  });
  try {
    return await run(lines);
  } finally {
    consoleError.mockRestore();
    stderrWrite.mockRestore();
    if (ttyDescriptor) {
      Object.defineProperty(process.stdin, "isTTY", ttyDescriptor);
    } else {
      Reflect.deleteProperty(process.stdin, "isTTY");
    }
  }
}

const sh = promisify(execFile);
const SERVER_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const readSource = (relative: string): Promise<string> =>
  readFile(join(SERVER_ROOT, relative), "utf8");


describe("sanctuary init: recovery key stays outside the fortress", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-"));
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_RECOVERY_OUT;
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("writes the default attended recovery key outside the fortress, 0700 dir and 0600 file", async () => {
    const fortressPath = join(tmp, "attended-default");
    const result = await attended(() =>
      init({ fortress: fortressPath, noPin: true, noIdentity: true }, {
        verifyRecoveryKeyReentry: async () => undefined,
      }),
    );

    const expected = agentGuidedRecoveryOutputPath(fortressPath);
    expect(result.recoveryKeyDisclosurePath).toBe(expected);
    // The defect this pins: on the old default this file was inside the
    // fortress, so losing or reading one directory lost or exposed everything.
    await expect(
      stat(join(fortressPath, RECOVERY_KEY_FILENAME)),
    ).rejects.toMatchObject({ code: "ENOENT" });
    // Mode and content of the SAME file object from one descriptor (fstat +
    // read on a single fd), not a path stat followed by a path read.
    const handle = await open(expected, "r");
    try {
      expect((await handle.stat()).mode & 0o777).toBe(0o600);
      expect(await handle.readFile("utf8")).toContain("Recovery key:");
    } finally {
      await handle.close();
    }
    expect((await stat(join(tmp, "Sanctuary Recovery"))).mode & 0o777).toBe(0o700);
  });

  it("refuses a --recovery-out that resolves inside the fortress through a symlink", async () => {
    const fortressPath = join(tmp, "symlinked-out");
    const alias = join(tmp, "alias-to-fortress");
    await symlink(fortressPath, alias);

    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        recoveryOut: join(alias, "recovery-key.txt"),
      }),
    ).rejects.toBeInstanceOf(RecoveryKeyOutputPathInsideFortressError);
  });

  it("names the recovery file only after it exists, and orders save before delete", async () => {
    const fortressPath = join(tmp, "guidance-order");
    const output = await attended(async (lines) => {
      await init({ fortress: fortressPath, noPin: true, noIdentity: true }, {
        verifyRecoveryKeyReentry: async () => undefined,
      });
      return lines.join("\n");
    });

    const expected = agentGuidedRecoveryOutputPath(fortressPath);
    expect(output).toContain(expected);
    await expect(stat(expected)).resolves.toBeDefined();
    const moveAt = output.indexOf("Move it off-host");
    const deleteAt = output.indexOf("then delete this file");
    expect(moveAt).toBeGreaterThanOrEqual(0);
    expect(deleteAt).toBeGreaterThan(moveAt);
  });
});

describe("sanctuary init: what init writes is what doctor checks", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-doctor-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("leaves doctor's principal-policy check non-FAIL on a freshly initialized fortress", async () => {
    const fortressPath = join(tmp, "fresh");
    await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });

    // Doctor first, deliberately: it is the assertion that states the defect
    // (init exited 0 and doctor then FAILED on the same fortress, naming "run
    // sanctuary init" as the remedy for a fortress init had just built). A
    // file-existence check placed ahead of it would short-circuit and report
    // a bare ENOENT instead of the operator-visible symptom.
    const checks = await runDoctorChecks({
      env: {},
      storagePath: fortressPath,
      platform: process.platform,
    });
    const policy = checks.find((check) => check.name === "principal policy");
    expect(policy).toBeDefined();
    expect(policy!.status).not.toBe("FAIL");

    // And doctor is non-FAIL because the file is really there, not because
    // the check was scoped away from a fortress that lacks it.
    await expect(
      stat(join(fortressPath, PRINCIPAL_POLICY_FILENAME)),
    ).resolves.toBeDefined();
  });
});

describe("sanctuary init: an existing principal policy is reported, and a planted one is refused", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-policy-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("says the existing principal policy was kept and not rewritten", async () => {
    // writeDefaultPrincipalPolicyFile never overwrites, so on --force over a
    // fortress that already had a policy the file on disk stays the old one.
    // Init used to discard that return value and say nothing, so the operator
    // read "init complete" as "init wrote the default approval tiers".
    const fortressPath = join(tmp, "kept");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    await writeFile(
      join(fortressPath, PRINCIPAL_POLICY_FILENAME),
      "version: 1\ntiers: {}\n",
      { mode: 0o600 },
    );

    const output = await attended(async (lines) => {
      await init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        force: true,
      });
      return lines.join("\n");
    });

    expect(output).toContain("kept the existing file");
    expect(output).toContain(join(fortressPath, PRINCIPAL_POLICY_FILENAME));
    expect(output).toContain("NOT rewritten");
    // And it really is the operator's file, not the default template.
    expect(
      await readFile(join(fortressPath, PRINCIPAL_POLICY_FILENAME), "utf8"),
    ).toBe("version: 1\ntiers: {}\n");
  });

  it("refuses a symlink at the principal-policy path even under --force", async () => {
    // The runtime freezes whatever this path resolves to as the policy, so a
    // link here lets a planted file outside the fortress decide the approval
    // tiers. --force authorizes overwriting a fortress, never following a link
    // out of one.
    const fortressPath = join(tmp, "planted");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    const outside = join(tmp, "attacker-policy.yaml");
    await writeFile(outside, "version: 1\ntiers: {}\n", { mode: 0o600 });
    await symlink(outside, join(fortressPath, PRINCIPAL_POLICY_FILENAME));

    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        force: true,
      }),
    ).rejects.toThrow(/is not a regular file/);
  });

  it("refuses the planted policy BEFORE minting, so a --force retry stays possible", async () => {
    // The writer's refusal fires at the END of init, after the recovery-key
    // file and the custody envelope, and `--force` skips rollback. So the
    // staged recovery file was already on disk, still unannounced: the cleanup
    // summary could not name it and the next `--force` retry died at the
    // single-issuance preflight on a file the operator had never been told
    // about. The refusal has to happen before anything is minted.
    const fortressPath = join(tmp, "planted-premint");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    const outside = join(tmp, "premint-attacker-policy.yaml");
    await writeFile(outside, "version: 1\ntiers: {}\n", { mode: 0o600 });
    const planted = join(fortressPath, PRINCIPAL_POLICY_FILENAME);
    await symlink(outside, planted);

    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        force: true,
      }),
    ).rejects.toThrow(/is not a regular file/);

    // Nothing was minted: no staged recovery file exists for a retry to trip on.
    const staged = agentGuidedRecoveryOutputPath(fortressPath);
    await expect(lstat(staged)).rejects.toMatchObject({ code: "ENOENT" });
    const stagingDir = dirname(staged);
    const stagedEntries = await readdir(stagingDir).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    });
    expect(stagedEntries).toEqual([]);
    await expect(lstat(join(fortressPath, "state"))).rejects.toMatchObject({
      code: "ENOENT",
    });

    // And the retry the operator is told to run actually works once the plant
    // is removed, which is the whole point of failing before the mint.
    await rm(planted);
    await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
      force: true,
    });
    expect((await lstat(join(fortressPath, PRINCIPAL_POLICY_FILENAME))).isFile()).toBe(
      true,
    );
    expect((await stat(staged)).mode & 0o777).toBe(0o600);
  });

  it("makes a symlinked principal policy a doctor finding rather than an OK", async () => {
    // Doctor read the policy with a symlink-following readFile while the wrap
    // path used the no-follow custody read, so doctor certified exactly the
    // shape init refuses.
    const fortressPath = join(tmp, "doctor-planted");
    await mkdir(join(fortressPath, "state"), { recursive: true, mode: 0o700 });
    const outside = join(tmp, "elsewhere-policy.yaml");
    await writeFile(outside, "version: 1\ntiers: {}\n", { mode: 0o600 });
    await symlink(outside, join(fortressPath, PRINCIPAL_POLICY_FILENAME));

    const checks = await runDoctorChecks({
      env: {},
      storagePath: fortressPath,
      platform: process.platform,
    });
    const policy = checks.find((check) => check.name === "principal policy");
    expect(policy).toBeDefined();
    expect(policy!.status).toBe("FAIL");
    expect(policy!.message).toContain("not a regular file");
    expect(policy!.hint).toContain("move or delete");
  });
});

describe("sanctuary init: a fortress named like the default staging directory", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-collide-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("names --recovery-out as the remedy instead of refusing a path the operator never chose", async () => {
    // `dirname(fortress)/Sanctuary Recovery` resolves back onto a fortress
    // that IS named `Sanctuary Recovery`, so the containment guard refused the
    // default destination and the operator read a containment violation about
    // a path they had not passed.
    const fortressPath = join(tmp, "Sanctuary Recovery");
    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      }),
    ).rejects.toThrow(/--recovery-out/);
    // Nothing was minted before the refusal.
    await expect(lstat(join(fortressPath, "state"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("accepts the same fortress name once --recovery-out names a destination", async () => {
    const fortressPath = join(tmp, "Sanctuary Recovery");
    const recoveryOut = join(tmp, "keys", "collide.txt");
    await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
      recoveryOut,
    });
    expect((await stat(recoveryOut)).mode & 0o777).toBe(0o600);
  });
});

describe("sanctuary init: a failed run is honest and cleans only its own work", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-fail-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("removes the announced recovery file with the custody it unwrapped, and says so", async () => {
    const fortressPath = join(tmp, "failing");
    const recoveryOut = join(tmp, "keys", "failing.txt");

    const output = await attended(async (lines) => {
      await expect(
        init(
          {
            fortress: fortressPath,
            noConfirm: true,
            noIdentity: true,
            recoveryOut,
          },
          {
            // Fail at the LAST step, after the key has been written and named.
            provisionPin: async () => 1,
          },
        ),
      ).rejects.toThrow(/Castle Wall key provisioning failed/);
      return lines.join("\n");
    });

    // The file the operator was told to save is REMOVED, because the rollback
    // also removed the custody it unwrapped: an announced key for a fortress
    // that no longer exists opens nothing, and leaving it behind made the
    // retry refuse on exactly that path.
    await expect(stat(recoveryOut)).rejects.toMatchObject({ code: "ENOENT" });
    expect(output).toContain("Removed:");
    expect(output).toContain(recoveryOut);
    expect(output).not.toContain("Kept on purpose");
    // Everything this run created inside the fortress is gone; the inert
    // state/ lock scaffold is the only residue and a retry reuses it.
    await expect(
      stat(join(fortressPath, PRINCIPAL_POLICY_FILENAME)),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(output).toContain("Cleaned up:");
    expect(output).toContain("Next step:");
    // Nothing outside the fortress that init did not create is touched.
    await expect(stat(join(tmp, "keys"))).resolves.toBeDefined();
  });

  it("does not claim completion when a later step fails", async () => {
    const fortressPath = join(tmp, "no-false-completion");
    const output = await attended(async (lines) => {
      await expect(
        init(
          { fortress: fortressPath, noPin: true },
          {
            verifyRecoveryKeyReentry: async (opts) => {
              // Print exactly what the real helper prints on success, so the
              // assertion is about the WORDING init chose, not about whether
              // verification ran.
              process.stderr.write(`${opts.verifiedMessage ?? "Recovery key verified."}\n`);
            },
            runLocalIntelligenceSetup: async () => {
              throw new Error("unreachable: identity seed fails first");
            },
            beforeDurableMutation: async (label) => {
              if (label === "operator-identity") {
                throw new Error("planted identity-seed failure");
              }
            },
          },
        ),
      ).rejects.toThrow(/operator identity seed failed/);
      return lines.join("\n");
    });

    // The defect this pins: a run that died later still printed a bare
    // "Recovery key verified." and nothing that scoped it to that moment.
    expect(output).toContain("Recovery key verified:");
    expect(output).toContain("Initialization has more steps");
    expect(output).not.toContain("Sanctuary init: complete.");
  });

  it("claims completion once, and only on a run that finished", async () => {
    const fortressPath = join(tmp, "completes");
    const output = await attended(async (lines) => {
      await init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      });
      return lines.join("\n");
    });
    expect(output).toContain("Sanctuary init: complete.");
  });
});

describe("recovery-key output containment", () => {
  it("refuses a destination equal to the fortress directory itself", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-eq-"));
    try {
      const fortressPath = join(tmp, "eq");
      await expect(
        init({
          fortress: fortressPath,
          noConfirm: true,
          noPin: true,
          noIdentity: true,
          recoveryOut: fortressPath,
        }),
      ).rejects.toBeInstanceOf(RecoveryKeyOutputPathInsideFortressError);
      await expect(lstat(join(fortressPath, "state"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});

describe("sanctuary init: the printed next step is a step that works", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-retry-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("names the kept key honestly and prints a retry the operator can execute", async () => {
    const fortressPath = join(tmp, "retry");
    const staged = agentGuidedRecoveryOutputPath(fortressPath);

    const output = await attended(async (lines) => {
      await expect(
        init(
          { fortress: fortressPath, noConfirm: true, noIdentity: true },
          { provisionPin: async () => 1 },
        ),
      ).rejects.toThrow(/Castle Wall key provisioning failed/);
      return lines.join("\n");
    });

    // The default destination is cleared by the rollback itself, so the
    // summary no longer has to teach the operator an `rm`, and the retry it
    // prints is a step that actually works.
    await expect(stat(staged)).rejects.toMatchObject({ code: "ENOENT" });
    expect(output).toContain("Removed:");
    const rmLine = output
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("rm "));
    expect(rmLine).toBeUndefined();

    // And the printed retry really does complete.
    const result = await init(
      { fortress: fortressPath, noConfirm: true, noPin: true, noIdentity: true },
    );
    expect(result.recoveryKeyDisclosurePath).toBe(staged);
  });

  it("leaves a recovery destination it cannot prove it wrote, and names it", async () => {
    // The removal is scoped by INODE IDENTITY, not by path: a destination that
    // was replaced between the write and the failure is somebody else's file,
    // and this rollback must not unlink it. The summary then has to name it,
    // because the retry refuses while any file stands at that path.
    const fortressPath = join(tmp, "swapped");
    const staged = agentGuidedRecoveryOutputPath(fortressPath);
    const output = await attended(async (lines) => {
      await expect(
        init(
          { fortress: fortressPath, noConfirm: true, noIdentity: true },
          {
            provisionPin: async () => {
              // Same path, different inode: exactly the shape the guard exists
              // for. Runs at the last step, after the key was written and
              // announced.
              //
              // The replacement is written to a SIBLING path first and moved
              // onto the destination with rename(2), rather than unlinked and
              // recreated in place. An unlink-then-create at the same path
              // asks the filesystem's allocator not to hand back the inode
              // number it just freed, which is not a portable guarantee: a
              // freshly formatted Linux tmp filesystem (tmpfs or a fresh ext4
              // allocation group, both routine on a CI runner) can and does
              // reuse the just-freed inode for the very next file created in
              // the same directory, while APFS on macOS practically never
              // does. This flaked the test on Linux CI (run 34493018511):
              // the reused inode made the rollback's dev/ino identity check
              // read "same file" and unlink the swapped-in content, and the
              // very next assertion then found nothing at `staged` to read.
              // Renaming a file whose inode was allocated separately, while
              // the original still holds its own live inode, cannot collide:
              // the two inodes coexist until the rename's atomic replace, so
              // the guard is exercised the same way on every filesystem.
              const swapSource = `${staged}.test-swap-source`;
              await writeFile(swapSource, "written by someone else\n", { mode: 0o600 });
              await rename(swapSource, staged);
              return 1;
            },
          },
        ),
      ).rejects.toThrow(/Castle Wall key provisioning failed/);
      return lines.join("\n");
    });

    expect(await readFile(staged, "utf8")).toBe("written by someone else\n");
    expect(output).toContain("Still on disk:");
    expect(output).not.toContain("Removed:");
    const rmLine = output
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("rm "));
    expect(rmLine).toBeDefined();

    await expect(
      init({ fortress: fortressPath, noConfirm: true, noPin: true, noIdentity: true }),
    ).rejects.toThrow(/existing --recovery-out file/);
  });
});

describe("sanctuary init: a failed identity seed states one truth", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-identity-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("says nothing about intact custody on the path that rolls custody back", async () => {
    const fortressPath = join(tmp, "rolled-back");
    const output = await attended(async (lines) => {
      await expect(
        init(
          { fortress: fortressPath, noConfirm: true, noPin: true },
          {
            beforeDurableMutation: async (label) => {
              if (label === "operator-identity") {
                throw new Error("planted identity-seed failure");
              }
            },
          },
        ),
      ).rejects.toThrow(/operator identity seed failed/);
      return lines.join("\n");
    });

    // The contradiction this pins: the identity-failure block advertised
    // `identity create` against a fortress the rollback then emptied, and the
    // cleanup summary immediately said the opposite.
    expect(output).toContain("failed to seed the default operator identity");
    expect(output).not.toContain("custody is intact");
    expect(output).not.toContain("sanctuary identity create");
    expect(output).toContain("Cleaned up:");
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("gives the custody-intact remediations only when rollback is deliberately skipped", async () => {
    const fortressPath = join(tmp, "forced");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    const output = await attended(async (lines) => {
      await expect(
        init(
          { fortress: fortressPath, noConfirm: true, noPin: true, force: true },
          {
            beforeDurableMutation: async (label) => {
              if (label === "operator-identity") {
                throw new Error("planted identity-seed failure");
              }
            },
          },
        ),
      ).rejects.toThrow(/operator identity seed failed/);
      return lines.join("\n");
    });

    expect(output).toContain("Nothing was rolled back (--force)");
    expect(output).toContain("sanctuary identity create");
    // And the summary agrees with it rather than contradicting it.
    expect(output).toContain("Nothing was cleaned up automatically");
    expect(output).not.toContain("Cleaned up:");
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).resolves.toBeDefined();
  });
});

describe("recovery-key output parent directory", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-parent-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("leaves a 0755 operator-chosen parent's mode alone and still writes the key 0600", async () => {
    // `--recovery-out ~/recovery-key.txt` makes the operator's HOME the parent.
    // An earlier revision chmod'ed ANY owned parent carrying group/other bits
    // to 0700, at preflight, with no rollback, so one flag silently relocked a
    // home directory or a Desktop. A conventional 0755 parent is accepted as
    // found: the key file itself is 0600 and a traversable-but-unwritable
    // directory does not expose it.
    const home = join(tmp, "home-like");
    await mkdir(home, { recursive: true });
    await chmod(home, 0o755);
    expect((await stat(home)).mode & 0o777).toBe(0o755);

    const fortressPath = join(tmp, "fortress");
    await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
      recoveryOut: join(home, "recovery.txt"),
    });

    expect((await stat(home)).mode & 0o777).toBe(0o755);
    expect((await stat(join(home, "recovery.txt"))).mode & 0o777).toBe(0o600);
  });

  it("refuses a group-writable operator-chosen parent instead of silently tightening it", async () => {
    // Group/other WRITABLE is the bit that matters: another principal who can
    // write the directory can replace the 0600 file after it lands. The old
    // behaviour chmod'ed this to 0700 and proceeded, so the refusal never
    // reached the operator and the mode change was invisible.
    const shared = join(tmp, "shared");
    await mkdir(shared, { recursive: true });
    await chmod(shared, 0o775);

    const fortressPath = join(tmp, "fortress-shared-parent");
    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        recoveryOut: join(shared, "recovery.txt"),
      }),
    ).rejects.toThrow(/writable by group or other/);
    // The remedy is the operator's to apply; Sanctuary did not apply it for them.
    expect((await stat(shared)).mode & 0o777).toBe(0o775);
    await expect(
      stat(join(shared, "recovery.txt")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("still tightens the default staging directory it owns, even pre-existing and loose", async () => {
    // The one directory Sanctuary DOES own. Pre-created 0755 by an earlier
    // interrupted run, it must come out 0700: nothing but Sanctuary puts
    // recovery material here, so there is no operator intent to preserve.
    const staging = join(tmp, "Sanctuary Recovery");
    await mkdir(staging, { recursive: true });
    await chmod(staging, 0o755);

    const fortressPath = join(tmp, "fortress-default-staging");
    await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });

    expect((await stat(staging)).mode & 0o777).toBe(0o700);
    expect(
      (await stat(agentGuidedRecoveryOutputPath(fortressPath))).mode & 0o777,
    ).toBe(0o600);
  });

  it("refuses a symlinked parent instead of writing the key through it", async () => {
    const real = join(tmp, "elsewhere");
    await mkdir(real, { recursive: true, mode: 0o700 });
    const linked = join(tmp, "link-to-elsewhere");
    await symlink(real, linked);

    const fortressPath = join(tmp, "fortress-symlink-parent");
    await expect(
      init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
        recoveryOut: join(linked, "recovery.txt"),
      }),
    ).rejects.toThrow(/not a stable directory/);
    // Nothing was written through the link, and no custody was minted.
    await expect(
      stat(join(real, "recovery.txt")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      lstat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("fortress path normalization", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-norm-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("normalizes . and .. out of an absolute --fortress before anything derives from it", () => {
    // An ABSOLUTE flag used to be taken verbatim.
    expect(resolveFortressPath({ fortress: "/a/b/." })).toBe("/a/b");
    expect(resolveFortressPath({ fortress: "/a/b/c/.." })).toBe("/a/b");
    expect(
      resolveFortressPath({}, { SANCTUARY_FORTRESS_PATH: "/a/b/c/.." }),
    ).toBe("/a/b");
    expect(
      resolveFortressPath({}, { SANCTUARY_STORAGE_PATH: "/a/b/." }),
    ).toBe("/a/b");
  });

  it("keeps the default recovery destination outside a fortress named with ..", async () => {
    // `dirname("/a/b/c/..")` is "/a/b/c", which is INSIDE the /a/b fortress:
    // the un-normalized flag put the plaintext recovery key in the one place
    // it may never be.
    const fortressPath = join(tmp, "outer", "inner");
    await mkdir(fortressPath, { recursive: true, mode: 0o700 });
    // Built as a raw string on purpose: path.join would normalize it away,
    // and the argv value init actually receives does not go through join.
    const viaDotDot = `${fortressPath}/child/..`;

    const result = await init({
      fortress: viaDotDot,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
      force: true,
    });

    expect(result.fortressPath).toBe(fortressPath);
    expect(result.recoveryKeyDisclosurePath).toBe(
      agentGuidedRecoveryOutputPath(fortressPath),
    );
    expect(result.recoveryKeyDisclosurePath.startsWith(`${fortressPath}/`)).toBe(
      false,
    );
  });
});

describe("an announced recovery file is accounted for after a failure right after the banner", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-announced-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("removes the announced file when the disclosure fence throws after the banner printed", async () => {
    const fortressPath = join(tmp, "banner-then-throw");
    const staged = agentGuidedRecoveryOutputPath(fortressPath);

    const output = await attended(async (lines) => {
      await expect(
        init({ fortress: fortressPath, noPin: true, noIdentity: true }, {
          verifyRecoveryKeyReentry: async () => undefined,
          // The window the announced bit used to miss: the banner has printed
          // and the operator has been told to save this exact path, but the
          // flag was not set until the fence returned.
          __testAfterRecoveryKeyBannerPrinted: () => {
            throw new Error("planted holder loss after the banner");
          },
        }),
      ).rejects.toThrow(/planted holder loss after the banner/);
      return lines.join("\n");
    });

    // The announced bit is still what this pins: the summary must ACCOUNT for
    // the file by name in this exact window. What changed is the account. The
    // rollback removed the custody this key unwrapped, so the key opens
    // nothing, and leaving it behind made the retry refuse on that path.
    expect(output).toContain(staged);
    await expect(stat(staged)).rejects.toMatchObject({ code: "ENOENT" });
    expect(output).toContain("Removed:");
    expect(output).not.toContain("Kept on purpose");
  });
});

describe("what a failed init's rollback actually reaches", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-rollback-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("does not claim rollback is scoped to entries this init created", async () => {
    // The comment at the rollback site asserted a scope the code does not
    // have. A source claim about a security-relevant reach is a defect when
    // it is wrong, and only the source can witness it.
    const source = await readSource("src/wrap/init.ts");
    expect(source).not.toContain(
      "removes only entries this init\n          // created under the fortress root",
    );
    expect(source).toContain("It is NOT scoped to authorship");
  });

  it("removes a same-uid file that appeared at the fortress root, and nothing outside it", async () => {
    const fortressPath = join(tmp, "reach");
    const sibling = join(tmp, "sibling");
    await mkdir(sibling, { recursive: true, mode: 0o700 });
    const recoveryOut = join(tmp, "keys", "reach.txt");
    const intruder = join(fortressPath, "appeared-after-the-check");

    await attended(async () => {
      await expect(
        init(
          { fortress: fortressPath, noConfirm: true, noIdentity: true, recoveryOut },
          {
            provisionPin: async () => 1,
            beforeDurableMutation: async (label) => {
              // After the under-lock freshness check has already passed.
              if (label === "principal-policy") {
                await writeFile(intruder, "not written by this init", { mode: 0o600 });
              }
            },
          },
        ),
      ).rejects.toThrow(/Castle Wall key provisioning failed/);
    });

    // Removed: it sits at the fortress root, whoever wrote it.
    await expect(stat(intruder)).rejects.toMatchObject({ code: "ENOENT" });
    // Untouched: the fortress directory itself and its siblings. The external
    // recovery file this run announced IS removed with the custody it
    // unwrapped, and its PARENT directory (which init did not create) stands.
    await expect(stat(fortressPath)).resolves.toBeDefined();
    await expect(stat(sibling)).resolves.toBeDefined();
    await expect(stat(recoveryOut)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(dirname(recoveryOut))).resolves.toBeDefined();
  });
});

describe("operator-facing text describes the destination init actually uses", () => {
  it("never tells the operator to delete the recovery key from the fortress directory", async () => {
    const source = await readSource("src/wrap/recovery-key-disclosure.ts");
    // The old file body and declined-error text described the retired
    // in-fortress default, so an operator who followed them looked in the one
    // directory the key is guaranteed not to be in.
    expect(source).not.toContain("delete it from the\n" + '    "fortress directory');
    expect(source).not.toContain("written to recovery-key.txt");
    expect(source).toContain("Never keep it inside the fortress directory it protects");
  });

  it("writes a recovery file whose own body points outside the fortress", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-text-"));
    try {
      const fortressPath = join(tmp, "text");
      const result = await init({
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
        noIdentity: true,
      });
      const body = await readFile(result.recoveryKeyDisclosurePath, "utf8");
      expect(body).toContain("Never keep it inside the fortress directory it protects");
      expect(body).not.toContain("delete it from the\nfortress directory");
    } finally {
      await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("documents both staged-recovery branches in the agent-guided install contract", async () => {
    const doc = await readFile(
      join(SERVER_ROOT, "..", "docs", "agent-guided-install.md"),
      "utf8",
    );
    expect(doc).toContain("Staged file present");
    expect(doc).toContain("Staged file absent");
    expect(doc).toContain("sanctuary export-passphrase");
  });

  it("keeps the principal-policy filename in one place", async () => {
    for (const relative of ["src/cli/agents/cli.ts", "src/cli/federation.ts"]) {
      const source = await readSource(relative);
      expect(source).not.toContain('"principal-policy.yaml")');
      expect(source).toContain("principalPolicyPath(");
    }
  });
});

describe("crash-residue recognition spans every recovery-file body ever written", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-a73-residue-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const residue = (bodyLines: readonly string[]): string =>
    "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.\n" +
    "Generated: 2026-09-01T00:00:00.000Z\n\nRecovery key:\n" +
    `${"A".repeat(43)}\n\n` +
    `${bodyLines.join("\n")}\n`;

  it.each([
    ["current", RECOVERY_KEY_FILE_BODY_LINES],
    [
      "retired in-fortress",
      [
        "This file was created on first init. Sanctuary will NOT regenerate this file on",
        "subsequent runs and will NOT display the key again. After moving this file off",
        "the host (encrypted backup, password manager, paper safe), delete it from the",
        "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses",
        "the fortress passphrase by design.",
      ],
    ],
  ])("recovers a fortress carrying the %s body without --force", async (_label, body) => {
    // The residue check is what authorizes DELETING a file, so it recognizes
    // the file completely or not at all. Recognizing only the newest wording
    // would leave every fortress interrupted under an older release stuck:
    // the retry refuses a non-empty fortress and nothing may clean it.
    const fortressPath = join(tmp, `residue-${_label.replace(/\s+/g, "-")}`);
    const lockDir = join(fortressPath, "state", "_meta");
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    await writeFile(join(lockDir, "custody-master.lock"), "", { mode: 0o600 });
    await writeFile(join(fortressPath, "recovery-key.txt"), residue(body), {
      mode: 0o600,
    });

    const result = await init({
      fortress: fortressPath,
      noConfirm: true,
      noPin: true,
      noIdentity: true,
    });
    await expect(
      stat(join(fortressPath, "recovery-key.txt")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(result.recoveryKeyDisclosurePath, "utf8")).not.toContain(
      "A".repeat(43),
    );
  });
});
