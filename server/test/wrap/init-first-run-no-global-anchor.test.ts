/**
 * `sanctuary init` on a first run: the vault is created, and creating it never
 * changes this machine's Castle Wall settings.
 *
 * Capability the tests below pin (register rows
 * defect.a73-default-init-fails-on-pre-existing-global-pin,
 * defect.a73-failed-init-leaves-announced-recovery-key-for-destroyed-fortress):
 *
 *   1. Default `init` creates the vault and its own Castle key pair, and the
 *      machine-wide Castle Wall anchor is byte-identical before and after,
 *      whatever that anchor already held.
 *   2. On a machine with no such anchor, `init` creates none.
 *   3. The vault records a named, readable "not yet on the wall" state, and
 *      says so in plain words.
 *   4. `--no-pin` and SANCTUARY_INIT_NO_PIN are accepted and change nothing.
 *   5. A run that fails after announcing a recovery key removes that key file
 *      along with the custody it unwrapped.
 *
 * Isolation: every fortress is a per-test temp directory, and the machine-wide
 * anchor is a temp path threaded through the existing `globalPinnedPublicKeyPath`
 * seam on the provisioning verb `init` runs. Nothing here reads or writes the
 * real machine-wide path, the operator's login keychain, or a real
 * `~/.sanctuary`.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runInit, resolveNoPin, type InitOptions, type RunInitDeps } from "../../src/wrap/init.js";
import { runProvisionPinAlreadyLocked } from "../../src/cli/castle-wall.js";
import {
  CASTLE_WALL_NOT_YET_WALLED,
  castleWallProvisionRecordPath,
  readPersistedCastleWallProvision,
} from "../../src/castle-wall/provision-state.js";
import { agentGuidedRecoveryOutputPath } from "../../src/wrap/custody-flow.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

/** Capture the operator-facing stderr channel init writes to. */
async function captured<T>(run: (lines: string[]) => Promise<T>): Promise<[T, string]> {
  const lines: string[] = [];
  const consoleError = vi
    .spyOn(console, "error")
    .mockImplementation((...args: unknown[]) => {
      lines.push(args.map((a) => String(a)).join(" "));
    });
  const stderrWrite = vi
    .spyOn(process.stderr, "write")
    .mockImplementation(((chunk: string | Uint8Array) => {
      lines.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    }) as typeof process.stderr.write);
  try {
    const value = await run(lines);
    return [value, lines.join("\n")];
  } finally {
    consoleError.mockRestore();
    stderrWrite.mockRestore();
  }
}

const init = (options: InitOptions, deps: RunInitDeps = {}) =>
  runInit({ noConfirm: true, noIdentity: true, ...options }, deps);

/** A syntactically valid 32-byte Ed25519 public key stand-in. */
const anchorBytes = (fill: number): Buffer => Buffer.alloc(32, fill);

/** A sink for CLI output a test does not assert on. */
const silent = (): Writable =>
  new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

describe("sanctuary init: a machine that already carries a Castle Wall anchor", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-firstrun-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("creates the vault on a machine whose anchor holds a foreign key", async () => {
    // The host shape this pins: a Mac that was armed by an earlier install, so
    // the machine-wide anchor holds a key no new vault can match. Every such
    // Mac is this shape, which is why the first command an upgrader types has
    // to work on it. Vault creation no longer consults that anchor at all, so
    // its contents cannot decide whether a vault can be made.
    const fortressPath = join(tmp, "vault");
    const [result, output] = await captured(() => init({ fortress: fortressPath }));

    expect(result.fortressPath).toBe(fortressPath);
    // The vault exists and opens: its custody envelope is on disk.
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).resolves.toBeDefined();
    // This vault has its own Castle key pair, inside the fortress.
    await expect(
      stat(join(fortressPath, "castle-pinned-pubkey.bin")),
    ).resolves.toBeDefined();
    expect(output).toContain("Sanctuary init: complete.");
  });

  it("leaves a foreign machine-wide anchor byte-identical, and creates none where there is none", async () => {
    // The provisioning verb `init` runs is the only place a machine-wide write
    // could live, and it takes a path seam, so this drives it directly at a
    // temp anchor and compares bytes. If a machine-wide write is ever
    // reintroduced, this is what fails.
    const anchor = join(tmp, "castle-pinned-pubkey.bin");
    const planted = anchorBytes(0x11);
    await writeFile(anchor, planted, { mode: 0o644 });

    const foreign = await runProvisionPinAlreadyLocked([], {
      out: silent(),
      err: silent(),
      env: { SANCTUARY_STORAGE_PATH: join(tmp, "on-armed-machine") },
      globalPinnedPublicKeyPath: anchor,
      __resolvedProvisionMasterKey: new Uint8Array(32).fill(0x5a),
    });
    expect(foreign).toBe(0);
    expect(await readFile(anchor)).toEqual(planted);

    // Same verb, a machine with no anchor at all: it publishes none.
    const absent = join(tmp, "absent-anchor.bin");
    const fresh = await runProvisionPinAlreadyLocked([], {
      out: silent(),
      err: silent(),
      env: { SANCTUARY_STORAGE_PATH: join(tmp, "on-fresh-machine") },
      globalPinnedPublicKeyPath: absent,
      __resolvedProvisionMasterKey: new Uint8Array(32).fill(0x5a),
    });
    expect(fresh).toBe(0);
    await expect(stat(absent)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("records a readable named state saying the vault is not yet on the wall", async () => {
    const fortressPath = join(tmp, "named-state");
    const [, output] = await captured(() => init({ fortress: fortressPath }));

    // At rest, as an explicit token rather than an absence, and readable
    // without opening the fortress.
    const record = await readFile(castleWallProvisionRecordPath(fortressPath), "utf8");
    expect(record).toBe(CASTLE_WALL_NOT_YET_WALLED);
    await expect(readPersistedCastleWallProvision(fortressPath)).resolves.toEqual({
      state: "not-yet-walled",
    });

    // And in words an operator on their first run can act on, with no
    // trust-anchor vocabulary.
    expect(output).toContain("your vault is created");
    expect(output).toContain("not yet on the Castle Wall of this Mac");
    expect(output).not.toContain("trust anchor");
    expect(output).not.toContain("provision-pin");
  });

  it("accepts --no-pin and SANCTUARY_INIT_NO_PIN, and changes nothing either way", async () => {
    const anchor = join(tmp, "flagged-anchor.bin");
    const planted = anchorBytes(0x22);
    await writeFile(anchor, planted, { mode: 0o644 });

    const fortressPath = join(tmp, "flagged");
    const [result, output] = await captured(() =>
      init({ fortress: fortressPath, noPin: true }),
    );

    expect(result.fortressPath).toBe(fortressPath);
    expect(await readFile(anchor)).toEqual(planted);
    // Same vault, same named state: the option selects only a deprecation line.
    await expect(readPersistedCastleWallProvision(fortressPath)).resolves.toEqual({
      state: "not-yet-walled",
    });
    expect(output).toContain("--no-pin is accepted but no longer does anything");
    expect(output).toContain("Sanctuary init: complete.");

    // The environment variable keeps its explicit allowlist: an inherited
    // "no"/"off" is not an opt-in.
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "1" })).toBe(true);
    expect(resolveNoPin({}, { SANCTUARY_INIT_NO_PIN: "off" })).toBe(false);
    expect(resolveNoPin({}, {})).toBe(false);
  });
});

describe("sanctuary init: a run that fails after announcing a recovery key", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-keyfate-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("removes the announced key file together with the custody it unwrapped", async () => {
    // A real temporary filesystem, not an in-memory builder: the behaviour
    // under test is the unlink itself and the fsync of its parent directory.
    const fortressPath = join(tmp, "doomed");
    const staged = agentGuidedRecoveryOutputPath(fortressPath);

    const [, output] = await captured(async () => {
      await expect(
        init(
          { fortress: fortressPath },
          { provisionPin: async () => 1 },
        ),
      ).rejects.toThrow(/Castle Wall key provisioning failed/);
    });

    // The custody this key unwrapped is gone, so the key opens nothing.
    await expect(
      stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    // And the announced file is gone with it, said in one sentence.
    await expect(stat(staged)).rejects.toMatchObject({ code: "ENOENT" });
    expect(output).toContain("Removed:");
    expect(output).toContain(staged);
    // The retry guidance no longer teaches the operator to delete anything.
    expect(output).not.toContain("rm ");
    expect(output).toContain("Next step:");

    // The named destination is clear, so the printed retry actually completes.
    const retry = await captured(() => init({ fortress: fortressPath }));
    expect(retry[0].recoveryKeyDisclosurePath).toBe(staged);
  });

  it("keeps the announced key when the custody it unwraps could NOT be removed", async () => {
    // ORDERING, not merely cleanup. The key unwraps the custody, so deleting
    // the key first and then failing to delete the custody destroys the only
    // recovery factor for a fortress that survived — while the summary tells
    // the operator the key "could no longer open anything", which is the one
    // sentence that is false in exactly this case.
    //
    // The failure is injected at the real custody-removal capability on a real
    // temporary filesystem, so the ordering under test is the shipped one.
    const fortressPath = join(tmp, "cleanup-fails");
    const staged = agentGuidedRecoveryOutputPath(fortressPath);
    const original = FilesystemStorage.prototype.withNamespaceLock;
    let removalAttempted = false;

    const spy = vi
      .spyOn(FilesystemStorage.prototype, "withNamespaceLock")
      .mockImplementation(function (
        this: FilesystemStorage,
        namespace: never,
        lockKey: never,
        operation: never,
        options: never,
      ) {
        return (original as (...a: unknown[]) => Promise<unknown>).call(
          this,
          namespace,
          lockKey,
          async (lease: { stableFortressFiles?: Record<string, unknown> }) => {
            if (!lease.stableFortressFiles) {
              return (operation as (l: unknown) => unknown)(lease);
            }
            return (operation as (l: unknown) => unknown)({
              ...lease,
              stableFortressFiles: {
                ...lease.stableFortressFiles,
                restoreFreshLockScaffold: async () => {
                  removalAttempted = true;
                  throw new Error("injected custody cleanup I/O failure");
                },
              },
            });
          },
          options,
        );
      } as never);

    try {
      const [, output] = await captured(async () => {
        await expect(
          init({ fortress: fortressPath }, { provisionPin: async () => 1 }),
        ).rejects.toThrow(/rollback did not complete/);
      });

      expect(removalAttempted).toBe(true);
      // The custody survived the failed cleanup...
      await expect(
        stat(join(fortressPath, "state", "_meta", "custody-envelope.enc")),
      ).resolves.toBeDefined();
      // ...so the key that opens it is still on disk, and the summary says so
      // instead of claiming the key is now useless.
      await expect(stat(staged)).resolves.toBeDefined();
      expect(output).toContain("Still on disk:");
      expect(output).toContain(staged);
      expect(output).not.toContain("could no longer open anything");
    } finally {
      spy.mockRestore();
    }
  });
});
