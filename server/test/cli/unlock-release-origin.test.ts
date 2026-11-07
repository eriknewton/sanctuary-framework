import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import * as custody from "../../src/core/master-custody.js";
import * as locks from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import { runMemoryArchiveExportCommand, runMemoryProvenancePruneSignersCommand } from "../../src/cli/memory-archive.js";

const passphrase = "unlock-release-fixture-passphrase";
const genericRefusal = "Error: could not open or unlock the fortress.\n";
const ordinaryRefusal = "Error: could not unlock the fortress:";
const failureExit = 1;
const outerAndMigrationSessions = 2;
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, done: () => void) { this.text += String(chunk); done(); }
}

type Fixture = {
  root: string;
  storage: FilesystemStorage;
  out: Capture;
  err: Capture;
  env: NodeJS.ProcessEnv;
  failRelease: (error: Error, migrationOnly?: boolean) => void;
  released: () => Promise<void>;
};
async function fixture(check: (f: Fixture) => Promise<void>, legacy = false) {
  const root = await mkdtemp(join(tmpdir(), "ur-"));
  const leases: locks.MasterWriteBarrierLease[] = [];
  const out = new Capture();
  const err = new Capture();
  try {
    vi.stubEnv("HOME", root);
    vi.stubEnv("SANCTUARY_STORAGE_PATH", root);
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "locks"));
    const storage = new FilesystemStorage(join(root, "state"));
    await mkdir(join(root, "state"));
    if (legacy) {
      const derived = await deriveMasterKey(passphrase);
      try {
        await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));
        await storage.write("_meta", "recovery-key-hash", stringToBytes(hashToString(derived.key)));
      }
      finally { derived.key.fill(0); }
    }
    let rejection: { error: Error; migrationOnly: boolean } | undefined;
    const acquire = locks.acquireMasterWriteBarrier;
    vi.spyOn(locks, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
      const lease = await acquire(...args);
      leases.push(lease);
      const failure = rejection;
      if (!failure || (failure.migrationOnly && leases.length !== outerAndMigrationSessions)) return lease;
      return { ...lease, release: async () => { await lease.release(); throw failure.error; } };
    });
    await check({
      root, storage, out, err, env: { SANCTUARY_PASSPHRASE: passphrase },
      failRelease: (error, migrationOnly = false) => { rejection = { error, migrationOnly }; },
      released: async () => {
        expect(leases.length).toBeGreaterThan(0);
        for (const lease of leases) expect(lease.signal.aborted).toBe(true);
        await expect(locks.withExclusiveMasterRotationBarrier(
          storage, custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
          async () => "entered", { timeoutMs: 0 }, // Probe immediately after awaited disposal.
        )).resolves.toBe("entered");
      },
    });
  } finally {
    vi.restoreAllMocks();
    try { await Promise.all(leases.map(lease => lease.release())); }
    finally {
      vi.unstubAllEnvs();
      out.destroy();
      err.destroy();
      await rm(root, { recursive: true, force: true });
    }
  }
}

function rejectLegacyMarker(error: Error) {
  const read = FilesystemStorage.prototype.read;
  vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(function (this: FilesystemStorage, namespace, key) {
    if (namespace === "_meta" && key === "key-params") return Promise.reject(error);
    return read.call(this, namespace, key);
  });
}

function assertRelease(error: unknown, cause: Error, members: unknown[]) {
  expect(error).toBeInstanceOf(custody.MasterEstablishmentReleaseError);
  const failure = error as custody.MasterEstablishmentReleaseError;
  expect(failure).not.toBe(cause);
  expect(failure.cause).toBe(cause);
  expect(failure.errors).toHaveLength(members.length);
  members.forEach((member, index) => expect(failure.errors[index]).toBe(member));
}

const verbs = [
  { name: "export", run: runMemoryArchiveExportCommand, argv: (root: string) => ["--archive-id", "a".repeat(32), "--out", join(root, "bundle")] }, // Archive IDs encode 16 bytes as 32 hex digits.
  { name: "provenance prune", run: runMemoryProvenancePruneSignersCommand, argv: () => [] },
];
function args(f: Fixture, argv: string[]) {
  return {
    argv: [...argv, "--owner-ref", "fixture-owner", "--fortress", f.root],
    env: f.env, out: f.out, err: f.err,
    dialogRunner: () => { throw new Error("bootstrap must not request approval"); },
  };
}

describe.skipIf(!locks.kernelBackedCrossProcessLockPlatformSupported(process.platform))("typed unlock release failures", () => {
  it.each(["refusal", "operation"])("unlock preserves %s cleanup failure with release origin", async mode => {
    await fixture(async f => {
      const releaseError = Object.freeze(new Error("release rejected"));
      const operationError = new Error("marker read rejected");
      f.failRelease(releaseError);
      if (mode === "operation") rejectLegacyMarker(operationError);
      const error = await unlockLocalFortress({ storage: f.storage, storagePath: f.root, env: f.env, writeIntent: true }).catch((failure: unknown) => failure);
      assertRelease(error, releaseError, mode === "operation" ? [operationError, releaseError] : [releaseError]);
      expect((error as Error).message).toBe(mode === "operation"
        ? "Fortress unlock and session release failed"
        : "Session release after unlock refusal failed");
      await f.released();
    });
  });

  it.each(verbs.flatMap(verb => ["refusal", "operation"].map(mode => ({ ...verb, mode }))))(
    "$name rejects typed unlock $mode release failure without printing a refusal", async ({ run, argv, mode }) => {
      await fixture(async f => {
        const releaseError = new Error("release rejected");
        const operationError = new Error("marker read rejected");
        f.failRelease(releaseError);
        if (mode === "operation") rejectLegacyMarker(operationError);
        const error = await run(args(f, argv(f.root))).catch((failure: unknown) => failure);
        assertRelease(error, releaseError, mode === "operation" ? [operationError, releaseError] : [releaseError]);
        expect(f.err.text).toBe("");
        await f.released();
      });
    },
  );

  it.each(verbs)("$name rethrows the original migration release error without printing a refusal", async ({ run, argv }) => {
    await fixture(async f => {
      const releaseError = new Error("migration release rejected");
      f.failRelease(releaseError, true);
      const resolve = custody.resolveCliMasterKey;
      let observed: unknown;
      vi.spyOn(custody, "resolveCliMasterKey").mockImplementation(async (...options) => {
        try { return await resolve(...options); }
        catch (error) { observed = error; throw error; }
      });
      // Recovery keys contain 32 bytes; the zero key cannot match the derived fixture key.
      const command = run({ ...args(f, argv(f.root)), env: { SANCTUARY_RECOVERY_KEY: toBase64url(new Uint8Array(32)) } });
      const error = await command.catch((failure: unknown) => failure);
      expect(observed).toBeInstanceOf(custody.MasterEstablishmentReleaseError);
      expect(error).toBe(observed);
      expect((error as custody.MasterEstablishmentReleaseError).cause).toBe(releaseError);
      expect((error as custody.MasterEstablishmentReleaseError).errors.at(-1)).toBe(releaseError);
      expect(f.err.text).toBe("");
      await f.released();
    }, true);
  });

  it.each(verbs)("$name keeps ordinary unlock refusal text and exit one", async ({ run, argv }) => {
    await fixture(async f => {
      expect(await run(args(f, argv(f.root)))).toBe(failureExit);
      expect(f.err.text).toContain(ordinaryRefusal);
      expect(f.err.text).not.toContain(genericRefusal);
      await f.released();
    });
  });

  it.each(verbs)("$name keeps ordinary non-release throws as generic refusal and exit one", async ({ run, argv }) => {
    await fixture(async f => {
      const error = new AggregateError([new Error("ordinary failure")], "Fortress unlock and session release failed");
      rejectLegacyMarker(error);
      expect(await run(args(f, argv(f.root)))).toBe(failureExit);
      expect(f.err.text).toBe(genericRefusal);
      await f.released();
    });
  });
});
