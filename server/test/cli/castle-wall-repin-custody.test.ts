/**
 * Re-pin custody and durable-audit contract.
 *
 * These tests use the suite-wide in-memory keyring through the custody
 * chokepoint; they never consult a login keychain.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";

import {
  runProvisionPinAlreadyLocked,
  runRePin,
} from "../../src/cli/castle-wall.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  establishMaster,
  verifyRecoveryWrapByReentry,
} from "../../src/core/master-custody.js";
import * as masterCustody from "../../src/core/master-custody.js";
import { toBase64url } from "../../src/core/encoding.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import { getOrCreateKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import {
  resolveFortressCustodyCredential,
  type CustodyCredentialResolution,
} from "../../src/wrap/custody-credential.js";
import type { ShimInvoker } from "../../src/castle-wall/runtime/helper-signer.js";

class CaptureStream extends Writable {
  private readonly chunks: string[] = [];

  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }

  text(): string {
    return this.chunks.join("");
  }
}

function makeMockHelper(): {
  pub: Uint8Array;
  rePinCalls: number;
  invoke: ShimInvoker;
} {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  const helper = {
    pub,
    rePinCalls: 0,
    invoke: async (args: string[], stdin: Uint8Array | null) => {
      if (args[0] === "re-pin") helper.rePinCalls += 1;
      if (args[0] === "get-pubkey" || args[0] === "re-pin") {
        return { stdout: toBase64url(pub), stderr: "", code: 0 };
      }
      return {
        stdout: toBase64url(ed25519.sign(stdin ?? new Uint8Array(0), seed)),
        stderr: "",
        code: 0,
      };
    },
  };
  return helper;
}

function unavailableResolution(): CustodyCredentialResolution {
  return {
    status: "unresolved",
    report: {
      found: [],
      rejected: [],
      indeterminate: ["enrolled-custody-key"],
      details: { "enrolled-custody-key": "test custody item unavailable" },
      integrityIndeterminate: false,
      envelopePresent: true,
      noCustodyStateAtAll: false,
      custodyKeyUnverifiable: false,
    },
  };
}

async function seedEnrolledFortress(fortressPath: string): Promise<Uint8Array> {
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  const custodyKey = await getOrCreateKeychainCustodyKey(fortressPath);
  if (!custodyKey) throw new Error("test keyring did not yield a custody key");
  const established = await establishMaster({
    storage,
    keychainKey: custodyKey,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
    storagePathHint: fortressPath,
  });
  // Match interactive init: the minted recovery factor becomes a verified
  // second factor only after its re-entry proves the saved value opens this
  // exact fortress. Castle pin provisioning correctly enforces that floor.
  await verifyRecoveryWrapByReentry(
    storage,
    established.envelope!,
    established.mintedRecoveryKey!,
  );
  await established.masterWriteBarrier?.release();
  custodyKey.fill(0);
  return established.masterKey;
}

async function provisionLocalPin(
  fortressPath: string,
  masterKey: Uint8Array,
): Promise<void> {
  const err = new CaptureStream();
  const code = await runProvisionPinAlreadyLocked([], {
    out: new CaptureStream(),
    err,
    env: { SANCTUARY_STORAGE_PATH: fortressPath },
    // The fixture never names the machine-wide anchor, even though this
    // provision-only path must remain fortress-local.
    globalPinnedPublicKeyPath: join(fortressPath, "test-global-pin.bin"),
    __resolvedProvisionMasterKey: masterKey.slice(),
  });
  if (code !== 0) throw new Error(`test local pin provisioning failed: ${err.text()}`);
}

function expectLiveSecret(buffer: Uint8Array | undefined, label: string): asserts buffer is Uint8Array {
  expect(buffer, `${label} was captured from the real custody path`).toBeInstanceOf(Uint8Array);
  expect(buffer!.some((byte) => byte !== 0), `${label} was live before cleanup`).toBe(true);
}

async function expectMasterRotationBarrierReleased(fortressPath: string): Promise<void> {
  let enteredExclusiveSection = false;
  await withExclusiveMasterRotationBarrier(
    new FilesystemStorage(join(fortressPath, "state")),
    masterCustody.CUSTODY_WRITE_LOCK_NAMESPACE,
    masterCustody.MASTER_ROTATION_BARRIER_NAME,
    async () => {
      enteredExclusiveSection = true;
    },
    { timeoutMs: 1_000, retryMs: 10 },
  );
  expect(enteredExclusiveSection).toBe(true);
}

describe("castle-wall re-pin enrolled custody", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("uses the enrolled exact-fortress keyring factor and durably records the re-pin", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-enrolled-"));
    tempDirs.push(fortressPath);
    const masterKey = await seedEnrolledFortress(fortressPath);
    try {
      await provisionLocalPin(fortressPath, masterKey);

      let rePinMasterKey: Uint8Array | undefined;
      let resolvedKeychainKey: Uint8Array | undefined;
      let releaseCalls = 0;
      let releaseLeakedLease: (() => Promise<void>) | undefined;
      const realEstablishMaster = masterCustody.establishMaster;
      vi.spyOn(masterCustody, "establishMaster").mockImplementation(async (options) => {
        const established = await realEstablishMaster(options);
        rePinMasterKey = established.masterKey;
        return established;
      });

      const helper = makeMockHelper();
      const code = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out: new CaptureStream(),
        err: new CaptureStream(),
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
        __testResolveRePinCustodyCredential: async (options) => {
          const resolution = await resolveFortressCustodyCredential(options);
          if (resolution.status === "resolved" && resolution.credential.kind === "keychain-key") {
            resolvedKeychainKey = resolution.credential.keychainKey;
          }
          return resolution;
        },
        __testAfterRePinMasterEstablished: (lease) => {
          expectLiveSecret(rePinMasterKey, "runRePin master key");
          expectLiveSecret(resolvedKeychainKey, "resolved keychain credential");
          if (lease === undefined) throw new Error("test expected a master-write barrier");
          const originalRelease = lease.release.bind(lease);
          releaseLeakedLease = originalRelease;
          vi.spyOn(lease, "release").mockImplementation(async () => {
            releaseCalls += 1;
            await originalRelease();
          });
        },
      });

      expect(code).toBe(0);
      expect(rePinMasterKey).toEqual(new Uint8Array(rePinMasterKey!.length));
      expect(resolvedKeychainKey).toEqual(new Uint8Array(resolvedKeychainKey!.length));
      try {
        await expectMasterRotationBarrierReleased(fortressPath);
      } finally {
        if (releaseCalls === 0) await releaseLeakedLease?.();
      }
      expect(releaseCalls).toBe(1);
      const audit = new AuditLog(
        new FilesystemStorage(join(fortressPath, "state")),
        masterKey,
        { integrityMode: "lenient" },
      );
      const entries = await audit.query({ layer: "l1", limit: 100 });
      expect(entries.entries.some((entry) =>
        entry.details?.source === "castle-wall-re-pin" &&
        ((entry.details as Record<string, unknown>).rotation_proof as {
          new_public_key?: string;
        } | undefined)?.new_public_key === toBase64url(helper.pub),
      )).toBe(true);

      const cleanupErr = new CaptureStream();
      const cleanupCode = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out: new CaptureStream(),
        err: cleanupErr,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
        __testAfterRePinMasterEstablished: (lease) => {
          if (lease === undefined) throw new Error("test expected a master-write barrier");
          const originalRelease = lease.release.bind(lease);
          vi.spyOn(lease, "release").mockImplementationOnce(async () => {
            await originalRelease();
            throw new Error("test cleanup failure");
          });
        },
      });
      expect(cleanupCode).toBe(1);
      expect(cleanupErr.text()).toContain("migration and its audit record completed");
      expect(cleanupErr.text()).toContain("test cleanup failure");
      await expectMasterRotationBarrierReleased(fortressPath);
    } finally {
      masterKey.fill(0);
    }
  });

  it("returns nonzero when an equal-pin re-assert audit flush fails", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-audit-failure-"));
    tempDirs.push(fortressPath);
    const masterKey = await seedEnrolledFortress(fortressPath);
    try {
      await provisionLocalPin(fortressPath, masterKey);

      const helper = makeMockHelper();
      await writeFile(join(fortressPath, "castle-pinned-pubkey.bin"), helper.pub);
      const successCode = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out: new CaptureStream(),
        err: new CaptureStream(),
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
      });
      expect(successCode).toBe(0);
      const audit = new AuditLog(
        new FilesystemStorage(join(fortressPath, "state")),
        masterKey,
        { integrityMode: "lenient" },
      );
      const entries = await audit.query({ layer: "l1", limit: 100 });
      const reassert = entries.entries.find((entry) =>
        entry.details?.source === "castle-wall-re-pin" &&
        (entry.details as Record<string, unknown>).note ===
          "re-assert (pin already holds helper key)",
      );
      expect(reassert?.details).toMatchObject({
        new_pin_fingerprint: createHash("sha256").update(helper.pub).digest("hex").slice(0, 16),
      });

      let rePinMasterKey: Uint8Array | undefined;
      let resolvedKeychainKey: Uint8Array | undefined;
      let releaseCalls = 0;
      let releaseLeakedLease: (() => Promise<void>) | undefined;
      const realEstablishMaster = masterCustody.establishMaster;
      vi.spyOn(masterCustody, "establishMaster").mockImplementation(async (options) => {
        const established = await realEstablishMaster(options);
        rePinMasterKey = established.masterKey;
        return established;
      });

      const flush = vi.spyOn(AuditLog.prototype, "flush").mockRejectedValue(
        new Error("test required audit flush failure"),
      );
      const out = new CaptureStream();
      const err = new CaptureStream();
      const code = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out,
        err,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
        __testResolveRePinCustodyCredential: async (options) => {
          const resolution = await resolveFortressCustodyCredential(options);
          if (resolution.status === "resolved" && resolution.credential.kind === "keychain-key") {
            resolvedKeychainKey = resolution.credential.keychainKey;
          }
          return resolution;
        },
        __testAfterRePinMasterEstablished: (lease) => {
          expectLiveSecret(rePinMasterKey, "runRePin master key");
          expectLiveSecret(resolvedKeychainKey, "resolved keychain credential");
          if (lease === undefined) throw new Error("test expected a master-write barrier");
          const originalRelease = lease.release.bind(lease);
          releaseLeakedLease = originalRelease;
          vi.spyOn(lease, "release").mockImplementation(async () => {
            releaseCalls += 1;
            await originalRelease();
          });
        },
      });

      expect(code).toBe(1);
      expect(out.text()).toMatch(/^[a-f0-9]{16}\n/);
      expect(err.text()).toContain("recording the rotation proof in the audit log failed");
      expect(err.text()).toContain("pin migration itself succeeded");
      expect(flush).toHaveBeenCalledTimes(1);
      expect(rePinMasterKey).toEqual(new Uint8Array(rePinMasterKey!.length));
      expect(resolvedKeychainKey).toEqual(new Uint8Array(resolvedKeychainKey!.length));
      try {
        await expectMasterRotationBarrierReleased(fortressPath);
      } finally {
        if (releaseCalls === 0) await releaseLeakedLease?.();
      }
      expect(releaseCalls).toBe(1);
    } finally {
      masterKey.fill(0);
    }
  });

  it("falls through an empty environment passphrase to enrolled custody", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-empty-env-"));
    tempDirs.push(fortressPath);
    const masterKey = await seedEnrolledFortress(fortressPath);
    try {
      await provisionLocalPin(fortressPath, masterKey);
      const helper = makeMockHelper();
      const code = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out: new CaptureStream(),
        err: new CaptureStream(),
        env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: "" },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
      });

      expect(code).toBe(0);
      expect(helper.rePinCalls).toBe(1);
      const audit = new AuditLog(
        new FilesystemStorage(join(fortressPath, "state")),
        masterKey,
        { integrityMode: "lenient" },
      );
      const entries = await audit.query({ layer: "l1", limit: 100 });
      expect(entries.entries.some((entry) =>
        entry.details?.source === "castle-wall-re-pin" &&
        ((entry.details as Record<string, unknown>).rotation_proof as {
          new_public_key?: string;
        } | undefined)?.new_public_key === toBase64url(helper.pub),
      )).toBe(true);
    } finally {
      masterKey.fill(0);
    }
  });

  it("does not fall back to enrolled custody after a nonempty wrong passphrase", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-explicit-"));
    tempDirs.push(fortressPath);
    const masterKey = await seedEnrolledFortress(fortressPath);
    try {
      await provisionLocalPin(fortressPath, masterKey);
      const err = new CaptureStream();
      const helper = makeMockHelper();
      const code = await runRePin([], {
        confirmStdin: Readable.from(["re-pin\n"]),
        out: new CaptureStream(),
        err,
        env: {
          SANCTUARY_STORAGE_PATH: fortressPath,
          SANCTUARY_PASSPHRASE: "not-the-enrolled-passphrase",
        },
        platform: "darwin",
        signerClientInvoke: helper.invoke,
      });

      expect(code).toBe(1);
      expect(helper.rePinCalls).toBe(1);
      expect(err.text()).not.toContain("Rotation proof recorded in the audit log");
      const audit = new AuditLog(
        new FilesystemStorage(join(fortressPath, "state")),
        masterKey,
        { integrityMode: "lenient" },
      );
      const entries = await audit.query({ layer: "l1", limit: 100 });
      expect(entries.entries.some((entry) =>
        entry.details?.source === "castle-wall-re-pin",
      )).toBe(false);
    } finally {
      masterKey.fill(0);
    }
  });

  it("refuses a virgin fortress without minting custody state", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-virgin-"));
    tempDirs.push(fortressPath);
    const err = new CaptureStream();
    const helper = makeMockHelper();
    const code = await runRePin([], {
      confirmStdin: Readable.from(["re-pin\n"]),
      out: new CaptureStream(),
      err,
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("has no enrolled custody credential");
    expect(helper.rePinCalls).toBe(0);
    await expect(stat(join(fortressPath, "state"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("refuses unavailable custody before invoking the helper", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-unavailable-"));
    tempDirs.push(fortressPath);
    const helper = makeMockHelper();
    const code = await runRePin([], {
      confirmStdin: Readable.from(["re-pin\n"]),
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      signerClientInvoke: helper.invoke,
      __testResolveRePinCustodyCredential: async () => unavailableResolution(),
    });

    expect(code).toBe(1);
    expect(helper.rePinCalls).toBe(0);
  });

  it("scrubs a resolved keychain buffer when the helper refuses before migration", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-repin-key-scrub-"));
    tempDirs.push(fortressPath);
    const keychainKey = new Uint8Array(32).fill(0x5a);
    const code = await runRePin([], {
      confirmStdin: Readable.from(["re-pin\n"]),
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath },
      platform: "darwin",
      signerClientInvoke: async () => {
        throw new Error("test helper refusal");
      },
      __testResolveRePinCustodyCredential: async () => ({
        status: "resolved",
        credential: {
          source: "enrolled-custody-key",
          kind: "keychain-key",
          keychainKey,
          location: "test keyring",
          displaySource: "enrolled-custody-key",
        },
        report: {
          found: ["enrolled-custody-key"],
          rejected: [],
          indeterminate: [],
          details: {},
          integrityIndeterminate: false,
          envelopePresent: true,
          noCustodyStateAtAll: false,
          custodyKeyUnverifiable: false,
        },
      }),
    });

    expect(code).toBe(1);
    expect(keychainKey).toEqual(new Uint8Array(32));
  });
});
