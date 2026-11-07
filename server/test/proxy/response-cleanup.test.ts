/** Factory failure and shutdown preserve persistence and custody cleanup. */
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { UnifiedInboxScheduler } from "../../src/principal-policy/unified-inbox-scheduler.js";
import { CalibrationSuggester } from "../../src/auto-trigger/calibration-suggester.js";
import { SentinelDispatcher } from "../../src/sentinel/sentinel-dispatcher.js";
import { AnomalyPipelineDispatcher } from "../../src/anomaly-detection/anomaly-pipeline.js";
import { CallGovernor } from "../../src/operational/call-governor.js";
import * as responseScreenModule from "../../src/proxy/response-screen.js";
import { kernelBackedCrossProcessLockPlatformSupported, withExclusiveMasterRotationBarrier, type MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSanctuaryServer } from "../../src/index.js";
import * as custody from "../../src/core/master-custody.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { SovereigntyProfileStore } from "../../src/sovereignty-profile.js";
import { ResponseScreen } from "../../src/proxy/response-screen.js";
import { ResponseController, ResponseSession } from "../../src/proxy/response-runtime.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

afterEach(() => vi.restoreAllMocks());
describe("response cleanup composition", () => {
  it.each(["fenced", "rejecting"])("startup scrubs its key after %s scanner cleanup", async mode => {
    const home = await createTempHome("response-startup-cleanup");
    const storage = new MemoryStorage();
    const seed = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
    try {
      const profile = new SovereigntyProfileStore(storage, seed.masterKey); await profile.load();
      await profile.update({ upstream_servers: [{ name: "fixture", enabled: true, default_tier: 3,
        transport: { type: "stdio", command: process.execPath, args: [] } }] });
    } finally { await seed.cleanup(); }
    const establish = custody.establishMaster;
    let master: Uint8Array | undefined;
    const release = vi.fn(async () => {});
    vi.spyOn(custody, "establishMaster").mockImplementation(async options => {
      const result = await establish(options); master = result.masterKey;
      return { ...result, masterWriteBarrier: { ...result.masterWriteBarrier, release } } as typeof result;
    });
    vi.spyOn(ResponseScreen.prototype, "initialize").mockImplementation(async function (this: ResponseScreen) {
      if (mode === "fenced") {
        // Local controller keeps simulated unproven workers out of other tests' process quota.
        const session = new ResponseSession(new ResponseController());
        Object.defineProperty(this, "session", { value: session });
        const lease = session.reserve(); lease.fence(); lease.finish();
      }
      throw new Error("fixture startup failure");
    });
    if (mode === "rejecting") vi.spyOn(ResponseScreen.prototype, "close").mockRejectedValue(new Error("fixture cleanup failure"));
    try {
      const boot = createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
      // An assertion timeout witnesses a hung drain without leaving a timer or OS worker behind.
      let failure: unknown;
      void boot.catch(error => { failure = error; });
      await vi.waitFor(() => expect(failure).toBeInstanceOf(Error));
      await expect(boot).rejects.toThrow("fixture startup failure");
      expect(release).toHaveBeenCalledOnce();
      expect(master).toBeDefined(); expect(master!.every(byte => byte === 0)).toBe(true);
    } finally { await home.cleanup(); }
  });
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

function captureStartedProducers(): Array<() => void | Promise<void>> {
  const rescue: Array<() => void | Promise<void>> = [];
  const inboxStart = UnifiedInboxScheduler.prototype.start;
  vi.spyOn(UnifiedInboxScheduler.prototype, "start").mockImplementation(function (this: UnifiedInboxScheduler) {
    rescue.push(() => this.stop());
    inboxStart.call(this);
  });
  const calibrationStart = CalibrationSuggester.prototype.start;
  vi.spyOn(CalibrationSuggester.prototype, "start").mockImplementation(function (this: CalibrationSuggester) {
    rescue.push(() => this.stop());
    calibrationStart.call(this);
  });
  const sentinelStart = SentinelDispatcher.prototype.start;
  vi.spyOn(SentinelDispatcher.prototype, "start").mockImplementation(function (this: SentinelDispatcher) {
    rescue.push(() => this.dispose());
    sentinelStart.call(this);
  });
  const anomalyStart = AnomalyPipelineDispatcher.prototype.start;
  vi.spyOn(AnomalyPipelineDispatcher.prototype, "start").mockImplementation(function (this: AnomalyPipelineDispatcher) {
    rescue.push(() => this.dispose());
    anomalyStart.call(this);
  });
  return rescue;
}

const kernelSupported = kernelBackedCrossProcessLockPlatformSupported(process.platform);

describe.skipIf(!kernelSupported)("server custody cleanup", () => {
  it.each(["normal", "flush", "stop", "cache", "release", "flush and release", "undefined and release"])(
    "cleanup releases custody after %s completion", async mode => {
      const home = await createTempHome("server-custody-cleanup");
      const storage = new FilesystemStorage(join(home.defaultFortressPath, "state"));
      const establish = custody.establishMaster;
      let ownerLease: MasterWriteBarrierLease | undefined;
      let server: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
      const rescue = captureStartedProducers();
      let screen: ResponseScreen | undefined;
      const operationError = mode.startsWith("undefined") ? undefined : new Error("fixture teardown");
      const releaseError = new Error("fixture release");
      const release = vi.fn(async () => {
        await ownerLease!.release();
        if (mode.includes("release")) throw releaseError;
      });
      vi.spyOn(custody, "establishMaster").mockImplementation(async options => {
        const result = await establish(options);
        ownerLease = result.masterWriteBarrier!;
        return { ...result, masterWriteBarrier: { ...ownerLease, release } };
      });
      const exclusive = () => withExclusiveMasterRotationBarrier(
        new FilesystemStorage(join(home.defaultFortressPath, "state")),
        custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
        async () => "entered", { timeoutMs: 0 },
      );
      try {
        server = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
        expect(ownerLease!.signal.aborted).toBe(false);
        await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
        if (mode.includes("flush") || mode.startsWith("undefined")) {
          vi.spyOn(server.auditLog, "flush").mockRejectedValue(operationError);
        }
        if (mode === "stop") vi.spyOn(ResponseScreen.prototype, "stop").mockImplementationOnce(function (this: ResponseScreen) {
          screen = this;
          throw operationError;
        });
        if (mode === "cache") vi.spyOn(CallGovernor.prototype, "clearResponseCache").mockImplementationOnce(() => { throw operationError; });
        const first = server.cleanup();
        expect(server.cleanup()).toBe(first);
        const outcome = await first.then(() => ({ ok: true as const }), error => ({ ok: false as const, error }));
        expect(ownerLease!.signal.aborted).toBe(true);
        await expect(exclusive()).resolves.toBe("entered");
        expect(release).toHaveBeenCalledOnce();
        expect(server.cleanup()).toBe(first);
        if (mode === "normal") expect(outcome.ok).toBe(true);
        else {
          expect(outcome.ok).toBe(false);
          if (!outcome.ok) {
            if (mode.includes(" and release")) {
              expect(outcome.error).toBeInstanceOf(AggregateError);
              expect(outcome.error.errors).toEqual([operationError, releaseError]);
            } else expect(outcome.error).toBe(mode === "release" ? releaseError : operationError);
            await expect(server.cleanup()).rejects.toBe(outcome.error);
          }
        }
      } finally {
        await server?.cleanup().catch(() => undefined);
        // Independent rescue keeps an interrupted teardown from outliving its fixture.
        try {
          for (const stop of rescue) await stop();
          await screen?.close();
          await server?.server.close();
        } finally {
          await ownerLease?.release();
          await home.cleanup();
        }
      }
    },
  );

  it("cleanup retains custody until pending final persistence completes", async () => {
    const home = await createTempHome("server-custody-persistence");
    const storage = new FilesystemStorage(join(home.defaultFortressPath, "state"));
    const establish = custody.establishMaster;
    let ownerLease: MasterWriteBarrierLease | undefined;
    let server: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
    const entered = deferred();
    const finish = deferred();
    const exclusive = () => withExclusiveMasterRotationBarrier(
      new FilesystemStorage(join(home.defaultFortressPath, "state")),
      custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
      async () => "entered", { timeoutMs: 0 },
    );
    vi.spyOn(custody, "establishMaster").mockImplementation(async options => {
      const result = await establish(options);
      ownerLease = result.masterWriteBarrier;
      return result;
    });
    try {
      server = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE });
      const flush = server.auditLog.flush.bind(server.auditLog);
      vi.spyOn(server.auditLog, "flush").mockImplementation(async () => {
        entered.resolve();
        await finish.promise;
        await flush();
      });
      const pending = server.cleanup();
      await entered.promise;
      expect(ownerLease!.signal.aborted).toBe(false);
      expect(server.masterKey.some(byte => byte !== 0)).toBe(true);
      await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
      finish.resolve();
      await pending;
      expect(ownerLease!.signal.aborted).toBe(true);
      await expect(exclusive()).resolves.toBe("entered");
    } finally {
      finish.resolve();
      await server?.cleanup().catch(() => undefined);
      await ownerLease?.release();
      await home.cleanup();
    }
  });

  it.each([false, true])("failed screen construction releases custody with release failure %s", async releaseFails => {
    const home = await createTempHome("server-custody-construction");
    const storage = new FilesystemStorage(join(home.defaultFortressPath, "state"));
    const establish = custody.establishMaster;
    let ownerLease: MasterWriteBarrierLease | undefined;
    let server: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
    const constructionError = new Error("fixture construction");
    const releaseError = new Error("fixture release");
    vi.spyOn(custody, "establishMaster").mockImplementation(async options => {
      const result = await establish(options);
      ownerLease = result.masterWriteBarrier!;
      return { ...result, masterWriteBarrier: { ...ownerLease, release: async () => {
        await ownerLease!.release();
        if (releaseFails) throw releaseError;
      } } };
    });
    vi.spyOn(responseScreenModule, "ResponseScreen").mockImplementation(function () { throw constructionError; });
    try {
      const outcome = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE })
        .then(value => { server = value; return undefined; }, error => error);
      expect(ownerLease!.signal.aborted).toBe(true);
      await expect(withExclusiveMasterRotationBarrier(
        new FilesystemStorage(join(home.defaultFortressPath, "state")),
        custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
        async () => "entered", { timeoutMs: 0 },
      )).resolves.toBe("entered");
      if (releaseFails) {
        expect(outcome).toBeInstanceOf(AggregateError);
        expect(outcome.errors).toEqual([constructionError, releaseError]);
      } else expect(outcome).toBe(constructionError);
    } finally {
      await server?.cleanup().catch(() => undefined);
      await ownerLease?.release();
      await home.cleanup();
    }
  });
});
