import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { signRevocationList } from "../../src/entitlement/revocation-list.js";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer, type SanctuaryServer } from "../../src/index.js";
import { ConstructionWork } from "../../src/dashboard/construction-work.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { SentinelFindingStore, SENTINEL_FINDING_NAMESPACE, SENTINEL_FINDING_KEY_PREFIX } from "../../src/sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";
import * as custody from "../../src/core/master-custody.js";
import { withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import { createTempFortress, TEST_PASSPHRASE, type TempFortress } from "../helpers/temp-fortress.js";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
const EPHEMERAL_PORT = 0;
const EXPIRED_AT = new Date("2000-01-01T00:00:00.000Z");
const EXPIRED_ID = "expired-construction-finding";
const RETAINED_ID = "retained-construction-finding";
const EXPIRED_KEY = `${SENTINEL_FINDING_KEY_PREFIX}${EXPIRED_ID}`;
const RETAINED_KEY = `${SENTINEL_FINDING_KEY_PREFIX}${RETAINED_ID}`;

describe("embedded construction session ordering", () => {
  let fortress: TempFortress;
  let env: NodeJS.ProcessEnv;
  let server: SanctuaryServer | undefined;
  let channels: DashboardApprovalChannel[];
  let sessions: custody.EstablishMasterResult[];
  let release: ReturnType<typeof vi.spyOn>;
  let finish: ReturnType<typeof deferred>;
  let entered: ReturnType<typeof deferred>;
  let released: ReturnType<typeof deferred>;
  let draining: ReturnType<typeof deferred>;
  let pending: Promise<unknown>[];
  let events: string[];
  let sentinelFinish: ReturnType<typeof deferred>;
  let drainOwner: ConstructionWork | undefined;
  let registrations: { owner: ConstructionWork; task: Promise<unknown> }[];
  let nonzeroAtRelease: boolean[];
  const finding = (id: string): SentinelFinding => ({
    finding_id: id, sentinel_id: "construction-fixture", severity: "info",
    summary: "Fixture finding", details: {}, observed_at: EXPIRED_AT.toISOString(),
    evidence_audit_ids: [], fortress_id: fortressIdFromStoragePath(fortress.storagePath),
  });
  const storage = () => new FilesystemStorage(join(fortress.storagePath, "state"));
  const exclusive = () => withExclusiveMasterRotationBarrier(storage(), custody.CUSTODY_WRITE_LOCK_NAMESPACE,
    custody.MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 });
  const own = <T>(promise: Promise<T>): Promise<T> => { pending.push(promise.catch(() => undefined)); return promise; };
  const boot = (options: Parameters<typeof createSanctuaryServer>[0] = {}) => own(createSanctuaryServer({
    passphrase: TEST_PASSPHRASE, ...options,
  }).then((value) => { server = value; return value; }));
  const holdSentinel = (boundary: "list" | "delete", reject = false) => {
    finish.resolve();
    const sentinelEntered = deferred();
    const settled = deferred();
    let callingPrune = false;
    let task: ReturnType<SentinelFindingStore["pruneExpired"]> | undefined;
    let store: SentinelFindingStore | undefined;
    const prune = SentinelFindingStore.prototype.pruneExpired;
    const pruneSpy = vi.spyOn(SentinelFindingStore.prototype, "pruneExpired").mockImplementation(function (this: SentinelFindingStore, ...args) {
      store = this;
      callingPrune = true;
      try {
        task = own(prune.apply(this, args));
        own(task.then(() => {
          events.push("sentinel-settled"); settled.resolve();
        }, () => {
          events.push("sentinel-settled"); settled.resolve();
        }));
        return task;
      } finally { callingPrune = false; }
    });
    const wait = async () => {
      sentinelEntered.resolve();
      await sentinelFinish.promise;
      if (reject) throw new Error("fixture prune read stop");
    };
    const list = vi.mocked(FilesystemStorage.prototype.list).getMockImplementation()!;
    vi.mocked(FilesystemStorage.prototype.list).mockImplementation(async function (this: FilesystemStorage, ...args) {
      // The synchronous caller flag isolates pruning from other finding-store scans.
      if (boundary === "list" && callingPrune && args[0] === SENTINEL_FINDING_NAMESPACE) await wait();
      return list.apply(this, args);
    });
    const remove = FilesystemStorage.prototype.delete;
    vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function (this: FilesystemStorage, ...args) {
      if (boundary === "delete" && args[0] === SENTINEL_FINDING_NAMESPACE && args[1] === EXPIRED_KEY) await wait();
      const value = await remove.apply(this, args);
      if (args[0] === SENTINEL_FINDING_NAMESPACE && args[1] === EXPIRED_KEY) events.push("sentinel-deleted");
      return value;
    });
    const assertOwned = async () => {
      await Promise.race([draining.promise, released.promise]);
      expect(task).toBeDefined();
      expect(drainOwner).toBeDefined();
      expect(registrations.filter((entry) => entry.owner === drainOwner && entry.task === task),
        "the drained owner must contain the exact prune promise").toHaveLength(1);
      expect(pruneSpy).toHaveBeenCalledOnce();
    };
    return { entered: sentinelEntered.promise, settled: settled.promise, assertOwned, store: () => store! };
  };
  const assertHeld = async () => {
    await Promise.race([draining.promise, released.promise]);
    expect(release, "release called while construction work is held").not.toHaveBeenCalled();
    expect(sessions[0]!.masterKey.some((byte) => byte !== 0)).toBe(true);
    await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
  };
  beforeEach(async () => {
    env = { ...process.env };
    fortress = await createTempFortress("embedded-construction");
    server = undefined; channels = []; sessions = []; pending = []; events = [];
    registrations = []; nonzeroAtRelease = []; drainOwner = undefined; sentinelFinish = deferred();
    finish = deferred(); entered = deferred(); released = deferred(); draining = deferred();
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    await mkdir(fortress.storagePath, { recursive: true });
    await writeFile(join(fortress.storagePath, "sanctuary.json"), "{}");
    await writeFile(join(fortress.storagePath, "principal-policy.yaml"),
      generateDefaultPolicyYaml().replace("type: stderr", "type: dashboard"));
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: fortress.storagePath });
    const seedStore = (now: Date) => new SentinelFindingStore({ storage: storage(), masterKey: seed.masterKey,
      fortressId: fortressIdFromStoragePath(fortress.storagePath), now: () => now });
    await seedStore(EXPIRED_AT).saveFinding(finding(EXPIRED_ID));
    await seedStore(new Date()).saveFinding(finding(RETAINED_ID));
    await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
    const establish = custody.establishMaster;
    vi.spyOn(custody, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options);
      sessions.push(session);
      const original = session.masterWriteBarrier!.release.bind(session.masterWriteBarrier);
      release = vi.spyOn(session.masterWriteBarrier!, "release").mockImplementation(async () => {
        nonzeroAtRelease.push(session.masterKey.some((byte) => byte !== 0));
        events.push("released"); released.resolve(); await original();
      });
      return session;
    });
    const list = FilesystemStorage.prototype.list;
    vi.spyOn(FilesystemStorage.prototype, "list").mockImplementation(async function (this: FilesystemStorage, ...args) {
      if (args[0] === "_chat") { entered.resolve(); await finish.promise; }
      const value = await list.apply(this, args);
      if (args[0] === "_chat") events.push("prune-list-settled");
      return value;
    });
    const drain = ConstructionWork.prototype.drain;
    vi.spyOn(ConstructionWork.prototype, "drain").mockImplementation(function (this: ConstructionWork) {
      drainOwner = this;
      draining.resolve(); return drain.call(this);
    });
    const track = ConstructionWork.prototype.track;
    vi.spyOn(ConstructionWork.prototype, "track").mockImplementation(function (this: ConstructionWork, task) {
      registrations.push({ owner: this, task }); return track.call(this, task);
    });
    const start = DashboardApprovalChannel.prototype.start;
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(function (this: DashboardApprovalChannel, options) {
      (this as unknown as { config: { port: number } }).config.port = EPHEMERAL_PORT;
      return start.call(this, options);
    });
    const attach = DashboardApprovalChannel.prototype.setV11Bindings;
    vi.spyOn(DashboardApprovalChannel.prototype, "setV11Bindings").mockImplementation(function (this: DashboardApprovalChannel, bindings) {
      channels.push(this); return attach.call(this, bindings);
    });
  });
  afterEach(async () => {
    finish.resolve();
    sentinelFinish.resolve();
    await Promise.allSettled(pending);
    await server?.cleanup().catch(() => undefined);
    for (const channel of channels) await channel.stop().catch(() => undefined);
    for (const session of sessions) { await session.masterWriteBarrier?.release(); session.masterKey.fill(0); }
    vi.restoreAllMocks();
    await fortress.cleanup();
    process.env = env;
  });

  it("dashboard cleanup settles construction before releasing custody", async () => {
    const result = await boot();
    await entered.promise;
    const stopped = own(result.cleanup());
    await assertHeld();
    finish.resolve(); await stopped;
    expect(release).toHaveBeenCalledOnce();
    expect(events).toContain("prune-list-settled"); expect(events).toContain("released");
    expect(events.indexOf("prune-list-settled")).toBeLessThan(events.indexOf("released"));
    await expect(exclusive()).resolves.toBe("entered");
  });

  it("failed dashboard startup settles construction before releasing and scrubbing custody", async () => {
    const failure = new Error("fixture attachment stop");
    vi.mocked(DashboardApprovalChannel.prototype.setV11Bindings).mockImplementation(function (this: DashboardApprovalChannel) {
      channels.push(this); throw failure;
    });
    const result = boot();
    await entered.promise;
    await assertHeld();
    finish.resolve();
    await expect(result).rejects.toBe(failure);
    expect(release).toHaveBeenCalledOnce();
    expect(sessions[0]!.masterKey.every((byte) => byte === 0)).toBe(true);
    expect(events).toContain("prune-list-settled"); expect(events).toContain("released");
    expect(events.indexOf("prune-list-settled")).toBeLessThan(events.indexOf("released"));
    await expect(exclusive()).resolves.toBe("entered");
  });

  it("settled dashboard construction preserves ordinary cleanup", async () => {
    finish.resolve();
    const result = await boot();
    await entered.promise;
    await result.cleanup();
    expect(release).toHaveBeenCalledOnce();
    await expect(exclusive()).resolves.toBe("entered");
  });

  it("a non-dashboard channel keeps ordinary cleanup", async () => {
    await writeFile(join(fortress.storagePath, "principal-policy.yaml"), generateDefaultPolicyYaml());
    const result = await boot();
    expect(channels).toHaveLength(0);
    await result.cleanup();
    expect(release).toHaveBeenCalledOnce();
    expect(events).not.toContain("prune-list-settled");
    await expect(exclusive()).resolves.toBe("entered");
  });

  it.each(["list", "delete"] as const)("sentinel %s settlement precedes cleanup persistence and release", async (boundary) => {
    const gate = holdSentinel(boundary);
    const result = await boot();
    await gate.entered;
    const retainedBytes = await storage().read(SENTINEL_FINDING_NAMESPACE, RETAINED_KEY);
    expect(await gate.store().listFindingMetadata()).toEqual(expect.arrayContaining([
      expect.objectContaining({ finding_id: RETAINED_ID }),
    ]));
    const flush = result.auditLog.flush.bind(result.auditLog);
    vi.spyOn(result.auditLog, "flush").mockImplementation(async () => {
      events.push("final-persistence"); return flush();
    });
    const master = result.masterKey.slice();
    let completed = false;
    const stopped = own(result.cleanup().then(() => { completed = true; }));
    await gate.assertOwned();
    await assertHeld();
    expect(completed).toBe(false);
    expect(events).not.toContain("final-persistence");
    sentinelFinish.resolve();
    await stopped;
    expect(release).toHaveBeenCalledOnce();
    expect(nonzeroAtRelease).toEqual([true]);
    expect(result.masterKey).toEqual(master);
    expect(events.indexOf("sentinel-deleted")).toBeLessThan(events.indexOf("sentinel-settled"));
    expect(events.indexOf("sentinel-settled")).toBeLessThan(events.indexOf("final-persistence"));
    expect(events.indexOf("final-persistence")).toBeLessThan(events.indexOf("released"));
    expect(await gate.store().loadFinding(EXPIRED_ID)).toBeNull();
    expect(await gate.store().loadFinding(RETAINED_ID)).toEqual(finding(RETAINED_ID));
    expect(await storage().read(SENTINEL_FINDING_NAMESPACE, RETAINED_KEY)).toEqual(retainedBytes);
    await expect(exclusive()).resolves.toBe("entered");
  });

  it.each(["bindings", "baseline"] as const)("sentinel settlement precedes failed startup release and scrub at %s", async (boundary) => {
    const gate = holdSentinel("list");
    const failure = new Error("fixture startup stop");
    if (boundary === "bindings") {
      vi.mocked(DashboardApprovalChannel.prototype.setV11Bindings).mockImplementation(function (this: DashboardApprovalChannel) {
        channels.push(this); throw failure;
      });
    } else {
      vi.spyOn(BaselineTracker.prototype, "load").mockRejectedValue(failure);
    }
    let completed = false;
    const result = own(boot().finally(() => { completed = true; }));
    await gate.entered;
    await gate.assertOwned();
    await assertHeld();
    expect(completed).toBe(false);
    if (boundary === "baseline") expect(channels).toHaveLength(0);
    sentinelFinish.resolve();
    await expect(result).rejects.toBe(failure);
    expect(release).toHaveBeenCalledOnce();
    expect(nonzeroAtRelease).toEqual([true]);
    expect(sessions[0]!.masterKey.every((byte) => byte === 0)).toBe(true);
    expect(events).toContain("sentinel-deleted");
    expect(events).toContain("sentinel-settled");
    expect(events.indexOf("sentinel-settled")).toBeLessThan(events.indexOf("released"));
    await expect(exclusive()).resolves.toBe("entered");
  });

  it("a rejected sentinel prune preserves cleanup status and output", async () => {
    const gate = holdSentinel("list", true);
    const result = await boot();
    await gate.entered;
    const stdout = vi.spyOn(process.stdout, "write");
    const stderr = vi.spyOn(process.stderr, "write");
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const status = process.exitCode;
    const stopped = own(result.cleanup());
    await gate.assertOwned();
    await assertHeld();
    sentinelFinish.resolve();
    await expect(stopped).resolves.toBeUndefined();
    expect(exit).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(status);
    expect(stdout).not.toHaveBeenCalled();
    expect(stderr).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledOnce();
    expect(events).toContain("sentinel-settled");
    expect(events.indexOf("sentinel-settled")).toBeLessThan(events.indexOf("released"));
  });

  it.each(["stderr", "callback", "webhook"] as const)("sentinel pruning belongs to the %s session", async (channel) => {
    const gate = holdSentinel("list");
    await writeFile(join(fortress.storagePath, "principal-policy.yaml"),
      generateDefaultPolicyYaml().replace("type: stderr", `type: ${channel}`));
    if (channel === "webhook") {
      await writeFile(join(fortress.storagePath, "sanctuary.json"), JSON.stringify({ webhook: {
        url: "http://127.0.0.1/unused", secret: "fixture-webhook-secret",
        callback_host: "127.0.0.1", callback_port: EPHEMERAL_PORT,
      } }));
    }
    const result = await boot({ approvalCallback: async () => ({
      decision: "deny", decided_at: new Date().toISOString(), decided_by: "auto",
    }) });
    await gate.entered;
    expect(channels).toHaveLength(0);
    const stopped = own(result.cleanup());
    await gate.assertOwned();
    await assertHeld();
    sentinelFinish.resolve();
    await stopped;
    expect(release).toHaveBeenCalledOnce();
    expect(events).toContain("sentinel-settled");
    expect(events.indexOf("sentinel-settled")).toBeLessThan(events.indexOf("released"));
    await expect(exclusive()).resolves.toBe("entered");
  });

  it("an empty sentinel prune settles before ordinary cleanup", async () => {
    await storage().delete(SENTINEL_FINDING_NAMESPACE, EXPIRED_KEY);
    await storage().delete(SENTINEL_FINDING_NAMESPACE, RETAINED_KEY);
    const gate = holdSentinel("list");
    sentinelFinish.resolve();
    const result = await boot();
    await gate.settled;
    await result.cleanup();
    await gate.assertOwned();
    expect(release).toHaveBeenCalledOnce();
    expect(events).not.toContain("sentinel-deleted");
    await expect(exclusive()).resolves.toBe("entered");
  });
  it("a pushed fleet tick settles before embedded cleanup releases custody", async () => {
    finish.resolve();
    const result = await boot();
    const channel = channels[0]!;
    type FleetOwner = { flights: Map<string, Promise<void>>; drain(): Promise<void> };
    const state = channel as unknown as {
      _federationWork?: FleetOwner;
      runFleetLicenseReResolveTick(): Promise<void>;
      runFleetLicenseReResolveTickOnce(): Promise<void>;
      resolveFleetIssuerPublicKey(): Uint8Array;
      applyPushedRevocationList(signed: unknown): Promise<{ ok: boolean }>;
    };
    const issuer = generateKeypair();
    vi.spyOn(state, "resolveFleetIssuerPublicKey").mockReturnValue(issuer.publicKey);
    const tickEntered = deferred(); const tickDraining = deferred();
    const tickFinish = deferred();
    let captured: Promise<void> | undefined;
    let drained: Map<string, Promise<void>> | undefined;
    const run = state.runFleetLicenseReResolveTickOnce.bind(state);
    const tick = vi.spyOn(state, "runFleetLicenseReResolveTickOnce").mockImplementation(async () => {
      tickEntered.resolve(); await tickFinish.promise;
      await run(); events.push("fleet-settled");
    });
    if (state._federationWork) {
      const owner = state._federationWork;
      const drain = owner.drain.bind(owner);
      vi.spyOn(owner, "drain").mockImplementation(() => {
        drained = new Map(owner.flights); tickDraining.resolve(); return drain();
      });
    }
    try {
      const signed = signRevocationList({ version: 1, revokedLicenseIds: [],
        issuer: "session-issuer", issuedAt: new Date().toISOString() },
      (bytes) => ed25519.sign(bytes, issuer.privateKey));
      expect(await state.applyPushedRevocationList(signed)).toMatchObject({ ok: true });
      await tickEntered.promise;
      captured = state._federationWork?.flights.get("fleet");
      const joined = own(state.runFleetLicenseReResolveTick());
      expect(tick).toHaveBeenCalledOnce();
      const stopped = own(result.cleanup());
      const winner = await Promise.race([
        tickDraining.promise.then(() => "drain entered"),
        released.promise.then(() => "release while flight held"),
        stopped.then(() => "completion while flight held"),
      ]);
      expect(drained, `fleet drain race winner: ${winner}`).toBeDefined();
      expect(captured).toBeDefined(); expect(drained!.get("fleet")).toBe(captured);
      expect(release).not.toHaveBeenCalled();
      await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
      tickFinish.resolve(); await joined; await stopped;
      expect(events).toContain("fleet-settled"); expect(events).toContain("released");
      expect(events.indexOf("fleet-settled")).toBeLessThan(events.indexOf("released"));
      expect(nonzeroAtRelease).toEqual([true]);
    } finally { tickFinish.resolve(); issuer.privateKey.fill(0); }
  });

});
