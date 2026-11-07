import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { join } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { startStandaloneDashboard, handleStandaloneShutdownSignal, __resetStandaloneShutdownStateForTest } from "../../src/dashboard-standalone.js";
import { ConstructionWork } from "../../src/dashboard/construction-work.js";
import { buildV11Bindings, fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ConciergeMemoryStore } from "../../src/chat/concierge-memory-store.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { DistressListener } from "../../src/distress/listener.js";
import * as custody from "../../src/core/master-custody.js";
import { generateKeypair } from "../../src/core/identity.js";
import { AgentContextCache } from "../../src/chat/agent-context-cache.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { loadFortressDidWebRecord, issueDidWeb, rotateDidWebKey, publishDidWebDocument } from "../../src/recognition/did-web.js";
import { loadFortressProducerKey } from "../../src/castle-wall/runtime/producer-signature.js";
import { withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import { createTempFortress, TEST_PASSPHRASE, type TempFortress } from "../helpers/temp-fortress.js";

vi.mock("../../src/recognition/did-web.js", async (original) => {
  const real = await original<typeof import("../../src/recognition/did-web.js")>();
  return { ...real, loadFortressDidWebRecord: vi.fn(real.loadFortressDidWebRecord) };
});
vi.mock("../../src/castle-wall/runtime/producer-signature.js", async (original) => {
  const real = await original<typeof import("../../src/castle-wall/runtime/producer-signature.js")>();
  return { ...real, loadFortressProducerKey: vi.fn(real.loadFortressProducerKey) };
});

const EPHEMERAL_PORT = 0;
const CACHE_REFRESH_LIMIT = 500; // Must match the construction refresh query shape.
const SIGNAL_STATUS_BASE = 128;
const SIGTERM_NUMBER = 15;
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("construction work session ordering", () => {
  let fortress: TempFortress;
  let env: NodeJS.ProcessEnv;
  let channels: DashboardApprovalChannel[];
  let listeners: DistressListener[];
  let sessions: custody.EstablishMasterResult[];
  let releases: ReturnType<typeof vi.spyOn>[];
  let gates: ReturnType<typeof deferred>[];
  let pending: Promise<unknown>[];
  let events: string[];
  let draining: ReturnType<typeof deferred>;
  let released: ReturnType<typeof deferred>;
  let closed: ReturnType<typeof deferred>;
  let occupying: Server | undefined;
  const originalDid = vi.mocked(loadFortressDidWebRecord).getMockImplementation()!;
  const originalProducer = vi.mocked(loadFortressProducerKey).getMockImplementation()!;
  const storage = () => new FilesystemStorage(join(fortress.storagePath, "state"));
  const exclusive = () => withExclusiveMasterRotationBarrier(storage(), custody.CUSTODY_WRITE_LOCK_NAMESPACE,
    custody.MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 });
  const boot = (options: Parameters<typeof startStandaloneDashboard>[0] = {}) => startStandaloneDashboard({
    passphrase: TEST_PASSPHRASE, host: "127.0.0.1", port: EPHEMERAL_PORT, distressPort: EPHEMERAL_PORT,
    configPath: join(fortress.home, "config.json"),
    discoveryOptions: { home: fortress.home, root: fortress.storagePath, env: {} }, ...options,
  });
  const own = <T>(promise: Promise<T>): Promise<T> => {
    pending.push(promise.catch(() => undefined));
    return promise;
  };
  function hold(kind: "concierge" | "cache" | "attribution" | "did" | "sentinel" | "concierge-write" | "concierge-delete", reject = false) {
    const entered = deferred();
    const finish = deferred();
    const completed = deferred();
    gates.push(finish);
    const run = async <T>(action: () => Promise<T>): Promise<T> => {
      entered.resolve();
      await finish.promise;
      try {
        if (reject) throw undefined;
        return await action();
      } finally {
        events.push("task-boundary-settled");
        completed.resolve();
      }
    };
    if (kind === "concierge-write" || kind === "concierge-delete") {
      const prototype = FilesystemStorage.prototype as unknown as {
        atomicWriteFile(path: string, data: Uint8Array, sync: boolean): Promise<void>;
        deleteAtPath(path: string, overwrite: boolean): Promise<boolean>;
      };
      const chatPath = storage().namespacePath("_chat");
      if (kind === "concierge-write") {
        const write = prototype.atomicWriteFile;
        vi.spyOn(prototype, "atomicWriteFile").mockImplementation(function (this: typeof prototype, ...args) {
          return args[0].startsWith(chatPath + "/") ? run(() => write.apply(this, args)) : write.apply(this, args);
        });
      } else {
        const remove = prototype.deleteAtPath;
        vi.spyOn(prototype, "deleteAtPath").mockImplementation(function (this: typeof prototype, ...args) {
          return args[0].startsWith(chatPath + "/") ? run(() => remove.apply(this, args)) : remove.apply(this, args);
        });
      }
    } else if (kind === "concierge" || kind === "sentinel") {
      const list = FilesystemStorage.prototype.list;
      const namespace = kind === "concierge" ? "_chat" : "_sentinel_findings";
      vi.spyOn(FilesystemStorage.prototype, "list").mockImplementation(function (this: FilesystemStorage, ...args) {
        return args[0] === namespace ? run(() => list.apply(this, args)) : list.apply(this, args);
      });
    } else if (kind === "cache") {
      const query = AuditLog.prototype.query;
      vi.spyOn(AuditLog.prototype, "query").mockImplementation(function (this: AuditLog, ...args) {
        return args[0]?.since && args[0]?.limit === CACHE_REFRESH_LIMIT
          ? run(() => query.apply(this, args)) : query.apply(this, args);
      });
    } else if (kind === "did") {
      vi.mocked(loadFortressDidWebRecord).mockImplementation((...args) => run(() => originalDid(...args)));
    } else {
      vi.mocked(loadFortressProducerKey).mockImplementation((...args) => run(() => originalProducer(...args)));
    }
    return { entered, finish, completed };
  }
  const assertHeld = async () => {
    // The old consumer positively reaches release while the boundary is still held.
    await Promise.race([draining.promise, released.promise]);
    expect(releases[0], "release called while construction work is held").not.toHaveBeenCalled();
    expect(sessions[0]!.masterKey.some((byte) => byte !== 0)).toBe(true);
    await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
  };
  const assertFinished = async () => {
    expect(releases[0]).toHaveBeenCalledOnce();
    expect(sessions[0]!.masterKey.every((byte) => byte === 0)).toBe(true);
    await expect(exclusive()).resolves.toBe("entered");
    expect(events).toContain("task-boundary-settled");
    expect(events).toContain("released");
    expect(events.indexOf("task-boundary-settled")).toBeLessThan(events.indexOf("released"));
  };

  beforeEach(async () => {
    vi.mocked(loadFortressDidWebRecord).mockClear();
    vi.mocked(loadFortressProducerKey).mockClear();
    env = { ...process.env };
    fortress = await createTempFortress("construction-session");
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "construction-session-token";
    await writeFile(join(fortress.home, "config.json"), "{}");
    channels = []; listeners = []; sessions = []; releases = []; gates = []; pending = []; events = [];
    draining = deferred(); released = deferred(); closed = deferred();
    __resetStandaloneShutdownStateForTest();
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: fortress.storagePath });
    await seed.masterWriteBarrier?.release();
    seed.masterKey.fill(0);
    const prune = ConciergeMemoryStore.prototype.pruneExpired;
    vi.spyOn(ConciergeMemoryStore.prototype, "pruneExpired").mockImplementation(function (this: ConciergeMemoryStore, ...args) {
      return own(prune.apply(this, args));
    });
    const refresh = AgentContextCache.prototype.refresh;
    vi.spyOn(AgentContextCache.prototype, "refresh").mockImplementation(function (this: AgentContextCache) {
      return own(refresh.call(this));
    });
    const sentinelPrune = SentinelFindingStore.prototype.pruneExpired;
    vi.spyOn(SentinelFindingStore.prototype, "pruneExpired").mockImplementation(function (this: SentinelFindingStore, ...args) {
      return own(sentinelPrune.apply(this, args));
    });
    const establish = custody.establishMaster;
    vi.spyOn(custody, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options);
      sessions.push(session);
      const lease = session.masterWriteBarrier!;
      const release = lease.release.bind(lease);
      releases.push(vi.spyOn(lease, "release").mockImplementation(async () => {
        events.push("released"); released.resolve(); await release();
      }));
      return session;
    });
    const drain = ConstructionWork.prototype.drain;
    vi.spyOn(ConstructionWork.prototype, "drain").mockImplementation(function (this: ConstructionWork) {
      draining.resolve(); return drain.call(this);
    });
    const mark = DashboardApprovalChannel.prototype.setStandaloneMode;
    vi.spyOn(DashboardApprovalChannel.prototype, "setStandaloneMode").mockImplementation(function (this: DashboardApprovalChannel, value) {
      channels.push(this); return mark.call(this, value);
    });
    const stop = DashboardApprovalChannel.prototype.stop;
    vi.spyOn(DashboardApprovalChannel.prototype, "stop").mockImplementation(async function (this: DashboardApprovalChannel) {
      await stop.call(this); closed.resolve();
    });
    const listen = DistressListener.prototype.start;
    vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener) {
      listeners.push(this); return listen.call(this);
    });
  });
  afterEach(async () => {
    for (const gate of gates) gate.resolve();
    await Promise.allSettled(pending);
    for (const channel of channels) await channel.stop().catch(() => undefined);
    for (const listener of listeners) await listener.stop().catch(() => undefined);
    for (const session of sessions) { await session.masterWriteBarrier?.release(); session.masterKey.fill(0); }
    if (occupying) await new Promise<void>((resolve, reject) => occupying!.close((error) => error ? reject(error) : resolve()));
    occupying = undefined;
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.mocked(loadFortressDidWebRecord).mockImplementation(originalDid);
    vi.mocked(loadFortressProducerKey).mockImplementation(originalProducer);
    __resetStandaloneShutdownStateForTest();
    await fortress.cleanup();
    process.env = env;
  });

  it.each(["concierge", "cache", "attribution", "did"] as const)("stop settles held %s construction before release", async (kind) => {
    const gate = hold(kind);
    const dashboard = await own(boot());
    await gate.entered.promise;
    const stopped = own(dashboard.stop());
    await closed.promise;
    await assertHeld();
    gate.finish.resolve();
    await stopped;
    await assertFinished();
  });

  it.each(["concierge", "cache", "attribution", "did"] as const)("a rejected %s task preserves successful stop", async (kind) => {
    const gate = hold(kind, true);
    const output = vi.spyOn(console, "error").mockImplementation(() => {});
    const dashboard = await own(boot());
    await gate.entered.promise;
    const stopped = own(dashboard.stop());
    await assertHeld();
    gate.finish.resolve();
    await expect(stopped).resolves.toBeUndefined();
    expect(output.mock.calls.flat()).not.toContain("Sanctuary Dashboard: cleanup failed.");
    await assertFinished();
  });

  it("a task with no settlement keeps custody after the listener closes", async () => {
    const gate = hold("concierge");
    const dashboard = await own(boot());
    await gate.entered.promise;
    let settled = false;
    const stopped = own(dashboard.stop().then(() => { settled = true; }));
    await closed.promise;
    await assertHeld();
    // Releasable stand-in for permanently hung I/O: no production timeout can prove settlement.
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(settled).toBe(false);
    expect((dashboard as unknown as { httpServer: unknown }).httpServer).toBeNull();
    gate.finish.resolve();
    await stopped;
  });

  it("signal shutdown waits for construction settlement before its existing exit status", async () => {
    const gate = hold("concierge", true);
    await own(boot());
    await gate.entered.promise;
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const signal = own(handleStandaloneShutdownSignal("SIGTERM"));
    await closed.promise;
    await assertHeld();
    expect(exit).not.toHaveBeenCalled();
    gate.finish.resolve();
    await signal;
    expect(exit).toHaveBeenCalledWith(SIGNAL_STATUS_BASE + SIGTERM_NUMBER);
    await assertFinished();
  });

  it("credentialed stand-down settles a rejected prune and returns successfully", async () => {
    occupying = createServer();
    await new Promise<void>((resolve) => occupying!.listen(0, "127.0.0.1", resolve)); // OS-assigned ephemeral port.
    const port = (occupying.address() as import("node:net").AddressInfo).port;
    const gate = hold("concierge", true);
    const result = own(boot({ allowPark: true, port }));
    await gate.entered.promise;
    await assertHeld();
    gate.finish.resolve();
    const dashboard = await result;
    expect(dashboard.addrInUse()).toBe(true);
    await assertFinished();
  });

  it("parked stand-down returns successfully without construction work", async () => {
    occupying = createServer();
    await new Promise<void>((resolve) => occupying!.listen(0, "127.0.0.1", resolve)); // OS-assigned ephemeral port.
    const dashboard = await own(boot({ allowPark: true, passphrase: undefined,
      port: (occupying.address() as import("node:net").AddressInfo).port }));
    expect(dashboard.addrInUse()).toBe(true);
    expect(sessions).toHaveLength(0);
    expect(loadFortressDidWebRecord).not.toHaveBeenCalled();
  });

  it("failed unlock drains a rejected prune and admits the next unlock", async () => {
    const gate = hold("concierge", true);
    let fail = true;
    const dashboard = await own(boot({ allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      if (fail) { fail = false; throw new Error("fixture wiring stop"); }
    } }));
    const unlock = (dashboard as unknown as { unlockHandler: (credential: { passphrase: string }) => Promise<boolean> }).unlockHandler;
    const attempt = own(unlock({ passphrase: TEST_PASSPHRASE }));
    await gate.entered.promise;
    await assertHeld();
    gate.finish.resolve();
    await expect(attempt).resolves.toBe(false);
    await expect(unlock({ passphrase: TEST_PASSPHRASE })).resolves.toBe(true);
    expect(sessions).toHaveLength(2);
    await dashboard.stop();
    expect(releases[1]).toHaveBeenCalledOnce();
  });

  it("initial wiring failure settles construction before returning its original error", async () => {
    const gate = hold("concierge");
    const failure = new Error("fixture wiring stop");
    const result = own(boot({ __testFaultAfterLoads: () => { throw failure; } }));
    await gate.entered.promise;
    await assertHeld();
    gate.finish.resolve();
    await expect(result).rejects.toBe(failure);
    await assertFinished();
  });

  it("settled construction keeps normal stop and shared sentinel reuse", async () => {
    const gate = hold("concierge");
    const list = vi.mocked(FilesystemStorage.prototype.list);
    gate.finish.resolve();
    const dashboard = await own(boot());
    await gate.completed.promise;
    await dashboard.stop();
    expect(list.mock.calls.some(([namespace]) => namespace === "_sentinel_findings")).toBe(false);
    await assertFinished();
  });

  it("park without unlock starts no construction tasks", async () => {
    const dashboard = await own(boot({ allowPark: true, passphrase: undefined }));
    await dashboard.stop();
    expect(sessions).toHaveLength(0);
    expect(loadFortressDidWebRecord).not.toHaveBeenCalled();
  });

  it.each([false, true])("fallback sentinel construction settles before its owner completes with rejection=%s", async (reject) => {
    const gate = hold("sentinel", reject);
    const session = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE });
    const owner = new ConstructionWork();
    buildV11Bindings({ constructionWork: owner, identityId: "fixture", fortressId: fortressIdFromStoragePath(fortress.storagePath),
      storagePath: fortress.storagePath, storage: storage(), masterKey: session.masterKey, auditLog: new AuditLog(storage(), session.masterKey) });
    await gate.entered.promise;
    let done = false;
    const stopped = own(owner.drain().then(() => { done = true; }));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(done, "owner completed while sentinel construction is held").toBe(false);
    gate.finish.resolve();
    await stopped;
  });

  it.each(["concierge-write", "concierge-delete"] as const)("stop joins admitted %s and preserves encrypted retained turns", async (kind) => {
    const seed = await custody.establishMaster({ storage: storage(), passphrase: TEST_PASSPHRASE });
    const memory = new ConciergeMemoryStore({ storage: storage(), masterKey: seed.masterKey,
      fortressId: fortressIdFromStoragePath(fortress.storagePath) });
    try {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2020-01-01T00:00:00.000Z"));
      await memory.appendTurn("mixed", "user", "expired");
      await memory.appendTurn("expired", "user", "expired");
      vi.useRealTimers();
      await memory.appendTurn("mixed", "user", "retained");
    } finally {
      vi.useRealTimers();
      await seed.masterWriteBarrier?.release(); seed.masterKey.fill(0);
    }
    sessions = []; releases = []; events = []; released = deferred();
    const gate = hold(kind);
    const dashboard = await own(boot());
    await gate.entered.promise;
    const stopped = own(dashboard.stop());
    await assertHeld();
    gate.finish.resolve(); await stopped;
    expect((await memory.readThread("mixed")).map((turn) => turn.content)).toEqual(["retained"]);
    expect(await memory.readThread("expired")).toEqual([]);
    await assertFinished();
  });

  it("DID construction persists expired-key removal and audit before release", async () => {
    const identifier = await issueDidWeb({ fortress_id: fortressIdFromStoragePath(fortress.storagePath),
      authority_host: "fixture.example.com", public_key: generateKeypair().publicKey });
    const rotation = await rotateDidWebKey(identifier, { reason: "manual", preserve_old_key_for: 1,
      now: () => new Date("2020-01-01T00:00:00.000Z") }); // One day, expired before the fixture boot.
    const rotated = { ...identifier, did_document: rotation.new_did_document };
    const artifact = publishDidWebDocument(rotated);
    const dir = join(fortress.storagePath, "recognition");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "did-web.json"), JSON.stringify({ version: 1, identifier: rotated, artifact }));
    const gate = hold("did");
    const append = vi.spyOn(AuditLog.prototype, "append");
    const dashboard = await own(boot());
    await gate.entered.promise;
    const stopped = own(dashboard.stop());
    try {
      await assertHeld();
    } finally {
      gate.finish.resolve();
      // Also join the real parent on the old consumer before fixture removal.
      await vi.waitFor(() => expect(append.mock.calls.some((args) => args[1] === "did_web_old_key_dropped")).toBe(true));
      await Promise.allSettled(append.mock.results.map((result) => result.value));
      await stopped;
    }
    const record = await originalDid(fortress.storagePath);
    expect(record!.identifier.did_document.verificationMethod).toHaveLength(1);
    expect(JSON.parse(await readFile(join(dir, "did.json"), "utf8")).verificationMethod).toHaveLength(1);
    await assertFinished();
  });

  it("hosted stop settles construction before unregistering cleanup", async () => {
    const gate = hold("concierge", true);
    let cleanup!: () => Promise<void>;
    const unregister = vi.fn();
    await own(boot({ processLifecycle: { registerCleanup: (action) => { cleanup = action; return unregister; } } }));
    await gate.entered.promise;
    const stopped = own(cleanup());
    await assertHeld();
    expect(unregister).not.toHaveBeenCalled();
    gate.finish.resolve(); await stopped;
    expect(unregister).toHaveBeenCalledOnce();
    await assertFinished();
  });

  it("HTTP unlock refusal waits for construction settlement and then permits retry", async () => {
    const gate = hold("concierge", true);
    let fail = true;
    const dashboard = await own(boot({ allowPark: true, passphrase: undefined, __testFaultAfterLoads: () => {
      if (fail) { fail = false; throw new Error("fixture wiring stop"); }
    } }));
    const port = ((dashboard as unknown as { httpServer: Server }).httpServer.address() as import("node:net").AddressInfo).port;
    const unlock = async () => {
      const response = await fetch(`http://127.0.0.1:${port}/api/unlock`, { method: "POST",
        headers: { Authorization: "Bearer construction-session-token", "Content-Type": "application/json" },
        body: JSON.stringify({ passphrase: TEST_PASSPHRASE }) });
      await response.text(); return response.status;
    };
    let responded = false;
    const request = own(unlock().then((status) => { responded = true; return status; }));
    await gate.entered.promise;
    await assertHeld();
    expect(responded).toBe(false);
    gate.finish.resolve();
    const UNAUTHORIZED = 401;
    const OK = 200;
    await expect(request).resolves.toBe(UNAUTHORIZED);
    await expect(own(unlock())).resolves.toBe(OK);
    await dashboard.stop();
  });

  it("a task rejected before stop preserves readiness and successful cleanup", async () => {
    const gate = hold("concierge", true);
    gate.finish.resolve();
    const output = vi.spyOn(console, "error").mockImplementation(() => {});
    const dashboard = await own(boot());
    await gate.completed.promise;
    await expect(dashboard.stop()).resolves.toBeUndefined();
    expect(output.mock.calls.flat()).not.toContain("Sanctuary Dashboard: cleanup failed.");
    await assertFinished();
  });

  it("cache integrity reporting finishes while its construction session remains owned", async () => {
    const gate = hold("cache");
    const dashboard = await own(boot());
    await gate.entered.promise;
    await storage().write("_audit", "fixture-unreadable", new Uint8Array([0])); // Invalid fixture envelope.
    const stopped = own(dashboard.stop());
    await assertHeld();
    gate.finish.resolve(); await stopped;
    const alert = await storage().read("_audit_integrity_alert", "audit-integrity-alert.log");
    expect(alert).not.toBeNull();
    await assertFinished();
  });

  it("construction ownership retains undefined rejection and has an idempotent drain", async () => {
    const owner = new ConstructionWork();
    const gate = deferred();
    gates.push(gate);
    owner.track(Promise.reject(undefined));
    owner.track(gate.promise);
    const first = owner.drain();
    expect(owner.drain()).toBe(first);
    gate.resolve();
    await expect(first).resolves.toBeUndefined();
    expect(() => owner.track(Promise.resolve())).toThrow("registration is sealed");
  });
});
