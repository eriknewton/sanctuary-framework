import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { access, cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import type { EstablishMasterResult } from "../../src/core/master-custody.js";
import type { BaselineTracker } from "../../src/principal-policy/baseline.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { DistressListener } from "../../src/distress/listener.js";

const os = vi.hoisted(() => ({
  pin: vi.fn(), daemon: vi.fn(), provision: vi.fn(), intelligence: vi.fn(),
}));
vi.mock("../../src/cli/castle-wall.js", async (original) => ({
  ...await original<typeof import("../../src/cli/castle-wall.js")>(),
  runProvisionPin: os.pin,
}));
vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: os.daemon,
  isLinuxProducerSignedActivationRequested: () => false,
}));
vi.mock("../../src/wrap/auto-provision.js", async (original) => ({
  ...await original<typeof import("../../src/wrap/auto-provision.js")>(),
  runAutoProvisionForWrap: os.provision,
}));
vi.mock("../../src/wrap/local-intelligence.js", async (original) => ({
  ...await original<typeof import("../../src/wrap/local-intelligence.js")>(),
  runLocalIntelligenceSetup: os.intelligence,
}));

const EPHEMERAL_PORT = 0;
const SIGINT_STATUS = 128 + 2; // Shell convention plus SIGINT.
const SIGTERM_STATUS = 128 + 15; // Shell convention plus SIGTERM.
const ERROR_STATUS = 1;
const REFUSAL_STATUS = 2;
const HTTP_OK = 200;
const CUSTODY_FAILURE_DIAGNOSTIC = "Fortress custody could not be released cleanly; any work the command already reported as complete was committed.";
const START_FAILURE_DIAGNOSTIC = "Sanctuary MCP Server failed to start:";
const checkpoint = () => new Promise<void>((resolve) => setImmediate(resolve));
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

// Lifecycle work is real except the explicit nonsettling-stop diagnostic witness;
// persistence and listener spies below call through to real work.
describe("protect owns its dashboard lifecycle", () => {
  let root: string;
  let fortress: string;
  let env: NodeJS.ProcessEnv;
  let argv: string[];
  let exitCode: typeof process.exitCode;
  let tty: boolean;
  let wrap: typeof import("../../src/wrap/cli.js");
  let standalone: typeof import("../../src/dashboard-standalone.js");
  let custody: typeof import("../../src/core/master-custody.js");
  let audit: typeof import("../../src/operational/audit-log.js");
  let baseline: typeof import("../../src/principal-policy/baseline.js");
  let channels: DashboardApprovalChannel[];
  let sessions: EstablishMasterResult[];
  let distress: DistressListener[];
  let gates: ReturnType<typeof deferred>[];
  let tasks: Promise<unknown>[];
  let bootTasks: Promise<unknown>[];
  let events: string[];
  let output: string[];
  let exits: number[];
  let exited: ReturnType<typeof deferred>;
  let terminal: Error;
  let interruptedBoot: boolean;
  let wrapAudit: AuditLog;
  let daemonStop: ReturnType<typeof vi.fn>;
  let originalListeners: Map<string, Set<(...args: never[]) => unknown>>;

  function gate() {
    const value = deferred();
    gates.push(value);
    return value;
  }
  async function reached(promise: Promise<unknown>) {
    await Promise.race([promise, exited.promise.then(() => {
      throw new Error(`exit before checkpoint: ${exits.join(",")}; ${output.join("\n")}`);
    })]);
  }
  function observe(promise: Promise<unknown>) {
    const observed = promise.catch((error: unknown) => {
      if (error !== terminal) throw error;
    });
    tasks.push(observed);
    return observed;
  }
  function signal(name: "SIGINT" | "SIGTERM") {
    // Invoke every registered application listener, preserving Node's order.
    for (const listener of process.listeners(name)) {
      if (!originalListeners.get(name)!.has(listener as never)) {
        observe(Promise.resolve(listener(name)));
      }
    }
  }
  function text() { return output.join("\n"); }
  function dashboard() { return channels[0]!; }
  function session() { return sessions.at(-1)!; }
  function url() {
    const server = (dashboard() as unknown as { httpServer: import("node:net").Server }).httpServer;
    return `http://127.0.0.1:${(server.address() as import("node:net").AddressInfo).port}`;
  }
  async function alive() {
    expect((await fetch(url())).status).toBe(HTTP_OK);
    expect(exits).toEqual([]);
    expect(session().masterWriteBarrier!.signal.aborted).toBe(false);
  }
  async function launch(extra: string[] = []) {
    process.argv = [process.execPath, "sanctuary", "--fortress", fortress, "protect",
      "--hermes", "--no-open", "--no-provision-agent-account", "--passphrase", "lifecycle-test-passphrase", ...extra];
    const entry = await import("../../src/cli.js");
    if (interruptedBoot) return entry.cliEntryInvocation.catch((error: unknown) => { if (error !== terminal) throw error; });
    return observe(entry.cliEntryInvocation);
  }
  function holdRelease() {
    const entered = gate();
    const finish = gate();
    const lease = session().masterWriteBarrier!;
    const release = lease.release.bind(lease);
    const spy = vi.spyOn(lease, "release").mockImplementation(async () => {
      entered.resolve();
      await finish.promise;
      await release();
      events.push("release");
    });
    return { entered, finish, spy };
  }
  async function released() {
    expect(session().masterWriteBarrier!.signal.aborted).toBe(true);
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const { withExclusiveMasterRotationBarrier } = await import("../../src/storage/cross-process-lock.js");
    await expect(withExclusiveMasterRotationBarrier(new FilesystemStorage(join(fortress, "state")),
      custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
      async () => "released", { timeoutMs: 0 })).resolves.toBe("released"); // Zero means no contention wait.
  }

  beforeEach(async () => {
    vi.resetModules();
    const { installInMemoryKeychainStore } = await import("../setup/keychain-memory-store.js");
    installInMemoryKeychainStore();
    vi.clearAllMocks();
    interruptedBoot = false;
    env = { ...process.env };
    argv = process.argv;
    exitCode = process.exitCode;
    tty = process.stdin.isTTY;
    process.exitCode = undefined;
    root = await mkdtemp(join(tmpdir(), "protect-lifecycle-"));
    fortress = join(root, "fortress");
    process.env.HOME = root;
    process.env.SANCTUARY_STORAGE_PATH = fortress;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "lifecycle-test-token";
    delete process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_PASSPHRASE;
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: false });
    channels = []; sessions = []; distress = []; gates = []; tasks = []; bootTasks = []; events = []; output = []; exits = [];
    exited = deferred();
    terminal = new Error("test observed process exit"); // Construct after resetModules, like all class-bearing fixtures.
    originalListeners = new Map(["SIGINT", "SIGTERM", "exit", "beforeExit"].map((name) =>
      [name, new Set(process.listeners(name) as ((...args: never[]) => unknown)[])]));
    const capture = (...values: unknown[]) => {
      // A thrown exit sentinel can unwind into main().catch; halt that synthetic
      // catch at its first output, before it can report or issue a second exit.
      if (exits.length) throw terminal;
      const line = values.map(String).join(" ");
      output.push(line);
      events.push(line);
    };
    vi.spyOn(console, "error").mockImplementation(capture);
    vi.spyOn(console, "log").mockImplementation(capture);
    vi.spyOn(console, "info").mockImplementation(capture);
    vi.spyOn(console, "warn").mockImplementation(capture);
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => { capture(chunk); return true; }) as typeof process.stderr.write);
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown, callback?: () => void) => {
      capture(chunk);
      // drainAndExit's callback is terminal too; catch only our exit sentinel.
      try { callback?.(); } catch (error) { if (error !== terminal) throw error; }
      return true;
    }) as typeof process.stdout.write);
    vi.spyOn(process, "exit").mockImplementation(((code: number) => {
      exits.push(code); events.push("exit"); exited.resolve(); throw terminal;
    }) as never);
    wrap = await import("../../src/wrap/cli.js");
    standalone = await import("../../src/dashboard-standalone.js");
    custody = await import("../../src/core/master-custody.js");
    audit = await import("../../src/operational/audit-log.js");
    baseline = await import("../../src/principal-policy/baseline.js");
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const seeded = await custody.establishMaster({ storage: new FilesystemStorage(join(fortress, "state")),
      passphrase: "lifecycle-test-passphrase", firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: fortress });
    await seeded.masterWriteBarrier?.release(); seeded.masterKey.fill(0);
    const establish = custody.establishMaster;
    vi.spyOn(custody, "establishMaster").mockImplementation(async (options) => {
      const result = await establish(options); sessions.push(result); return result;
    });
    const { DashboardApprovalChannel } = await import("../../src/principal-policy/dashboard.js");
    const mark = DashboardApprovalChannel.prototype.setStandaloneMode;
    vi.spyOn(DashboardApprovalChannel.prototype, "setStandaloneMode").mockImplementation(function (this: DashboardApprovalChannel, enabled) {
      channels.push(this); return mark.call(this, enabled);
    });
    // The CLI has no distressPort argument; constrain the OS bind dependency
    // to the same ephemeral setting as distressPort: 0 without replacing boot.
    const { DistressListener } = await import("../../src/distress/listener.js");
    const listen = DistressListener.prototype.start;
    vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener) {
      distress.push(this);
      (this as unknown as { port: number }).port = EPHEMERAL_PORT;
      return listen.call(this);
    });
    const bind = DashboardApprovalChannel.prototype.start;
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(function (this: DashboardApprovalChannel, options) {
      (this as unknown as { config: { port: number; host: string } }).config.port = EPHEMERAL_PORT;
      (this as unknown as { config: { host: string } }).config.host = "127.0.0.1";
      return bind.call(this, options);
    });
    const parity = await import("../helpers/hermes-parity.js");
    parity.installHermesParityHook(parity.agreeingHermesParity);
    await mkdir(join(root, ".hermes"), { recursive: true });
    await cp(new URL("../harness/fixtures/hermes.json", import.meta.url), join(root, ".hermes", "cli-config.json"));
    os.pin.mockResolvedValue(0); // Successful OS provisioning command.
    daemonStop = vi.fn(async () => { events.push("daemon"); });
    os.daemon.mockImplementation(async (options: { auditLog: AuditLog }) => { wrapAudit = options.auditLog; return { stop: daemonStop }; });
    os.intelligence.mockResolvedValue({ kind: "not-requested" });
    os.provision.mockResolvedValue({ ran: false });
  });

  afterEach(async () => {
    // Release every latch even when a red witness failed before reaching it.
    for (const value of gates) value.resolve();
    await Promise.allSettled(bootTasks);
    await checkpoint();
    for (const channel of channels) await channel.stop().catch(() => undefined);
    for (const listener of distress) await listener.stop().catch(() => undefined);
    for (const acquired of sessions) {
      await acquired.masterWriteBarrier?.release().catch(() => undefined);
      acquired.masterKey.fill(0);
    }
    // Interrupted startup and the nonsettling-stop witness own no handles through their pending promises.
    await Promise.all(tasks);
    await checkpoint();
    wrap.__resetProcessShutdownStateForTest();
    standalone.__resetStandaloneShutdownStateForTest();
    for (const [name, before] of originalListeners) {
      for (const listener of process.listeners(name)) if (!before.has(listener as never)) process.removeListener(name, listener);
    }
    vi.useRealTimers();
    vi.restoreAllMocks();
    process.env = env; process.argv = argv; process.exitCode = exitCode;
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: tty });
    await rm(root, { recursive: true, force: true });
  });

  it.each(["SIGINT", "SIGTERM"] as const)("awaits dashboard release before %s exit", async (name) => {
    await launch();
    await alive();
    const held = holdRelease();
    const save = baseline.BaselineTracker.prototype.save;
    vi.spyOn(baseline.BaselineTracker.prototype, "save").mockImplementation(async function (this: BaselineTracker) {
      await save.call(this); events.push("save");
    });
    const flush = audit.AuditLog.prototype.flush;
    vi.spyOn(audit.AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
      await flush.call(this); if (this !== wrapAudit) events.push("flush");
    });
    signal(name);
    await reached(held.entered.promise);
    await checkpoint();
    expect(exits).toEqual([]);
    expect(session().masterWriteBarrier!.signal.aborted).toBe(false);
    held.finish.resolve();
    await exited.promise;
    await released();
    expect(exits).toEqual([name === "SIGINT" ? SIGINT_STATUS : SIGTERM_STATUS]);
    expect(events.filter((event) => ["save", "flush", "release", "exit"].includes(event)))
      .toEqual(["save", "flush", "release", "exit"]);
    expect(held.spy).toHaveBeenCalledOnce();
  });

  it("awaits wrap teardown after the dashboard has finalized", async () => {
    const entered = gate(); const finish = gate();
    daemonStop.mockImplementation(async () => { entered.resolve(); await finish.promise; events.push("daemon"); });
    await launch();
    const held = holdRelease(); held.finish.resolve();
    signal("SIGTERM");
    await reached(entered.promise);
    await dashboard().stop();
    await checkpoint();
    expect(exits).toEqual([]);
    await released();
    finish.resolve(); await exited.promise;
    expect(exits).toEqual([SIGTERM_STATUS]);
    expect(events.indexOf("daemon")).toBeLessThan(events.indexOf("exit"));
  });

  it.each(["SIGINT", "SIGTERM"] as const)("keeps the dashboard alive during mutation after first %s", async (name) => {
    const entered = gate(); const finish = gate();
    os.provision.mockImplementation(async (options: { beforeFirstMutation(): boolean }) => {
      expect(options.beforeFirstMutation()).toBe(true);
      entered.resolve(); await finish.promise;
      return { ran: true, outcome: { kind: "skipped-non-tty-cooperative-only", reason: "mutation completed witness" } };
    });
    const pending = launch();
    await reached(entered.promise);
    const held = holdRelease();
    signal(name); await checkpoint();
    await alive();
    expect(output).toContain(wrap.renderAutoProvisionSignalRefusal(name));
    expect(held.spy).not.toHaveBeenCalled();
    finish.resolve();
    await reached(held.entered.promise);
    const outcomeLine = "  mutation completed witness";
    expect(output).toContain(outcomeLine);
    expect(exits).toEqual([]);
    held.finish.resolve(); await exited.promise; await pending;
    await released();
    expect(exits).toEqual([name === "SIGINT" ? SIGINT_STATUS : SIGTERM_STATUS]);
    expect(events.indexOf(outcomeLine)).toBeLessThan(events.indexOf("release"));
  });

  it.each(["refusal", "preselected refusal", "unexpected Error", "unexpected undefined", "unexpected custody cleanup"])("joins stop before %s leaves the CLI", async (kind) => {
    const entered = gate(); const finish = gate();
    const operation = kind === "unexpected undefined" ? undefined
      : kind === "unexpected custody cleanup" ? new custody.MasterEstablishmentReleaseError([], "local setup sentinel")
      : new Error("local setup sentinel");
    os.intelligence.mockImplementation(async () => {
      entered.resolve(); await finish.promise;
      if (kind.startsWith("unexpected")) throw operation;
      if (kind === "preselected refusal") process.exitCode = REFUSAL_STATUS;
      return { kind: "refused", reason: "non_tty" };
    });
    const pending = launch(["--provision-local-intelligence"]);
    await reached(entered.promise);
    const held = holdRelease();
    if (kind === "preselected refusal") {
      const release = held.spy.getMockImplementation()!;
      held.spy.mockImplementation(async () => { await release(); process.exitCode = ERROR_STATUS; });
    }
    finish.resolve();
    await reached(held.entered.promise);
    expect(exits).toEqual([]);
    held.finish.resolve(); await exited.promise; await pending;
    await released();
    expect(exits).toEqual([kind === "preselected refusal" ? REFUSAL_STATUS : ERROR_STATUS]);
    expect(text().slice(text().indexOf("Wrapped"))).toContain("Dashboard unavailable in this run.");
    if (kind.startsWith("unexpected")) {
      const diagnostic = kind === "unexpected custody cleanup" ? CUSTODY_FAILURE_DIAGNOSTIC : START_FAILURE_DIAGNOSTIC;
      const diagnostics = vi.mocked(console.error).mock.calls.filter(([message]) =>
        message === CUSTODY_FAILURE_DIAGNOSTIC || message === START_FAILURE_DIAGNOSTIC);
      expect(diagnostics).toEqual([[diagnostic, operation]]);
    } else {
      expect(text()).toContain("Sanctuary protect refused: --provision-local-intelligence was explicitly requested");
      expect(text()).not.toContain("Sanctuary MCP Server failed to start:");
    }
  });

  it.each(["save", "flush", "release", "all"] as const)("preserves the wrap error while reporting dashboard %s failure", async (phase) => {
    const entered = gate(); const finish = gate();
    os.provision.mockImplementation(async () => { entered.resolve(); await finish.promise; return { ran: false }; });
    const operation = new Error("wrap final flush sentinel");
    const cleanup = new Error("dashboard cleanup sentinel");
    const pending = launch(); await reached(entered.promise);
    const held = holdRelease();
    const release = held.spy.getMockImplementation()!;
    held.spy.mockImplementation(async () => { await release(); if (phase === "release" || phase === "all") throw cleanup; });
    const save = baseline.BaselineTracker.prototype.save;
    vi.spyOn(baseline.BaselineTracker.prototype, "save").mockImplementation(async function (this: BaselineTracker) {
      await save.call(this); if (phase === "save" || phase === "all") throw cleanup;
    });
    const flush = audit.AuditLog.prototype.flush;
    vi.spyOn(audit.AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
      await flush.call(this);
      if (this === wrapAudit) throw operation;
      if (phase === "flush" || phase === "all") throw cleanup;
    });
    finish.resolve(); await reached(held.entered.promise);
    expect(exits).toEqual([]);
    held.finish.resolve(); await exited.promise; await pending;
    await released();
    expect(exits).toEqual([ERROR_STATUS]);
    expect(held.spy).toHaveBeenCalledOnce();
    expect(vi.mocked(console.error).mock.calls.filter(([line]) => line === "Sanctuary Dashboard: cleanup failed.")).toHaveLength(1);
    expect(vi.mocked(console.error).mock.calls.filter(([line]) => line === "Sanctuary MCP Server failed to start:")).toEqual([["Sanctuary MCP Server failed to start:", operation]]);
  });

  it("a mixed second signal exits at the existing grace while release remains pending", async () => {
    await launch(); const held = holdRelease();
    signal("SIGTERM"); await reached(held.entered.promise);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    signal("SIGINT");
    await vi.advanceTimersByTimeAsync(wrap.PROCESS_SHUTDOWN_REPEAT_SIGNAL_GRACE_MS - 1); // One millisecond before the existing grace expires.
    expect(exits).toEqual([]);
    await vi.advanceTimersByTimeAsync(1); // The final millisecond of the production grace.
    await exited.promise;
    expect(exits).toEqual([SIGTERM_STATUS]);
    expect(session().masterWriteBarrier!.signal.aborted).toBe(false);
    held.finish.resolve();
    await Promise.all(tasks);
    await released();
    expect(exits).toEqual([SIGTERM_STATUS]);
  });

  it("a policy read resumed during release cannot construct or write after signal stop", async () => {
    const loader = await import("../../src/principal-policy/loader.js");
    const load = loader.loadPrincipalPolicy;
    const entered = gate(); const finish = gate();
    vi.spyOn(loader, "loadPrincipalPolicy").mockImplementation(async (...args) => {
      const policy = await load(...args);
      entered.resolve(); await finish.promise;
      return policy;
    });
    let completed = false;
    interruptedBoot = true;
    void launch().then(() => { completed = true; });
    await reached(entered.promise);
    const identity = await import("../../src/cognitive/tools.js");
    const state = await import("../../src/cognitive/state-store.js");
    const runtime = await import("../../src/cli/agents/runtime.js");
    const filesystem = await import("../../src/storage/filesystem.js");
    const { AgentContextCache } = await import("../../src/chat/agent-context-cache.js");
    const { ConciergeMemoryStore } = await import("../../src/chat/concierge-memory-store.js");
    // Join construction-time background work even when the unfixed boot runs after finalization.
    const refresh = AgentContextCache.prototype.refresh;
    vi.spyOn(AgentContextCache.prototype, "refresh").mockImplementation(function (this: InstanceType<typeof AgentContextCache>) {
      const pending = refresh.call(this); bootTasks.push(pending); return pending;
    });
    const prune = ConciergeMemoryStore.prototype.pruneExpired;
    vi.spyOn(ConciergeMemoryStore.prototype, "pruneExpired").mockImplementation(function (this: InstanceType<typeof ConciergeMemoryStore>) {
      const pending = prune.call(this); bootTasks.push(pending); return pending;
    });
    const dashboardStorage = vi.mocked(custody.establishMaster).mock.calls.at(-1)![0].storage;
    const identitySave = vi.spyOn(identity.IdentityManager.prototype, "save");
    const stateWrite = vi.spyOn(state.StateStore.prototype, "write");
    const writes = (["write", "writeIfAbsent", "writeDurable"] as const).map((method) =>
      vi.spyOn(filesystem.FilesystemStorage.prototype, method));
    const Audit = audit.AuditLog; const Baseline = baseline.BaselineTracker;
    const Identity = identity.IdentityManager; const State = state.StateStore;
    // Return real instances so constructor observation preserves their prototypes.
    const constructors = [
      vi.spyOn(audit, "AuditLog").mockImplementation(function (...args) { return new Audit(...args); }),
      vi.spyOn(baseline, "BaselineTracker").mockImplementation(function (...args) { return new Baseline(...args); }),
      vi.spyOn(identity, "IdentityManager").mockImplementation(function (...args) { return new Identity(...args); }),
      vi.spyOn(state, "StateStore").mockImplementation(function (...args) { return new State(...args); }),
    ];
    const runtimeWrite = vi.spyOn(runtime, "writeTenantRuntime");
    const checked = gate();
    const held = holdRelease();
    const abort = AbortController.prototype.abort;
    const cancellation = vi.spyOn(AbortController.prototype, "abort");
    signal("SIGTERM");
    expect(cancellation).toHaveBeenCalledOnce();
    const stoppedController = cancellation.mock.contexts[0];
    await reached(held.entered.promise);
    expect(exits).toEqual([]);
    expect(session().masterKey.every((byte) => byte === 0)).toBe(true); // Finalization zeroes every key byte before release.
    cancellation.mockImplementation(function (this: AbortController, reason) {
      // Re-entering stop with this session's controller marks the startup catch.
      if (this === stoppedController) checked.resolve();
      return abort.call(this, reason);
    });
    finish.resolve();
    await reached(checked.promise);
    // Startup reached its catch while real release is still held, whether wiring ran or cancellation stopped it.
    expect(exits).toEqual([]);
    for (const constructor of constructors) expect.soft(constructor).not.toHaveBeenCalled();
    expect.soft(identitySave).not.toHaveBeenCalled();
    expect.soft(stateWrite).not.toHaveBeenCalled();
    for (const write of writes) expect.soft(write.mock.contexts.filter((storage) => storage === dashboardStorage)).toEqual([]);
    expect.soft(runtimeWrite).not.toHaveBeenCalled();
    await expect.soft(access(join(fortress, runtime.RUNTIME_FILE_NAME))).rejects.toMatchObject({ code: "ENOENT" });
    expect.soft(channels).toHaveLength(0);
    expect.soft(distress).toEqual([]);
    expect.soft(os.intelligence).not.toHaveBeenCalled();
    expect.soft(os.provision).not.toHaveBeenCalled();
    await Promise.allSettled(bootTasks);
    held.finish.resolve(); await exited.promise;
    expect(completed).toBe(false);
    await released(); expect(exits).toEqual([SIGTERM_STATUS]);
  });

  it.each(["refusal", "preselected refusal", "unexpected Error", "unexpected undefined", "unexpected custody cleanup"])(
    "prints %s before waiting on a dashboard stop that never settles", async (kind) => {
      const entered = gate(); const finish = gate(); const stopping = gate();
      const operation = kind === "unexpected undefined" ? undefined
        : kind === "unexpected custody cleanup" ? new custody.MasterEstablishmentReleaseError([], "local setup sentinel")
        : new Error("local setup sentinel");
      os.intelligence.mockImplementation(async () => {
        entered.resolve(); await finish.promise;
        if (kind.startsWith("unexpected")) throw operation;
        if (kind === "preselected refusal") process.exitCode = REFUSAL_STATUS;
        return { kind: "refused", reason: "non_tty" };
      });
      // This invocation deliberately never settles; the pending promise owns no handles.
      interruptedBoot = true;
      void launch(["--provision-local-intelligence"]);
      await reached(entered.promise);
      const stop = vi.spyOn(dashboard(), "stop").mockImplementation(() => {
        stopping.resolve();
        return new Promise<void>(() => undefined);
      });
      try {
        finish.resolve();
        await reached(stopping.promise);
        expect(exits).toEqual([]);
        if (kind.startsWith("unexpected")) {
          const diagnostic = kind === "unexpected custody cleanup" ? CUSTODY_FAILURE_DIAGNOSTIC : START_FAILURE_DIAGNOSTIC;
          expect(vi.mocked(console.error).mock.calls.filter(([message]) =>
            message === CUSTODY_FAILURE_DIAGNOSTIC || message === START_FAILURE_DIAGNOSTIC))
            .toEqual([[diagnostic, operation]]);
        } else {
          expect(text()).toContain("Sanctuary protect refused: --provision-local-intelligence was explicitly requested");
          expect(text()).not.toContain("Sanctuary MCP Server failed to start:");
          if (kind === "preselected refusal") expect(process.exitCode).toBe(REFUSAL_STATUS);
        }
      } finally {
        // Teardown calls the real stop to reap listeners and the acquired lease.
        stop.mockRestore();
      }
    },
  );
});
