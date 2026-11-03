/** Exercises production CLI/cleanup; only fault injection lives in this fixture. */
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const mode = process.argv[2]!;
const root = process.env.HOME!;
if (mode.startsWith("cli-lk1")) {
  const { installInMemoryKeychainStore } = await import("../setup/keychain-memory-store.js");
  installInMemoryKeychainStore();
  const fs = (await import("node:fs/promises")).default;
  const { syncBuiltinESMExports } = await import("node:module");
  const { createHash } = await import("node:crypto");
  const { Server } = await import("node:net");
  const quotaDirectory = join(process.env.SANCTUARY_STORAGE_PATH!, "state", "_memory_save_quota");
  const quotaPath = join(quotaDirectory, "own-scope-save-quota.json");
  const bound = new Map<string, InstanceType<typeof Server>>();
  const originalListen = Server.prototype.listen;
  Server.prototype.listen = function (this: InstanceType<typeof Server>, ...args: Parameters<InstanceType<typeof Server>["listen"]>) {
    const options = args[0] as unknown as { path?: string };
    if (options?.path?.endsWith(".sock")) {
      if (bound.size >= 64) throw new Error("fixture listener observation limit"); // Same six-family headroom budget as LK1.
      bound.set(options.path, this);
    }
    return Reflect.apply(originalListen, this, args);
  } as InstanceType<typeof Server>["listen"];
  let armed = false, paused = false, stopping = false, dispositionReported = false;
  const monotonicNow = performance.now.bind(performance);
  let elapsed = 0;
  Object.defineProperty(performance, "now", { configurable: true, value: () => monotonicNow() + elapsed });
  let resume: (() => void) | undefined;
  let prepareRecovery: (() => Promise<void>) | undefined;
  let recoveryCalls = 0, importCalls = 0, floorReached = false;
  const send = (phase: string, data: object = {}) => process.send!({ phase, ...data });
  // Must match the LK1 IPC commands in test/cli/lifecycle-idle-shutdown.test.ts.
  process.on("message", async (message: { command: string; identity?: string }) => {
    if (message.command === "BIND" && message.identity) {
      process.env.SANCTUARY_SESSION_IDENTITY_ID = message.identity;
      send("BOUND");
    } else if (message.command === "ARM" && !armed && !paused) {
      await prepareRecovery?.(); armed = true; send("ARMED");
    } else if (message.command === "RESUME" && resume) {
      // Must match OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS in principal-policy/gate.ts: advance only after the read barrier.
      if (mode === "cli-lk1") elapsed += OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS;
      const release = resume; resume = undefined; release();
    } else if (message.command === "COUNTS") {
      send("RECOVERY_COUNTS", { recoveryCalls, importCalls, floorReached });
    } else if (message.command === "LOADS") {
      send("CACHE_STATE", { durableLoads });
    } else if (message.command === "STOPPING" && !stopping) {
      stopping = true; send("STOPPING");
    } else throw new Error("unexpected lifecycle fixture command");
  });
  const originalOpen = fs.open;
  fs.open = (async (...args: Parameters<typeof originalOpen>) => {
    const file = await originalOpen(...args);
    if (String(args[0]) !== quotaPath) return file;
    return new Proxy(file, {
      get(target, property) {
        if (property === "read") return async (...readArgs: unknown[]) => {
          if (armed && mode === "cli-lk1") {
            armed = false; paused = true;
            const directory = await fs.lstat(quotaDirectory, { bigint: true });
            // Must match the directory identity and digest contract in storage/cross-process-lock.ts.
            const digest = createHash("sha256").update(`${directory.dev}:${directory.ino}:own-scope-save-quota.lock`).digest("hex");
            const path = join(process.env.SANCTUARY_CUSTODY_LOCK_ROOT!, `${digest.slice(0, 40)}.sock`);
            if (!bound.get(path)?.listening) throw new Error("quota bind was not observed");
            const released = new Promise<void>(resolve => { resume = resolve; });
            send("READ_PAUSED", { path, directory: quotaDirectory });
            await released;
          }
          return Reflect.apply(target.read, target, readArgs);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }) as typeof originalOpen;
  syncBuiltinESMExports();
  const { DashboardApprovalChannel } = await import("../../src/principal-policy/dashboard.js");
  const dashboard = DashboardApprovalChannel.prototype as unknown as Record<string, (...args: any[]) => any>;
  const broadcast = dashboard.broadcastSSE!;
  dashboard.broadcastSSE = function (event: string, data: Record<string, unknown>) {
    const result = Reflect.apply(broadcast, this, [event, data]);
    if (event === "pending-request") send("HOLD", data);
    return result;
  };
  const { ApprovalGate, OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS } = await import("../../src/principal-policy/gate.js");
  const evaluate = ApprovalGate.prototype.evaluate;
  ApprovalGate.prototype.evaluate = async function (...args: Parameters<typeof evaluate>) {
    const result = await Reflect.apply(evaluate, this, args);
    if (mode === "cli-lk1" && paused && !dispositionReported) {
      await (this as unknown as { ownScopeSaveTail: Promise<unknown> }).ownScopeSaveTail;
      dispositionReported = true; send("DISPOSAL_SETTLED");
    }
    return result;
  };
  if (mode === "cli-lk1-identity" || mode === "cli-lk1-import") {
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const { ReputationStore } = await import("../../src/reputation/reputation-store.js");
    const { CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY, CUSTODY_WRITE_LOCK_FILE } = await import("../../src/core/master-custody.js");
    const remove = FilesystemStorage.prototype.delete;
    let journal: Uint8Array | undefined;
    FilesystemStorage.prototype.delete = async function (...args: Parameters<typeof remove>) {
      if (args[0] === "_meta" && args[1] === CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY) {
        const raw = await this.read(args[0], args[1]);
        if (raw) journal = raw.slice();
      }
      const result = await Reflect.apply(remove, this, args);
      return result;
    };
    const withNamespaceLock = FilesystemStorage.prototype.withNamespaceLock;
    FilesystemStorage.prototype.withNamespaceLock = async function (this: InstanceType<typeof FilesystemStorage>, namespace, filename, operation, options) {
      if (!armed || namespace !== "_meta" || filename !== CUSTODY_WRITE_LOCK_FILE) {
        return withNamespaceLock.call(this, namespace, filename, operation, options);
      }
      const directoryPath = this.namespacePath(namespace);
      const atFloor = new Error().stack?.includes("enforceCustodyFloor") === true;
      return withNamespaceLock.call(this, namespace, filename, async lease => {
        armed = false; paused = true; recoveryCalls++; floorReached = atFloor;
        const directory = await fs.lstat(directoryPath, { bigint: true });
        const digest = createHash("sha256").update(`${directory.dev}:${directory.ino}:${CUSTODY_WRITE_LOCK_FILE}`).digest("hex");
        const path = join(process.env.SANCTUARY_CUSTODY_LOCK_ROOT!, `${digest.slice(0, 40)}.sock`);
        if (!bound.get(path)?.listening) throw new Error("recovery bind was not observed");
        const released = new Promise<void>(resolve => { resume = resolve; });
        send("RECOVERY_PAUSED", { path, directory: directoryPath, floorReached });
        await released;
        return operation(lease);
      }, options);
    } as typeof withNamespaceLock;
    prepareRecovery = async () => {
      if (!journal) throw new Error("real writer journal was not captured");
      const storage = new FilesystemStorage(join(process.env.SANCTUARY_STORAGE_PATH!, "state"));
      await storage.write("_meta", CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY, journal);
    };
    const save = IdentityManager.prototype.save;
    IdentityManager.prototype.save = async function (...args: Parameters<typeof save>) {
      try { return await Reflect.apply(save, this, args); }
      finally { if (mode === "cli-lk1-identity" && paused && !dispositionReported) { dispositionReported = true; send("DISPOSAL_SETTLED"); } }
    };
    const importBundle = ReputationStore.prototype.importBundle;
    ReputationStore.prototype.importBundle = async function (...args: Parameters<typeof importBundle>) {
      importCalls++;
      try { return await Reflect.apply(importBundle, this, args); }
      finally { if (mode === "cli-lk1-import" && paused && !dispositionReported) { dispositionReported = true; send("DISPOSAL_SETTLED"); } }
    };
  }
  let durableLoads = 0;
  if (mode === "cli-lk1-claim") {
    const { StateStore } = await import("../../src/cognitive/state-store.js");
    const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
    const { OpaqueNamespaceRegistry, MEMORY_HANDLE_REGISTRY_NAMESPACE, MEMORY_HANDLE_REGISTRY_LOCK } = await import("../../src/agent-native/safety-base.js");
    const write = StateStore.prototype.write;
    StateStore.prototype.write = async function (...args: Parameters<typeof write>) {
      const result = await Reflect.apply(write, this, args);
      if (armed && args[0] === MEMORY_HANDLE_REGISTRY_NAMESPACE) {
        armed = false; paused = true;
        const storage = new FilesystemStorage(join(process.env.SANCTUARY_STORAGE_PATH!, "state"));
        const directoryPath = storage.namespacePath(MEMORY_HANDLE_REGISTRY_NAMESPACE);
        const directory = await fs.lstat(directoryPath, { bigint: true });
        const digest = createHash("sha256").update(`${directory.dev}:${directory.ino}:${MEMORY_HANDLE_REGISTRY_LOCK}`).digest("hex");
        const path = join(process.env.SANCTUARY_CUSTODY_LOCK_ROOT!, `${digest.slice(0, 40)}.sock`);
        if (!bound.get(path)?.listening) throw new Error("claim bind was not observed");
        const released = new Promise<void>(resolve => { resume = resolve; });
        send("CLAIM_PAUSED", { path, directory: directoryPath });
        await released;
      }
      return result;
    };
    const read = StateStore.prototype.read;
    StateStore.prototype.read = async function (...args: Parameters<typeof read>) {
      const result = await Reflect.apply(read, this, args);
      if (paused && args[0] === MEMORY_HANDLE_REGISTRY_NAMESPACE && result !== null) durableLoads++;
      return result;
    };
    const issue = OpaqueNamespaceRegistry.prototype.issuePersistedMemoryHandle;
    OpaqueNamespaceRegistry.prototype.issuePersistedMemoryHandle = async function (...args: Parameters<typeof issue>) {
      try { return await Reflect.apply(issue, this, args); }
      finally { if (paused && !dispositionReported) { dispositionReported = true; send("DISPOSAL_SETTLED"); } }
    };
  }
  const { BaselineTracker } = await import("../../src/principal-policy/baseline.js");
  const { AuditLog } = await import("../../src/operational/audit-log.js");
  const { UnifiedInboxBridge } = await import("../../src/principal-policy/unified-inbox-bridge.js");
  const completed = new Set<string>();
  for (const [prototype, method, label] of [
    [UnifiedInboxBridge.prototype, "flushPersistence", "inbox"],
    [BaselineTracker.prototype, "save", "baseline"],
    [AuditLog.prototype, "flush", "audit"],
  ] as const) {
    const methods = prototype as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    const original = methods[method]!;
    methods[method] = async function (...args: unknown[]) {
      const result = await Reflect.apply(original, this, args);
      if (stopping) {
        completed.add(label);
        if (completed.size === 3) { // The three production persistence consumers above must finish.
          await writeFile(join(root, "lk1-flush.json"), JSON.stringify([...completed]), { mode: 0o600 });
          stopping = false;
          process.send!({ phase: "FLUSH_DONE" }, () => process.disconnect!());
        }
      }
      return result;
    };
  }
}
const report = (value: unknown): Promise<void> =>
  writeFile(join(root, "observations.json"), JSON.stringify(value), { mode: 0o600 });

if (mode.startsWith("helper-")) {
  const { installStdioShutdown } = await import("../../src/cli/stdio-shutdown.js");
  const server: { onclose?: () => void } = {};
  let calls = 0;
  let reentrant: Promise<void> | undefined;
  const shutdown = installStdioShutdown(server, async () => {
    calls++;
    server.onclose?.();
    reentrant = shutdown();
    if (mode === "helper-stray") setInterval(() => {}, 60_000);
    if (mode === "helper-pending") await new Promise(() => {});
    if (mode === "helper-reject") throw new Error("synthetic cleanup rejection");
  }, 300);
  if (mode === "helper-prior") process.exitCode = 42;
  process.stdin.resume();
  process.stderr.write("LIFECYCLE:READY\n");
  if (mode === "helper-reentry") {
    const first = shutdown();
    const second = shutdown();
    await first;
    await report({ calls, same: first === second && first === reentrant && first === shutdown() });
    process.stdin.pause();
  }
} else {
  // A legacy recovery fixture uses its random key as master; migration is real.
  // Providing recovery env avoids any OS-keychain lookup or first-run disclosure.
  const { FilesystemStorage } = await import("../../src/storage/filesystem.js");
  const { toBase64url, stringToBytes } = await import("../../src/core/encoding.js");
  const { hashToString } = await import("../../src/core/hashing.js");
  const { defaultConfig, saveConfig } = await import("../../src/config.js");
  const { loadPrincipalPolicy } = await import("../../src/principal-policy/loader.js");
  const key = await readFile(join(root, "fixture-key"));
  process.env.SANCTUARY_RECOVERY_KEY = toBase64url(key);
  const fortress = process.env.SANCTUARY_STORAGE_PATH!;
  const storage = new FilesystemStorage(join(fortress, "state"));
  await storage.write("_meta", "recovery-key-hash", stringToBytes(hashToString(key)));
  if (mode === "cli-lk1-identity" || mode === "cli-lk1-import") {
    const { prepareRecoveryWrapWithKey, writeCustodyEnvelope } = await import("../../src/core/master-custody.js");
    const prepared = prepareRecoveryWrapWithKey({ v: 1, install_mode: "headless", wraps: [], created_at: new Date().toISOString(), mac: "" }, key, toBase64url(key));
    await writeCustodyEnvelope(storage, prepared.envelope, key);
  }
  if (mode === "cli" || mode.startsWith("cli-lk1")) {
    const { BaselineTracker } = await import("../../src/principal-policy/baseline.js");
    const baseline = new BaselineTracker(storage, key);
    baseline.recordNamespaceAccess("lifecycle");
    await baseline.save();
  }
  key.fill(0);
  await saveConfig({ ...defaultConfig(), storage_path: fortress });
  await loadPrincipalPolicy(fortress);
  const policyPath = join(fortress, "principal-policy.yaml");
  const policy = await readFile(policyPath, "utf8");
  if (!policy.includes("  type: stderr")) throw new Error("Unexpected default approval channel");
  await writeFile(policyPath, policy.replace("  type: stderr", "  type: dashboard"), { mode: 0o600 });

  if (mode.startsWith("cli")) {
    if (mode === "cli-preended") {
      const { once } = await import("node:events");
      const ended = once(process.stdin, "end");
      process.stdin.resume();
      await ended;
    }
    // Import the actual entry point: no hand-written signal wiring here.
    process.argv = [process.execPath, new URL("../../src/cli.ts", import.meta.url).pathname];
    await import("../../src/cli.js");
  } else {
    const { createSanctuaryServer } = await import("../../src/index.js");
    const graph = await createSanctuaryServer();
    const trace: string[] = [];
    // Wrap the real graph's class methods, retaining their actual behavior.
    function observe(proto: object, method: string, label: string): void {
      const methods = proto as Record<string, (...args: unknown[]) => unknown>;
      const original = methods[method]!;
      methods[method] = function (...args: unknown[]) {
        trace.push(label);
        return Reflect.apply(original, this, args);
      };
    }
    const { BaselineTracker } = await import("../../src/principal-policy/baseline.js");
    const { AuditLog } = await import("../../src/operational/audit-log.js");
    const { UnifiedInboxScheduler } = await import("../../src/principal-policy/unified-inbox-scheduler.js");
    const { UnifiedInboxBridge } = await import("../../src/principal-policy/unified-inbox-bridge.js");
    const { CalibrationSuggester } = await import("../../src/auto-trigger/calibration-suggester.js");
    const { ActionDispatcher } = await import("../../src/auto-trigger/action-dispatcher.js");
    const { SentinelDispatcher } = await import("../../src/sentinel/sentinel-dispatcher.js");
    const { AnomalyPipelineDispatcher } = await import("../../src/anomaly-detection/anomaly-pipeline.js");
    const { DashboardApprovalChannel } = await import("../../src/principal-policy/dashboard.js");
    observe(UnifiedInboxScheduler.prototype, "stop", "inbox-stop");
    observe(CalibrationSuggester.prototype, "stop", "suggester-stop");
    observe(SentinelDispatcher.prototype, "dispose", "sentinel-dispose");
    observe(AnomalyPipelineDispatcher.prototype, "dispose", "anomaly-dispose");
    observe(ActionDispatcher.prototype, "dispose", "actions-dispose");
    observe(DashboardApprovalChannel.prototype, "stop", "dashboard-stop");
    observe(UnifiedInboxBridge.prototype, "flushPersistence", "inbox-flush");
    observe(BaselineTracker.prototype, "save", "baseline-save");
    observe(AuditLog.prototype, "flush", "audit-flush");
    // Real asynchronous close reenters cleanup, then rejects. Independent
    // production cleanup steps must still run, once, including final persistence.
    const originalClose = graph.server.close.bind(graph.server);
    let reentrant: Promise<void> | undefined;
    graph.server.close = async () => {
      trace.push("close-start");
      reentrant = graph.cleanup();
      await new Promise(resolve => setTimeout(resolve, 25));
      await originalClose();
      trace.push("close-end");
      if (mode === "graph-reject") throw new Error("synthetic transport close rejection");
    };
    await graph.auditLog.append("l2", "lifecycle_final_append", "system", {});
    const first = graph.cleanup();
    const second = graph.cleanup();
    let rejected = false;
    try { await first; } catch { rejected = true; }
    await report({ trace, rejected, same: first === second && first === reentrant && first === graph.cleanup(), keyStillHeld: graph.masterKey.some(byte => byte !== 0) });
    if (rejected) process.exitCode = 1;
  }
}
