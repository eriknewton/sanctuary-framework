/** Exercises production CLI/cleanup; only fault injection lives in this fixture. */
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const mode = process.argv[2]!;
const root = process.env.HOME!;
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
  if (mode === "cli") {
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
