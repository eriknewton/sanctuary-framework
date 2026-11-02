import { withPathLock, resolveAuditGuardRuntimeRoot } from "../../src/storage/cross-process-lock.js";
const [directory, testRoot] = process.argv.slice(2);
const release = new Promise<void>(resolve => process.on("message", message => { if (message === "release") resolve(); }));
// Must match guard name and runtimeRoot in operational/audit-log.ts; omit the test root for the real rendezvous drill.
await withPathLock(directory, ".audit-write.lock.guard", async () => {
  process.send?.({ state: "acquired", root: testRoot ?? resolveAuditGuardRuntimeRoot(process.getuid!(), process.platform) });
  await release;
}, {
  kernelBacked: true, scaffold: false,
  runtimeRoot: testRoot ?? resolveAuditGuardRuntimeRoot(process.getuid!(), process.platform),
  onContended: () => process.send?.({ state: "contended" }),
});
process.send?.({ state: "released" });
process.disconnect?.();
