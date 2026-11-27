// fail-before-exempt: pins only; "cleanup flushes namespace inserts, saves the baseline, closes the ledger, then flushes the audit log, in that order", "a ledger close whose own appends never settle returns within its deadline and reports the unsettled count, and cleanup then reaches the audit flush", and "a call's response does not wait for its marker to be durable, and cleanup still drains the queue" pin the merged cleanup order.
/**
 * Shutdown persists in a fixed order: the inbox, the namespace inserts, the
 * baseline, the denial ledger (bounded by its own deadline), then the audit
 * log's final flush. A call's response never waits for its success marker,
 * and cleanup still drains the audit queue before it resolves.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createSanctuaryServer } from "../../src/index.js";
import { AUDIT_NAMESPACE, AuditLog } from "../../src/operational/audit-log.js";
import { BaselineNamespaceInserts, BaselineTracker } from "../../src/principal-policy/baseline.js";
import { UnifiedInboxBridge } from "../../src/principal-policy/unified-inbox-bridge.js";
import { DenialLedger, LEDGER_CLOSE_DEADLINE_MS } from "../../src/agent-native/denial-ledger.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

/** Audit-namespace writes are held while `holding` is set, until released; every other write proceeds. */
class HeldAuditWriteStorage extends MemoryStorage {
  holding = false;
  readonly held: Array<() => void> = [];
  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (this.holding && namespace === AUDIT_NAMESPACE) await new Promise<void>((release) => { this.held.push(release); });
    return super.write(namespace, key, data);
  }
  release(): void {
    this.holding = false;
    for (const release of this.held.splice(0)) release();
  }
}

const teardown: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of teardown.splice(0).reverse()) await step();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

async function boot(storage = new MemoryStorage()) {
  const fortress = await createTempFortress("cleanup-order");
  teardown.push(() => fortress.cleanup());
  vi.stubEnv("SANCTUARY_SESSION_IDENTITY_ID", "");
  const app = await createSanctuaryServer({
    storage,
    passphrase: TEST_PASSPHRASE,
    approvalCallback: async () => ({ decision: "approve", decided_at: new Date().toISOString(), decided_by: "human" }),
  });
  const client = new Client({ name: "cleanup-order", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await app.server.connect(serverTransport);
  await client.connect(clientTransport);
  let cleaned = false;
  const cleanup = async () => {
    if (cleaned) return;
    cleaned = true;
    await client.close();
    await app.cleanup();
  };
  teardown.push(async () => { await cleanup(); await app.server.close(); });
  return { app, client, cleanup };
}

/** Record the calls cleanup makes on each persistence step, by name, once recording starts. */
function recordSteps() {
  const order: string[] = [];
  const state = { recording: false };
  const steps: Array<[object, string, string]> = [
    [UnifiedInboxBridge.prototype, "flushPersistence", "inbox.flushPersistence"],
    [BaselineNamespaceInserts.prototype, "flushPending", "namespaceInserts.flushPending"],
    [BaselineTracker.prototype, "save", "baseline.save"],
    [DenialLedger.prototype, "close", "denialLedger.close"],
    [AuditLog.prototype, "flush", "auditLog.flush"],
  ];
  for (const [proto, method, label] of steps) {
    const original = (proto as Record<string, (...args: unknown[]) => unknown>)[method]!;
    vi.spyOn(proto as Record<string, (...args: unknown[]) => unknown>, method).mockImplementation(function (this: unknown, ...args: unknown[]) {
      if (state.recording) order.push(label);
      return original.apply(this, args);
    });
  }
  return { order, state };
}

/** The labels in the order of each one's last call. */
function lastCallOrder(order: string[]): string[] {
  return [...new Set([...order].reverse())].reverse();
}

describe("cleanup order", () => {
  it("cleanup flushes namespace inserts, saves the baseline, closes the ledger, then flushes the audit log, in that order", async () => {
    const steps = recordSteps();
    const b = await boot();
    steps.state.recording = true;
    await b.cleanup();
    expect(lastCallOrder(steps.order)).toEqual([
      "inbox.flushPersistence",
      "namespaceInserts.flushPending",
      "baseline.save",
      "denialLedger.close",
      "auditLog.flush",
    ]);
  });

  it("a ledger close whose own appends never settle returns within its deadline and reports the unsettled count, and cleanup then reaches the audit flush", async () => {
    const steps = recordSteps();
    const b = await boot();
    const appendCritical = b.app.auditLog.appendCritical.bind(b.app.auditLog);
    // Only the ledger's own appends hang; the shared audit store is untouched.
    vi.spyOn(b.app.auditLog, "appendCritical").mockImplementation((entry) =>
      entry.operation === "denial_cause" || entry.operation === "denial_cause_summary"
        ? new Promise<void>(() => undefined)
        : appendCritical(entry));
    // The composition root's ledger reports to stderr.
    const warnings: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => { warnings.push(String(chunk)); return true; }) as typeof process.stderr.write);
    // A refusal the ledger records: a forget without its required approval.
    expect((await b.client.callTool({ name: "sanctuary_forget", arguments: { key: "k", mode: "secure", approval_ref: "x" } })).isError).toBe(true);
    steps.state.recording = true;
    const started = performance.now();
    await b.cleanup();
    const elapsed = performance.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(LEDGER_CLOSE_DEADLINE_MS - 50);
    expect(elapsed).toBeLessThan(LEDGER_CLOSE_DEADLINE_MS * 4);
    expect(warnings.some((line) => /denial ledger closed with 1 audit appends unsettled/.test(line))).toBe(true);
    expect(lastCallOrder(steps.order).slice(-2)).toEqual(["denialLedger.close", "auditLog.flush"]);
  }, LEDGER_CLOSE_DEADLINE_MS * 6);

  it("a call's response does not wait for its marker to be durable, and cleanup still drains the queue", async () => {
    const storage = new HeldAuditWriteStorage();
    const steps = recordSteps();
    const b = await boot(storage);
    const appendCritical = b.app.auditLog.appendCritical.bind(b.app.auditLog);
    // Hold every audit write after the call's own row is durable: the next one is its success marker.
    vi.spyOn(b.app.auditLog, "appendCritical").mockImplementation(async (entry) => {
      await appendCritical(entry);
      if (entry.operation === "sanctuary_who_am_i") storage.holding = true;
    });
    const response = await b.client.callTool({ name: "sanctuary_who_am_i", arguments: {} });
    expect(response.isError).not.toBe(true);
    // The response arrived; the marker's write is still held.
    await vi.waitFor(() => expect(storage.held.length).toBeGreaterThan(0));
    let cleanupDone = false;
    steps.state.recording = true;
    const cleanup = b.cleanup().then(() => { cleanupDone = true; });
    await vi.waitFor(() => expect(steps.order).toContain("auditLog.flush"));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(cleanupDone).toBe(false);
    storage.release();
    await cleanup;
    expect(cleanupDone).toBe(true);
    expect(storage.held).toEqual([]);
  });
});
