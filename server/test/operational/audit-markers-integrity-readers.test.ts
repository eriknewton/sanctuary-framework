/**
 * Paths that count stored audit rows read success markers too: exit receipts
 * export every stored row, and the posture digest's coverage, which locates
 * chain positions by count, still reads a log holding markers as complete.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import {
  AuditLog,
  CALL_OUTCOME_SUCCESS_OPERATION,
  runInCallScope,
  settleCallOutcome,
  writeCallOutcomeMarkers,
} from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { exportExitBundle } from "../../src/exit/index.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { computeAuditPeriodSummary } from "../../src/compliance/eu_ai_act/generator.js";

const temps: string[] = [];
afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
});

async function successfulCall(log: AuditLog, operation: string): Promise<void> {
  await runInCallScope(async (scope) => {
    await log.append("l2", operation, "agent:one");
    settleCallOutcome(scope, "succeeded");
    writeCallOutcomeMarkers(scope);
  });
  await log.flush();
}

describe("integrity readers count success markers", () => {
  it("exit receipts count every stored row including markers", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { identityManager, tools } = createL1Tools(stateStore, storage, masterKey, "recovery-key", auditLog);
    await identityManager.load();
    await tools.find((t) => t.name === "identity_create")!.handler({ label: "exit-markers" });
    const { reputationStore } = createL4Tools(storage, masterKey, identityManager, auditLog);
    await successfulCall(auditLog, "own_activity");
    const stored = (await auditLog.query({ limit: 10_000, include_outcome_markers: true })).entries;
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-exit-markers-"));
    temps.push(bundleDir);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage,
      masterKey,
      identityManager,
      auditLog,
      reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      keySource: "recovery-key",
    });
    const artifact = JSON.parse(await readFile(join(bundleDir, "artifacts/audit_receipts.json"), "utf8")) as {
      total: number;
      entries: Array<{ operation: string }>;
      truncated?: boolean;
    };
    const markerCount = artifact.entries.filter((e) => e.operation === CALL_OUTCOME_SUCCESS_OPERATION).length;
    expect(markerCount).toBe(1);
    expect(artifact.truncated).toBeUndefined();
    // Every row stored before the export (the export appends its own rows after reading).
    expect(artifact.total).toBeGreaterThanOrEqual(stored.length);
    expect(artifact.entries.slice(0, stored.length).map((e) => e.operation)).toEqual(stored.map((e) => e.operation));
  });

  it("the posture digest reads a complete window over a log holding markers", async () => {
    const now = Date.now();
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    await successfulCall(auditLog, "own_activity");
    await successfulCall(auditLog, "more_activity");
    const digest = await buildAuditDigest({ auditLog, originMachine: "fortress:test", protectionClaimSubject: null, now });
    expect(digest).toMatchObject({ window_complete: true, window_incomplete_reason: null });
  });
});

describe("the approved compliance bundle's counts", () => {
  it("the period summary counts the same with and without a success marker in the log", async () => {
    const periodStart = new Date(Date.now() - 60_000).toISOString();
    const periodEnd = new Date(Date.now() + 60_000).toISOString();
    const withMarker = new AuditLog(new MemoryStorage(), generateRandomKey());
    await successfulCall(withMarker, "own_activity");
    const withoutMarker = new AuditLog(new MemoryStorage(), generateRandomKey());
    await withoutMarker.append("l2", "own_activity", "agent:one");
    await withoutMarker.flush();
    const a = await computeAuditPeriodSummary(withMarker, periodStart, periodEnd);
    const b = await computeAuditPeriodSummary(withoutMarker, periodStart, periodEnd);
    const { period_start: _a1, period_end: _a2, ...countsA } = a;
    const { period_start: _b1, period_end: _b2, ...countsB } = b;
    expect(countsA).toEqual(countsB);
    expect(a.unique_operations).not.toContain(CALL_OUTCOME_SUCCESS_OPERATION);
  });
});
