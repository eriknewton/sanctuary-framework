/**
 * The evidence pack's audit read counts every stored row, success markers
 * included, so a complete log reads complete; its activity counts leave the
 * markers out.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuditLog,
  CALL_OUTCOME_SUCCESS_OPERATION,
  runInCallScope,
  settleCallOutcome,
  writeCallOutcomeMarkers,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { aggregateQuarter } from "../../src/evidence-pack/aggregate.js";
import { quarterWindow } from "../../src/evidence-pack/quarter.js";
import type { AuditReadData } from "../../src/evidence-pack/generate.js";
import type { ReadOutcome } from "../../src/evidence-pack/read-outcome.js";

const fixture = vi.hoisted(() => ({
  server: undefined as unknown,
  captured: [] as unknown[],
}));

vi.mock("../../src/index.js", () => ({
  createSanctuaryServer: async () => fixture.server,
}));

vi.mock("../../src/evidence-pack/generate.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/evidence-pack/generate.js")>();
  return {
    ...actual,
    buildEvidencePack: (input: unknown, deps: { audit: unknown }) => {
      fixture.captured.push(deps.audit);
      throw new Error("evidence pack capture stop");
    },
  };
});

const { runEvidencePack } = await import("../../src/evidence-pack/cli.js");

const temps: string[] = [];
afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
  fixture.captured.length = 0;
  vi.restoreAllMocks();
});

async function writeCalls(log: AuditLog): Promise<void> {
  await log.append("l2", "gate_allow:state_write", "system");
  await runInCallScope(async (scope) => {
    await log.append("l2", "gate_allow:state_write", "agent:one");
    settleCallOutcome(scope, "succeeded");
    writeCallOutcomeMarkers(scope);
  });
  await log.flush();
}

async function auditOutcomeFromCli(log: AuditLog, masterKey: Uint8Array): Promise<ReadOutcome<AuditReadData>> {
  const root = await mkdtemp(join(tmpdir(), "evidence-pack-markers-"));
  temps.push(root);
  const identityManager = new IdentityManager(new MemoryStorage(), masterKey);
  const { storedIdentity } = createIdentity("fixture-firm", derivePurposeKey(masterKey, "identity-encryption"), "recovery-key");
  await identityManager.save(storedIdentity);
  fixture.server = { config: { storage_path: root }, identityManager, masterKey, auditLog: log };
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  await expect(runEvidencePack(["generate", "--firm", "Fixture", "--output", join(root, "out")])).rejects.toThrow("evidence pack capture stop");
  const captured = fixture.captured.splice(0);
  expect(captured).toHaveLength(1);
  return captured[0] as ReadOutcome<AuditReadData>;
}

describe("evidence pack audit read with success markers", () => {
  it("a complete log holding one marker reads complete", async () => {
    const masterKey = generateRandomKey();
    const log = new AuditLog(new MemoryStorage(), masterKey);
    await writeCalls(log);
    const raw = await log.query({ limit: 100, include_outcome_markers: true });
    expect(raw.entries.map((e) => e.operation)).toContain(CALL_OUTCOME_SUCCESS_OPERATION);
    const outcome = await auditOutcomeFromCli(log, masterKey);
    expect(outcome.status).toBe("populated");
  });

  it("a truncated window still reads failed", async () => {
    const masterKey = generateRandomKey();
    const log = new AuditLog(new MemoryStorage(), masterKey);
    await writeCalls(log);
    const usage = log.getRetentionUsage.bind(log);
    vi.spyOn(log, "getRetentionUsage").mockImplementation(async () => {
      const real = await usage();
      return { ...real, entryCount: real.entryCount + 1 };
    });
    const outcome = await auditOutcomeFromCli(log, masterKey);
    expect(outcome.status).toBe("read_failed");
  });

  it("activity counts are the same with and without a marker in the log", async () => {
    const masterKey = generateRandomKey();
    const withMarker = new AuditLog(new MemoryStorage(), masterKey);
    await writeCalls(withMarker);
    const withoutMarker = new AuditLog(new MemoryStorage(), masterKey);
    await withoutMarker.append("l2", "gate_allow:state_write", "system");
    await runInCallScope(async (scope) => {
      await withoutMarker.append("l2", "gate_allow:state_write", "agent:one");
      settleCallOutcome(scope, "refused");
    });
    await withoutMarker.flush();
    const a = await auditOutcomeFromCli(withMarker, masterKey);
    const b = await auditOutcomeFromCli(withoutMarker, masterKey);
    if (a.status !== "populated" || b.status !== "populated") throw new Error("expected populated reads");
    expect(a.value.entries.map((e: AuditEntry) => e.operation)).toEqual(b.value.entries.map((e: AuditEntry) => e.operation));
    const window = quarterWindow({ year: new Date().getUTCFullYear(), quarter: (Math.floor(new Date().getUTCMonth() / 3) + 1) as 1 | 2 | 3 | 4 });
    const aggA = aggregateQuarter(a.value.entries, window);
    const aggB = aggregateQuarter(b.value.entries, window);
    expect(aggA.total_in_window).toBe(aggB.total_in_window);
    expect(aggA.by_category).toEqual(aggB.by_category);
    expect(a.value.retention.retained_total).toBe(b.value.retention.retained_total + 1);
  });

});
