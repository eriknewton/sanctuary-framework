/**
 * At the retention limit, refused calls' rows still count toward retention,
 * so how many older visible rows survive can depend on how many rows a
 * refused call wrote. This measures that and records it; it asserts only
 * that no reader returns a refused call's row.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLog,
  runInCallScope,
  settleCallOutcome,
  writeCallOutcomeMarkers,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const AGENT = "agent:pressure";
const HISTORY = 20;
const SUCCESSES = 5;

async function call(log: AuditLog, rows: number, tag: string, outcome: "succeeded" | "refused"): Promise<void> {
  await runInCallScope(async (scope) => {
    for (let i = 0; i < rows; i++) await log.append("l2", "pressure_row", AGENT, { tag: `${tag}-${i}` });
    settleCallOutcome(scope, outcome);
    writeCallOutcomeMarkers(scope);
  });
  await log.flush();
}

async function world(config: { maxEntries?: number; maxTotalSizeBytes?: number }, refusedRows: number) {
  const log = new AuditLog(new MemoryStorage(), generateRandomKey(), config);
  for (let i = 0; i < HISTORY; i++) await log.append("l2", "pressure_row", AGENT, { tag: `history-${i}` });
  await log.flush();
  await call(log, refusedRows, "refused", "refused");
  for (let i = 0; i < SUCCESSES; i++) await call(log, 1, `ok-${i}`, "succeeded");
  const visible = await log.query({ identity_id: AGENT, agent_visible: true, limit: 1_000 });
  return {
    returned_refused_rows: visible.entries.filter((e) => String(e.details?.tag).startsWith("refused")).length,
    visible_total: visible.total,
    visible_history: visible.entries.filter((e) => String(e.details?.tag).startsWith("history")).length,
  };
}

describe("retention pressure from refused calls", () => {
  for (const boundary of [
    { name: "count", config: { maxEntries: 24 } },
    { name: "bytes", config: { maxTotalSizeBytes: 24 * 700 } },
  ]) {
    it(`at the ${boundary.name} boundary no reader returns a refused call's row, and the surviving history is measured`, async () => {
      const one = await world(boundary.config, 1);
      const several = await world(boundary.config, 8);
      console.log(`RETENTION-PRESSURE-MEASUREMENT ${JSON.stringify({ boundary: boundary.name, one_row_refusal: one, several_row_refusal: several })}`);
      expect(one.returned_refused_rows).toBe(0);
      expect(several.returned_refused_rows).toBe(0);
    });
  }
});
