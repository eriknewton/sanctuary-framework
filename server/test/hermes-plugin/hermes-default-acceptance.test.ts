// These checks run only when SANCTUARY_HERMES_PYTHON names an installed Hermes interpreter.
// CI without Hermes skips them; installed Linux and Mac environments can run them.
// The production bridge and shim class run against temporary storage and a framing relay.
// Native Swift, its installed agent uid-502 check, and the fixed darwin entry require the attended platform drill.
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RECALL_PREFETCH_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { startFixture, type Fixture } from "./harness/fixture.js";

const python = process.env.SANCTUARY_HERMES_PYTHON;
const python019 = process.env.SANCTUARY_HERMES_PYTHON_019;
const query = "When is the board meeting?";
const savedText = "The board meeting moved to Thursday 3pm.";
const digest = (text: string) => createHash("sha256").update(text).digest("hex");
const refusal = { outcome: "unavailable", message: "This is not available yet; nothing was done." };
const denied = { outcome: "denied", message: "Request denied." };
const runsRequired = 5; // Five independent cold processes are the timing sample.

describe.skipIf(!python)("Hermes persistent memory through the installed plugin pair", () => {
  let fixture: Fixture;
  beforeAll(async () => { fixture = await startFixture(); });
  afterAll(async () => { await fixture?.close(); });

  it("loads, saves, recalls, preserves refusals, guards native calls and settles transport loss", async () => {
    // Keep every session in this case so the temporary credential store survives until teardown.
    const loading = await fixture.session(python!, "loading");
    expect(loading.provider).toBe("sanctuary_memory");
    expect(loading.plugin_loaded).toBe(true);
    expect(loading.memory_store_none).toBe(true);
    expect(loading.spawns).toBe(1);

    const saved = await fixture.session(python!, "save");
    expect(saved.results).toEqual([{ outcome: "saved", message: "Saved." }]);
    const rows = await fixture.audit();
    const inserts = rows.filter(row => row.details?.kind === "insert_admitted");
    expect(inserts).toHaveLength(1);
    const passageId = String(inserts[0]!.details!.passage_id);
    expect(await fixture.document(String(inserts[0]!.details!.document_id))).toContain(savedText);

    const beforeRecall = fixture.responses.length;
    const recalled = await fixture.session(python!, "recall");
    expect(recalled.context).toContain("Thursday 3pm");
    const bridgeRecall = fixture.responses.slice(beforeRecall).find(value => value.outcome === "recalled");
    expect(recalled.provider_sha256).toBe(digest(String(bridgeRecall!.context)));
    const recallRows = (await fixture.audit()).filter(row => row.details?.kind === "memory_recall" && (row.details?.passage_ids as string[]).includes(passageId));
    expect(recallRows).toHaveLength(1);
    expect(recallRows[0]!.details!.passage_ids).toEqual([passageId]);
    expect(JSON.stringify(await fixture.audit())).not.toContain(query);
    expect(recalled.shim_log).not.toContain(query);
    expect(recalled.hermes_log).not.toContain(query);
    expect(recalled.executed_tools).not.toContain("session_search");

    const runs = [];
    for (let run = 0; run < runsRequired; run++) {
      const report = await fixture.session(python!, "recall");
      const measured = { prefetch_ms: report.prefetch_ms, ready_ms: report.ready_ms,
        within_budget: report.prefetch_ms <= RECALL_PREFETCH_BUDGET_MS,
        context_has_answer: report.context.includes("Thursday 3pm") };
      runs.push(measured);
      expect(measured.within_budget).toBe(true);
      expect(measured.context_has_answer).toBe(true);
    }
    if (process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR) {
      await mkdir(process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR, { recursive: true });
      await writeFile(join(process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR, "cold-recall.json"), JSON.stringify({ runs }));
    }
    console.info("Cold recall measurements:", JSON.stringify({ runs }));

    for (const interpreter of [python!, ...(python019 ? [python019] : [])]) {
      if (interpreter === python019) {
        const report = await fixture.session(interpreter, "loading");
        expect(report.provider).toBe("sanctuary_memory");
        expect(report.plugin_loaded).toBe(true);
        expect(report.memory_store_none).toBe(true);
        expect(report.spawns).toBe(1);
      }
      for (const scenario of ["refusals", "refusals-concurrent"]) {
        const report = await fixture.session(interpreter, scenario);
        expect(report.results).toEqual([refusal, denied, refusal]);
        expect(report.classified_failures).toEqual([false, false, false]);
        expect(report.failure_count).toBe(0);
        expect(report.hermes_log).not.toContain("consecutive failures");
        expect(JSON.stringify(report.results)).not.toMatch(/error|failed/i);
        expect(report.shim_lines.every((line: Record<string, unknown>) => !("error" in line))).toBe(true);
      }
      const guard = await fixture.session(interpreter, "guard");
      expect(guard.blocked_message).toBe(denied.message);
      expect(guard.native_calls).toBe(1);
      expect(guard.ordinary_ran).toBe(true);
      expect(guard.own_directives).toEqual([null, null, null, null]);
      expect(guard.own_results.every((result: Record<string, unknown>) => "outcome" in result && !("error" in result))).toBe(true);
      expect(guard.directive.action).toBe("block");
    }

    const beforeFault = (await fixture.audit()).filter(row => row.details?.kind === "insert_admitted").length;
    const fault = await fixture.session(python!, "fault-insert");
    expect(fault.results).toEqual([{ outcome: "unconfirmed", message: "I could not confirm whether this completed." }]);
    expect(fault.insert_requests).toBeLessThanOrEqual(1);
    expect((await fixture.audit()).filter(row => row.details?.kind === "insert_admitted").length - beforeFault).toBeLessThanOrEqual(1);
    const missing = await fixture.session(python!, "no-shim");
    expect(missing.results).toEqual([{ outcome: "unavailable", message: "Sanctuary could not take this request right now; nothing was done." }]);
    expect(missing.context).toBe("");
    expect(missing.within_budgets).toBe(true);
    if (python019) {
      const observations = [];
      for (const order of ["block-first", "approve-first"]) observations.push(await fixture.session(python019, order));
      console.info("Hermes directive observations:", JSON.stringify(observations));
      if (process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR) {
        await writeFile(join(process.env.SANCTUARY_PLUGIN_EVIDENCE_DIR, "directive-orders.json"), JSON.stringify(observations));
      }
    }
  }, 240_000); // Two Hermes versions and independent cold processes share a four-minute outer bound.
});
