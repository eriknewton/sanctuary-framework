// These checks run only when SANCTUARY_HERMES_PYTHON names an installed Hermes interpreter.
// CI without Hermes skips them; installed Linux and Mac environments can run them.
// The production bridge and shim class run against temporary storage and a framing relay.
// Native Swift, its installed agent uid-502 check, and the fixed darwin entry require the attended platform drill.
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RECALL_PREFETCH_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { startFixture, type Fixture } from "./harness/fixture.js";

const python = process.env.SANCTUARY_HERMES_PYTHON;
const python019 = process.env.SANCTUARY_HERMES_PYTHON_019;
const query = "When is the board meeting?";
const savedText = "The board meeting moved to Thursday 3pm.";
const digest = (text: string) => createHash("sha256").update(text).digest("hex");
const refusal = { outcome: "unavailable", message: "This is not available yet; nothing was done." };
const denied = { outcome: "denied", message: "Request denied." };
const runsRequired = 5; // Five independent cold processes are the timing sample.
// Must match FACT, ASSISTANT_TOKEN and TOOL_TOKEN in hermes-plugin/tests/harness/drive_hermes.py.
const captureFact = "FYI, the Lisbon demo for Jamie is set for Thursday at 3pm.";
const assistantToken = "assistant-token-5f1c";
const toolToken = "tool-token-9b3e";
// Must match CAPTURE_TAG in hermes-plugin/sanctuary_memory/__init__.py.
const captureTag = "turn-capture";
const assertNoSessionSearch = (report: Record<string, unknown>) => {
  expect(Array.isArray(report.executed_tools)).toBe(true);
  expect(report.executed_tools).not.toContain("session_search");
};

describe.skipIf(!python)("Hermes persistent memory through the installed plugin pair", () => {
  let fixture: Fixture;
  beforeAll(async () => { fixture = await startFixture(); });
  afterAll(async () => { await fixture?.close(); });

  it("loads, saves, recalls, preserves refusals, guards native calls and settles transport loss", async () => {
    // Keep every session in this case so the temporary credential store survives until teardown.
    const loading = await fixture.session(python!, "recall-session-search");
    expect(loading.provider).toBe("sanctuary_memory");
    expect(loading.plugin_loaded).toBe(true);
    expect(loading.memory_store_none).toBe(true);
    expect(loading.spawns).toBe(1);

    // The same recall assertion must reject an actual inline search in the driver process.
    expect(loading.executed_tools.filter((name: string) => name === "session_search")).toHaveLength(1);
    expect(() => assertNoSessionSearch(loading)).toThrow();

    const saved = await fixture.session(python!, "save");
    expect(saved.executed_tools).toContain("remember");
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
    assertNoSessionSearch(recalled);

    const runs = [];
    for (let run = 0; run < runsRequired; run++) {
      const report = await fixture.session(python!, "recall");
      assertNoSessionSearch(report);
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

    // A plain fact with no save wording is saved by completed-turn capture, with no remember call.
    const captured = await fixture.session(python!, "capture");
    expect(captured.capture_prompt).toBe(true);
    expect(captured.executed_tools).toContain("read_file");
    expect(captured.executed_tools).not.toContain("remember");
    expect(captured.turns.fact.flushed).toBe(true);
    // The assistant reply and the tool result reached the model but never a capture frame.
    expect(captured.tool_token_reached_model).toBe(true);
    expect(captured.insert_lines_text).toContain(captureFact);
    expect(captured.insert_lines_text).not.toContain(assistantToken);
    expect(captured.insert_lines_text).not.toContain(toolToken);
    expect(captured.turns.fact.inserts).toEqual([{ text: captureFact, taint: "user_content", tags: [captureTag] }]);
    // A quoted reply, an @ expansion and an interrupted turn are never captured.
    expect(captured.expanded_has_marker).toBe(true);
    for (const label of ["reply_quote", "at_reference", "interrupted"]) {
      expect(captured.turns[label].flushed, label).toBe(true);
      expect(captured.turns[label].inserts, label).toEqual([]);
    }
    expect(captured.turns.interrupted.interrupted).toBe(true);
    const captureRows = (await fixture.audit()).filter(row => row.details?.text_sha256 === hermesBridgePassageTextDigest(captureFact));
    expect(captureRows.map(row => row.details?.kind)).toEqual(["insert_admitted"]);
    const capturedPassage = String(captureRows[0]!.details!.passage_id);
    const capturedDocument = String(captureRows[0]!.details!.document_id);
    expect(await fixture.document(capturedDocument)).toBe(captureFact);
    expect(await fixture.documentTags(capturedDocument)).toEqual([captureTag]);
    // Scoped to this capture's own entry: from its admission on, no refusal or unconfirmed row names that entry and no latch
    // row exists. Entry ids are numbered per bridge process, so rows are read from the admission onward, never before it.
    const captureEntry = String(captureRows[0]!.details!.entryId);
    expect(captureEntry).toMatch(/^hermes-entry-/);
    const auditAfterCapture = await fixture.audit();
    const admittedAt = auditAfterCapture.findIndex(row => row.details?.kind === "insert_admitted" &&
      row.details?.text_sha256 === hermesBridgePassageTextDigest(captureFact));
    expect(admittedAt).toBeGreaterThanOrEqual(0);
    const sinceCapture = auditAfterCapture.slice(admittedAt);
    expect(sinceCapture.filter(row => row.details?.entryId === captureEntry).map(row => row.details?.kind)).toEqual(["insert_admitted"]);
    expect(sinceCapture.filter(row => row.details?.kind === "latch")).toEqual([]);

    // A fresh process recalls the captured fact through Sanctuary, not session search; the question itself is not captured.
    const recalledCapture = await fixture.session(python!, "capture-recall");
    expect(recalledCapture.turns.question.inserts).toEqual([]);
    expect(recalledCapture.fact_reached_model).toBe(true);
    assertNoSessionSearch(recalledCapture);
    const captureRecall = (await fixture.audit()).filter(row => row.details?.kind === "memory_recall" && (row.details?.passage_ids as string[]).includes(capturedPassage));
    expect(captureRecall).toHaveLength(1);
    expect(captureRecall[0]!.details!.truncated).toBe(false);

    // A cron-platform agent with memory on neither captures nor is told it does.
    const cron = await fixture.session(python!, "capture-cron");
    expect(cron.turns.cron.flushed).toBe(true);
    expect(cron.turns.cron.inserts).toEqual([]);
    expect(cron.capture_prompt).toBe(false);

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
  }, 420_000); // Two Hermes versions, independent cold processes and three capture sessions share a seven-minute outer bound.
});
