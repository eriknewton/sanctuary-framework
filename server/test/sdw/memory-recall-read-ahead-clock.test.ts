// At the default window, on a clock driven by when reads complete, the known context from the first passage is kept
// and the call reports truncation when the reserve is reached after the next passage's reads complete.
import { expect, it } from "vitest";
import { HermesRecallBudget, RECALL_VERIFY_RESERVE_MS, RECALL_WALL_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { KeyOrderMemoryStorage } from "./recall-score-first-fixture.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const CREATED = "2026-11-01T00:00:00.000Z";
const FALLBACK_TURNS = 100; // A hundred event-loop turns: far more than a's reads and commit need in this in-memory store.

it("keeps the first passage's context and reports truncation when the reserve is reached as the next passage's reads complete", async () => {
  const storage = new KeyOrderMemoryStorage();
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: new Uint8Array(32).fill(17),
    fortressId: "completion-clock", ownerRef: "agent", now: () => CREATED });
  await adapter.insertPassage({ passage_id: "a", text: "board meeting" }, "user_content");
  await adapter.insertPassage({ passage_id: "b", text: "board meeting later" }, "user_content");
  let now = 0;
  let openGate!: () => void;
  const gate = new Promise<void>(resolve => { openGate = resolve; });
  const original = storage.read.bind(storage);
  storage.read = async (namespace, key) => {
    const ofB = key.endsWith("mem.agent.b");
    if (ofB) await gate;
    const value = await original(namespace, key);
    // The clock is driven by completion: reaching b's bytes takes the call to the verification reserve.
    if (ofB) now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS;
    return value;
  };
  class ObservedBudget extends HermesRecallBudget {
    // b's reads complete once a has been decided, as they would after a's own reads in real time; a build that never
    // decides a before b completes gets b's completion after a bounded fallback instead.
    override score(...args: Parameters<HermesRecallBudget["score"]>) {
      if (args[0].passage_id === "a") openGate();
      return super.score(...args);
    }
  }
  void (async () => { for (let n = 0; n < FALLBACK_TURNS; n++) await new Promise<void>(resolve => setImmediate(resolve)); openGate(); })();
  const result = await adapter.recallPassages(new ObservedBudget("board meeting", () => now, new AbortController().signal));
  expect(result).toEqual({ outcome: "recalled", truncated: true,
    passages: [{ passage_id: "a", created_at: CREATED }], context: "- (saved 2026-11-01) board meeting\n" });
});
