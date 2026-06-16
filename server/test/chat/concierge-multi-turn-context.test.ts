/**
 * Concierge Multi-Turn Coherence Tests (WP-V1.3-9 Tau-2)
 *
 * Verifies the read-side fold that surfaces prior turns to the
 * substrate so the concierge maintains coherence across a session:
 *
 *   - sliding-window context: prior N turns appear in substrate context
 *   - 10-turn cap: 13th turn folds only the most recent 10 turns
 *   - 24h freshness: turns older than the cutoff drop out of the fold
 *   - token-budget pruning: oldest turns drop first when over budget
 *   - session-TTL rotation: a fresh thread_id is allocated after quiet
 *   - graceful degradation: a corrupted bundle emits the failure event
 *     and the round-trip proceeds single-turn
 *   - thread_id + turn_index fields on operator_concierge_chat events
 *   - existing single-turn happy path still works without memory wired
 *   - audit safe-metadata: raw bodies never appear in audit details
 *
 * The substrate selector exposes a `context: string` shape (not a
 * messages array) so the fold renders a structured "## Prior
 * conversation" section with explicit OPERATOR / CONCIERGE turn
 * boundaries.
 */

import { describe, it, expect, vi } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  ConciergeMemoryStore,
  CONCIERGE_MEMORY_KEY_PREFIX,
  CONCIERGE_MEMORY_NAMESPACE,
  OPERATOR_CHAT_OPS,
  OperatorChatService,
  OperatorChatStore,
} from "../../src/chat/operator-chat-index.js";
import type { OperatorChatServiceDeps } from "../../src/chat/operator-chat-service.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type {
  SubstrateHandle,
  SubstrateResponse,
  SummarizeRequest,
} from "../../src/intelligence/types.js";

const TEST_IDENTITY = "tau2-operator";
const TEST_FORTRESS = "tau2-fortress";

interface CapturedSelector {
  selector: SubstrateSelector;
  contexts: string[];
  responses: string[];
}

function makeCapturingSelector(opts?: {
  responseFor?: (req: SummarizeRequest, callIndex: number) => string;
}): CapturedSelector {
  const contexts: string[] = [];
  const responses: string[] = [];

  const handle: SubstrateHandle = {
    surface: "concierge",
    substrate: "local",
    badge: {
      surface: "concierge",
      substrate: "local",
      labelKey: "test",
      tradeoffKey: "test",
      status: "green",
    },
    capability: { summarize: true, classify: false, redact: false },
    displayLabel: "Test Local",
  };

  let callCount = 0;
  const selector = {
    getSubstrate: vi.fn().mockResolvedValue(handle),
    invokeSummarize: vi.fn(
      async (
        _surface: string,
        req: SummarizeRequest,
      ): Promise<SubstrateResponse> => {
        contexts.push(req.context);
        const text = opts?.responseFor
          ? opts.responseFor(req, callCount)
          : `mock response ${callCount + 1}`;
        callCount += 1;
        responses.push(text);
        return {
          servedBy: "local",
          failureClass: null,
          body: { kind: "summarize" as const, text },
          completedAt: new Date().toISOString(),
          latencyMs: 10,
        };
      },
    ),
  } as unknown as SubstrateSelector;

  return { selector, contexts, responses };
}

interface BuildOptions {
  withMemory?: boolean;
  selector?: SubstrateSelector;
  contextProviders?: OperatorChatServiceDeps["conciergeContextProviders"];
  historyWindowTurns?: number;
  historyFreshnessMs?: number;
  historyTokenBudget?: number;
  sessionTtlMs?: number;
  clock?: () => number;
}

function buildService(opts: BuildOptions = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);
  const memory =
    opts.withMemory === false
      ? undefined
      : new ConciergeMemoryStore({
          storage,
          masterKey,
          fortressId: TEST_FORTRESS,
        });
  const deps: OperatorChatServiceDeps = {
    store,
    auditLog,
    identityId: TEST_IDENTITY,
    ...(memory ? { conciergeMemory: memory } : {}),
    ...(opts.selector ? { substrateSelector: opts.selector } : {}),
    ...(opts.contextProviders
      ? { conciergeContextProviders: opts.contextProviders }
      : {}),
    ...(opts.historyWindowTurns !== undefined
      ? { conciergeHistoryWindowTurns: opts.historyWindowTurns }
      : {}),
    ...(opts.historyFreshnessMs !== undefined
      ? { conciergeHistoryFreshnessMs: opts.historyFreshnessMs }
      : {}),
    ...(opts.historyTokenBudget !== undefined
      ? { conciergeHistoryTokenBudget: opts.historyTokenBudget }
      : {}),
    ...(opts.sessionTtlMs !== undefined
      ? { conciergeSessionTtlMs: opts.sessionTtlMs }
      : {}),
    ...(opts.clock ? { conciergeClock: opts.clock } : {}),
  };
  const service = new OperatorChatService(deps);
  return { service, auditLog, store, memory, storage };
}

describe("OperatorChatService — Tau-2 multi-turn coherence", () => {
  it("folds prior turns into the substrate context across a 5-turn session", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service } = buildService({ selector });

    const queries = ["one", "two", "three", "four", "five", "six"];
    for (const q of queries) await service.sendConcierge(q);

    expect(contexts.length).toBe(6);
    // First call: no prior conversation section.
    expect(contexts[0]!).not.toContain("## Prior conversation");
    // Sixth call carries five prior round-trips (10 turns).
    const ctx6 = contexts[5]!;
    expect(ctx6).toContain("## Prior conversation");
    expect(ctx6).toContain("OPERATOR: one");
    expect(ctx6).toContain("OPERATOR: five");
    expect(ctx6).toContain("CONCIERGE: mock response 1");
    expect(ctx6).toContain("CONCIERGE: mock response 5");
    // The current operator query is the substrate's `query` arg, not
    // folded into the prior-conversation block.
    expect(ctx6).not.toContain("OPERATOR: six");
  });

  it("caps the prior-turn window at the configured size", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service } = buildService({ selector, historyWindowTurns: 10 });

    // 12 round-trips (24 turns total) before the 13th triggers the cap.
    for (let i = 1; i <= 12; i++) {
      await service.sendConcierge(`q${i}`);
    }
    await service.sendConcierge("q13");

    const ctx13 = contexts[12]!;
    expect(ctx13).toContain("## Prior conversation");
    // Most-recent 10 turns kept; 14 oldest dropped.
    expect(ctx13).toContain("OPERATOR: q12");
    expect(ctx13).toContain("CONCIERGE: mock response 12");
    // Earliest q1 / q2 must be outside the window of the 13th call.
    const priorSection = ctx13.split("## Prior conversation")[1] ?? "";
    const operatorMentions = priorSection.match(/^OPERATOR: /gm) ?? [];
    const conciergeMentions = priorSection.match(/^CONCIERGE: /gm) ?? [];
    expect(operatorMentions.length + conciergeMentions.length).toBe(10);
    expect(priorSection).not.toContain("OPERATOR: q1\n");
    expect(priorSection).not.toContain("OPERATOR: q2\n");
  });

  it("excludes turns older than the freshness window", async () => {
    const { selector, contexts } = makeCapturingSelector();
    // Use a deterministic injected clock so the freshness window check
    // is exact: prior turns are written at t=1000, the third call runs
    // at t=1000 + 25h, freshness is 24h, so the prior turns are stale.
    let now = 1_000;
    const clock = () => now;
    const { service } = buildService({
      selector,
      historyFreshnessMs: 24 * 60 * 60 * 1000,
      clock,
    });

    await service.sendConcierge("warm one");
    await service.sendConcierge("warm two");
    // Note: turn `created_at` uses real Date() inside the memory store,
    // so we cannot inject the freshness-cutoff time perfectly through
    // the clock alone. The freshness filter compares Date.parse(turn.created_at)
    // against `clock() - freshnessMs`. With clock() = 1000 + 25h and
    // freshness = 24h, cutoff = 1h after epoch boot, which is still
    // well past the actual real-clock created_at (Date.now() at
    // sendConcierge time). So the freshness check WILL see the seeded
    // turns as stale only if the cutoff is in the future relative to
    // their created_at.
    //
    // To make this deterministic, advance the clock past +25h AND
    // ensure the cutoff exceeds the real-time created_at: set the
    // injected clock to a far future ms.
    now = Date.now() + 25 * 60 * 60 * 1000;
    await service.sendConcierge("after-freshness");

    const lastCtx = contexts[contexts.length - 1]!;
    expect(lastCtx).not.toContain("## Prior conversation");
  });

  it("prunes oldest turns first when prior-conversation exceeds the token budget", async () => {
    const { selector, contexts } = makeCapturingSelector();
    // 50-token budget so even modest turns force pruning.
    const { service } = buildService({ selector, historyTokenBudget: 50 });

    const longish = "a".repeat(80); // ~20 tokens per turn after rendering
    for (let i = 1; i <= 6; i++) {
      await service.sendConcierge(`${longish} ${i}`);
    }
    await service.sendConcierge("budget-final");

    const lastCtx = contexts[6]!;
    expect(lastCtx).toContain("## Prior conversation");
    // Most recent turn (i=6) must survive the budget.
    expect(lastCtx).toContain("OPERATOR: " + longish + " 6");
    // Oldest turn (i=1) must NOT survive — at least one earlier turn
    // dropped out.
    expect(lastCtx).not.toContain("OPERATOR: " + longish + " 1");
  });

  it("rotates to a fresh thread_id after the session-TTL elapses", async () => {
    let now = 1_000_000;
    const clock = () => now;
    const { selector, contexts } = makeCapturingSelector();
    const { service, memory } = buildService({
      selector,
      sessionTtlMs: 60_000,
      clock,
    });

    await service.sendConcierge("session-A turn 1");
    const summariesA = await memory!.listThreads();
    expect(summariesA).toHaveLength(1);
    const threadA = summariesA[0]!.thread_id;

    // Advance clock past the TTL.
    now += 70_000;
    await service.sendConcierge("session-B turn 1");

    const summariesB = await memory!.listThreads();
    expect(summariesB).toHaveLength(2);
    const threadIds = summariesB.map((s) => s.thread_id);
    expect(threadIds).toContain(threadA);
    expect(threadIds.find((id) => id !== threadA)).toBeDefined();

    // The substrate context for the second session has no prior fold
    // even though session-A turns exist on disk.
    expect(contexts[1]!).not.toContain("## Prior conversation");
  });

  it("does NOT rotate the thread_id when activity stays within the TTL window", async () => {
    let now = 2_000_000;
    const clock = () => now;
    const { selector } = makeCapturingSelector();
    const { service, memory } = buildService({
      selector,
      sessionTtlMs: 60_000,
      clock,
    });

    await service.sendConcierge("first");
    now += 30_000; // half of TTL
    await service.sendConcierge("second");
    now += 30_000;
    await service.sendConcierge("third");

    const summaries = await memory!.listThreads();
    expect(summaries).toHaveLength(1);
    expect(summaries[0]!.turn_count).toBe(6);
  });

  it("emits operator_concierge_memory_read_failed and degrades to single-turn on a corrupted bundle", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service, auditLog, memory, storage } = buildService({ selector });

    // Seed two turns.
    await service.sendConcierge("first turn that succeeds");
    const summaries = await memory!.listThreads();
    expect(summaries).toHaveLength(1);
    const threadId = summaries[0]!.thread_id;

    // Corrupt the on-disk bundle by overwriting it with garbage. The
    // memory store stores a JSON envelope; we replace it with bytes
    // that will fail JSON.parse → schema_mismatch.
    await storage.write(
      CONCIERGE_MEMORY_NAMESPACE,
      `${CONCIERGE_MEMORY_KEY_PREFIX}${threadId}`,
      new TextEncoder().encode("this is not a valid envelope"),
    );

    const response = await service.sendConcierge("second turn after corruption");
    // The user-facing call still succeeds — the substrate was invoked.
    expect(response.outcome).toBe("ok");
    // Substrate context for the second call carries no prior fold.
    expect(contexts[1]!).not.toContain("## Prior conversation");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_MEMORY_READ_FAILED,
      limit: 5,
    });
    expect(result.entries.length).toBe(1);
    const entry = result.entries[0]!;
    expect(entry.result).toBe("failure");
    const details = entry.details as Record<string, unknown>;
    expect(details.kind).toBe("operator_concierge_memory_read_failed");
    expect(details.thread_id).toBe(threadId);
    expect(typeof details.failure_reason).toBe("string");
  });

  it("operator_concierge_chat events carry thread_id + turn_index when memory is wired", async () => {
    const { selector } = makeCapturingSelector();
    const { service, auditLog, memory } = buildService({ selector });

    await service.sendConcierge("turn one");
    await service.sendConcierge("turn two");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
      limit: 10,
    });
    expect(result.entries.length).toBe(2);

    const summaries = await memory!.listThreads();
    const threadId = summaries[0]!.thread_id;
    const detailsList = result.entries.map(
      (e) => e.details as Record<string, unknown>,
    );
    for (const details of detailsList) {
      expect(details.thread_id).toBe(threadId);
      expect(typeof details.turn_index).toBe("number");
      expect(typeof details.prior_turns_folded).toBe("number");
    }
    // First entry: 0 prior turns folded; assistant turn id = 2.
    // Second entry: 2 prior turns folded; assistant turn id = 4.
    const sorted = detailsList.sort(
      (a, b) => (a.turn_index as number) - (b.turn_index as number),
    );
    expect(sorted[0]!.turn_index).toBe(2);
    expect(sorted[0]!.prior_turns_folded).toBe(0);
    expect(sorted[1]!.turn_index).toBe(4);
    expect(sorted[1]!.prior_turns_folded).toBe(2);
  });

  it("does not stamp thread_id / turn_index when memory is not wired", async () => {
    const { selector } = makeCapturingSelector();
    const { service, auditLog } = buildService({
      selector,
      withMemory: false,
    });

    await service.sendConcierge("memoryless");
    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
      limit: 5,
    });
    const details = result.entries[0]!.details as Record<string, unknown>;
    expect(details.thread_id).toBeUndefined();
    expect(details.turn_index).toBeUndefined();
    expect(details.prior_turns_folded).toBeUndefined();
  });

  it("renders prior turns with explicit OPERATOR / CONCIERGE boundaries", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service } = buildService({ selector });

    await service.sendConcierge("first question");
    await service.sendConcierge("follow-up");

    const ctx2 = contexts[1]!;
    const priorSection = ctx2.split("## Prior conversation")[1] ?? "";
    expect(priorSection).toMatch(/OPERATOR:\s+first question/);
    expect(priorSection).toMatch(/CONCIERGE:\s+mock response 1/);
  });

  it("preserves the existing single-turn happy path when memory is wired but is the first turn", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service } = buildService({ selector });
    const response = await service.sendConcierge("first ever");
    expect(response.outcome).toBe("ok");
    expect(contexts[0]!).not.toContain("## Prior conversation");
  });

  it("audit safe-metadata: raw turn bodies never appear in operator_concierge_chat details", async () => {
    const { selector } = makeCapturingSelector();
    const { service, auditLog } = buildService({ selector });

    await service.sendConcierge("super-secret-query-12345");
    await service.sendConcierge("another-super-secret-query-67890");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
      limit: 10,
    });
    for (const entry of result.entries) {
      const blob = JSON.stringify(entry.details ?? {});
      expect(blob).not.toContain("super-secret-query-12345");
      expect(blob).not.toContain("another-super-secret-query-67890");
    }
  });

  it("resetConciergeMemoryThread mid-session forces a fresh thread on the next call", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const { service, memory } = buildService({ selector });

    await service.sendConcierge("alpha");
    await service.sendConcierge("beta");
    expect((await memory!.listThreads())).toHaveLength(1);

    service.resetConciergeMemoryThread();
    await service.sendConcierge("gamma");

    const summaries = await memory!.listThreads();
    expect(summaries).toHaveLength(2);
    // The third substrate call must NOT carry the old prior conversation.
    expect(contexts[2]!).not.toContain("## Prior conversation");
  });

  it("PII filter applies to the current query but does NOT rewrite the prior fold", async () => {
    const { selector, contexts } = makeCapturingSelector();
    const piiFilter = {
      filter(input: string) {
        const out = input.replace(/\bSECRET\b/g, "[REDACTED]");
        return { filtered: out, redactions: out === input ? 0 : 1 };
      },
    };
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const store = new OperatorChatStore(storage, masterKey);
    const memory = new ConciergeMemoryStore({
      storage,
      masterKey,
      fortressId: TEST_FORTRESS,
    });
    const service = new OperatorChatService({
      store,
      auditLog,
      identityId: TEST_IDENTITY,
      conciergeMemory: memory,
      substrateSelector: selector,
      conciergePiiFilter: piiFilter,
    });

    // First call: SECRET in body persists raw to memory store; the
    // SUBSTRATE sees the redacted form via `query`. The persistence
    // layer holds the operator's actual words so the operator can
    // scroll history and see what they typed.
    await service.sendConcierge("the SECRET is hidden");
    await service.sendConcierge("follow-up question");

    const ctx2 = contexts[1]!;
    // Prior fold contains the unredacted operator turn (operator
    // confidentiality stays inside the fortress; the substrate already
    // saw a redacted query for THAT turn).
    expect(ctx2).toContain("OPERATOR: the SECRET is hidden");
  });

  it("survives a memory.readThreadStrict throw (returns io_failed shape)", async () => {
    const { selector } = makeCapturingSelector();
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const store = new OperatorChatStore(storage, masterKey);
    const memory = new ConciergeMemoryStore({
      storage,
      masterKey,
      fortressId: TEST_FORTRESS,
    });
    // Replace readThreadStrict with one that throws synchronously.
    (memory as unknown as { readThreadStrict: () => Promise<never> }).readThreadStrict =
      vi.fn().mockRejectedValue(new Error("disk on fire"));

    const service = new OperatorChatService({
      store,
      auditLog,
      identityId: TEST_IDENTITY,
      conciergeMemory: memory,
      substrateSelector: selector,
    });

    const response = await service.sendConcierge("query in a fire");
    expect(response.outcome).toBe("ok");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_MEMORY_READ_FAILED,
      limit: 5,
    });
    expect(result.entries.length).toBe(1);
    const details = result.entries[0]!.details as Record<string, unknown>;
    expect(details.failure_reason).toBe("io_failed");
  });

  it("turn_index increments across a multi-turn session and matches assistant turn ids", async () => {
    const { selector } = makeCapturingSelector();
    const { service, auditLog, memory } = buildService({ selector });

    await service.sendConcierge("a");
    await service.sendConcierge("b");
    await service.sendConcierge("c");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
      limit: 10,
    });
    const turnIndices = result.entries
      .map((e) => (e.details as Record<string, unknown>).turn_index as number)
      .sort((x, y) => x - y);
    expect(turnIndices).toEqual([2, 4, 6]);

    const summaries = await memory!.listThreads();
    expect(summaries[0]!.turn_count).toBe(6);
  });

  it("does not fold prior turns when the substrate selector is not wired", async () => {
    const { service, auditLog } = buildService({});
    const response = await service.sendConcierge("sub-disabled");
    expect(response.outcome).toBe("substrate_disabled");

    await auditLog.flush();
    const result = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
      limit: 5,
    });
    expect(result.entries.length).toBe(1);
    const details = result.entries[0]!.details as Record<string, unknown>;
    // Memory wired by default → thread_id present; substrate disabled
    // means no fold actually went out, but the contract still records
    // the active thread id.
    expect(typeof details.thread_id).toBe("string");
    expect(details.outcome).toBe("substrate_disabled");
  });
});
