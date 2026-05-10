/**
 * Concierge Memory Service Wire-Up Tests (WP-V1.3-9 Tau-1)
 *
 * Verifies the operator-chat-service dual-write + memory accessors:
 *   - sendConcierge dual-writes to OperatorChatStore + ConciergeMemoryStore
 *   - active session reuses the same thread_id across multiple turns
 *   - readConciergeMemoryThread surfaces both turns oldest-first
 *   - listConciergeMemoryThreads returns the active thread + emits
 *     operator_concierge_history_read with thread_id="*" and total turn count
 *   - deleteConciergeMemoryThread emits operator_concierge_thread_deleted
 *     and clears the active thread_id
 *   - existing concierge happy-path (single-turn) still works (regression)
 *   - service constructed without a memory store keeps working
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import {
  ConciergeMemoryStore,
  OperatorChatService,
  OperatorChatStore,
  CONCIERGE_THREAD_KEY,
  OPERATOR_CHAT_OPS,
} from "../../src/chat/operator-chat-index.js";

const TEST_IDENTITY = "test-operator-tau1";
const TEST_FORTRESS = "fortress-tau1-service";

function buildWiredService(opts?: { withMemory?: boolean }) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);
  const memory =
    opts?.withMemory === false
      ? undefined
      : new ConciergeMemoryStore({
          storage,
          masterKey,
          fortressId: TEST_FORTRESS,
        });
  const service = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
    ...(memory ? { conciergeMemory: memory } : {}),
  });
  return { service, auditLog, store, memory, storage };
}

describe("OperatorChatService — concierge memory wire-up (Tau-1)", () => {
  it("sendConcierge dual-writes to both OperatorChatStore and ConciergeMemoryStore", async () => {
    const { service, store, memory } = buildWiredService();
    expect(memory).toBeDefined();

    await service.sendConcierge("first turn from the operator");

    // Existing single-thread store carries the operator + concierge
    // messages.
    const legacy = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(legacy?.messages.length).toBe(2);
    expect(legacy?.messages[0]?.role).toBe("operator");

    // The new memory store carries the same pair under a
    // service-allocated thread_id.
    const summaries = await memory!.listThreads();
    expect(summaries).toHaveLength(1);
    const turns = await memory!.readThread(summaries[0]!.thread_id);
    expect(turns).toHaveLength(2);
    expect(turns[0]?.role).toBe("user");
    expect(turns[1]?.role).toBe("assistant");
  });

  it("the active session reuses the same thread_id across multiple sendConcierge calls", async () => {
    const { service, memory } = buildWiredService();

    await service.sendConcierge("turn A");
    await service.sendConcierge("turn B");
    await service.sendConcierge("turn C");

    const summaries = await memory!.listThreads();
    expect(summaries).toHaveLength(1);
    expect(summaries[0]?.turn_count).toBe(6); // 3 user + 3 assistant
  });

  it("listConciergeMemoryThreads emits operator_concierge_history_read with safe metadata", async () => {
    const { service, auditLog } = buildWiredService();
    await service.sendConcierge("seed-turn");
    await service.sendConcierge("another seed-turn");

    const threads = await service.listConciergeMemoryThreads();
    expect(threads.length).toBeGreaterThanOrEqual(1);

    await auditLog.flush();
    const { entries } = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_HISTORY_READ,
      limit: 10,
    });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    const last = entries[entries.length - 1]!;
    const details = last.details as Record<string, unknown>;
    expect(details.kind).toBe("operator_concierge_history_read");
    expect(details.surface).toBe("concierge");
    expect(details.thread_id).toBe("*");
    expect(typeof details.turn_count).toBe("number");
    // Safe-metadata invariant: no raw turn body should appear.
    const serialized = JSON.stringify(details);
    expect(serialized).not.toContain("seed-turn");
    expect(serialized).not.toContain("another seed-turn");
  });

  it("readConciergeMemoryThread emits operator_concierge_history_read tagged with the thread_id", async () => {
    const { service, auditLog, memory } = buildWiredService();
    await service.sendConcierge("scrollback test");
    const summaries = await memory!.listThreads();
    const threadId = summaries[0]!.thread_id;

    const turns = await service.readConciergeMemoryThread(threadId);
    expect(turns).toHaveLength(2);

    await auditLog.flush();
    const { entries } = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_HISTORY_READ,
      limit: 10,
    });
    const last = entries[entries.length - 1]!;
    const details = last.details as Record<string, unknown>;
    expect(details.thread_id).toBe(threadId);
    expect(details.turn_count).toBe(2);
  });

  it("deleteConciergeMemoryThread emits the deleted event and clears the active thread", async () => {
    const { service, auditLog, memory } = buildWiredService();
    await service.sendConcierge("about to be deleted");
    const summaries = await memory!.listThreads();
    const threadId = summaries[0]!.thread_id;

    const removed = await service.deleteConciergeMemoryThread(threadId);
    expect(removed).toBe(true);

    await auditLog.flush();
    const { entries } = await auditLog.query({
      operation_type: OPERATOR_CHAT_OPS.CONCIERGE_THREAD_DELETED,
      limit: 5,
    });
    expect(entries.length).toBe(1);
    const details = entries[0]!.details as Record<string, unknown>;
    expect(details.kind).toBe("operator_concierge_thread_deleted");
    expect(details.thread_id).toBe(threadId);
    expect(details.turn_count).toBe(2);

    // Subsequent send creates a fresh thread (active id was cleared).
    await service.sendConcierge("after-delete turn");
    const summariesAfter = await memory!.listThreads();
    expect(summariesAfter).toHaveLength(1);
    expect(summariesAfter[0]?.thread_id).not.toBe(threadId);
  });

  it("existing concierge happy-path still works without a memory store wired", async () => {
    const { service } = buildWiredService({ withMemory: false });
    expect(service.hasConciergeMemory()).toBe(false);

    const response = await service.sendConcierge("hello fortress");
    expect(response.outcome).toBe("substrate_disabled");
    const history = await service.getConciergeHistory();
    expect(history.length).toBe(2);
  });

  it("memory accessors throw when the memory store is not wired", async () => {
    const { service } = buildWiredService({ withMemory: false });
    await expect(service.listConciergeMemoryThreads()).rejects.toThrow(
      /not configured/,
    );
    await expect(
      service.readConciergeMemoryThread("any-thread"),
    ).rejects.toThrow(/not configured/);
    await expect(
      service.deleteConciergeMemoryThread("any-thread"),
    ).rejects.toThrow(/not configured/);
  });
});
