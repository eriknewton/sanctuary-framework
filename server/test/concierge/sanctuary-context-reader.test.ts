import { describe, expect, it } from "vitest";
import { SanctuaryContextReader } from "../../src/concierge/index.js";

function makeReader(overrides: Partial<ConstructorParameters<typeof SanctuaryContextReader>[0]> = {}) {
  return new SanctuaryContextReader({
    auditLog: {
      query: async () => ({
        total: 1,
        entries: [{
          timestamp: "2026-05-16T00:00:00.000Z",
          layer: "l2",
          operation: "approval_request",
          identity_id: "operator",
          result: "success",
        }],
        integrity_findings: [],
      }),
      append: async () => undefined,
    },
    identityManager: {
      listWithRotationCount: () => [{
        identity_id: "operator",
        label: "Operator",
        public_key: "pub",
        did: "did:key:test",
        created_at: "2026-05-16T00:00:00.000Z",
        key_type: "ed25519",
        key_protection: "passphrase",
        rotation_count: 0,
      }],
      list: () => [],
    },
    inboxSources: {
      listPendingApprovals: () => [{
        version: "1.1",
        item_id: "approval-1",
        kind: "approval_pending",
        created_at: "2026-05-16T00:00:00.000Z",
        identity_id: "operator",
        display_template_id: "approval.test",
        display_template_args: [],
        resolved: false,
        tier: "tier1",
        operation_category: "policy_change",
      }],
      listRecentBlockedEgress: () => [],
      listRecentPrivacyEvents: () => [],
      listActiveBudgetWarnings: () => [],
      listActiveRecoveryPrompts: () => [],
      listRecentAgentErrors: () => [],
    },
    taskService: {
      list: async () => [{
        id: "task-1",
        fortress_id: "fortress-a",
        title: "Test task",
        creator: "operator",
        status: "pending",
        created_at: "2026-05-16T00:00:00.000Z",
        updated_at: "2026-05-16T00:00:00.000Z",
        schema_version: 1,
      }],
    },
    stateStore: {
      list: async () => ({
        total: 1,
        merkle_root: "root",
        keys: [{
          key: "fortress-a/task-1",
          version: 1,
          size_bytes: 10,
          written_at: "2026-05-16T00:00:00.000Z",
          tags: ["task"],
        }],
      }),
      read: async () => ({
        key: "fortress-a/task-1",
        namespace: "sanctuary.tasks",
        value: "payload",
        version: 1,
        integrity_verified: true,
        signature_verified: true,
        merkle_proof: [],
        written_at: "2026-05-16T00:00:00.000Z",
        written_by: "pub",
      }),
    },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    fortressId: "fortress-a",
    identityId: "operator",
    ...overrides,
  });
}

describe("SanctuaryContextReader", () => {
  it("returns all configured read-surface shapes", async () => {
    const context = await makeReader().readContext({
      question: "how many pending approvals are there?",
      stream: false,
      now: new Date("2026-05-16T00:00:30.000Z"),
    });

    expect(context.read_surfaces).toEqual([
      "audit_log",
      "identity_registry",
      "approval_inbox",
      "sovereignty_profile",
      "task_state",
      "state_store",
    ]);
    expect(context.approval_inbox.pending_count).toBe(1);
    expect(context.task_state.status_counts.pending).toBe(1);
    expect(context.state_store.namespaces[0]!.recent_keys[0]).not.toHaveProperty("payload");
  });

  it("does not include state payloads unless explicitly requested", async () => {
    const context = await makeReader().readContext({
      question: "show state",
      stream: false,
      includePayloads: true,
    });

    expect(context.state_store.namespaces[0]!.recent_keys[0]!.payload).toBe("payload");
  });

  it("keeps fortress reads scoped to the supplied task service", async () => {
    const readerA = makeReader();
    const readerB = makeReader({
      fortressId: "fortress-b",
      taskService: { list: async () => [] },
      auditLog: {
        query: async () => ({ total: 0, entries: [], integrity_findings: [] }),
        append: async () => undefined,
      },
    });

    expect((await readerA.readContext({ question: "tasks" })).task_state.total).toBe(1);
    expect((await readerB.readContext({ question: "tasks" })).task_state.total).toBe(0);
  });
});

/**
 * `maxAuditEntries` rides on the caller-supplied ask request, so it is a knob
 * on how much work this fortress does to answer one question. Unclamped, a
 * single `ask` could drive an arbitrarily large audit query and decryption
 * pass; nothing downstream could ever use the rows, because the prompt
 * projection caps the rendered bundle far below the ceiling.
 */
describe("the concierge audit read is clamped, whatever the caller asks for", () => {
  function readerRecordingLimit(limits: number[]) {
    return makeReader({
      auditLog: {
        query: async (query: { limit: number }) => {
          limits.push(query.limit);
          return { total: 0, entries: [], integrity_findings: [] };
        },
        append: async () => undefined,
      },
    } as never);
  }

  it("clamps an oversized request to the ceiling", async () => {
    const limits: number[] = [];
    await readerRecordingLimit(limits).readContext({
      question: "audit",
      maxAuditEntries: 1_000_000,
    });
    expect(limits).toEqual([100]);
  });

  it("passes an in-range request through unchanged", async () => {
    const limits: number[] = [];
    await readerRecordingLimit(limits).readContext({
      question: "audit",
      maxAuditEntries: 25,
    });
    expect(limits).toEqual([25]);
  });

  it("floors a zero, negative, or fractional request instead of querying with it", async () => {
    // A negative or NaN limit is not a smaller query, it is a malformed one:
    // the storage layer would see a bound it cannot honor.
    for (const [requested, expected] of [[0, 1], [-5, 1], [3.7, 3], [Number.NaN, 20]] as const) {
      const limits: number[] = [];
      await readerRecordingLimit(limits).readContext({
        question: "audit",
        maxAuditEntries: requested,
      });
      expect(limits, `maxAuditEntries=${requested}`).toEqual([expected]);
    }
  });

  it("keeps the question-derived defaults when no limit is supplied", async () => {
    const audit: number[] = [];
    await readerRecordingLimit(audit).readContext({ question: "show me the audit log" });
    expect(audit).toEqual([50]);
    const other: number[] = [];
    await readerRecordingLimit(other).readContext({ question: "how many identities?" });
    expect(other).toEqual([20]);
  });
});
