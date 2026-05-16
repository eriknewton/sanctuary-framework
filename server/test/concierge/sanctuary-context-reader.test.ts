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
