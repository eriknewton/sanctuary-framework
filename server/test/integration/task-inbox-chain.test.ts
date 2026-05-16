import { describe, expect, it } from "vitest";

import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { TaskService } from "../../src/l2-operational/task-coordination/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  type HubAgentController,
} from "../../src/hub/index.js";

const controller: HubAgentController = {
  async pause() {
    return "paused";
  },
  async resume() {
    return "active";
  },
  async restart() {
    return "active";
  },
  async unwrap() {
    return "unwrapping";
  },
  async lockdown() {
    return "locked_down";
  },
  async bindPolicy() {},
  async bindChannelTemplate() {},
};

describe("task to inbox approval chain", () => {
  it("creates a pending approval when a task becomes ready_for_review", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "operator",
      identityEncryptionKey,
      "recovery-key",
    );

    const hub = new HubService({
      identityId: storedIdentity.identity_id,
      fortressId: "fortress-a",
      agentRegistry: new InMemoryLocalAgentRegistry(),
      inboxSources: {
        listPendingApprovals: () => [],
        listRecentBlockedEgress: () => [],
        listRecentPrivacyEvents: () => [],
        listActiveBudgetWarnings: () => [],
        listActiveRecoveryPrompts: () => [],
        listRecentAgentErrors: () => [],
      },
      activitySources: { auditLog, identityId: storedIdentity.identity_id },
      policyBudgetSources: {
        listPolicySummaries: () => [],
        listBudgetSummaries: () => [],
      },
      agentController: controller,
    });

    const tasks = new TaskService({
      stateStore,
      auditLog,
      fortressId: "fortress-a",
      identityId: storedIdentity.identity_id,
      signingIdentity: storedIdentity,
      identityEncryptionKey,
      enqueueReviewApproval: (task, actor) =>
        hub.enqueueTaskReviewApproval(task, actor),
    });
    hub.setTaskService(tasks);

    const task = await hub.createTask({
      title: "Cross harness review",
      creator: "operator",
      assignee: "agent-a",
    });
    await hub.updateTaskStatus(task.id, {
      status: "in_progress",
      actor: "agent-a",
    });
    const ready = await hub.updateTaskStatus(task.id, {
      status: "ready_for_review",
      actor: "agent-a",
    });

    expect(ready.approval_request_id).toMatch(/^task\.review\./);
    const inbox = hub.listInbox();
    expect(inbox).toHaveLength(1);
    expect(inbox[0]).toMatchObject({
      item_id: ready.approval_request_id,
      kind: "approval_pending",
      tier: "tier2",
      operation_category: "other",
      agent_id: "agent-a",
      resolved: false,
    });

    const audit = await auditLog.query({ layer: "l2", limit: 20 });
    expect(audit.entries.map((entry) => entry.operation)).toContain(
      "task.inbox_chain",
    );
  });
});
