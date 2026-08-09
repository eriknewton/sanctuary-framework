// fail-before-exempt: authenticated StateStore fixture wiring only; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
import { describe, expect, it } from "vitest";

import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { TaskService } from "../../src/operational/task-coordination/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  type HubAgentController,
} from "../../src/hub/index.js";
import type { Task } from "../../src/operational/task-coordination/index.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

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
    const { auditLog, hub } = await makeRig("fortress-a");

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

  it("approves a task review inbox item and completes the task", async () => {
    const { auditLog, hub } = await makeRig("fortress-a");
    const ready = await createReadyForReviewTask(hub);

    await hub.resolveInboxItem(ready.approval_request_id!, "approve");

    const completed = await hub.getTask(ready.id);
    expect(completed.status).toBe("completed");
    expect(completed.completed_at).toBeDefined();
    expect(hub.listInbox()[0]).toMatchObject({
      item_id: ready.approval_request_id,
      resolved: true,
    });

    const audit = await auditLog.query({ layer: "l2", limit: 30 });
    const entries = audit.entries.filter(
      (entry) => entry.details?.task_id === ready.id,
    );
    const createIndex = entries.findIndex((entry) => entry.operation === "task.create");
    const readyIndex = entries.findIndex(
      (entry) =>
        entry.operation === "task.update_status" &&
        entry.details?.new_status === "ready_for_review",
    );
    const inboxIndex = entries.findIndex(
      (entry) => entry.operation === "task.inbox_chain",
    );
    const completeIndex = entries.findIndex(
      (entry) =>
        entry.operation === "task.update_status" &&
        entry.details?.new_status === "completed",
    );
    const resolvedIndex = entries.findIndex(
      (entry) => entry.operation === "task.review_approval_resolved",
    );

    expect(createIndex).toBeGreaterThanOrEqual(0);
    expect(readyIndex).toBeGreaterThan(createIndex);
    expect(inboxIndex).toBeGreaterThan(readyIndex);
    expect(completeIndex).toBeGreaterThan(inboxIndex);
    expect(resolvedIndex).toBeGreaterThan(completeIndex);
  });

  it("denies a task review inbox item and returns the task to in_progress", async () => {
    const { auditLog, hub } = await makeRig("fortress-a");
    const ready = await createReadyForReviewTask(hub);

    await hub.resolveInboxItem(ready.approval_request_id!, "deny");

    await expect(hub.getTask(ready.id)).resolves.toMatchObject({
      status: "in_progress",
    });
    const audit = await auditLog.query({ layer: "l2", limit: 30 });
    expect(audit.entries).toContainEqual(
      expect.objectContaining({
        operation: "task.review_approval_resolved",
        details: expect.objectContaining({
          task_id: ready.id,
          decision: "deny",
          new_status: "in_progress",
        }),
      }),
    );
  });

  it("leaves the inbox item unresolved when the task transition fails", async () => {
    const { auditLog, hub } = await makeRig("fortress-a");
    const ready = await createReadyForReviewTask(hub);
    await hub.updateTaskStatus(ready.id, {
      status: "completed",
      actor: "operator",
    });

    await expect(
      hub.resolveInboxItem(ready.approval_request_id!, "approve"),
    ).rejects.toThrow("illegal task status transition: completed to completed");

    expect(hub.listInbox()[0]).toMatchObject({
      item_id: ready.approval_request_id,
      resolved: false,
    });
    const audit = await auditLog.query({ layer: "l2", limit: 30 });
    expect(
      audit.entries.some(
        (entry) =>
          entry.operation === "task.review_approval_resolved" &&
          entry.details?.approval_request_id === ready.approval_request_id,
      ),
    ).toBe(false);
  });

  it("does not let a fortress A approval resolve a fortress B task", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const rigA = await makeRig("fortress-a", storage, masterKey);
    const rigB = await makeRig("fortress-b", storage, masterKey);
    const readyB = await createReadyForReviewTask(rigB.hub, "agent-b");
    const inboxItemA = rigA.hub.enqueueTaskReviewApproval(readyB, "agent-b");

    await expect(rigA.hub.resolveInboxItem(inboxItemA, "approve")).rejects.toThrow(
      `task for inbox item ${inboxItemA}`,
    );

    await expect(rigB.hub.getTask(readyB.id)).resolves.toMatchObject({
      status: "ready_for_review",
      approval_request_id: readyB.approval_request_id,
    });
  });
});

async function makeRig(
  fortressId: string,
  storage = new MemoryStorage(),
  masterKey = generateRandomKey(),
) {
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    "operator",
    identityEncryptionKey,
    "recovery-key",
  );
  await persistStoredIdentity(storage, masterKey, storedIdentity);

  const hub = new HubService({
    identityId: storedIdentity.identity_id,
    fortressId,
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
    fortressId,
    identityId: storedIdentity.identity_id,
    signingIdentity: storedIdentity,
    identityEncryptionKey,
    enqueueReviewApproval: (task, actor) =>
      hub.enqueueTaskReviewApproval(task, actor),
  });
  hub.setTaskService(tasks);

  return { auditLog, hub, tasks };
}

async function createReadyForReviewTask(
  hub: HubService,
  assignee = "agent-a",
): Promise<Task> {
  const task = await hub.createTask({
    title: "Cross harness review",
    creator: "operator",
    assignee,
  });
  await hub.updateTaskStatus(task.id, {
    status: "in_progress",
    actor: assignee,
  });
  return hub.updateTaskStatus(task.id, {
    status: "ready_for_review",
    actor: assignee,
  });
}
