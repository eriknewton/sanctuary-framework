import { describe, expect, it } from "vitest";

import {
  TASK_STATUSES,
  type AssignTaskInput,
  type CancelTaskInput,
  type CreateTaskInput,
  type ListTasksFilter,
  type Task,
  type TaskStatus,
  type UpdateTaskStatusInput,
} from "../../../src/l2-operational/task-coordination/task-types.js";

describe("task coordination task types", () => {
  it("exports the complete task status catalog in state-machine order", () => {
    expect(TASK_STATUSES).toEqual([
      "pending",
      "in_progress",
      "blocked",
      "ready_for_review",
      "completed",
      "cancelled",
    ]);
  });

  it("keeps task statuses unique for filter and transition iteration", () => {
    expect(new Set(TASK_STATUSES).size).toBe(TASK_STATUSES.length);
  });

  it("accepts the exported status literals in the public task input shapes", () => {
    const task: Task = {
      id: "task-1",
      fortress_id: "fortress-a",
      title: "Review task",
      creator: "operator",
      status: "ready_for_review",
      created_at: "2026-06-09T00:00:00.000Z",
      updated_at: "2026-06-09T00:01:00.000Z",
      approval_request_id: "approval-1",
      metadata: { priority: "high" },
      schema_version: 1,
    };
    const createInput: CreateTaskInput = {
      title: task.title,
      description: "Review the pending work",
      creator: task.creator,
      assignee: "agent-a",
      parent_task_id: "task-parent",
      metadata: task.metadata,
    };
    const listFilter: ListTasksFilter = {
      status: task.status,
      assignee: createInput.assignee,
      creator: createInput.creator,
    };
    const updateStatusInput: UpdateTaskStatusInput = {
      status: "completed",
      actor: "operator",
    };
    const assignInput: AssignTaskInput = {
      assignee: "agent-b",
      actor: "operator",
    };
    const cancelInput: CancelTaskInput = {
      actor: "operator",
      reason: "superseded",
    };

    const statuses: TaskStatus[] = [task.status, updateStatusInput.status];

    expect(statuses).toEqual(["ready_for_review", "completed"]);
    expect(listFilter).toEqual({
      status: "ready_for_review",
      assignee: "agent-a",
      creator: "operator",
    });
    expect(assignInput).toEqual({ assignee: "agent-b", actor: "operator" });
    expect(cancelInput).toEqual({ actor: "operator", reason: "superseded" });
  });
});
