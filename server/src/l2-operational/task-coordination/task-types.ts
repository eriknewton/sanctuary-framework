export const TASK_STATUSES = [
  "pending",
  "in_progress",
  "blocked",
  "ready_for_review",
  "completed",
  "cancelled",
] as const;

export type TaskStatus = (typeof TASK_STATUSES)[number];

export interface Task {
  id: string;
  fortress_id: string;
  title: string;
  description?: string;
  creator: string;
  assignee?: string;
  status: TaskStatus;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  parent_task_id?: string;
  approval_request_id?: string;
  metadata?: Record<string, unknown>;
  schema_version: 1;
}

export interface CreateTaskInput {
  title: string;
  description?: string;
  creator: string;
  assignee?: string;
  parent_task_id?: string;
  metadata?: Record<string, unknown>;
}

export interface ListTasksFilter {
  status?: TaskStatus;
  assignee?: string;
  creator?: string;
}

export interface UpdateTaskStatusInput {
  status: TaskStatus;
  actor: string;
}

export interface AssignTaskInput {
  assignee: string;
  actor: string;
}

export interface CancelTaskInput {
  actor: string;
  reason?: string;
}
