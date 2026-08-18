import type { EncryptedPayload } from "../../core/encryption.js";
import { hashToString } from "../../core/hashing.js";
import { randomBytes } from "../../core/random.js";
import { stringToBytes } from "../../core/encoding.js";
import type { StoredIdentity } from "../../core/identity.js";
import type { StateStore } from "../../cognitive/state-store.js";
import { scanNamespaceEntries } from "../../cognitive/namespace-scan.js";
import type { AuditLog } from "../audit-log.js";
import {
  TASK_STATUSES,
  type AssignTaskInput,
  type CancelTaskInput,
  type CreateTaskInput,
  type ListTasksFilter,
  type Task,
  type TaskStatus,
  type UpdateTaskStatusInput,
} from "./task-types.js";

export const TASK_NAMESPACE = "sanctuary.tasks";

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const ALLOWED_TRANSITIONS: Record<TaskStatus, readonly TaskStatus[]> = {
  pending: ["in_progress", "blocked", "cancelled"],
  in_progress: ["blocked", "ready_for_review", "completed", "cancelled"],
  blocked: ["in_progress", "cancelled"],
  ready_for_review: ["completed", "in_progress", "cancelled"],
  completed: [],
  cancelled: [],
};

export class TaskValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TaskValidationError";
  }
}

export class TaskNotFoundError extends Error {
  constructor(taskId: string) {
    super(`task not found: ${taskId}`);
    this.name = "TaskNotFoundError";
  }
}

export class TaskStateTransitionError extends Error {
  constructor(from: TaskStatus, to: TaskStatus) {
    super(`illegal task status transition: ${from} to ${to}`);
    this.name = "TaskStateTransitionError";
  }
}

export interface TaskServiceDeps {
  stateStore: StateStore;
  auditLog: Pick<AuditLog, "appendCritical">;
  fortressId: string;
  identityId: string;
  signingIdentity: StoredIdentity;
  identityEncryptionKey: Uint8Array;
  now?: () => Date;
  enqueueReviewApproval?: (task: Task, actor: string) => Promise<string> | string;
}

export class TaskService {
  private readonly deps: TaskServiceDeps;

  constructor(deps: TaskServiceDeps) {
    this.deps = deps;
  }

  async create(input: CreateTaskInput): Promise<Task> {
    const title = nonEmpty(input.title, "title");
    const creator = nonEmpty(input.creator, "creator");
    const now = this.nowIso();
    const task: Task = {
      id: generateUlid(this.deps.now?.()),
      fortress_id: this.deps.fortressId,
      title,
      creator,
      status: "pending",
      created_at: now,
      updated_at: now,
      schema_version: 1,
      ...(input.description ? { description: input.description } : {}),
      ...(input.assignee ? { assignee: input.assignee } : {}),
      ...(input.parent_task_id ? { parent_task_id: input.parent_task_id } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    };

    await this.auditLifecycle("task.create", task, {
      new_status: task.status,
      actor: creator,
    });
    await this.writeTask(task);
    return task;
  }

  /**
   * List this fortress's tasks.
   *
   * SKIP-AND-RECORD PER ROW. One stored task that cannot be read back (an
   * unresolvable writer key, a failed integrity check) or cannot be normalized
   * must not take the whole listing down: this method backs the hub tasks
   * endpoint, the CLI task list, and the concierge's task-state surface, and a
   * propagating row error turns all three into a total outage over a single bad
   * row. The failed rows are audited rather than discarded, because a listing
   * that is quietly shorter than the truth is the same absent-reads-as-present
   * conflation in the other direction.
   *
   * `get()` deliberately keeps propagating: a caller asking for ONE task by id
   * must never be told it does not exist when it merely could not be read.
   *
   * STATED BOUND: the unreadable count reaches the audit log, not yet the hub
   * JSON response or the CLI output.
   */
  async list(filter: ListTasksFilter = {}): Promise<Task[]> {
    const { items: tasks, failures } = await scanNamespaceEntries<Task>(
      this.deps.stateStore,
      TASK_NAMESPACE,
      (value) => normalizeTask(JSON.parse(value)),
      { prefix: this.keyPrefix() },
    );
    for (const failure of failures) {
      await this.auditUnreadableTaskRow(failure.key, failure.error);
    }
    return tasks
      .filter((task) => task.fortress_id === this.deps.fortressId)
      .filter((task) => !filter.status || task.status === filter.status)
      .filter((task) => !filter.assignee || task.assignee === filter.assignee)
      .filter((task) => !filter.creator || task.creator === filter.creator)
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  async get(taskId: string): Promise<Task> {
    const id = nonEmpty(taskId, "task_id");
    const task = await this.readTaskByKey(this.keyFor(id));
    if (!task || task.fortress_id !== this.deps.fortressId) {
      throw new TaskNotFoundError(id);
    }
    return task;
  }

  async updateStatus(taskId: string, input: UpdateTaskStatusInput): Promise<Task> {
    const actor = nonEmpty(input.actor, "actor");
    const next = normalizeStatus(input.status);
    const prior = await this.get(taskId);
    assertTransition(prior.status, next);

    const updated: Task = {
      ...prior,
      status: next,
      updated_at: this.nowIso(),
      ...(next === "completed" ? { completed_at: this.nowIso() } : {}),
    };

    if (next === "ready_for_review") {
      if (!this.deps.enqueueReviewApproval) {
        throw new TaskValidationError("task review approval queue is not configured");
      }
      updated.approval_request_id = await this.deps.enqueueReviewApproval(
        updated,
        actor,
      );
    }

    await this.auditLifecycle("task.update_status", updated, {
      prev_status: prior.status,
      new_status: next,
      actor,
    });
    if (next === "ready_for_review") {
      await this.auditLifecycle("task.inbox_chain", updated, {
        prev_status: prior.status,
        new_status: next,
        actor,
      });
    }
    await this.writeTask(updated);
    return updated;
  }

  async assign(taskId: string, input: AssignTaskInput): Promise<Task> {
    const assignee = nonEmpty(input.assignee, "assignee");
    const actor = nonEmpty(input.actor, "actor");
    const prior = await this.get(taskId);
    if (isTerminal(prior.status)) {
      throw new TaskStateTransitionError(prior.status, prior.status);
    }
    const updated: Task = {
      ...prior,
      assignee,
      updated_at: this.nowIso(),
    };
    await this.auditLifecycle("task.assign", updated, {
      prev_status: prior.status,
      new_status: prior.status,
      actor,
    });
    await this.writeTask(updated);
    return updated;
  }

  async cancel(taskId: string, input: CancelTaskInput): Promise<Task> {
    const actor = nonEmpty(input.actor, "actor");
    const prior = await this.get(taskId);
    assertTransition(prior.status, "cancelled");
    const updated: Task = {
      ...prior,
      status: "cancelled",
      updated_at: this.nowIso(),
      ...(input.reason
        ? { metadata: { ...(prior.metadata ?? {}), cancel_reason: input.reason } }
        : {}),
    };
    await this.auditLifecycle("task.cancel", updated, {
      prev_status: prior.status,
      new_status: "cancelled",
      actor,
    });
    await this.writeTask(updated);
    return updated;
  }

  private async readTaskByKey(key: string): Promise<Task | null> {
    const result = await this.deps.stateStore.read(TASK_NAMESPACE, key);
    if (!result) return null;
    return normalizeTask(JSON.parse(result.value));
  }

  private async writeTask(task: Task): Promise<void> {
    await this.deps.stateStore.write(
      TASK_NAMESPACE,
      this.keyFor(task.id),
      JSON.stringify(task),
      this.deps.identityId,
      this.deps.signingIdentity.encrypted_private_key as EncryptedPayload,
      this.deps.identityEncryptionKey,
      {
        content_type: "application/json",
        tags: ["task", task.status, task.fortress_id],
      },
    );
  }

  private async auditLifecycle(
    eventType: string,
    task: Task,
    details: {
      prev_status?: TaskStatus;
      new_status: TaskStatus;
      actor: string;
    },
  ): Promise<void> {
    await this.deps.auditLog.appendCritical({
      layer: "l2",
      operation: eventType,
      identity_id: this.deps.identityId,
      result: "success",
      details: {
        event_type: eventType,
        task_id: task.id,
        ...details,
        approval_request_id: task.approval_request_id,
      },
    });
  }

  /**
   * Durable record that a stored task row could not be read back. Best-effort:
   * an audit-write failure must not turn a listing that DID recover most rows
   * into a total failure, which is the exact outage this method exists to
   * prevent. The key is recorded; the row's contents are not, since they are
   * what could not be read.
   */
  private async auditUnreadableTaskRow(key: string, cause: unknown): Promise<void> {
    try {
      await this.deps.auditLog.appendCritical({
        layer: "l2",
        operation: "task.list_row_unreadable",
        identity_id: this.deps.identityId,
        result: "failure",
        details: {
          event_type: "task.list_row_unreadable",
          state_key: key,
          reason: cause instanceof Error ? cause.message : String(cause),
        },
      });
    } catch {
      // Best-effort by design; see the doc-comment above.
    }
  }

  private keyPrefix(): string {
    return `${this.deps.fortressId}/`;
  }

  private keyFor(taskId: string): string {
    return `${this.keyPrefix()}${taskId}`;
  }

  private nowIso(): string {
    return (this.deps.now ? this.deps.now() : new Date()).toISOString();
  }
}

export function isTaskStatus(value: unknown): value is TaskStatus {
  return typeof value === "string" && TASK_STATUSES.includes(value as TaskStatus);
}

function normalizeStatus(value: unknown): TaskStatus {
  if (isTaskStatus(value)) return value;
  throw new TaskValidationError(
    `status must be one of: ${TASK_STATUSES.join(", ")}`,
  );
}

function normalizeTask(value: unknown): Task {
  if (!value || typeof value !== "object") {
    throw new TaskValidationError("stored task is not an object");
  }
  const record = value as Record<string, unknown>;
  const task: Task = {
    id: nonEmpty(record.id, "id"),
    fortress_id: nonEmpty(record.fortress_id, "fortress_id"),
    title: nonEmpty(record.title, "title"),
    creator: nonEmpty(record.creator, "creator"),
    status: normalizeStatus(record.status),
    created_at: nonEmpty(record.created_at, "created_at"),
    updated_at: nonEmpty(record.updated_at, "updated_at"),
    schema_version: 1,
  };
  if (typeof record.description === "string") task.description = record.description;
  if (typeof record.assignee === "string") task.assignee = record.assignee;
  if (typeof record.completed_at === "string") task.completed_at = record.completed_at;
  if (typeof record.parent_task_id === "string") {
    task.parent_task_id = record.parent_task_id;
  }
  if (typeof record.approval_request_id === "string") {
    task.approval_request_id = record.approval_request_id;
  }
  if (
    record.metadata &&
    typeof record.metadata === "object" &&
    !Array.isArray(record.metadata)
  ) {
    task.metadata = record.metadata as Record<string, unknown>;
  }
  return task;
}

function assertTransition(from: TaskStatus, to: TaskStatus): void {
  if (!ALLOWED_TRANSITIONS[from].includes(to)) {
    throw new TaskStateTransitionError(from, to);
  }
}

function isTerminal(status: TaskStatus): boolean {
  return status === "completed" || status === "cancelled";
}

function nonEmpty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TaskValidationError(`${field} required`);
  }
  return value.trim();
}

function generateUlid(now?: Date): string {
  const timestampMs = now ? now.getTime() : Date.now();
  const time = Math.max(0, Math.min(timestampMs, 0xffffffffffff));
  const entropy = randomBytes(10);
  return encodeUlid(time, entropy);
}

function encodeUlid(timestampMs: number, random: Uint8Array): string {
  let time = Math.floor(timestampMs);
  const chars = new Array<string>(26);
  for (let i = 9; i >= 0; i--) {
    chars[i] = ULID_ALPHABET[time & 31]!;
    time = Math.floor(time / 32);
  }

  let bitBuffer = 0;
  let bitCount = 0;
  let out = 10;
  for (const byte of random) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      chars[out++] = ULID_ALPHABET[(bitBuffer >> bitCount) & 31]!;
    }
  }
  if (bitCount > 0) {
    chars[out] = ULID_ALPHABET[(bitBuffer << (5 - bitCount)) & 31]!;
  }
  return chars.join("");
}

export function taskBodyHash(task: Task): string {
  return hashToString(stringToBytes(JSON.stringify(task)));
}
