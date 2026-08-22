/**
 * Sanctuary v1.1. Operator Hub Service
 *
 * Public API the router calls. Owns no domain logic: it composes the
 * agent registry source, the inbox aggregator + store, the activity feed
 * projection, and the agent controller.
 *
 * Tier 1 enforcement contract:
 * Hub control endpoints for `unwrap`, `lockdown`, and `policy_change` MUST
 * NOT execute synchronously. The hub enqueues an `approval_pending` inbox
 * item carrying the operation_category and binds the controller call to
 * the inbox-store resolution handler. Only operator approval through the
 * inbox path causes the controller call to fire. The dashboard never
 * auto-approves Tier 1 work.
 */

import { randomUUID } from "node:crypto";

import type {
  HubAgentStatusSnapshot,
  HubApprovalPendingItem,
  HubInboxItem,
  HubActivityFeedEntry,
} from "../contracts/v1.1/hub-events.js";
import type { HubAgentStatus } from "../contracts/v1.1/constants.js";
import type {
  LocalAgentRecord,
  LocalAgentRegistryFilter,
} from "../contracts/v1.1/local-agent-records.js";
import { effectiveLivenessStatus } from "../contracts/v1.1/liveness.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import { CHANNEL_TEMPLATE_IDS } from "../policy-engine/constants.js";
import { applyChannelTemplate } from "../policy-engine/channel-templates.js";

import {
  HUB_AGENT_CONTROL_ACTIONS,
  HUB_INBOX_TEMPLATE_NAMESPACES,
  HUB_TIER_1_AGENT_CONTROL_ACTIONS,
  type HubAgentControlAction,
  type HubInboxAction,
  type HubTier1AgentControlAction,
} from "./constants.js";
import {
  HubCapabilityError,
  HubConflictError,
  HubLocalOnlyError,
  HubNotFoundError,
  HubValidationError,
} from "./errors.js";
import { aggregateInbox } from "./inbox-aggregator.js";
import { HubInboxStore } from "./inbox-store.js";
import { writeLockdownStatus } from "../lockdown/status.js";
import { aggregateActivity } from "./activity-feed.js";
import type {
  HubAgentControlResult,
  HubAgentLockdownControllerResult,
  HubBudgetSummary,
  HubAgentInspectPanel,
  HubFortressExportResult,
  HubPolicySummary,
  HubServiceDeps,
  HubTier1ApprovalEnqueuedResult,
  HubTier1FortressApprovalEnqueuedResult,
  HubTemplateBindingApprovalEnqueuedResult,
} from "./types.js";
import type {
  ConciergeResponse,
  OperatorChatMessage,
} from "../chat/operator-chat-types.js";
import type {
  ConciergeAskRequest,
  ConciergeAskResponse,
  ConciergeService,
  ConciergeStatus,
} from "../concierge/index.js";
import type {
  ConciergeThreadSummary,
  ConciergeTurn,
  ListThreadsOptions,
  ReadThreadOptions,
} from "../chat/concierge-memory-store.js";
import {
  TaskNotFoundError,
  TaskService,
  TaskStateTransitionError,
  TaskValidationError,
  type AssignTaskInput,
  type CancelTaskInput,
  type CreateTaskInput,
  type ListTasksFilter,
  type Task,
  type UpdateTaskStatusInput,
} from "../operational/task-coordination/index.js";

type LockdownOutcomePayload = NonNullable<
  HubApprovalPendingItem["resolution_payload"]
>;

type HubServiceTaskDeps = HubServiceDeps & {
  taskService?: TaskService;
};

function isTier1ControlAction(
  action: HubAgentControlAction,
): action is HubTier1AgentControlAction {
  return (HUB_TIER_1_AGENT_CONTROL_ACTIONS as readonly string[]).includes(
    action,
  );
}

function isLockdownControllerResult(
  value: unknown,
): value is HubAgentLockdownControllerResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "outcome" in value &&
    ((value as { outcome?: unknown }).outcome === "engaged" ||
      (value as { outcome?: unknown }).outcome === "partial")
  );
}

function lockdownPayloadFromResult(
  result: HubAgentStatus | HubAgentLockdownControllerResult,
): LockdownOutcomePayload {
  if (!isLockdownControllerResult(result)) {
    return {
      outcome: "engaged",
      reload_confirmed: true,
      residual_allow_count: 0,
    };
  }
  return {
    outcome: result.outcome,
    ...(result.agent_uid !== undefined ? { agent_uid: result.agent_uid } : {}),
    ...(result.revoked_rule_ids !== undefined
      ? { revoked_rule_ids: result.revoked_rule_ids }
      : {}),
    ...(result.residual_allow_count !== undefined
      ? { residual_allow_count: result.residual_allow_count }
      : {}),
    ...(result.reload_confirmed !== undefined
      ? { reload_confirmed: result.reload_confirmed }
      : {}),
    ...(result.reason_code !== undefined ? { reason_code: result.reason_code } : {}),
  };
}

function lockdownStatusFromResult(
  result: HubAgentStatus | HubAgentLockdownControllerResult,
): HubAgentStatus | null {
  if (!isLockdownControllerResult(result)) return result;
  return result.new_status ?? null;
}

function checkChannelTemplateId(value: unknown): ChannelTemplateId {
  if (
    typeof value === "string" &&
    (CHANNEL_TEMPLATE_IDS as readonly string[]).includes(value)
  ) {
    return value as ChannelTemplateId;
  }
  throw new HubValidationError(
    `channel_template_id must be one of: ${CHANNEL_TEMPLATE_IDS.join(", ")}`,
  );
}

function snapshotForRecord(
  record: LocalAgentRecord,
  openInboxItemIds: string[],
): HubAgentStatusSnapshot {
  // Liveness aging: the stored `active` status is the last value written and is
  // never aged, so a dead agent would keep reading "Running / protected /
  // verified". Age a stale `active` (last_activity_at past the window) down to
  // `unknown` in this read-projection. This is display/SSE only; control paths
  // read the raw record via getAgent, so liveness aging never affects them.
  const snap: HubAgentStatusSnapshot = {
    version: "1.1",
    agent_id: record.agent_id,
    status: effectiveLivenessStatus(record.status, record.last_activity_at),
    last_activity_at: record.last_activity_at,
    open_inbox_item_ids: openInboxItemIds,
  };
  if (record.status_reason_class) {
    snap.status_reason_class = record.status_reason_class;
  }
  return snap;
}

export class HubService {
  private deps: HubServiceDeps;
  private inboxStore: HubInboxStore;
  private taskService?: TaskService;
  private concierge?: ConciergeService;

  constructor(deps: HubServiceTaskDeps) {
    this.deps = deps;
    this.inboxStore = new HubInboxStore();
    this.taskService = deps.taskService;
    this.concierge = deps.concierge;
  }

  // ── Internal helpers ────────────────────────────────────────────────

  private now(): Date {
    return this.deps.now ? this.deps.now() : new Date();
  }

  private nowIso(): string {
    return this.now().toISOString();
  }

  private refreshPersistedLocalAgents(): void {
    const readPersistedLocalAgents = this.deps.readPersistedLocalAgents;
    if (!readPersistedLocalAgents) return;
    for (const record of readPersistedLocalAgents()) {
      this.deps.agentRegistry.put(record);
    }
  }

  // ── Inbox ───────────────────────────────────────────────────────────

  listInbox(): HubInboxItem[] {
    const items = aggregateInbox(this.deps.inboxSources, this.inboxStore);
    return items.filter((i) => i.identity_id === this.deps.identityId);
  }

  async resolveInboxItem(
    itemId: string,
    action: HubInboxAction,
  ): Promise<HubInboxItem> {
    // Aggregate first so source-pulled items (egress, privacy, budget,
    // recovery, agent_error) are present in the store before we resolve.
    // Tier 1 hub-enqueued items already live in the store regardless.
    aggregateInbox(this.deps.inboxSources, this.inboxStore);
    return this.inboxStore.resolve(itemId, action, this.nowIso());
  }

  // ── Tasks ──────────────────────────────────────────────────────────

  setTaskService(taskService: TaskService): void {
    this.taskService = taskService;
  }

  async createTask(input: CreateTaskInput): Promise<Task> {
    return this.withTaskErrors(() => this.requireTaskService().create(input));
  }

  async listTasks(filter?: ListTasksFilter): Promise<Task[]> {
    return this.withTaskErrors(() => this.requireTaskService().list(filter));
  }

  async getTask(taskId: string): Promise<Task> {
    return this.withTaskErrors(() => this.requireTaskService().get(taskId));
  }

  async updateTaskStatus(
    taskId: string,
    input: UpdateTaskStatusInput,
  ): Promise<Task> {
    return this.withTaskErrors(() =>
      this.requireTaskService().updateStatus(taskId, input),
    );
  }

  async assignTask(taskId: string, input: AssignTaskInput): Promise<Task> {
    return this.withTaskErrors(() =>
      this.requireTaskService().assign(taskId, input),
    );
  }

  async cancelTask(taskId: string, input: CancelTaskInput): Promise<Task> {
    return this.withTaskErrors(() =>
      this.requireTaskService().cancel(taskId, input),
    );
  }

  enqueueTaskReviewApproval(task: Task, actor: string): string {
    const itemId = `task.review.${task.id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      identity_id: this.deps.identityId,
      ...(task.assignee ? { agent_id: task.assignee } : {}),
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.task.ready_for_review`,
      display_template_args: [
        { kind: "identity_id", value: this.deps.identityId },
        { kind: "tier", value: "tier2" },
        ...(task.assignee
          ? [{ kind: "agent_id" as const, value: task.assignee }]
          : []),
      ],
      resolved: false,
      tier: "tier2",
      operation_category: "other",
    };

    this.inboxStore.enqueueTier1(item, async (_item, decision) => {
      const taskService = this.requireTaskService();
      const matchingTask = (await taskService.list()).find(
        (candidate) => candidate.approval_request_id === item.item_id,
      );
      if (!matchingTask) {
        throw new HubNotFoundError(`task for inbox item ${item.item_id}`);
      }

      // A denied review means the task needs revision, so return it to work.
      const nextStatus = decision === "approve" ? "completed" : "in_progress";
      await taskService.updateStatus(matchingTask.id, {
        status: nextStatus,
        actor: this.deps.identityId,
      });

      await this.deps.activitySources.auditLog.appendCritical({
        layer: "l2",
        operation: "task.review_approval_resolved",
        identity_id: this.deps.identityId,
        result: "success",
        details: {
          task_id: matchingTask.id,
          actor: this.deps.identityId,
          review_actor: actor,
          decision,
          new_status: nextStatus,
          approval_request_id: item.item_id,
        },
      });
    });
    return itemId;
  }

  private requireTaskService(): TaskService {
    if (!this.taskService) {
      throw new HubCapabilityError("task_service_not_configured");
    }
    return this.taskService;
  }

  private async withTaskErrors<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof TaskNotFoundError) {
        throw new HubNotFoundError(err.message);
      }
      if (err instanceof TaskStateTransitionError) {
        throw new HubConflictError(err.message);
      }
      if (err instanceof TaskValidationError) {
        throw new HubValidationError(err.message);
      }
      throw err;
    }
  }

  // ── Concierge ─────────────────────────────────────────────────────

  setConciergeService(concierge: ConciergeService): void {
    this.concierge = concierge;
  }

  async askConcierge(input: ConciergeAskRequest): Promise<ConciergeAskResponse> {
    if (!this.concierge) {
      throw new HubCapabilityError("concierge_service_not_configured");
    }
    return this.concierge.ask(input);
  }

  async getConciergeStatus(): Promise<ConciergeStatus> {
    if (!this.concierge) {
      throw new HubCapabilityError("concierge_service_not_configured");
    }
    return this.concierge.status();
  }

  // ── Agents ──────────────────────────────────────────────────────────

  listAgents(filter?: LocalAgentRegistryFilter): LocalAgentRecord[] {
    this.refreshPersistedLocalAgents();
    const safeFilter: LocalAgentRegistryFilter = {
      ...(filter ?? {}),
      identity_id: this.deps.identityId,
    };
    return this.deps.agentRegistry.list(safeFilter);
  }

  getAgent(agentId: string): LocalAgentRecord {
    const record = this.deps.agentRegistry.get(agentId);
    if (!record) throw new HubNotFoundError(`agent ${agentId}`);
    if (record.identity_id !== this.deps.identityId) {
      // Records bound to other identities are out of scope; v1.2 multi-
      // identity work will revisit; v1.1 single-operator denies.
      throw new HubLocalOnlyError(
        "agent belongs to a different operator identity",
      );
    }
    return record;
  }

  getAgentStatusSnapshot(agentId: string): HubAgentStatusSnapshot {
    const record = this.getAgent(agentId);
    const openIds = this.listInbox()
      .filter((i) => !i.resolved && i.agent_id === record.agent_id)
      .map((i) => i.item_id);
    return snapshotForRecord(record, openIds);
  }

  // ── Agent control ──────────────────────────────────────────────────

  async controlAgent(
    agentId: string,
    action: HubAgentControlAction,
  ): Promise<HubAgentControlResult | HubTier1ApprovalEnqueuedResult> {
    if (!(HUB_AGENT_CONTROL_ACTIONS as readonly string[]).includes(action)) {
      throw new HubValidationError(`unknown control action: ${action}`);
    }
    const record = this.getAgent(agentId);
    await this.assertCapability(record, action);

    if (isTier1ControlAction(action)) {
      return this.enqueueTier1ControlAction(record, action);
    }

    const prior = record.status;
    let next: LocalAgentRecord;
    switch (action) {
      case "pause": {
        const status = await this.deps.agentController.pause(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      case "resume": {
        const status = await this.deps.agentController.resume(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      case "restart": {
        const status = await this.deps.agentController.restart(agentId);
        next = this.deps.agentRegistry.updateStatus(agentId, status);
        break;
      }
      default:
        throw new HubValidationError(`unhandled control action: ${action}`);
    }
    return {
      agent_id: agentId,
      prior_status: prior,
      new_status: next.status,
      applied_at: this.nowIso(),
    };
  }

  /**
   * Capability gate. Returns silently when the action is supported by the
   * harness; throws HubCapabilityError when not.
   */
  private async assertCapability(
    record: LocalAgentRecord,
    action: HubAgentControlAction,
  ): Promise<void> {
    const c = record.capabilities;
    const supports: Record<HubAgentControlAction, boolean> = {
      pause: c.can_pause,
      resume: c.can_resume,
      restart: c.can_restart,
      unwrap: c.can_unwrap,
      lockdown: c.can_lockdown,
    };
    if (!supports[action]) throw new HubCapabilityError(action);
    const executorSupports = this.deps.agentController.supports
      ? await this.deps.agentController.supports(action, record.agent_id)
      : true;
    if (!executorSupports) {
      const reasonByAction: Record<HubAgentControlAction, string> = {
        pause: "agent_control_pause_unsupported_no_process_handle",
        resume: "agent_control_resume_unsupported_no_process_handle",
        restart: "agent_control_restart_unsupported_no_process_handle",
        unwrap: "agent_control_unwrap_unsupported_operator_decision_pending",
        lockdown: "agent_control_lockdown_unsupported_no_confinement",
      };
      throw new HubCapabilityError(reasonByAction[action]);
    }
  }

  /**
   * Build a Tier 1 inbox item for an unwrap/lockdown/policy_change action
   * and bind the controller call to its resolution.
   */
  private enqueueTier1ControlAction(
    record: LocalAgentRecord,
    action: HubTier1AgentControlAction,
  ): HubTier1ApprovalEnqueuedResult {
    const operationCategory: HubApprovalPendingItem["operation_category"] =
      action;
    const itemId = `tier1.${action}.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.${action}`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "identity_id", value: record.identity_id },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: operationCategory,
    };

    this.inboxStore.enqueueTier1(item, async (approvedItem, decision) => {
      if (decision === "deny") return;
      switch (action) {
        case "unwrap": {
          const status = await this.deps.agentController.unwrap(
            approvedItem.agent_id ?? record.agent_id,
          );
          this.deps.agentRegistry.updateStatus(
            record.agent_id,
            status,
            "operator_lockdown",
          );
          void this.deps.activitySources.auditLog.append(
            "l2",
            "agent_unwrap_engaged",
            this.deps.identityId,
            {
              agent_id: record.agent_id,
              identity_id: record.identity_id,
              operator_audit_id: itemId,
            },
          );
          return;
        }
        case "lockdown": {
          let result: Awaited<ReturnType<typeof this.deps.agentController.lockdown>>;
          try {
            result = await this.deps.agentController.lockdown(
              approvedItem.agent_id ?? record.agent_id,
            );
          } catch (err) {
            if (err instanceof HubCapabilityError) {
              void this.deps.activitySources.auditLog.append(
                "l2",
                "agent_lockdown_refused",
                this.deps.identityId,
                {
                  agent_id: record.agent_id,
                  identity_id: record.identity_id,
                  operator_audit_id: itemId,
                  reason_code: err.reasonCode,
                },
              );
            }
            throw err;
          }
          const status = lockdownStatusFromResult(result);
          if (status !== null) {
            this.deps.agentRegistry.updateStatus(
              record.agent_id,
              status,
              "operator_lockdown",
            );
          }
          const payload = lockdownPayloadFromResult(result);
          void this.deps.activitySources.auditLog.append(
            "l2",
            payload.outcome === "partial"
              ? "agent_lockdown_partial"
              : "agent_lockdown_engaged",
            this.deps.identityId,
            {
              agent_id: record.agent_id,
              identity_id: record.identity_id,
              operator_audit_id: itemId,
              ...payload,
            },
          );
          return { resolution_payload: payload };
        }
      }
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: operationCategory,
    };
  }

  /**
   * Bind a different policy on an agent. Tier 1: enqueues an approval
   * pending inbox item rather than executing synchronously.
   */
  bindAgentPolicy(
    agentId: string,
    policyId: string,
  ): HubTier1ApprovalEnqueuedResult {
    if (!policyId || typeof policyId !== "string") {
      throw new HubValidationError("policy_id required");
    }
    const record = this.getAgent(agentId);
    const itemId = `tier1.policy_change.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.policy_change`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "policy_id", value: policyId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "policy_change",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      await this.deps.agentController.bindPolicy(record.agent_id, policyId);
      this.deps.agentRegistry.updatePolicyBinding(record.agent_id, policyId);
      void this.deps.activitySources.auditLog.append(
        "l2",
        "agent_policy_change_engaged",
        this.deps.identityId,
        {
          agent_id: record.agent_id,
          identity_id: record.identity_id,
          operator_audit_id: itemId,
          policy_id: policyId,
        },
      );
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "policy_change",
    };
  }

  /**
   * Bind a different channel template. Tier 1: enqueues a policy_change
   * approval item and only applies the binding after operator approval.
   */
  bindAgentChannelTemplate(
    agentId: string,
    rawTemplateId: unknown,
  ): HubTemplateBindingApprovalEnqueuedResult {
    const templateId = checkChannelTemplateId(rawTemplateId);
    const record = this.getAgent(agentId);
    const currentTemplate =
      typeof record.channel_template_id === "string" &&
      (CHANNEL_TEMPLATE_IDS as readonly string[]).includes(record.channel_template_id)
        ? (record.channel_template_id as ChannelTemplateId)
        : undefined;
    const compiled = applyChannelTemplate(templateId, {
      agent_id: record.agent_id,
      counterparty: this.deps.identityId,
      fortress_id: this.deps.fortressId,
      policy_version: Date.now(),
    });
    const compiledPolicyId = `${record.agent_id}:${templateId}:v${compiled.policy_version}`;
    const itemId = `tier1.policy_change.template.${record.agent_id}.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      agent_id: record.agent_id,
      identity_id: record.identity_id,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.policy_change_template`,
      display_template_args: [
        { kind: "agent_id", value: record.agent_id },
        { kind: "policy_id", value: templateId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "policy_change",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") {
        void this.deps.activitySources.auditLog.append(
          "l2",
          "agent_policy_change_denied",
          this.deps.identityId,
          {
            agent_id: record.agent_id,
            identity_id: record.identity_id,
            operator_audit_id: itemId,
            current_template: currentTemplate ?? null,
            proposed_template: templateId,
          },
        );
        return;
      }
      await this.deps.agentController.bindChannelTemplate(record.agent_id, templateId);
      this.deps.agentRegistry.updateChannelTemplateBinding(record.agent_id, templateId);
      this.deps.agentRegistry.updatePolicyBinding(record.agent_id, compiledPolicyId);
      this.deps.writePersistedLocalAgents?.(this.deps.agentRegistry.list());
      void this.deps.activitySources.auditLog.append(
        "l2",
        "agent_policy_change_engaged",
        this.deps.identityId,
        {
          agent_id: record.agent_id,
          identity_id: record.identity_id,
          operator_audit_id: itemId,
          current_template: currentTemplate ?? null,
          proposed_template: templateId,
          policy_id: compiledPolicyId,
        },
      );
    });

    return {
      agent_id: record.agent_id,
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "policy_change",
      ...(currentTemplate ? { current_template_id: currentTemplate } : {}),
      proposed_template_id: templateId,
      compiled_policy_id: compiledPolicyId,
    };
  }

  // ── Fortress-scope Tier 1 actions ──────────────────────────────────

  /**
   * Enqueue a fortress-scope Tier 1 lockdown. One inbox item is created;
   * on operator approval the handler iterates `agentController.lockdown`
   * over every wrapped agent for the bound identity, captures partial
   * failures as per-agent `agent_error` inbox items, and emits a single
   * `lifecycle` activity entry. Stacked fortress lockdowns are rejected
   * with `HubConflictError` until the prior pending item resolves.
   */
  enqueueFortressLockdown(): HubTier1FortressApprovalEnqueuedResult {
    this.assertNoPendingFortressTier1("lockdown");

    const itemId = `tier1.fortress.lockdown.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      identity_id: this.deps.identityId,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.fortress_lockdown`,
      display_template_args: [
        { kind: "identity_id", value: this.deps.identityId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "lockdown",
    };

    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      const records = this.deps.agentRegistry.list({
        identity_id: this.deps.identityId,
      });
      const failed: Array<{ agent_id: string; error: string }> = [];
      for (const record of records) {
        try {
          const result = await this.deps.agentController.lockdown(
            record.agent_id,
          );
          const status = lockdownStatusFromResult(result);
          if (status !== null) {
            this.deps.agentRegistry.updateStatus(
              record.agent_id,
              status,
              "operator_lockdown",
            );
          } else {
            failed.push({
              agent_id: record.agent_id,
              error: "lockdown returned no applied status",
            });
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          failed.push({ agent_id: record.agent_id, error: msg });
        }
      }
      const attempted = records.length;
      const locked = attempted - failed.length;
      const outcome =
        attempted === 0
          ? "no_agents"
          : locked === 0
            ? "failed"
            : locked < attempted
              ? "partial"
              : "engaged";
      const operation =
        outcome === "engaged"
          ? "fortress_lockdown_engaged"
          : outcome === "partial"
            ? "fortress_lockdown_partial"
            : outcome === "failed"
              ? "fortress_lockdown_failed"
              : "fortress_lockdown_no_agents";
      // One fortress-level activity entry, regardless of partial-failure
      // count. Per-agent failures surface as individual agent_error items
      // below.
      void this.deps.activitySources.auditLog.append(
        "l2",
        operation,
        this.deps.identityId,
        {
          fortress_id: this.deps.fortressId,
          locked_count: locked,
          failed_count: failed.length,
          ...(outcome === "no_agents" ? { agent_count: 0 } : {}),
        },
      );
      if (locked > 0 && this.deps.storagePath) {
        await writeLockdownStatus(this.deps.storagePath, {
          active: true,
          activated_at: this.nowIso(),
          reason: "operator_lockdown",
        });
      }
      // One agent_error inbox item per per-agent failure; the operator
      // sees both the fortress success AND the failed agents.
      for (const f of failed) {
        const errId = `fortress.lockdown.error.${f.agent_id}.${randomUUID()}`;
        this.inboxStore.upsertFromSource({
          version: "1.1",
          item_id: errId,
          kind: "agent_error",
          created_at: this.nowIso(),
          identity_id: this.deps.identityId,
          agent_id: f.agent_id,
          display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.agent_error}.E_FORTRESS_LOCKDOWN_FAILED`,
          display_template_args: [
            { kind: "agent_id", value: f.agent_id },
          ],
          resolved: false,
          error_class: "E_FORTRESS_LOCKDOWN_FAILED",
          agent_still_active: true,
        });
      }
      return {
        resolution_payload: {
          outcome,
          locked_count: locked,
          failed_count: failed.length,
        },
      };
    });

    return {
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "lockdown",
      fortress_scope: true,
    };
  }

  /**
   * Enqueue a fortress-scope Tier 1 exit-bundle export. One inbox item is
   * created; on operator approval the handler invokes
   * `fortressExportBundle()` once at fortress scope, attaches
   * `bundle_dir` + `manifest_hash` + `artifact_count` to the inbox item's
   * `resolution_payload`, and emits a `lifecycle` activity entry.
   * Stacked exports are rejected with `HubConflictError`.
   */
  enqueueFortressExportBundle(): HubTier1FortressApprovalEnqueuedResult {
    if (!this.deps.fortressExportBundle) {
      throw new HubCapabilityError("fortress_exit_bundle_export");
    }
    this.assertNoPendingFortressTier1("exit_bundle_export");

    const itemId = `tier1.fortress.exit_bundle_export.${randomUUID()}`;
    const item: HubApprovalPendingItem = {
      version: "1.1",
      item_id: itemId,
      kind: "approval_pending",
      created_at: this.nowIso(),
      identity_id: this.deps.identityId,
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.fortress_exit_bundle_export`,
      display_template_args: [
        { kind: "identity_id", value: this.deps.identityId },
        { kind: "tier", value: "tier1" },
      ],
      resolved: false,
      tier: "tier1",
      operation_category: "exit_bundle_export",
    };

    const fortressExportBundle = this.deps.fortressExportBundle;
    this.inboxStore.enqueueTier1(item, async (_approvedItem, decision) => {
      if (decision === "deny") return;
      // Thread the inbox item id into the callback as the approval audit
      // id so `exportExitBundle()` can embed it in the manifest's
      // `export_approval_audit_id` field (v1.0.2 (j)).
      const result: HubFortressExportResult = await fortressExportBundle(
        itemId,
      );
      void this.deps.activitySources.auditLog.append(
        "l2",
        "exit_bundle_exported",
        this.deps.identityId,
        {
          fortress_id: this.deps.fortressId,
          bundle_dir: result.bundle_dir,
          manifest_hash: result.manifest_hash,
          artifact_count: result.artifact_count,
          state_entry_count: result.state_entry_count,
        },
      );
      return {
        resolution_payload: {
          bundle_dir: result.bundle_dir,
          manifest_hash: result.manifest_hash,
          artifact_count: result.artifact_count,
          // A7: carry state_entry_count and warnings through so the dashboard
          // inbox item carries the honest count. Must match HubFortressExportResult
          // in hub/types.ts and resolution_payload in hub-events.ts.
          state_entry_count: result.state_entry_count,
          ...(result.warnings !== undefined
            ? { warnings: result.warnings }
            : {}),
        },
      };
    });

    return {
      inbox_item_id: itemId,
      status: "approval_pending",
      operation_category: "exit_bundle_export",
      fortress_scope: true,
    };
  }

  /**
   * Reject stacked fortress-scope Tier 1 items. The check scans the inbox
   * store for an unresolved `approval_pending` item with the same
   * `operation_category` and no `agent_id` (the fortress-scope marker).
   */
  private assertNoPendingFortressTier1(
    operationCategory: HubApprovalPendingItem["operation_category"],
  ): void {
    for (const item of this.inboxStore.list()) {
      if (item.kind !== "approval_pending") continue;
      if (item.resolved) continue;
      if (item.agent_id !== undefined) continue;
      if (item.operation_category !== operationCategory) continue;
      throw new HubConflictError(
        `fortress-scope ${operationCategory} already pending; resolve the existing inbox item first`,
      );
    }
  }

  // ── Activity feed ───────────────────────────────────────────────────

  async listActivity(filter: {
    since?: string;
    limit?: number;
    agent_id?: string;
    category?: HubActivityFeedEntry["category"];
  }): Promise<HubActivityFeedEntry[]> {
    return aggregateActivity(
      {
        ...this.deps.activitySources,
        listLocalAgents: () => this.listAgents(),
      },
      filter,
    );
  }

  // ── Policy + budget summaries ──────────────────────────────────────

  listPolicySummaries(): HubPolicySummary[] {
    return this.deps.policyBudgetSources.listPolicySummaries();
  }

  listBudgetSummaries(): HubBudgetSummary[] {
    return this.deps.policyBudgetSources.listBudgetSummaries();
  }

  // ── Local-only enforcement helpers ─────────────────────────────────

  /**
   * Validate that a caller-supplied filter does not request cross-fortress
   * scope; v1.1 hub is single-fortress; the filter rejects fortress-bridging
   * fields outright; v1.3 federation will introduce an alternate surface.
   */
  static assertLocalOnlyFilter(filter: Record<string, unknown> | null): void {
    if (!filter) return;
    for (const key of Object.keys(filter)) {
      if (
        key === "fortress_id" ||
        key === "peer_id" ||
        key === "remote_fortress_id"
      ) {
        throw new HubLocalOnlyError(
          `filter field '${key}' is not supported at v1.1 (cross-fortress reach)`,
        );
      }
    }
  }

  /**
   * Test/inspection helper. Not part of the public service surface.
   */
  inboxStoreSize(): number {
    return this.inboxStore.size();
  }

  // ── Operator chat (WP-V1.2-4) ──────────────────────────────────────

  private requireOperatorChat(): NonNullable<HubServiceDeps["operatorChat"]> {
    if (!this.deps.operatorChat) {
      throw new HubCapabilityError("operator_chat_not_wired");
    }
    return this.deps.operatorChat;
  }

  /**
   * Operator submit on the concierge chat surface. Pass-through to the
   * operator-chat-service which owns substrate-selector routing, PII
   * filtering, persistence, and audit emission.
   */
  async sendConcierge(query: string): Promise<ConciergeResponse> {
    const chat = this.requireOperatorChat();
    return chat.sendConcierge(query);
  }

  /**
   * Read the persisted concierge thread.
   */
  async getConciergeHistory(): Promise<OperatorChatMessage[]> {
    const chat = this.requireOperatorChat();
    return chat.getConciergeHistory();
  }

  // ── Concierge memory threads (WP-V1.3-9 Tau-1) ─────────────────────

  /**
   * Whether the operator-chat service has the WP-V1.3-9 memory store
   * wired. Routes use this to 503 cleanly when the foundation memory
   * surface is unavailable on a given fortress.
   */
  hasConciergeMemory(): boolean {
    return Boolean(this.deps.operatorChat?.hasConciergeMemory());
  }

  async listConciergeMemoryThreads(
    opts?: ListThreadsOptions,
  ): Promise<ConciergeThreadSummary[]> {
    const chat = this.requireOperatorChat();
    if (!chat.hasConciergeMemory()) {
      throw new HubCapabilityError("concierge_memory_not_wired");
    }
    return chat.listConciergeMemoryThreads(opts);
  }

  async readConciergeMemoryThread(
    threadId: string,
    opts?: ReadThreadOptions,
  ): Promise<ConciergeTurn[]> {
    const chat = this.requireOperatorChat();
    if (!chat.hasConciergeMemory()) {
      throw new HubCapabilityError("concierge_memory_not_wired");
    }
    return chat.readConciergeMemoryThread(threadId, opts);
  }

  async deleteConciergeMemoryThread(threadId: string): Promise<boolean> {
    const chat = this.requireOperatorChat();
    if (!chat.hasConciergeMemory()) {
      throw new HubCapabilityError("concierge_memory_not_wired");
    }
    return chat.deleteConciergeMemoryThread(threadId);
  }

  /**
   * Open the click-to-inspect/approve panel for a wrapped agent. The
   * panel surfaces recent activity routed through this agent, pending
   * Tier 1 approvals on this agent, and the bound policy summary,
   * repurposing the click-to-chat wire-up from PR #98 + PR #100 to a
   * substrate-aligned inspect destination after the v1.2 reshape removed
   * direct-agent chat.
   *
   * Synchronous open shape preserved (caller's `await` semantics
   * unchanged from the prior `openDirectAgentSession` surface). The
   * panel is read-only; no side effects beyond the audit-event emission
   * for the panel-open itself.
   */
  async openAgentInspectPanel(
    agentId: string,
    options: { activityLimit?: number } = {},
  ): Promise<HubAgentInspectPanel> {
    const record = this.getAgent(agentId);
    const limit = options.activityLimit ?? 20;
    const recentActivity = await this.listActivity({
      agent_id: record.agent_id,
      limit,
    });
    const pendingApprovals = this.listInbox().filter(
      (item) =>
        !item.resolved &&
        item.kind === "approval_pending" &&
        item.agent_id === record.agent_id,
    );
    const policySummary =
      typeof record.channel_template_id === "string"
        ? this.listPolicySummaries().find(
            (summary) =>
              summary.channel_template_id === record.channel_template_id,
          ) ?? null
        : null;

    const openedAt = this.nowIso();
    void this.deps.activitySources.auditLog.append(
      "l2",
      "agent_inspect_panel_opened",
      this.deps.identityId,
      {
        agent_id: record.agent_id,
        identity_id: record.identity_id,
        opened_at: openedAt,
        activity_count: recentActivity.length,
        pending_approvals_count: pendingApprovals.length,
      },
    );

    return {
      agent_id: record.agent_id,
      opened_at: openedAt,
      recent_activity: recentActivity,
      pending_approvals: pendingApprovals,
      policy_summary: policySummary,
    };
  }
}

export {
  HubConflictError,
  HubCapabilityError,
  HubLocalOnlyError,
  HubNotFoundError,
  HubValidationError,
};
