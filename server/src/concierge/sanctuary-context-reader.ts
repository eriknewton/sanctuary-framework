import type { SanctuaryConfig } from "../config.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { PublicIdentity } from "../core/identity.js";
import type { StateStore } from "../cognitive/state-store.js";
import {
  TASK_STATUSES,
  TaskService,
  type Task,
  type TaskStatus,
} from "../operational/task-coordination/index.js";
import type {
  HubInboxSources,
  HubPolicyAndBudgetSources,
} from "../hub/types.js";
import {
  CONCIERGE_READ_SURFACES,
  type ApprovalInboxContext,
  type AuditLogContext,
  type ConciergeAskRequest,
  type ConciergeContextBundle,
  type IdentityRegistryContext,
  type SovereigntyProfileContext,
  type StateStoreContext,
  type TaskStateContext,
} from "./concierge-types.js";

export interface SanctuaryContextReaderDeps {
  auditLog: Pick<AuditLog, "query" | "append">;
  identityManager: Pick<IdentityManager, "listWithRotationCount" | "list">;
  inboxSources: HubInboxSources;
  policyBudgetSources?: HubPolicyAndBudgetSources;
  taskService?: Pick<TaskService, "list">;
  stateStore?: Pick<StateStore, "list" | "read">;
  config?: SanctuaryConfig;
  fortressId: string;
  storagePath?: string;
  identityId: string;
  now?: () => Date;
}

export class SanctuaryContextReader {
  private readonly deps: SanctuaryContextReaderDeps;

  constructor(deps: SanctuaryContextReaderDeps) {
    this.deps = deps;
  }

  async readContext(request: ConciergeAskRequest): Promise<ConciergeContextBundle> {
    const now = request.now ?? this.deps.now?.() ?? new Date();
    const auditQuery = inferAuditQuery(request.question, request.maxAuditEntries);
    const [
      audit_log,
      identity_registry,
      approval_inbox,
      sovereignty_profile,
      task_state,
      state_store,
    ] = await Promise.all([
      this.readAuditLog(auditQuery),
      this.readIdentityRegistry(),
      this.readApprovalInbox(now),
      this.readSovereigntyProfile(),
      this.readTaskState(),
      this.readStateStore(request.includePayloads === true),
    ]);

    void this.deps.auditLog.append(
      "l2",
      "concierge.state_read",
      this.deps.identityId,
      {
        read_surfaces: CONCIERGE_READ_SURFACES,
        question_fingerprint: fingerprint(request.question),
      },
    );

    return {
      generated_at: now.toISOString(),
      read_surfaces: [...CONCIERGE_READ_SURFACES],
      audit_log,
      identity_registry,
      approval_inbox,
      sovereignty_profile,
      task_state,
      state_store,
    };
  }

  private async readAuditLog(query: {
    since?: string;
    operation_type?: string;
    limit: number;
  }): Promise<AuditLogContext> {
    const result = await this.deps.auditLog.query({
      ...(query.since ? { since: query.since } : {}),
      ...(query.operation_type ? { operation_type: query.operation_type } : {}),
      limit: query.limit,
    });
    return {
      total_matching: result.total,
      entries: result.entries,
      integrity_findings: result.integrity_findings,
    };
  }

  private async readIdentityRegistry(): Promise<IdentityRegistryContext> {
    const listed = this.deps.identityManager.listWithRotationCount();
    return {
      identities: listed.map((identity: PublicIdentity & { rotation_count?: number }) => ({
        ...identity,
        kid: identity.public_key,
        roles: [identity.identity_id === this.deps.identityId ? "operator" : "identity"],
      })),
    };
  }

  private readApprovalInbox(now: Date): ApprovalInboxContext {
    const items = [
      ...this.deps.inboxSources.listPendingApprovals(),
      ...this.deps.inboxSources.listRecentBlockedEgress(),
      ...this.deps.inboxSources.listRecentPrivacyEvents(),
      ...this.deps.inboxSources.listActiveBudgetWarnings(),
      ...this.deps.inboxSources.listActiveRecoveryPrompts(),
      ...this.deps.inboxSources.listRecentAgentErrors(),
    ];
    const pending = items.filter((item) => !item.resolved);
    return {
      pending_count: pending.length,
      items: pending.map((item) => ({
        item_id: item.item_id,
        kind: item.kind,
        created_at: item.created_at,
        resolved: item.resolved,
        age_seconds: Math.max(
          0,
          Math.floor((now.getTime() - new Date(item.created_at).getTime()) / 1000),
        ),
        status: item.resolved ? "resolved" : "pending",
        ...("tier" in item && typeof item.tier === "string" ? { tier: item.tier } : {}),
        ...("operation_category" in item && typeof item.operation_category === "string"
          ? { operation_category: item.operation_category }
          : {}),
        ...(item.agent_id ? { agent_id: item.agent_id } : {}),
        ...(item.identity_id ? { identity_id: item.identity_id } : {}),
      })),
    };
  }

  private readSovereigntyProfile(): SovereigntyProfileContext {
    const policies = this.deps.policyBudgetSources?.listPolicySummaries() ?? [];
    const config = this.deps.config;
    return {
      fortress_id: this.deps.fortressId,
      ...(this.deps.storagePath ? { storage_path: this.deps.storagePath } : {}),
      tier_policy: policies.length
        ? `${policies.length} policy summaries bound`
        : "policy summaries unavailable",
      context_gating_state: "operator CLI concierge only; no MCP exposure",
      castle_wall: {
        dashboard_enabled: config?.dashboard.enabled ?? false,
        ...(config?.dashboard.host ? { dashboard_host: config.dashboard.host } : {}),
        ...(config?.dashboard.port ? { dashboard_port: config.dashboard.port } : {}),
        ...(config?.transport ? { transport: config.transport } : {}),
      },
    };
  }

  private async readTaskState(): Promise<TaskStateContext> {
    const tasks = this.deps.taskService ? await this.deps.taskService.list() : [];
    const status_counts = TASK_STATUSES.reduce(
      (acc, status) => ({ ...acc, [status]: 0 }),
      {} as Record<TaskStatus, number>,
    );
    for (const task of tasks) status_counts[task.status]++;
    const recent = [...tasks]
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
      .slice(0, 20);
    return {
      total: tasks.length,
      status_counts,
      tasks: recent,
      recent_activity: recent.map((task: Task) => ({
        task_id: task.id,
        title: task.title,
        status: task.status,
        updated_at: task.updated_at,
        ...(task.assignee ? { assignee: task.assignee } : {}),
      })),
    };
  }

  private async readStateStore(includePayloads: boolean): Promise<StateStoreContext> {
    if (!this.deps.stateStore) {
      return { include_payloads: includePayloads, namespaces: [] };
    }
    const namespaces = ["sanctuary.tasks", "_sovereignty_profile", "_context_gate_policies"];
    const summaries: StateStoreContext["namespaces"] = [];
    for (const namespace of namespaces) {
      const listed = await this.deps.stateStore.list(namespace, undefined, undefined, 25);
      const recent = [...listed.keys]
        .sort((a, b) => b.written_at.localeCompare(a.written_at))
        .slice(0, 10);
      summaries.push({
        namespace,
        total_keys: listed.total,
        recent_keys: await Promise.all(
          recent.map(async (entry) => ({
            key: entry.key,
            version: entry.version,
            size_bytes: entry.size_bytes,
            written_at: entry.written_at,
            tags: entry.tags,
            ...(includePayloads
              ? {
                  payload:
                    (await this.deps.stateStore!.read(namespace, entry.key).catch(
                      () => null,
                    ))?.value ?? undefined,
                }
              : {}),
          })),
        ),
      });
    }
    return { include_payloads: includePayloads, namespaces: summaries };
  }
}

function inferAuditQuery(
  question: string,
  explicitLimit?: number,
): { since?: string; operation_type?: string; limit: number } {
  const lower = question.toLowerCase();
  const limit = explicitLimit ?? (lower.includes("audit") ? 50 : 20);
  const since = lower.includes("today")
    ? new Date(new Date().setHours(0, 0, 0, 0)).toISOString()
    : undefined;
  const operation_type = lower.includes("approval")
    ? "approval_request"
    : lower.includes("task")
      ? "task.create"
      : undefined;
  return {
    ...(since ? { since } : {}),
    ...(operation_type ? { operation_type } : {}),
    limit,
  };
}

function fingerprint(value: string): string {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}
