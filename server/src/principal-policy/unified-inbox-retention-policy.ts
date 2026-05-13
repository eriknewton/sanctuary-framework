import type { AuditLog } from "../l2-operational/audit-log.js";
import type {
  UnifiedInboxBridge,
  UnifiedInboxEntryState,
  UnifiedInboxSourceClass,
} from "./unified-inbox-bridge.js";

export interface RetentionPolicy {
  source_class: UnifiedInboxSourceClass;
  state: Extract<UnifiedInboxEntryState, "archived" | "dismissed">;
  retain_for_days: number;
}

export interface RetentionSweepResult {
  fortress_id: string;
  deleted: number;
  archived_deleted: number;
  dismissed_deleted: number;
}

export const INBOX_RETENTION_AUDIT_OPS = {
  SWEPT: "inbox_retention_swept",
  POLICY_UPDATED: "inbox_retention_policy_updated",
} as const;

const DEFAULT_ARCHIVED_DAYS = 90;
const DEFAULT_DISMISSED_DAYS = 30;

export class UnifiedInboxRetentionPolicy {
  private readonly overrides = new Map<string, RetentionPolicy>();

  constructor(initial?: RetentionPolicy[]) {
    for (const policy of initial ?? []) {
      this.set(policy);
    }
  }

  list(): RetentionPolicy[] {
    return [...this.overrides.values()].sort((a, b) =>
      `${a.source_class}:${a.state}`.localeCompare(`${b.source_class}:${b.state}`),
    );
  }

  set(policy: RetentionPolicy): void {
    if (!Number.isFinite(policy.retain_for_days) || policy.retain_for_days < 0) {
      throw new Error("retain_for_days must be a non-negative number");
    }
    this.overrides.set(keyFor(policy.source_class, policy.state), {
      source_class: policy.source_class,
      state: policy.state,
      retain_for_days: Math.floor(policy.retain_for_days),
    });
  }

  daysFor(
    sourceClass: UnifiedInboxSourceClass,
    state: RetentionPolicy["state"],
  ): number {
    return (
      this.overrides.get(keyFor(sourceClass, state))?.retain_for_days ??
      (state === "archived" ? DEFAULT_ARCHIVED_DAYS : DEFAULT_DISMISSED_DAYS)
    );
  }
}

export async function sweepUnifiedInboxRetention(opts: {
  bridge: UnifiedInboxBridge;
  policy?: UnifiedInboxRetentionPolicy;
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  now?: Date;
}): Promise<RetentionSweepResult> {
  const policy = opts.policy ?? new UnifiedInboxRetentionPolicy();
  const nowMs = (opts.now ?? new Date()).getTime();
  let archivedDeleted = 0;
  let dismissedDeleted = 0;
  const expiredIds: string[] = [];

  for (const entry of opts.bridge.queryInbox({
    state: ["archived", "dismissed"],
  })) {
    const state = entry.state === "archived" ? "archived" : "dismissed";
    const anchor = state === "archived" ? entry.archived_at : entry.dismissed_at;
    const anchorMs = Date.parse(anchor ?? entry.resolved_at ?? entry.observed_at);
    if (!Number.isFinite(anchorMs)) continue;
    const retainMs = policy.daysFor(entry.source_class, state) * 24 * 60 * 60 * 1000;
    if (anchorMs + retainMs > nowMs) continue;
    expiredIds.push(entry.inbox_id);
    if (state === "archived") archivedDeleted += 1;
    else dismissedDeleted += 1;
  }

  if (expiredIds.length > 0) {
    opts.bridge.deleteBatch(expiredIds);
  }

  const result: RetentionSweepResult = {
    fortress_id: opts.fortressId,
    deleted: expiredIds.length,
    archived_deleted: archivedDeleted,
    dismissed_deleted: dismissedDeleted,
  };
  opts.auditLog.append(
    "l2",
    INBOX_RETENTION_AUDIT_OPS.SWEPT,
    opts.identityId,
    { ...result },
  );
  return result;
}

function keyFor(
  sourceClass: UnifiedInboxSourceClass,
  state: RetentionPolicy["state"],
): string {
  return `${sourceClass}:${state}`;
}
