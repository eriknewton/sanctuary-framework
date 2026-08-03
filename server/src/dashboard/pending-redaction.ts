export interface PendingApprovalsRedactedMarker {
  pending_approvals_redacted: true;
  pending_approvals_count: number;
}

function redactedCount(count: number): number {
  return Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
}

/**
 * Admission-class chokepoint for pending-approval disclosure. Any payload that
 * would expose operator-only pending approval rows to a loopback-position
 * caller is reduced to this count-only marker before emission.
 */
export function pendingApprovalsRedactedMarker(
  count: number,
): PendingApprovalsRedactedMarker {
  return {
    pending_approvals_redacted: true,
    pending_approvals_count: redactedCount(count),
  };
}

export function isPendingApprovalsRedactedMarker(
  value: unknown,
): value is PendingApprovalsRedactedMarker {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    record.pending_approvals_redacted === true &&
    typeof record.pending_approvals_count === "number"
  );
}

export function isHubApprovalPendingItem(value: unknown): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    (value as { kind?: unknown }).kind === "approval_pending"
  );
}

export function redactApprovalPendingItemsForPositionOnly<T>(
  items: readonly T[],
): {
  items: T[];
  pending_approvals_redacted?: true;
  pending_approvals_count?: number;
} {
  const visible = items.filter((item) => !isHubApprovalPendingItem(item));
  const hiddenCount = items.length - visible.length;
  if (hiddenCount <= 0) return { items: visible };
  return {
    items: visible,
    ...pendingApprovalsRedactedMarker(hiddenCount),
  };
}
