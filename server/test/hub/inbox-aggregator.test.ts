/**
 * Sanctuary v1.1 Hub inbox aggregator regression suite.
 *
 * Real HubInboxStore; source callbacks are small in-test fakes whose arrays
 * are controlled by each test.
 */

import { describe, expect, it } from "vitest";

import type {
  HubAgentErrorItem,
  HubApprovalPendingItem,
  HubBlockedEgressItem,
  HubBudgetWarningItem,
  HubInboxItem,
  HubPrivacyEventItem,
  HubRecoveryPromptItem,
} from "../../src/contracts/v1.1/hub-events.js";
import { aggregateInbox } from "../../src/hub/inbox-aggregator.js";
import { HubInboxStore } from "../../src/hub/inbox-store.js";
import type { HubInboxSources } from "../../src/hub/types.js";

const IDENTITY_ID = "operator-inbox-aggregator-test-001";
const CREATED_AT = "2026-01-02T03:04:05.000Z";
const RESOLVED_AT = "2026-01-02T04:05:06.000Z";

interface SourceRig {
  sources: HubInboxSources;
  approvals: HubApprovalPendingItem[];
  blockedEgress: HubBlockedEgressItem[];
  privacyEvents: HubPrivacyEventItem[];
  budgetWarnings: HubBudgetWarningItem[];
  recoveryPrompts: HubRecoveryPromptItem[];
  agentErrors: HubAgentErrorItem[];
}

function sourceRig(): SourceRig {
  const rig = {
    approvals: [] as HubApprovalPendingItem[],
    blockedEgress: [] as HubBlockedEgressItem[],
    privacyEvents: [] as HubPrivacyEventItem[],
    budgetWarnings: [] as HubBudgetWarningItem[],
    recoveryPrompts: [] as HubRecoveryPromptItem[],
    agentErrors: [] as HubAgentErrorItem[],
  };

  return {
    ...rig,
    sources: {
      listPendingApprovals: () => rig.approvals,
      listRecentBlockedEgress: () => rig.blockedEgress,
      listRecentPrivacyEvents: () => rig.privacyEvents,
      listActiveBudgetWarnings: () => rig.budgetWarnings,
      listActiveRecoveryPrompts: () => rig.recoveryPrompts,
      listRecentAgentErrors: () => rig.agentErrors,
    },
  };
}

function ids(items: HubInboxItem[]): string[] {
  return items.map((item) => item.item_id);
}

function header(itemId: string, kind: HubInboxItem["kind"]) {
  return {
    version: "1.1" as const,
    item_id: itemId,
    kind,
    created_at: CREATED_AT,
    identity_id: IDENTITY_ID,
    display_template_id: `${kind}.test`,
    display_template_args: [],
    resolved: false,
  };
}

function approval(itemId: string): HubApprovalPendingItem {
  return {
    ...header(itemId, "approval_pending"),
    tier: "tier1",
    operation_category: "lockdown",
  };
}

function blockedEgress(itemId: string): HubBlockedEgressItem {
  return {
    ...header(itemId, "blocked_egress"),
    destination_category: "tool-api",
    block_reason_class: "egress_policy_deny",
  };
}

function privacyEvent(itemId: string): HubPrivacyEventItem {
  return {
    ...header(itemId, "privacy_event"),
    privacy_event_id: `${itemId}-privacy-event`,
    privacy_event_kind: "denied",
  };
}

function budgetWarning(itemId: string): HubBudgetWarningItem {
  return {
    ...header(itemId, "budget_warning"),
    bucket: "daily",
    severity: "soft_warn",
    used_fraction: 0.8,
  };
}

function recoveryPrompt(itemId: string): HubRecoveryPromptItem {
  return {
    ...header(itemId, "recovery_prompt"),
    recovery_class: "exit_drill",
  };
}

function agentError(itemId: string): HubAgentErrorItem {
  return {
    ...header(itemId, "agent_error"),
    error_class: "harness_error",
    agent_still_active: true,
  };
}

describe("aggregateInbox", () => {
  it("returns an empty list for empty sources and an empty store", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();

    expect(aggregateInbox(rig.sources, store)).toEqual([]);
    expect(store.size()).toBe(0);
  });

  it("pulls items from a single source kind into the store and returns them", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.approvals.push(approval("approval-single-001"));

    expect(aggregateInbox(rig.sources, store)).toEqual([
      approval("approval-single-001"),
    ]);
    expect(store.size()).toBe(1);
  });

  it("aggregates all source kinds in source-pull order", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.approvals.push(approval("approval-all-001"));
    rig.blockedEgress.push(blockedEgress("blocked-egress-all-001"));
    rig.privacyEvents.push(privacyEvent("privacy-event-all-001"));
    rig.budgetWarnings.push(budgetWarning("budget-warning-all-001"));
    rig.recoveryPrompts.push(recoveryPrompt("recovery-prompt-all-001"));
    rig.agentErrors.push(agentError("agent-error-all-001"));

    const items = aggregateInbox(rig.sources, store);

    expect(items).toHaveLength(6);
    expect(ids(items)).toEqual([
      "approval-all-001",
      "blocked-egress-all-001",
      "privacy-event-all-001",
      "budget-warning-all-001",
      "recovery-prompt-all-001",
      "agent-error-all-001",
    ]);
    expect(store.size()).toBe(6);
  });

  it("deduplicates re-emitted source items across aggregate runs", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.approvals.push(approval("approval-dedup-001"));
    rig.agentErrors.push(agentError("agent-error-dedup-001"));

    expect(ids(aggregateInbox(rig.sources, store))).toEqual([
      "approval-dedup-001",
      "agent-error-dedup-001",
    ]);
    expect(ids(aggregateInbox(rig.sources, store))).toEqual([
      "approval-dedup-001",
      "agent-error-dedup-001",
    ]);
    expect(store.size()).toBe(2);
  });

  it("does not revert resolution when a source re-emits the same item", async () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.blockedEgress.push(blockedEgress("blocked-egress-resolved-001"));

    aggregateInbox(rig.sources, store);
    await store.resolve("blocked-egress-resolved-001", "dismiss", RESOLVED_AT);
    rig.blockedEgress[0] = {
      ...blockedEgress("blocked-egress-resolved-001"),
      block_reason_class: "lockdown_active",
      display_template_args: [
        { kind: "destination_category", value: "tool-api" },
      ],
    };

    const items = aggregateInbox(rig.sources, store);
    const resolvedItem = items.find(
      (item) => item.item_id === "blocked-egress-resolved-001",
    );

    expect(resolvedItem).toEqual({
      ...blockedEgress("blocked-egress-resolved-001"),
      block_reason_class: "lockdown_active",
      display_template_args: [
        { kind: "destination_category", value: "tool-api" },
      ],
      resolved: true,
      resolved_at: RESOLVED_AT,
    });
    expect(store.get("blocked-egress-resolved-001")).toEqual(resolvedItem);
  });

  it("includes a brand-new source item that appears on a later aggregate call", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.privacyEvents.push(privacyEvent("privacy-event-mutation-001"));

    expect(ids(aggregateInbox(rig.sources, store))).toEqual([
      "privacy-event-mutation-001",
    ]);

    rig.privacyEvents.push(privacyEvent("privacy-event-mutation-002"));

    expect(ids(aggregateInbox(rig.sources, store))).toEqual([
      "privacy-event-mutation-001",
      "privacy-event-mutation-002",
    ]);
    expect(store.size()).toBe(2);
  });

  it("collapses items that share an item_id across different source kinds (last-write-wins by item_id)", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    rig.approvals.push(approval("COLLIDE-001"));
    rig.agentErrors.push(agentError("COLLIDE-001"));

    const items = aggregateInbox(rig.sources, store);

    // CHARACTERIZATION ONLY — this pins current behavior, it does NOT endorse it.
    // upsertFromSource keys solely on item_id, so a later source pull overwrites
    // an earlier item's whole shape (here an agent_error clobbers an approval card).
    // This is a last-write-wins merge with no kind/source guard. It is NOT reachable
    // in production today: hub-enqueued Tier 1 approval ids are
    // `tier1.<action>.<agent_id>.<randomUUID()>` (hub-service.ts) and source ids are
    // audit-chain-derived, so the namespaces cannot collide. If the merge key ever
    // changes (or ids stop being globally unique) this test must be revisited — and
    // the latent fragility it documents (a colliding source item could mutate a Tier 1
    // card's `kind`, which resolve() gates handler execution on) is tracked as a
    // separate coordinator-reviewed hardening item, intentionally out of scope here.
    expect(store.size()).toBe(1);
    expect(items).toEqual([agentError("COLLIDE-001")]);
    expect(items[0]?.kind).toBe("agent_error");
  });

  it("includes hub-enqueued Tier 1 items alongside source items", () => {
    const rig = sourceRig();
    const store = new HubInboxStore();
    const hubItem = approval("approval-hub-enqueued-001");
    rig.budgetWarnings.push(budgetWarning("budget-warning-source-001"));

    store.enqueueTier1(hubItem, async () => undefined);

    const items = aggregateInbox(rig.sources, store);

    expect(ids(items)).toEqual([
      "approval-hub-enqueued-001",
      "budget-warning-source-001",
    ]);
    expect(items).toEqual([hubItem, budgetWarning("budget-warning-source-001")]);
    expect(store.size()).toBe(2);
  });
});
