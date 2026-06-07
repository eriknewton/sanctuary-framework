import { describe, expect, it } from "vitest";
import { extractStreamEventId } from "../../../src/dashboard/v1_1/sse-events.js";
import type {
  HubActivityFeedEntry,
  HubAgentStatusSnapshot,
  HubInboxItem,
} from "../../../src/contracts/v1.1/hub-events.js";

describe("v1.1 dashboard SSE event ids", () => {
  it("returns the inbox item_id", () => {
    const inboxItem = {
      version: "1.1",
      item_id: "inbox-item-001",
      kind: "approval_pending",
      created_at: "2026-06-06T10:00:00.000Z",
      identity_id: "identity-001",
      display_template_id: "approval_pending.tier1.export",
      display_template_args: [],
      resolved: false,
      tier: "tier1",
      operation_category: "state_export",
    } satisfies HubInboxItem;

    const otherInboxItem = {
      ...inboxItem,
      item_id: "inbox-item-002",
    } satisfies HubInboxItem;

    // Stability half of the dedup property: a distinct snapshot object
    // carrying the same item_id must produce the same id (so a duplicate
    // inbox event arriving across the reconnect refetch overlap dedupes).
    const sameItemDifferentSnapshot = {
      ...inboxItem,
      resolved: true,
      display_template_id: "approval_pending.tier1.import",
    } satisfies HubInboxItem;

    const id = extractStreamEventId({ type: "inbox", data: inboxItem });
    expect(id).toBe("inbox-item-001");
    expect(
      extractStreamEventId({ type: "inbox", data: otherInboxItem }),
    ).toBe("inbox-item-002");
    expect(
      extractStreamEventId({ type: "inbox", data: sameItemDifferentSnapshot }),
    ).toBe(id);
  });

  it("returns the agent_status composite agent_id:last_activity_at key", () => {
    const agentStatus = {
      version: "1.1",
      agent_id: "agent-alpha",
      status: "active",
      last_activity_at: "2026-06-06T10:00:00.000Z",
      open_inbox_item_ids: [],
    } satisfies HubAgentStatusSnapshot;
    const sameAgentSameActivityDifferentSnapshot = {
      version: "1.1",
      agent_id: "agent-alpha",
      status: "paused",
      last_activity_at: "2026-06-06T10:00:00.000Z",
      open_inbox_item_ids: ["inbox-item-001"],
    } satisfies HubAgentStatusSnapshot;
    const sameAgentLaterActivity = {
      ...agentStatus,
      last_activity_at: "2026-06-06T10:05:00.000Z",
    } satisfies HubAgentStatusSnapshot;
    const differentAgentSameActivity = {
      ...agentStatus,
      agent_id: "agent-beta",
    } satisfies HubAgentStatusSnapshot;

    const id = extractStreamEventId({
      type: "agent_status",
      data: agentStatus,
    });
    const sameAgentSameActivityDifferentSnapshotId = extractStreamEventId({
      type: "agent_status",
      data: sameAgentSameActivityDifferentSnapshot,
    });
    const sameAgentLaterActivityId = extractStreamEventId({
      type: "agent_status",
      data: sameAgentLaterActivity,
    });
    const differentAgentSameActivityId = extractStreamEventId({
      type: "agent_status",
      data: differentAgentSameActivity,
    });

    expect(id).toBe("agent-alpha:2026-06-06T10:00:00.000Z");
    expect(sameAgentSameActivityDifferentSnapshotId).toBe(
      "agent-alpha:2026-06-06T10:00:00.000Z",
    );
    expect(sameAgentSameActivityDifferentSnapshotId).toBe(id);
    expect(sameAgentLaterActivityId).toBe(
      "agent-alpha:2026-06-06T10:05:00.000Z",
    );
    expect(differentAgentSameActivityId).toBe(
      "agent-beta:2026-06-06T10:00:00.000Z",
    );
  });

  it("returns the activity entry_id", () => {
    const activityEntry = {
      version: "1.1",
      entry_id: "activity-entry-001",
      emitted_at: "2026-06-06T10:00:00.000Z",
      identity_id: "identity-001",
      category: "lifecycle",
      display_template_id: "lifecycle.agent.started",
      display_template_args: [],
    } satisfies HubActivityFeedEntry;

    expect(
      extractStreamEventId({ type: "activity", data: activityEntry }),
    ).toBe("activity-entry-001");
  });
});
