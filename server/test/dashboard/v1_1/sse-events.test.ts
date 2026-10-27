import { describe, expect, it } from "vitest";
import { extractStreamEventId } from "../../../src/dashboard/v1_1/sse-events.js";
import type {
  HubActivityFeedEntry,
  HubAgentStatusSnapshot,
} from "../../../src/contracts/v1.1/hub-events.js";
import type { HubInboxStreamFrame } from "../../../src/hub/types.js";

describe("v1.1 dashboard SSE event ids", () => {
  it("returns the inbox item_id with its state and emission time", () => {
    const frame = {
      item_id: "inbox-item-001",
      kind: "approval_pending",
      identity_id: "identity-001",
      fortress_id: "fortress-001",
      emitted_at: "2026-06-06T10:00:00.000Z",
      resolved: false,
    } satisfies HubInboxStreamFrame;

    const otherItem = { ...frame, item_id: "inbox-item-002" } satisfies HubInboxStreamFrame;

    // Stability half of the dedup property: a distinct frame object carrying
    // the same item, state and emission time must produce the same id (so a
    // duplicate inbox event arriving across the reconnect refetch overlap dedupes).
    const sameFrameDifferentObject = { ...frame };

    // The item is announced again when it resolves and when it re-emits after
    // a clear; each announcement is a new event, never a duplicate of the first.
    const resolvedLater = { ...frame, resolved: true, emitted_at: "2026-06-06T10:00:05.000Z" } satisfies HubInboxStreamFrame;
    const reemittedLater = { ...frame, emitted_at: "2026-06-06T10:00:09.000Z" } satisfies HubInboxStreamFrame;

    const id = extractStreamEventId({ type: "inbox", data: frame });
    expect(id).toBe("inbox-item-001:open:2026-06-06T10:00:00.000Z");
    expect(extractStreamEventId({ type: "inbox", data: otherItem })).toBe("inbox-item-002:open:2026-06-06T10:00:00.000Z");
    expect(extractStreamEventId({ type: "inbox", data: sameFrameDifferentObject })).toBe(id);
    expect(extractStreamEventId({ type: "inbox", data: resolvedLater })).not.toBe(id);
    expect(extractStreamEventId({ type: "inbox", data: reemittedLater })).not.toBe(id);
    expect(extractStreamEventId({ type: "inbox", data: resolvedLater })).not.toBe(extractStreamEventId({ type: "inbox", data: reemittedLater }));
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
