/**
 * Sanctuary v1.1 Dashboard — SSE Event Taxonomy Extensions
 *
 * The existing dashboard SSE producer at `server/src/dashboard/api.ts`
 * emits three event names: `snapshot`, `activity`, `approval`. v1.1 adds
 * two more: `inbox` and `agent_status`. Producer wiring is preserved
 * intact; this module declares the new event-name shapes so consumers and
 * producers agree on a single payload contract.
 *
 * Reconnect-and-restore rule: the v1.1 client drops to a refetch
 * (snapshot + inbox + activity) on disconnect, then resumes SSE. Event
 * payloads carry a stable `event_id` so duplicates that arrive across the
 * refetch overlap can be deduped client-side.
 */

import type {
  HubActivityFeedEntry,
  HubAgentStatusSnapshot,
  HubInboxItem,
} from "../../contracts/v1.1/hub-events.js";

/** New v1.1 SSE event for hub inbox updates. */
export interface HubInboxStreamEvent {
  type: "inbox";
  data: HubInboxItem;
}

/** New v1.1 SSE event for per-agent status changes. */
export interface HubAgentStatusStreamEvent {
  type: "agent_status";
  data: HubAgentStatusSnapshot;
}

/** Existing SSE shapes augmented with v1.1 typing. */
export interface HubActivityStreamEvent {
  type: "activity";
  data: HubActivityFeedEntry;
}

/**
 * Discriminated union of every v1.1 hub-emitted SSE event. The
 * `snapshot` and `approval` events from the v1.0 dashboard live in
 * `dashboard/api.ts` and are not re-typed here; they pass through
 * unchanged.
 */
export type HubV11StreamEvent =
  | HubInboxStreamEvent
  | HubAgentStatusStreamEvent
  | HubActivityStreamEvent;

/** Stable event-id extractor for client-side deduplication. */
export function extractStreamEventId(
  event: HubV11StreamEvent,
): string | null {
  switch (event.type) {
    case "inbox":
      return event.data.item_id;
    case "agent_status":
      return `${event.data.agent_id}:${event.data.last_activity_at}`;
    case "activity":
      return event.data.entry_id;
  }
}
