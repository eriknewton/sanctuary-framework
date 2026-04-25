/**
 * Sanctuary v1.1 Coordination — Context Transfer
 *
 * Materializes a single context slot from the sender's namespace into a form
 * the recipient may consume. Two gates run in fixed order:
 *
 *   1. Recipient policy gate — does the recipient's pinned policy permit
 *      reading this slot from the sender? Hermetic deny on null policy
 *      flows through naturally.
 *   2. Privacy filter — when configured, outbound content is filtered
 *      through the operator's privacy policy before it reaches the
 *      recipient. The destination_category is `peer-agent` so the privacy
 *      core's audit trail attributes the event to a local handoff.
 *
 * Both gates produce audit signal through their existing receipt + event
 * surfaces; the coordinator does not duplicate that audit traffic. The
 * caller is the consumer of this function — it is invoked when the
 * recipient agent actually pulls content, not at handoff create time.
 */

import type {
  CoordinationGateDecision,
  CoordinationPolicyGate,
} from "./coordinator.js";
import type { LocalHandoffRecord } from "../contracts/v1.1/handoff-records.js";

/** A single content slot to materialize from sender to recipient. */
export interface ContextSlotRequest {
  slot: "memory" | "credentials" | "plans" | "outputs";
  /** Raw content the sender exposes for transfer. Filtered before return. */
  content: unknown;
}

/**
 * Privacy-engine adapter. Coordination keeps the dependency injectable so
 * the privacy module owns its own contract; we only need a single hook that
 * filters a payload destined for a peer-agent recipient.
 */
export interface CoordinationPrivacyFilter {
  filterForPeerAgent(input: {
    sender_agent_id: string;
    recipient_agent_id: string;
    identity_id: string;
    payload: unknown;
  }): Promise<{ status: "allowed" | "filtered" | "denied"; payload: unknown }>;
}

export type ContextTransferResult =
  | {
      status: "allowed";
      slot: ContextSlotRequest["slot"];
      content: unknown;
    }
  | {
      status: "filtered";
      slot: ContextSlotRequest["slot"];
      content: unknown;
    }
  | {
      status: "denied";
      slot: ContextSlotRequest["slot"];
      reason_code: string;
    };

export interface TransferContextSlotInput {
  handoff: LocalHandoffRecord;
  request: ContextSlotRequest;
  policyGate: CoordinationPolicyGate;
  privacyFilter?: CoordinationPrivacyFilter;
}

export async function transferContextSlot(
  input: TransferContextSlotInput,
): Promise<ContextTransferResult> {
  if (input.handoff.status !== "accepted") {
    return {
      status: "denied",
      slot: input.request.slot,
      reason_code: "handoff_not_accepted",
    };
  }
  const gateDecision: CoordinationGateDecision =
    input.policyGate.evaluateContextTransfer({
      sender_agent_id: input.handoff.sender_agent_id,
      recipient_agent_id: input.handoff.recipient_agent_id,
      identity_id: input.handoff.identity_id,
      requested_capabilities: [input.request.slot],
    });
  if (gateDecision.decision === "deny") {
    return {
      status: "denied",
      slot: input.request.slot,
      reason_code: gateDecision.reason_code,
    };
  }

  if (!input.privacyFilter) {
    return {
      status: "allowed",
      slot: input.request.slot,
      content: input.request.content,
    };
  }

  const filterResult = await input.privacyFilter.filterForPeerAgent({
    sender_agent_id: input.handoff.sender_agent_id,
    recipient_agent_id: input.handoff.recipient_agent_id,
    identity_id: input.handoff.identity_id,
    payload: input.request.content,
  });
  if (filterResult.status === "denied") {
    return {
      status: "denied",
      slot: input.request.slot,
      reason_code: "privacy_filter_denied",
    };
  }
  return {
    status: filterResult.status === "allowed" ? "allowed" : "filtered",
    slot: input.request.slot,
    content: filterResult.payload,
  };
}
