/**
 * Operator approval-flow types.
 *
 * The dashboard surface receives an ApprovalPromptRequest, displays it via the
 * menubar, collects the operator's four-button decision, and returns it via
 * the IPC DecisionResponse. The coalescing layer here is the throttle that
 * defeats prompt-flood attacks per scope-lock section 5 amendment 2.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 6 + Codex
 * amendment E6.3 (confidence-warning UI default for opaque destinations).
 */

import {
  CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP,
  CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS,
} from "../constants.js";
import type { IpcAgentAttribution, IpcDestination } from "../ipc/messages.js";

/** Confidence label shown to the operator alongside the four-button choice. */
export type ApprovalConfidence =
  | "high"
  | "low_opaque"
  | "low_raw_ip"
  | "low_doh_dot";

/** Subset of confidence labels that trigger the strict-mode extra-confirmation path. */
export const LOW_CONFIDENCE_LABELS: ReadonlyArray<ApprovalConfidence> = Object.freeze([
  "low_opaque",
  "low_raw_ip",
  "low_doh_dot",
]);

/**
 * The dashboard-facing prompt request. The dashboard derives confidence from
 * the IpcDestination's hostname_source + opaque flag; the daemon emits the
 * raw destination, the dashboard derives the label.
 */
export interface ApprovalPromptRequest {
  request_id: string;
  destination: IpcDestination;
  agent: IpcAgentAttribution;
  confidence: ApprovalConfidence;
  rate_limited: boolean;
  expires_at: string;
}

/** Compute the default-strict-mode flag for a destination based on confidence. */
export function shouldRequireStrictConfirmation(
  confidence: ApprovalConfidence,
  strictModeEnabled: boolean
): boolean {
  if (!strictModeEnabled) return false;
  return LOW_CONFIDENCE_LABELS.includes(confidence);
}

/** Window record used by the daemon-side coalescer. */
export interface CoalescingWindow {
  count: number;
  window_started_at: string;
}

/**
 * Coalescing configuration. Defaults match scope-lock section 5 (5 prompts
 * per 30-second window per agent-instance). PR 4 implements the in-memory
 * coalescer that consumes this config.
 */
export interface PromptCoalescingConfig {
  default_cap_per_agent: {
    count: number;
    window_seconds: number;
  };
  per_template_overrides: Record<
    string,
    { count: number; window_seconds: number }
  >;
}

/** v1.0 default coalescing configuration. */
export function defaultPromptCoalescingConfig(): PromptCoalescingConfig {
  return {
    default_cap_per_agent: {
      count: CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP,
      window_seconds: CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS,
    },
    per_template_overrides: {},
  };
}

/**
 * Tagged result from the coalescer. The daemon calls coalesce() to decide
 * whether to forward a novel-destination prompt to main or to suppress it.
 * Subsequent PRs implement the actual coalescer; this is the contract type.
 */
export type CoalesceResult =
  | { kind: "emit"; window: CoalescingWindow }
  | { kind: "suppress"; reason: "flood_cap_exceeded"; window: CoalescingWindow };
