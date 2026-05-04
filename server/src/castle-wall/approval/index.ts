/** Public surface of the approval module. */

export type {
  ApprovalConfidence,
  ApprovalPromptRequest,
  CoalescingWindow,
  PromptCoalescingConfig,
  CoalesceResult,
} from "./types.js";
export {
  LOW_CONFIDENCE_LABELS,
  shouldRequireStrictConfirmation,
  defaultPromptCoalescingConfig,
} from "./types.js";
