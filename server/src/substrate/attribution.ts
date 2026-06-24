import type { HookClass } from "./fields.js";
import type { PluginDecision } from "./verdict.js";

export type PluginContributionVerdict =
  | PluginDecision
  | "fail_mode_applied"
  | "timeout"
  | "unhealthy_skipped";

export interface PluginContribution {
  plugin_id: string;
  bundle_hash: string;
  instance_id: string;
  hook_class: HookClass;
  verdict: PluginContributionVerdict;
  confidence?: number;
  rationale: string;
  latency_ms: number;
  transcript_ref?: string;
}

const MAX_CONTRIBUTION_RATIONALE_CHARS = 4096;

export function boundContributionRationale(rationale: string): string {
  if (rationale.length <= MAX_CONTRIBUTION_RATIONALE_CHARS) return rationale;
  return rationale.slice(0, MAX_CONTRIBUTION_RATIONALE_CHARS);
}
