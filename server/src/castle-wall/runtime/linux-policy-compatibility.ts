/**
 * Linux L2 policy profile and fail-before publication gate.
 *
 * The packet evaluator currently receives only a kernel-authenticated agent id
 * and the destination IP/port/protocol tuple. It has no authenticated DNS/SNI
 * binding and no template attestation. Keep that limitation at the producer
 * boundary as well as in Rust: an incompatible rule must be refused before it
 * is signed or sent to the privileged broker.
 */

import type { AllowlistRule } from "../allowlist/schema.js";
import { validateAgentOrigin } from "../allowlist/agent-origin.js";
import {
  LinuxInstallAgentIdScopeError,
  validateLinuxInstallAgentIdScopes,
} from "../allowlist/confined-agent-id.js";
import {
  formatBoundedDiagnosticList,
  formatBoundedDiagnosticValue,
} from "../allowlist/bounded-diagnostic-text.js";
import {
  publishSignedManifest,
  type BuildSignedManifestInput,
  type ManifestStorage,
} from "./manifest-publisher.js";
import { RuntimeLinuxActivationError } from "./errors.js";

// Must match `RuleScope` in castle-wall-daemon/src/policy.rs.
export const LINUX_DAEMON_RULE_SCOPE_AXES = Object.freeze([
  "agent_ids",
  "template_ids",
] as const);

const LINUX_DAEMON_RULE_SCOPE_AXIS_SET = new Set<string>(LINUX_DAEMON_RULE_SCOPE_AXES);

export const LINUX_SIGNABLE_SCOPE_AXES = Object.freeze(["agent_ids"] as const);

export const LINUX_IP_CIDR_POLICY_PROFILE = Object.freeze({
  id: "linux-ip-cidr-v1",
  destination_axes: Object.freeze(["ip", "cidr"] as const),
  optional_match_axes: Object.freeze(["port", "protocol"] as const),
  daemon_modeled_scope_axes: LINUX_DAEMON_RULE_SCOPE_AXES,
  supported_scope_axes: LINUX_SIGNABLE_SCOPE_AXES,
  scope_axis_subset_reason:
    "template_ids is modeled by the daemon RuleScope but is not signable until template attestation is available; uids is macOS-only and is not modeled by the Linux daemon.",
  refused_axes: Object.freeze([
    "host",
    "host_pattern",
    "template_ids",
    "uids",
    "time_window",
  ] as const),
});

export type LinuxPolicyCompatibilityAxis =
  | "match.host"
  | "match.host_pattern"
  | "match.destination"
  | `scope.${string}`
  | "scope.template_ids"
  | "time_window";

export interface LinuxPolicyCompatibilityIssue {
  ruleId: string;
  axis: LinuxPolicyCompatibilityAxis;
  reason: string;
}

function hasValues(value: string | readonly string[] | undefined): boolean {
  return typeof value === "string" ? value.length > 0 : Array.isArray(value) && value.length > 0;
}

/** Return every Linux-profile incompatibility in stable rule/axis order. */
export function inspectLinuxPolicyCompatibility(
  rules: readonly AllowlistRule[]
): readonly LinuxPolicyCompatibilityIssue[] {
  const issues: LinuxPolicyCompatibilityIssue[] = [];
  for (const rule of rules) {
    if (rule.time_window !== undefined) {
      issues.push({
        ruleId: rule.id,
        axis: "time_window",
        reason: "Linux L2 has no authenticated time-window enforcement",
      });
    }
    if (rule.match.host !== undefined) {
      issues.push({
        ruleId: rule.id,
        axis: "match.host",
        reason: "authenticated DNS/SNI binding is unavailable",
      });
    }
    if (rule.match.host_pattern !== undefined) {
      issues.push({
        ruleId: rule.id,
        axis: "match.host_pattern",
        reason: "authenticated DNS/SNI binding is unavailable",
      });
    }
    for (const axis of Object.keys(rule.scope ?? {})) {
      if (LINUX_DAEMON_RULE_SCOPE_AXIS_SET.has(axis)) continue;
      // The Linux signer must refuse a scope axis before signing because the
      // Rust loader rejects unmodeled scope fields at parse time.
      issues.push({
        ruleId: rule.id,
        axis: `scope.${axis}`,
        reason:
          axis === "uids"
            ? "macOS-only scope axis is not modeled by the Linux daemon"
            : "scope axis is not modeled by the Linux daemon",
      });
    }
    if ((rule.scope.template_ids?.length ?? 0) > 0) {
      issues.push({
        ruleId: rule.id,
        axis: "scope.template_ids",
        reason: "template attestation is unavailable",
      });
    }
    if (!hasValues(rule.match.ip) && !hasValues(rule.match.cidr)) {
      issues.push({
        ruleId: rule.id,
        axis: "match.destination",
        reason: "Linux L2 requires a non-empty ip or cidr destination",
      });
    }
  }
  return issues;
}

export function assertLinuxPolicyCompatibility(rules: readonly AllowlistRule[]): void {
  const issues = inspectLinuxPolicyCompatibility(rules);
  if (issues.length === 0) return;
  const summary = formatBoundedDiagnosticList(
    issues,
    (issue) =>
      // Refusal diagnostics include local rule text, so each echoed value gets a fixed display budget.
      `${formatBoundedDiagnosticValue(issue.ruleId)}:${formatBoundedDiagnosticValue(issue.axis)} (${issue.reason})`,
  );
  throw new RuntimeLinuxActivationError(
    `Castle Wall Linux policy is incompatible with ${LINUX_IP_CIDR_POLICY_PROFILE.id}: ${summary}`,
    "policy_incompatible"
  );
}

/** Sign and publish only after the complete rule set passes the Linux profile. */
export async function publishLinuxCompatiblePolicy(
  input: BuildSignedManifestInput,
  storage: ManifestStorage
): Promise<Awaited<ReturnType<typeof publishSignedManifest>>> {
  assertLinuxPolicyCompatibility(input.rules);
  const origin = validateAgentOrigin(input.agentOrigin);
  if (origin?.mode === "uid" && origin.agent_uid !== undefined) {
    // The broker and installer publish through this producer gate, so uid-mode scopes are refused before signing.
    try {
      validateLinuxInstallAgentIdScopes(input.rules, origin.agent_uid);
    } catch (error) {
      if (error instanceof LinuxInstallAgentIdScopeError) {
        throw new RuntimeLinuxActivationError(
          `Castle Wall Linux policy is incompatible with ${LINUX_IP_CIDR_POLICY_PROFILE.id}: ${error.message}`,
          "policy_incompatible",
        );
      }
      throw error;
    }
  }
  return publishSignedManifest(input, storage);
}
