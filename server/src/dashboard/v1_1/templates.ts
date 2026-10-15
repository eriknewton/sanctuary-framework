/**
 * Sanctuary v1.1 Dashboard - Display Template Registry
 *
 * Backends emit (display_template_id, display_template_args). The dashboard
 * owns the human-readable strings. This module is the single source of
 * truth for that mapping.
 *
 * Safe-fallback rule: an unknown template id MUST produce a diagnostic
 * placeholder rather than throw. Adding a new id without an entry is a UI
 * regression, not a runtime crash.
 *
 * No-em-dash rule: every operator-visible string here uses periods, commas,
 * colons, or parentheses. Em-dashes (U+2014) are reserved for internal
 * comments only.
 *
 * Naming-discipline rule: no competitor names in any operator-visible
 * string. Composition partners are not surfaced here at all (composition
 * page is hidden at v1.1 ship).
 *
 * UBAI-retirement rule: no "Universal Basic AI" / "UBAI" / "AI for everyone"
 * surfaces. v1.1 is the Local Sovereignty Harness.
 */

import type { HubDisplayTemplateArg } from "../../contracts/v1.1/hub-events.js";
import { HUB_ACTIVITY_TEMPLATE_NAMESPACES } from "../../hub/constants.js";

// Must match ACTIVITY_TEMPLATE_NAMESPACES in client.ts, injected from hub/constants.ts.
const ACTIVITY_TEMPLATE_NAMESPACES = Object.values(HUB_ACTIVITY_TEMPLATE_NAMESPACES);

// Categories whose sentence only says an event of that kind was recorded, so it holds for every operation the hub
// files there. The other category sentences assert an actor or an outcome (an operator approval or denial, traffic
// that left, a decision, an internal handoff, a lifecycle change, a change applied) that an operation in the category
// need not carry: the hub files by prefix, substring and catch-all rules, so views and refusals land there too.
const ACTIVITY_CATEGORIES_WITH_GENERAL_SENTENCES: ReadonlyArray<keyof typeof HUB_ACTIVITY_TEMPLATE_NAMESPACES> = [
  "privacy",
  "other",
];

/** The registered sentence an operation-suffixed activity id renders through, and the arg it needs to render. */
export interface ActivityFallbackTemplate {
  readonly template: string;
  /** A typed arg that must carry a nonempty value for the sentence to render; null when the sentence needs none. */
  readonly requiredArg: "agent_id" | null;
}

/**
 * How an operation-suffixed activity id renders, keyed by its category namespace: the category's own sentence where
 * that sentence is true of every operation in it, the generic audit sentence otherwise. The generic sentence renders
 * only for a row with a verified agent; any other row keeps the diagnostic fallback.
 * Must match ACTIVITY_FALLBACK_TEMPLATES in client.ts, which is injected from this map.
 */
export const ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE: Readonly<Record<string, ActivityFallbackTemplate>> = Object.freeze(
  Object.fromEntries(
    (Object.keys(HUB_ACTIVITY_TEMPLATE_NAMESPACES) as Array<keyof typeof HUB_ACTIVITY_TEMPLATE_NAMESPACES>).map(
      (category) => {
        const template = ACTIVITY_CATEGORIES_WITH_GENERAL_SENTENCES.includes(category)
          ? HUB_ACTIVITY_TEMPLATE_NAMESPACES[category]
          : HUB_ACTIVITY_TEMPLATE_NAMESPACES.other;
        // The generic sentence names its agent and reads "(fortress)" when none is served. The hub serves agent_id
        // only when the producer signature re-verifies, so a row without one has no verified subject and must not be
        // attributed to the fortress. Privacy names a missing agent as unknown and needs no arg.
        const requiredArg = template === HUB_ACTIVITY_TEMPLATE_NAMESPACES.other ? "agent_id" : null;
        return [HUB_ACTIVITY_TEMPLATE_NAMESPACES[category], Object.freeze({ template, requiredArg })];
      },
    ),
  ),
);

/**
 * Render-context flags pass through to the template fn so a single template
 * id can produce slightly different strings for inbox cards versus the
 * activity feed (e.g., past-tense vs. action-prompt).
 */
export interface TemplateRenderContext {
  /**
   * Where the template is being rendered. Templates may use this to vary
   * tense or omit subject when the surrounding card already carries it.
   */
  surface: "inbox" | "activity" | "chat" | "agent_detail";
}

export type TemplateRenderer = (
  args: HubDisplayTemplateArg[],
  ctx: TemplateRenderContext,
) => string;

/**
 * Lookup helper. Returns the value of the first arg of the requested kind,
 * or the fallback string. Template authors stay defensive: backends must
 * pass typed args, but a missing arg is rendered as a stable placeholder
 * (not the empty string, not a thrown error).
 */
function arg(
  args: HubDisplayTemplateArg[],
  kind: HubDisplayTemplateArg["kind"],
  fallback = "(unknown)",
): string {
  const found = args.find((a) => a.kind === kind);
  if (!found) return fallback;
  switch (found.kind) {
    case "agent_id":
    case "identity_id":
    case "policy_id":
    case "channel_template_id":
    case "destination_category":
    case "tier":
    case "iso8601":
      return String(found.value);
    case "count":
    case "duration_ms":
      return String(found.value);
  }
}

/**
 * True when the first arg of `kind`, the one `arg` renders, carries a nonempty string. Must match hasArgValue in
 * client.ts.
 */
function hasArgValue(args: HubDisplayTemplateArg[], kind: HubDisplayTemplateArg["kind"]): boolean {
  // A null element is skipped, as the client mirror skips it, so a malformed arg list reaches the diagnostic fallback.
  const found = Array.isArray(args) ? args.find((a) => Boolean(a) && a.kind === kind) : undefined;
  return found !== undefined && typeof found.value === "string" && found.value.length > 0;
}

/**
 * Format an iso8601 string as a short "Apr 25, 14:32" style for ops UI.
 * Falls back to the raw value when parsing fails.
 */
function shortTime(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const month = d.toLocaleString("en-US", { month: "short" });
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${month} ${day}, ${hh}:${mm}`;
}

// ─────────────────────────────────────────────────────────────────────────
// Template registry
// ─────────────────────────────────────────────────────────────────────────

// Cross-file contract: every key in this registry must have a matching key
// in the client TEMPLATES map in client.ts (mirror of server templates.ts,
// ~line 372). Enforced by the full-set parity test in templates.test.ts;
// a key present here but absent there falls through to
// "[unrecognized template: ...]" on a live operator-facing card.
const TEMPLATES: Record<string, TemplateRenderer> = {
  // ── approval_pending.tier1.* ─────────────────────────────────────────
  "approval_pending.tier1.lockdown": (a) =>
    `Cut agent ${arg(a, "agent_id")}'s network access. The agent keeps running and keeps local access; it stops reaching anything off this machine.`,
  "approval_pending.tier1.fortress_lockdown": () =>
    "Lockdown approval pending. Approving revokes network access for confined agents. Agents keep running and keep local access; off-machine reachability is cut when Castle Wall reloads.",
  "approval_pending.tier1.fortress_exit_bundle_export": () =>
    "Export the entire fortress as a portable exit bundle.",
  // Must match "approval_pending.tier1.unwrap" in client.ts.
  "approval_pending.tier1.unwrap": (a) =>
    `Request to remove protection from agent ${arg(a, "agent_id")}. This build refuses unsupported removals before approval is queued.`,
  "approval_pending.tier1.policy_change": (a) =>
    `Bind agent ${arg(a, "agent_id")} to policy ${arg(a, "policy_id")}.`,
  "approval_pending.tier1.policy_change_template": (a) =>
    `Bind agent ${arg(a, "agent_id")} to template ${arg(a, "policy_id")}.`,
  "approval_pending.tier1.exit_bundle_export": (a) =>
    `Export the fortress as a portable bundle. Agent: ${arg(a, "agent_id", "all agents")}.`,
  "approval_pending.tier1.exit_bundle_import": (a) =>
    `Import a portable bundle into this fortress. Agent: ${arg(a, "agent_id", "all agents")}.`,
  "approval_pending.tier1.exit_bundle_rekey": (a) =>
    `Re-key encrypted state for portable export. Agent: ${arg(a, "agent_id", "all agents")}.`,
  "approval_pending.tier1.state_export": (a) =>
    `Export agent ${arg(a, "agent_id")} state as a portable bundle.`,
  "approval_pending.tier1.state_import": (a) =>
    `Import state into agent ${arg(a, "agent_id")}.`,
  "approval_pending.tier1.state_delete": (a) =>
    `Delete state for agent ${arg(a, "agent_id")}. This is irreversible.`,
  "approval_pending.tier1.identity_rotate": (a) =>
    `Rotate the identity key for ${arg(a, "agent_id", "this fortress")}.`,
  "approval_pending.tier1.reputation_export": (a) =>
    `Export reputation bundle for ${arg(a, "agent_id")}.`,
  "approval_pending.tier1.reputation_import": (a) =>
    `Import reputation bundle for ${arg(a, "agent_id")}.`,
  "approval_pending.tier1.sanctuary_export_identity_bundle": (a) =>
    `Export the operator identity bundle for ${arg(a, "agent_id", "this operator")}.`,
  "approval_pending.tier1.other": (a) =>
    `Tier 1 operation pending on agent ${arg(a, "agent_id", "(no agent)")}.`,

  // ── approval_pending.tier2.* ─────────────────────────────────────────
  "approval_pending.tier2.policy_change": (a) =>
    `Tier 2 policy change requested on agent ${arg(a, "agent_id")}.`,
  "approval_pending.tier2.other": (a) =>
    `Tier 2 operation pending on agent ${arg(a, "agent_id", "(no agent)")}.`,

  // ── blocked_egress.* ─────────────────────────────────────────────────
  "blocked_egress.egress_policy_deny": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked by policy on agent ${arg(a, "agent_id")}.`,
  "blocked_egress.budget_exceeded": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked: budget exceeded for agent ${arg(a, "agent_id")}.`,
  "blocked_egress.privacy_fail_closed": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked: privacy filter unavailable, fail-closed default applied for agent ${arg(a, "agent_id")}.`,
  "blocked_egress.privacy_deny_rule": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked by privacy rule on agent ${arg(a, "agent_id")}.`,
  "blocked_egress.lockdown_active": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked by active lockdown on agent ${arg(a, "agent_id")}.`,
  "blocked_egress.other": (a) =>
    `Egress to ${arg(a, "destination_category")} blocked on agent ${arg(a, "agent_id")}.`,

  // ── privacy_event.* ─────────────────────────────────────────────────
  "privacy_event.filtered": (a) =>
    `Privacy filter applied to outbound traffic from agent ${arg(a, "agent_id")}.`,
  "privacy_event.allowed": (a) =>
    `Outbound traffic allowed by privacy policy for agent ${arg(a, "agent_id")}.`,
  "privacy_event.denied": (a) =>
    `Outbound traffic denied by privacy policy for agent ${arg(a, "agent_id")}.`,
  "privacy_event.error": (a) =>
    `Privacy filter error on agent ${arg(a, "agent_id")}. Outbound traffic blocked, fail-closed.`,
  "privacy_event.rehydrated": (a) =>
    `Inbound response rehydrated through placeholder vault for agent ${arg(a, "agent_id")}.`,

  // ── budget_warning.* ────────────────────────────────────────────────
  "budget_warning.soft_warn": (a) =>
    `Budget soft-warn on agent ${arg(a, "agent_id")}.`,
  "budget_warning.hard_cap": (a) =>
    `Budget hard-cap reached on agent ${arg(a, "agent_id")}. Operator unblock required.`,

  // ── recovery_prompt.* ───────────────────────────────────────────────
  "recovery_prompt.passphrase_reset": () =>
    `Recommended: rotate the fortress passphrase.`,
  "recovery_prompt.keychain_rebind": () =>
    `Recommended: rebind the keychain entry for this fortress.`,
  "recovery_prompt.config_backup_restore": () =>
    `Recommended: back up your current configuration.`,
  "recovery_prompt.exit_drill": () =>
    `Recommended: run an exit drill so you know recovery works.`,
  "recovery_prompt.other": () =>
    `Recovery action recommended.`,

  // ── agent_error.* ───────────────────────────────────────────────────
  "agent_error.harness_error": (a) =>
    `Agent ${arg(a, "agent_id")} reported a harness error.`,
  "agent_error.harness_unreachable": (a) =>
    `Agent ${arg(a, "agent_id")} is unreachable.`,
  "agent_error.policy_breach": (a) =>
    `Agent ${arg(a, "agent_id")} attempted a policy-breaching action and was blocked.`,
  "agent_error.config_drift": (a) =>
    `Agent ${arg(a, "agent_id")} configuration has drifted from the bound policy.`,
  "agent_error.other": (a) =>
    `Agent ${arg(a, "agent_id")} reported an internal error.`,

  // ── activity feed templates ──────────────────────────────────────────
  "activity.policy_decision": (a) =>
    `Policy gate decision on agent ${arg(a, "agent_id")}.`,
  "activity.approval": (a, ctx) => {
    const tense = ctx.surface === "activity" ? "approved" : "approve";
    return `Operator ${tense} action for agent ${arg(a, "agent_id")}.`;
  },
  "activity.denial": (a, ctx) => {
    const tense = ctx.surface === "activity" ? "denied" : "deny";
    return `Operator ${tense} action for agent ${arg(a, "agent_id")}.`;
  },
  "activity.egress": (a) =>
    `Outbound traffic from agent ${arg(a, "agent_id")} to ${arg(a, "destination_category")}.`,
  "activity.privacy": (a) =>
    `Privacy event recorded for agent ${arg(a, "agent_id")}.`,
  "activity.handoff": (a) =>
    `Internal handoff event involving agent ${arg(a, "agent_id")}.`,
  "activity.lifecycle": (a) =>
    `Lifecycle change on agent ${arg(a, "agent_id")} at ${shortTime(arg(a, "iso8601", ""))}.`,
  "activity.lifecycle.agent_lockdown_engaged": (a) =>
    `Network access revoked for agent ${arg(a, "agent_id")}.`,
  "activity.lifecycle.agent_lockdown_partial": (a) =>
    `Network access was revoked on disk for agent ${arg(a, "agent_id")}, but the live Castle Wall reload was not confirmed.`,
  "activity.lifecycle.agent_lockdown_refused": (a) =>
    `Network stop refused for agent ${arg(a, "agent_id")}.`,
  "activity.lifecycle.fortress_lockdown_engaged": () =>
    "Fortress lockdown engaged for all confined agents.",
  "activity.lifecycle.fortress_lockdown_partial": () =>
    "Fortress lockdown partially engaged; at least one confined agent could not be locked.",
  "activity.lifecycle.fortress_lockdown_failed": () =>
    "Fortress lockdown failed; no confined agent was locked.",
  "activity.lifecycle.fortress_lockdown_no_agents": () =>
    "Fortress lockdown found no confined agents to lock.",
  "activity.agent_policy_change_engaged": (a) =>
    `Template binding changed on agent ${arg(a, "agent_id")}: ${arg(a, "channel_template_id", "default none")} to ${arg(a, "policy_id")}.`,
  "activity.agent_policy_change_denied": (a) =>
    `Template binding denied on agent ${arg(a, "agent_id")}: ${arg(a, "channel_template_id", "default none")} to ${arg(a, "policy_id")}.`,
  "activity.config": (a) =>
    `Configuration change applied. Agent: ${arg(a, "agent_id", "(fortress)")}.`,
  "activity.other": (a) =>
    `Audit event recorded for agent ${arg(a, "agent_id", "(fortress)")}.`,
};

const DEFAULT_CTX: TemplateRenderContext = { surface: "inbox" };

/**
 * Resolve a (template_id, args) pair into operator-readable text.
 *
 * Returns a safe diagnostic fallback when the id is unknown. The fallback
 * contains the id so the dashboard developer can grep for it; the original
 * args are NOT interpolated into the fallback because some args may not be
 * safe to render outside a known template (defense-in-depth).
 */
export function renderTemplate(
  templateId: string,
  args: HubDisplayTemplateArg[],
  ctx: TemplateRenderContext = DEFAULT_CTX,
): string {
  let renderer = TEMPLATES[templateId];
  if (!renderer && typeof templateId === "string") {
    // The hub serves operation-suffixed ids; the dashboard registers sentences per category. An operation renders its
    // category's sentence only where that sentence is true of every operation the hub files there.
    const namespace = ACTIVITY_TEMPLATE_NAMESPACES.find((prefix) => templateId.startsWith(`${prefix}.`));
    const fallback = namespace ? ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE[namespace] : undefined;
    // A row without a verified agent never renders a sentence that would name the fortress as its subject: the hub
    // serves agent_id only for a re-verified producer signature, so the row keeps the diagnostic fallback instead.
    if (fallback && (fallback.requiredArg === null || hasArgValue(args, fallback.requiredArg))) {
      renderer = TEMPLATES[fallback.template];
    }
  }
  if (!renderer) {
    return `[unrecognized template: ${templateId}]`;
  }
  try {
    return renderer(args, ctx);
  } catch {
    return `[template render failed: ${templateId}]`;
  }
}

/**
 * Test-only helper: list every registered template id. Used by registry
 * coverage tests. Not part of the runtime render path.
 */
export function listRegisteredTemplateIds(): string[] {
  return Object.keys(TEMPLATES).sort();
}
