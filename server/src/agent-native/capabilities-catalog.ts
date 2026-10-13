/**
 * Sanctuary Agent-Native surface - Capabilities catalog (first-class surfacing).
 *
 * Availability is not use. The cooperative tools already exist and are
 * introspectable via tools/list, but a cooperative agent has to DISCOVER them
 * and understand WHEN to reach for each one. This module is the single source
 * of that "start here" catalog. It feeds two universal, harness-agnostic
 * discovery surfaces:
 *
 *   1. The MCP server `instructions` string (returned in the initialize
 *      response). This is the standard MCP mechanism: a harness reads it once
 *      at connect time to learn what the server is for.
 *   2. The `sanctuary_capabilities` tool, so an agent can re-read the catalog
 *      on demand mid-session without re-initializing.
 *
 * Agent-facing UX (forward-documentation rule): every string here is product
 * copy for an AI-agent audience deciding whether to call a tool. It is
 * accurate and never overclaims: it describes only what the cooperative tools
 * DO, and it does not promise enforcement it cannot deliver on its own. The
 * cooperative layer is "wants-to-do-good-via-Sanctuary"; it does not itself
 * block anything (that is the separate Castle Wall enforcement layer).
 */

import {
  CATALOG_COOPERATIVE_TOOL_NAMES,
  COOPERATIVE_TOOL_NAMES,
  type CatalogCooperativeToolName,
} from "./tool-names.js";

/** One cooperative tool's entry in the start-here catalog. */
export interface CapabilityEntry {
  /** The exact MCP tool name (must match the registered tool). */
  tool: CatalogCooperativeToolName;
  /** One line: what the tool does, agent-facing. */
  does: string;
  /** One line: when an agent should reach for it. */
  when: string;
}

/**
 * The cooperative-tool catalog, ordered from "read your context" to
 * "act on memory" to "review your history". Only the stable cooperative
 * surface is listed; internal/compound tools are intentionally omitted from
 * the start-here summary to keep it legible for a first-time agent.
 */
export const COOPERATIVE_CAPABILITIES: readonly CapabilityEntry[] = [
  {
    tool: COOPERATIVE_TOOL_NAMES.help,
    does: "Classifies a free-text intent and returns which Sanctuary tool to use, with a runnable example for ordinary requests; evaluation questions (what this protects, the bounds, which platforms, how to verify, how to uninstall) route to the read-only posture tools or to the CLI command that answers.",
    when: "You are unsure which tool fits, or you are deciding whether to install or keep this server. Ask here first before acting.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.whoAmI,
    does: "Returns the disclosable identity facts for this session (label, did, identity fingerprint, memory namespace handle). Never returns private keys.",
    when: "You need to confirm which sovereign identity you are operating as.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.activeProtections,
    does: "Lists the security guarantees currently in force (encrypted-at-rest state, approval-gate mediation, append-only audit, opaque memory handles).",
    when: "You need to tell a counterparty, or yourself, what protections apply right now.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.remember,
    does: "Stores a key/value into encrypted, identity-bound, audited memory. Prefer this over raw state_write for working memory you want auditable.",
    when: "You want to persist working memory that survives across turns.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.recall,
    does: "Reads a key back from encrypted memory, verifying integrity before returning it.",
    when: "You need to retrieve something you (or a prior turn) stored.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.hide,
    does: "Marks a stored key so sanctuary_recall stops returning it, without deleting the data.",
    when: "You want to suppress a memory from default reads but keep it recoverable.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.forget,
    does: "Permanently deletes a memory key. Operator-approved (Tier 1): pass an approval proof. At-rest confidentiality rests on encryption, not on overwrite.",
    when: "The operator has approved permanently removing a memory.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.eventsOpenCursor,
    does: "Opens a paginated cursor over your own redacted audit events, optionally filtered by operation.",
    when: "You want to page through your recent activity. Read with sanctuary_events_read, then sanctuary_events_close.",
  },
  {
    tool: COOPERATIVE_TOOL_NAMES.auditSearch,
    does: "Full-text searches your own audit history (own-signed scope only), verified against the audit chain.",
    when: "You need to find when a past operation ran and its result.",
  },
] as const;

const catalogToolNames = COOPERATIVE_CAPABILITIES.map((entry) => entry.tool);
if (catalogToolNames.join("\0") !== CATALOG_COOPERATIVE_TOOL_NAMES.join("\0")) {
  throw new Error("cooperative capabilities catalog drifted from tool-name contract");
}

/**
 * Canonical URL of the Assurance Matrix, the evidence ledger every capability
 * claim in this repository traces to. Must match the `ASSURANCE_MATRIX.md`
 * link target in the root README.md (the file at the repository root on
 * `main`).
 */
export const ASSURANCE_MATRIX_URL =
  "https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md";

/**
 * The bounds an evaluating agent must hear before it believes anything else
 * this server says about itself: the platforms the wall is proven on, the
 * approval tiers, what is never claimed, and where the evidence lives.
 *
 * Must match README.md "Summary for agents" ("What it is not" and "Platforms
 * and runtime") and the Assurance Matrix rows they cite. `platforms` and
 * `neverClaimed` are COPIED sentence for sentence from the README, never
 * paraphrased: `server/test/structure/server-bounds-copied-from-readme.test.ts`
 * asserts each sentence is a README substring, so a stronger claim cannot be
 * typed here without first landing in the README. Every enforcement sentence
 * carries "on a patched host" because the drills that proved it ran on a
 * patched host and nothing here extends the proof beyond that.
 */
export const SERVER_BOUNDS = {
  platforms:
    "macOS: proven, on a patched host. Linux enforcement is proven on Ubuntu 24.04 (x86-64) only, on a patched host; every other distribution or architecture remains unproven. Windows enforcement is roadmapped; nothing enforces on Windows today.",
  tiers:
    "Approval runs in three tiers: Tier 3 auto-allows with an audit record, Tier 2 asks a human on anomaly, and Tier 1 always waits for a human.",
  neverClaimed:
    "No Assurance Matrix row claims a filesystem or process sandbox for the agent; that is what your harness's own sandbox provides. The record is not an audited per-rule, per-flow trail.",
  evidence:
    `Every claim, its platform and its evidence is a row in the Assurance Matrix at ${ASSURANCE_MATRIX_URL}; to evaluate this install call monitor_health, then sovereignty_audit.`,
} as const;

/** The four bounds sentences as one paragraph, in the order an agent needs them. */
export function buildBoundsParagraph(): string {
  return [
    SERVER_BOUNDS.platforms,
    SERVER_BOUNDS.tiers,
    SERVER_BOUNDS.neverClaimed,
    SERVER_BOUNDS.evidence,
  ].join(" ");
}

/**
 * The read-only tools an evaluating agent is routed to by `sanctuary_help`.
 *
 * These are wire tool names registered outside this module, so they are
 * pinned here rather than imported: must match the `name` literal of
 * `monitor_health` in `server/src/index.ts`, of `sovereignty_audit` in
 * `server/src/audit/tools.ts`, and of `sanctuary_policy_status` in
 * `server/src/sanctuary-tools.ts`; `test/agent-native/first-class-surfacing.test.ts`
 * boots the real server and fails if any of them stops being registered.
 */
export const EVALUATE_ROUTE_TOOLS = {
  activeProtections: COOPERATIVE_TOOL_NAMES.activeProtections,
  monitorHealth: "monitor_health",
  sovereigntyAudit: "sovereignty_audit",
  policyStatus: "sanctuary_policy_status",
} as const;

export type EvaluateRouteToolName =
  (typeof EVALUATE_ROUTE_TOOLS)[keyof typeof EVALUATE_ROUTE_TOOLS];

/**
 * What each evaluate-route tool answers and the tier it runs at under the
 * default policy. Tier labels must match `DEFAULT_POLICY` in
 * `server/src/principal-policy/loader.ts`: the three posture reads are in
 * `tier3_always_allow`; `sanctuary_policy_status` is a forced Tier 1 read
 * (reading the policy is never unattended). The first-class-surfacing test
 * asserts this table against the policy so a re-tiering cannot leave it stale.
 */
export const EVALUATE_RELATED_TOOLS = [
  {
    tool: EVALUATE_ROUTE_TOOLS.activeProtections,
    tier: "Tier 3 (auto-allowed with an audit record)",
    use_for: "the guarantees in force for this session, reported only when active",
  },
  {
    tool: EVALUATE_ROUTE_TOOLS.monitorHealth,
    tier: "Tier 3 (auto-allowed with an audit record)",
    use_for: "this instance's health, wall status and configured-but-unverified posture",
  },
  {
    tool: EVALUATE_ROUTE_TOOLS.sovereigntyAudit,
    tier: "Tier 3 (auto-allowed with an audit record)",
    use_for: "a scored gap analysis of the local sovereignty posture",
  },
  {
    tool: EVALUATE_ROUTE_TOOLS.policyStatus,
    tier: "Tier 1 (waits for operator approval on every call)",
    use_for: "the active Tier 1 and Tier 3 operation lists",
  },
] as const;

/**
 * The two evaluate questions no MCP tool answers: verification runs end to
 * end on the CLI, and removal is deliberately not an MCP tool. Must match the
 * `doctor` and `uninstall` verbs in `server/src/cli/subcommands.ts` and the
 * `protect --unwrap` flag in `server/src/cli.ts`. The removal split (the
 * enforcement footprint versus the harness config) must match the README
 * "Uninstall" paragraph: the route also matches "unwrap", so the guidance
 * names both commands or an agent asking to unwrap is sent to the wrong one.
 */
export const EVALUATE_CLI_GUIDANCE = {
  verify:
    "On the CLI, run `sanctuary doctor --json`; it is read-only and prints one JSON object with a `checks` array (healthy: exit code 0 and no check with status FAIL). In-session, monitor_health reports what this server can see of its own posture.",
  uninstall:
    "On the CLI: `sanctuary uninstall` removes the installed enforcement footprint and keeps the fortress state, keys and audit log; `sanctuary protect --unwrap` restores the original harness config and removes nothing else. There is no MCP tool for either.",
} as const;

/** The named evaluate states `sanctuary_help` can land in; first match wins. */
export type EvaluateQuestion =
  | "uninstall"
  | "verify"
  | "tiers"
  | "protections"
  | "bounds"
  | "install_decision";

export interface EvaluateRoute {
  readonly question: EvaluateQuestion;
  /** Word-boundary needles over the lower-cased intent; never the `g` flag (test() would keep state). */
  readonly matches: RegExp;
  readonly tool: EvaluateRouteToolName | null;
  readonly example: Record<string, unknown> | null;
  readonly why_sanctuary: string;
  readonly guidance: string;
}

/**
 * The evaluate nouns, one word form per entry so a test can iterate them. An
 * intent that carries one is a question about the socket itself, so
 * `classifyIntent` consults EVALUATE_ROUTES before the ordinary memory
 * routes, but only over a bare read/get verb: any other memory verb
 * (remember, store, save, recall, lookup; the sets in
 * MEMORY_VERBS, `cooperative-surface.ts`) outranks the noun, so "remember
 * platform=linux" and "recall my bounds note" stay memory intents while
 * "read the bounds" is a bounds question. "protected" is deliberately absent:
 * it is an adjective about the agent's own data ("read my protected key"), not
 * a question about this socket's protections. Every word here resolves to a
 * route below, enforced by `test/agent-native/first-class-surfacing.test.ts`.
 */
export const EVALUATE_NOUN_WORDS = [
  "bound",
  "bounds",
  "platform",
  "platforms",
  "install",
  "installing",
  "installed",
  "installation",
  "uninstall",
  "verify",
  "verified",
  "verification",
  "protect",
  "protects",
  "protection",
  "protections",
  "evidence",
  "matrix",
  "tier",
  "tiers",
  "proven",
  "unproven",
] as const;

/** Word-boundary alternation over EVALUATE_NOUN_WORDS; never the `g` flag (test() would keep state). */
export const EVALUATE_NOUNS = new RegExp(`\\b(${EVALUATE_NOUN_WORDS.join("|")})\\b`);

/**
 * Evaluate-intent routing table, consumed by `classifyIntent` in
 * `cooperative-surface.ts`. Ordered from the most specific question to the
 * broadest so "how do I verify the install" lands on `verify`, not on
 * `install_decision`. Every route is read-only or CLI guidance: nothing here
 * can mutate state. A runnable example is offered only where the tool runs
 * unattended (Tier 3 under the default policy); the Tier 1 policy read gets
 * guidance only, because an example the agent follows would trigger an
 * operator prompt and audit `runnable_example: true` for a gated call.
 */
export const EVALUATE_ROUTES: readonly EvaluateRoute[] = [
  {
    question: "uninstall",
    matches: /\b(uninstall|unwrap|tear\s*down|teardown)\b/,
    tool: null,
    example: null,
    why_sanctuary: "Removal is an operator action on the CLI, never an agent-callable tool.",
    guidance: EVALUATE_CLI_GUIDANCE.uninstall,
  },
  {
    question: "verify",
    matches: /\b(verify|verified|verification|working|healthy|health|doctor)\b|\bcheck\b.*\binstall/,
    tool: EVALUATE_ROUTE_TOOLS.monitorHealth,
    example: {},
    why_sanctuary: "monitor_health is read-only and reports configured-but-unverified posture, not observed enforcement.",
    guidance: EVALUATE_CLI_GUIDANCE.verify,
  },
  {
    question: "tiers",
    matches: /\btiers?\b|\bneeds? a human\b/,
    // No runnable example: sanctuary_policy_status is forced Tier 1 under the
    // default policy, so an example here would walk the agent into an
    // operator prompt; the tool stays named in EVALUATE_RELATED_TOOLS.
    tool: null,
    example: null,
    why_sanctuary: "The tier answer is stated here from the README; sanctuary_policy_status lists the active assignments but is itself Tier 1, so no runnable example is offered.",
    guidance: `${SERVER_BOUNDS.tiers} sanctuary_policy_status returns the active Tier 1 and Tier 3 lists but is itself Tier 1 (waits for operator approval on every call), so call it only when the operator expects the prompt.`,
  },
  {
    question: "protections",
    matches: /\bprotect(s|ed|ion|ions)?\b|\bguarantees?\b|\bsafeguards?\b/,
    tool: EVALUATE_ROUTE_TOOLS.activeProtections,
    example: {},
    why_sanctuary: "sanctuary_active_protections reports only what is active; absence of a flag is not a claim.",
    guidance: buildBoundsParagraph(),
  },
  {
    question: "bounds",
    matches:
      /\bbounds?\b|\blimits?\b|\blimitations?\b|\bproven\b|\bunproven\b|\bevidence\b|\bmatrix\b|\bplatforms?\b|\bmacos\b|\blinux\b|\bwindows\b|\bubuntu\b|\b(not|never|cannot|can't|don't|do not) do\b|\bgaps?\b|\bmissing\b/,
    tool: EVALUATE_ROUTE_TOOLS.monitorHealth,
    example: {},
    why_sanctuary: "The bounds are stated here from the README and the Assurance Matrix; monitor_health shows which of them apply to this instance.",
    guidance: buildBoundsParagraph(),
  },
  {
    question: "install_decision",
    matches: /\bshould i\b|\bworth\b|\binstall(ing|ed|ation)?\b|\bevaluat(e|ing|ion)\b|\bassess\b|\badopt\b|\btrust (this|it|you)\b/,
    tool: EVALUATE_ROUTE_TOOLS.sovereigntyAudit,
    example: { deep_scan: false },
    why_sanctuary: "sovereignty_audit is read-only and returns a scored gap analysis; read the bounds before weighing the score.",
    guidance: buildBoundsParagraph(),
  },
] as const;

/**
 * Build the agent-facing MCP `instructions` string from the catalog.
 *
 * This is what a harness reads at connect time. It is a concise "start here"
 * for an AI agent: what this server offers cooperatively and why to route
 * through it, followed by the per-tool catalog, then the bounds paragraph
 * (platforms, tiers, what is never claimed, where evidence lives). It makes
 * no enforcement claim the cooperative layer cannot back on its own; the
 * bounds paragraph is copied from the README bound, never strengthened.
 */
export function buildServerInstructions(): string {
  const lines: string[] = [
    "Sanctuary gives you sovereign, encrypted, audited working memory and identity tools.",
    "Route memory and identity work through these cooperative tools rather than ad-hoc state: they encrypt at rest, bind to your identity, and write an append-only audit trail you can query.",
    "",
    "Start here:",
    `- Unsure which tool fits? Call ${COOPERATIVE_TOOL_NAMES.help} with a free-text intent.`,
    `- Want the full catalog again mid-session? Call ${COOPERATIVE_TOOL_NAMES.capabilities}.`,
    "",
    "Cooperative tools:",
  ];
  for (const entry of COOPERATIVE_CAPABILITIES) {
    lines.push(`- ${entry.tool}: ${entry.does} Use when: ${entry.when}`);
  }
  // Bounds come last and are never omitted: an agent that reads only the
  // catalog above would believe the cooperative layer is the whole product.
  lines.push("", "Bounds, tiers and evidence:", buildBoundsParagraph());
  return lines.join("\n");
}
