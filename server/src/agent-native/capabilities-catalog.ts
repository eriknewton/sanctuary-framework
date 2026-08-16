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
    does: "Classifies a free-text intent and returns which Sanctuary tool to use, with a runnable example for ordinary requests.",
    when: "You are unsure which tool fits. Ask here first before acting.",
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
 * Build the agent-facing MCP `instructions` string from the catalog.
 *
 * This is what a harness reads at connect time. It is a concise "start here"
 * for an AI agent: what this server offers cooperatively and why to route
 * through it, followed by the per-tool catalog. It makes no enforcement claim
 * the cooperative layer cannot back on its own.
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
  return lines.join("\n");
}
