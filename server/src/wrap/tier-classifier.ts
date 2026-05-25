/**
 * Sanctuary Cocoon — Tool Tier Auto-Classifier
 *
 * Heuristic classification of upstream MCP tools into approval tiers
 * based on tool name patterns. This is the zero-config protection layer
 * that makes Cocoon safe out of the box.
 *
 * Tier 1 (requires approval): destructive, executable, or sensitive operations
 * Tier 2 (anomaly-monitored): default for unclassified tools
 * Tier 3 (auto-allowed): read-only, listing, and query operations
 */

// ── Patterns ─────────────────────────────────────────────────────────

/** Tools matching these patterns default to Tier 1 (requires human approval) */
const TIER_1_PATTERNS = [
  "write", "delete", "remove", "exec", "execute", "run",
  "send", "post", "put", "patch", "create", "update",
  "upload", "deploy", "install", "uninstall",
  "drop", "truncate", "modify", "mutate", "set",
  "push", "publish", "emit", "dispatch",
  "kill", "stop", "restart", "shutdown",
  "grant", "revoke", "chmod", "chown",
];

/** Tools matching these patterns default to Tier 3 (auto-allowed with audit) */
const TIER_3_PATTERNS = [
  "read", "get", "list", "search", "query", "find",
  "fetch", "retrieve", "lookup", "describe", "show",
  "info", "status", "count", "check", "exists",
  "head", "peek", "inspect", "view", "browse",
  "help", "version", "ping", "health", "echo",
];

// ── Classifier ──────────────────────────────────────────────────────

/**
 * Classify a tool name into a tier based on heuristic pattern matching.
 *
 * Uses word-boundary matching: "read_file" matches "read",
 * but "spreadsheet" does not match "read".
 *
 * @returns 1, 2, or 3
 */
export function classifyTool(toolName: string): 1 | 2 | 3 {
  // Check Tier 1 patterns first (most restrictive wins)
  for (const pattern of TIER_1_PATTERNS) {
    if (matchesWordBoundary(toolName, pattern)) {
      return 1;
    }
  }

  // Check Tier 3 patterns
  for (const pattern of TIER_3_PATTERNS) {
    if (matchesWordBoundary(toolName, pattern)) {
      return 3;
    }
  }

  // Default: Tier 2 (anomaly-monitored)
  return 2;
}

/**
 * Classify all tools from an upstream server. Returns a map of
 * tool_name → { tier } for use as tool_overrides in the sovereignty profile.
 */
export function classifyServerTools(
  toolNames: string[]
): Record<string, { tier: 1 | 2 | 3 }> {
  const overrides: Record<string, { tier: 1 | 2 | 3 }> = {};
  for (const name of toolNames) {
    const tier = classifyTool(name);
    // Only store overrides for non-default tiers (Tier 2 is default)
    if (tier !== 2) {
      overrides[name] = { tier };
    }
  }
  return overrides;
}

/**
 * Get a human-readable tier description.
 */
export function tierDescription(tier: 1 | 2 | 3): string {
  switch (tier) {
    case 1: return "Requires your approval";
    case 2: return "Auto-monitored";
    case 3: return "Auto-allowed";
  }
}

// ── Internal ────────────────────────────────────────────────────────

/**
 * Check if a pattern appears at a word boundary in the tool name.
 * Word boundaries are: start/end of string, underscore, hyphen, slash, dot,
 * or camelCase transitions.
 */
function matchesWordBoundary(toolName: string, pattern: string): boolean {
  // Split on common separators and camelCase
  const words = toolName
    .replace(/([a-z])([A-Z])/g, "$1_$2") // camelCase → snake_case
    .toLowerCase()
    .split(/[_\-./]/);

  for (const word of words) {
    if (word === pattern) return true;
  }

  return false;
}
