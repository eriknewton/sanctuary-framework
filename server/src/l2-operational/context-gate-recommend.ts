/**
 * Sanctuary MCP Server — L2 Context Gating: Policy Recommendation Engine
 *
 * Analyzes a sample context object and recommends a context-gating policy
 * based on field name heuristics. The agent (or human) can then review,
 * adjust, and apply the recommendation.
 *
 * This is deliberately conservative: when in doubt, it recommends redact.
 * A false redaction is a usability issue; a false allow is a privacy leak.
 *
 * Classification heuristics:
 * - Known secret patterns → redact (highest confidence)
 * - Known PII patterns → redact (high confidence)
 * - Known internal state patterns → redact (high confidence)
 * - Known ID patterns → hash (medium confidence)
 * - Known history patterns → summarize (medium confidence)
 * - Known task/query patterns → allow (medium confidence)
 * - Everything else → redact (conservative default)
 *
 * WARNING: Fields like 'tool_results' and 'tool_output' are classified as
 * "allow" (medium confidence) but may contain sensitive data from external
 * API responses, including auth tokens, user data, or PII. Always review
 * recommendations before applying — the heuristic classifies by field NAME,
 * not field CONTENT.
 */

/** Classification result for a single field */
export interface FieldClassification {
  field: string;
  recommended_action: "allow" | "redact" | "hash" | "summarize";
  reason: string;
  confidence: "high" | "medium" | "low";
  /** Pattern that matched, if any */
  matched_pattern: string | null;
}

/** Full recommendation result */
export interface PolicyRecommendation {
  provider: string;
  classifications: FieldClassification[];
  recommended_rules: {
    allow: string[];
    redact: string[];
    hash: string[];
    summarize: string[];
  };
  default_action: "redact";
  summary: {
    total_fields: number;
    allow: number;
    redact: number;
    hash: number;
    summarize: number;
  };
  warnings: string[];
}

// ── Pattern Definitions ─────────────────────────────────────────────────
// Each pattern set maps field name patterns to a classification.
// Order matters: earlier sets have higher priority.

interface PatternRule {
  /** Patterns to match against field names (lowercase) */
  patterns: string[];
  /** Action to recommend */
  action: "allow" | "redact" | "hash" | "summarize";
  /** Confidence level */
  confidence: "high" | "medium" | "low";
  /** Human-readable reason */
  reason: string;
}

const CLASSIFICATION_RULES: PatternRule[] = [
  // ── Secrets (always redact, high confidence) ─────────────────────
  {
    patterns: [
      "api_key", "apikey", "api_secret",
      "secret", "secret_key", "secret_token",
      "password", "passwd", "pass",
      "credential", "credentials",
      "private_key", "privkey",
      "recovery_key",
      "passphrase",
      "token", "access_token", "refresh_token", "bearer_token",
      "auth_token", "auth_header", "authorization",
      "encryption_key", "master_key", "signing_key",
      "webhook_secret", "client_secret",
      "connection_string",
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known secret/credential pattern",
  },

  // ── PII (always redact, high confidence) ─────────────────────────
  {
    patterns: [
      "name", "full_name", "first_name", "last_name", "display_name",
      "email", "email_address",
      "phone", "phone_number", "mobile",
      "address", "street_address", "mailing_address",
      "ssn", "social_security",
      "date_of_birth", "dob", "birthday",
      "ip_address", "ip",
      "location", "geolocation", "coordinates",
      "credit_card", "card_number", "cvv",
      "bank_account", "routing_number",
      "passport", "drivers_license", "license_number",
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known PII pattern",
  },

  // ── Internal agent state (redact, high confidence) ───────────────
  {
    patterns: [
      "memory", "agent_memory", "long_term_memory",
      "internal_reasoning", "reasoning_trace", "chain_of_thought",
      "internal_state", "agent_state",
      "private_notes", "scratchpad",
      "soul", "personality", "persona",
      "system_prompt", "system_message", "system_instruction",
      "preferences", "user_preferences", "agent_preferences",
      "beliefs", "goals", "motivations",
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known internal agent state pattern",
  },

  // ── IDs (hash, medium confidence) ────────────────────────────────
  {
    patterns: [
      "user_id", "userid",
      "session_id", "sessionid",
      "agent_id", "agentid",
      "identity_id",
      "conversation_id",
      "thread_id", "threadid",
      "request_id", "requestid",
      "correlation_id",
      "trace_id", "traceid",
      "account_id", "accountid",
    ],
    action: "hash",
    confidence: "medium",
    reason: "Matches known identifier pattern — hash preserves correlation without exposing value",
  },

  // ── History (summarize, medium confidence) ───────────────────────
  {
    patterns: [
      "conversation_history", "chat_history",
      "message_history", "messages",
      "previous_messages", "prior_messages",
      "context_window",
      "interaction_history",
      "audit_log", "event_log",
    ],
    action: "summarize",
    confidence: "medium",
    reason: "Matches known history/log pattern — summarize to reduce exposure",
  },

  // ── Task/query (allow, medium confidence) ────────────────────────
  {
    patterns: [
      "task", "task_description",
      "query", "current_query", "search_query",
      "prompt", "user_prompt",
      "question", "current_question",
      "instruction", "instructions",
      "objective", "goal",
      "current_step", "next_step",
      "remaining_steps",
      "constraints", "requirements",
      "output_format", "format",
      "tool_results", "tool_output",
      "tool_input", "tool_parameters",
    ],
    action: "allow",
    confidence: "medium",
    reason: "Matches known task/query pattern — likely needed for inference",
  },
];

// ── Classification Engine ───────────────────────────────────────────────

/**
 * Classify a single field name and return a recommendation.
 */
export function classifyField(fieldName: string): FieldClassification {
  const normalized = fieldName.toLowerCase().trim();

  for (const rule of CLASSIFICATION_RULES) {
    for (const pattern of rule.patterns) {
      if (matchesFieldPattern(normalized, pattern)) {
        return {
          field: fieldName,
          recommended_action: rule.action,
          reason: rule.reason,
          confidence: rule.confidence,
          matched_pattern: pattern,
        };
      }
    }
  }

  // No pattern matched — conservative default
  return {
    field: fieldName,
    recommended_action: "redact",
    reason: "No known pattern matched — defaulting to redact (conservative)",
    confidence: "low",
    matched_pattern: null,
  };
}

/**
 * Analyze a full context object and recommend a policy.
 */
export function recommendPolicy(
  context: Record<string, unknown>,
  provider: string = "inference"
): PolicyRecommendation {
  const fields = Object.keys(context);
  const classifications: FieldClassification[] = fields.map(classifyField);
  const warnings: string[] = [];

  // Build rule lists
  const allow: string[] = [];
  const redact: string[] = [];
  const hash: string[] = [];
  const summarize: string[] = [];

  for (const c of classifications) {
    switch (c.recommended_action) {
      case "allow": allow.push(c.field); break;
      case "redact": redact.push(c.field); break;
      case "hash": hash.push(c.field); break;
      case "summarize": summarize.push(c.field); break;
    }
  }

  // Generate warnings
  const lowConfidence = classifications.filter((c) => c.confidence === "low");
  if (lowConfidence.length > 0) {
    warnings.push(
      `${lowConfidence.length} field(s) could not be classified by pattern and will ` +
      `default to redact: ${lowConfidence.map((c) => c.field).join(", ")}. ` +
      `Review these manually.`
    );
  }

  // Check for fields that look like they might contain large content
  for (const [key, value] of Object.entries(context)) {
    if (typeof value === "string" && value.length > 5000) {
      const existing = classifications.find((c) => c.field === key);
      if (existing && existing.recommended_action === "allow") {
        warnings.push(
          `Field "${key}" is allowed but contains ${value.length} characters. ` +
          `Consider summarizing it to reduce context size and exposure.`
        );
      }
    }
  }

  return {
    provider,
    classifications,
    recommended_rules: { allow, redact, hash, summarize },
    default_action: "redact",
    summary: {
      total_fields: fields.length,
      allow: allow.length,
      redact: redact.length,
      hash: hash.length,
      summarize: summarize.length,
    },
    warnings,
  };
}

// ── Pattern Matching ────────────────────────────────────────────────────

/**
 * Match a normalized field name against a pattern.
 * Supports exact match and substring containment for compound field names.
 *
 * Examples:
 * - "api_key" matches field "api_key" (exact)
 * - "api_key" matches field "openai_api_key" (contains)
 * - "secret" matches field "client_secret" (contains)
 * - "password" matches field "db_password" (contains)
 */
function matchesFieldPattern(normalizedField: string, pattern: string): boolean {
  if (normalizedField === pattern) return true;
  // Check if the pattern appears as a complete word boundary segment
  // e.g., "api_key" should match "openai_api_key" but "key" alone shouldn't match "keyboard"
  if (pattern.length >= 3 && normalizedField.includes(pattern)) {
    // Verify it's at a word boundary (start/end of string, or adjacent to _ or -)
    const idx = normalizedField.indexOf(pattern);
    const before = idx === 0 || normalizedField[idx - 1] === "_" || normalizedField[idx - 1] === "-";
    const after = idx + pattern.length === normalizedField.length ||
      normalizedField[idx + pattern.length] === "_" ||
      normalizedField[idx + pattern.length] === "-";
    return before && after;
  }
  return false;
}
