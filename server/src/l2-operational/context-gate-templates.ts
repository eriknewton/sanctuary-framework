/**
 * Sanctuary MCP Server — L2 Context Gating: Starter Policy Templates
 *
 * Pre-built policies for common use cases. These are starting points —
 * users should customize them for their specific context structure.
 *
 * Templates:
 *
 *   inference-minimal
 *     Only the current task and query reach the LLM. Everything else
 *     is redacted. Secrets, PII, memory, reasoning, and history are
 *     all blocked. IDs are hashed. Maximum privacy, minimum context.
 *
 *   inference-standard
 *     Task, query, and tool results pass through. Conversation history
 *     is flagged for summarization (compress before sending). Secrets,
 *     PII, and internal reasoning are redacted. IDs are hashed.
 *     Balanced: the LLM has enough context to be useful without seeing
 *     everything the agent knows.
 *
 *   logging-strict
 *     Redacts everything for logging/analytics providers. Only
 *     operation names and timestamps pass through. Use this for
 *     telemetry services where you want usage metrics without
 *     content exposure.
 *
 *   tool-api-scoped
 *     Allows tool-specific parameters and the current task, redacts
 *     memory, history, secrets, and PII. Hashes IDs. For outbound
 *     calls to external APIs (search, database, etc.) where you need
 *     to send query parameters but not your agent's full state.
 */

import type { ContextGateRule } from "./context-gate.js";

/** A template definition ready to be applied via the policy store */
export interface ContextGateTemplate {
  /** Machine-readable template ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** One-line description */
  description: string;
  /** When to use this template */
  use_when: string;
  /** The rules that make up this template */
  rules: ContextGateRule[];
  /** Default action for unmatched fields */
  default_action: "redact" | "deny";
}

// ── Shared Patterns ─────────────────────────────────────────────────────
// These field patterns appear across multiple templates. Keeping them
// as named constants makes the security-critical redact lists auditable.

/** Fields that must ALWAYS be redacted regardless of provider */
const ALWAYS_REDACT_SECRETS = [
  "api_key",
  "secret_*",
  "*_secret",
  "*_token",
  "*_key",
  "password",
  "*_password",
  "credential",
  "*_credential",
  "private_key",
  "recovery_key",
  "passphrase",
  "auth_*",
];

/** Fields containing personally identifiable information */
const PII_PATTERNS = [
  "*_pii",
  "name",
  "full_name",
  "email",
  "email_address",
  "phone",
  "phone_number",
  "address",
  "ssn",
  "date_of_birth",
  "ip_address",
  "credit_card",
  "card_number",
  "cvv",
  "bank_account",
  "account_number",
  "routing_number",
];

/** Fields containing agent internal state */
const INTERNAL_STATE_PATTERNS = [
  "memory",
  "agent_memory",
  "internal_reasoning",
  "internal_state",
  "reasoning_trace",
  "chain_of_thought",
  "private_notes",
  "soul",
  "personality",
  "system_prompt",
];

/** ID fields that should be hashed rather than sent in plaintext */
const ID_PATTERNS = [
  "user_id",
  "session_id",
  "agent_id",
  "identity_id",
  "conversation_id",
  "thread_id",
];

/** History/context fields that are large and should be summarized */
const HISTORY_PATTERNS = [
  "conversation_history",
  "message_history",
  "chat_history",
  "context_window",
  "previous_messages",
];

// ── Templates ───────────────────────────────────────────────────────────

export const INFERENCE_MINIMAL: ContextGateTemplate = {
  id: "inference-minimal",
  name: "Inference Minimal",
  description:
    "Maximum privacy. Only the current task and query reach the LLM provider.",
  use_when:
    "You want the strictest possible context control for inference calls. " +
    "The LLM sees only what it needs for the immediate task.",
  rules: [
    {
      provider: "inference",
      allow: [
        "task",
        "task_description",
        "current_query",
        "query",
        "prompt",
        "question",
        "instruction",
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
        "tool_results",
        "previous_results",
      ],
      hash: [...ID_PATTERNS],
      summarize: [],
    },
  ],
  default_action: "redact",
};

export const INFERENCE_STANDARD: ContextGateTemplate = {
  id: "inference-standard",
  name: "Inference Standard",
  description:
    "Balanced privacy. Task, query, and tool results pass through. " +
    "History flagged for summarization. Secrets and PII redacted.",
  use_when:
    "You need the LLM to have enough context for multi-step tasks " +
    "while keeping secrets, PII, and internal reasoning private.",
  rules: [
    {
      provider: "inference",
      allow: [
        "task",
        "task_description",
        "current_query",
        "query",
        "prompt",
        "question",
        "instruction",
        "tool_results",
        "tool_output",
        "previous_results",
        "current_step",
        "remaining_steps",
        "objective",
        "constraints",
        "format",
        "output_format",
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
      ],
      hash: [...ID_PATTERNS],
      summarize: [...HISTORY_PATTERNS],
    },
  ],
  default_action: "redact",
};

export const LOGGING_STRICT: ContextGateTemplate = {
  id: "logging-strict",
  name: "Logging Strict",
  description:
    "Redacts all content for logging and analytics providers. " +
    "Only operation metadata passes through.",
  use_when:
    "You send telemetry to logging or analytics services and want " +
    "usage metrics without any content exposure.",
  rules: [
    {
      provider: "logging",
      allow: [
        "operation",
        "operation_name",
        "tool_name",
        "timestamp",
        "duration_ms",
        "status",
        "error_code",
        "event_type",
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
      ],
      hash: [...ID_PATTERNS],
      summarize: [],
    },
    {
      provider: "analytics",
      allow: [
        "event_type",
        "timestamp",
        "duration_ms",
        "status",
        "tool_name",
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
      ],
      hash: [...ID_PATTERNS],
      summarize: [],
    },
  ],
  default_action: "redact",
};

export const TOOL_API_SCOPED: ContextGateTemplate = {
  id: "tool-api-scoped",
  name: "Tool API Scoped",
  description:
    "Allows tool-specific parameters for external API calls. " +
    "Redacts memory, history, secrets, and PII.",
  use_when:
    "Your agent calls external APIs (search, database, web) and you " +
    "want to send query parameters without full agent context. " +
    "Note: 'headers' and 'body' are redacted by default because they " +
    "frequently carry authorization tokens. Add them to 'allow' only " +
    "if you verify they contain no credentials for your use case.",
  rules: [
    {
      provider: "tool-api",
      allow: [
        "task",
        "task_description",
        "query",
        "search_query",
        "tool_input",
        "tool_parameters",
        "url",
        "endpoint",
        "method",
        "filter",
        "sort",
        "limit",
        "offset",
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
      ],
      hash: [...ID_PATTERNS],
      summarize: [],
    },
  ],
  default_action: "redact",
};

/**
 * Remote Inference Sanitization template
 *
 * Inspired by Vitalik Buterin's "Secure LLM" blog post (April 2026):
 * When a local agent needs to call out to a remote/cloud LLM for tasks
 * beyond local capability (complex coding, deep research, etc.), this
 * template provides maximum privacy by stripping all identity, financial,
 * and personal data before passing queries to external models.
 *
 * This is the "2-of-2 sovereignty" model: local agent maintains full
 * control over what the remote model sees.
 */
export const REMOTE_INFERENCE_SANITIZE: ContextGateTemplate = {
  id: "remote-inference-sanitize",
  name: "Remote Inference Sanitization",
  description:
    "Maximum privacy for remote/cloud LLM calls. Strips all identity, " +
    "financial, location, and personal data before passing queries to " +
    "external models. Inspired by Vitalik Buterin's 2-of-2 sovereignty model.",
  use_when:
    "Your local agent needs to call a remote LLM for tasks beyond local " +
    "model capability (complex coding, deep research) and you want to " +
    "minimize data leakage to the remote provider. The remote model gets " +
    "only the task, query, format requirements, and stripped code context.",
  rules: [
    {
      provider: "inference",
      allow: [
        "task",
        "task_description",
        "current_query",
        "query",
        "prompt",
        "question",
        "instruction",
        "output_format",
        "format",
        "language",
        "code_context",      // Stripped code snippets for coding tasks
        "error_message",     // For debugging help
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
        "tool_results",
        "previous_results",
        // Additional redactions for remote inference
        "model_data",
        "agent_state",
        "runtime_config",
        "capabilities",
        "tool_list",
      ],
      // Deny patterns — these must NEVER reach the remote model, not even redacted
      hash: [],
      summarize: [],
    },
  ],
  default_action: "deny",
};

// ── Template Registry ───────────────────────────────────────────────────

/** All available templates, keyed by ID */
export const TEMPLATES: Record<string, ContextGateTemplate> = {
  "inference-minimal": INFERENCE_MINIMAL,
  "inference-standard": INFERENCE_STANDARD,
  "logging-strict": LOGGING_STRICT,
  "tool-api-scoped": TOOL_API_SCOPED,
  "remote-inference-sanitize": REMOTE_INFERENCE_SANITIZE,
};

/** List all available template IDs */
export function listTemplateIds(): string[] {
  return Object.keys(TEMPLATES);
}

/** Get a template by ID (returns undefined if not found) */
export function getTemplate(id: string): ContextGateTemplate | undefined {
  return TEMPLATES[id];
}
