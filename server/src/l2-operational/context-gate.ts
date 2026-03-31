/**
 * Sanctuary MCP Server — L2 Operational Isolation: Context Gating
 *
 * Context gating controls what information leaves the sovereignty boundary
 * when an agent makes outbound calls — especially inference calls to remote
 * LLM providers. This is the "minimum-necessary context" enforcement layer.
 *
 * The problem: When an agent sends a request to a remote LLM provider (Claude,
 * GPT, etc.), most harnesses send the agent's full context — conversation
 * history, memory, tool results, preferences, internal reasoning. The agent
 * has no control over what the provider sees.
 *
 * Context gating lets the agent define:
 * - Provider categories (inference, tool-api, logging, analytics, etc.)
 * - What fields/categories of context may flow to each provider type
 * - What must always be redacted (secrets, internal reasoning, PII, etc.)
 * - What requires transformation (hashing, summarizing, anonymizing)
 *
 * This sits in L2 (Operational Isolation) because it controls information
 * flow at the execution boundary. L3 (Selective Disclosure) handles agent-
 * to-agent trust negotiation with cryptographic proofs; context gating
 * handles agent-to-infrastructure information flow.
 *
 * Security invariants:
 * - Redact rules take absolute priority (like withhold in L3)
 * - Policies are stored encrypted under L1 sovereignty
 * - Every filter operation is audit-logged with a content hash
 *   (what was sent, what was redacted — without storing the content itself)
 * - Default policy: redact everything not explicitly allowed
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { hashToString } from "../core/hashing.js";

// ── Types ───────────────────────────────────────────────────────────────

/** Provider categories that context may flow to */
export type ProviderCategory =
  | "inference"    // Remote LLM API calls (Claude, GPT, etc.)
  | "tool-api"     // External tool/API calls (web search, database, etc.)
  | "logging"      // Telemetry and logging services
  | "analytics"    // Usage analytics and metrics
  | "peer-agent"   // Other agents (falls through to L3 disclosure for crypto)
  | "custom";      // User-defined category

/** Actions that can be taken on a context field */
export type ContextAction =
  | "allow"     // Field passes through unchanged
  | "redact"    // Field is completely removed (replaced with "[REDACTED]")
  | "hash"      // Field value is replaced with its SHA-256 hash
  | "summarize" // Field is marked for summarization (advisory — agent should compress)
  | "deny";     // Entire request should be blocked if this field is present

/** A rule within a context-gating policy */
export interface ContextGateRule {
  /** Provider category this rule applies to */
  provider: ProviderCategory | "*";
  /** Fields/patterns that may pass through */
  allow: string[];
  /** Fields/patterns that must be redacted (highest priority) */
  redact: string[];
  /** Fields/patterns that should be hashed */
  hash: string[];
  /** Fields/patterns that should be summarized (advisory) */
  summarize: string[];
}

/** A complete context-gating policy */
export interface ContextGatePolicy {
  policy_id: string;
  policy_name: string;
  rules: ContextGateRule[];
  /** Default action when no rule matches a field */
  default_action: "redact" | "deny";
  /** Identity this policy is bound to (optional) */
  identity_id?: string;
  created_at: string;
  updated_at: string;
}

/** Result of filtering a single field */
export interface FieldFilterResult {
  field: string;
  action: ContextAction;
  reason: string;
  /** If action is "hash", contains the hash */
  hash_value?: string;
}

/** Result of a full context filter operation */
export interface ContextFilterResult {
  policy_id: string;
  provider: ProviderCategory | string;
  fields_allowed: number;
  fields_redacted: number;
  fields_hashed: number;
  fields_summarized: number;
  fields_denied: number;
  decisions: FieldFilterResult[];
  /** SHA-256 hash of the original context (for audit trail) */
  original_context_hash: string;
  /** SHA-256 hash of the filtered output (for audit trail) */
  filtered_context_hash: string;
  filtered_at: string;
}

// ── Policy Evaluation ───────────────────────────────────────────────────

/**
 * Evaluate a context field against a policy for a given provider.
 *
 * Priority order (same as L3 disclosure):
 * 1. Redact (blocks — highest priority)
 * 2. Deny (blocks entire request)
 * 3. Hash (transforms)
 * 4. Summarize (advisory transform)
 * 5. Allow (passes through)
 * 6. Default action
 */
export function evaluateField(
  policy: ContextGatePolicy,
  provider: ProviderCategory | string,
  field: string
): FieldFilterResult {
  // Find matching rules: exact provider first, then wildcard
  const exactRule = policy.rules.find((r) => r.provider === provider);
  const wildcardRule = policy.rules.find((r) => r.provider === "*");
  const matchedRule = exactRule ?? wildcardRule;

  if (!matchedRule) {
    return {
      field,
      action: policy.default_action === "deny" ? "deny" : "redact",
      reason: `No rule matches provider "${provider}"; applying default (${policy.default_action})`,
    };
  }

  // Redact takes absolute priority
  if (matchesPattern(field, matchedRule.redact)) {
    return {
      field,
      action: "redact",
      reason: `Field "${field}" is explicitly redacted for ${matchedRule.provider} provider`,
    };
  }

  // Hash
  if (matchesPattern(field, matchedRule.hash)) {
    return {
      field,
      action: "hash",
      reason: `Field "${field}" is hashed for ${matchedRule.provider} provider`,
    };
  }

  // Summarize (advisory)
  if (matchesPattern(field, matchedRule.summarize)) {
    return {
      field,
      action: "summarize",
      reason: `Field "${field}" should be summarized for ${matchedRule.provider} provider`,
    };
  }

  // Allow
  if (matchesPattern(field, matchedRule.allow)) {
    return {
      field,
      action: "allow",
      reason: `Field "${field}" is allowed for ${matchedRule.provider} provider`,
    };
  }

  // Not mentioned — fall to default
  return {
    field,
    action: policy.default_action === "deny" ? "deny" : "redact",
    reason: `Field "${field}" not addressed in ${matchedRule.provider} rule; applying default (${policy.default_action})`,
  };
}

/**
 * Filter a full context object against a policy for a given provider.
 * Returns per-field decisions and content hashes for the audit trail.
 */
export function filterContext(
  policy: ContextGatePolicy,
  provider: ProviderCategory | string,
  context: Record<string, unknown>
): ContextFilterResult {
  const fields = Object.keys(context);
  const decisions: FieldFilterResult[] = [];
  let allowed = 0;
  let redacted = 0;
  let hashed = 0;
  let summarized = 0;
  let denied = 0;

  for (const field of fields) {
    const result = evaluateField(policy, provider, field);

    // If hash action, compute the hash
    if (result.action === "hash") {
      const value = typeof context[field] === "string"
        ? context[field] as string
        : JSON.stringify(context[field]);
      result.hash_value = hashToString(stringToBytes(value));
    }

    decisions.push(result);

    switch (result.action) {
      case "allow": allowed++; break;
      case "redact": redacted++; break;
      case "hash": hashed++; break;
      case "summarize": summarized++; break;
      case "deny": denied++; break;
    }
  }

  // Compute content hashes for audit trail
  const originalHash = hashToString(
    stringToBytes(JSON.stringify(context))
  );

  // Build filtered output for hash computation
  const filteredOutput: Record<string, unknown> = {};
  for (const decision of decisions) {
    switch (decision.action) {
      case "allow":
        filteredOutput[decision.field] = context[decision.field];
        break;
      case "redact":
        filteredOutput[decision.field] = "[REDACTED]";
        break;
      case "hash":
        filteredOutput[decision.field] = `[HASH:${decision.hash_value}]`;
        break;
      case "summarize":
        filteredOutput[decision.field] = "[SUMMARIZE]";
        break;
      case "deny":
        // Field excluded entirely
        break;
    }
  }
  const filteredHash = hashToString(
    stringToBytes(JSON.stringify(filteredOutput))
  );

  return {
    policy_id: policy.policy_id,
    provider,
    fields_allowed: allowed,
    fields_redacted: redacted,
    fields_hashed: hashed,
    fields_summarized: summarized,
    fields_denied: denied,
    decisions,
    original_context_hash: originalHash,
    filtered_context_hash: filteredHash,
    filtered_at: new Date().toISOString(),
  };
}

// ── Pattern Matching ────────────────────────────────────────────────────

/**
 * Check if a field name matches any pattern in a list.
 * Supports:
 * - Exact match: "conversation_history"
 * - Wildcard prefix: "secret_*" matches "secret_key", "secret_token"
 * - Wildcard suffix: "*_pii" matches "name_pii", "email_pii"
 * - Full wildcard: "*" matches everything
 */
function matchesPattern(field: string, patterns: string[]): boolean {
  const normalizedField = field.toLowerCase();
  for (const pattern of patterns) {
    if (pattern === "*") return true;
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern === normalizedField) return true;
    if (normalizedPattern.endsWith("*") && normalizedField.startsWith(normalizedPattern.slice(0, -1))) return true;
    if (normalizedPattern.startsWith("*") && normalizedField.endsWith(normalizedPattern.slice(1))) return true;
  }
  return false;
}

// ── Policy Store ────────────────────────────────────────────────────────

/**
 * Context gate policy store — encrypted under L1 sovereignty.
 */
export class ContextGatePolicyStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private policies: Map<string, ContextGatePolicy> = new Map();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l2-context-gate");
  }

  /**
   * Create and store a new context-gating policy.
   */
  async create(
    policyName: string,
    rules: ContextGateRule[],
    defaultAction: "redact" | "deny",
    identityId?: string
  ): Promise<ContextGatePolicy> {
    const policyId = `cg-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date().toISOString();

    const policy: ContextGatePolicy = {
      policy_id: policyId,
      policy_name: policyName,
      rules,
      default_action: defaultAction,
      identity_id: identityId,
      created_at: now,
      updated_at: now,
    };

    await this.persist(policy);
    this.policies.set(policyId, policy);

    return policy;
  }

  /**
   * Get a policy by ID.
   */
  async get(policyId: string): Promise<ContextGatePolicy | null> {
    if (this.policies.has(policyId)) {
      return this.policies.get(policyId)!;
    }

    const raw = await this.storage.read("_context_gate_policies", policyId);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const policy: ContextGatePolicy = JSON.parse(bytesToString(decrypted));
      this.policies.set(policyId, policy);
      return policy;
    } catch {
      return null;
    }
  }

  /**
   * List all context-gating policies.
   */
  async list(): Promise<ContextGatePolicy[]> {
    await this.loadAll();
    return Array.from(this.policies.values());
  }

  /**
   * Load all persisted policies into memory.
   */
  private async loadAll(): Promise<void> {
    try {
      const entries = await this.storage.list("_context_gate_policies");
      for (const meta of entries) {
        if (this.policies.has(meta.key)) continue;
        const raw = await this.storage.read("_context_gate_policies", meta.key);
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const policy: ContextGatePolicy = JSON.parse(bytesToString(decrypted));
          this.policies.set(policy.policy_id, policy);
        } catch {
          // Skip corrupted policies
        }
      }
    } catch {
      // Storage not available
    }
  }

  private async persist(policy: ContextGatePolicy): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(policy));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_context_gate_policies",
      policy.policy_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
}
