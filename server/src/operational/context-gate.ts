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
  | "model-registry" // Signed model-manifest-approved weight downloads
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
  /** Context after policy filtering, safe to pass to the span privacy filter */
  filtered_output: Record<string, unknown>;
  /** SHA-256 hash of the original context (for audit trail) */
  original_context_hash: string;
  /** SHA-256 hash of the filtered output (for audit trail) */
  filtered_context_hash: string;
  filtered_at: string;
}

// ── Size Limits ─────────────────────────────────────────────────────────

/** Maximum number of top-level fields in a context object */
export const MAX_CONTEXT_FIELDS = 1000;

/** Maximum number of rules in a policy */
export const MAX_POLICY_RULES = 50;

/** Maximum number of patterns in a single rule array (allow, redact, hash, summarize) */
export const MAX_PATTERNS_PER_ARRAY = 500;

/**
 * Maximum nesting depth examined during recursive filtering. Structures deeper
 * than this fail closed (the over-deep subtree is redacted, never emitted
 * unexamined). Also bounds recursion so a hostile deeply-nested context cannot
 * exhaust the stack.
 */
export const MAX_CONTEXT_DEPTH = 64;

/**
 * JSON-serialize for the audit hash without crashing on a cyclic context. A
 * hostile agent could send a self-referential object; the filter must still
 * produce a deterministic fingerprint rather than throw on the outbound
 * enforcement path. Non-cyclic inputs use plain JSON.stringify (no behavior
 * change); only a structure that actually throws falls back to the
 * circular-safe replacer.
 */
function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    const seen = new WeakSet<object>();
    return JSON.stringify(value, (_key, val) => {
      if (typeof val === "object" && val !== null) {
        if (seen.has(val)) return "[Circular]";
        seen.add(val);
      }
      return val;
    });
  }
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
 *
 * Recurses into nested objects and arrays. A value is only emitted if EVERY
 * field on its path is explicitly allowed: an allowed container is examined
 * recursively and each nested field is evaluated independently by its own key
 * name. So a secret nested under an allowed field (e.g. `metadata.api_key`) is
 * caught by the same `api_key` / `secret_*` patterns that protect a top-level
 * field, instead of riding through verbatim inside its parent. Anything not
 * explicitly allowed falls to the policy default (redact / deny) all the way
 * down. This closes the nested-field exfiltration gap where a redact rule on a
 * top-level key did nothing for the same key nested one level deeper.
 *
 * Fails closed on hostile shapes: total field count across the whole tree is
 * capped (MAX_CONTEXT_FIELDS), nesting depth is capped (MAX_CONTEXT_DEPTH), and
 * cyclic references are redacted rather than followed.
 *
 * Returns per-field decisions (nested fields use dotted / `[index]` paths) and
 * content hashes for the audit trail.
 */
export function filterContext(
  policy: ContextGatePolicy,
  provider: ProviderCategory | string,
  context: Record<string, unknown>
): ContextFilterResult {
  const decisions: FieldFilterResult[] = [];
  let allowed = 0;
  let redacted = 0;
  let hashed = 0;
  let summarized = 0;
  let denied = 0;
  let totalFields = 0;
  const seen = new WeakSet<object>();

  /** Sentinel returned for a denied field so the caller drops it entirely. */
  const OMIT = Symbol("omit");

  const isContainer = (v: unknown): v is Record<string, unknown> | unknown[] =>
    typeof v === "object" && v !== null;

  const record = (decision: FieldFilterResult): void => {
    decisions.push(decision);
    switch (decision.action) {
      case "allow": allowed++; break;
      case "redact": redacted++; break;
      case "hash": hashed++; break;
      case "summarize": summarized++; break;
      case "deny": denied++; break;
    }
  };

  const failClosed = (path: string, reason: string): string => {
    record({ field: path, action: "redact", reason });
    return "[REDACTED]";
  };

  /**
   * Evaluate one field (key + value) at `path`, returning the value to emit in
   * the filtered output, or OMIT to drop it. Recurses into allowed containers.
   */
  const filterField = (
    key: string,
    value: unknown,
    path: string,
    depth: number
  ): unknown | typeof OMIT => {
    totalFields++;
    if (totalFields > MAX_CONTEXT_FIELDS) {
      throw new Error(
        `Context object has more than ${MAX_CONTEXT_FIELDS} fields (including nested), exceeding limit of ${MAX_CONTEXT_FIELDS}`
      );
    }

    const decision: FieldFilterResult = {
      ...evaluateField(policy, provider, key),
      field: path,
    };

    switch (decision.action) {
      case "redact":
        record(decision);
        return "[REDACTED]";
      case "deny":
        record(decision);
        return OMIT;
      case "hash": {
        const v = typeof value === "string" ? value : JSON.stringify(value);
        decision.hash_value = hashToString(stringToBytes(v));
        record(decision);
        return `[HASH:${decision.hash_value}]`;
      }
      case "summarize":
        record(decision);
        return "[SUMMARIZE]";
      case "allow":
        if (isContainer(value)) {
          if (seen.has(value)) {
            return failClosed(path, `Field "${path}" is a cyclic reference; redacted (fail-closed)`);
          }
          if (depth >= MAX_CONTEXT_DEPTH) {
            return failClosed(path, `Field "${path}" exceeds max nesting depth ${MAX_CONTEXT_DEPTH}; redacted (fail-closed)`);
          }
          // The container itself is allowed; its children are evaluated below.
          record(decision);
          return filterContainer(value, path, depth + 1);
        }
        record(decision);
        return value;
      default:
        return failClosed(path, `Field "${path}" produced an unknown action; redacted (fail-closed)`);
    }
  };

  const filterContainer = (
    container: Record<string, unknown> | unknown[],
    basePath: string,
    depth: number
  ): unknown => {
    seen.add(container);
    if (Array.isArray(container)) {
      const out: unknown[] = [];
      for (let i = 0; i < container.length; i++) {
        const el = container[i];
        const elPath = `${basePath}[${i}]`;
        if (isContainer(el)) {
          if (seen.has(el)) {
            out.push(failClosed(elPath, `Field "${elPath}" is a cyclic reference; redacted (fail-closed)`));
          } else if (depth >= MAX_CONTEXT_DEPTH) {
            out.push(failClosed(elPath, `Field "${elPath}" exceeds max nesting depth ${MAX_CONTEXT_DEPTH}; redacted (fail-closed)`));
          } else {
            out.push(filterContainer(el, elPath, depth + 1));
          }
        } else {
          // A primitive element of an allowed array passes through unchanged.
          out.push(el);
        }
      }
      return out;
    }
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(container)) {
      const childPath = basePath ? `${basePath}.${key}` : key;
      const emitted = filterField(key, val, childPath, depth);
      if (emitted !== OMIT) out[key] = emitted;
    }
    return out;
  };

  const filteredOutput = filterContainer(context, "", 1) as Record<string, unknown>;

  const originalHash = hashToString(stringToBytes(safeStringify(context)));
  const filteredHash = hashToString(stringToBytes(safeStringify(filteredOutput)));

  return {
    policy_id: policy.policy_id,
    provider,
    fields_allowed: allowed,
    fields_redacted: redacted,
    fields_hashed: hashed,
    fields_summarized: summarized,
    fields_denied: denied,
    decisions,
    filtered_output: filteredOutput,
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
export function matchesPattern(field: string, patterns: string[]): boolean {
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
    // Defense in depth: the context_gate_set_policy tool already enforces these
    // caps, but the store must not trust callers — an unbounded policy turns
    // every later filter into an O(fields x patterns) DoS sink.
    if (rules.length > MAX_POLICY_RULES) {
      throw new Error(
        `Policy has ${rules.length} rules, exceeding limit of ${MAX_POLICY_RULES}`
      );
    }
    for (const rule of rules) {
      for (const arr of [rule.allow, rule.redact, rule.hash, rule.summarize]) {
        if (Array.isArray(arr) && arr.length > MAX_PATTERNS_PER_ARRAY) {
          throw new Error(
            `A rule pattern array has ${arr.length} patterns, exceeding limit of ${MAX_PATTERNS_PER_ARRAY}`
          );
        }
      }
    }

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
