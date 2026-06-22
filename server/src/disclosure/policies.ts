/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Disclosure Policies
 *
 * Disclosure policies define what an agent will and will not disclose
 * in different interaction contexts. Policies are evaluated against
 * incoming disclosure requests to produce per-field decisions.
 *
 * This is the agent's "privacy preferences" layer — it codifies the
 * human principal's intent about what information can flow where.
 *
 * Security invariants:
 * - Policies are stored encrypted under L1 sovereignty
 * - Default action is always "withhold" unless explicitly overridden
 * - Policy evaluation is deterministic (same request → same decision)
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";

/** A single disclosure rule within a policy */
export interface DisclosureRule {
  /** Interaction context this rule applies to */
  context: string; // "negotiation", "commerce", "identity", "*"
  /** Fields/claims the agent MAY disclose */
  disclose: string[];
  /** Fields/claims the agent MUST NOT disclose */
  withhold: string[];
  /** Fields that require proof rather than plain disclosure */
  proof_required: string[];
}

/** A complete disclosure policy */
export interface DisclosurePolicy {
  policy_id: string;
  policy_name: string;
  rules: DisclosureRule[];
  default_action: "withhold" | "ask-principal";
  identity_id?: string;
  created_at: string;
  updated_at: string;
}

/** Result of evaluating a disclosure request */
export interface DisclosureDecision {
  field: string;
  action: "disclose" | "withhold" | "proof" | "ask-principal";
  reason: string;
  applicable_rule: string;
}

/**
 * Evaluate a disclosure request against a policy.
 *
 * For each requested field, finds the most specific matching rule:
 * 1. Exact context match
 * 2. Wildcard "*" context
 * 3. Default action
 *
 * Within a matched rule:
 * - If field is in `withhold` → withhold (highest priority)
 * - If field is in `proof_required` → proof
 * - If field is in `disclose` → disclose
 * - Otherwise → default_action
 */
export function evaluateDisclosure(
  policy: DisclosurePolicy,
  context: string,
  requestedFields: string[]
): DisclosureDecision[] {
  return requestedFields.map((field) => {
    // Find matching rules: exact context first, then wildcard
    const exactRule = policy.rules.find((r) => r.context === context);
    const wildcardRule = policy.rules.find((r) => r.context === "*");
    const matchedRule = exactRule ?? wildcardRule;

    if (!matchedRule) {
      return {
        field,
        action: policy.default_action,
        reason: `No rule matches context "${context}"`,
        applicable_rule: "default",
      };
    }

    const ruleName = `${matchedRule.context}`;

    // Withhold takes priority
    if (matchedRule.withhold.includes(field)) {
      return {
        field,
        action: "withhold" as const,
        reason: `Field "${field}" is explicitly withheld in ${ruleName} context`,
        applicable_rule: ruleName,
      };
    }

    // Proof required next
    if (matchedRule.proof_required.includes(field)) {
      return {
        field,
        action: "proof" as const,
        reason: `Field "${field}" requires cryptographic proof in ${ruleName} context`,
        applicable_rule: ruleName,
      };
    }

    // Explicit disclose
    if (matchedRule.disclose.includes(field)) {
      return {
        field,
        action: "disclose" as const,
        reason: `Field "${field}" is permitted for disclosure in ${ruleName} context`,
        applicable_rule: ruleName,
      };
    }

    // Not mentioned in the rule — fall to default
    return {
      field,
      action: policy.default_action,
      reason: `Field "${field}" not addressed in ${ruleName} rule; applying default`,
      applicable_rule: ruleName,
    };
  });
}

/**
 * Policy store — manages disclosure policies encrypted under L1 sovereignty.
 */
export class PolicyStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private policies: Map<string, DisclosurePolicy> = new Map();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l3-policies");
  }

  /**
   * Create and store a new disclosure policy.
   */
  async create(
    policyName: string,
    rules: DisclosureRule[],
    defaultAction: "withhold" | "ask-principal",
    identityId?: string
  ): Promise<DisclosurePolicy> {
    const policyId = `pol-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date().toISOString();

    const policy: DisclosurePolicy = {
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
  async get(policyId: string): Promise<DisclosurePolicy | null> {
    // Check in-memory cache first
    if (this.policies.has(policyId)) {
      return this.policies.get(policyId)!;
    }

    // Try to load from storage
    const raw = await this.storage.read("_policies", policyId);
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const policy: DisclosurePolicy = JSON.parse(bytesToString(decrypted));
      this.policies.set(policyId, policy);
      return policy;
    } catch {
      return null;
    }
  }

  /**
   * List all policies.
   */
  async list(): Promise<DisclosurePolicy[]> {
    await this.loadAll();
    return Array.from(this.policies.values());
  }

  /**
   * Load all persisted policies into memory.
   */
  private async loadAll(): Promise<void> {
    try {
      const entries = await this.storage.list("_policies");
      for (const meta of entries) {
        if (this.policies.has(meta.key)) continue;
        const raw = await this.storage.read("_policies", meta.key);
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const policy: DisclosurePolicy = JSON.parse(bytesToString(decrypted));
          this.policies.set(policy.policy_id, policy);
        } catch {
          // Skip corrupted policies
        }
      }
    } catch {
      // Storage not available
    }
  }

  private async persist(policy: DisclosurePolicy): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(policy));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_policies",
      policy.policy_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
}
