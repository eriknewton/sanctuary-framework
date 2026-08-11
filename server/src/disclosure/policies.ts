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
import { BoundedMap, type BoundedMapRefuseReason } from "../core/bounded-map.js";

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
  /**
   * SERVER-SET agent-session principal (`callerIdentity`, router.ts —
   * never a caller-supplied field) that created this policy. Persisted
   * (not just tracked in the in-memory BoundedMap) so ownership survives a
   * restart: `PolicyStore.update`'s in-place-replace path binds to this
   * value, not to `identity_id` above, because `identity_id` is
   * caller-supplied and `identity_create` is Tier-3 always-allow (Class C
   * lesson — a per-identity check is defeated by minting more identities).
   * Optional only for backward-compat with policies persisted before this
   * field existed; such a policy can still be read but never updated in
   * place (see `update`'s doc) since there is no owner to verify against.
   */
  owner_session?: string;
  created_at: string;
  updated_at: string;
}

/**
 * Global cap on stored disclosure policies (AGENTS.md rule 8 — LD3
 * register: `disclosure_set_policy` minted a random policy id on EVERY
 * call and cached the caller-supplied rules forever, with no bound at all).
 * 200 = generous headroom over any realistic fortress's disclosure-policy
 * count (a human principal configures a handful of policies, one per major
 * interaction category, not hundreds) while keeping the capacity-refusal
 * path reachable in an adversarial test without an impractical loop.
 * Mirrors the derivation shape of handshake/tools.ts's
 * MAX_HANDSHAKE_SESSIONS.
 */
export const MAX_DISCLOSURE_POLICIES = 200;

/**
 * Per-origin quota (AGENTS.md rule 8). The origin is the SERVER-SET
 * agent-session principal (`callerIdentity`), NEVER the caller-supplied
 * `identity_id` field — see `DisclosurePolicy.owner_session`'s doc and
 * handshake/tools.ts's `MAX_HANDSHAKE_SESSIONS_PER_ORIGIN` for the full
 * mint-many-identities defeat this same shape closes. 20 = 1/10th of
 * MAX_DISCLOSURE_POLICIES: generous for one agent session's legitimate
 * policy set, while guaranteeing at least 10 distinct agent sessions can
 * each hold a full policy set before any single one could threaten the
 * shared ceiling.
 */
export const MAX_DISCLOSURE_POLICIES_PER_ORIGIN = 20;

/**
 * Bound on `policy_name` length (rule 8(d) — bounded work/storage per
 * request). 200 = generous room for a human-readable label, far below any
 * memory concern; a name this long already indicates misuse rather than a
 * legitimate label.
 */
export const MAX_DISCLOSURE_POLICY_NAME_LENGTH = 200;

/**
 * Bound on the number of `DisclosureRule` entries a single policy may
 * carry. 50 = an order of magnitude above any realistic distinct-context
 * count (negotiation/commerce/identity/"*"/... a handful in practice) —
 * the cap exists to stop a single policy from becoming an unbounded
 * caller-supplied payload, not to constrain legitimate use.
 */
export const MAX_DISCLOSURE_POLICY_RULES = 50;

/**
 * Bound on the number of field entries within a single rule's
 * `disclose` / `withhold` / `proof_required` array. 100 = generous for a
 * real field taxonomy while bounding the per-rule payload an attacker can
 * cache permanently.
 */
export const MAX_DISCLOSURE_RULE_FIELD_ITEMS = 100;

/**
 * Bound on the length of any single string within a rule (`context`, and
 * every entry of `disclose` / `withhold` / `proof_required`). 256 =
 * generous for a dotted field path or context label; long past that a
 * string is not a field name, it is caller-supplied payload being smuggled
 * into permanent storage.
 */
export const MAX_DISCLOSURE_RULE_STRING_LENGTH = 256;

/** Result of `validatePolicyInput` — a discriminated union so a caller
 * cannot forget to check `ok` before reading `error`. */
export type PolicyValidationResult =
  | { ok: true }
  | { ok: false; error: string };

/**
 * Bound the caller-supplied `policy_name` and `rules` payload BEFORE it
 * ever reaches `PolicyStore.create` / `update` (rule 8: bounded rule
 * COUNT and bounded per-rule STRING sizes, not just a count on the
 * policies map itself). Called from the tool handler so an oversized
 * payload is refused before any storage write or quota slot is touched.
 */
export function validatePolicyInput(
  policyName: string,
  rules: DisclosureRule[]
): PolicyValidationResult {
  if (
    typeof policyName !== "string" ||
    policyName.length > MAX_DISCLOSURE_POLICY_NAME_LENGTH
  ) {
    return {
      ok: false,
      error: `policy_name must be a string of at most ${MAX_DISCLOSURE_POLICY_NAME_LENGTH} characters`,
    };
  }
  if (!Array.isArray(rules) || rules.length > MAX_DISCLOSURE_POLICY_RULES) {
    return {
      ok: false,
      error: `rules must contain at most ${MAX_DISCLOSURE_POLICY_RULES} entries`,
    };
  }
  for (const rule of rules) {
    if (
      typeof rule.context !== "string" ||
      rule.context.length > MAX_DISCLOSURE_RULE_STRING_LENGTH
    ) {
      return {
        ok: false,
        error: `rule context must be a string of at most ${MAX_DISCLOSURE_RULE_STRING_LENGTH} characters`,
      };
    }
    for (const [listName, list] of [
      ["disclose", rule.disclose],
      ["withhold", rule.withhold],
      ["proof_required", rule.proof_required],
    ] as const) {
      if (
        !Array.isArray(list) ||
        list.length > MAX_DISCLOSURE_RULE_FIELD_ITEMS
      ) {
        return {
          ok: false,
          error: `rule.${listName} must contain at most ${MAX_DISCLOSURE_RULE_FIELD_ITEMS} entries`,
        };
      }
      for (const field of list) {
        if (
          typeof field !== "string" ||
          field.length > MAX_DISCLOSURE_RULE_STRING_LENGTH
        ) {
          return {
            ok: false,
            error: `rule.${listName} entries must be strings of at most ${MAX_DISCLOSURE_RULE_STRING_LENGTH} characters`,
          };
        }
      }
    }
  }
  return { ok: true };
}

/**
 * Shared bucket for calls with no server-set session (mirrors
 * handshake/tools.ts's `AGENT_UNKNOWN_ORIGIN` — same literal, same
 * semantics: router.ts sets `callerIdentity` to this exact string whenever
 * `options.currentAgentId()` returns undefined). Every module that quotas
 * on `callerIdentity` independently falls back to this literal rather than
 * skipping accounting for an "unknown" caller — a shared bucket, not an
 * unbounded escape hatch, since every unknown-identity call still shares
 * ONE already-bounded origin.
 */
export const DISCLOSURE_UNKNOWN_ORIGIN = "agent:unknown";

/**
 * Resolve the per-origin quota key for a `PolicyStore` write. `undefined`
 * covers both the router's own `agent:unknown` fallback and a call that
 * bypassed the router entirely (a direct unit-test call, or a future
 * non-MCP caller) — both land in the same shared bucket rather than
 * skipping accounting.
 */
export function resolvePolicyOrigin(
  callerIdentity: string | undefined
): string {
  return callerIdentity && callerIdentity.length > 0
    ? callerIdentity
    : DISCLOSURE_UNKNOWN_ORIGIN;
}

/** Why a `PolicyStore.create` / `update` call was refused. Extends
 * `BoundedMapRefuseReason` with the two reasons specific to the
 * update-in-place ownership check. */
export type PolicyWriteRefuseReason =
  | BoundedMapRefuseReason
  | "not_found"
  | "forbidden";

/** Result of `PolicyStore.create` / `update` — a discriminated union so a
 * caller cannot read `.policy` on a refused write. */
export type PolicyWriteResult =
  | { ok: true; policy: DisclosurePolicy }
  | { ok: false; reason: PolicyWriteRefuseReason };

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

    // Withhold is the first matched action so an explicit deny cannot be weakened by proof_required or disclose lists.
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
 *
 * BOUNDED (LD3, rule 8): `policies` is a `BoundedMap` capped globally
 * (`MAX_DISCLOSURE_POLICIES`) and per-caller-session
 * (`MAX_DISCLOSURE_POLICIES_PER_ORIGIN`), mirroring the pattern
 * handshake/tools.ts established for its own attacker-writable maps. Never
 * evicts: unlike a handshake session (safe to drop — a fresh one costs
 * nothing to re-request) a disclosure policy is a human-configured privacy
 * preference the principal actively relies on, so `selectEviction` below
 * always refuses rather than silently discarding one to admit another.
 */
export class PolicyStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private readonly policies: BoundedMap<string, DisclosurePolicy>;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l3-policies");
    this.policies = new BoundedMap<string, DisclosurePolicy>({
      maxSize: MAX_DISCLOSURE_POLICIES,
      maxPerOrigin: MAX_DISCLOSURE_POLICIES_PER_ORIGIN,
      // Policies are never silently traded away — see the class doc above.
      selectEviction: () => ({ refuse: true }),
      // No onRefuse/onEvict here: the tool layer (disclosure/tools.ts,
      // mirroring handshake/tools.ts's insertSession) reads `create`'s own
      // PolicyWriteResult and audits the domain-specific reason itself
      // with the caller-facing context (policy_name, origin) a generic
      // BoundedMap-level hook would not have.
    });
  }

  /**
   * Create and store a new disclosure policy.
   *
   * Quota enforcement (rule 8) happens by inserting into the bounded,
   * per-origin-capped map FIRST — before the durable write — mirroring
   * handshake/tools.ts's `insertSession`: a refused caller must never
   * reach storage, or a retried call could grow on-disk state past the cap
   * even while the in-memory cache refuses to track the phantom entry.
   *
   * `origin` is the SERVER-SET agent-session principal (`callerIdentity`,
   * threaded from router.ts through disclosure/tools.ts's
   * `resolvePolicyOrigin`) — the quota key. `identityId` is the caller-
   * supplied optional Sanctuary identity this policy is scoped to; kept
   * only as descriptive metadata (`identity_id`, `owner_session` doc)
   * because `identity_create` is Tier-3 always-allow and therefore
   * agent-mintable (Class C lesson — never the quota key).
   */
  async create(
    policyName: string,
    rules: DisclosureRule[],
    defaultAction: "withhold" | "ask-principal",
    identityId?: string,
    origin?: string
  ): Promise<PolicyWriteResult> {
    const resolvedOrigin = resolvePolicyOrigin(origin);
    const policyId = `pol-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date().toISOString();

    const policy: DisclosurePolicy = {
      policy_id: policyId,
      policy_name: policyName,
      rules,
      default_action: defaultAction,
      identity_id: identityId,
      owner_session: resolvedOrigin,
      created_at: now,
      updated_at: now,
    };

    const result = await this.policies.set(policyId, policy, resolvedOrigin);
    if (!result.ok) {
      return { ok: false, reason: result.reason };
    }
    try {
      await this.persist(policy);
    } catch (err) {
      // Roll back the reserved slot: a storage failure must never leave a
      // counted-but-unpersisted phantom policy occupying this origin's
      // quota forever (the map has no other way to notice the write never
      // landed on disk).
      this.policies.delete(policyId);
      throw err;
    }

    return { ok: true, policy };
  }

  /**
   * Replace an existing policy's rules IN PLACE, without minting a new id
   * or consuming a new quota slot (rule 8 — "an explicit delete/replace
   * path so a caller can reclaim its own policy slots"). Bound to the
   * ORIGINAL creator's session (`owner_session`), never to a
   * caller-supplied `identity_id` or to the `policy_id` alone — otherwise
   * any caller who merely guesses or is told another session's policy_id
   * could overwrite that session's privacy configuration for free.
   *
   * `undefined` `owner_session` (a policy persisted before this field
   * existed) fails CLOSED: it can never be claimed as an update target,
   * only superseded by a brand-new `create`. This is deliberate — there is
   * no recorded owner to verify a claim against, and allowing the first
   * caller to assert ownership of unattributed state is exactly the
   * "any identity mints its way in" shape rule 8 exists to close.
   */
  async update(
    policyId: string,
    policyName: string,
    rules: DisclosureRule[],
    defaultAction: "withhold" | "ask-principal",
    identityId: string | undefined,
    origin: string | undefined
  ): Promise<PolicyWriteResult> {
    const resolvedOrigin = resolvePolicyOrigin(origin);
    const existing = await this.get(policyId);
    if (!existing) {
      return { ok: false, reason: "not_found" };
    }
    const ownerOrigin = this.policies.originOf(policyId);
    if (ownerOrigin === undefined || ownerOrigin !== resolvedOrigin) {
      return { ok: false, reason: "forbidden" };
    }

    const policy: DisclosurePolicy = {
      ...existing,
      policy_name: policyName,
      rules,
      default_action: defaultAction,
      identity_id: identityId,
      updated_at: new Date().toISOString(),
    };

    await this.persist(policy);
    // Existing-key `set()` bypasses BoundedMap's admission lock/quota
    // entirely (core/bounded-map.ts: "for an EXISTING key never touches
    // origins") — this can never fail on quota and never consumes a new
    // per-caller slot, which is the whole point of an in-place update.
    await this.policies.set(policyId, policy, ownerOrigin);

    return { ok: true, policy };
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
      // Best-effort cache, bounded by the same caps as create() (see
      // loadAll's doc): a policy already over cap due to legacy pre-fix
      // data is still returned to the caller, just not cached.
      await this.policies.set(policy.policy_id, policy, policy.owner_session);
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
   *
   * Cap enforcement applies to restored entries too (rule 8): if disk
   * holds more policies than the current cap allows (legacy data written
   * before this fix, or a lowered cap), the surplus is silently left
   * uncached rather than failing the whole restore — `this.policies.set`
   * simply refuses once a cap is hit and the loop continues past it. This
   * bounds in-memory working set from EVERY source, not only from calls
   * made after this fix shipped.
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
          await this.policies.set(
            policy.policy_id,
            policy,
            policy.owner_session
          );
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
