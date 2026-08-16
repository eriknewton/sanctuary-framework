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
 * Reconstruct every rule from ONLY its four known fields (LD3 gate DEFECT
 * 1 — a two-family adversarial re-review of the LD3 fix above). Confirmed
 * exploit: `validatePolicyInput` bounds the four known fields' lengths but
 * never rejects an EXTRA own property on a rule object, and
 * `tool-args.ts`'s `validateArgs` byte-caps only TOP-LEVEL string args —
 * it never recurses into `rules[]` items — so a rule shaped
 * `{context, disclose:[], withhold:[], proof_required:[], junk:
 * "A".repeat(5_000_000)}` passed both upstream checks and `create()`/
 * `update()` would otherwise persist it verbatim, smuggling an unbounded
 * per-rule payload into permanent storage (up to
 * MAX_DISCLOSURE_POLICY_RULES rules x MAX_DISCLOSURE_POLICIES_PER_ORIGIN
 * policies per caller). This is the STORAGE-BOUNDARY fix (the write path
 * itself, not just the pre-write validator that a direct `PolicyStore`
 * caller — such as a future non-MCP caller, or these tests — could bypass
 * entirely): building a BRAND-NEW object from named fields means an
 * unexpected own property can never survive into what `create`/`update`
 * persist, whatever validation upstream did or skipped. Called from
 * `create()` and `update()` — both are write paths that reach `persist()`.
 *
 * DEEPENED (LD3 gate fix-round-2 MUST-FIX 2): the reconstruction above was
 * only SHALLOW — `context` was copied by reference and `[...rule.disclose]`
 * etc. copy the ARRAY but not its elements, so a nested object inside an
 * element (`disclose: [{ junk: "A".repeat(5_000_000) }]`) still reached
 * `persist()` verbatim when a caller reached `PolicyStore` directly,
 * bypassing `validatePolicyInput`'s own element-type check. The MCP-facing
 * `disclosure_set_policy` handler always calls `validatePolicyInput` first
 * (tools.ts), which DOES reject a non-string element — so this is
 * defense-in-depth for the storage boundary itself (a future non-MCP
 * caller, or a direct `PolicyStore` call as in this file's own tests),
 * not the primary gate. `sanitizeStringArray` below drops (never
 * stringifies) a non-string element so no attacker-controlled object
 * shape is ever serialized into storage.
 */
function sanitizeRules(rules: DisclosureRule[]): DisclosureRule[] {
  return rules.map((rule) => ({
    context: typeof rule.context === "string" ? rule.context : "",
    disclose: sanitizeStringArray(rule.disclose),
    withhold: sanitizeStringArray(rule.withhold),
    proof_required: sanitizeStringArray(rule.proof_required),
  }));
}

/**
 * Reduce a value to an array of only its STRING elements (LD3 gate
 * fix-round-2 MUST-FIX 2, `sanitizeRules`'s helper). A non-array input
 * becomes `[]`; a non-string element is DROPPED rather than coerced —
 * coercing (e.g. `String(item)`) would still serialize an attacker-chosen
 * object's shape (via its `toString`) into storage, which is exactly the
 * smuggling path this function exists to close.
 */
function sanitizeStringArray(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  return list.filter((item): item is string => typeof item === "string");
}

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
  | "forbidden"
  | "quota_state_unavailable";

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
    // REHYDRATE BEFORE QUOTA CHECK (LD3 gate DEFECT 2): the BoundedMap's
    // size/per-origin counters start at zero for a freshly constructed
    // `PolicyStore` — a process restart, not just a fresh test instance.
    // Persisted policies from BEFORE the restart stay on disk but the
    // in-memory counters have no memory of them until something loads
    // them back in. Without this call, a caller could re-fill an
    // already-full origin's quota (and the global cap) every time the
    // process restarts, because the check below reads `this.policies`,
    // not disk. `loadAll` is idempotent (skips keys already cached) so
    // calling it on every write is correctness, not just a boot-time nicety.
    //
    // FAIL CLOSED on a failed rehydrate (LD3 gate fix-round-2 MUST-FIX 1,
    // MUST-NEVER #5): `loadAll` reports `ok: false` only when it could NOT
    // durably confirm the persisted set (a `storage.list()`/`read()`
    // exception), never for a genuinely empty store (which is `ok: true`
    // with zero entries). Proceeding past a failed rehydrate would check
    // the quota against a map that is an UNKNOWN UNDERCOUNT, not a
    // verified count — a caller could ride a transient listing failure
    // straight past MAX_DISCLOSURE_POLICIES_PER_ORIGIN / global cap. Refuse
    // and let the caller retry once storage enumeration recovers.
    const rehydrated = await this.loadAll();
    if (!rehydrated.ok) {
      return { ok: false, reason: "quota_state_unavailable" };
    }
    // DEBT (residual, LD3 gate fix-round-2, accepted not fixed): the
    // rehydrate-then-admit sequence above is not atomic ACROSS PROCESSES —
    // two `PolicyStore` instances backed by the same storage could both
    // `loadAll()` a count of 19 and both admit, landing at 21. Accepted
    // because the deployment target is single-process (same class as the
    // deferred cross-process bridge-dedup item); a storage-level lock or
    // compare-and-swap on the persisted set is the future fix if a
    // multi-process deployment is ever needed.

    const resolvedOrigin = resolvePolicyOrigin(origin);
    const policyId = `pol-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = new Date().toISOString();

    const policy: DisclosurePolicy = {
      policy_id: policyId,
      policy_name: policyName,
      // Sanitized (LD3 gate DEFECT 1): never persist the caller-supplied
      // `rules` array verbatim — see `sanitizeRules`'s doc for the
      // unbounded-nested-field exploit this closes.
      rules: sanitizeRules(rules),
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
    // See `create()`'s matching comment (LD3 gate DEFECT 2): `update` also
    // reads `this.policies.originOf` below, and a not-yet-rehydrated map
    // after a restart would report `undefined` for a legitimately owned
    // pre-restart policy (`get()` only caches the ONE record it happens to
    // look up, not the full inventory), turning a legitimate owner's
    // update into a spurious "forbidden". Rehydrating here keeps ownership
    // resolution correct across a restart the same way it keeps the quota
    // check correct in `create()`.
    //
    // FAIL CLOSED on a failed rehydrate (LD3 gate fix-round-2 MUST-FIX 1,
    // MUST-NEVER #5): same rationale as `create()` above — `ownerOrigin`
    // resolution just below depends on this map already reflecting the
    // full persisted set. Proceeding past a failed rehydrate risks either
    // a spurious "forbidden" (a legitimate owner's entry never got loaded)
    // or, via `get()`'s own best-effort re-cache, an update decision made
    // against an undercounted map. Refuse rather than guess.
    const rehydrated = await this.loadAll();
    if (!rehydrated.ok) {
      return { ok: false, reason: "quota_state_unavailable" };
    }

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
      // Sanitized (LD3 gate DEFECT 1) — same reconstruction as `create()`;
      // `update` is the other write path that reaches `persist()`.
      rules: sanitizeRules(rules),
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
   *
   * Called from `create()`/`update()` (LD3 gate DEFECT 2) as well as
   * `list()`: the quota/ownership checks in the write paths need the
   * in-memory `BoundedMap` to already reflect what is durably stored, not
   * only what THIS process instance has created since it started — see
   * `create()`'s call site comment. Cheap to call repeatedly for entries
   * that got cached: the `this.policies.has(meta.key)` guard below skips
   * them, so a call after the first successful rehydrate only re-lists
   * storage metadata and does no redundant decrypt work for those keys.
   * DEBT (LD3 gate fix-round-2, accepted not fixed): a legacy, pre-fix
   * over-cap policy that `this.policies.set()` REFUSES below is never
   * cached, so `has()` never skips it — every future call to `loadAll()`
   * (i.e. every `create()`/`update()`, since both call it) re-reads and
   * re-decrypts that same over-cap record, an O(N)-per-write cost for a
   * fortress carrying legacy over-cap data. An in-memory "known-refused"
   * id set would bound this to one decrypt per process lifetime.
   *
   * Returns `{ ok: false }` when `storage.list()` or `storage.read()`
   * THROWS — a signal that the persisted set could not be fully
   * enumerated, distinct from a genuinely empty store (`ok: true`, zero
   * entries; `storage.list()` resolving to `[]` is not an error). A
   * single unreadable/corrupted policy record (JSON parse or decrypt
   * failure) is skipped and does NOT flip this to `ok: false` — that
   * failure mode is unchanged from before this fix and is tracked
   * separately; only a `list()`/`read()` exception, which leaves the
   * rest of the on-disk set unaccounted for, does. `create()`/`update()`
   * (fix-round-2 MUST-FIX 1) fail closed on `ok: false` rather than
   * proceed with a quota count that may be an undercount.
   */
  private async loadAll(): Promise<{ ok: boolean }> {
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
      return { ok: true };
    } catch {
      // FAIL CLOSED signal (LD3 gate fix-round-2 MUST-FIX 1, MUST-NEVER
      // #5): `storage.list()`/`storage.read()` threw, so the in-memory
      // map may be an undercount of what is actually on disk. Reporting
      // `ok: true` here (as before this fix) let `create()`/`update()`
      // check quota against that undercount and admit a policy past the
      // cap on a transient storage failure — a fail-OPEN on the quota.
      // `list()` (public API, read-only) still returns whatever is
      // cached rather than throwing here; only the two write paths that
      // gate an admission decision on this result are made to refuse.
      return { ok: false };
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
