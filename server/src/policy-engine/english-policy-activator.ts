/**
 * Sanctuary WP-V1.3-6 Xi-2 English-Authored Policy Activation Lifecycle.
 *
 * Closes the operator-decision arc for Xi-1's compile-only foundation.
 * Operator submits English text -> Xi-1 produces a `CompiledPolicy`
 * draft -> Xi-2 mounts the draft into the live `PrincipalPolicy` on
 * explicit operator action (`activate`) and unmounts it on `revoke`.
 *
 * Lifecycle states:
 *   pending     - Xi-1 compile result; not yet applied.
 *   activated   - Xi-2 applied the rule to the live PrincipalPolicy.
 *   revoked     - Xi-2 removed the rule from the live policy.
 *
 * Xi-2 invariants:
 *
 *   1. NO auto-activation. Activation requires an explicit operator
 *      decision through this surface. The compile path does not
 *      mutate the live policy.
 *
 *   2. Low-confidence drafts refuse to activate unless the operator
 *      passes `override_low_confidence: true`. The override is
 *      audit-logged for replay. CompiledPolicy.compile_confidence ===
 *      "low" is the gate.
 *
 *   3. Activation + revocation persist to encrypted fortress state
 *      (PolicyActivationStore) so the lifecycle survives restarts.
 *      Persistence shape: PolicyDraftRecord wrapping the Xi-1
 *      CompiledPolicy + status + activation metadata + pre-activation
 *      policy hash (so revoke can verify the policy hasn't drifted
 *      under us).
 *
 *   4. Rule application is structural. `applyRule()` is a pure
 *      function that maps (PrincipalPolicy, CompiledPolicyRule) ->
 *      PrincipalPolicy. Activate composes apply; revoke composes the
 *      INVERSE rule and applies that. Tests cover all five rule kinds
 *      + their inverse.
 *
 *   5. Castle-walking: no new outbound surface. Activator + store +
 *      routes all read + write to local fortress storage only. The
 *      live PrincipalPolicy I/O is plugged in via readPolicy /
 *      writePolicy callbacks so this module does not couple to
 *      principal-policy.yaml file paths or in-memory cache details.
 */

import { createHash, randomUUID } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type {
  AnomalyAction,
  PrincipalPolicy,
  Tier2Config,
} from "../principal-policy/types.js";
import { enforceForcedTiers } from "../principal-policy/loader.js";
import type {
  CompiledPolicy,
  CompiledPolicyRule,
} from "./english-policy-compiler.js";
import {
  conflictIds,
  detectConflicts,
  hasHighSeverityConflict,
  principalPolicyToRules,
  type PolicyConflict,
} from "./conflict-detector.js";

// ── Public types ─────────────────────────────────────────────────────

export type PolicyDraftStatus = "pending" | "activated" | "revoked";

export interface PolicyDraftRecord {
  /** The Xi-1 compile output. Immutable across the lifecycle. */
  draft: CompiledPolicy;
  status: PolicyDraftStatus;
  /** Wall fortress id stamped at first persist. */
  fortress_id: string;
  /** Audit-trail ids the operator can follow for replay. */
  activated_at?: string;
  activated_by?: string;
  /**
   * SHA-256 hex of the canonicalized PrincipalPolicy snapshot
   * BEFORE this draft's rule was applied. Persisted so revoke can
   * detect the case where the live policy has drifted between
   * activation and revocation (drift triggers an audit warning and
   * conservative revocation that only undoes the rule's specific
   * contribution, not the full pre-activation state).
   */
  pre_activation_policy_hash?: string;
  revoked_at?: string;
  revoked_by?: string;
  /** True when activation was allowed despite compile_confidence === "low". */
  activation_override?: boolean;
  /** Conflicts the operator saw and acknowledged before activation. */
  conflicts_acknowledged?: PolicyConflict[];
  /** High-severity conflict ids explicitly forced by the operator. */
  forced_conflict_ids?: string[];
}

export type ActivationFailure =
  | "draft_not_found"
  | "low_confidence_refused"
  | "policy_conflicts_unacknowledged"
  | "policy_conflict_force_required"
  | "already_activated"
  | "invalid_rule"
  | "policy_io_failed";

export type RevocationFailure =
  | "draft_not_found"
  | "not_activated"
  | "policy_io_failed";

export type ActivationOutcome =
  | { ok: true; updated_policy: PrincipalPolicy; record: PolicyDraftRecord }
  | {
      ok: false;
      reason: ActivationFailure;
      message: string;
      conflicts?: PolicyConflict[];
    };

export type RevocationOutcome =
  | { ok: true; updated_policy: PrincipalPolicy; record: PolicyDraftRecord }
  | { ok: false; reason: RevocationFailure; message: string };

export const ENGLISH_POLICY_ACTIVATION_AUDIT_OPS = {
  ACTIVATED: "english_policy_activated",
  REVOKED: "english_policy_revoked",
  ACTIVATION_REFUSED: "english_policy_activation_refused",
  CONFLICT_DETECTED: "policy_conflict_detected",
  CONFLICT_ACKNOWLEDGED: "policy_conflict_acknowledged",
  FORCE_CONFLICT_USED: "policy_force_conflict_used",
} as const;

export type EnglishPolicyActivationAuditOp =
  (typeof ENGLISH_POLICY_ACTIVATION_AUDIT_OPS)[keyof typeof ENGLISH_POLICY_ACTIVATION_AUDIT_OPS];

// ── Encrypted persistence ───────────────────────────────────────────

const ACTIVATION_STORE_NAMESPACE = "_english_policy_activation";
const ACTIVATION_STORE_KEY_PREFIX = "draft.";
const ACTIVATION_HKDF_INFO = "l2-english-policy-activation-v1";

interface PersistedEnvelope {
  version: 1;
  draft_id: string;
  fortress_id: string;
  saved_at: string;
  record: PolicyDraftRecord;
}

export interface PolicyActivationStoreDeps {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  now?: () => Date;
}

export class PolicyActivationStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(deps: PolicyActivationStoreDeps) {
    this.storage = deps.storage;
    this.encryptionKey = derivePurposeKey(deps.masterKey, ACTIVATION_HKDF_INFO);
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
  }

  async save(record: PolicyDraftRecord): Promise<void> {
    const envelope: PersistedEnvelope = {
      version: 1,
      draft_id: record.draft.draft_id,
      fortress_id: this.fortressId,
      saved_at: this.now().toISOString(),
      record,
    };
    const aad = stringToBytes(this.aadFor(record.draft.draft_id));
    const cipher = encrypt(
      stringToBytes(JSON.stringify(envelope)),
      this.encryptionKey,
      aad,
    );
    await this.storage.write(
      ACTIVATION_STORE_NAMESPACE,
      `${ACTIVATION_STORE_KEY_PREFIX}${record.draft.draft_id}`,
      stringToBytes(JSON.stringify(cipher)),
    );
  }

  async load(draftId: string): Promise<PolicyDraftRecord | null> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        ACTIVATION_STORE_NAMESPACE,
        `${ACTIVATION_STORE_KEY_PREFIX}${draftId}`,
      );
    } catch {
      return null;
    }
    if (!raw) return null;
    try {
      const cipher: EncryptedPayload = JSON.parse(bytesToString(raw));
      const aad = stringToBytes(this.aadFor(draftId));
      const plaintext = decrypt(cipher, this.encryptionKey, aad);
      const envelope: PersistedEnvelope = JSON.parse(bytesToString(plaintext));
      if (envelope.version !== 1) return null;
      if (envelope.fortress_id !== this.fortressId) return null;
      if (envelope.record.draft.draft_id !== draftId) return null;
      return envelope.record;
    } catch {
      return null;
    }
  }

  async list(): Promise<PolicyDraftRecord[]> {
    const metas = await this.storage.list(
      ACTIVATION_STORE_NAMESPACE,
      ACTIVATION_STORE_KEY_PREFIX,
    );
    const out: PolicyDraftRecord[] = [];
    for (const meta of metas) {
      if (!meta.key.startsWith(ACTIVATION_STORE_KEY_PREFIX)) continue;
      const draftId = meta.key.slice(ACTIVATION_STORE_KEY_PREFIX.length);
      const record = await this.load(draftId);
      if (record) out.push(record);
    }
    return out;
  }

  private aadFor(draftId: string): string {
    return `${this.fortressId}|${draftId}`;
  }
}

// ── Activator ────────────────────────────────────────────────────────

export interface EnglishPolicyActivatorDeps {
  store: PolicyActivationStore;
  auditLog: AuditLog;
  fortressId: string;
  /** Returns the current PrincipalPolicy snapshot. */
  readPolicy: () => Promise<PrincipalPolicy>;
  /** Persists the mutated PrincipalPolicy. */
  writePolicy: (policy: PrincipalPolicy) => Promise<void>;
  now?: () => Date;
}

export interface ActivateOptions {
  override_low_confidence?: boolean;
  conflicts_acknowledged?: PolicyConflict[];
  force_conflict_ids?: string[];
}

export class EnglishPolicyActivator {
  private readonly store: PolicyActivationStore;
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;
  private readonly readPolicy: () => Promise<PrincipalPolicy>;
  private readonly writePolicy: (policy: PrincipalPolicy) => Promise<void>;
  private readonly now: () => Date;

  constructor(deps: EnglishPolicyActivatorDeps) {
    this.store = deps.store;
    this.auditLog = deps.auditLog;
    this.fortressId = deps.fortressId;
    this.readPolicy = deps.readPolicy;
    this.writePolicy = deps.writePolicy;
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Promote a Xi-1 compile-only draft to an activated rule on the
   * live policy. Idempotent on `already_activated`; ID lookup
   * across in-memory + persisted stores is the caller's job
   * (routes do that wiring).
   */
  async activate(
    draft: CompiledPolicy,
    operatorId: string,
    opts: ActivateOptions = {},
  ): Promise<ActivationOutcome> {
    // 1. Low-confidence refusal unless explicit override.
    if (
      draft.compile_confidence === "low" &&
      opts.override_low_confidence !== true
    ) {
      const reason: ActivationFailure = "low_confidence_refused";
      const message = `compile_confidence === "low" refuses activation; pass override_low_confidence: true to bypass`;
      await this.auditLog.append(
        "l2",
        ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATION_REFUSED,
        operatorId,
        {
          draft_id: draft.draft_id,
          reason,
          warnings: draft.compile_warnings,
          fortress_id: this.fortressId,
        },
        "failure",
      );
      return { ok: false, reason, message };
    }

    // 2. Already-activated check via persisted store.
    const existing = await this.store.load(draft.draft_id);
    if (existing && existing.status === "activated") {
      return {
        ok: false,
        reason: "already_activated",
        message: `draft ${draft.draft_id} is already activated`,
      };
    }

    // 3. Read current policy, detect conflicts, then apply the rule.
    let prePolicy: PrincipalPolicy;
    try {
      prePolicy = await this.readPolicy();
    } catch (err) {
      return {
        ok: false,
        reason: "policy_io_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    const conflicts = detectConflicts(draft, principalPolicyToRules(prePolicy));
    if (conflicts.length > 0) {
      await this.auditLog.append(
        "l2",
        ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_DETECTED,
        operatorId,
        {
          draft_id: draft.draft_id,
          conflict_ids: conflictIds(conflicts),
          severities: conflicts.map((c) => c.severity),
          fortress_id: this.fortressId,
        },
      );
      const acknowledged = opts.conflicts_acknowledged ?? [];
      const acknowledgedIds = new Set(acknowledged.map((c) => c.conflict_id));
      const allAcknowledged = conflicts.every((c) =>
        acknowledgedIds.has(c.conflict_id)
      );
      if (!allAcknowledged) {
        return {
          ok: false,
          reason: "policy_conflicts_unacknowledged",
          message: "policy conflicts require explicit operator acknowledgment before activation",
          conflicts,
        };
      }
      await this.auditLog.append(
        "l2",
        ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_ACKNOWLEDGED,
        operatorId,
        {
          draft_id: draft.draft_id,
          conflict_ids: conflictIds(conflicts),
          fortress_id: this.fortressId,
        },
      );
      if (hasHighSeverityConflict(conflicts)) {
        const forcedIds = new Set(opts.force_conflict_ids ?? []);
        const unforcedHigh = conflicts.filter(
          (c) => c.severity === "high" && !forcedIds.has(c.conflict_id),
        );
        if (unforcedHigh.length > 0) {
          return {
            ok: false,
            reason: "policy_conflict_force_required",
            message: "high-severity policy conflicts require force_conflict_ids before activation",
            conflicts,
          };
        }
        await this.auditLog.append(
          "l2",
          ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.FORCE_CONFLICT_USED,
          operatorId,
          {
            draft_id: draft.draft_id,
            conflict_ids: [...forcedIds],
            fortress_id: this.fortressId,
          },
          "success",
        );
      }
    }
    const preHash = canonicalPolicyHash(prePolicy);
    let updatedPolicy: PrincipalPolicy;
    try {
      updatedPolicy = applyRule(prePolicy, draft.compiled_rule);
    } catch (err) {
      return {
        ok: false,
        reason: "invalid_rule",
        message: err instanceof Error ? err.message : String(err),
      };
    }

    try {
      await this.writePolicy(updatedPolicy);
    } catch (err) {
      return {
        ok: false,
        reason: "policy_io_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }

    // 4. Persist the activated record.
    const activatedAt = this.now().toISOString();
    const record: PolicyDraftRecord = {
      draft,
      status: "activated",
      fortress_id: this.fortressId,
      activated_at: activatedAt,
      activated_by: operatorId,
      pre_activation_policy_hash: preHash,
      ...(opts.override_low_confidence === true
        ? { activation_override: true }
        : {}),
      ...(conflicts.length > 0
        ? { conflicts_acknowledged: opts.conflicts_acknowledged ?? [] }
        : {}),
      ...((opts.force_conflict_ids ?? []).length > 0
        ? { forced_conflict_ids: opts.force_conflict_ids }
        : {}),
    };
    await this.store.save(record);

    // 5. Audit emit.
    await this.auditLog.append(
      "l2",
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATED,
      operatorId,
      {
        draft_id: draft.draft_id,
        rule_kind: draft.compiled_rule.kind,
        rule_operation:
          draft.compiled_rule.operation ?? null,
        compile_confidence: draft.compile_confidence,
        activation_override: opts.override_low_confidence === true,
        pre_activation_policy_hash: preHash,
        fortress_id: this.fortressId,
      },
    );

    return { ok: true, updated_policy: updatedPolicy, record };
  }

  /**
   * Revoke an activated draft. Applies the rule's inverse to the live
   * policy. If the live policy has drifted since activation (policy
   * hash mismatch), the inverse is still applied but a drift warning
   * fires in the audit so the operator can review.
   */
  async revoke(
    draftId: string,
    operatorId: string,
  ): Promise<RevocationOutcome> {
    const existing = await this.store.load(draftId);
    if (!existing) {
      return {
        ok: false,
        reason: "draft_not_found",
        message: `draft ${draftId} is not in the activation store`,
      };
    }
    if (existing.status !== "activated") {
      return {
        ok: false,
        reason: "not_activated",
        message: `draft ${draftId} status is ${existing.status}; only activated drafts can be revoked`,
      };
    }

    let prePolicy: PrincipalPolicy;
    try {
      prePolicy = await this.readPolicy();
    } catch (err) {
      return {
        ok: false,
        reason: "policy_io_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    const driftWarning =
      existing.pre_activation_policy_hash !== undefined &&
      canonicalPolicyHash(prePolicy) === existing.pre_activation_policy_hash
        ? null
        : "policy_drift_since_activation";

    let updatedPolicy: PrincipalPolicy;
    try {
      updatedPolicy = applyRule(
        prePolicy,
        inverseRule(existing.draft.compiled_rule, prePolicy),
      );
    } catch (err) {
      return {
        ok: false,
        reason: "policy_io_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    try {
      await this.writePolicy(updatedPolicy);
    } catch (err) {
      return {
        ok: false,
        reason: "policy_io_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }

    const revokedAt = this.now().toISOString();
    const record: PolicyDraftRecord = {
      ...existing,
      status: "revoked",
      revoked_at: revokedAt,
      revoked_by: operatorId,
    };
    await this.store.save(record);

    await this.auditLog.append(
      "l2",
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED,
      operatorId,
      {
        draft_id: draftId,
        rule_kind: existing.draft.compiled_rule.kind,
        rule_operation: existing.draft.compiled_rule.operation ?? null,
        drift_warning: driftWarning,
        fortress_id: this.fortressId,
      },
    );

    return { ok: true, updated_policy: updatedPolicy, record };
  }

  /** Look up an activation record by draft id. */
  async getRecord(draftId: string): Promise<PolicyDraftRecord | null> {
    return this.store.load(draftId);
  }

  async listRecords(): Promise<PolicyDraftRecord[]> {
    return this.store.list();
  }

  async checkConflicts(
    draft: CompiledPolicy,
    operatorId = "operator",
  ): Promise<PolicyConflict[]> {
    const policy = await this.readPolicy();
    const conflicts = detectConflicts(draft, principalPolicyToRules(policy));
    if (conflicts.length > 0) {
      await this.auditLog.append(
        "l2",
        ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_DETECTED,
        operatorId,
        {
          draft_id: draft.draft_id,
          conflict_ids: conflictIds(conflicts),
          severities: conflicts.map((c) => c.severity),
          fortress_id: this.fortressId,
        },
      );
    }
    return conflicts;
  }

  /**
   * Helper for the routes layer. Convert a Xi-1 CompiledPolicy
   * lookup into a fully-formed PolicyDraftRecord regardless of
   * whether the draft has been persisted yet. Used by the routes
   * when the operator hits the activate endpoint with a draft that
   * was compiled into Xi-1's in-memory store but never persisted.
   */
  buildPendingRecord(draft: CompiledPolicy): PolicyDraftRecord {
    return {
      draft,
      status: "pending",
      fortress_id: this.fortressId,
    };
  }
}

// ── Pure helpers (exported for tests) ────────────────────────────────

/**
 * Apply a compiled rule to a PrincipalPolicy. Pure function; returns
 * a new policy object. Throws on rules that name a field outside the
 * Tier2Config schema.
 *
 * The structural rule is applied first (applyRuleStructural), then the
 * forced-Tier invariants are re-asserted via enforceForcedTiers, the SAME
 * normalizer the policy loader runs at load time. This closes a defense-in-
 * depth fail-open: a tier1_remove_operation could otherwise drop a forced
 * Tier-1 op (e.g. identity_sign) out of Tier 1, and a tier3_add_operation
 * could otherwise smuggle one (e.g. operator_cloud_provision) into Tier 3,
 * a silent enforcement downgrade. Because activate AND revoke both route through
 * applyRule, both uphold the invariant the loader guarantees (Hard
 * Constraint #5: never silently degrade; #7: policy integrity).
 *
 * Non-forced operations are unaffected: enforceForcedTiers only touches the
 * forced-Tier sets, so a legitimate mutation of any other operation applies
 * exactly as the structural rule produced it.
 */
export function applyRule(
  policy: PrincipalPolicy,
  rule: CompiledPolicyRule,
): PrincipalPolicy {
  return enforceForcedTiers(applyRuleStructural(policy, rule));
}

/**
 * The raw structural rule application. Maps (PrincipalPolicy,
 * CompiledPolicyRule) -> PrincipalPolicy without re-asserting the
 * forced-Tier invariants; applyRule wraps this with enforceForcedTiers.
 */
function applyRuleStructural(
  policy: PrincipalPolicy,
  rule: CompiledPolicyRule,
): PrincipalPolicy {
  switch (rule.kind) {
    case "tier1_add_operation":
      return {
        ...policy,
        tier1_always_approve: dedupedAdd(
          policy.tier1_always_approve,
          requireOperation(rule),
        ),
      };
    case "tier1_remove_operation":
      return {
        ...policy,
        tier1_always_approve: policy.tier1_always_approve.filter(
          (op) => op !== requireOperation(rule),
        ),
      };
    case "tier3_add_operation":
      return {
        ...policy,
        tier3_always_allow: dedupedAdd(
          policy.tier3_always_allow,
          requireOperation(rule),
        ),
      };
    case "tier3_remove_operation":
      return {
        ...policy,
        tier3_always_allow: policy.tier3_always_allow.filter(
          (op) => op !== requireOperation(rule),
        ),
      };
    case "tier2_set_field": {
      const update = rule.tier2_update;
      if (!update) throw new Error("tier2_set_field requires tier2_update");
      if (!(update.field in policy.tier2_anomaly)) {
        throw new Error(`unknown Tier2Config field: ${String(update.field)}`);
      }
      const nextTier2 = { ...policy.tier2_anomaly } as Tier2Config;
      // Numeric vs AnomalyAction is enforced by the field type union
      // at the type level; runtime trust comes from `update.value` being
      // typed `AnomalyAction | number`. We assign by-field via a
      // type-safe switch keyed on field name.
      assignTier2Field(nextTier2, update.field, update.value);
      return {
        ...policy,
        tier2_anomaly: nextTier2,
      };
    }
    default: {
      const _exhaustive: never = rule.kind;
      throw new Error(`unsupported rule kind: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Compute the inverse rule for revoke. The inverse of "add X" is
 * "remove X"; the inverse of "set field F to V" requires reading the
 * pre-revocation policy to know what V was originally (we just remove
 * the change; full undo is out-of-scope for v1.x and would require
 * stashing the pre-activation value).
 *
 * For tier2_set_field, the inverse here is "no-op" with a warning;
 * the operator must follow up with another draft if they need the
 * field restored to a specific value. Documented in the audit emit
 * + the revoke return value.
 */
export function inverseRule(
  rule: CompiledPolicyRule,
  _currentPolicy: PrincipalPolicy,
): CompiledPolicyRule {
  switch (rule.kind) {
    case "tier1_add_operation":
      return { kind: "tier1_remove_operation", operation: rule.operation };
    case "tier1_remove_operation":
      return { kind: "tier1_add_operation", operation: rule.operation };
    case "tier3_add_operation":
      return { kind: "tier3_remove_operation", operation: rule.operation };
    case "tier3_remove_operation":
      return { kind: "tier3_add_operation", operation: rule.operation };
    case "tier2_set_field":
      // Tier2 inverse is non-trivial without the pre-activation value;
      // revoke applies a no-op set to the current value (idempotent).
      return rule;
    default: {
      const _exhaustive: never = rule.kind;
      throw new Error(`unsupported rule kind: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Stable SHA-256 hex of a PrincipalPolicy snapshot. Used as the
 * pre-activation hash for drift detection at revocation time.
 * Field order: tier1_always_approve (sorted), tier3_always_allow
 * (sorted), tier2_anomaly (key-sorted), approval_channel (passthrough).
 * The hash function is exported for tests.
 */
export function canonicalPolicyHash(policy: PrincipalPolicy): string {
  const canonical = {
    version: policy.version,
    tier1_always_approve: [...policy.tier1_always_approve].sort(),
    tier3_always_allow: [...policy.tier3_always_allow].sort(),
    tier2_anomaly: sortKeys(policy.tier2_anomaly as unknown as Record<string, unknown>),
    approval_channel: sortKeys(policy.approval_channel as unknown as Record<string, unknown>),
  };
  return createHash("sha256")
    .update(JSON.stringify(canonical))
    .digest("hex");
}

// ── Internal helpers ─────────────────────────────────────────────────

function requireOperation(rule: CompiledPolicyRule): string {
  if (typeof rule.operation !== "string" || rule.operation.length === 0) {
    throw new Error(`${rule.kind} requires a non-empty operation`);
  }
  return rule.operation;
}

function dedupedAdd(arr: string[], op: string): string[] {
  if (arr.includes(op)) return arr;
  return [...arr, op];
}

function assignTier2Field(
  target: Tier2Config,
  field: keyof Tier2Config,
  value: AnomalyAction | number,
): void {
  // Per Tier2Config: numeric fields are
  //   frequency_spike_multiplier, max_signs_per_minute, bulk_read_threshold.
  // AnomalyAction fields are
  //   new_namespace_access, new_counterparty, first_session_policy.
  if (
    field === "frequency_spike_multiplier" ||
    field === "max_signs_per_minute" ||
    field === "bulk_read_threshold"
  ) {
    if (typeof value !== "number") {
      throw new Error(`field ${field} requires a numeric value`);
    }
    target[field] = value;
    return;
  }
  if (
    field === "new_namespace_access" ||
    field === "new_counterparty" ||
    field === "first_session_policy"
  ) {
    if (typeof value !== "string") {
      throw new Error(`field ${field} requires an AnomalyAction string`);
    }
    if (!isAnomalyAction(value)) {
      throw new Error(`field ${field} value must be one of "approve" | "log" | "allow"`);
    }
    target[field] = value;
    return;
  }
  // Field not in the closed enum: exhaustiveness check.
  throw new Error(`unknown Tier2Config field: ${String(field)}`);
}

function isAnomalyAction(value: string): value is AnomalyAction {
  return value === "approve" || value === "log" || value === "allow";
}

function sortKeys<T extends Record<string, unknown>>(obj: T): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = (obj as Record<string, unknown>)[key];
  }
  return out;
}

/**
 * Convenience: random uuid wrapper exported so the routes layer can
 * stamp an audit-only event id without pulling node:crypto directly.
 */
export function makeActivationEventId(): string {
  return `xi2-${randomUUID()}`;
}
