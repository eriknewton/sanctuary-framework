/**
 * Promote orchestration: selected candidates -> live, signed allow rules.
 *
 * THE RED-LINE INVARIANT (this function exists to uphold it): no manifest
 * mutation, no `publish()` call, and no rule addition happens unless
 * `deps.approve()` returns `allowed: true`. Approval is the SAME Tier-1
 * gate class as `state_export` / key rotation (registered as a
 * non-relaxable Tier-1 operation in `principal-policy/loader.ts` +
 * `gate.ts`, mirroring the Governed File-Grant v1 precedent). If the
 * approval channel is unreachable or denies, this function returns without
 * ever calling `deps.publish` -- the live ruleset is byte-unchanged and
 * every selected destination stays denied (adversarial review finding H1
 * and H2; CI DoD tests 3 and 5).
 *
 * TRUST-BOUNDARY HARDENING (two-family gate fix-round, 2026-07-07):
 *   - The existing ruleset carried forward into the re-signed manifest is
 *     read through `deps.readVerifiedManifest`, which MUST verify the
 *     on-disk manifest's Ed25519 signature against the pinned key AND
 *     re-validate every referenced rule (sig / sha256 / validateRule). A
 *     tampered or unreadable manifest ABORTS the promote and fails closed
 *     (FIX 1). We never launder an unverified on-disk rule into a freshly
 *     signed manifest, and never let an unverified rule shadow a verified
 *     one on an id collision.
 *   - The authoritative read+verify happens twice: once for the BASIS
 *     (pre-approval, to compute the candidate set + approval context) and
 *     again IMMEDIATELY BEFORE publish (post-approval). If the on-disk
 *     manifest digest changed between the two, promote ABORTS (a
 *     compare-and-set), so a concurrent manifest update (e.g. a baseline
 *     deny rule added by another path) is never silently overwritten by a
 *     stale merged set (FIX 2, the read-then-publish lost-update window).
 *   - The approval context carries each synthesized rule's EFFECTIVE match
 *     + scope (what actually gets signed), not the raw observed
 *     host:port -- so a widening granularity (`per_template_etld1`) can
 *     never sign a broader grant than the human saw (FIX 3).
 *
 * A candidate that cannot synthesize a valid rule (fails `validateRule`, or
 * is a refused public-suffix widening) is dropped BEFORE the approval gate
 * is even asked -- it is never offered, and a bad row never blocks
 * promoting the rest of a clean selection (CI DoD test 2).
 */

import type { AllowlistRule, RuleMatch, RuleScope } from "../allowlist/schema.js";
import type { AgentOrigin, OperatorBaseline } from "../allowlist/manifest.js";
import { synthesizeCandidateRule } from "./synthesize.js";
import {
  DEFAULT_OBSERVE_GRANULARITY,
  type CandidateObservation,
  type ObserveGranularity,
} from "./types.js";

/** One row the operator selected to promote, with an optional per-row granularity override (D-Q2). */
export interface PromoteSelectionRow {
  key: string;
  granularity?: ObserveGranularity;
}

export interface PromotePublishResult {
  written_rule_filenames: string[];
  removed_rule_filenames: string[];
}

/**
 * The signature-VERIFIED manifest-level descriptors carried forward on a
 * re-sign. Both live INSIDE the signed `manifest` body (not a separate rule
 * file), so they ride the same pinned-key Ed25519 signature the rules do; a
 * value here is therefore only ever read off a signature-checked manifest,
 * NEVER raw on-disk bytes. Absent when the source manifest omitted the field.
 *
 * WHY CARRYING THEM FORWARD MATTERS (#897 P1, fail-closed correctness):
 * dropping these on a re-sign is strictly MORE denying -- an absent
 * `agent_origin` makes the macOS sysext classify every flow `.agent`
 * (machine-wide default-deny), and an absent `operator_baseline` falls back to
 * the UID-only baseline -- so a silent drop severs the operator's own
 * system-essential connectivity even though the Tier-1 approval only reviewed
 * the newly-added allow rules. Carrying them forward keeps a re-signed
 * manifest faithful to what the operator already signed.
 */
export interface ManifestDescriptors {
  agentOrigin?: AgentOrigin;
  operatorBaseline?: OperatorBaseline;
}

/**
 * The result of reading + cryptographically verifying the current on-disk
 * signed manifest.
 *   - `ok`: signature verified against the pinned key AND every referenced
 *     rule re-validated (sha256 + validateRule); `rules` are the verified
 *     carry-forward set, `agentOrigin`/`operatorBaseline` are the verified
 *     manifest-level descriptors carried forward alongside them, and `digest`
 *     is a compare-and-set token over the signed-manifest bytes.
 *   - `absent`: no manifest exists yet (fresh install) -- an empty ruleset.
 *   - `tampered`: the manifest exists but does NOT verify (bad signature,
 *     unreadable/corrupt JSON, missing rule file, sha256 mismatch, or a
 *     rule that fails validateRule). Promote MUST fail closed on this.
 */
export type VerifiedManifestRead =
  | {
      status: "ok";
      rules: AllowlistRule[];
      digest: string;
      /**
       * The signature-VERIFIED manifest-level descriptors (both optional).
       * Set only when the source manifest carried them, so a re-sign preserves
       * them; omitted otherwise (keeps the re-signed canonical bytes identical).
       */
      agentOrigin?: AgentOrigin;
      operatorBaseline?: OperatorBaseline;
    }
  | { status: "absent" }
  | { status: "tampered"; reason: string };

/** Narrow approval-gate surface `promoteCandidates` needs; `ApprovalGate.evaluate` satisfies it. */
export interface PromoteApprover {
  (operation: string, context: Record<string, unknown>): Promise<{ allowed: boolean; reason?: string }>;
}

export interface PromoteDeps {
  /**
   * Read + cryptographically VERIFY the current on-disk signed manifest.
   * Called twice: once for the basis (pre-approval) and again immediately
   * before publish (post-approval, for the compare-and-set). MUST verify the
   * Ed25519 signature against the pinned key and re-validate every rule; a
   * manifest that does not verify returns `tampered` and aborts the promote.
   */
  readVerifiedManifest: () => Promise<VerifiedManifestRead>;
  /** Tier-1 approval call. Never invoked when there is nothing valid to promote. */
  approve: PromoteApprover;
  /**
   * Re-signs + atomically publishes the FULL merged ruleset PLUS the verified
   * manifest-level descriptors carried forward from the current manifest (#897
   * P1). Invoked ONLY after `approve()` returns `allowed: true` AND the
   * publish-time compare-and-set passes -- never before, never on a denial,
   * never on a tampered/changed manifest. Wraps `runtime/manifest-publisher.ts`'s
   * `publishSignedManifest` in production; a test double in unit tests.
   */
  publish: (rules: AllowlistRule[], descriptors: ManifestDescriptors) => Promise<PromotePublishResult>;
  /**
   * Best-effort per-candidate audit append, one call per promoted
   * candidate. A throw here must NEVER be reported as "promote failed" --
   * by the time this runs the manifest has already been re-signed and
   * published (mirrors `file-grant/mint.ts`'s post-place confirmation
   * audit: a throw after the access-conferring step never rolls back a
   * live grant).
   */
  auditPromotedCandidate?: (row: {
    key: string;
    rule_id: string;
    candidate: CandidateObservation;
  }) => Promise<void>;
  now: Date;
}

export type PromoteDroppedReason = "not_found" | "failed_validation";

export type PromoteOutcome =
  | {
      status: "no_candidates";
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      /** The on-disk manifest failed verification at basis or publish time. Nothing changed. */
      status: "tampered_manifest";
      reason: string;
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      /** The on-disk manifest changed between the approval basis and publish. Nothing changed. */
      status: "manifest_changed";
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      status: "denied";
      reason: string;
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      status: "promoted";
      promotedKeys: string[];
      addedRules: AllowlistRule[];
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
      publish: PromotePublishResult;
    };

/** Stable compare-and-set token for an absent manifest (fresh install). */
const ABSENT_DIGEST = "absent";

function digestOf(read: VerifiedManifestRead): string {
  return read.status === "ok" ? read.digest : ABSENT_DIGEST;
}

function verifiedRulesOf(read: VerifiedManifestRead): AllowlistRule[] {
  return read.status === "ok" ? read.rules : [];
}

/**
 * The verified manifest-level descriptors to carry forward. Sourced ONLY from
 * an `ok` (signature-verified) read; an absent/tampered read carries nothing.
 * Each field is copied only when the source manifest set it, so an absent
 * descriptor stays absent (the re-signed canonical bytes match a manifest
 * built without it).
 */
function verifiedDescriptorsOf(read: VerifiedManifestRead): ManifestDescriptors {
  if (read.status !== "ok") return {};
  const out: ManifestDescriptors = {};
  if (read.agentOrigin !== undefined) out.agentOrigin = read.agentOrigin;
  if (read.operatorBaseline !== undefined) out.operatorBaseline = read.operatorBaseline;
  return out;
}

/**
 * Compact, human-legible description of a synthesized rule's EFFECTIVE match
 * + scope, for the Tier-1 approval context. This is what actually gets
 * signed, so the human approves the real effect (FIX 3), not the raw
 * observed destination. Kept a scalar STRING (not a nested object/array) so
 * it survives the approval gate's `summarizeArgs`, which collapses
 * objects/arrays to a shape summary but passes strings through.
 */
export function describeEffectiveRule(match: RuleMatch, scope: RuleScope): string {
  const parts: string[] = [];
  const axis = (label: string, value: string | string[] | undefined): void => {
    if (value === undefined) return;
    parts.push(`${label}=${Array.isArray(value) ? value.join(",") : value}`);
  };
  axis("host", match.host);
  axis("host_pattern", match.host_pattern);
  axis("ip", match.ip);
  axis("cidr", match.cidr);
  if (match.port !== undefined) {
    parts.push(`port=${Array.isArray(match.port) ? match.port.join(",") : match.port}`);
  }
  if (match.protocol !== undefined) parts.push(match.protocol);
  const scopeDesc = scope.agent_ids?.length
    ? `agent:${scope.agent_ids.join(",")}`
    : scope.template_ids?.length
      ? `template:${scope.template_ids.join(",")}`
      : "all-agents";
  return `allow ${parts.join(" ")} scope=${scopeDesc}`;
}

/** Max synthesized-match lines put into the approval context before summarizing the tail. */
const MAX_APPROVAL_RULE_LINES = 25;

export async function promoteCandidates(
  selection: readonly PromoteSelectionRow[],
  candidatesByKey: ReadonlyMap<string, CandidateObservation>,
  deps: PromoteDeps,
): Promise<PromoteOutcome> {
  const dropped: Array<{ key: string; reason: PromoteDroppedReason }> = [];
  const createdAt = deps.now.toISOString();

  // ── Basis read + verify (FIX 1 fail-closed on tamper) ───────────────────
  // Fail closed BEFORE synthesizing anything: a tampered on-disk manifest
  // must stop the promote, never be laundered into a freshly signed one.
  const basis = await deps.readVerifiedManifest();
  if (basis.status === "tampered") {
    return { status: "tampered_manifest", reason: basis.reason, dropped };
  }
  const basisDigest = digestOf(basis);
  const basisRules = verifiedRulesOf(basis);
  const basisIds = new Set(basisRules.map((rule) => rule.id));

  const promotable: Array<{ key: string; observation: CandidateObservation; rule: AllowlistRule }> = [];
  for (const row of selection) {
    const observation = candidatesByKey.get(row.key);
    if (!observation) {
      dropped.push({ key: row.key, reason: "not_found" });
      continue;
    }
    const rule = synthesizeCandidateRule(observation, createdAt, row.granularity ?? DEFAULT_OBSERVE_GRANULARITY);
    if (!rule) {
      dropped.push({ key: row.key, reason: "failed_validation" });
      continue;
    }
    promotable.push({ key: row.key, observation, rule });
  }

  if (promotable.length === 0) {
    // Nothing to approve, nothing to publish. Deliberately does NOT call
    // `deps.approve` -- there is nothing valid for a human to approve.
    return { status: "no_candidates", dropped };
  }

  // ── Approval context: the SYNTHESIZED effective matches (FIX 3) ─────────
  // Each `rule_N` is the exact match+scope that will be signed if approved.
  const approvalContext: Record<string, unknown> = { candidate_count: promotable.length };
  const shown = promotable.slice(0, MAX_APPROVAL_RULE_LINES);
  shown.forEach((row, i) => {
    approvalContext[`rule_${i + 1}`] = describeEffectiveRule(row.rule.match, row.rule.scope);
  });
  if (promotable.length > shown.length) {
    approvalContext["rules_omitted"] = `${promotable.length - shown.length} more (run promote with a smaller selection to review each)`;
  }

  const approval = await deps.approve("castle_wall_observe_promote", approvalContext);

  if (!approval.allowed) {
    // THE RED-LINE INVARIANT: no publish() call below this line on the
    // denied path. The live manifest is byte-unchanged; every selected
    // destination stays blocked.
    return { status: "denied", reason: approval.reason ?? "not approved", dropped };
  }

  // ── Publish-time re-read + verify + compare-and-set (FIX 1 + FIX 2) ─────
  // Re-verify the on-disk manifest AFTER approval (approval may block on
  // human input). If it no longer verifies, or if its digest changed since
  // the basis we approved against, ABORT and fail closed -- never publish a
  // stale merged set that could drop a concurrently-added rule.
  const atPublish = await deps.readVerifiedManifest();
  if (atPublish.status === "tampered") {
    return { status: "tampered_manifest", reason: atPublish.reason, dropped };
  }
  if (digestOf(atPublish) !== basisDigest) {
    return { status: "manifest_changed", dropped };
  }
  const currentRules = verifiedRulesOf(atPublish);
  // Carry the signature-VERIFIED manifest-level descriptors forward from the
  // SAME verified publish-time read the rules come from -- never raw on-disk
  // bytes -- so the re-signed manifest preserves them (#897 P1). This rides the
  // identical laundering-safe path as the rules: `atPublish` is only `ok` after
  // the pinned-key signature + per-rule verification, and the descriptors live
  // under that signature, so a planted descriptor breaks the signature and
  // lands in the `tampered` abort above rather than getting re-signed.
  const descriptors = verifiedDescriptorsOf(atPublish);

  // Merge: the VERIFIED carry-forward rules first, then the freshly
  // synthesized + validated added rules whose id is not already present.
  // Both sides are trustworthy (currentRules are cryptographically verified;
  // addedRules are validateRule-clean), and ids are content-derived, so a
  // collision means identical content -- keeping the existing verified rule
  // is the safe direction and a synthesized rule can never shadow it.
  const existingIds = new Set(currentRules.map((rule) => rule.id));
  // Defensive: the publish-time set must be digest-equal to the basis, so
  // basisIds and existingIds agree; kept distinct only to make the invariant
  // explicit for a future reader.
  void basisIds;
  const addedRules = promotable.filter((row) => !existingIds.has(row.rule.id)).map((row) => row.rule);
  const mergedRules = [...currentRules, ...addedRules];
  const publishResult = await deps.publish(mergedRules, descriptors);

  for (const row of promotable) {
    if (!deps.auditPromotedCandidate) continue;
    try {
      await deps.auditPromotedCandidate({ key: row.key, rule_id: row.rule.id, candidate: row.observation });
    } catch {
      // Best-effort: the manifest is already published. A throw here must
      // never surface as "promote failed" once the access-widening step
      // (publish) has already succeeded.
    }
  }

  return {
    status: "promoted",
    promotedKeys: promotable.map((row) => row.key),
    addedRules,
    dropped,
    publish: publishResult,
  };
}
