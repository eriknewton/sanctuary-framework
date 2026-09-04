/**
 * Sanctuary MCP Server — L4 Verifiable Reputation: Tool Definitions
 *
 * MCP tool wrappers for reputation recording, querying, export/import,
 * and trust bootstrapping (escrow + principal guarantees).
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import { InterruptedExitImportPendingError } from "../storage/exit-import-journal.js";
import {
  ReputationBundleVerificationError,
  ReputationStore,
  ReputationStoreQuotaError,
  ReputationAlreadyRecordedError,
  ReputationIdOccupiedUnverifiedError,
  trustedSovereigntyTier,
  type InteractionOutcome,
  type ReputationStoreTestOverrides,
  type ReputationInLockAuditEmit,
  type StoredAttestation,
} from "./reputation-store.js";
import {
  BRIDGE_METRIC_POLICY,
  BridgeAttestationMetricValidationError,
  isConcordiaBridgeReputationContext,
} from "./bridge-metrics.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import type { SanctuaryConfig } from "../config.js";
import type { RuntimeStatus } from "../health/evidence.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { requireLocalDidEncodings } from "../core/identity.js";
import {
  resolveTierByDid,
  computeWeightedScore,
  tierDistribution,
  TIER_WEIGHTS,
  type TieredAttestation,
  type SovereigntyTier,
} from "./tiers.js";

/**
 * Map an evidence-derived RuntimeStatus to the Verascore publish layer shape.
 *
 * HONESTY (seam #12): the published SHR payload is signed with the agent's real
 * key and POSTed to an EXTERNAL reputation surface that relying parties consume.
 * A layer's `score`/`status`/`description` must therefore reflect the same
 * evidence `monitor_health` reports, never a hardcoded "100 / active /
 * cryptographically verified". When a layer is not backed by observed
 * enforcement evidence we publish the conservative claim ("unknown" /
 * "configured, unverified") rather than a perfect score.
 */
function verascoreLayerFromStatus(
  status: RuntimeStatus,
  evidence: string
): { score: number; status: string; description: string } {
  switch (status) {
    case "active":
      // Reserved for evidence-backed enforcement (e.g. Castle Wall reports the
      // wall actually armed). Still not a hardcoded 100; "active" is earned.
      return { score: 100, status: "active", description: evidence };
    case "degraded":
      return { score: 72, status: "degraded", description: evidence };
    case "inactive":
      return { score: 0, status: "inactive", description: evidence };
    case "not_configured":
      return {
        score: 0,
        status: "not_configured",
        description: `Configured off / not present: ${evidence}`,
      };
    case "unknown":
    default:
      // No runtime detector confirmed this layer. Publish the absence of
      // evidence as absence of evidence, not as a verified claim.
      return {
        score: 0,
        status: "unknown",
        description: `Configured, unverified (no runtime evidence): ${evidence}`,
      };
  }
}

type BridgeMetricPolicyDisclosure = {
  policy: typeof BRIDGE_METRIC_POLICY;
  status:
    | "policy_rated"
    | "mixed_policy_and_legacy"
    | "legacy_unbounded_metrics"
    | "unverified_policy_claims"
    | "mixed_policy_and_unverified"
    | "no_bridge_metric_evidence";
  policy_rated_attestations: number;
  legacy_unbounded_attestations: number;
  unverified_policy_claim_attestations: number;
  note: string;
};

function filterAttestationsByTimeRange(
  attestations: StoredAttestation[],
  timeRange?: { start: string; end: string }
): StoredAttestation[] {
  if (!timeRange) return attestations;
  const start = new Date(timeRange.start).getTime();
  const end = new Date(timeRange.end).getTime();
  return attestations.filter((a) => {
    const timestamp = new Date(a.attestation.data.timestamp).getTime();
    return timestamp >= start && timestamp <= end;
  });
}

async function bridgeMetricPolicyDisclosure(options: {
  reputationStore: ReputationStore;
  attestations: StoredAttestation[];
  requestedMetrics?: string[];
  includeEmptyBridgeContext?: boolean;
}): Promise<BridgeMetricPolicyDisclosure | undefined> {
  const requestedMetricSet =
    options.requestedMetrics !== undefined
      ? new Set(options.requestedMetrics)
      : undefined;
  const bridgeMetricAttestations = options.attestations.filter((a) => {
    const data = a.attestation.data;
    if (!isConcordiaBridgeReputationContext(data.context)) return false;
    if (!requestedMetricSet) return Object.keys(data.metrics).length > 0;
    return Array.from(requestedMetricSet).some(
      (metric) => data.metrics[metric] !== undefined
    );
  });

  if (
    bridgeMetricAttestations.length === 0 &&
    options.includeEmptyBridgeContext !== true
  ) {
    return undefined;
  }

  let policyRatedBridgeCount = 0;
  let legacyBridgeCount = 0;
  let unverifiedPolicyClaimCount = 0;
  for (const attestation of bridgeMetricAttestations) {
    const status =
      await options.reputationStore.classifyBridgeMetricEvidence(attestation);
    if (status === "policy_rated") {
      policyRatedBridgeCount++;
    } else if (status === "legacy_unbounded_metrics") {
      legacyBridgeCount++;
    } else if (status === "unverified_policy_claim") {
      unverifiedPolicyClaimCount++;
    }
  }

  const unsafeBridgeCount = legacyBridgeCount + unverifiedPolicyClaimCount;
  return {
    policy: BRIDGE_METRIC_POLICY,
    status:
      bridgeMetricAttestations.length === 0
        ? "no_bridge_metric_evidence"
        : policyRatedBridgeCount > 0 && unsafeBridgeCount === 0
          ? "policy_rated"
          : policyRatedBridgeCount > 0 && legacyBridgeCount > 0
            ? "mixed_policy_and_legacy"
            : policyRatedBridgeCount > 0 && unverifiedPolicyClaimCount > 0
              ? "mixed_policy_and_unverified"
              : unverifiedPolicyClaimCount > 0
                ? "unverified_policy_claims"
                : "legacy_unbounded_metrics",
    policy_rated_attestations: policyRatedBridgeCount,
    legacy_unbounded_attestations: legacyBridgeCount,
    unverified_policy_claim_attestations: unverifiedPolicyClaimCount,
    note:
      unsafeBridgeCount > 0
        ? "Legacy or unverified bridge metric claims are excluded from aggregate metric calculations and are not privacy-rated policy evidence."
        : "Only bridge metrics carrying the current metric_policy and matching local bridge commitment provenance are privacy-rated policy evidence.",
  };
}

export function createReputationTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identityManager: IdentityManager,
  auditLog: AuditLog,
  handshakeResults?: ReadonlyMap<string, HandshakeResult>,
  verascoreUrl?: string,
  config?: SanctuaryConfig,
  /**
   * Test-only override for ReputationStore's record()-chokepoint growth
   * bounds (LD3 gate fix-round DEFECT 1). Production call sites never set
   * this — see ReputationStoreTestOverrides's doc (reputation-store.ts).
   */
  reputationStoreTestOverrides?: ReputationStoreTestOverrides
): { tools: ToolDefinition[]; reputationStore: ReputationStore } {
  const reputationStore = new ReputationStore(
    storage,
    masterKey,
    reputationStoreTestOverrides
  );
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  // Default to empty map if no handshake results provided
  const hsResults = handshakeResults ?? new Map<string, HandshakeResult>();

  const tools: ToolDefinition[] = [
    // ─── Reputation Recording ─────────────────────────────────────────

    {
      name: "reputation_record",
      description:
        "Record an interaction outcome as a signed attestation. " +
        "Creates an EAS-compatible attestation signed by the specified identity.",
      inputSchema: {
        type: "object",
        properties: {
          interaction_id: {
            type: "string",
            description: "Unique interaction identifier",
          },
          counterparty_did: {
            type: "string",
            description: "Counterparty's DID",
          },
          outcome: {
            type: "object",
            description: "Interaction outcome",
            properties: {
              type: {
                type: "string",
                enum: ["transaction", "negotiation", "service", "dispute", "custom"],
              },
              result: {
                type: "string",
                enum: ["completed", "partial", "failed", "disputed"],
              },
              metrics: {
                type: "object",
                description: "Domain-specific metrics (e.g., fulfillment_rate, response_time_ms)",
              },
            },
            required: ["type", "result"],
          },
          context: {
            type: "string",
            description: "Category/domain for context-specific reputation",
            default: "general",
          },
          counterparty_attestation: {
            type: "string",
            description:
              "Optional raw counterparty attestation attachment. " +
              "Presence alone is not treated as verified confirmation.",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign with (uses default if omitted)",
          },
        },
        required: ["interaction_id", "counterparty_did", "outcome"],
      },
      handler: async (args, callerIdentity) => {
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();

        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        const outcome = args.outcome as InteractionOutcome;
        const context = (args.context as string) ?? "general";
        if (isConcordiaBridgeReputationContext(context)) {
          return toolResult({
            error:
              "Concordia bridge reputation must be recorded with bridge_attest " +
              "so metric buckets are derived from a verified bridge commitment.",
          });
        }

        const counterpartyDid = args.counterparty_did as string;
        // The weight reflects who makes the claim, not who it is about, so an
        // untrusted caller cannot borrow a verified counterparty's credibility.
        // REP-01: the signer (identity.did) is a LOCAL identity, so its
        // credibility cannot come from this instance's own handshake map (a match
        // there is a self-vouch). Cap it at self-attested. Passing exactly the
        // signer DID is race-free vs a snapshot of identityManager.list() (no
        // rotation window). The storage chokepoint (trustedSovereigntyTier,
        // A11 — now an UNCONDITIONAL clamp) enforces the same cap at scoring
        // for every record regardless of caller, closing the residual this
        // record-time cap alone could not: a pre-fix laundered record, or a
        // direct ReputationStore.record() caller that bypasses this tool.
        // requireLocalDidEncodings (not bare identity.did) so BOTH DID
        // encodings this identity's key could be persisted under are capped
        // — see resolveTierByDid's doc. The "require" (hard-fail) form, not
        // the soft localDidEncodings, because `identity` is a HELD identity:
        // a decode failure on our own key material is an integrity error and
        // must refuse the record, never silently produce an empty cap set
        // (register §Z RECHECK MUST-FIX-1).
        const tierMeta = resolveTierByDid(
          identity.did,
          hsResults,
          true,
          new Set(requireLocalDidEncodings(identity.public_key))
        );

        // LD6 BP-DEADLINE-03 (V2-2/V2-5): the success audit is threaded in
        // as an `InLockAuditEmit` closure and runs INSIDE record()'s
        // admission lock (either right after the write, or as the
        // reconcile step on an already-committed retry -- see
        // ReputationInLockAuditEmit's doc). Captures ONLY `auditLog` +
        // primitive locals -- never `reputationStore` -- so re-entry into any
        // store's admission lock from inside it does not happen HERE, by
        // CONVENTION, not by a type-system guarantee -- see
        // ReputationInLockAuditEmit's doc for why the callback type cannot
        // enforce this on its own (V2-5 gap-5).
        //
        // Reconcile-audit fidelity (fix-round, closes a three-way
        // divergence): every field below reads from `projection`, NEVER
        // from the outer `outcome`/`tierMeta` closure captures. On the
        // reconcile branch (an already-committed retry), `projection`
        // carries the EXISTING stored attestation's own outcome/tier --
        // the same values the caller-visible `already_committed` result
        // returns and the durable record holds. A same-tuple retry with a
        // DIFFERENT incoming outcome must still audit the STORED truth, or
        // caller-result / durable-write / audit-entry disagree, which is
        // the exact divergence class this admission-completion fix exists
        // to close.
        const emitAudit: ReputationInLockAuditEmit = async (projection) => {
          // F4 (fix-round-2, tag-based dedupe): a reconcile re-emission is
          // TAGGED rather than deduped by an in-lock audit-log read -- see
          // ReputationRecordAuditProjection's `reconcile` doc.
          await auditLog.appendCritical({
            layer: "l4",
            operation: "reputation_record",
            identity_id: identity.identity_id,
            result: "success",
            details: {
              attestation_id: projection.attestation_id,
              interaction_id: projection.interaction_id,
              outcome_type: projection.outcome_type,
              outcome_result: projection.outcome_result,
              context: projection.context,
              sovereignty_tier: projection.sovereignty_tier,
              ...(projection.reconcile ? { reconcile: true } : {}),
            },
          });
        };

        let stored;
        let alreadyCommitted = false;
        try {
          stored = await reputationStore.record(
            args.interaction_id as string,
            counterpartyDid,
            outcome,
            context,
            identity,
            identityEncryptionKey,
            args.counterparty_attestation as string | undefined,
            tierMeta.sovereignty_tier,
            // LD3 gate fix-round DEFECT 1: `reputation_record` is Tier-2
            // (anomaly-gated auto-allow), so it is the general-purpose,
            // freely-callable path into `_reputation` — the pre-fix version
            // called record() with no origin at all, so this tool's writes
            // were exempt from every quota bridge_attest enforced on
            // itself. Threading the SERVER-SET `callerIdentity` here is
            // what puts this tool's growth under record()'s own
            // MAX_REPUTATION_RECORDS / MAX_REPUTATION_RECORDS_PER_ORIGIN
            // chokepoint bound (reputation-store.ts) — never `identity_id`,
            // which is Tier-3 `identity_create`-mintable and would let a
            // caller reset its quota by minting a fresh identity per call.
            callerIdentity,
            undefined, // additionalQuotaCheck: reputation_record has none of its own
            emitAudit
          );
        } catch (err) {
          if (err instanceof BridgeAttestationMetricValidationError) {
            return toolResult({ error: err.message });
          }
          // LD6 BP-DEADLINE-03 (Erik-ratified caller-semantic change): a
          // repeated (interaction_id, participant_did, counterparty_did,
          // context) tuple is now an idempotent retry -- mirrors
          // bridge_attest's existing `already_attested` shape -- rather than
          // minting a second attestation. The structural existence guard
          // inside record() rejects with this error; return the EXISTING
          // record instead of treating it as a failure.
          if (err instanceof ReputationAlreadyRecordedError) {
            stored = err.existing;
            alreadyCommitted = true;
          } else if (err instanceof ReputationIdOccupiedUnverifiedError) {
            void auditLog.append(
              "l4",
              "reputation_record_id_occupied_unverified",
              identity.identity_id,
              {
                interaction_id: args.interaction_id,
                context,
                caller_identity: callerIdentity,
              },
              "failure"
            );
            return toolResult({ error: err.message });
          } else if (err instanceof ReputationStoreQuotaError) {
            // `admission_busy` (LD3 gate fix-round-2, MUST-FIX 3) is
            // distinct from `scan_unavailable`: this call never even
            // reached the quota scan, refused instead at the store's
            // admission-waiter cap — see runAdmissionExclusiveBounded's doc
            // (reputation-store.ts).
            void auditLog.append(
              "l4",
              err.reason === "origin_quota"
                ? "reputation_record_origin_quota_exceeded"
                : err.reason === "capacity"
                  ? "reputation_record_store_saturated"
                  : err.reason === "admission_busy"
                    ? "reputation_record_admission_busy"
                    : "reputation_record_quota_scan_unavailable",
              identity.identity_id,
              {
                interaction_id: args.interaction_id,
                context,
                caller_identity: callerIdentity,
              },
              "failure"
            );
            return toolResult({ error: err.message });
          } else if (err instanceof InterruptedExitImportPendingError) {
            // N4 (coordinator gate, 2026-08-22): reputationStore.record
            // refuses while an exit-import journal exists (reputation-store.ts).
            void auditLog.append(
              "l4",
              "reputation_record_refused_pending_exit_import_recovery",
              identity.identity_id,
              { interaction_id: args.interaction_id, context },
              "failure"
            );
            return toolResult({
              error: "exit_import_pending_recovery",
              message: err.message,
            });
          } else {
            throw err;
          }
        }

        // LD6 BP-DEADLINE-03: the success audit for a NEW record (or the
        // reconciled audit for an already-committed one) is already emitted
        // INSIDE record()'s admission lock via `emitAudit` above -- no
        // second, out-of-lock append here.
        return toolResult({
          attestation_id: stored.attestation.attestation_id,
          interaction_id: stored.attestation.data.interaction_id,
          self_attestation: stored.attestation.signature,
          sovereignty_tier: stored.attestation.data.sovereignty_tier,
          context,
          recorded_at: stored.recorded_at,
          // LD6 BP-DEADLINE-03 (Erik decision 3): a caller that retries the
          // identical (interaction_id, participant_did, counterparty_did,
          // context) tuple is told this was already recorded, rather than
          // getting a second record -- the retry-safe result shape a
          // timed-out caller relies on.
          already_committed: alreadyCommitted,
        });
      },
    },

    // ─── Reputation Query ─────────────────────────────────────────────

    {
      name: "reputation_query",
      description:
        "Query aggregated reputation data with filtering. " +
        "Returns summary statistics, never raw interaction details.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "string",
            description: "Filter by context/domain",
          },
          time_range: {
            type: "object",
            description: "Filter by time range",
            properties: {
              start: { type: "string", description: "ISO 8601 start" },
              end: { type: "string", description: "ISO 8601 end" },
            },
          },
          metrics: {
            type: "array",
            items: { type: "string" },
            description: "Which metrics to aggregate",
          },
          counterparty_did: {
            type: "string",
            description: "Filter by counterparty",
          },
        },
      },
      handler: async (args) => {
        const context = args.context as string | undefined;
        const timeRange = args.time_range as
          | { start: string; end: string }
          | undefined;
        const metrics = args.metrics as string[] | undefined;
        const counterpartyDid = args.counterparty_did as string | undefined;
        const summary = await reputationStore.query({
          context,
          time_range: timeRange,
          metrics,
          counterparty_did: counterpartyDid,
        });
        const scopedAttestations = filterAttestationsByTimeRange(
          await reputationStore.loadAllForTierScoring({
            context,
            counterparty_did: counterpartyDid,
          }),
          timeRange
        );
        const bridgeMetricPolicy = await bridgeMetricPolicyDisclosure({
          reputationStore,
          attestations: scopedAttestations,
          requestedMetrics: metrics,
          includeEmptyBridgeContext: context === "concordia-bridge",
        });

        void auditLog.append("l4", "reputation_query", "system", {
          total_interactions: summary.total_interactions,
          contexts: summary.contexts,
        });

        return toolResult({
          summary,
          ...(bridgeMetricPolicy
            ? { bridge_metric_policy: bridgeMetricPolicy }
            : {}),
          // SEC-ADD-03: Tag response as containing counterparty-generated attestation data
          _content_trust: "external",
        });
      },
    },

    // ─── Reputation Export ─────────────────────────────────────────────

    {
      name: "reputation_export",
      description:
        "Export a portable reputation bundle (SANCTUARY_REP_V1). " +
        "Includes signed attestations plus a signed completeness manifest for the exported set. " +
        "On reputation_import, the manifest verifies that the bundle body still matches the export scope and rejects dropped or changed attestations within that scope. " +
        "It does not prove the export is the agent's complete lifetime history or that data outside the chosen export scope should have been included.",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["SANCTUARY_REP_V1"],
            default: "SANCTUARY_REP_V1",
          },
          context: {
            type: "string",
            description: "Export specific context only",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the bundle with",
          },
        },
      },
      handler: async (args) => {
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();

        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        const context = args.context as string | undefined;
        const bundle = await reputationStore.exportBundle(
          identity,
          identityEncryptionKey,
          context
        );

        const bundleJson = JSON.stringify(bundle);
        const bundleBase64 = toBase64url(
          new TextEncoder().encode(bundleJson)
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "reputation_export",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            attestation_count: bundle.attestations.length,
            contexts: Array.from(
              new Set(bundle.attestations.map((a) => a.data.context))
            ),
          },
        });

        const { hashToString } = await import("../core/hashing.js");
        const { stringToBytes } = await import("../core/encoding.js");

        return toolResult({
          bundle: bundleBase64,
          attestation_count: bundle.attestations.length,
          contexts: Array.from(
            new Set(bundle.attestations.map((a) => a.data.context))
          ),
          bundle_hash: hashToString(stringToBytes(bundleJson)),
          completeness_manifest: bundle.completeness_manifest,
          exported_at: bundle.exported_at,
        });
      },
    },

    // ─── Reputation Import ────────────────────────────────────────────

    {
      name: "reputation_import",
      description:
        "Import a reputation bundle from another Sanctuary instance. " +
        "By default, import requires a signed completeness manifest, recomputes it before any write, and verifies all attestation signatures. " +
        "Manifest, count, checksum, signature, or newer-schema mismatches are rejected without crediting any attestations. " +
        "The verification proves the bundle body still matches the export scope; it does not prove a complete lifetime history. " +
        "Manifestless legacy bundles are rejected unless allow_unverified_legacy is true, and that import result is flagged unverified-completeness-legacy-bundle. " +
        "Policy-rated concordia-bridge attestations also require matching local bridge commitments; untagged legacy bridge metrics are rejected.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: {
            type: "string",
            description: "Base64url-encoded reputation bundle",
          },
          allow_unverified_legacy: {
            type: "boolean",
            default: false,
            description:
              "Explicitly import a manifestless legacy reputation bundle without completeness guarantees. Default false rejects bundles that predate signed completeness verification.",
          },
        },
        required: ["bundle"],
      },
      handler: async (args, callerIdentity) => {
        const bundleBase64 = args.bundle as string;
        // Signature verification is always enforced; no caller override.
        // Allowing callers to skip verification was a prompt-injection footgun.
        const verifySignatures = true;

        let bundle;
        try {
          const bundleBytes = fromBase64url(bundleBase64);
          const bundleJson = new TextDecoder().decode(bundleBytes);
          bundle = JSON.parse(bundleJson);
        } catch {
          return toolResult({
            error: "Invalid bundle format. Expected base64url-encoded JSON.",
          });
        }

        // Build public key map from known identities for verification
        const publicKeys = new Map<string, Uint8Array>();
        for (const pub of identityManager.list()) {
          const identity = identityManager.get(pub.identity_id);
          if (identity) {
            publicKeys.set(identity.did, fromBase64url(identity.public_key));
          }
        }

        let result;
        try {
          // `callerIdentity` (LD3 gate fix-round-2, MUST-FIX 1): the
          // SERVER-SET agent-session principal that performed THIS import
          // call, threaded through as importBundle's quota-key origin — the
          // same shape record() already uses (see ReputationStore.resolveOrigin's
          // doc, reputation-store.ts). `reputation_import` is Tier-1
          // (human-approved), but an approved import that omitted an origin
          // would still pool into REPUTATION_UNKNOWN_ORIGIN correctly rather
          // than bypassing the quota — this is not the security-critical
          // half of the fix (importBundle enforces the cap regardless of
          // what origin resolves to), it is attribution so repeated imports
          // by the SAME session share one per-origin bucket rather than each
          // falling into the shared unknown bucket.
          result = await reputationStore.importBundle(
            bundle,
            verifySignatures,
            publicKeys,
            { allowUnverifiedLegacy: args.allow_unverified_legacy === true },
            callerIdentity
          );
        } catch (err) {
          // ITEM-5 (coordinator gate, 2026-08-22): same named-error branch
          // as state_write/state_delete/state_import/reputation_record -
          // ReputationStore.importBundle refuses while an exit-import
          // journal exists (N4).
          if (err instanceof InterruptedExitImportPendingError) {
            await auditLog.appendCritical({
              layer: "l4",
              operation: "reputation_import_refused_pending_exit_import_recovery",
              identity_id: "system",
              result: "failure",
              details: {},
            });
            return toolResult({
              error: "exit_import_pending_recovery",
              message: err.message,
              imported_attestations: 0,
              invalid_attestations: 0,
              contexts: [],
              completeness_verification: "failed",
              imported_at: new Date().toISOString(),
            });
          }
          const invalid =
            err instanceof ReputationBundleVerificationError
              ? err.invalidAttestations
              : 0;
          const message =
            err instanceof Error
              ? err.message
              : "Reputation bundle verification failed";
          // ReputationStoreQuotaError (LD3 gate fix-round-2, MUST-FIX 1):
          // importBundle now enforces MAX_REPUTATION_RECORDS(_PER_ORIGIN)
          // for the WHOLE bundle atomically — a refusal here means NOTHING
          // was imported (all-or-nothing; see importBundle's doc,
          // reputation-store.ts). Recorded in the audit details so an
          // operator can tell a quota refusal apart from a signature/
          // completeness failure, both of which land in this same catch.
          const quotaRefuseReason =
            err instanceof ReputationStoreQuotaError ? err.reason : undefined;

          await auditLog.appendCritical({
            layer: "l4",
            operation: "reputation_import",
            identity_id: "system",
            result: "failure",
            details: {
              imported: 0,
              invalid,
              contexts: [],
              completeness_verification: "failed",
              ...(quotaRefuseReason !== undefined
                ? { quota_refuse_reason: quotaRefuseReason }
                : {}),
            },
          });

          return toolResult({
            error: message,
            imported_attestations: 0,
            invalid_attestations: invalid,
            contexts: [],
            completeness_verification: "failed",
            imported_at: new Date().toISOString(),
          });
        }

        await auditLog.appendCritical({
          layer: "l4",
          operation: "reputation_import",
          identity_id: "system",
          result: result.invalid > 0 ? "failure" : "success",
          details: {
            imported: result.imported,
            invalid: result.invalid,
            contexts: result.contexts,
            completeness_verification: result.completeness_verification,
          },
        });

        return toolResult({
          imported_attestations: result.imported,
          invalid_attestations: result.invalid,
          contexts: result.contexts,
          completeness_verification: result.completeness_verification,
          imported_at: new Date().toISOString(),
        });
      },
    },

    // ─── Sovereignty-Weighted Query ──────────────────────────────────

    {
      name: "reputation_query_weighted",
      description:
        "Query reputation with sovereignty-weighted scoring. " +
        "Every attestation this instance stores or imports is scored at " +
        "self-attested (0.5) or unverified (0.2) weight; verified-sovereign " +
        "(1.0) and verified-degraded (0.8) are not currently reachable " +
        "through recorded or imported attestations. " +
        "Returns both the weighted score and tier distribution.",
      inputSchema: {
        type: "object",
        properties: {
          metric: {
            type: "string",
            description: "Which metric to compute the weighted score for",
          },
          context: {
            type: "string",
            description: "Filter by context/domain",
          },
          counterparty_did: {
            type: "string",
            description: "Filter by counterparty",
          },
        },
        required: ["metric"],
      },
      handler: async (args) => {
        const metric = args.metric as string;
        const summary = await reputationStore.query({
          context: args.context as string | undefined,
          counterparty_did: args.counterparty_did as string | undefined,
          metrics: [metric],
        });

        // Get the raw attestations for tier-aware scoring
        // We use the internal loadAllForTierScoring method
        const allAttestations = await reputationStore.loadAllForTierScoring({
          context: args.context as string | undefined,
          counterparty_did: args.counterparty_did as string | undefined,
        });

        // Build tiered attestations for scoring
        const scoringAttestations =
          await reputationStore.redactUnsafeBridgeMetrics(allAttestations);
        const tieredAttestations: TieredAttestation[] = scoringAttestations
          .filter((a) => a.attestation.data.metrics[metric] !== undefined)
          .map((a) => ({
            value: a.attestation.data.metrics[metric]!,
            // Trust-clamped tier: an imported attestation cannot claim a
            // privileged (verified-*) tier this instance never witnessed, so a
            // forged import cannot inflate its own scoring weight.
            tier: (trustedSovereigntyTier(a) ?? "unverified") as SovereigntyTier,
          }));

        const weightedScore = computeWeightedScore(tieredAttestations) ?? 0;

        // Compute tier distribution over the same trust-clamped tiers.
        const tiers = allAttestations.map(
          (a) => (trustedSovereigntyTier(a) ?? "unverified") as SovereigntyTier
        );
        const dist = tierDistribution(tiers);
        const bridgeMetricPolicy = await bridgeMetricPolicyDisclosure({
          reputationStore,
          attestations: allAttestations,
          requestedMetrics: [metric],
          includeEmptyBridgeContext: args.context === "concordia-bridge",
        });

        void auditLog.append("l4", "reputation_query_weighted", "system", {
          metric,
          attestation_count: tieredAttestations.length,
          weighted_score: weightedScore,
        });

        return toolResult({
          metric,
          weighted_score: weightedScore,
          attestation_count: tieredAttestations.length,
          tier_distribution: dist,
          tier_weights: TIER_WEIGHTS,
          unweighted_summary: summary,
          ...(bridgeMetricPolicy ? { bridge_metric_policy: bridgeMetricPolicy } : {}),
        });
      },
    },

    // ─── Trust Bootstrap: Escrow ──────────────────────────────────────

    {
      name: "bootstrap_create_escrow",
      description:
        "Create an escrow record for trust bootstrapping. " +
        "Allows new participants with no reputation to transact safely.",
      inputSchema: {
        type: "object",
        properties: {
          transaction_terms: {
            type: "string",
            description: "Description of the transaction",
          },
          collateral_amount: {
            type: "number",
            description: "Optional stake/collateral amount",
          },
          counterparty_did: {
            type: "string",
            description: "Counterparty's DID",
          },
          timeout_seconds: {
            type: "number",
            description: "Escrow timeout in seconds",
          },
          identity_id: {
            type: "string",
            description: "Identity creating the escrow",
          },
        },
        required: ["transaction_terms", "counterparty_did", "timeout_seconds"],
      },
      handler: async (args) => {
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();

        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        const escrow = await reputationStore.createEscrow(
          args.transaction_terms as string,
          args.counterparty_did as string,
          args.timeout_seconds as number,
          identity.did,
          args.collateral_amount as number | undefined
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "bootstrap_create_escrow",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            escrow_id: escrow.escrow_id,
            counterparty_did: args.counterparty_did,
            timeout_seconds: args.timeout_seconds,
          },
        });

        return toolResult({
          escrow_id: escrow.escrow_id,
          terms_hash: escrow.terms_hash,
          created_at: escrow.created_at,
          expires_at: escrow.expires_at,
          status: escrow.status,
        });
      },
    },

    // ─── Trust Bootstrap: Guarantee ───────────────────────────────────

    {
      name: "bootstrap_provide_guarantee",
      description:
        "A principal provides a signed reputation guarantee for a new agent. " +
        "The guarantee certificate can be presented to counterparties.",
      inputSchema: {
        type: "object",
        properties: {
          principal_identity_id: {
            type: "string",
            description: "Identity of the guarantor (principal)",
          },
          agent_identity_id: {
            type: "string",
            description: "Identity of the agent being guaranteed",
          },
          scope: {
            type: "string",
            description: "What the guarantee covers",
          },
          duration_seconds: {
            type: "number",
            description: "How long the guarantee is valid",
          },
          max_liability: {
            type: "number",
            description: "Maximum liability amount",
          },
        },
        required: [
          "principal_identity_id",
          "agent_identity_id",
          "scope",
          "duration_seconds",
        ],
      },
      handler: async (args) => {
        const principalIdentity = identityManager.get(
          args.principal_identity_id as string
        );
        const agentIdentity = identityManager.get(
          args.agent_identity_id as string
        );

        if (!principalIdentity) {
          return toolResult({
            error: `Principal identity "${args.principal_identity_id}" not found.`,
          });
        }
        if (!agentIdentity) {
          return toolResult({
            error: `Agent identity "${args.agent_identity_id}" not found.`,
          });
        }

        const guarantee = await reputationStore.createGuarantee(
          principalIdentity,
          agentIdentity.did,
          args.scope as string,
          args.duration_seconds as number,
          identityEncryptionKey,
          args.max_liability as number | undefined
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "bootstrap_provide_guarantee",
          identity_id: principalIdentity.identity_id,
          result: "success",
          details: {
            guarantee_id: guarantee.guarantee_id,
            agent_did: agentIdentity.did,
            scope: args.scope,
          },
        });

        return toolResult({
          guarantee_id: guarantee.guarantee_id,
          guarantee_certificate: guarantee.certificate,
          scope: guarantee.scope,
          valid_until: guarantee.valid_until,
        });
      },
    },

    // ─── Verascore Reputation Publish ────────────────────────────────

    {
      name: "reputation_publish",
      description:
        "Publish sovereignty data to Verascore using the supplied or DID-derived agent id; " +
        "payload is Ed25519-signed; the Verascore API response determines profile " +
        "existence/acceptance.",
      inputSchema: {
        type: "object",
        properties: {
          type: {
            type: "string",
            enum: ["shr", "handshake", "sovereignty-update"],
            description:
              "Type of data to publish: 'shr' for full sovereignty health report, " +
              "'handshake' for a handshake attestation, 'sovereignty-update' for layer-level updates.",
          },
          verascore_agent_id: {
            type: "string",
            description:
              "Agent ID on Verascore. If omitted, uses the default identity's DID-derived slug.",
          },
          verascore_url: {
            type: "string",
            description:
              "Verascore API base URL. Defaults to https://verascore.ai",
          },
          data: {
            type: "object",
            description:
              "The data payload. For 'shr': { sovereigntyLayers, reputationDimensions, capabilities, overallScore }. " +
              "For 'handshake': { attestation: { id, responderId, ... } }. " +
              "For 'sovereignty-update': { layers: [{ name, label, score, status, description }] }.",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign with (uses default if omitted)",
          },
        },
        required: ["type"],
      },
      handler: async (args) => {
        const identityId = args.identity_id as string | undefined;
        const identity = identityId
          ? identityManager.get(identityId)
          : identityManager.getDefault();

        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first.",
          });
        }

        const publishType = args.type as string;
        const configuredVerascoreUrl = verascoreUrl || "https://verascore.ai";
        const veracoreUrl = (args.verascore_url as string) || configuredVerascoreUrl;

        // SEC-037: Validate verascore_url to prevent SSRF.
        // Only allow HTTPS URLs to known Verascore domains OR the configured host.
        const ALLOWED_VERASCORE_HOSTS = new Set([
          "verascore.ai",
          "www.verascore.ai",
          "api.verascore.ai",
        ]);
        // Also allow the host from the server-configured URL (supports staging/dev).
        try {
          const configuredHost = new URL(configuredVerascoreUrl).hostname;
          ALLOWED_VERASCORE_HOSTS.add(configuredHost);
        } catch {
          // Ignore: configuredVerascoreUrl may be malformed; defaults still apply.
        }
        try {
          const parsed = new URL(veracoreUrl);
          if (parsed.protocol !== "https:") {
            return toolResult({
              error: `verascore_url must use HTTPS. Got: ${parsed.protocol}`,
            });
          }
          if (!ALLOWED_VERASCORE_HOSTS.has(parsed.hostname)) {
            return toolResult({
              error: `verascore_url must point to a known Verascore domain (${[...ALLOWED_VERASCORE_HOSTS].join(", ")}). Got: ${parsed.hostname}`,
            });
          }
        } catch {
          return toolResult({
            error: `verascore_url is not a valid URL: ${veracoreUrl}`,
          });
        }

        const agentId = (args.verascore_agent_id as string) || identity.did.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();

        // Build the payload based on type
        let publishData: Record<string, unknown>;

        if (args.data) {
          publishData = args.data as Record<string, unknown>;
        } else {
          // Auto-generate from current state if no explicit data provided.
          //
          // HONESTY (seam #12): this payload is signed with the agent's real
          // key and POSTed to an external reputation surface. We therefore
          // refuse to fabricate a perfect score. The auto-generated SHR is
          // derived from the SAME evidence source `monitor_health` uses
          // (buildHealthEvidenceReport), so a layer with no observed
          // enforcement evidence publishes as "unknown" / "configured,
          // unverified" rather than "100 / active / cryptographically
          // verified". Callers who want to publish a specific (e.g. earned)
          // claim must pass it explicitly via `data`.
          switch (publishType) {
            case "shr": {
              if (!config) {
                return toolResult({
                  error:
                    "Cannot auto-generate an SHR publish payload without a live evidence source. " +
                    "Provide an explicit 'data' payload, or use shr_generate to produce a signed report.",
                });
              }

              const { buildHealthEvidenceReport } = await import("../health/evidence.js");
              const { castleWallSnapshotForHealthReport } = await import(
                "../health/castle-wall-detector.js"
              );
              // WIRED CONSUMER (AGENTS rule 4). This payload is SIGNED and
              // published to an external reputation surface, so it is the one
              // place a fabricated Castle Wall verdict would leave the machine.
              // Same evidence source as `monitor_health` and `exec_attest`; a
              // second derivation here would let the signed claim disagree with
              // the local one.
              const evidence = buildHealthEvidenceReport({
                config,
                identityCount: identityManager.list().length,
                storageBackendName: storage.constructor.name,
                castleWall: await castleWallSnapshotForHealthReport({
                  config,
                  masterKey,
                }),
              });

              const l1 = verascoreLayerFromStatus(
                evidence.layers.l1.status,
                evidence.layers.l1.evidence
              );
              const l2 = verascoreLayerFromStatus(
                evidence.layers.l2.status,
                evidence.layers.l2.evidence
              );
              const l3 = verascoreLayerFromStatus(
                evidence.layers.l3.status,
                evidence.layers.l3.evidence
              );
              const l4 = verascoreLayerFromStatus(
                evidence.layers.l4.status,
                evidence.layers.l4.evidence
              );

              const sovereigntyLayers = [
                { name: "L1", label: "Cognitive Sovereignty", ...l1 },
                { name: "L2", label: "Operational Isolation", ...l2 },
                { name: "L3", label: "Selective Disclosure", ...l3 },
                { name: "L4", label: "Verifiable Reputation", ...l4 },
              ];

              // Overall score is the mean of the evidence-derived layer scores,
              // never a hardcoded constant. A degraded/unknown layer drags it
              // down exactly as the evidence warrants.
              const overallScore = Math.round(
                sovereigntyLayers.reduce((sum, layer) => sum + layer.score, 0) /
                  sovereigntyLayers.length
              );

              publishData = {
                sovereigntyLayers,
                capabilities: [
                  "sovereignty-handshake",
                  "concordia-negotiation",
                  "audit-trail-export",
                ],
                overallScore,
                evidence_basis: "derived from live health evidence (monitor_health)",
              };
              break;
            }
            case "sovereignty-update":
            case "handshake": {
              return toolResult({
                error: `For type '${publishType}', you must provide explicit data in the 'data' field.`,
              });
            }
            default:
              return toolResult({ error: `Unknown publish type: ${publishType}` });
          }
        }

        // SEC-036: Sign the payload with the identity's actual Ed25519 key.
        // Previously used a derived key that didn't match the published public key,
        // making verification impossible. Now signs with the identity's private key
        // (same key used for SHR signing, attestations, etc.).
        const { sign: identitySign } = await import("../core/identity.js");
        const payloadBytes = new TextEncoder().encode(JSON.stringify(publishData));

        let signatureB64: string;
        try {
          const signingBytes = identitySign(
            payloadBytes,
            identity.encrypted_private_key,
            identityEncryptionKey,
          );
          signatureB64 = toBase64url(signingBytes);
        } catch (signError) {
          // SEC-036: Do NOT fall back to a placeholder signature.
          // If signing fails, the operation must fail, not silently degrade.
          return toolResult({
            error: "Failed to sign publish payload. Identity key may be corrupted.",
            details: signError instanceof Error ? signError.message : String(signError),
          });
        }

        // Build the request
        const requestBody = {
          agentId,
          signature: signatureB64,
          publicKey: identity.public_key,
          type: publishType,
          data: publishData,
        };

        // Publish to Verascore
        try {
          const response = await fetch(`${veracoreUrl}/api/publish`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody),
          });

          const result = (await response.json()) as Record<string, unknown>;

          await auditLog.appendCritical({
            layer: "l4",
            operation: "reputation_publish",
            identity_id: identity.identity_id,
            result: response.ok ? "success" : "failure",
            details: {
              type: publishType,
              verascore_agent_id: agentId,
              verascore_url: veracoreUrl,
              status: response.status,
              success: (result.success as boolean) ?? false,
            },
          });

          if (!response.ok) {
            return toolResult({
              error: `Verascore API returned ${response.status}`,
              details: result,
              verascore_url: veracoreUrl,
            });
          }

          return toolResult({
            published: true,
            type: publishType,
            verascore_agent_id: agentId,
            verascore_url: veracoreUrl,
            response: result,
            signed_by: identity.did,
          });
        } catch (fetchError) {
          const errorMessage = fetchError instanceof Error ? fetchError.message : String(fetchError);

          await auditLog.appendCritical({
            layer: "l4",
            operation: "reputation_publish",
            identity_id: identity.identity_id,
            result: "failure",
            details: {
              type: publishType,
              verascore_agent_id: agentId,
              error: errorMessage,
            },
          });

          return toolResult({
            error: `Failed to reach Verascore at ${veracoreUrl}: ${errorMessage}`,
            hint: "Ensure verascore.ai is reachable and the agent has a profile.",
          });
        }
      },
    },
  ];

  return { tools, reputationStore };
}

// ── Back-compat alias (L1-L4 rename PR-3) ───────────────────────────────
// The layer-numbered name stays exported so downstream imports keep working.
// The functional name above is canonical.
export const createL4Tools = createReputationTools;
