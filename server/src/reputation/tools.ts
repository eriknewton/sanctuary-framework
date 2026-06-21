/**
 * Sanctuary MCP Server — L4 Verifiable Reputation: Tool Definitions
 *
 * MCP tool wrappers for reputation recording, querying, export/import,
 * and trust bootstrapping (escrow + principal guarantees).
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import { ReputationStore, type InteractionOutcome } from "./reputation-store.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import type { SanctuaryConfig } from "../config.js";
import type { RuntimeStatus } from "../health/evidence.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
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

export function createReputationTools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identityManager: IdentityManager,
  auditLog: AuditLog,
  handshakeResults?: Map<string, HandshakeResult>,
  verascoreUrl?: string,
  config?: SanctuaryConfig
): { tools: ToolDefinition[]; reputationStore: ReputationStore } {
  const reputationStore = new ReputationStore(storage, masterKey);
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
            description: "Counterparty's signed attestation of the same interaction",
          },
          identity_id: {
            type: "string",
            description: "Identity to sign with (uses default if omitted)",
          },
        },
        required: ["interaction_id", "counterparty_did", "outcome"],
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

        const outcome = args.outcome as InteractionOutcome;
        const context = (args.context as string) ?? "general";

        // Resolve sovereignty tier for the counterparty
        const counterpartyDid = args.counterparty_did as string;
        const hasSanctuaryIdentity = identityManager.list().some(
          (id) => identityManager.get(id.identity_id)?.did === counterpartyDid
        );
        const tierMeta = resolveTierByDid(counterpartyDid, hsResults, hasSanctuaryIdentity);

        const stored = await reputationStore.record(
          args.interaction_id as string,
          counterpartyDid,
          outcome,
          context,
          identity,
          identityEncryptionKey,
          args.counterparty_attestation as string | undefined,
          tierMeta.sovereignty_tier
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "reputation_record",
          identity_id: identity.identity_id,
          result: "success",
          details: {
            interaction_id: args.interaction_id,
            outcome_type: outcome.type,
            outcome_result: outcome.result,
            context,
            sovereignty_tier: tierMeta.sovereignty_tier,
          },
        });

        return toolResult({
          attestation_id: stored.attestation.attestation_id,
          interaction_id: stored.attestation.data.interaction_id,
          self_attestation: stored.attestation.signature,
          counterparty_confirmed: stored.counterparty_confirmed,
          sovereignty_tier: tierMeta.sovereignty_tier,
          context,
          recorded_at: stored.recorded_at,
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
        const summary = await reputationStore.query({
          context: args.context as string | undefined,
          time_range: args.time_range as
            | { start: string; end: string }
            | undefined,
          metrics: args.metrics as string[] | undefined,
          counterparty_did: args.counterparty_did as string | undefined,
        });

        void auditLog.append("l4", "reputation_query", "system", {
          total_interactions: summary.total_interactions,
          contexts: summary.contexts,
        });

        return toolResult({
          summary,
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
        "Includes all signed attestations for independent verification.",
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
          exported_at: bundle.exported_at,
        });
      },
    },

    // ─── Reputation Import ────────────────────────────────────────────

    {
      name: "reputation_import",
      description:
        "Import a reputation bundle from another Sanctuary instance. " +
        "Verifies all attestation signatures by default.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: {
            type: "string",
            description: "Base64url-encoded reputation bundle",
          },
        },
        required: ["bundle"],
      },
      handler: async (args) => {
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

        const result = await reputationStore.importBundle(
          bundle,
          verifySignatures,
          publicKeys
        );

        await auditLog.appendCritical({
          layer: "l4",
          operation: "reputation_import",
          identity_id: "system",
          result: result.invalid > 0 ? "failure" : "success",
          details: {
            imported: result.imported,
            invalid: result.invalid,
            contexts: result.contexts,
          },
        });

        return toolResult({
          imported_attestations: result.imported,
          invalid_attestations: result.invalid,
          contexts: result.contexts,
          imported_at: new Date().toISOString(),
        });
      },
    },

    // ─── Sovereignty-Weighted Query ──────────────────────────────────

    {
      name: "reputation_query_weighted",
      description:
        "Query reputation with sovereignty-weighted scoring. " +
        "Attestations from verified-sovereign agents carry full weight (1.0); " +
        "unverified attestations carry reduced weight (0.2). " +
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
        const summary = await reputationStore.query({
          context: args.context as string | undefined,
          counterparty_did: args.counterparty_did as string | undefined,
        });

        // Get the raw attestations for tier-aware scoring
        // We use the internal loadAllForTierScoring method
        const allAttestations = await reputationStore.loadAllForTierScoring({
          context: args.context as string | undefined,
          counterparty_did: args.counterparty_did as string | undefined,
        });

        const metric = args.metric as string;

        // Build tiered attestations for scoring
        const tieredAttestations: TieredAttestation[] = allAttestations
          .filter((a) => a.attestation.data.metrics[metric] !== undefined)
          .map((a) => ({
            value: a.attestation.data.metrics[metric]!,
            tier: (a.attestation.data.sovereignty_tier ?? "unverified") as SovereigntyTier,
          }));

        const weightedScore = computeWeightedScore(tieredAttestations);

        // Compute tier distribution
        const tiers = allAttestations.map(
          (a) => (a.attestation.data.sovereignty_tier ?? "unverified") as SovereigntyTier
        );
        const dist = tierDistribution(tiers);

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
              const evidence = buildHealthEvidenceReport({
                config,
                identityCount: identityManager.list().length,
                storageBackendName: storage.constructor.name,
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
