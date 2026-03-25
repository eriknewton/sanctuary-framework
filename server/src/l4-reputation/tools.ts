/**
 * Sanctuary MCP Server — L4 Verifiable Reputation: Tool Definitions
 *
 * MCP tool wrappers for reputation recording, querying, export/import,
 * and trust bootstrapping (escrow + principal guarantees).
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import { ReputationStore, type InteractionOutcome } from "./reputation-store.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";

export function createL4Tools(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identityManager: IdentityManager,
  auditLog: AuditLog
): { tools: ToolDefinition[]; reputationStore: ReputationStore } {
  const reputationStore = new ReputationStore(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");

  const tools: ToolDefinition[] = [
    // ─── Reputation Recording ─────────────────────────────────────────

    {
      name: "sanctuary/reputation_record",
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

        const stored = await reputationStore.record(
          args.interaction_id as string,
          args.counterparty_did as string,
          outcome,
          context,
          identity,
          identityEncryptionKey,
          args.counterparty_attestation as string | undefined
        );

        auditLog.append("l4", "reputation_record", identity.identity_id, {
          interaction_id: args.interaction_id,
          outcome_type: outcome.type,
          outcome_result: outcome.result,
          context,
        });

        return toolResult({
          attestation_id: stored.attestation.attestation_id,
          interaction_id: stored.attestation.data.interaction_id,
          self_attestation: stored.attestation.signature,
          counterparty_confirmed: stored.counterparty_confirmed,
          context,
          recorded_at: stored.recorded_at,
        });
      },
    },

    // ─── Reputation Query ─────────────────────────────────────────────

    {
      name: "sanctuary/reputation_query",
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

        auditLog.append("l4", "reputation_query", "system", {
          total_interactions: summary.total_interactions,
          contexts: summary.contexts,
        });

        return toolResult({
          summary,
        });
      },
    },

    // ─── Reputation Export ─────────────────────────────────────────────

    {
      name: "sanctuary/reputation_export",
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

        auditLog.append("l4", "reputation_export", identity.identity_id, {
          attestation_count: bundle.attestations.length,
          contexts: Array.from(
            new Set(bundle.attestations.map((a) => a.data.context))
          ),
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
      name: "sanctuary/reputation_import",
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
          verify_signatures: {
            type: "boolean",
            description: "Verify attestation signatures (default: true)",
            default: true,
          },
        },
        required: ["bundle"],
      },
      handler: async (args) => {
        const bundleBase64 = args.bundle as string;
        const verifySignatures = (args.verify_signatures as boolean) ?? true;

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

        auditLog.append("l4", "reputation_import", "system", {
          imported: result.imported,
          invalid: result.invalid,
          contexts: result.contexts,
        });

        return toolResult({
          imported_attestations: result.imported,
          invalid_attestations: result.invalid,
          contexts: result.contexts,
          imported_at: new Date().toISOString(),
        });
      },
    },

    // ─── Trust Bootstrap: Escrow ──────────────────────────────────────

    {
      name: "sanctuary/bootstrap_create_escrow",
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

        auditLog.append("l4", "bootstrap_create_escrow", identity.identity_id, {
          escrow_id: escrow.escrow_id,
          counterparty_did: args.counterparty_did,
          timeout_seconds: args.timeout_seconds,
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
      name: "sanctuary/bootstrap_provide_guarantee",
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

        auditLog.append(
          "l4",
          "bootstrap_provide_guarantee",
          principalIdentity.identity_id,
          {
            guarantee_id: guarantee.guarantee_id,
            agent_did: agentIdentity.did,
            scope: args.scope,
          }
        );

        return toolResult({
          guarantee_id: guarantee.guarantee_id,
          guarantee_certificate: guarantee.certificate,
          scope: guarantee.scope,
          valid_until: guarantee.valid_until,
        });
      },
    },
  ];

  return { tools, reputationStore };
}
