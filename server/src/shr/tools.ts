/**
 * Sanctuary MCP Server — SHR MCP Tools
 *
 * MCP tool definitions for generating and verifying Sovereignty Health Reports.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { SanctuaryConfig } from "../config.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import {
  generateSHR,
  type SHRGeneratorOptions,
  type L4Evidence,
} from "./generator.js";
import { verifySHR } from "./verifier.js";
import type { SignedSHR } from "./types.js";
import { transformSHRForGateway, transformSHRGeneric } from "./gateway-adapter.js";
import type { ReputationStore } from "../l4-reputation/reputation-store.js";

/**
 * Gather L4 reputation evidence for the signing identity.
 *
 * Pulls attestation summary from the reputation store and checks the
 * audit log for at least one successful `reputation_publish` entry
 * attributed to the identity. Returns a plain `L4Evidence` struct
 * consumed by the SHR generator.
 */
export async function gatherL4Evidence(
  reputationStore: ReputationStore,
  auditLog: AuditLog,
  identity: { identity_id: string; did: string }
): Promise<L4Evidence> {
  const summary = await reputationStore.summarizeForSHR(identity.did);

  // Check the audit log for any successful reputation_publish call
  // attributed to this identity. We scan a generous window; successful
  // publish events are rare and keeping a high limit avoids missing the
  // signal on long-lived instances.
  const published = await auditLog.query({
    layer: "l4",
    operation_type: "reputation_publish",
    limit: 500,
  });
  const verascoreLinked = published.entries.some(
    (e) =>
      e.result === "success" &&
      e.identity_id === identity.identity_id
  );

  return {
    attestation_count: summary.attestation_count,
    tier_distribution: summary.tier_distribution,
    most_recent_attestation_at: summary.most_recent_attestation_at,
    dispute_count: summary.dispute_count,
    context_breakdown: summary.context_breakdown,
    verascore_linked: verascoreLinked,
  };
}

export function createSHRTools(
  config: SanctuaryConfig,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog,
  reputationStore?: ReputationStore
): { tools: ToolDefinition[] } {
  const generatorOpts: SHRGeneratorOptions = {
    config,
    identityManager,
    masterKey,
  };

  /**
   * Resolve the signing identity then gather L4 evidence for it.
   * Returns undefined when no identity exists (the generator will
   * surface a clear error) or when the reputation store is absent.
   */
  async function resolveL4Evidence(
    identityId: string | undefined
  ): Promise<L4Evidence | undefined> {
    if (!reputationStore) return undefined;
    const identity = identityId
      ? identityManager.get(identityId)
      : identityManager.getDefault();
    if (!identity) return undefined;
    return gatherL4Evidence(reputationStore, auditLog, identity);
  }

  const tools: ToolDefinition[] = [
    {
      name: "shr_generate",
      description:
        "Generate a signed Sovereignty Health Report (SHR) — a machine-readable, " +
        "cryptographically signed advertisement of this instance's sovereignty posture. " +
        "Present this to counterparties to prove your sovereignty capabilities.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description:
              "Identity to sign the SHR with. Defaults to primary identity.",
          },
          validity_minutes: {
            type: "number",
            description: "How long the SHR is valid (minutes). Default: 60.",
          },
        },
      },
      handler: async (args) => {
        const validityMs = args.validity_minutes
          ? (args.validity_minutes as number) * 60 * 1000
          : undefined;

        const identityId = args.identity_id as string | undefined;
        const l4Evidence = await resolveL4Evidence(identityId);

        const result = generateSHR(identityId, {
          ...generatorOpts,
          validityMs,
          l4Evidence,
        });

        if (typeof result === "string") {
          return toolResult({ error: result });
        }

        auditLog.append("l2", "shr_generate", result.body.instance_id);

        return toolResult(result);
      },
    },

    {
      name: "shr_verify",
      description:
        "Verify a counterparty's Sovereignty Health Report (SHR). " +
        "Checks signature validity, temporal validity, and assesses sovereignty level.",
      inputSchema: {
        type: "object",
        properties: {
          shr: {
            type: "object",
            description: "The signed SHR to verify (full SignedSHR object).",
          },
        },
        required: ["shr"],
      },
      handler: async (args) => {
        const shr = args.shr as unknown as SignedSHR;
        const result = verifySHR(shr);

        auditLog.append(
          "l2",
          "shr_verify",
          result.counterparty_id,
          undefined,
          result.valid ? "success" : "failure"
        );

        return toolResult(result);
      },
    },

    {
      name: "shr_gateway_export",
      description:
        "Export this instance's Sovereignty Health Report formatted for " +
        "Ping Identity's Agent Gateway or other identity providers. " +
        "Transforms the SHR into an authorization context with sovereignty scores, " +
        "capability flags, and recommended access constraints.",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["ping", "generic"],
            description:
              "Output format: 'ping' (Ping Identity Gateway format) or 'generic' (format-agnostic). Default: 'ping'.",
          },
          identity_id: {
            type: "string",
            description:
              "Identity to sign the SHR with. Defaults to primary identity.",
          },
          validity_minutes: {
            type: "number",
            description: "How long the SHR is valid (minutes). Default: 60.",
          },
        },
      },
      handler: async (args) => {
        const format = (args.format as string) || "ping";
        const validityMs = args.validity_minutes
          ? (args.validity_minutes as number) * 60 * 1000
          : undefined;

        const identityId = args.identity_id as string | undefined;
        const l4Evidence = await resolveL4Evidence(identityId);

        // Generate a fresh SHR
        const shrResult = generateSHR(identityId, {
          ...generatorOpts,
          validityMs,
          l4Evidence,
        });

        if (typeof shrResult === "string") {
          return toolResult({ error: shrResult });
        }

        // Transform for the requested format
        let context;
        if (format === "generic") {
          context = transformSHRGeneric(shrResult);
        } else {
          context = transformSHRForGateway(shrResult);
        }

        auditLog.append(
          "l2",
          "shr_gateway_export",
          shrResult.body.instance_id,
          undefined,
          "success"
        );

        return toolResult(context);
      },
    },
  ];

  return { tools };
}
