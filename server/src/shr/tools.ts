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
import { generateSHR, type SHRGeneratorOptions } from "./generator.js";
import { verifySHR } from "./verifier.js";
import type { SignedSHR } from "./types.js";
import { transformSHRForGateway, transformSHRGeneric } from "./gateway-adapter.js";

export function createSHRTools(
  config: SanctuaryConfig,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[] } {
  const generatorOpts: SHRGeneratorOptions = {
    config,
    identityManager,
    masterKey,
  };

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

        const result = generateSHR(args.identity_id as string | undefined, {
          ...generatorOpts,
          validityMs,
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

        // Generate a fresh SHR
        const shrResult = generateSHR(args.identity_id as string | undefined, {
          ...generatorOpts,
          validityMs,
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
