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
      name: "sanctuary/shr_generate",
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
      name: "sanctuary/shr_verify",
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
  ];

  return { tools };
}
