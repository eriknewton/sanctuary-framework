import { fixedDenial } from "../agent-native/safety-base.js";
import type { AuditLog } from "../operational/audit-log.js";
import { toolResult, type ToolDefinition } from "../router.js";
import type { MultiAgentIsolationGuard } from "./memory-isolation.js";
import {
  MAX_MEMORY_PROVENANCE_BAD_SIGNER_REASON_BYTES,
  type MemoryProvenanceBadSignerStore,
} from "./memory-provenance-bad-signers.js";

export const MEMORY_PROVENANCE_BAD_SIGNER_TOOL_OPS = Object.freeze({
  mark: "memory_provenance_mark_bad_signer",
  clear: "memory_provenance_clear_bad_signer",
} as const);

export function createMemoryProvenanceBadSignerTools(options: {
  readonly store: MemoryProvenanceBadSignerStore;
  readonly auditLog: AuditLog;
  readonly isolationGuard: MultiAgentIsolationGuard;
}): ToolDefinition[] {
  const deny = (operation: string) =>
    toolResult(fixedDenial(`audit:${operation}`, "request_review", null));
  const commonProperties = {
    signer_did: { type: "string", minLength: 5, maxLength: 256 },
    public_key_sha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
  };
  return [
    {
      name: MEMORY_PROVENANCE_BAD_SIGNER_TOOL_OPS.mark,
      description:
        "Tier-1 operator action: quarantine every foreign memory dependency on one exact " +
        "self-certified DID and raw-key SHA-256 fingerprint. This does not mark local keys.",
      tool_class: "write",
      inputSchema: {
        type: "object",
        properties: {
          ...commonProperties,
          reason: { type: "string", minLength: 1, maxLength: MAX_MEMORY_PROVENANCE_BAD_SIGNER_REASON_BYTES },
        },
        required: ["signer_did", "public_key_sha256", "reason"],
        additionalProperties: false,
      },
      handler: async (args, _caller, context) => {
        const operation = MEMORY_PROVENANCE_BAD_SIGNER_TOOL_OPS.mark;
        if (!options.isolationGuard(operation).allowed || context?.approvalAuditId === undefined) {
          return deny(operation);
        }
        try {
          const record = await options.store.mark({
            signerDid: args.signer_did as string,
            publicKeySha256: args.public_key_sha256 as string,
            reason: args.reason as string,
            approvalAuditId: context.approvalAuditId,
          }, options.auditLog);
          return toolResult({
            marked: true,
            signer_did: record.signer_did,
            public_key_sha256: record.public_key_sha256,
            marked_at: record.marked_at,
          });
        } catch {
          return deny(operation);
        }
      },
    },
    {
      name: MEMORY_PROVENANCE_BAD_SIGNER_TOOL_OPS.clear,
      description:
        "Tier-1 operator action: clear one exact foreign bad-signer mark only after a " +
        "complete bounded re-verification of every affected record.",
      tool_class: "write",
      inputSchema: {
        type: "object",
        properties: commonProperties,
        required: ["signer_did", "public_key_sha256"],
        additionalProperties: false,
      },
      handler: async (args, _caller, context) => {
        const operation = MEMORY_PROVENANCE_BAD_SIGNER_TOOL_OPS.clear;
        if (!options.isolationGuard(operation).allowed || context?.approvalAuditId === undefined) {
          return deny(operation);
        }
        try {
          const scan = await options.store.clear({
            signerDid: args.signer_did as string,
            publicKeySha256: args.public_key_sha256 as string,
            approvalAuditId: context.approvalAuditId,
          }, options.auditLog);
          return toolResult({ cleared: true, reverified: scan.affected, scanned: scan.scanned });
        } catch {
          return deny(operation);
        }
      },
    },
  ];
}
