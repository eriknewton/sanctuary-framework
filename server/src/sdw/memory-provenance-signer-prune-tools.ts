import { fixedDenial } from "../agent-native/safety-base.js";
import type { AuditLog } from "../operational/audit-log.js";
import { toolResult, type ToolDefinition } from "../router.js";
import type { MultiAgentIsolationGuard } from "./memory-isolation.js";
import {
  MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
  type MemoryProvenanceSignerPruner,
} from "./memory-provenance-signer-prune.js";

export function createMemoryProvenanceSignerPruneTool(options: {
  readonly pruner: MemoryProvenanceSignerPruner;
  readonly auditLog: AuditLog;
  readonly isolationGuard: MultiAgentIsolationGuard;
}): ToolDefinition {
  return {
    name: MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
    description:
      "Tier-1 operator maintenance: reclaim only foreign memory-provenance signer " +
      "mappings proven unreachable by a complete authenticated bounded corpus scan.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
    handler: async (_args, _caller, context) => {
      if (!(await options.isolationGuard(MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION)).allowed ||
          context?.approvalAuditId === undefined) {
        return toolResult(fixedDenial(
          `audit:${MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION}`,
          "request_review",
          null,
        ));
      }
      try {
        const result = await options.pruner.prune({
          approvalAuditId: context.approvalAuditId,
        });
        return toolResult({
          pruned: true,
          deleted: result.deleted.length,
          exact_set_digest: result.exact_set_digest,
          scanned: result.scanned,
        });
      } catch {
        await options.auditLog.appendCritical({
          layer: "l1",
          operation: MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
          identity_id: "principal",
          result: "failure",
        }).catch(() => undefined);
        return toolResult(fixedDenial(
          `audit:${MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION}`,
          "request_review",
          null,
        ));
      }
    },
  };
}
