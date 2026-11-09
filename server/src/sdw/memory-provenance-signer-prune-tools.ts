import { fixedDenial } from "../agent-native/safety-base.js";
import type { AuditLog } from "../operational/audit-log.js";
import { SignerPruneError } from "../storage/signer-prune-outcome.js";
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
      const denial = async () => {
        try {
          // Both isolation and authorization refusals require their own settled evidence.
          await options.auditLog.appendCritical({
            layer: "l1",
            operation: MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION,
            identity_id: "principal",
            result: "failure",
          });
        } catch {
          // An audit failure is terminal; recursively auditing it cannot establish evidence.
          return failure("audit unavailable");
        }
        return toolResult(fixedDenial(
          `audit:${MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION}`,
          "request_review",
          null,
        ));
      };
      try {
        if (!(await options.isolationGuard(MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION)).allowed ||
            context?.approvalAuditId === undefined) {
          return await denial();
        }
      } catch {
        return await denial();
      }
      try {
        const result = await options.pruner.prune({
          approvalAuditId: context.approvalAuditId,
        });
        // Success continues only after journal, cache, completion audit and lock release.
        return toolResult({
          pruned: true,
          deleted: result.deleted.length,
          exact_set_digest: result.exact_set_digest,
          scanned: result.scanned,
        });
      } catch (error) {
        // Must match SignerPruneOutcome in storage/signer-prune-outcome.ts.
        // Continuing: proved no-commit + settled failure audit -> ordinary denial.
        // Refusing: unknown phase -> recovery; commit -> phase-specific fixed error.
        if (!(error instanceof SignerPruneError) || error.outcome.phase === "uncertain") {
          return failure("deletion state uncertain, recovery required");
        }
        const outcome = error.outcome;
        if (outcome.phase === "committed") {
          const message = outcome.cleanup !== "finished"
            ? "deletion committed, cleanup incomplete"
            : outcome.finalization !== "finished"
              ? "deletion committed, finalization unavailable"
              : outcome.completionAudit !== "settled"
                ? "deletion committed, audit unavailable"
                : "deletion committed, lock finalization unavailable";
          return failure(message, { committed: true, audited: outcome.completionAudit === "settled" });
        }
        if (outcome.completionAudit === "failed" || outcome.completionAudit === "pending") {
          return failure("audit unavailable");
        }
        if (outcome.completionAudit === "settled") {
          return failure("lock finalization unavailable", { committed: false, audited: true });
        }
        return await denial();
      }
    },
  };
}

function failure(error: string, evidence: { committed?: boolean; audited?: boolean } = {}) {
  // toolResult alone denotes success; callers must receive the MCP error bit explicitly.
  return { ...toolResult({ error, ...evidence }), isError: true };
}
