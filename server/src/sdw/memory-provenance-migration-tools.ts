import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fixedDenial } from "../agent-native/safety-base.js";
import type { MultiAgentIsolationGuard } from "./memory-isolation.js";
import {
  SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS,
  type SdwMemoryMigrationProgress,
  type SdwMemoryProvenanceMigration,
} from "./memory-provenance-migration.js";

export interface SdwMemoryProvenanceMigrationToolsOptions {
  readonly migration: SdwMemoryProvenanceMigration;
  readonly auditLog: AuditLog;
  readonly isolationGuard: MultiAgentIsolationGuard;
}

function publicProgress(progress: SdwMemoryMigrationProgress): Record<string, unknown> {
  return {
    migration: "MI_C_SDW_MEMORY_PROVENANCE_V1",
    state: progress.state,
    completed: progress.completed,
    scanned: progress.scanned,
    migrated: progress.migrated,
    verified: progress.verified,
    quarantined: progress.quarantined,
    unsigned: progress.unsigned,
    cursor_present: progress.cursor !== null,
  };
}

/** Operator-only C3 state transitions plus one read-only progress surface. */
export function createSdwMemoryProvenanceMigrationTools(
  options: SdwMemoryProvenanceMigrationToolsOptions,
): ToolDefinition[] {
  const deny = (operation: string) =>
    toolResult(fixedDenial(`audit:${operation}`, "request_review", null));
  const audit = (
    operation: string,
    result: "success" | "failure",
    details: Record<string, unknown>,
  ) => options.auditLog.appendCritical({
    layer: "l1",
    operation,
    identity_id: "principal",
    result,
    details,
  });
  const run = async (
    operation: string,
    action: () => Promise<SdwMemoryMigrationProgress>,
  ) => {
    if (!(await options.isolationGuard(operation)).allowed) {
      await audit(`${operation}_denied`, "failure", { denial_class: "multi_agent_isolation" });
      return deny(operation);
    }
    try {
      const progress = await action();
      await audit(operation, "success", {
        state: progress.state,
        completed: progress.completed,
        scanned: progress.scanned,
        migrated: progress.migrated,
        verified: progress.verified,
        quarantined: progress.quarantined,
        unsigned: progress.unsigned,
      });
      return toolResult(publicProgress(progress));
    } catch (error) {
      await audit(`${operation}_failed`, "failure", {
        failure_class: error instanceof Error ? error.name : "unknown",
      });
      return deny(operation);
    }
  };

  return [
    {
      name: SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.status,
      description:
        "Report the bounded local SDW memory provenance migration state and counts. " +
        "A complete state means every currently visible local candidate verified at completion; " +
        "it does not prove latest-state freshness or recover erased history.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      handler: async () => {
        if (!(await options.isolationGuard(SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.status)).allowed) {
          return deny(SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.status);
        }
        try {
          return toolResult(publicProgress(await options.migration.status()));
        } catch {
          return deny(SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.status);
        }
      },
    },
    {
      name: SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.migrate,
      description:
        "Operator-approved bounded migration of one local SDW memory page into signed " +
        "legacy-unattested provenance. This binds only a current local observation; it does " +
        "not recover true authorship, original ingress, content truth, or safety. " +
        "Reinvoke until complete; conflicts stay quarantined.",
      tool_class: "write",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      handler: async () => run(
        SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.migrate,
        () => options.migration.migratePage(),
      ),
    },
    {
      name: SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.abort,
      description:
        "Operator-approved abandonment of a recoverable incomplete provenance migration. " +
        "Verified companions remain and the store returns to temporary pre-migration compatibility.",
      tool_class: "write",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      handler: async () => run(
        SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.abort,
        () => options.migration.abortMigration(),
      ),
    },
    {
      name: SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.repair,
      description:
        "Operator-approved repair of a missing post-completion marker. The operation restores " +
        "only the prior replay-anchor epoch after a fresh bounded full verification pass.",
      tool_class: "write",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      handler: async () => run(
        SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS.repair,
        () => options.migration.repairCompletionMarker(),
      ),
    },
  ];
}
