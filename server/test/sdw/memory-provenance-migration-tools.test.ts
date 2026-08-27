import { describe, expect, it, vi } from "vitest";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolDefinition } from "../../src/router.js";
import {
  createSdwMemoryProvenanceMigrationTools,
} from "../../src/sdw/memory-provenance-migration-tools.js";
import type {
  SdwMemoryMigrationProgress,
  SdwMemoryProvenanceMigration,
} from "../../src/sdw/memory-provenance-migration.js";

const PROGRESS: SdwMemoryMigrationProgress = {
  state: "state_MIGRATING",
  run_id: "private-run-id",
  scanned: 10,
  migrated: 6,
  verified: 3,
  quarantined: 1,
  unsigned: 2,
  cursor: "mem.fleet-self.private-cursor",
  completed: false,
};

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

function fixture(allowed = true) {
  const calls: Array<{ operation: string; result: string; details?: Record<string, unknown> }> = [];
  const migration = {
    status: vi.fn(async () => PROGRESS),
    migratePage: vi.fn(async () => PROGRESS),
    abortMigration: vi.fn(async () => ({ ...PROGRESS, state: "state_PRE_MIGRATION" })),
    repairCompletionMarker: vi.fn(async () => ({ ...PROGRESS, state: "state_COMPLETE", completed: true })),
  } as unknown as SdwMemoryProvenanceMigration;
  const auditLog = {
    appendCritical: vi.fn(async (entry: {
      operation: string;
      result: string;
      details?: Record<string, unknown>;
    }) => {
      calls.push(entry);
    }),
  } as unknown as AuditLog;
  const tools = new Map<string, ToolDefinition>(
    createSdwMemoryProvenanceMigrationTools({
      migration,
      auditLog,
      isolationGuard: () => allowed
        ? { allowed: true }
        : { allowed: false, denial: "multi_agent_isolation" },
    }).map((tool) => [tool.name, tool]),
  );
  return { tools, migration, calls };
}

describe("Memory Integrity C3 operator tools", () => {
  it("freezes the exact four surfaces and existing router classes", () => {
    const { tools } = fixture();
    expect([...tools.keys()].sort()).toEqual([
      "sdw_memory_provenance_abort_migration",
      "sdw_memory_provenance_migrate",
      "sdw_memory_provenance_migration_status",
      "sdw_memory_provenance_repair_completion_marker",
    ]);
    expect(tools.get("sdw_memory_provenance_migration_status")!.tool_class).toBe("read");
    for (const name of [
      "sdw_memory_provenance_abort_migration",
      "sdw_memory_provenance_migrate",
      "sdw_memory_provenance_repair_completion_marker",
    ]) expect(tools.get(name)!.tool_class).toBe("write");
    const migrateDescription = tools.get("sdw_memory_provenance_migrate")!.description;
    for (const bound of ["current local observation", "true authorship", "original ingress", "content truth", "safety"]) {
      expect(migrateDescription).toContain(bound);
    }
  });

  it("returns an exact bounded projection without run, cursor, signer, or fortress identity", async () => {
    const { tools } = fixture();
    const out = parse(await tools.get("sdw_memory_provenance_migration_status")!.handler({}));
    expect(out).toEqual({
      migration: "MI_C_SDW_MEMORY_PROVENANCE_V1",
      state: "state_MIGRATING",
      completed: false,
      scanned: 10,
      migrated: 6,
      verified: 3,
      quarantined: 1,
      unsigned: 2,
      cursor_present: true,
    });
    expect(JSON.stringify(out)).not.toContain("private-run-id");
    expect(JSON.stringify(out)).not.toContain("private-cursor");
  });

  it("audits each successful state transition under its frozen operation", async () => {
    const { tools, calls } = fixture();
    for (const operation of [
      "sdw_memory_provenance_migrate",
      "sdw_memory_provenance_abort_migration",
      "sdw_memory_provenance_repair_completion_marker",
    ]) {
      const out = parse(await tools.get(operation)!.handler({}));
      expect(out.migration).toBe("MI_C_SDW_MEMORY_PROVENANCE_V1");
    }
    expect(calls.map((call) => [call.operation, call.result])).toEqual([
      ["sdw_memory_provenance_migrate", "success"],
      ["sdw_memory_provenance_abort_migration", "success"],
      ["sdw_memory_provenance_repair_completion_marker", "success"],
    ]);
  });

  it("denies before mutation when the existing memory isolation guard refuses", async () => {
    const { tools, migration, calls } = fixture(false);
    const out = parse(await tools.get("sdw_memory_provenance_migrate")!.handler({}));
    expect(out.denied).toBe(true);
    expect(migration.migratePage).not.toHaveBeenCalled();
    expect(calls).toEqual([expect.objectContaining({
      operation: "sdw_memory_provenance_migrate_denied",
      result: "failure",
    })]);
  });
});
