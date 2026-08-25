import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
  SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
} from "../../src/sdw/grammar.js";
import {
  SDW_MEMORY_INTEGRITY_STATES,
} from "../../src/sdw/records.js";
import {
  SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID,
  SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS,
  SDW_MEMORY_PROVENANCE_MIGRATION_ID,
  SDW_MEMORY_PROVENANCE_MIGRATION_PAGE_SIZE,
} from "../../src/sdw/memory-provenance-migration.js";
import {
  NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS,
} from "../../src/principal-policy/loader.js";

const ROOT = join(import.meta.dirname, "../..");

async function productionTypeScriptFiles(): Promise<string[]> {
  const files: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile() && entry.name.endsWith(".ts")) files.push(path);
    }
  };
  await walk(join(ROOT, "src"));
  return files.sort();
}

function methodCallCount(source: string, method: string): number {
  const file = ts.createSourceFile("inventory.ts", source, ts.ScriptTarget.Latest, true);
  let count = 0;
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === method
    ) count += 1;
    ts.forEachChild(node, visit);
  };
  visit(file);
  return count;
}

function constructorCount(source: string, className: string): number {
  const file = ts.createSourceFile("inventory.ts", source, ts.ScriptTarget.Latest, true);
  let count = 0;
  const visit = (node: ts.Node): void => {
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === className) {
      count += 1;
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return count;
}

describe("Memory Integrity C3 frozen and operator-only surfaces", () => {
  it("pins exact state, record-key, migration, counter, page, audit, and Tier-1 literals", () => {
    expect(SDW_MEMORY_INTEGRITY_STATES).toEqual([
      "state_PRE_MIGRATION",
      "state_MIGRATING",
      "state_COMPLETE",
      "state_MARKER_ABSENT_POST_COMPLETE",
    ]);
    expect([
      SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
      SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
      SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
    ]).toEqual([
      "memory-provenance-migration.active-v1",
      "memory-provenance-migration.journal-v1",
      "memory-provenance-migration.completion-v1",
    ]);
    expect(SDW_MEMORY_PROVENANCE_MIGRATION_ID).toBe("MI_C_SDW_MEMORY_PROVENANCE_V1");
    expect(SDW_MEMORY_PROVENANCE_COMPLETION_COUNTER_ID).toBe("memory-provenance-v1");
    expect(SDW_MEMORY_PROVENANCE_MIGRATION_PAGE_SIZE).toBe(100);
    expect(SDW_MEMORY_PROVENANCE_MIGRATION_AUDIT_OPS).toEqual({
      migrate: "sdw_memory_provenance_migrate",
      abort: "sdw_memory_provenance_abort_migration",
      repair: "sdw_memory_provenance_repair_completion_marker",
      status: "sdw_memory_provenance_migration_status",
    });
    expect(NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS).toEqual([
      "memory_checkpoint_restore",
      "sdw_memory_provenance_migrate",
      "sdw_memory_provenance_abort_migration",
      "sdw_memory_provenance_repair_completion_marker",
      "memory_provenance_mark_bad_signer",
      "memory_provenance_clear_bad_signer",
    ]);
  });

  it("has exactly one production constructor and only operator-tool transition calls", async () => {
    const inventory: Array<{ file: string; constructors: number; migrateCalls: number }> = [];
    for (const path of await productionTypeScriptFiles()) {
      const source = await readFile(path, "utf8");
      const constructors = constructorCount(source, "SdwMemoryProvenanceMigration");
      const migrateCalls = methodCallCount(source, "migratePage");
      if (constructors > 0 || migrateCalls > 0) {
        inventory.push({ file: relative(ROOT, path), constructors, migrateCalls });
      }
    }
    expect(inventory).toEqual([
      { file: "src/cli/memory-archive.ts", constructors: 1, migrateCalls: 0 },
      { file: "src/cli/memory-file.ts", constructors: 1, migrateCalls: 0 },
      { file: "src/index.ts", constructors: 1, migrateCalls: 0 },
      { file: "src/sdw/memory-provenance-migration-tools.ts", constructors: 0, migrateCalls: 1 },
    ]);
    const restoreMethods = [
      "restoreMemoryMigrationProvenancePreimage",
      "restoreMemoryMigrationProvenanceStatusPreimage",
      "restorePriorMemoryMigrationMetadata",
      "restorePriorReplayAnchor",
    ] as const;
    for (const method of restoreMethods) {
      const callers: string[] = [];
      for (const path of await productionTypeScriptFiles()) {
        if (methodCallCount(await readFile(path, "utf8"), method) > 0) {
          callers.push(relative(ROOT, path));
        }
      }
      expect(callers, `${method} must remain migration-only`).toEqual([
        "src/sdw/memory-provenance-migration.ts",
      ]);
    }
  });

  it("does not let comments or string constants satisfy the live-call inventory", () => {
    expect(methodCallCount([
      "// migration.migratePage()",
      "const decoy = 'migration.migratePage()';",
      "const another = `migration.migratePage()`;",
    ].join("\n"), "migratePage")).toBe(0);
    expect(methodCallCount("migration.migratePage();", "migratePage")).toBe(1);
    // Dead executable code is intentionally counted: it is still a callable
    // production seam and cannot be used to hide an automatic invocation.
    expect(methodCallCount("if (false) migration.migratePage();", "migratePage")).toBe(1);
  });

  it("pins the shared locks, durable state resolver, and roadmap-exempt manifest row", async () => {
    const migration = await readFile(join(ROOT, "src/sdw/memory-provenance-migration.ts"), "utf8");
    const composition = await readFile(join(ROOT, "src/index.ts"), "utf8");
    const manifest = await readFile(join(ROOT, "reorg-surface-manifest.md"), "utf8");
    expect(migration).toContain('withExitAdmissionLock(this.storage, "memory_migration"');
    expect(migration).toContain("withSdwMemoryCorpusMutationLock(this.storage");
    expect(migration).toContain("sdwMemoryCorpusBatchLockFile()");
    expect(composition).toContain("resolveMemoryIntegrityState: () => sdwMemoryMigration.getState()");
    expect(manifest).toContain("C3 `MI_C_SDW_MEMORY_PROVENANCE_V1` migration and completion state");
    expect(manifest).toContain("C3 operator tool, audit, and admission-lock literals");
    expect(manifest).toContain("C2+C3 remain one deployment unit");
  });
});
