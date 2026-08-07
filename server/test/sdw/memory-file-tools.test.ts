import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import type { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolDefinition } from "../../src/router.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createSdwMemoryFileTools, memoryFileApprovalArgs } from "../../src/sdw/memory-file-tools.js";
import { createMultiAgentIsolationGuard } from "../../src/sdw/memory-isolation.js";
import { createSdwMemoryTools } from "../../src/sdw/memory-tools.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const MASTER_KEY = new Uint8Array(32).fill(13);
const NOW = "2026-08-07T18:00:00.000Z";

const cleanupTasks: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanupTasks.length > 0) {
    await cleanupTasks.pop()!();
  }
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** A writable copy of a fixture set, so a test can add a file to it. */
async function copyFixtureSet(name: string, prefix: string): Promise<string> {
  const source = join(FIXTURE_ROOT, name);
  const target = await tempDir(prefix);
  const { readdir } = await import("node:fs/promises");
  for (const filename of (await readdir(source)).filter((f) => f.endsWith(".md"))) {
    await writeFile(join(target, filename), await readFile(join(source, filename)));
  }
  return target;
}

interface AuditCall {
  readonly operation: string;
  readonly result: "success" | "failure";
  readonly details: Record<string, unknown>;
}

interface Harness {
  readonly tools: Map<string, ToolDefinition>;
  readonly auditCalls: AuditCall[];
  readonly adapter: SdwMemoryBackendAdapter;
}

async function makeTools(
  options: {
    readonly ownerIdentity?: () => string | undefined;
    readonly ownerRef?: string;
  } = {},
): Promise<Harness> {
  const storage = new FilesystemStorage(await tempDir("cc-memory-tool-vault"));
  const adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: "fortress:memory-file-tools",
    ownerRef: options.ownerRef ?? "fleet-self",
    now: () => NOW,
  });
  const auditCalls: AuditCall[] = [];
  const auditLog = {
    async appendCritical(entry: {
      readonly operation: string;
      readonly result: "success" | "failure";
      readonly details?: Record<string, unknown>;
    }): Promise<void> {
      auditCalls.push({
        operation: entry.operation,
        result: entry.result,
        details: entry.details ?? {},
      });
    },
  } as unknown as AuditLog;

  return {
    tools: new Map(
      createSdwMemoryFileTools({
        adapter,
        auditLog,
        now: () => NOW,
        ...(options.ownerIdentity !== undefined
          ? { ownerIdentity: options.ownerIdentity }
          : {}),
      }).map((tool) => [tool.name, tool]),
    ),
    auditCalls,
    adapter,
  };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("SDW memory file tools", () => {
  it("registers manual Claude Code transcode tools as write tools with honest non-sync descriptions", async () => {
    const { tools } = await makeTools();
    expect([...tools.keys()].sort()).toEqual(["memory_emit", "memory_ingest"]);
    for (const tool of tools.values()) {
      expect(tool.tool_class).toBe("write");
      expect(tool.description.toLowerCase()).toContain("does not sync");
      expect(tool.description.toLowerCase()).toContain("exposed to that vendor at inference");
    }
    // The ingest description tells an agent that a partial mirror is possible.
    expect(tools.get("memory_ingest")!.description).toContain("skipped_file_count");
  });

  it("approval projection carries command metadata AND whose memory moves, never memory file bytes", () => {
    expect(
      memoryFileApprovalArgs({
        harness: "claude-code",
        dir: "/tmp/source",
        text: "body that must not enter approval context",
      }),
    ).toEqual({ harness: "claude-code", dir: "/tmp/source" });

    // Wired form: the operator approving a plaintext dump has to be told which
    // owner scope and which calling agent it is for.
    expect(
      memoryFileApprovalArgs(
        { harness: "claude-code", dir: "/tmp/out", text: "body" },
        { ownerRef: "fleet-self", agentId: "agent-beta" },
      ),
    ).toEqual({
      harness: "claude-code",
      dir: "/tmp/out",
      owner_ref: "fleet-self",
      agent_id: "agent-beta",
    });
  });

  it("the wired approval projection names the owner scope and the calling agent", async () => {
    const { tools } = await makeTools({
      ownerIdentity: () => "agent-alpha",
      ownerRef: "fleet-self",
    });
    for (const name of ["memory_ingest", "memory_emit"]) {
      const projected = tools.get(name)!.approvalTargetArgs!({
        harness: "claude-code",
        dir: "/tmp/out",
      });
      expect(projected).toEqual({
        harness: "claude-code",
        dir: "/tmp/out",
        owner_ref: "fleet-self",
        agent_id: "agent-alpha",
      });
    }
  });

  it("ingests and emits Claude Code files through the MCP handlers without returning bodies in ingest output", async () => {
    const { tools, auditCalls } = await makeTools();
    const output = await tempDir("cc-memory-tool-output");

    const ingested = parse(
      await tools.get("memory_ingest")!.handler({
        harness: "claude-code",
        dir: join(FIXTURE_ROOT, "empty-body"),
      }),
    );
    expect(ingested.ingested).toBe(true);
    expect(ingested.complete).toBe(true);
    expect(ingested.file_count).toBe(2);
    expect(ingested.skipped_file_count).toBe(0);
    expect(JSON.stringify(ingested)).not.toContain("Frontmatter with no body");

    const emitted = parse(
      await tools.get("memory_emit")!.handler({
        harness: "claude-code",
        dir: output,
      }),
    );
    expect(emitted.emitted).toBe(true);
    expect(emitted.file_count).toBe(2);

    // The write-ahead record is an INTENT (`_started`); the record that claims
    // the operation happened is appended AFTER it happened and carries what
    // actually landed.
    expect(auditCalls.map((call) => call.operation)).toEqual([
      "memory_ingest_started",
      "memory_ingest",
      "memory_emit_started",
      "memory_emit",
    ]);
    const ingestOutcome = auditCalls.find((call) => call.operation === "memory_ingest")!;
    expect(ingestOutcome.details.committed_file_count).toBe(2);
    expect(ingestOutcome.details.skipped_file_count).toBe(0);
    expect(ingestOutcome.details.complete).toBe(true);
    expect(auditCalls.find((call) => call.operation === "memory_emit")!.details)
      .toMatchObject({ emitted_file_count: 2 });
  });

  it("reports skipped files in the result AND in the outcome audit record", async () => {
    const { tools, auditCalls } = await makeTools();
    const source = await copyFixtureSet("basic", "cc-memory-tool-skip");
    await writeFile(
      join(source, "note-with-secret.md"),
      "# Ops note\n\nThe principal policy file lives in the fortress root.\n",
    );

    const ingested = parse(
      await tools.get("memory_ingest")!.handler({ harness: "claude-code", dir: source }),
    );

    expect(ingested.ingested).toBe(true);
    expect(ingested.complete).toBe(false);
    expect(ingested.source_file_count).toBe(4);
    expect(ingested.file_count).toBe(3);
    expect(ingested.skipped_file_count).toBe(1);
    expect(ingested.skipped).toEqual([
      {
        source_path: "note-with-secret.md",
        reason: "classifier_reject",
        detail: expect.stringContaining("classifier"),
      },
    ]);

    const outcome = auditCalls.find((call) => call.operation === "memory_ingest")!;
    expect(outcome.details).toMatchObject({
      source_file_count: 4,
      committed_file_count: 3,
      skipped_file_count: 1,
      complete: false,
    });
    expect(outcome.details.skipped).toEqual([
      { source_path: "note-with-secret.md", reason: "classifier_reject" },
    ]);
  });

  it("appends NO success-labelled record when the ingest itself fails", async () => {
    const { tools, auditCalls } = await makeTools();
    const denied = parse(
      await tools.get("memory_ingest")!.handler({
        harness: "claude-code",
        dir: join(await tempDir("cc-memory-tool-empty"), "no-such-dir"),
      }),
    );
    expect(denied.denied).toBe(true);
    // The intent record may exist, but nothing claims the operation succeeded.
    expect(auditCalls.map((call) => call.operation)).not.toContain("memory_ingest");
    expect(auditCalls.at(-1)).toMatchObject({
      operation: "memory_ingest_denied",
      result: "failure",
    });
  });

  it("denies unsupported harness values without touching the adapter", async () => {
    const { tools, auditCalls } = await makeTools();
    const denied = parse(
      await tools.get("memory_ingest")!.handler({
        harness: "codex",
        dir: join(FIXTURE_ROOT, "basic"),
      }),
    );

    expect(denied.denied).toBe(true);
    expect(auditCalls).toEqual([
      {
        operation: "memory_ingest_denied",
        result: "failure",
        details: { denial_class: "invalid_args" },
      },
    ]);
  });

  it("refuses a second distinct wrapped-agent identity on both transcode handlers", async () => {
    let current: string | undefined = "agent-alpha";
    const { tools, auditCalls } = await makeTools({ ownerIdentity: () => current });
    const output = await tempDir("cc-memory-isolation-output");

    const first = parse(
      await tools.get("memory_ingest")!.handler({
        harness: "claude-code",
        dir: join(FIXTURE_ROOT, "empty-body"),
      }),
    );
    expect(first.ingested).toBe(true);

    current = "agent-beta";
    const refusedEmit = parse(
      await tools.get("memory_emit")!.handler({ harness: "claude-code", dir: output }),
    );
    expect(refusedEmit.denied).toBe(true);
    const refusedIngest = parse(
      await tools.get("memory_ingest")!.handler({
        harness: "claude-code",
        dir: join(FIXTURE_ROOT, "basic"),
      }),
    );
    expect(refusedIngest.denied).toBe(true);
    expect(
      auditCalls.filter((call) => call.details.denial_class === "owner_scope_conflict"),
    ).toHaveLength(2);

    // Fail closed means nothing was materialized for the second agent.
    const { readdir } = await import("node:fs/promises");
    expect(await readdir(output)).toEqual([]);
  });

  it("a guard shared with the read/write tools refuses an agent memory_get already refused", async () => {
    // The hole this pins: with a per-family guard, an agent refused by
    // memory_get is the FIRST caller of memory_emit and dumps the whole shared
    // corpus as plaintext. One guard instance closes it.
    const storage = new FilesystemStorage(await tempDir("cc-memory-shared-guard-vault"));
    const adapter = new SdwMemoryBackendAdapter({
      storage,
      masterKey: MASTER_KEY,
      fortressId: "fortress:memory-file-tools",
      ownerRef: "fleet-self",
      now: () => NOW,
    });
    const auditLog = {
      async appendCritical(): Promise<void> {
        // Audit content is asserted elsewhere; this test is about the refusal.
      },
    } as unknown as AuditLog;

    let current: string | undefined = "agent-alpha";
    const isolationGuard = createMultiAgentIsolationGuard(() => current);
    const readWrite = new Map(
      createSdwMemoryTools({ adapter, auditLog, isolationGuard }).map((t) => [t.name, t]),
    );
    const fileTools = new Map(
      createSdwMemoryFileTools({ adapter, auditLog, isolationGuard, now: () => NOW }).map(
        (t) => [t.name, t],
      ),
    );

    // agent-alpha touches the read surface first, pinning the shared scope.
    await readWrite.get("memory_list")!.handler({});

    current = "agent-beta";
    expect(parse(await readWrite.get("memory_list")!.handler({})).denied).toBe(true);
    const output = await tempDir("cc-memory-shared-guard-output");
    expect(
      parse(await fileTools.get("memory_emit")!.handler({ harness: "claude-code", dir: output }))
        .denied,
    ).toBe(true);
    const { readdir } = await import("node:fs/promises");
    expect(await readdir(output)).toEqual([]);
  });

  it("index.ts wires ONE guard instance into both memory tool families", async () => {
    // The behavioral test above builds the shared guard itself, so it proves the
    // mechanism works but not that production uses it. This reads the real
    // wiring: a second `createMultiAgentIsolationGuard(` call in index.ts, or a
    // factory call without the shared guard, re-opens the memory_emit hole.
    const indexSource = await readFile(
      fileURLToPath(new URL("../../src/index.ts", import.meta.url)),
      "utf8",
    );
    const guardConstructions = indexSource.match(/createMultiAgentIsolationGuard\(/g) ?? [];
    expect(guardConstructions).toHaveLength(1);

    for (const factory of ["createSdwMemoryTools", "createSdwMemoryFileTools"]) {
      const call = new RegExp(`${factory}\\(\\{[\\s\\S]*?\\n  \\}\\)`).exec(indexSource);
      expect(call, `${factory} call not found in index.ts`).not.toBeNull();
      expect(call![0], `${factory} must receive the shared isolation guard`).toContain(
        "isolationGuard: sdwMemoryIsolationGuard",
      );
    }
  });
});
