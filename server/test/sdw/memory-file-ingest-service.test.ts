import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuditLog } from "../../src/operational/audit-log.js";
import { ingestMemoryFiles } from "../../src/sdw/memory-file-ingest-service.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const SOURCE = fileURLToPath(new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url));
const OWNER = "service-test-owner";
const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

async function adapter() {
  const dir = await mkdtemp(join(tmpdir(), "memory-ingest-service-"));
  tempDirs.push(dir);
  return new TestSdwMemoryBackendAdapter({
    storage: new FilesystemStorage(dir),
    masterKey: new Uint8Array(32).fill(29),
    fortressId: "fortress:memory-ingest-service-test",
    ownerRef: OWNER,
  });
}

function request(
  memoryAdapter: Awaited<ReturnType<typeof adapter>>,
  auditLog: AuditLog,
  authorize: () => Promise<{
    readonly approvalBasis: "operator_policy_tier3";
    readonly policyTier: 3;
  } | null>,
) {
  return {
    adapter: memoryAdapter,
    auditLog,
    harness: "claude-code" as const,
    sourceDir: SOURCE,
    ownerRef: OWNER,
    allowFiles: new Set<string>(),
    authorize,
    beforeCommit: async () => {},
  };
}

describe("memory-file ingest service authorization and write ordering", () => {
  it("denies before reading an unavailable source or writing any audit intent", async () => {
    const memoryAdapter = await adapter();
    const appendCritical = vi.fn();
    const putPassages = vi.spyOn(memoryAdapter, "putPassages");
    const input = { ...request(memoryAdapter, { appendCritical } as unknown as AuditLog, async () => null),
      sourceDir: join(tmpdir(), "source-that-does-not-exist") };

    expect(await ingestMemoryFiles(input)).toBeNull();
    expect(appendCritical).not.toHaveBeenCalled();
    expect(putPassages).not.toHaveBeenCalled();
  });

  it("rejects an owner mismatch before consulting authorization", async () => {
    const memoryAdapter = await adapter();
    const authorize = vi.fn(async () => ({ approvalBasis: "operator_policy_tier3" as const, policyTier: 3 as const }));
    const input = { ...request(memoryAdapter, { appendCritical: vi.fn() } as unknown as AuditLog, authorize),
      ownerRef: "another-owner" };

    await expect(ingestMemoryFiles(input)).rejects.toThrow("owner does not match");
    expect(authorize).not.toHaveBeenCalled();
  });

  it("records intent before commit and stops with no commit if that record fails", async () => {
    const memoryAdapter = await adapter();
    const events: string[] = [];
    const putPassages = vi.spyOn(memoryAdapter, "putPassages").mockImplementation(async () => {
      events.push("commit");
      return [];
    });
    const auditLog = {
      appendCritical: vi.fn(async (entry: { operation: string }) => {
        events.push(entry.operation);
        throw new Error("audit unavailable");
      }),
    } as unknown as AuditLog;
    const input = request(memoryAdapter, auditLog, async () => ({
      approvalBasis: "operator_policy_tier3", policyTier: 3,
    }));

    await expect(ingestMemoryFiles(input)).rejects.toThrow("audit unavailable");
    expect(events).toEqual(["memory_ingest_started"]);
    expect(putPassages).not.toHaveBeenCalled();
  });

  it("aborts after intent when the required final authorization check revokes access", async () => {
    const memoryAdapter = await adapter();
    const events: string[] = [];
    const putPassages = vi.spyOn(memoryAdapter, "putPassages");
    const auditLog = {
      appendCritical: vi.fn(async (entry: { operation: string }) => {
        events.push(entry.operation);
      }),
    } as unknown as AuditLog;
    const input = {
      ...request(memoryAdapter, auditLog, async () => ({
        approvalBasis: "operator_policy_tier3" as const, policyTier: 3 as const,
      })),
      beforeCommit: async () => {
        events.push("recheck");
        throw new Error("grant revoked");
      },
    };

    await expect(ingestMemoryFiles(input)).rejects.toThrow("grant revoked");
    expect(events).toEqual(["memory_ingest_started", "recheck"]);
    expect(putPassages).not.toHaveBeenCalled();
  });
});
