import { constants as fsConstants } from "node:fs";
import { lstat, mkdtemp, open, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemoryPassageInput,
} from "../../src/sdw/adapters/memory-backend.js";
import {
  ingestClaudeCodeMemoryDirectory,
} from "../../src/sdw/adapters/claude-code-file-adapter.js";
import { ingestCodexMemoryDirectory } from "../../src/sdw/adapters/codex-memory-file-adapter.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import {
  restoreMemoryTranscodeArchive,
  transcodeMemoryDirectory,
} from "../../src/sdw/memory-transcode.js";
import type { PersistableTaint } from "../../src/sdw/provenance.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const CLAUDE_FIXTURES = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const CODEX_FIXTURES = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/codex-memory/", import.meta.url),
);
const MASTER_KEY = new Uint8Array(32).fill(29);
const NOW = "2026-08-14T20:00:00.000Z";
const cleanupTasks: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
});

async function tempDir(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(path, { recursive: true, force: true }));
  return realpath(path);
}

async function makeAdapter(prefix: string): Promise<{
  readonly adapter: SdwMemoryBackendAdapter;
  readonly vaultRoot: string;
}> {
  const vaultRoot = await tempDir(prefix);
  return {
    vaultRoot,
    adapter: new SdwMemoryBackendAdapter({
      storage: new FilesystemStorage(vaultRoot),
      masterKey: MASTER_KEY,
      fortressId: "fortress:memory-transcode",
      ownerRef: "fleet-self",
      now: () => NOW,
    }),
  };
}

async function markdownFiles(root: string): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  for (const name of (await readdir(root)).filter((entry) => entry.endsWith(".md")).sort()) {
    files.set(name, await readFile(join(root, name)));
  }
  return files;
}

async function expectFileSetsEqual(
  actualRoot: string,
  expectedRoot: string,
): Promise<void> {
  const actual = await markdownFiles(actualRoot);
  const expected = await markdownFiles(expectedRoot);
  expect([...actual.keys()]).toEqual([...expected.keys()]);
  for (const [name, bytes] of expected) expect(actual.get(name)).toEqual(bytes);
}

async function allRawStorageText(root: string): Promise<string> {
  const chunks: Buffer[] = [];
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        chunks.push(await handle.readFile());
      } finally {
        await handle.close();
      }
    }
  }
  await walk(root);
  return Buffer.concat(chunks).toString("utf8");
}

function metadataValue(passage: MemoryPassage, key: string): string | undefined {
  return passage.metadata.find((entry) => entry.key === key)?.value;
}

function passageInput(
  passage: MemoryPassage,
  overrides: Partial<Pick<MemoryPassageInput, "text" | "metadata">> = {},
): MemoryPassageInput {
  return {
    passage_id: passage.passage_id,
    text: overrides.text ?? passage.text,
    tags: passage.tags,
    metadata: overrides.metadata ?? passage.metadata,
    created_at: passage.created_at,
  };
}

describe("manual reversible memory transcode", () => {
  it("projects Claude Code to exactly three Codex files while the encrypted archive restores exact bytes", async () => {
    const { adapter, vaultRoot } = await makeAdapter("transcode-cc-vault");
    const source = join(CLAUDE_FIXTURES, "basic");
    await ingestClaudeCodeMemoryDirectory(adapter, source, { ingestedAt: NOW });
    const parent = await tempDir("transcode-cc-output-parent");
    const projection = join(parent, "codex-projection");

    const result = await transcodeMemoryDirectory(
      adapter,
      "claude-code",
      "codex",
      projection,
      { now: () => NOW },
    );

    expect(result).toMatchObject({
      version: "SANCTUARY_MEMORY_TRANSCODE_V1",
      mode: "reversible",
      from_harness: "claude-code",
      to_harness: "codex",
      source_file_count: 3,
      projection_file_count: 3,
    });
    expect((await readdir(projection)).sort()).toEqual([
      "MEMORY.md",
      "memory_summary.md",
      "raw_memories.md",
    ]);
    const projectedIndex = await readFile(join(projection, "MEMORY.md"), "utf8");
    expect(projectedIndex).toContain("plaintext Codex-native projection");
    expect(projectedIndex).toContain(`Recovery archive_id: \`${result.archive_id}\``);
    expect(await allRawStorageText(vaultRoot)).not.toContain(
      "Prefer brief status notes with concrete next steps",
    );

    const restored = join(parent, "restored-source");
    await expect(
      restoreMemoryTranscodeArchive(adapter, result.archive_id, restored),
    ).resolves.toMatchObject({ restored: true, source_harness: "claude-code" });
    await expectFileSetsEqual(restored, source);
  });

  it("round-trips exact Codex source bytes for basic, Unicode, and empty-body fixtures", async () => {
    for (const fixture of ["basic", "unicode", "empty-body"] as const) {
      const { adapter } = await makeAdapter(`transcode-codex-${fixture}-vault`);
      const source = join(CODEX_FIXTURES, fixture);
      await ingestCodexMemoryDirectory(adapter, source, { ingestedAt: NOW });
      const parent = await tempDir(`transcode-codex-${fixture}-output-parent`);
      const result = await transcodeMemoryDirectory(
        adapter,
        "codex",
        "claude-code",
        join(parent, "claude-projection"),
        { now: () => NOW },
      );
      expect(result.projection_files.map((file) => file.path)).toEqual([
        "MEMORY.md",
        "codex-memory-index.md",
        "codex-memory-summary.md",
        "codex-raw-memories.md",
      ]);
      const projectedIndex = await readFile(join(parent, "claude-projection", "MEMORY.md"), "utf8");
      expect(projectedIndex).toContain("plaintext Claude Code-native projection");
      expect(projectedIndex).toContain(`Recovery archive_id: \`${result.archive_id}\``);
      const restored = join(parent, "restored-source");
      await restoreMemoryTranscodeArchive(adapter, result.archive_id, restored);
      await expectFileSetsEqual(restored, source);
    }
  });

  it("does not overwrite or delete a pre-existing output file and rolls back the prepared archive", async () => {
    const { adapter } = await makeAdapter("transcode-no-overwrite-vault");
    await ingestClaudeCodeMemoryDirectory(adapter, join(CLAUDE_FIXTURES, "basic"), {
      ingestedAt: NOW,
    });
    const beforeCount = await adapter.countPassages();
    const output = await tempDir("transcode-no-overwrite-output");
    await writeFile(join(output, "MEMORY.md"), "operator-owned sentinel\n", { mode: 0o600 });

    await expect(
      transcodeMemoryDirectory(adapter, "claude-code", "codex", output, { now: () => NOW }),
    ).rejects.toThrow("output directory must be empty");
    expect(await readFile(join(output, "MEMORY.md"), "utf8")).toBe("operator-owned sentinel\n");
    expect(await adapter.countPassages()).toBe(beforeCount);
  });

  it("fails before archive or output writes when the backend cursor or archive-id contract is invalid", async () => {
    const { adapter } = await makeAdapter("transcode-backend-contract-vault");
    await ingestClaudeCodeMemoryDirectory(adapter, join(CLAUDE_FIXTURES, "basic"), {
      ingestedAt: NOW,
    });
    const parent = await tempDir("transcode-backend-contract-parent");
    const stuckCursor: MemoryBackendAdapter = new Proxy(adapter, {
      get(target, property, receiver): unknown {
        if (property === "listPassages") {
          return async () => target.listPassages({});
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      transcodeMemoryDirectory(
        stuckCursor,
        "claude-code",
        "codex",
        join(parent, "stuck-cursor"),
      ),
    ).rejects.toThrow("pagination cursor did not advance");

    const invalidId: MemoryBackendAdapter = new Proxy(adapter, {
      get(target, property, receiver): unknown {
        if (property === "derivePassageId") return () => "unsupported-id";
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      transcodeMemoryDirectory(
        invalidId,
        "claude-code",
        "codex",
        join(parent, "invalid-id"),
      ),
    ).rejects.toThrow("unsupported archive id");
    await expect(lstat(join(parent, "stuck-cursor"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(parent, "invalid-id"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("removes only its completed projection and archive when manifest completion fails", async () => {
    const { adapter } = await makeAdapter("transcode-completion-failure-vault");
    await ingestClaudeCodeMemoryDirectory(adapter, join(CLAUDE_FIXTURES, "basic"), {
      ingestedAt: NOW,
    });
    const beforeCount = await adapter.countPassages();
    let puts = 0;
    const failing: MemoryBackendAdapter = new Proxy(adapter, {
      get(target, property, receiver): unknown {
        if (property === "putPassages") {
          return async (inputs: readonly MemoryPassageInput[], taint: PersistableTaint) => {
            puts += 1;
            if (puts === 2) throw new Error("injected manifest completion failure");
            return target.putPassages(inputs, taint);
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const parent = await tempDir("transcode-completion-failure-parent");
    const output = join(parent, "projection");

    await expect(
      transcodeMemoryDirectory(failing, "claude-code", "codex", output, { now: () => NOW }),
    ).rejects.toThrow("injected manifest completion failure");
    await expect(lstat(output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await adapter.countPassages()).toBe(beforeCount);
  });

  it("refuses a tampered or prepared archive before creating any restored output", async () => {
    const { adapter } = await makeAdapter("transcode-tamper-vault");
    await ingestCodexMemoryDirectory(adapter, join(CODEX_FIXTURES, "unicode"), {
      ingestedAt: NOW,
    });
    const parent = await tempDir("transcode-tamper-parent");
    const result = await transcodeMemoryDirectory(
      adapter,
      "codex",
      "claude-code",
      join(parent, "projection"),
      { now: () => NOW },
    );
    const originalManifest = (await adapter.getPassage(result.archive_id))!;
    const oversizedCountMetadata = originalManifest.metadata.map((entry) =>
      entry.key === "memory_transcode_source_file_count" ? { ...entry, value: "501" } : entry
    );
    await adapter.putPassages(
      [passageInput(originalManifest, { metadata: oversizedCountMetadata })],
      "user_content",
    );
    const oversizedCountOutput = join(parent, "oversized-count-restore");
    await expect(
      restoreMemoryTranscodeArchive(adapter, result.archive_id, oversizedCountOutput),
    ).rejects.toThrow("source file count is invalid");
    await expect(lstat(oversizedCountOutput)).rejects.toMatchObject({ code: "ENOENT" });
    await adapter.putPassages([passageInput(originalManifest)], "user_content");

    const archived = (await adapter.listPassages({ limit: 500 })).find((passage) =>
      metadataValue(passage, "memory_transcode_archive_id") === result.archive_id &&
      metadataValue(passage, "memory_transcode_kind") === "file"
    )!;
    await adapter.putPassages(
      [passageInput(archived, { text: `${archived.text}\ntampered` })],
      "user_content",
    );
    const tamperedOutput = join(parent, "tampered-restore");
    await expect(
      restoreMemoryTranscodeArchive(adapter, result.archive_id, tamperedOutput),
    ).rejects.toThrow(/size mismatch|digest mismatch/);
    await expect(lstat(tamperedOutput)).rejects.toMatchObject({ code: "ENOENT" });

    await adapter.putPassages([passageInput(archived)], "user_content");
    const manifest = (await adapter.getPassage(result.archive_id))!;
    const unboundProjectionMetadata = manifest.metadata.map((entry) =>
      entry.key === "memory_transcode_projection_set_sha256"
        ? { ...entry, value: "0".repeat(64) }
        : entry
    );
    await adapter.putPassages(
      [passageInput(manifest, { metadata: unboundProjectionMetadata })],
      "user_content",
    );
    const unboundOutput = join(parent, "unbound-restore");
    await expect(
      restoreMemoryTranscodeArchive(adapter, result.archive_id, unboundOutput),
    ).rejects.toThrow("projection binding does not match its source");
    await expect(lstat(unboundOutput)).rejects.toMatchObject({ code: "ENOENT" });

    const unboundManifest = (await adapter.getPassage(result.archive_id))!;
    const preparedMetadata = unboundManifest.metadata.map((entry) =>
      entry.key === "memory_transcode_state" ? { ...entry, value: "prepared" } : entry
    );
    await adapter.putPassages(
      [passageInput(unboundManifest, { metadata: preparedMetadata })],
      "user_content",
    );
    const preparedOutput = join(parent, "prepared-restore");
    await expect(
      restoreMemoryTranscodeArchive(adapter, result.archive_id, preparedOutput),
    ).rejects.toThrow("archive is not complete");
    await expect(lstat(preparedOutput)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
