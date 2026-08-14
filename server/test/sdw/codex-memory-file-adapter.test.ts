import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  CODEX_MEMORY_FILES,
  emitCodexMemoryDirectory,
  ingestCodexMemoryDirectory,
  passageIdForCodexMemoryFile,
  readCodexMemoryDirectory,
  requireCodexNoFollowFlag,
  resolveCodexMemoryDirectory,
} from "../../src/sdw/adapters/codex-memory-file-adapter.js";
import {
  emitClaudeCodeMemoryDirectory,
  ingestClaudeCodeMemoryDirectory,
  passageIdForClaudeCodeMemoryFile,
} from "../../src/sdw/adapters/claude-code-file-adapter.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { encryptedEnvelopeContains } from "../../src/sdw/write-gate.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/codex-memory/", import.meta.url),
);
const CLAUDE_FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url),
);
const MASTER_KEY = new Uint8Array(32).fill(29);
const INGESTED_AT = "2026-08-14T18:00:00.000Z";
const FIXTURE_SETS = ["basic", "unicode", "empty-body"] as const;
const cleanupTasks: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function makeAdapter(storagePath: string, ownerRef: string): SdwMemoryBackendAdapter {
  return new SdwMemoryBackendAdapter({
    storage: new FilesystemStorage(storagePath),
    masterKey: MASTER_KEY,
    fortressId: "fortress:codex-file-adapter",
    ownerRef,
    now: () => INGESTED_AT,
  });
}

async function copyFixtureSet(name: (typeof FIXTURE_SETS)[number]): Promise<string> {
  const target = await tempDir(`codex-memory-${name}`);
  for (const filename of CODEX_MEMORY_FILES) {
    await writeFile(join(target, filename), await readFile(join(FIXTURE_ROOT, name, filename)));
  }
  return target;
}

async function hashAllowlistedFiles(dir: string): Promise<string> {
  const digest = createHash("sha256");
  for (const filename of CODEX_MEMORY_FILES) {
    digest.update(`${filename}\0`, "utf8");
    digest.update(await readFile(join(dir, filename)));
    digest.update("\0", "utf8");
  }
  return digest.digest("hex");
}

async function expectAllowlistedFilesEqual(actual: string, expected: string): Promise<void> {
  expect((await readdir(actual)).sort()).toEqual([...CODEX_MEMORY_FILES].sort());
  for (const filename of CODEX_MEMORY_FILES) {
    expect(await readFile(join(actual, filename))).toEqual(await readFile(join(expected, filename)));
  }
}

describe("Codex memory-file adapter", () => {
  it("fails closed when the platform cannot enforce O_NOFOLLOW", () => {
    expect(() => requireCodexNoFollowFlag(undefined)).toThrow(
      "Codex memory ingest requires O_NOFOLLOW support",
    );
    expect(() => requireCodexNoFollowFlag(0)).toThrow(
      "Codex memory ingest requires O_NOFOLLOW support",
    );
    expect(requireCodexNoFollowFlag(0x20000)).toBe(0x20000);
  });

  it("resolves a Codex home without enumerating or opening non-memory state", async () => {
    const codexHome = await tempDir("synthetic-codex-home");
    const memories = join(codexHome, "memories");
    await mkdir(join(codexHome, "logs"), { recursive: true });
    await mkdir(memories, { recursive: true });
    for (const filename of CODEX_MEMORY_FILES) {
      await writeFile(
        join(memories, filename),
        await readFile(join(FIXTURE_ROOT, "basic", filename)),
      );
    }
    // Every file below is deliberately invalid memory input. Success plus the
    // read seam proves none of their bodies entered the adapter.
    await writeFile(join(codexHome, "state_5.sqlite"), Buffer.from([0, 255, 0, 255]));
    await writeFile(join(codexHome, "history.jsonl"), "not curated memory\n");
    await writeFile(join(codexHome, "auth.json"), "credential-shaped state\n");
    await writeFile(join(codexHome, "logs", "session.log"), "telemetry\n");
    await writeFile(join(memories, "stray.md"), "# Not allowlisted\n");
    await writeFile(join(memories, "telemetry.sqlite"), Buffer.from([255, 254, 253]));

    const opened: string[] = [];
    const snapshot = await readCodexMemoryDirectory(codexHome, {
      ingestedAt: INGESTED_AT,
      readFile: async (path) => {
        opened.push(path);
        return new Uint8Array(await readFile(path));
      },
    });

    expect(snapshot.root_dir).toBe(memories);
    expect(snapshot.entries.map((entry) => entry.source_path)).toEqual(CODEX_MEMORY_FILES);
    expect(opened.map((path) => basename(path))).toEqual(CODEX_MEMORY_FILES);
    expect(opened.every((path) => path.startsWith(`${memories}/`))).toBe(true);
  });

  it("maps the three curated files to distinct source classes and unsigned provenance", async () => {
    const snapshot = await readCodexMemoryDirectory(join(FIXTURE_ROOT, "basic"), {
      ingestedAt: INGESTED_AT,
    });

    expect(snapshot.entries.map((entry) => entry.source_class)).toEqual([
      "index",
      "summary",
      "raw",
    ]);
    for (const entry of snapshot.entries) {
      expect(entry.passage_input).not.toHaveProperty("passage_id");
      expect(entry.passage_input.tags).toEqual(
        expect.arrayContaining([
          "codex",
          "ingress:file_import",
          `source_class:${entry.source_class}`,
        ]),
      );
      expect(entry.passage_input.metadata).toEqual(
        expect.arrayContaining([
          { key: "origin_harness", value: "codex" },
          { key: "ingress", value: "file_import" },
          { key: "source_path", value: entry.source_path },
          { key: "ingested_at", value: INGESTED_AT },
        ]),
      );
    }
  });

  it("round-trips exact UTF-8 bytes across three fixture sets without touching sources", async () => {
    for (const fixture of FIXTURE_SETS) {
      const source = await copyFixtureSet(fixture);
      const before = await hashAllowlistedFiles(source);
      const adapter = makeAdapter(await tempDir(`codex-vault-${fixture}`), `codex-${fixture}`);
      const output = await tempDir(`codex-output-${fixture}`);
      const secondOutput = await tempDir(`codex-second-output-${fixture}`);

      const result = await ingestCodexMemoryDirectory(adapter, source, {
        ingestedAt: INGESTED_AT,
      });
      expect(result).toMatchObject({
        source_file_count: 3,
        complete: true,
        skipped: [],
      });
      await emitCodexMemoryDirectory(adapter, output);
      expect(await hashAllowlistedFiles(source)).toBe(before);
      expect(await hashAllowlistedFiles(output)).toBe(before);
      await expectAllowlistedFilesEqual(output, source);

      const reimport = makeAdapter(
        await tempDir(`codex-reimport-${fixture}`),
        `codex-reimport-${fixture}`,
      );
      await ingestCodexMemoryDirectory(reimport, output, { ingestedAt: INGESTED_AT });
      await emitCodexMemoryDirectory(reimport, secondOutput);
      await expectAllowlistedFilesEqual(secondOutput, source);
    }
  });

  it("uses stable opaque ids that cannot collide with Claude Code MEMORY.md", async () => {
    const storagePath = await tempDir("cross-harness-memory-vault");
    const adapter = makeAdapter(storagePath, "cross-harness");
    await ingestCodexMemoryDirectory(adapter, join(FIXTURE_ROOT, "basic"), {
      ingestedAt: INGESTED_AT,
    });
    await ingestClaudeCodeMemoryDirectory(adapter, CLAUDE_FIXTURE_ROOT, {
      ingestedAt: INGESTED_AT,
    });

    const codexId = passageIdForCodexMemoryFile(adapter, "index", "MEMORY.md");
    const claudeId = passageIdForClaudeCodeMemoryFile(adapter, "index", "MEMORY.md");
    expect(codexId).not.toBe(claudeId);
    expect(passageIdForCodexMemoryFile(adapter, "index", "MEMORY.md")).toBe(codexId);
    expect(await adapter.countPassages()).toBe(6);

    const storageEntries = await readdir(join(storagePath, SDW_DOCUMENT_CORPUS_NAMESPACE));
    for (const entry of storageEntries) {
      expect(entry.toLowerCase()).not.toContain("memory");
      expect(entry.toLowerCase()).not.toContain("summary");
      expect(entry.toLowerCase()).not.toContain("raw");
    }

    const codexOutput = await tempDir("codex-filtered-output");
    const claudeOutput = await tempDir("claude-filtered-output");
    await emitCodexMemoryDirectory(adapter, codexOutput);
    await emitClaudeCodeMemoryDirectory(adapter, claudeOutput);
    expect((await readdir(codexOutput)).sort()).toEqual([...CODEX_MEMORY_FILES].sort());
    expect((await readdir(claudeOutput)).filter((name) => name.endsWith(".md"))).toHaveLength(3);
  });

  it("reports classifier-refused allowlisted bytes and never writes them to the vault", async () => {
    const source = await copyFixtureSet("basic");
    await writeFile(
      join(source, "raw_memories.md"),
      "# Raw Memories\n\nSANCTUARY_RECOVERY_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
    );
    const storagePath = await tempDir("codex-classifier-vault");
    const adapter = makeAdapter(storagePath, "codex-classifier");
    const result = await ingestCodexMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });

    expect(result.complete).toBe(false);
    expect(result.ingested).toHaveLength(2);
    expect(result.skipped).toEqual([
      {
        source_path: "raw_memories.md",
        reason: "classifier_reject",
        detail: expect.stringContaining("classifier"),
      },
    ]);
    const corpusDir = join(storagePath, SDW_DOCUMENT_CORPUS_NAMESPACE);
    for (const filename of await readdir(corpusDir)) {
      const raw = new Uint8Array(await readFile(join(corpusDir, filename)));
      expect(encryptedEnvelopeContains(raw, "SANCTUARY_RECOVERY_KEY")).toBe(false);
    }
  });

  it("fails closed on ambiguous roots and symlinked allowlisted files", async () => {
    const ambiguous = await tempDir("ambiguous-codex-home");
    await mkdir(join(ambiguous, "memories"));
    await writeFile(join(ambiguous, "MEMORY.md"), "# Loose\n");
    await expect(resolveCodexMemoryDirectory(ambiguous)).rejects.toThrow(
      "Ambiguous Codex memory path",
    );

    const source = await copyFixtureSet("basic");
    const outside = join(await tempDir("codex-outside"), "outside.md");
    await writeFile(outside, "# Outside\n");
    await rm(join(source, "raw_memories.md"));
    await symlink(outside, join(source, "raw_memories.md"));
    await expect(readCodexMemoryDirectory(source)).rejects.toThrow(
      "not a regular file",
    );
  });

  it("refuses to overwrite an existing output and preserves the source tree", async () => {
    const source = await copyFixtureSet("basic");
    const before = await hashAllowlistedFiles(source);
    const adapter = makeAdapter(await tempDir("codex-overwrite-vault"), "codex-overwrite");
    await ingestCodexMemoryDirectory(adapter, source, { ingestedAt: INGESTED_AT });

    await expect(emitCodexMemoryDirectory(adapter, source)).rejects.toThrow(
      "Refusing to overwrite existing Codex memory file",
    );
    expect(await hashAllowlistedFiles(source)).toBe(before);
  });
});
