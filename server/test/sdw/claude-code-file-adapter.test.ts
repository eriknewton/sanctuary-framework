import { createHash } from "node:crypto";
import {
  readdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
  mkdtemp,
  mkdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  CLAUDE_CODE_MEMORY_INDEX,
  emitClaudeCodeMemoryDirectory,
  ingestClaudeCodeMemoryDirectory,
  passageIdForClaudeCodeMemoryFile,
  readClaudeCodeMemoryDirectory,
} from "../../src/sdw/adapters/claude-code-file-adapter.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { encryptedEnvelopeContains } from "../../src/sdw/write-gate.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const MASTER_KEY = new Uint8Array(32).fill(12);
const INGESTED_AT = "2026-08-07T17:00:00.000Z";
const OWNER_REF = "claude-code-fixture";
const FIXTURE_SETS = ["basic", "unicode", "empty-body"] as const;

const cleanupTasks: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanupTasks.length > 0) {
    await cleanupTasks.pop()!();
  }
});

function trackTempDir(path: string): string {
  cleanupTasks.push(() => rm(path, { recursive: true, force: true }));
  return path;
}

async function tempDir(prefix: string): Promise<string> {
  return trackTempDir(await mkdtemp(join(tmpdir(), `${prefix}-`)));
}

function makeAdapter(
  storage: StorageBackend | string,
  ownerRef = OWNER_REF,
): SdwMemoryBackendAdapter {
  return new SdwMemoryBackendAdapter({
    storage: typeof storage === "string" ? new FilesystemStorage(storage) : storage,
    masterKey: MASTER_KEY,
    fortressId: "fortress:cc-file-adapter",
    ownerRef,
    now: () => INGESTED_AT,
  });
}

/**
 * Storage that fails the Nth document-corpus write. Ingest of a real memory
 * directory is a multi-passage batch, so a mid-batch failure is the case the
 * all-or-nothing contract exists for; without an injected failure the batch
 * path is only ever exercised on its happy path.
 */
class FailAfterNWritesStorage implements StorageBackend {
  private writes = 0;
  constructor(
    private readonly inner: StorageBackend,
    private readonly failOnWrite: number,
  ) {}
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.writes += 1;
    if (this.writes === this.failOnWrite) {
      throw new Error("injected storage failure");
    }
    return this.inner.write(namespace, key, data);
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(namespace, key);
  }
  async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    return this.inner.delete(namespace, key, secureOverwrite);
  }
  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }
  async exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }
  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
}

async function copyFixtureSet(name: string): Promise<string> {
  const source = join(FIXTURE_ROOT, name);
  const target = await tempDir(`cc-memory-source-${name}`);
  for (const filename of await sortedMarkdownFiles(source)) {
    const body = await readFile(join(source, filename));
    const destination = join(target, filename);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, body);
  }
  return target;
}

async function sortedMarkdownFiles(dir: string): Promise<readonly string[]> {
  const names = await readdir(dir);
  return names
    .filter((name) => name.endsWith(".md"))
    .sort((a, b) => {
      if (a === CLAUDE_CODE_MEMORY_INDEX) return -1;
      if (b === CLAUDE_CODE_MEMORY_INDEX) return 1;
      return a.localeCompare(b);
    });
}

async function hashMarkdownTree(dir: string): Promise<string> {
  const digest = createHash("sha256");
  for (const filename of await sortedMarkdownFiles(dir)) {
    const body = await readFile(join(dir, filename));
    digest.update(`${filename}\0`, "utf8");
    digest.update(body);
    digest.update("\0", "utf8");
  }
  return digest.digest("hex");
}

async function assertMarkdownTreesEqual(actual: string, expected: string): Promise<void> {
  expect(await sortedMarkdownFiles(actual)).toEqual(await sortedMarkdownFiles(expected));
  for (const filename of await sortedMarkdownFiles(expected)) {
    expect(await readFile(join(actual, filename))).toEqual(await readFile(join(expected, filename)));
  }
}

describe("Claude Code memory-file adapter", () => {
  it("maps the Claude Code index, frontmatter, sections, and descriptive provenance", async () => {
    const snapshot = await readClaudeCodeMemoryDirectory(join(FIXTURE_ROOT, "basic"), {
      ingestedAt: INGESTED_AT,
    });

    expect(snapshot.entries.map((entry) => entry.source_path)).toEqual([
      "MEMORY.md",
      "concise-updates.md",
      "rung-one-scope.md",
    ]);

    const index = snapshot.entries[0]!;
    expect(index.source_class).toBe("index");
    expect(index.passage_input.tags).toContain("source_class:index");
    expect(index.passage_input.tags).toContain("ingress:file_import");
    expect(index.passage_input.tags).toContain("ingested_at:2026-08-07t17:00:00.000z");
    expect(index.passage_input.metadata).toContainEqual({
      key: "origin_harness",
      value: "claude-code",
    });
    expect(index.passage_input.metadata).toContainEqual({
      key: "ingress",
      value: "file_import",
    });

    const concise = snapshot.entries[1]!;
    expect(concise.source_class).toBe("fact");
    // Reading a directory must NOT mint an id: the id is a fortress-keyed
    // digest, and only the backend holds the key.
    expect(concise.passage_input).not.toHaveProperty("passage_id");
    expect(concise.passage_input.tags).toEqual(
      expect.arrayContaining(["index_member", "section:operating-preferences"]),
    );
    expect(concise.passage_input.metadata).toEqual(
      expect.arrayContaining([
        { key: "source_path", value: "concise-updates.md" },
        { key: "frontmatter.name", value: "concise-updates" },
        { key: "frontmatter.metadata.originsessionid", value: "11111111-1111-4111-8111-111111111111" },
        { key: "ingested_at", value: INGESTED_AT },
      ]),
    );
  });

  it("ingests and emits byte-faithful Claude Code memory files across three fixture sets without touching sources", async () => {
    for (const fixture of FIXTURE_SETS) {
      const source = await copyFixtureSet(fixture);
      const storagePath = await tempDir(`cc-memory-vault-${fixture}`);
      const output = await tempDir(`cc-memory-output-${fixture}`);
      const reimportStorage = await tempDir(`cc-memory-reimport-vault-${fixture}`);
      const secondOutput = await tempDir(`cc-memory-reemit-${fixture}`);
      const beforeHash = await hashMarkdownTree(source);

      const adapter = makeAdapter(storagePath, `cc-${fixture}`);
      const ingest = await ingestClaudeCodeMemoryDirectory(adapter, source, {
        ingestedAt: INGESTED_AT,
      });
      expect(ingest.complete).toBe(true);
      expect(ingest.skipped).toEqual([]);
      await emitClaudeCodeMemoryDirectory(adapter, output);

      expect(await hashMarkdownTree(source)).toBe(beforeHash);
      expect(await hashMarkdownTree(output)).toBe(beforeHash);
      await assertMarkdownTreesEqual(output, source);
      // A successful emit leaves no temp files behind.
      expect((await readdir(output)).filter((name) => name.endsWith(".tmp"))).toEqual([]);

      const reimportAdapter = makeAdapter(reimportStorage, `cc-reimport-${fixture}`);
      await ingestClaudeCodeMemoryDirectory(reimportAdapter, output, { ingestedAt: INGESTED_AT });
      await emitClaudeCodeMemoryDirectory(reimportAdapter, secondOutput);

      expect(await hashMarkdownTree(secondOutput)).toBe(beforeHash);
      await assertMarkdownTreesEqual(secondOutput, source);
    }
  });

  it("roundtrips prose that names protected concepts without secret material", async () => {
    const source = await copyFixtureSet("basic");
    const prose = "# Security notes\n\nThe principal policy and recovery key are stored offline.\n";
    await writeFile(join(source, "security-notes.md"), prose);
    const storagePath = await tempDir("cc-memory-security-prose-vault");
    const output = await tempDir("cc-memory-security-prose-output");
    const adapter = makeAdapter(storagePath, "cc-security-prose");

    const ingest = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });
    expect(ingest.complete).toBe(true);
    expect(ingest.skipped).toEqual([]);

    await emitClaudeCodeMemoryDirectory(adapter, output);
    expect(await readFile(join(output, "security-notes.md"), "utf8")).toBe(prose);
  });

  it("re-ingesting a CHANGED directory into the SAME vault and owner_ref replaces the passages in place", async () => {
    // Regression pin for the "mirror works exactly once" defect. Memory files
    // change daily, so the second run is the normal case, not an edge case. The
    // vault, the owner_ref, and the adapter are deliberately reused: a test that
    // re-imports into a fresh storage path with a different owner_ref cannot
    // fail on an id that collides with its own prior run.
    const source = await copyFixtureSet("basic");
    const storagePath = await tempDir("cc-memory-reingest-vault");
    const adapter = makeAdapter(storagePath, "cc-reingest");

    const first = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });
    expect(first.ingested).toHaveLength(3);
    const firstIds = first.ingested.map((passage) => passage.passage_id).sort();

    // Edit one file the way an operator would, and add a new one.
    const changedPath = join(source, "rung-one-scope.md");
    const updatedBody = `${await readFile(changedPath, "utf8")}\n- appended on the second day\n`;
    await writeFile(changedPath, updatedBody);
    await writeFile(join(source, "new-topic.md"), "# New topic\n\nAdded later.\n");

    const second = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: "2026-08-08T17:00:00.000Z",
    });
    expect(second.complete).toBe(true);
    expect(second.ingested).toHaveLength(4);

    // The three pre-existing files kept their ids (replace, not re-insert).
    const secondIds = second.ingested.map((passage) => passage.passage_id);
    for (const id of firstIds) expect(secondIds).toContain(id);
    // Exactly four passages exist: the replaced three plus the new one.
    expect(await adapter.countPassages()).toBe(4);

    // The UPDATED bytes are what the vault now returns.
    const changedId = passageIdForClaudeCodeMemoryFile(adapter, "fact", "rung-one-scope.md");
    const stored = await adapter.getPassage(changedId);
    expect(stored?.text).toBe(updatedBody);

    // And an emit reproduces the changed tree byte for byte.
    const output = await tempDir("cc-memory-reingest-output");
    await emitClaudeCodeMemoryDirectory(adapter, output);
    await assertMarkdownTreesEqual(output, source);
  });

  it("skips and REPORTS a file the secret classifier refuses, mirrors the rest, and stays re-runnable", async () => {
    const source = await copyFixtureSet("basic");
    // The classifier refuses this labeled, material-shaped recovery key. Sorted after
    // MEMORY.md and concise-updates.md, so a whole-run abort here would leave a
    // committed prefix behind: exactly the failure this test pins.
    await writeFile(
      join(source, "note-with-secret.md"),
      "# Ops note\n\nSANCTUARY_RECOVERY_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
    );
    const storagePath = await tempDir("cc-memory-skip-vault");
    const adapter = makeAdapter(storagePath, "cc-skip");

    const result = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });

    expect(result.complete).toBe(false);
    expect(result.source_file_count).toBe(4);
    expect(result.ingested).toHaveLength(3);
    expect(result.skipped).toEqual([
      {
        source_path: "note-with-secret.md",
        reason: "classifier_reject",
        detail: expect.stringContaining("classifier"),
        detector: "labeled_recovery_key",
        line: 3,
      },
    ]);

    // The refused bytes are NOT in the vault: skipping is not exempting.
    expect(
      await adapter.getPassage(
        passageIdForClaudeCodeMemoryFile(adapter, "fact", "note-with-secret.md"),
      ),
    ).toBeNull();
    for (const raw of await readRawCorpusFiles(storagePath)) {
      expect(encryptedEnvelopeContains(raw, "SANCTUARY_RECOVERY_KEY")).toBe(false);
    }

    // The run is repeatable: the previously committed files replace cleanly
    // instead of colliding, which is what made the original partial commit
    // unrecoverable without a Tier-1 delete per passage.
    const rerun = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });
    expect(rerun.ingested).toHaveLength(3);
    expect(rerun.skipped).toHaveLength(1);
    expect(await adapter.countPassages()).toBe(3);
  });

  it("leaves the vault untouched when a write fails part way through the batch", async () => {
    const source = await copyFixtureSet("basic");
    const storagePath = await tempDir("cc-memory-atomic-vault");
    // Fail on the 4th corpus write: the first passage's chunk + document are
    // already through, so a non-atomic ingest would leave a committed prefix.
    const storage = new FailAfterNWritesStorage(new FilesystemStorage(storagePath), 4);
    const adapter = makeAdapter(storage, "cc-atomic");
    const beforeRawCorpusKeys = await rawCorpusKeys(storage);

    await expect(
      ingestClaudeCodeMemoryDirectory(adapter, source, { ingestedAt: INGESTED_AT }),
    ).rejects.toThrow("injected storage failure");

    expect(await adapter.countPassages()).toBe(0);
    expect(await adapter.listPassages()).toEqual([]);
    expect(await rawCorpusKeys(storage)).toEqual(beforeRawCorpusKeys);
  });

  it("never writes the memory topic file name into an on-disk storage key", async () => {
    // The bodies are encrypted, but the storage key becomes a directory entry
    // name. Deriving the passage id from the file name would publish the
    // operator's memory topics as a cleartext index next to the ciphertext.
    const source = await copyFixtureSet("basic");
    const storagePath = await tempDir("cc-memory-opacity-vault");
    const adapter = makeAdapter(storagePath, "cc-opacity");
    await ingestClaudeCodeMemoryDirectory(adapter, source, { ingestedAt: INGESTED_AT });

    const entries = await readdir(join(storagePath, SDW_DOCUMENT_CORPUS_NAMESPACE));
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(entry).not.toContain("concise-updates");
      expect(entry).not.toContain("rung-one-scope");
      expect(entry.toLowerCase()).not.toContain("memory");
    }

    // Same label, same vault, same id: the mirror stays addressable.
    expect(passageIdForClaudeCodeMemoryFile(adapter, "fact", "concise-updates.md")).toBe(
      passageIdForClaudeCodeMemoryFile(adapter, "fact", "concise-updates.md"),
    );
    // Different label, different id.
    expect(passageIdForClaudeCodeMemoryFile(adapter, "fact", "concise-updates.md")).not.toBe(
      passageIdForClaudeCodeMemoryFile(adapter, "fact", "rung-one-scope.md"),
    );
    // Different fortress key, different id: the digest is keyed, not public.
    const otherKeyAdapter = new SdwMemoryBackendAdapter({
      storage: new FilesystemStorage(await tempDir("cc-memory-opacity-other")),
      masterKey: new Uint8Array(32).fill(99),
      fortressId: "fortress:cc-file-adapter",
      ownerRef: "cc-opacity",
      now: () => INGESTED_AT,
    });
    expect(passageIdForClaudeCodeMemoryFile(otherKeyAdapter, "fact", "concise-updates.md")).not.toBe(
      passageIdForClaudeCodeMemoryFile(adapter, "fact", "concise-updates.md"),
    );
  });

  it("refuses to emit over an existing Claude Code memory tree and leaves it unchanged", async () => {
    const source = await copyFixtureSet("basic");
    const storagePath = await tempDir("cc-memory-overwrite-vault");
    const beforeHash = await hashMarkdownTree(source);
    const adapter = makeAdapter(storagePath, "cc-overwrite");

    await ingestClaudeCodeMemoryDirectory(adapter, source, { ingestedAt: INGESTED_AT });

    await expect(emitClaudeCodeMemoryDirectory(adapter, source)).rejects.toThrow(
      "Refusing to overwrite existing Claude Code memory file",
    );
    expect(await hashMarkdownTree(source)).toBe(beforeHash);
  });

  it("removes every file it created when an emit fails part way through", async () => {
    const source = await copyFixtureSet("basic");
    const storagePath = await tempDir("cc-memory-emit-cleanup-vault");
    const output = await tempDir("cc-memory-emit-cleanup-output");
    const adapter = makeAdapter(storagePath, "cc-emit-cleanup");
    await ingestClaudeCodeMemoryDirectory(adapter, source, { ingestedAt: INGESTED_AT });

    // A dangling symlink is invisible to the stat-based pre-flight (stat
    // follows the link and gets ENOENT) but is a real directory entry, so the
    // link() of the LAST file fails after the first two have been placed.
    await symlink(join(output, "does-not-exist"), join(output, "rung-one-scope.md"));

    await expect(emitClaudeCodeMemoryDirectory(adapter, output)).rejects.toThrow();

    // Every file this run created is gone, and no temp file was orphaned, so a
    // retry is not blocked by the overwrite refusal.
    const remaining = (await readdir(output)).sort();
    expect(remaining).toEqual(["rung-one-scope.md"]);
    expect(remaining.some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("stores mirrored files as encrypted SDW records and fails closed after raw byte tamper", async () => {
    const source = await copyFixtureSet("unicode");
    const storagePath = await tempDir("cc-memory-custody-vault");
    const adapter = makeAdapter(storagePath, "cc-custody");
    const result = await ingestClaudeCodeMemoryDirectory(adapter, source, {
      ingestedAt: INGESTED_AT,
    });

    const rawFiles = await readRawCorpusFiles(storagePath);
    expect(rawFiles.length).toBeGreaterThan(0);
    for (const raw of rawFiles) {
      expect(encryptedEnvelopeContains(raw, "Café notes")).toBe(false);
      expect(encryptedEnvelopeContains(raw, "こんにちは")).toBe(false);
      expect(encryptedEnvelopeContains(raw, "emoji")).toBe(false);
    }

    const passageId = result.ingested.find((passage) => passage.text.includes("Café notes"))!.passage_id;
    const tamperPath = await firstChunkFileForPassage(storagePath, "cc-custody", passageId);
    const before = await readFile(tamperPath);
    const tampered = Buffer.from(before);
    const midpoint = Math.floor(tampered.length / 2);
    tampered[midpoint] = tampered[midpoint]! ^ 1;
    await writeFile(tamperPath, tampered);

    await expect(adapter.getPassage(passageId)).rejects.toMatchObject({
      category: "auth_failed",
    });
  });
});

async function readRawCorpusFiles(storagePath: string): Promise<readonly Uint8Array[]> {
  const corpusDir = join(storagePath, SDW_DOCUMENT_CORPUS_NAMESPACE);
  const entries = await readdir(corpusDir);
  const out: Uint8Array[] = [];
  for (const entry of entries.filter((name) => name.endsWith(".enc")).sort()) {
    out.push(new Uint8Array(await readFile(join(corpusDir, entry))));
  }
  return out;
}

async function rawCorpusKeys(storage: StorageBackend): Promise<readonly string[]> {
  return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE))
    .map((entry) => entry.key)
    .sort();
}

async function firstChunkFileForPassage(
  storagePath: string,
  ownerRef: string,
  passageId: string,
): Promise<string> {
  const corpusDir = join(storagePath, SDW_DOCUMENT_CORPUS_NAMESPACE);
  const prefix = `chunk.mem.${ownerRef}.${passageId}.`;
  for (const filename of await readdir(corpusDir)) {
    if (filename.startsWith(prefix) && filename.endsWith(".enc")) {
      const path = join(corpusDir, filename);
      const fileStat = await stat(path);
      expect(fileStat.isFile()).toBe(true);
      return path;
    }
  }
  throw new Error(`No chunk file found for passage ${passageId}`);
}
