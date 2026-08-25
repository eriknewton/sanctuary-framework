/**
 * Manual, reversible Claude Code <-> Codex memory projection.
 *
 * This is intentionally not sync. A call reads one already-mirrored harness
 * snapshot from the encrypted SDW owner scope, stores a frozen encrypted
 * archive copy in that same scope, and writes a plaintext native projection
 * only to an operator-named empty directory. Restoration reads the encrypted
 * archive and reproduces the exact source files; it never attempts to infer
 * the source tree from the lossy native projection.
 */

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemoryPassageInput,
} from "./adapters/memory-backend.js";
import { memoryTranscodeIngress } from "./memory-provenance-ingress.js";
import { CLAUDE_CODE_MEMORY_HARNESS } from "./adapters/claude-code-file-adapter.js";
import {
  CODEX_MEMORY_FILES,
  CODEX_MEMORY_HARNESS,
  type CodexMemoryFilename,
} from "./adapters/codex-memory-file-adapter.js";
import { SdwValidationError } from "./errors.js";

export const MEMORY_TRANSCODE_VERSION = "SANCTUARY_MEMORY_TRANSCODE_V1" as const;
export const MEMORY_TRANSCODE_MODE = "reversible" as const;
export const MEMORY_TRANSCODE_ARCHIVE_DOMAIN = "memory-transcode-archive-v1" as const;

export type MemoryTranscodeHarness =
  | typeof CLAUDE_CODE_MEMORY_HARNESS
  | typeof CODEX_MEMORY_HARNESS;

export interface MemoryTranscodeResult {
  readonly archive_id: string;
  readonly version: typeof MEMORY_TRANSCODE_VERSION;
  readonly mode: typeof MEMORY_TRANSCODE_MODE;
  readonly from_harness: MemoryTranscodeHarness;
  readonly to_harness: MemoryTranscodeHarness;
  readonly source_file_count: number;
  readonly projection_file_count: number;
  readonly source_set_sha256: string;
  readonly projection_set_sha256: string;
  readonly projection_files: readonly {
    readonly path: string;
    readonly sha256: string;
    readonly size: number;
  }[];
}

export interface MemoryTranscodeRestoreResult {
  readonly restored: true;
  readonly archive_id: string;
  readonly version: typeof MEMORY_TRANSCODE_VERSION;
  readonly source_harness: MemoryTranscodeHarness;
  readonly source_file_count: number;
  readonly source_set_sha256: string;
  readonly files: readonly {
    readonly path: string;
    readonly sha256: string;
    readonly size: number;
  }[];
}

interface SourceFile {
  readonly passageId?: string;
  readonly path: string;
  readonly sourceClass: string;
  readonly text: string;
}

/**
 * A validated, write-free view of one completed transcode archive.
 *
 * This is the shared parse boundary for local restore and Exit V2 export, so
 * the two consumers cannot disagree about file, count, path, or digest rules.
 */
export interface MemoryTranscodeLogicalArchive {
  readonly archive_id: string;
  readonly owner_ref: string;
  readonly version: typeof MEMORY_TRANSCODE_VERSION;
  readonly state: "complete";
  readonly from_harness: MemoryTranscodeHarness;
  readonly to_harness: MemoryTranscodeHarness;
  readonly source_file_count: number;
  readonly source_set_sha256: string;
  readonly projection_file_count: number;
  readonly projection_set_sha256: string;
  readonly files: readonly {
    readonly source_passage_id?: string;
    readonly path: string;
    readonly source_class: string;
    readonly text: string;
    readonly size: number;
    readonly sha256: string;
  }[];
}

interface OutputFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

interface OutputWriteReceipt {
  readonly root: string;
  readonly root_created: boolean;
  readonly targets: readonly string[];
}

const ARCHIVE_KIND_KEY = "memory_transcode_kind";
const ARCHIVE_KIND_MANIFEST = "manifest";
const ARCHIVE_KIND_FILE = "file";
const ARCHIVE_ID_KEY = "memory_transcode_archive_id";
const ARCHIVE_VERSION_KEY = "memory_transcode_version";
const ARCHIVE_STATE_KEY = "memory_transcode_state";
const ARCHIVE_STATE_PREPARED = "prepared";
const ARCHIVE_STATE_COMPLETE = "complete";
const FROM_HARNESS_KEY = "memory_transcode_from_harness";
const TO_HARNESS_KEY = "memory_transcode_to_harness";
const SOURCE_PATH_KEY = "memory_transcode_source_path";
const SOURCE_CLASS_KEY = "memory_transcode_source_class";
const SOURCE_SHA_KEY = "memory_transcode_source_sha256";
const SOURCE_SIZE_KEY = "memory_transcode_source_size";
const SOURCE_SET_SHA_KEY = "memory_transcode_source_set_sha256";
const SOURCE_FILE_COUNT_KEY = "memory_transcode_source_file_count";
const PROJECTION_SET_SHA_KEY = "memory_transcode_projection_set_sha256";
const PROJECTION_FILE_COUNT_KEY = "memory_transcode_projection_file_count";

const MAX_SOURCE_FILES = 500;
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const MAX_SOURCE_SET_BYTES = 16 * 1024 * 1024;
const MAX_OWNER_SCOPE_PAGES = 10_000;
const TEMP_SUFFIX_BYTES = 8;
const ARCHIVE_TAINT = "user_content" as const;

export async function transcodeMemoryDirectory(
  adapter: MemoryBackendAdapter,
  fromHarness: MemoryTranscodeHarness,
  toHarness: MemoryTranscodeHarness,
  outputDir: string,
  options: { readonly now?: () => string } = {},
): Promise<MemoryTranscodeResult> {
  if (fromHarness === toHarness) {
    throw new SdwValidationError(
      "invalid_identifier",
      "memory_transcode requires different source and destination harnesses",
    );
  }
  const source = await sourceFilesFromVault(adapter, fromHarness);
  const sourceSetSha = hashFileSet(source.map((file) => ({
    path: file.path,
    bytes: Buffer.from(file.text, "utf8"),
  })));
  const createdAt = options.now?.() ?? new Date().toISOString();
  const archiveId = adapter.derivePassageId(
    MEMORY_TRANSCODE_ARCHIVE_DOMAIN,
    `archive\n${createdAt}\n${randomBytes(32).toString("hex")}`,
  );
  assertArchiveId(archiveId);
  const projection = buildProjection(source, fromHarness, toHarness, archiveId);
  const projectionSetSha = hashFileSet(projection);
  const fileInputs = source.map((file) => archiveFileInput(
    adapter,
    archiveId,
    file,
    fromHarness,
    toHarness,
    createdAt,
  ));
  const preparedManifest = archiveManifestInput({
    archiveId,
    fromHarness,
    toHarness,
    state: ARCHIVE_STATE_PREPARED,
    sourceSetSha,
    sourceFileCount: source.length,
    createdAt,
  });
  const archiveIds = [...fileInputs.map((input) => input.passage_id!), archiveId];

  // Encrypted archive first. A crash before projection leaves only an opaque,
  // prepared archive in the vault; restore refuses prepared manifests.
  await adapter.putPassages([...fileInputs, preparedManifest], ARCHIVE_TAINT);
  let projectionReceipt: OutputWriteReceipt | null = null;
  try {
    projectionReceipt = await writeOutputSet(outputDir, projection);
    const completeManifest = archiveManifestInput({
      archiveId,
      fromHarness,
      toHarness,
      state: ARCHIVE_STATE_COMPLETE,
      sourceSetSha,
      sourceFileCount: source.length,
      projectionSetSha,
      projectionFileCount: projection.length,
      createdAt,
    });
    await adapter.putPassages([completeManifest], ARCHIVE_TAINT);
  } catch (error) {
    const cleanupFailures: unknown[] = [];
    if (projectionReceipt !== null) {
      try {
        await removeOutputSet(projectionReceipt);
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    try {
      await rollbackArchive(adapter, archiveIds, error);
    } catch (rollbackError) {
      cleanupFailures.push(rollbackError);
    }
    if (cleanupFailures.length > 0) {
      throw new SdwValidationError(
        "partial_scope",
        "memory transcode cleanup could not verify complete rollback",
        { cause: new AggregateError([error, ...cleanupFailures]) },
      );
    }
    throw error;
  }

  return {
    archive_id: archiveId,
    version: MEMORY_TRANSCODE_VERSION,
    mode: MEMORY_TRANSCODE_MODE,
    from_harness: fromHarness,
    to_harness: toHarness,
    source_file_count: source.length,
    projection_file_count: projection.length,
    source_set_sha256: sourceSetSha,
    projection_set_sha256: projectionSetSha,
    projection_files: describeFiles(projection),
  };
}

export async function restoreMemoryTranscodeArchive(
  adapter: MemoryBackendAdapter,
  archiveId: string,
  outputDir: string,
): Promise<MemoryTranscodeRestoreResult> {
  const archive = await readMemoryTranscodeArchive(adapter, archiveId);
  const files = archive.files.map((file) => ({
    path: file.path,
    bytes: Buffer.from(file.text, "utf8"),
  }));
  await writeOutputSet(outputDir, files);
  return {
    restored: true,
    archive_id: archiveId,
    version: MEMORY_TRANSCODE_VERSION,
    source_harness: archive.from_harness,
    source_file_count: files.length,
    source_set_sha256: archive.source_set_sha256,
    files: describeFiles(files),
  };
}

/** Validate and read a completed archive without creating a plaintext projection. */
export async function readMemoryTranscodeArchive(
  adapter: MemoryBackendAdapter,
  archiveId: string,
): Promise<MemoryTranscodeLogicalArchive> {
  const manifest = await adapter.getPassage(archiveId);
  if (manifest === null || metadataValue(manifest, ARCHIVE_KIND_KEY) !== ARCHIVE_KIND_MANIFEST) {
    throw new Error("memory transcode archive manifest was not found");
  }
  assertArchiveVersion(manifest);
  if (metadataValue(manifest, ARCHIVE_ID_KEY) !== archiveId) {
    throw new Error("memory transcode archive manifest id is invalid");
  }
  if (metadataValue(manifest, ARCHIVE_STATE_KEY) !== ARCHIVE_STATE_COMPLETE) {
    throw new Error("memory transcode archive is not complete");
  }
  const fromHarness = asHarness(metadataValue(manifest, FROM_HARNESS_KEY));
  if (fromHarness === null) throw new Error("memory transcode archive source harness is invalid");
  const toHarness = asHarness(metadataValue(manifest, TO_HARNESS_KEY));
  if (toHarness === null || toHarness === fromHarness) {
    throw new Error("memory transcode archive destination harness is invalid");
  }
  const expectedCount = parseBoundedInteger(
    metadataValue(manifest, SOURCE_FILE_COUNT_KEY),
    "source file count",
    MAX_SOURCE_FILES,
  );
  const expectedSetSha = requiredMetadata(manifest, SOURCE_SET_SHA_KEY);
  assertSha256(expectedSetSha, "source-set digest");
  const expectedProjectionSetSha = requiredMetadata(manifest, PROJECTION_SET_SHA_KEY);
  assertSha256(expectedProjectionSetSha, "projection-set digest");
  const expectedProjectionCount = parseBoundedInteger(
    metadataValue(manifest, PROJECTION_FILE_COUNT_KEY),
    "projection file count",
    MAX_SOURCE_FILES,
  );
  const all = await listAllPassages(adapter);
  const archivedFiles = all.filter((passage) =>
    metadataValue(passage, ARCHIVE_KIND_KEY) === ARCHIVE_KIND_FILE &&
    metadataValue(passage, ARCHIVE_ID_KEY) === archiveId
  );
  if (archivedFiles.length !== expectedCount) {
    throw new Error("memory transcode archive file count does not match its manifest");
  }
  const source = archivedFiles
    .map((passage) => archiveFileFromPassage(
      adapter,
      passage,
      archiveId,
      fromHarness,
      toHarness,
    ))
    .sort(compareSourceFiles);
  assertUniqueSourcePaths(source);
  assertSourceBounds(source);
  const files = source.map((file) => ({ path: file.path, bytes: Buffer.from(file.text, "utf8") }));
  if (hashFileSet(files) !== expectedSetSha) {
    throw new Error("memory transcode archive source-set digest does not match its manifest");
  }
  const projection = buildProjection(source, fromHarness, toHarness, archiveId);
  if (
    projection.length !== expectedProjectionCount ||
    hashFileSet(projection) !== expectedProjectionSetSha
  ) {
    throw new Error("memory transcode archive projection binding does not match its source");
  }
  return {
    archive_id: archiveId,
    owner_ref: adapter.ownerRef,
    version: MEMORY_TRANSCODE_VERSION,
    state: ARCHIVE_STATE_COMPLETE,
    from_harness: fromHarness,
    to_harness: toHarness,
    source_file_count: files.length,
    source_set_sha256: expectedSetSha,
    projection_file_count: expectedProjectionCount,
    projection_set_sha256: expectedProjectionSetSha,
    files: source.map((file) => {
      const bytes = Buffer.from(file.text, "utf8");
      return {
        source_passage_id: file.passageId!,
        path: file.path,
        source_class: file.sourceClass,
        text: file.text,
        size: bytes.length,
        sha256: sha256(bytes),
      };
    }),
  };
}

/**
 * Build a destination-local completed archive as one atomic passage set.
 *
 * The caller adds any companion records (Exit V2 adds signed lineage) and
 * submits the combined array through one `putPassages` call. Passage ids and
 * the projection binding are re-derived under the destination adapter and
 * archive id; source-fortress opaque ids are never copied.
 */
export function buildMemoryTranscodeArchivePassages(
  adapter: MemoryBackendAdapter,
  destinationArchiveId: string,
  archive: Pick<
    MemoryTranscodeLogicalArchive,
    "version" | "state" | "from_harness" | "to_harness" | "source_set_sha256" | "files"
  >,
  createdAt: string,
): readonly MemoryPassageInput[] {
  assertArchiveId(destinationArchiveId);
  if (archive.version !== MEMORY_TRANSCODE_VERSION || archive.state !== ARCHIVE_STATE_COMPLETE) {
    throw new Error("memory transcode logical archive is not a supported completed archive");
  }
  if (archive.from_harness === archive.to_harness) {
    throw new Error("memory transcode logical archive harness binding is invalid");
  }
  const source: SourceFile[] = archive.files.map((file) => ({
    path: file.path,
    sourceClass: file.source_class,
    text: file.text,
  }));
  assertUniqueSourcePaths(source);
  assertSourceBounds(source);
  const files = source.map((file) => ({ path: file.path, bytes: Buffer.from(file.text, "utf8") }));
  if (hashFileSet(files) !== archive.source_set_sha256) {
    throw new Error("memory transcode logical archive source-set digest is invalid");
  }
  for (const file of archive.files) {
    const bytes = Buffer.from(file.text, "utf8");
    if (bytes.length !== file.size || sha256(bytes) !== file.sha256) {
      throw new Error(`memory transcode logical archive file binding is invalid: ${file.path}`);
    }
  }
  const projection = buildProjection(
    source,
    archive.from_harness,
    archive.to_harness,
    destinationArchiveId,
  );
  const fileInputs = source.map((file) => archiveFileInput(
    adapter,
    destinationArchiveId,
    file,
    archive.from_harness,
    archive.to_harness,
    createdAt,
  ));
  const manifest = archiveManifestInput({
    archiveId: destinationArchiveId,
    fromHarness: archive.from_harness,
    toHarness: archive.to_harness,
    state: ARCHIVE_STATE_COMPLETE,
    sourceSetSha: archive.source_set_sha256,
    sourceFileCount: source.length,
    projectionSetSha: hashFileSet(projection),
    projectionFileCount: projection.length,
    createdAt,
  });
  return [...fileInputs, manifest];
}

async function sourceFilesFromVault(
  adapter: MemoryBackendAdapter,
  harness: MemoryTranscodeHarness,
): Promise<readonly SourceFile[]> {
  const passages = await listAllPassages(adapter);
  const source = passages
    .filter((passage) =>
      metadataValue(passage, "origin_harness") === harness &&
      metadataValue(passage, "ingress") === "file_import"
    )
    .map((passage) => {
      const path = requiredMetadata(passage, "source_path");
      const sourceClass = requiredMetadata(passage, "source_class");
      assertSourcePath(path, harness);
      return { path, sourceClass, text: passage.text };
    })
    .sort(compareSourceFiles);
  if (!source.some((file) => file.path === "MEMORY.md")) {
    throw new Error(`vault has no complete ${harness} memory snapshot: MEMORY.md is absent`);
  }
  const paths = new Set<string>();
  for (const file of source) {
    if (paths.has(file.path)) throw new Error(`vault has duplicate memory source path: ${file.path}`);
    paths.add(file.path);
  }
  assertSourceBounds(source);
  return source;
}

function buildProjection(
  source: readonly SourceFile[],
  fromHarness: MemoryTranscodeHarness,
  toHarness: MemoryTranscodeHarness,
  archiveId: string,
): readonly OutputFile[] {
  if (fromHarness === CLAUDE_CODE_MEMORY_HARNESS && toHarness === CODEX_MEMORY_HARNESS) {
    return buildCodexProjection(source, archiveId);
  }
  if (fromHarness === CODEX_MEMORY_HARNESS && toHarness === CLAUDE_CODE_MEMORY_HARNESS) {
    return buildClaudeCodeProjection(source, archiveId);
  }
  throw new Error("unsupported memory transcode direction");
}

function buildCodexProjection(
  source: readonly SourceFile[],
  archiveId: string,
): readonly OutputFile[] {
  const index = source.find((file) => file.path === "MEMORY.md")!;
  const facts = source.filter((file) => file.path !== "MEMORY.md");
  const memory =
    "# Sanctuary manual memory projection\n\n" +
    "This directory is a plaintext Codex-native projection of a Claude Code snapshot. " +
    "Its provenance is descriptive and unsigned until Sanctuary Memory-Integrity Slice C. " +
    "It is not a sync path. Exact source recovery uses the encrypted Sanctuary transcode archive, " +
    "not these projected files. Memory supplied to a configured model provider is visible to that provider.\n\n" +
    `Recovery archive_id: \`${archiveId}\`\n\n` +
    "- [Projected Claude Code index](memory_summary.md)\n" +
    "- [Projected source files](raw_memories.md)\n";
  const summary =
    "# Projected Claude Code index\n\n" +
    "The content below is the source MEMORY.md snapshot.\n\n" +
    index.text;
  const raw = facts.length === 0
    ? "# Projected Claude Code source files\n\nNo non-index source files were present.\n"
    : "# Projected Claude Code source files\n\n" + facts.map((file) => {
      const bytes = Buffer.from(file.text, "utf8");
      return [
        `## Source file: ${file.path}`,
        `<!-- bytes=${String(bytes.length)} sha256=${sha256(bytes)} -->`,
        "",
        file.text,
      ].join("\n");
    }).join("\n\n");
  return [
    outputText("MEMORY.md", memory),
    outputText("memory_summary.md", summary),
    outputText("raw_memories.md", raw),
  ];
}

function buildClaudeCodeProjection(
  source: readonly SourceFile[],
  archiveId: string,
): readonly OutputFile[] {
  const byPath = new Map(source.map((file) => [file.path, file.text]));
  const entries: Array<{ readonly label: string; readonly path: string; readonly source: string }> = [
    { label: "Codex MEMORY.md", path: "codex-memory-index.md", source: "MEMORY.md" },
  ];
  if (byPath.has("memory_summary.md")) {
    entries.push({
      label: "Codex memory summary",
      path: "codex-memory-summary.md",
      source: "memory_summary.md",
    });
  }
  if (byPath.has("raw_memories.md")) {
    entries.push({
      label: "Codex raw memories",
      path: "codex-raw-memories.md",
      source: "raw_memories.md",
    });
  }
  const index =
    "# Sanctuary manual memory projection\n\n" +
    "This directory is a plaintext Claude Code-native projection of a Codex snapshot. " +
    "Its provenance is descriptive and unsigned until Sanctuary Memory-Integrity Slice C. " +
    "It is not a sync path. Exact source recovery uses the encrypted Sanctuary transcode archive, " +
    "not these projected files. Memory supplied to a configured model provider is visible to that provider.\n\n" +
    `Recovery archive_id: \`${archiveId}\`\n\n` +
    entries.map((entry) => `- [**${entry.label}**](${entry.path})`).join("\n") +
    "\n";
  return [
    outputText("MEMORY.md", index),
    ...entries.map((entry) => outputText(entry.path, byPath.get(entry.source)!)),
  ];
}

function archiveFileInput(
  adapter: MemoryBackendAdapter,
  archiveId: string,
  file: SourceFile,
  fromHarness: MemoryTranscodeHarness,
  toHarness: MemoryTranscodeHarness,
  createdAt: string,
): MemoryPassageInput {
  const bytes = Buffer.from(file.text, "utf8");
  return {
    passage_id: adapter.derivePassageId(
      MEMORY_TRANSCODE_ARCHIVE_DOMAIN,
      `file\n${archiveId}\n${file.path}`,
    ),
    text: file.text,
    tags: ["memory_transcode_archive", "memory_transcode_file"],
    metadata: [
      { key: ARCHIVE_KIND_KEY, value: ARCHIVE_KIND_FILE },
      { key: ARCHIVE_ID_KEY, value: archiveId },
      { key: ARCHIVE_VERSION_KEY, value: MEMORY_TRANSCODE_VERSION },
      { key: FROM_HARNESS_KEY, value: fromHarness },
      { key: TO_HARNESS_KEY, value: toHarness },
      { key: SOURCE_PATH_KEY, value: file.path },
      { key: SOURCE_CLASS_KEY, value: file.sourceClass },
      { key: SOURCE_SHA_KEY, value: sha256(bytes) },
      { key: SOURCE_SIZE_KEY, value: String(bytes.length) },
    ],
    created_at: createdAt,
    provenanceContext: memoryTranscodeIngress("system:memory-transcode", "transcode_source_file"),
  };
}

function archiveManifestInput(input: {
  readonly archiveId: string;
  readonly fromHarness: MemoryTranscodeHarness;
  readonly toHarness: MemoryTranscodeHarness;
  readonly state: typeof ARCHIVE_STATE_PREPARED | typeof ARCHIVE_STATE_COMPLETE;
  readonly sourceSetSha: string;
  readonly sourceFileCount: number;
  readonly projectionSetSha?: string;
  readonly projectionFileCount?: number;
  readonly createdAt: string;
}): MemoryPassageInput {
  return {
    passage_id: input.archiveId,
    text: `Sanctuary reversible memory transcode archive (${input.state}).`,
    tags: ["memory_transcode_archive", `memory_transcode_${input.state}`],
    metadata: [
      { key: ARCHIVE_KIND_KEY, value: ARCHIVE_KIND_MANIFEST },
      { key: ARCHIVE_ID_KEY, value: input.archiveId },
      { key: ARCHIVE_VERSION_KEY, value: MEMORY_TRANSCODE_VERSION },
      { key: ARCHIVE_STATE_KEY, value: input.state },
      { key: FROM_HARNESS_KEY, value: input.fromHarness },
      { key: TO_HARNESS_KEY, value: input.toHarness },
      { key: SOURCE_SET_SHA_KEY, value: input.sourceSetSha },
      { key: SOURCE_FILE_COUNT_KEY, value: String(input.sourceFileCount) },
      ...(input.projectionSetSha === undefined
        ? []
        : [{ key: PROJECTION_SET_SHA_KEY, value: input.projectionSetSha }]),
      ...(input.projectionFileCount === undefined
        ? []
        : [{ key: PROJECTION_FILE_COUNT_KEY, value: String(input.projectionFileCount) }]),
    ],
    created_at: input.createdAt,
    provenanceContext: memoryTranscodeIngress("system:memory-transcode", "transcode_manifest"),
  };
}

function archiveFileFromPassage(
  adapter: MemoryBackendAdapter,
  passage: MemoryPassage,
  archiveId: string,
  fromHarness: MemoryTranscodeHarness,
  toHarness: MemoryTranscodeHarness,
): SourceFile {
  assertArchiveVersion(passage);
  if (metadataValue(passage, ARCHIVE_ID_KEY) !== archiveId) {
    throw new Error("memory transcode archive file id does not match its manifest");
  }
  const path = requiredMetadata(passage, SOURCE_PATH_KEY);
  if (
    passage.passage_id !== adapter.derivePassageId(
      MEMORY_TRANSCODE_ARCHIVE_DOMAIN,
      `file\n${archiveId}\n${path}`,
    )
  ) {
    throw new Error("memory transcode archive file passage id is invalid");
  }
  if (
    metadataValue(passage, FROM_HARNESS_KEY) !== fromHarness ||
    metadataValue(passage, TO_HARNESS_KEY) !== toHarness
  ) {
    throw new Error("memory transcode archive file harness binding is invalid");
  }
  assertSourcePath(path, fromHarness);
  const bytes = Buffer.from(passage.text, "utf8");
  const expectedSize = parseBoundedInteger(
    metadataValue(passage, SOURCE_SIZE_KEY),
    "source size",
    MAX_SOURCE_SET_BYTES,
  );
  if (bytes.length !== expectedSize) {
    throw new Error(`memory transcode archive size mismatch for ${path}`);
  }
  if (sha256(bytes) !== requiredMetadata(passage, SOURCE_SHA_KEY)) {
    throw new Error(`memory transcode archive digest mismatch for ${path}`);
  }
  return {
    passageId: passage.passage_id,
    path,
    sourceClass: requiredMetadata(passage, SOURCE_CLASS_KEY),
    text: passage.text,
  };
}

async function listAllPassages(adapter: MemoryBackendAdapter): Promise<readonly MemoryPassage[]> {
  const all: MemoryPassage[] = [];
  let after: string | undefined;
  for (let pageNumber = 0; pageNumber < MAX_OWNER_SCOPE_PAGES; pageNumber++) {
    const page = await adapter.listPassages({ after });
    if (page.length === 0) break;
    const next = page.at(-1)!.passage_id;
    if (after !== undefined && next <= after) {
      throw new Error("memory transcode vault pagination cursor did not advance");
    }
    all.push(...page);
    after = next;
    if (pageNumber === MAX_OWNER_SCOPE_PAGES - 1) {
      throw new Error("memory transcode vault pagination exceeded its page bound");
    }
  }
  return all;
}

async function writeOutputSet(
  outputDir: string,
  files: readonly OutputFile[],
): Promise<OutputWriteReceipt> {
  const requestedRoot = resolve(outputDir);
  const parent = dirname(requestedRoot);
  if (await pathStatus(parent) !== "directory") {
    throw new Error("memory transcode output parent must be a real, non-symlink directory");
  }
  const parentReal = await realpath(parent);
  const requestedStatus = await pathStatus(requestedRoot);
  if (requestedStatus === "symlink" || requestedStatus === "other") {
    throw new Error("memory transcode output must be a real, non-symlink directory");
  }
  const existed = requestedStatus === "directory";
  const root = existed
    ? await realpath(requestedRoot)
    : join(parentReal, basename(requestedRoot));
  if (!existed) await mkdir(root, { mode: 0o700 });
  if (await pathStatus(root) !== "directory") {
    if (!existed) await rmdirQuietly(root);
    throw new Error("memory transcode output must be a real, non-symlink directory");
  }
  if ((await readdir(root)).length !== 0) {
    if (!existed) await rmdirQuietly(root);
    throw new Error("memory transcode output directory must be empty");
  }
  const created: string[] = [];
  let pendingTemp: string | null = null;
  try {
    for (const file of files) {
      assertOutputPath(file.path);
      const target = join(root, file.path);
      const temp = join(root, `.${basename(file.path)}.${randomBytes(TEMP_SUFFIX_BYTES).toString("hex")}.tmp`);
      pendingTemp = temp;
      const handle = await open(
        temp,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
      try {
        await handle.writeFile(file.bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await link(temp, target);
      created.push(target);
      await unlink(temp);
      pendingTemp = null;
    }
    await syncDirectory(root);
    await verifyOutputFiles(files, root);
    const expectedNames = created.map((target) => basename(target)).sort();
    const actualNames = (await readdir(root)).sort();
    if (
      actualNames.length !== expectedNames.length ||
      actualNames.some((name, index) => name !== expectedNames[index])
    ) {
      throw new Error("memory transcode output inventory changed during projection");
    }
    return { root, root_created: !existed, targets: [...created] };
  } catch (error) {
    const cleanupFailures: unknown[] = [];
    if (pendingTemp !== null) {
      try {
        await unlinkQuietly(pendingTemp);
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    for (const target of [...created].reverse()) {
      try {
        await unlinkQuietly(target);
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    for (const target of created) {
      try {
        if (await pathStatus(target) !== "missing") {
          cleanupFailures.push(new Error("projection cleanup left an output file present"));
        }
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    if (!existed) {
      try {
        await rmdir(root);
        if (await pathStatus(root) !== "missing") {
          cleanupFailures.push(new Error("projection cleanup left its output directory present"));
        }
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError);
      }
    }
    if (cleanupFailures.length > 0) {
      throw new SdwValidationError(
        "partial_scope",
        "memory transcode projection cleanup could not be verified",
        { cause: new AggregateError([error, ...cleanupFailures]) },
      );
    }
    throw error;
  }
}

async function verifyOutputFiles(files: readonly OutputFile[], root: string): Promise<void> {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow !== "number" || noFollow === 0) {
    throw new Error("memory transcode output verification requires kernel O_NOFOLLOW support");
  }
  for (const file of files) {
    const handle = await open(join(root, file.path), fsConstants.O_RDONLY | noFollow);
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size !== file.bytes.byteLength) {
        throw new Error(`memory transcode output file shape is invalid: ${file.path}`);
      }
      const actual = await handle.readFile();
      const after = await handle.stat();
      if (
        before.dev !== after.dev ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs ||
        !actual.equals(Buffer.from(file.bytes))
      ) {
        throw new Error(`memory transcode output file verification failed: ${file.path}`);
      }
    } finally {
      await handle.close();
    }
  }
}

async function removeOutputSet(receipt: OutputWriteReceipt): Promise<void> {
  for (const target of [...receipt.targets].reverse()) await unlinkQuietly(target);
  for (const target of receipt.targets) {
    if (await pathStatus(target) !== "missing") {
      throw new Error("memory transcode projection rollback left an output file present");
    }
  }
  if (receipt.root_created) {
    await rmdir(receipt.root);
    if (await pathStatus(receipt.root) !== "missing") {
      throw new Error("memory transcode projection rollback left its output directory present");
    }
  }
}

async function rollbackArchive(
  adapter: MemoryBackendAdapter,
  passageIds: readonly string[],
  originalError: unknown,
): Promise<void> {
  const failures: unknown[] = [];
  for (const passageId of [...passageIds].reverse()) {
    try {
      await adapter.deletePassage(passageId);
    } catch (error) {
      failures.push(error);
    }
  }
  for (const passageId of passageIds) {
    try {
      if (await adapter.getPassage(passageId) !== null) {
        failures.push(new Error("archive rollback left a passage present"));
      }
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new SdwValidationError(
      "partial_scope",
      "memory transcode rollback could not verify archive removal",
      { cause: new AggregateError([originalError, ...failures]) },
    );
  }
}

function assertSourceBounds(files: readonly SourceFile[]): void {
  if (files.length < 1 || files.length > MAX_SOURCE_FILES) {
    throw new Error(`memory transcode source file count must be 1-${String(MAX_SOURCE_FILES)}`);
  }
  let total = 0;
  for (const file of files) {
    const size = Buffer.byteLength(file.text, "utf8");
    if (size > MAX_SOURCE_FILE_BYTES) {
      throw new Error(`memory transcode source file exceeds ${String(MAX_SOURCE_FILE_BYTES)} bytes`);
    }
    total += size;
  }
  if (total > MAX_SOURCE_SET_BYTES) {
    throw new Error(`memory transcode source set exceeds ${String(MAX_SOURCE_SET_BYTES)} bytes`);
  }
}

function assertUniqueSourcePaths(files: readonly SourceFile[]): void {
  const paths = new Set<string>();
  for (const file of files) {
    if (paths.has(file.path)) {
      throw new Error(`memory transcode archive has duplicate source path: ${file.path}`);
    }
    paths.add(file.path);
  }
}

function assertSourcePath(path: string, harness: MemoryTranscodeHarness): void {
  assertOutputPath(path);
  if (!path.endsWith(".md")) throw new Error("memory transcode source path must be Markdown");
  if (
    harness === CODEX_MEMORY_HARNESS &&
    !CODEX_MEMORY_FILES.includes(path as CodexMemoryFilename)
  ) {
    throw new Error(`memory transcode Codex source path is not allowlisted: ${path}`);
  }
}

function assertOutputPath(path: string): void {
  if (
    path.length === 0 ||
    path === "." ||
    path === ".." ||
    path.includes("/") ||
    path.includes("\\") ||
    basename(path) !== path
  ) {
    throw new Error(`memory transcode path is unsafe: ${path}`);
  }
}

function hashFileSet(files: readonly OutputFile[]): string {
  const digest = createHash("sha256");
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    updateLengthPrefixed(digest, Buffer.from(file.path, "utf8"));
    updateLengthPrefixed(digest, file.bytes);
  }
  return digest.digest("hex");
}

function updateLengthPrefixed(digest: ReturnType<typeof createHash>, bytes: Uint8Array): void {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.byteLength));
  digest.update(length);
  digest.update(bytes);
}

function outputText(path: string, text: string): OutputFile {
  return { path, bytes: Buffer.from(text, "utf8") };
}

function describeFiles(files: readonly OutputFile[]): readonly {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}[] {
  return files.map((file) => ({
    path: file.path,
    sha256: sha256(file.bytes),
    size: file.bytes.byteLength,
  }));
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSha256(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`memory transcode archive ${label} is invalid`);
  }
}

function assertArchiveId(value: string): void {
  if (!/^[a-f0-9]{32}$/.test(value)) {
    throw new Error("memory transcode backend produced an unsupported archive id");
  }
}

function compareSourceFiles(a: SourceFile, b: SourceFile): number {
  if (a.path === b.path) return 0;
  if (a.path === "MEMORY.md") return -1;
  if (b.path === "MEMORY.md") return 1;
  return a.path.localeCompare(b.path);
}

function metadataValue(passage: MemoryPassage, key: string): string | undefined {
  return passage.metadata.find((entry) => entry.key === key)?.value;
}

function requiredMetadata(passage: MemoryPassage, key: string): string {
  const value = metadataValue(passage, key);
  if (value === undefined) throw new Error(`memory transcode archive is missing ${key}`);
  return value;
}

function assertArchiveVersion(passage: MemoryPassage): void {
  if (metadataValue(passage, ARCHIVE_VERSION_KEY) !== MEMORY_TRANSCODE_VERSION) {
    throw new Error("memory transcode archive version is unsupported");
  }
}

function asHarness(value: string | undefined): MemoryTranscodeHarness | null {
  return value === CLAUDE_CODE_MEMORY_HARNESS || value === CODEX_MEMORY_HARNESS
    ? value
    : null;
}

function parseBoundedInteger(
  value: string | undefined,
  label: string,
  maximum: number,
): number {
  const parsed = value === undefined ? NaN : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error(`memory transcode archive ${label} is invalid`);
  }
  return parsed;
}

type PathStatus = "missing" | "directory" | "symlink" | "other";

async function pathStatus(path: string): Promise<PathStatus> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return "symlink";
    if (info.isDirectory()) return "directory";
    return "other";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    throw error;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, fsConstants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function unlinkQuietly(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function rmdirQuietly(path: string): Promise<void> {
  try {
    await rmdir(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTEMPTY") throw error;
  }
}
