/**
 * Codex memory-file adapter for the SDW memory backend.
 *
 * Rung-1 posture: this is a manual, non-destructive mirror of the three
 * curated Markdown files under Codex's `memories/` directory. The wider Codex
 * home contains session, telemetry, credential, and SQLite state; this adapter
 * never enumerates or opens that wider surface. There is no watcher, automatic
 * propagation, SQLite ingest, or live harness write path here.
 */

import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { link, lstat, mkdir, open, stat, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";

import type { SdwDocumentMetadata } from "../records.js";
import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemoryPassageInput,
} from "./memory-backend.js";

export const CODEX_MEMORY_HARNESS = "codex" as const;
export const CODEX_MEMORY_INGRESS = "file_import" as const;
export const CODEX_MEMORY_INDEX = "MEMORY.md" as const;
export const CODEX_MEMORY_FILES = [
  CODEX_MEMORY_INDEX,
  "memory_summary.md",
  "raw_memories.md",
] as const;

/**
 * FROZEN once shipped. A distinct domain prevents a Codex MEMORY.md from
 * replacing a Claude Code MEMORY.md in the same owner scope.
 */
export const CODEX_MEMORY_PASSAGE_DOMAIN = "codex-memory-file-v1" as const;

export type CodexMemoryFilename = (typeof CODEX_MEMORY_FILES)[number];
export type CodexMemorySourceClass = "index" | "summary" | "raw";
export type CodexMemoryPassageDraft = Omit<MemoryPassageInput, "passage_id">;

export interface CodexMemoryEntry {
  readonly source_path: CodexMemoryFilename;
  readonly source_class: CodexMemorySourceClass;
  readonly text: string;
  readonly passage_input: CodexMemoryPassageDraft;
}

export interface CodexMemorySnapshot {
  /** Resolved `memories/` directory, never the wider Codex home. */
  readonly root_dir: string;
  readonly entries: readonly CodexMemoryEntry[];
}

export interface ReadCodexMemoryOptions {
  readonly ingestedAt?: string;
  /** Test seam proving which file bodies were opened. */
  readonly readFile?: (path: string) => Promise<Uint8Array>;
}

export interface CodexMemorySkip {
  readonly source_path: string;
  readonly reason: string;
  readonly detail: string;
}

export interface IngestCodexMemoryResult {
  readonly ingested: readonly MemoryPassage[];
  readonly skipped: readonly CodexMemorySkip[];
  readonly source_file_count: number;
  readonly complete: boolean;
}

export interface EmitCodexMemoryResult {
  readonly emitted: readonly {
    readonly passage_id: string;
    readonly source_path: string;
  }[];
  readonly index_present: boolean;
}

const UTF8_ENCODING = "utf8";
const EMIT_TEMP_SUFFIX_BYTES = 8;
const CODEX_MEMORY_TAINT = "user_content" as const;

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Accept either the Codex home or its `memories/` directory. Resolution probes
 * only the literal child name and the three allowlisted filenames; it never
 * enumerates the Codex home.
 */
export async function resolveCodexMemoryDirectory(inputDir: string): Promise<string> {
  const rootDir = resolve(inputDir);
  await assertDirectoryNoSymlink(rootDir, `Codex memory path is not a directory: ${inputDir}`);

  const nestedDir = join(rootDir, "memories");
  const nestedStatus = await entryStatus(nestedDir);
  if (nestedStatus === "symlink") {
    throw new Error(`Refusing symlinked Codex memories directory: ${nestedDir}`);
  }
  if (nestedStatus === "other") {
    throw new Error(`Codex memories path is not a directory: ${nestedDir}`);
  }

  const looseAllowed = await Promise.all(
    CODEX_MEMORY_FILES.map((filename) => entryStatus(join(rootDir, filename))),
  );
  const hasLooseAllowed = looseAllowed.some((status) => status !== "missing");

  if (nestedStatus === "directory") {
    if (hasLooseAllowed) {
      throw new Error(
        "Ambiguous Codex memory path: allowlisted files exist both beside and inside memories/",
      );
    }
    return nestedDir;
  }

  if (!hasLooseAllowed) {
    throw new Error(
      `Codex memory path contains neither memories/ nor ${CODEX_MEMORY_INDEX}: ${inputDir}`,
    );
  }
  return rootDir;
}

export async function readCodexMemoryDirectory(
  inputDir: string,
  options: ReadCodexMemoryOptions = {},
): Promise<CodexMemorySnapshot> {
  const rootDir = await resolveCodexMemoryDirectory(inputDir);
  const readFile = options.readFile ?? readRegularFileNoSymlink;
  const ingestedAt = options.ingestedAt ?? nowIso();
  const entries: CodexMemoryEntry[] = [];

  for (const filename of CODEX_MEMORY_FILES) {
    const path = join(rootDir, filename);
    const status = await entryStatus(path);
    if (status === "missing") continue;
    if (status !== "file") {
      throw new Error(`Codex memory entry is not a regular file: ${path}`);
    }
    const text = bytesToUtf8Text(filename, await readFile(path));
    const sourceClass = sourceClassFor(filename);
    entries.push(buildEntry(filename, sourceClass, text, ingestedAt));
  }

  if (!entries.some((entry) => entry.source_path === CODEX_MEMORY_INDEX)) {
    throw new Error(`Codex memory directory is missing ${CODEX_MEMORY_INDEX}`);
  }

  return { root_dir: rootDir, entries };
}

export async function ingestCodexMemoryDirectory(
  adapter: MemoryBackendAdapter,
  memoryDir: string,
  options: ReadCodexMemoryOptions = {},
): Promise<IngestCodexMemoryResult> {
  return ingestCodexMemorySnapshot(adapter, await readCodexMemoryDirectory(memoryDir, options));
}

export async function ingestCodexMemorySnapshot(
  adapter: MemoryBackendAdapter,
  snapshot: CodexMemorySnapshot,
): Promise<IngestCodexMemoryResult> {
  const accepted: MemoryPassageInput[] = [];
  const skipped: CodexMemorySkip[] = [];

  for (const entry of snapshot.entries) {
    const input: MemoryPassageInput = {
      ...entry.passage_input,
      passage_id: passageIdForCodexMemoryFile(
        adapter,
        entry.source_class,
        entry.source_path,
      ),
    };
    const screen = adapter.screenPassage(input, CODEX_MEMORY_TAINT);
    if (!screen.ok) {
      skipped.push({
        source_path: entry.source_path,
        reason: screen.category,
        detail: screen.message,
      });
      continue;
    }
    accepted.push(input);
  }

  const ingested = await adapter.putPassages(accepted, CODEX_MEMORY_TAINT);
  return {
    ingested,
    skipped,
    source_file_count: snapshot.entries.length,
    complete: skipped.length === 0,
  };
}

export async function emitCodexMemoryDirectory(
  adapter: MemoryBackendAdapter,
  outputDir: string,
): Promise<EmitCodexMemoryResult> {
  const rootDir = resolve(outputDir);
  const passages = (await listAllPassages(adapter))
    .filter(isCodexMemoryPassage)
    .sort(compareCodexPassagesForEmit);

  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const targets = passages.map((passage) => {
    const sourcePath = metadataValue(passage, "source_path");
    if (!isCodexMemoryFilename(sourcePath)) {
      throw new Error(`Codex memory passage ${passage.passage_id} has invalid source_path`);
    }
    const target = resolve(rootDir, sourcePath);
    assertTargetInsideRoot(rootDir, target);
    return { passage, sourcePath, target };
  });

  for (const item of targets) {
    if (await pathExists(item.target)) {
      throw new Error(`Refusing to overwrite existing Codex memory file: ${item.sourcePath}`);
    }
  }

  const created: string[] = [];
  let pendingTemp: string | null = null;
  try {
    for (const item of targets) {
      const targetDir = dirname(item.target);
      await mkdir(targetDir, { recursive: true, mode: 0o700 });
      const tempPath = join(
        targetDir,
        `.${basename(item.target)}.${randomBytes(EMIT_TEMP_SUFFIX_BYTES).toString("hex")}.tmp`,
      );
      pendingTemp = tempPath;
      const handle = await open(
        tempPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
      try {
        await handle.writeFile(Buffer.from(item.passage.text, UTF8_ENCODING));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await link(tempPath, item.target);
      created.push(item.target);
      await unlink(tempPath);
      pendingTemp = null;
      await syncDirectory(targetDir);
    }
  } catch (error) {
    if (pendingTemp !== null) await unlinkQuietly(pendingTemp);
    for (const path of [...created].reverse()) await unlinkQuietly(path);
    throw error;
  }

  const emitted = targets.map((item) => ({
    passage_id: item.passage.passage_id,
    source_path: item.sourcePath,
  }));
  return {
    emitted,
    index_present: emitted.some((item) => item.source_path === CODEX_MEMORY_INDEX),
  };
}

export function passageIdForCodexMemoryFile(
  adapter: MemoryBackendAdapter,
  sourceClass: CodexMemorySourceClass,
  sourcePath: CodexMemoryFilename,
): string {
  return adapter.derivePassageId(
    CODEX_MEMORY_PASSAGE_DOMAIN,
    `${sourceClass}\n${sourcePath}`,
  );
}

function buildEntry(
  sourcePath: CodexMemoryFilename,
  sourceClass: CodexMemorySourceClass,
  text: string,
  ingestedAt: string,
): CodexMemoryEntry {
  const metadata: SdwDocumentMetadata[] = [
    { key: "origin_harness", value: CODEX_MEMORY_HARNESS },
    { key: "ingress", value: CODEX_MEMORY_INGRESS },
    { key: "source_class", value: sourceClass },
    { key: "source_path", value: sourcePath },
    { key: "source_name", value: basename(sourcePath, ".md") },
    { key: "ingested_at", value: ingestedAt },
  ];
  return {
    source_path: sourcePath,
    source_class: sourceClass,
    text,
    passage_input: {
      text,
      tags: [
        CODEX_MEMORY_HARNESS,
        `ingress:${CODEX_MEMORY_INGRESS}`,
        `source_class:${sourceClass}`,
        `ingested_at:${ingestedAt}`,
      ],
      metadata,
      created_at: ingestedAt,
    },
  };
}

function sourceClassFor(filename: CodexMemoryFilename): CodexMemorySourceClass {
  if (filename === CODEX_MEMORY_INDEX) return "index";
  if (filename === "memory_summary.md") return "summary";
  return "raw";
}

function isCodexMemoryFilename(value: string | undefined): value is CodexMemoryFilename {
  return CODEX_MEMORY_FILES.includes(value as CodexMemoryFilename);
}

function isCodexMemoryPassage(passage: MemoryPassage): boolean {
  return (
    metadataValue(passage, "origin_harness") === CODEX_MEMORY_HARNESS &&
    metadataValue(passage, "ingress") === CODEX_MEMORY_INGRESS &&
    isCodexMemoryFilename(metadataValue(passage, "source_path"))
  );
}

function compareCodexPassagesForEmit(a: MemoryPassage, b: MemoryPassage): number {
  const aPath = metadataValue(a, "source_path");
  const bPath = metadataValue(b, "source_path");
  return CODEX_MEMORY_FILES.indexOf(aPath as CodexMemoryFilename) -
    CODEX_MEMORY_FILES.indexOf(bPath as CodexMemoryFilename);
}

function metadataValue(passage: MemoryPassage, key: string): string | undefined {
  return passage.metadata.find((entry) => entry.key === key)?.value;
}

async function listAllPassages(adapter: MemoryBackendAdapter): Promise<readonly MemoryPassage[]> {
  const all: MemoryPassage[] = [];
  let after: string | undefined;
  for (;;) {
    const page = await adapter.listPassages({ after });
    if (page.length === 0) break;
    all.push(...page);
    after = page[page.length - 1]?.passage_id;
  }
  return all;
}

type EntryStatus = "missing" | "file" | "directory" | "symlink" | "other";

async function entryStatus(path: string): Promise<EntryStatus> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return "symlink";
    if (info.isFile()) return "file";
    if (info.isDirectory()) return "directory";
    return "other";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    throw error;
  }
}

async function assertDirectoryNoSymlink(path: string, message: string): Promise<void> {
  const status = await entryStatus(path);
  if (status !== "directory") throw new Error(message);
}

/** Internal testable boundary for the platform-level no-follow requirement. */
export function requireCodexNoFollowFlag(value: unknown): number {
  if (typeof value !== "number" || value === 0) {
    throw new Error("Codex memory ingest requires O_NOFOLLOW support");
  }
  return value;
}

async function readRegularFileNoSymlink(path: string): Promise<Uint8Array> {
  // Fail closed on a platform that cannot make the final-component symlink
  // refusal atomic. Falling back to zero turns the preceding lstat into a
  // check-then-open race: an attacker could replace an allowlisted memory file
  // with a symlink between those calls and redirect the read outside memories/.
  const noFollow = requireCodexNoFollowFlag(fsConstants.O_NOFOLLOW);
  // Read only. No O_CREAT or write flag is present. The explicit O_NOFOLLOW is
  // the security boundary for a final-component swap, including when a test
  // fixture lives under the operating system's temporary directory.
  const handle = await open(path, fsConstants.O_RDONLY | noFollow);
  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile()) {
      throw new Error(`Codex memory entry is not a regular file: ${path}`);
    }
    const buffer = await handle.readFile();
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } finally {
    await handle.close();
  }
}

function bytesToUtf8Text(filename: string, bytes: Uint8Array): string {
  const text = Buffer.from(bytes).toString(UTF8_ENCODING);
  if (!Buffer.from(text, UTF8_ENCODING).equals(Buffer.from(bytes))) {
    throw new Error(`Codex memory file is not byte-faithful UTF-8: ${filename}`);
  }
  return text;
}

function assertTargetInsideRoot(rootDir: string, target: string): void {
  const rootPrefix = rootDir.endsWith(sep) ? rootDir : `${rootDir}${sep}`;
  if (target !== rootDir && !target.startsWith(rootPrefix)) {
    throw new Error("Refusing to emit Codex memory outside the output directory");
  }
}

async function syncDirectory(path: string): Promise<void> {
  try {
    const handle = await open(path, fsConstants.O_RDONLY);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Directory fsync is not portable. File bytes are already durable.
  }
}

async function unlinkQuietly(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch {
    // Cleanup is best effort; preserve the original error.
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}
