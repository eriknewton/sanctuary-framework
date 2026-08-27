/**
 * Claude Code memory-file adapter for the SDW memory backend.
 *
 * Rung-1 posture: this is a non-destructive mirror. Claude Code keeps reading
 * and writing its own plaintext files; Sanctuary reads a snapshot into the
 * encrypted SDW vault and can emit those exact bytes to an operator-named
 * output directory. There is no watcher, no automatic propagation, and no
 * live harness write path here.
 */

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { link, mkdir, open, readdir, stat, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";

import { isSdwIdentifier } from "../grammar.js";
import { fileImportIngress } from "../memory-provenance-ingress.js";
import type { SdwDocumentMetadata } from "../records.js";
import type {
  MemoryBackendAdapter,
  MemoryPassage,
  MemoryPassageInput,
} from "./memory-backend.js";
import {
  screenMemoryFileEntries,
  type MemoryFileOverride,
  type MemoryFileScreenOutcome,
  type MemoryFileSkip,
} from "./memory-file-allow-list.js";

/** No paths allow-listed: every call site that omits `allowFiles` gets this. */
const EMPTY_ALLOW_FILES: ReadonlySet<string> = new Set();

export const CLAUDE_CODE_MEMORY_HARNESS = "claude-code" as const;
export const CLAUDE_CODE_MEMORY_INGRESS = "file_import" as const;
export const CLAUDE_CODE_MEMORY_INDEX = "MEMORY.md" as const;

/**
 * Passage-id domain for Claude Code memory files. FROZEN: the id is a keyed
 * digest over this domain plus the source path, and re-ingest depends on
 * landing on the same id, so changing the string orphans every mirrored
 * passage and silently doubles the vault on the next run.
 */
export const CLAUDE_CODE_MEMORY_PASSAGE_DOMAIN = "cc-memory-file-v1" as const;

export type ClaudeCodeMemorySourceClass = "index" | "fact";

/**
 * Passage fields for one memory file, WITHOUT the passage id. The id is a
 * fortress-keyed digest only the backend can compute (see
 * MemoryBackendAdapter.derivePassageId), because the natural id, the file name,
 * would publish the operator's memory topics as cleartext directory entries.
 */
export type ClaudeCodeMemoryPassageDraft = Omit<MemoryPassageInput, "passage_id">;

export interface ClaudeCodeMemoryEntry {
  readonly source_path: string;
  readonly source_class: ClaudeCodeMemorySourceClass;
  readonly text: string;
  readonly passage_input: ClaudeCodeMemoryPassageDraft;
}

export interface ClaudeCodeMemorySnapshot {
  readonly root_dir: string;
  readonly entries: readonly ClaudeCodeMemoryEntry[];
}

export interface ReadClaudeCodeMemoryOptions {
  /** Injectable timestamp for deterministic tests. */
  readonly ingestedAt?: string;
}

/** One source file the write gate refused, named so the operator can act on it. */
export type ClaudeCodeMemorySkip = MemoryFileSkip;

/**
 * One source file the classifier would have refused, ingested anyway because
 * the operator named it on `--allow-file` / `allow_files` (Rung-1 point 3).
 */
export type ClaudeCodeMemoryOverride = MemoryFileOverride;

export interface IngestClaudeCodeMemoryResult {
  readonly ingested: readonly MemoryPassage[];
  /**
   * Files present in the source directory that were NOT mirrored. A non-empty
   * list means the vault holds a PARTIAL mirror; callers must surface it rather
   * than report a file count that looks like success.
   */
  readonly skipped: readonly ClaudeCodeMemorySkip[];
  /**
   * Files the classifier refused but that WERE mirrored because the operator
   * allow-listed that exact path. Disjoint from `skipped`: an overridden file
   * is not also counted as skipped, and `complete` below does not count it as
   * incomplete.
   */
  readonly overridden: readonly ClaudeCodeMemoryOverride[];
  /**
   * Allow-listed paths that were never a classifier refusal (nothing was
   * waived for them) -- surfaced so a stale allow-file entry is visible.
   */
  readonly unused_allow_files: readonly string[];
  /** Markdown files found in the source directory (ingested + skipped). */
  readonly source_file_count: number;
  /** True only when every source file was mirrored (overrides count as mirrored). */
  readonly complete: boolean;
}

export interface EmitClaudeCodeMemoryResult {
  readonly emitted: readonly {
    readonly passage_id: string;
    readonly source_path: string;
  }[];
  /** True when the emitted tree includes the Claude Code index file. */
  readonly index_present: boolean;
}

const DIGEST_HEX_CHARS = 16; // 16 hex chars = 64 bits of collision suffix.
const MAX_IDENTIFIER_COMPONENT_CHARS = 96;
const MARKDOWN_EXTENSION = ".md";
const UTF8_ENCODING = "utf8";
const EMIT_TEMP_SUFFIX_BYTES = 8;
/** Taint asserted for every mirrored memory file; these are operator notes. */
const CLAUDE_CODE_MEMORY_TAINT = "user_content" as const;

function nowIso(): string {
  return new Date().toISOString();
}

export async function readClaudeCodeMemoryDirectory(
  memoryDir: string,
  options: ReadClaudeCodeMemoryOptions = {},
): Promise<ClaudeCodeMemorySnapshot> {
  const rootDir = resolve(memoryDir);
  const rootStat = await stat(rootDir);
  if (!rootStat.isDirectory()) {
    throw new Error(`Claude Code memory path is not a directory: ${memoryDir}`);
  }

  const dirents = await readdir(rootDir, { withFileTypes: true });
  const markdownFiles = dirents
    .filter((entry) => entry.isFile() && entry.name.endsWith(MARKDOWN_EXTENSION))
    .map((entry) => entry.name)
    .sort(compareClaudeCodeMemoryFiles);

  if (!markdownFiles.includes(CLAUDE_CODE_MEMORY_INDEX)) {
    throw new Error(`Claude Code memory directory is missing ${CLAUDE_CODE_MEMORY_INDEX}`);
  }

  const rawFiles = new Map<string, string>();
  for (const filename of markdownFiles) {
    assertSafeClaudeCodeRelativePath(filename);
    const bytes = await readRegularFileNoSymlink(join(rootDir, filename));
    rawFiles.set(filename, bytesToUtf8Text(filename, bytes));
  }

  const indexText = rawFiles.get(CLAUDE_CODE_MEMORY_INDEX)!;
  const indexMembership = parseIndexMembership(indexText);
  const ingestedAt = options.ingestedAt ?? nowIso();
  const entries: ClaudeCodeMemoryEntry[] = [];

  for (const filename of markdownFiles) {
    const text = rawFiles.get(filename)!;
    if (filename === CLAUDE_CODE_MEMORY_INDEX) {
      entries.push(buildEntry({
        relativePath: filename,
        sourceClass: "index",
        text,
        ingestedAt,
        indexMembership,
      }));
      continue;
    }

    const frontmatter = parseFrontmatter(text);
    entries.push(buildEntry({
      relativePath: filename,
      sourceClass: "fact",
      text,
      ingestedAt,
      indexMembership,
      frontmatter,
    }));
  }

  return { root_dir: rootDir, entries };
}

export interface IngestClaudeCodeMemoryOptions {
  /**
   * Rung-1 point 3: source paths (bare filenames, exact match, no globs or
   * directories) the operator explicitly named to ingest as-is even if the
   * secret classifier would refuse them. Unknown paths are a thrown error, not
   * a silent no-op (see assertAllowFilesKnown). Never a global switch: a path
   * absent from this set is screened exactly as before.
   */
  readonly allowFiles?: ReadonlySet<string>;
}

export async function ingestClaudeCodeMemoryDirectory(
  adapter: MemoryBackendAdapter,
  memoryDir: string,
  options: ReadClaudeCodeMemoryOptions & IngestClaudeCodeMemoryOptions = {},
): Promise<IngestClaudeCodeMemoryResult> {
  const snapshot = await readClaudeCodeMemoryDirectory(memoryDir, options);
  return ingestClaudeCodeMemorySnapshot(adapter, snapshot, options);
}

/**
 * Mirror a snapshot into the vault as one verified unit, skipping (and
 * reporting) any individual file the SDW write gate refuses.
 *
 * Two properties this function must keep, both learned from real large memory
 * directories in which the secret classifier refused files. Concrete
 * measurement, 2026-08-12: readClaudeCodeMemoryDirectory plus
 * SdwMemoryBackendAdapter.screenPassage over a real Claude Code memory
 * directory refused 36 of 438 markdown files (8.2%) on the pre-fix gate. Of
 * those, 26 contained only protected-concept names; the shape-based gate
 * refuses 10 of 438 (2.3%), all through token/entropy checks, and accepts
 * MEMORY.md. The measurement collected counts and detector classes only.
 *
 *  - A refused file is a REPORTED SKIP, never a whole-run abort. It is also
 *    never an implicit exemption: the same gate still runs on everything
 *    written, and the refused bytes never reach the vault UNLESS the operator
 *    named that exact source path on `options.allowFiles` (Rung-1 point 3),
 *    in which case it is a REPORTED OVERRIDE, not a skip, and the refusal
 *    metadata (detector, line) is retained in the result and the caller's
 *    audit record rather than discarded.
 *  - A thrown storage failure must either restore the owner scope to its
 *    pre-write state or surface partial_scope. A run that committed a prefix
 *    and then threw left a vault that could not be re-imported (every committed
 *    id collides) and could not be told apart from a complete one.
 *
 * Re-ingest of a changed directory REPLACES the prior passages in place: ids
 * are derived from the source path, so the mirror tracks the source instead of
 * failing on its own previous run.
 */
/**
 * Preflight-only phase (2026-08-22): resolve accept /
 * skip / override for every entry WITHOUT writing anything to the vault. The
 * CLI/MCP callers durably audit each override BEFORE calling
 * commitClaudeCodeMemorySnapshot below, so a crash between screening and
 * commit leaves no committed content whose waiver was never recorded.
 */
export interface ClaudeCodeMemoryScreenResult {
  readonly outcome: MemoryFileScreenOutcome;
  readonly source_file_count: number;
}

export function screenClaudeCodeMemorySnapshot(
  adapter: MemoryBackendAdapter,
  snapshot: ClaudeCodeMemorySnapshot,
  options: IngestClaudeCodeMemoryOptions = {},
): ClaudeCodeMemoryScreenResult {
  const allowFiles = options.allowFiles ?? EMPTY_ALLOW_FILES;
  const entries = snapshot.entries.map((entry) => ({
    sourcePath: entry.source_path,
    input: {
      ...entry.passage_input,
      provenanceContext: fileImportIngress(
        "system:claude-code-memory-import",
        entry.source_class === "index" ? "claude_code_index" : "claude_code_fact",
      ),
      passage_id: passageIdForClaudeCodeMemoryFile(
        adapter,
        entry.source_class,
        entry.source_path,
      ),
    },
  }));
  // applyBareCredentialFallback=true (threaded through screenMemoryFileEntries):
  // a raw Claude Code memory file has no other backstop (both this ingest and
  // the write below tag it "user_content").
  const outcome = screenMemoryFileEntries(adapter, entries, CLAUDE_CODE_MEMORY_TAINT, allowFiles);
  return { outcome, source_file_count: snapshot.entries.length };
}

/**
 * Commit phase: persist the ALREADY-screened batch. Callers that need the
 * override-record-before-commit ordering call
 * screenClaudeCodeMemorySnapshot, durably audit `screened.outcome.overridden`
 * themselves, and only then call this.
 */
export async function commitClaudeCodeMemorySnapshot(
  adapter: MemoryBackendAdapter,
  screened: ClaudeCodeMemoryScreenResult,
): Promise<IngestClaudeCodeMemoryResult> {
  const ingested = await adapter.putPassages(screened.outcome.accepted, CLAUDE_CODE_MEMORY_TAINT, true);
  return {
    ingested,
    skipped: screened.outcome.skipped,
    overridden: screened.outcome.overridden,
    unused_allow_files: screened.outcome.unused_allow_files,
    source_file_count: screened.source_file_count,
    complete: screened.outcome.skipped.length === 0,
  };
}

/**
 * Convenience composition of screen + commit for callers that do not need
 * the override-record-before-commit ordering (e.g. direct adapter-level
 * tests). The CLI and MCP memory_ingest surfaces do NOT use this: see
 * screenClaudeCodeMemorySnapshot/commitClaudeCodeMemorySnapshot above.
 */
export async function ingestClaudeCodeMemorySnapshot(
  adapter: MemoryBackendAdapter,
  snapshot: ClaudeCodeMemorySnapshot,
  options: IngestClaudeCodeMemoryOptions = {},
): Promise<IngestClaudeCodeMemoryResult> {
  return commitClaudeCodeMemorySnapshot(
    adapter,
    screenClaudeCodeMemorySnapshot(adapter, snapshot, options),
  );
}

/**
 * Page through the whole owner scope via the `after` cursor. listPassages
 * caps decrypt work to a bounded per-call scan (LD4 SDW-SEARCH-DOS-01); an
 * export must see the WHOLE vault, so it pages explicitly instead of relying
 * on one call to return everything, which would silently under-export a
 * vault larger than the per-call cap.
 */
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

export async function emitClaudeCodeMemoryDirectory(
  adapter: MemoryBackendAdapter,
  outputDir: string,
): Promise<EmitClaudeCodeMemoryResult> {
  const rootDir = resolve(outputDir);
  const passages = (await listAllPassages(adapter))
    .filter(isClaudeCodeMemoryPassage)
    .sort(compareClaudeCodePassagesForEmit);

  await mkdir(rootDir, { recursive: true, mode: 0o700 });

  const targets = passages.map((passage) => {
    const relativePath = metadataValue(passage, "source_path");
    if (relativePath === undefined) {
      throw new Error(`Claude Code memory passage ${passage.passage_id} has no source_path`);
    }
    assertSafeClaudeCodeRelativePath(relativePath);
    const target = resolve(rootDir, relativePath);
    assertTargetInsideRoot(rootDir, target);
    return { passage, relativePath, target };
  });

  for (const item of targets) {
    if (await pathExists(item.target)) {
      throw new Error(
        `Refusing to overwrite existing Claude Code memory file: ${item.relativePath}`,
      );
    }
  }

  // Crash atomicity and failure cleanup. Writing straight into the final name
  // has two failure modes an operator cannot see: a crash mid-write leaves a
  // TRUNCATED file that reads as a complete memory file, and a mid-run error
  // leaves earlier files behind, after which the overwrite refusal above blocks
  // every retry. Each file is therefore written to a temp name, fsync'd, and
  // link()ed into place (link still fails if the target exists), and anything
  // this run created is removed if any later file fails.
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
        // Durability before the name exists: after the link below, a reader that
        // sees the file must see all of its bytes.
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
    source_path: item.relativePath,
  }));
  return {
    emitted,
    index_present: emitted.some((item) => item.source_path === CLAUDE_CODE_MEMORY_INDEX),
  };
}

/**
 * Stable vault id for one memory file.
 *
 * Two properties, both required:
 *  - Stable across runs, so re-ingesting a changed file REPLACES its passage
 *    instead of colliding with the previous run's.
 *  - Opaque on disk. The id ends up in a storage key, and the filesystem
 *    backend turns a storage key into a directory entry name, so deriving it
 *    from the file name would publish the operator's memory topics in
 *    cleartext next to the encrypted bodies. The readable name lives only in
 *    the encrypted record metadata; the id is a fortress-keyed digest.
 */
export function passageIdForClaudeCodeMemoryFile(
  adapter: MemoryBackendAdapter,
  sourceClass: ClaudeCodeMemorySourceClass,
  sourcePath: string,
): string {
  return adapter.derivePassageId(
    CLAUDE_CODE_MEMORY_PASSAGE_DOMAIN,
    `${sourceClass}\n${sourcePath}`,
  );
}

function buildEntry(input: {
  readonly relativePath: string;
  readonly sourceClass: ClaudeCodeMemorySourceClass;
  readonly text: string;
  readonly ingestedAt: string;
  readonly indexMembership: ReadonlyMap<string, readonly string[]>;
  readonly frontmatter?: ParsedFrontmatter;
}): ClaudeCodeMemoryEntry {
  const sourceName = input.frontmatter?.root.name ?? basename(input.relativePath, MARKDOWN_EXTENSION);
  const metadata: SdwDocumentMetadata[] = [
    { key: "origin_harness", value: CLAUDE_CODE_MEMORY_HARNESS },
    { key: "ingress", value: CLAUDE_CODE_MEMORY_INGRESS },
    { key: "source_class", value: input.sourceClass },
    { key: "source_path", value: input.relativePath },
    { key: "source_name", value: sourceName },
    { key: "ingested_at", value: input.ingestedAt },
  ];

  for (const [key, value] of Object.entries(input.frontmatter?.root ?? {})) {
    metadata.push({ key: `frontmatter.${identifierComponent(key)}`, value });
  }
  for (const [key, value] of Object.entries(input.frontmatter?.metadata ?? {})) {
    metadata.push({ key: `frontmatter.metadata.${identifierComponent(key)}`, value });
  }

  const tags = new Set<string>([
    CLAUDE_CODE_MEMORY_HARNESS,
    `ingress:${CLAUDE_CODE_MEMORY_INGRESS}`,
    `source_class:${input.sourceClass}`,
    `ingested_at:${identifierComponent(input.ingestedAt)}`,
  ]);
  if (input.sourceClass === "fact") tags.add("index_member");
  for (const section of input.indexMembership.get(input.relativePath) ?? []) {
    tags.add(`section:${identifierComponent(section)}`);
  }

  return {
    source_path: input.relativePath,
    source_class: input.sourceClass,
    text: input.text,
    passage_input: {
      text: input.text,
      tags: [...tags],
      metadata,
      created_at: input.ingestedAt,
    },
  };
}

interface ParsedFrontmatter {
  readonly root: Record<string, string>;
  readonly metadata: Record<string, string>;
}

function parseFrontmatter(text: string): ParsedFrontmatter {
  const root: Record<string, string> = {};
  const metadata: Record<string, string> = {};
  const lines = text.split(/\r?\n/);
  if (lines[0] !== "---") return { root, metadata };

  let inMetadata = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === "---") break;
    if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;

    const nested = /^ {2}([A-Za-z0-9_.:@+-]+):(?:\s*(.*))?$/.exec(line);
    if (nested && inMetadata) {
      metadata[nested[1]!] = parseYamlScalar(nested[2] ?? "");
      continue;
    }

    const rootMatch = /^([A-Za-z0-9_.:@+-]+):(?:\s*(.*))?$/.exec(line);
    if (!rootMatch) continue;
    const key = rootMatch[1]!;
    const value = rootMatch[2] ?? "";
    inMetadata = key === "metadata" && value.trim().length === 0;
    if (!inMetadata) root[key] = parseYamlScalar(value);
  }

  return { root, metadata };
}

function parseYamlScalar(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return "";
  if (
    (trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    const body = trimmed.slice(1, -1);
    return trimmed.startsWith("\"")
      ? body.replace(/\\"/g, "\"").replace(/\\\\/g, "\\")
      : body.replace(/''/g, "'");
  }
  return trimmed;
}

function parseIndexMembership(indexText: string): ReadonlyMap<string, readonly string[]> {
  const out = new Map<string, string[]>();
  let currentSection = "index";
  for (const line of indexText.split(/\r?\n/)) {
    const heading = /^##\s+(.+?)\s*$/.exec(line);
    if (heading) {
      currentSection = heading[1]!;
      continue;
    }

    const links = line.matchAll(/\[[^\]]+\]\(([^)]+\.md)\)/g);
    for (const link of links) {
      const rawTarget = link[1]!;
      if (rawTarget === CLAUDE_CODE_MEMORY_INDEX) continue;
      if (!isSafeClaudeCodeRelativePath(rawTarget)) continue;
      const existing = out.get(rawTarget) ?? [];
      existing.push(currentSection);
      out.set(rawTarget, existing);
    }
  }
  return out;
}

function isClaudeCodeMemoryPassage(passage: MemoryPassage): boolean {
  return (
    metadataValue(passage, "origin_harness") === CLAUDE_CODE_MEMORY_HARNESS &&
    metadataValue(passage, "ingress") === CLAUDE_CODE_MEMORY_INGRESS &&
    metadataValue(passage, "source_path") !== undefined
  );
}

function compareClaudeCodeMemoryFiles(a: string, b: string): number {
  if (a === CLAUDE_CODE_MEMORY_INDEX) return -1;
  if (b === CLAUDE_CODE_MEMORY_INDEX) return 1;
  return a.localeCompare(b);
}

function compareClaudeCodePassagesForEmit(a: MemoryPassage, b: MemoryPassage): number {
  const aPath = metadataValue(a, "source_path") ?? "";
  const bPath = metadataValue(b, "source_path") ?? "";
  return compareClaudeCodeMemoryFiles(aPath, bPath);
}

function metadataValue(passage: MemoryPassage, key: string): string | undefined {
  return passage.metadata.find((entry) => entry.key === key)?.value;
}

function identifierComponent(value: string): string {
  const ascii = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^A-Za-z0-9._:@+-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, MAX_IDENTIFIER_COMPONENT_CHARS);
  const safe = ascii.length > 0 ? ascii : "unnamed";
  const candidate = safe.toLowerCase();
  return isSdwIdentifier(candidate) ? candidate : `id-${digestHex(value)}`;
}

function digestHex(value: string): string {
  return createHash("sha256").update(value, UTF8_ENCODING).digest("hex").slice(0, DIGEST_HEX_CHARS);
}

async function readRegularFileNoSymlink(path: string): Promise<Uint8Array> {
  // Read only, and never through a link. The operator names this directory, so
  // a symlink planted inside it must not become a read of some other file: the
  // O_NOFOLLOW open refuses the link atomically rather than after a stat, which
  // closes the check-then-open window. No O_CREAT, no mode: this call creates
  // nothing. CodeQL reads the numeric flag word as a possible write and reports
  // js/insecure-temporary-file here when a caller's directory came from the OS
  // temp dir (test fixtures do); that is the same false positive already
  // dismissed on audit-log.ts's read-only lock inspection.
  const noFollow = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;
  const handle = await open(path, fsConstants.O_RDONLY | noFollow);
  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile()) {
      throw new Error(`Claude Code memory entry is not a regular file: ${path}`);
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
    throw new Error(`Claude Code memory file is not byte-faithful UTF-8: ${filename}`);
  }
  return text;
}

function assertSafeClaudeCodeRelativePath(relativePath: string): void {
  if (!isSafeClaudeCodeRelativePath(relativePath)) {
    throw new Error(`Unsafe Claude Code memory relative path: ${relativePath}`);
  }
}

function isSafeClaudeCodeRelativePath(relativePath: string): boolean {
  return (
    relativePath.length > MARKDOWN_EXTENSION.length &&
    !isAbsolute(relativePath) &&
    !relativePath.includes("/") &&
    !relativePath.includes("\\") &&
    !relativePath.split(/[\\/]/).includes("..") &&
    relativePath.endsWith(MARKDOWN_EXTENSION)
  );
}

function assertTargetInsideRoot(rootDir: string, target: string): void {
  const rootPrefix = rootDir.endsWith(sep) ? rootDir : `${rootDir}${sep}`;
  if (target !== rootDir && !target.startsWith(rootPrefix)) {
    // The source_path metadata came from an encrypted vault record, not the
    // operator's argv, so re-check containment here before any plaintext emit.
    throw new Error("Refusing to emit Claude Code memory outside the output directory");
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
    // Directory fsync is not portable (some platforms reject it outright). The
    // file contents are already fsync'd; this only tightens durability of the
    // directory entry, so a refusal here must not fail the emit.
  }
}

async function unlinkQuietly(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch {
    // Cleanup is best effort; the original failure is what the caller must see.
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
