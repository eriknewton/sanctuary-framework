/**
 * Sanctuary Wrap — Agent Config Reader
 *
 * Detects and reads MCP server configurations from various agent platforms.
 * Supports: OpenClaw, Claude Code, Cursor, Cline, Mastra, and generic MCP config files.
 *
 * Security invariant: Never modifies configs without explicit request.
 * All original configs are backed up before any modification.
 */

import {
  mkdir,
  realpath,
  open,
  lstat,
  unlink,
  readdir,
  rename,
  link,
} from "node:fs/promises";
import { constants as fsConstants, type Stats } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join, extname, resolve, dirname, basename, sep } from "node:path";
import { homedir } from "node:os";
import { resolveStoragePath } from "../paths.js";
import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";
import { detectHarnessSchema } from "./harness-schema.js";
import { hermesConfigYamlPath } from "./hermes-yaml.js";

// ── Types ───────────────────────────────────────────────────────────

export type AgentPlatform =
  | "openclaw"
  | "claude-code"
  | "cursor"
  | "hermes"
  | "mastra"
  | "cline"
  | "generic";

export interface MCPServerEntry {
  /** Human-readable name for this server */
  name: string;
  /** Transport type */
  transport: "stdio" | "sse";
  /** For stdio: the command to run */
  command?: string;
  /** For stdio: command arguments */
  args?: string[];
  /** For SSE: the server URL */
  url?: string;
  /** Environment variables */
  env?: Record<string, string>;
}

export interface AgentConfig {
  platform: AgentPlatform;
  configPath: string;
  servers: MCPServerEntry[];
  rawConfig: unknown;
}

// ── Platform Paths ──────────────────────────────────────────────────

// Iteration order = auto-detect priority. OpenClaw first (primary dogfood),
// Hermes second (v1.0 secondary per README agent-installable rewrite),
// Cline third (VS Code extension), Claude Code + Cursor trail. `generic` is
// the catch-all with no paths.
//
// Computed lazily from the current homedir() on every call so sandboxed /
// multi-tenant callers that reassign `process.env.HOME` at runtime get the
// paths rooted at their current HOME. Matches the pattern of
// `resolveStoragePath()` already used elsewhere in the wrap surface.
export function getPlatformPaths(): Record<AgentPlatform, string[]> {
  const home = homedir();
  return {
    "openclaw": [
      join(home, ".openclaw", "openclaw.json"),
      join(home, ".openclaw", "config.json"),
      join(home, "Library", "Application Support", "OpenClaw", "openclaw.json"),
      join(home, "Library", "Application Support", "OpenClaw", "config.json"),
    ],
    // Hermes Agent (NousResearch) canonicals live under ~/.hermes. These
    // JSON paths drive detection (and the upstream-server listing); the
    // MCP surface Hermes v0.16.0 actually loads at runtime is
    // ~/.hermes/config.yaml (`mcp_servers:` key), which the wrap CLI
    // additionally injects via wrap/hermes-yaml.ts (D4 staging, Bug 2).
    // The JSON write is kept for forward-compat with the documented
    // cli-config.json surface.
    "hermes": [
      join(home, ".hermes", "cli-config.json"),
      join(home, ".hermes", "config.json"),
      join(home, ".config", "hermes", "cli-config.json"),
    ],
    // Claude Code's modern canonical surface is ~/.claude.json (`claude mcp
    // add` writes here). The legacy ~/.claude/settings.json shape predates
    // it and is still respected if present. Probe order = preference order:
    // wrap operates on the first one that exists, and bootstraps a fresh
    // ~/.claude.json when neither is present (per the cli.ts bootstrap).
    "claude-code": [
      join(home, ".claude.json"),
      join(home, ".claude", "settings.json"),
      join(home, ".config", "claude-code", "settings.json"),
    ],
    "cursor": [
      join(home, ".cursor", "mcp.json"),
    ],
    // Cline is a VS Code extension (saoudrizwan.claude-dev). Its MCP settings
    // live under the VS Code globalStorage tree, which is OS-specific. We
    // enumerate the three supported OS layouts; at detection time only the
    // one matching the running OS will exist.
    "cline": [
      // macOS
      join(
        home,
        "Library",
        "Application Support",
        "Code",
        "User",
        "globalStorage",
        "saoudrizwan.claude-dev",
        "settings",
        "cline_mcp_settings.json"
      ),
      // Linux
      join(
        home,
        ".config",
        "Code",
        "User",
        "globalStorage",
        "saoudrizwan.claude-dev",
        "settings",
        "cline_mcp_settings.json"
      ),
      // Windows (honour APPDATA when set, otherwise reconstruct under home)
      process.env.APPDATA
        ? join(
            process.env.APPDATA,
            "Code",
            "User",
            "globalStorage",
            "saoudrizwan.claude-dev",
            "settings",
            "cline_mcp_settings.json"
          )
        : join(
            home,
            "AppData",
            "Roaming",
            "Code",
            "User",
            "globalStorage",
            "saoudrizwan.claude-dev",
            "settings",
            "cline_mcp_settings.json"
          ),
    ],
    "mastra": [
      join(home, ".mastra", "mcp.json"),
      join(home, "mastra", "mcp.json"),
      join(home, ".config", "mastra", "mcp.json"),
    ],
    "generic": [],
  };
}

// ── Backup ──────────────────────────────────────────────────────────

/**
 * Resolve the per-tenant backup directory.
 *
 * Multi-tenancy: each Sanctuary instance keeps its backups under its own
 * `SANCTUARY_STORAGE_PATH/backup` so `sanctuary wrap --unwrap` on one
 * agent cannot pick up a meta pointer written by a sibling instance.
 */
function backupDir(): string {
  return join(resolveStoragePath(), "backup");
}

/**
 * Short, stable per-surface tag embedded in backup filenames so backups in
 * the shared per-tenant backup dir can be attributed to the config file
 * they were taken from (2026-07-02 hardening, surface-scoped breadcrumbs).
 * Keyed on the resolve()d source path - the same scoping discipline
 * removeWrapMeta / saveWrapMeta use for the wrap-meta pointer. A content
 * hash would NOT work here: two surfaces can hold identical bytes.
 */
function backupSurfaceTag(originalPath: string): string {
  return createHash("sha256")
    .update(resolve(originalPath))
    .digest("hex")
    .slice(0, 12);
}

/**
 * Back up a config file before modification.
 * Returns the backup path.
 *
 * The backup keeps the source file's extension (D4 staging, Bug 2: the
 * Hermes wrap now also backs up ~/.hermes/config.yaml, and a .yaml backup
 * named .json would mislead manual recovery).
 *
 * 2026-07-02 hardening (surface-scoped breadcrumbs): the filename embeds a
 * short hash of the resolve()d source path
 * (`config-backup-<timestamp>-<surface-tag><ext>`), so consumers that scan
 * the shared backup dir (findNewerBackup) can discriminate by SURFACE
 * instead of by extension alone - two wrapped .json configs previously
 * cross-matched each other's backups. The `config-backup-` prefix and the
 * embedded ISO timestamp (lexical order = chronological order) are
 * unchanged; wrap-meta pointers store the full path, so backups written by
 * earlier releases stay restorable.
 */
export async function backupConfig(configPath: string): Promise<string> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const extension = extname(configPath) || ".json";
  const backupPath = join(
    dir,
    `config-backup-${timestamp}-${backupSurfaceTag(configPath)}${extension}`,
  );
  const data = await readFileCustody(configPath, { verifyPathIdentity: true });
  await writeFileCustody(backupPath, data, { mode: 0o600, createParent: false });
  return backupPath;
}

/**
 * Atomic no-follow write primitive (D4 round-2 P1-A).
 *
 * The round-1 symlink fix lstat()ed the sink and then wrote with
 * writeFile/copyFile — two separate syscalls, so an attacker looping
 * rename+symlink in the config directory could land a symlink between the
 * check and the write and redirect it to an arbitrary victim file (classic
 * TOCTOU). Opening the sink with O_NOFOLLOW makes the refusal atomic: the
 * kernel rejects a symlink at the final path component with ELOOP (POSIX
 * semantics on both Linux and macOS) in the same syscall that would
 * otherwise create/truncate the file. Plan-time lstat checks remain as
 * early courtesy refusals that leave every surface untouched; THIS is the
 * enforcement at the sink.
 */
export async function writeFileNoFollow(
  path: string,
  data: string | Uint8Array,
  mode = 0o600
): Promise<void> {
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        fsConstants.O_NOFOLLOW,
      mode
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(
        `${path} is a symlink; refusing to write through it. ` +
          `Replace the symlink with a regular file and re-run.`,
        { cause: err }
      );
    }
    throw err;
  }
  try {
    await handle.writeFile(data);
  } finally {
    await handle.close();
  }
}

/**
 * The operator HOME, treated as the trusted root for every wrap-module
 * write. Returned resolve()d but NOT realpath-resolved: every wrap sink
 * builds its target from homedir() (e.g. join(homedir(), ".hermes", ...)),
 * so the trusted root must use the same lexical home for the prefix check
 * to hold. The walk only inspects components BELOW this root, so a symlink
 * in the HOME prefix itself (which is operator-owned and trusted) is out of
 * scope by design; the segments wrap actually creates (`.hermes`, the leaf)
 * are the ones an attacker could redirect, and those ARE walked.
 */
function trustedHomeRoot(): string {
  return resolve(homedir());
}

/**
 * Pick the trusted root for an arbitrary write target.
 *
 * Under the operator HOME (the production case — every agent config path is
 * built from homedir()), HOME is the trust anchor and the full
 * `.hermes`/`.claude`-config-dir/leaf chain below it is walked, so a
 * symlinked config DIRECTORY is caught.
 *
 * For a target NOT under HOME (operator- or test-injected custom location,
 * e.g. a tmpdir config path), the anchor is the GRANDPARENT — `dirname` of
 * the leaf's parent — so the leaf's IMMEDIATE parent directory is always
 * walked and a symlinked config dir is still caught. (Anchoring at the leaf's
 * own parent would skip exactly the directory most likely to be the redirect
 * link.) The chain above the grandparent is treated as operator-owned.
 */
function deriveTrustedRoot(targetPath: string): string {
  const home = trustedHomeRoot();
  const resolved = resolve(targetPath);
  if (isWithin(resolved, home)) return home;
  const parent = dirname(resolved);
  const grandparent = dirname(parent);
  // dirname() is idempotent at the filesystem root; fall back to the parent
  // when the target is too shallow to have a distinct grandparent.
  return grandparent === parent ? parent : grandparent;
}

/**
 * D4 round-3 P1-A/B/C — close the WHOLE symlink-redirection class, not just
 * the leaf.
 *
 * `writeFileNoFollow` opens the FINAL path component O_NOFOLLOW, which the
 * kernel honours only for that last component: a symlinked PARENT directory
 * (e.g. `~/.hermes -> /tmp/victim`) is still traversed transparently, so
 * every "hardened" write/restore/mkdir lands wherever the link points. The
 * leaf-only guard cannot see that — only a walk can.
 *
 * This helper lstat()s every component from `trustedRoot` (exclusive) down
 * to the leaf's PARENT (inclusive) and refuses loudly if any is a symlink.
 * The trustedRoot itself is trusted (the operator HOME / agent config dir)
 * and is NOT re-checked. The leaf is intentionally NOT walked here: the
 * caller's O_NOFOLLOW open is the leaf enforcement and closes the
 * final-component leaf-swap TOCTOU window that a pure lstat walk cannot.
 *
 * THREAT-MODEL BOUNDARY (documented honestly, not papered over): between
 * this walk and the caller's subsequent open/mkdir there is a non-atomic
 * window in which a same-privilege attacker who can win the parent-directory
 * race could swap a parent into a symlink. Node exposes no portable
 * openat()/O_NOFOLLOW-per-component primitive to make the parent walk atomic,
 * so we re-walk immediately before the sink to MINIMISE (not eliminate) that
 * window. A same-privilege local attacker racing the parent dir of a
 * single-operator wrap is out of scope; cross-privilege redirection (the
 * actual attack this class represents) is closed because the attacker cannot
 * create a symlink the walk does not see.
 */
/**
 * D4 round-3 P2 (post-merge finding) — the walk→sink path-identity gap.
 *
 * `assertNoSymlinkInPath` lstat-walks `resolve(targetPath)`, but the leaf
 * sinks (`writeFileNoFollow`, `unlink`) historically opened the ORIGINAL,
 * non-normalised `targetPath` string. A target with a `..` AFTER a symlinked
 * component slips through: e.g. `<root>/link/../victim/config.yaml` where
 * `<root>/link -> /outside`. Lexical `resolve()` collapses `link/..` away, so
 * the walk inspects `<root>/victim` (clean, no symlink) — but the kernel
 * resolves `link` to `/outside` FIRST, then applies `..`, so the actual
 * open/unlink syscall lands at `/outside/../victim/config.yaml`. O_NOFOLLOW
 * only guards the final component, never the intermediate `link`.
 *
 * Defence is path identity: every safe sink computes `resolve(targetPath)`
 * ONCE and feeds that single byte-identical value to BOTH the symlink walk
 * AND the syscall, so the kernel acts on exactly the path that was verified.
 * Belt-and-suspenders: this guard additionally REFUSES any target that is not
 * already equal to its own `resolve()` — i.e. carries `..`/`.`/non-normalised
 * segments. wrap never legitimately needs a `..` in a config path, so a
 * non-normalised target is treated as hostile and rejected loudly.
 */
function assertNormalisedTarget(targetPath: string): string {
  const resolved = resolve(targetPath);
  if (targetPath !== resolved) {
    throw new Error(
      `${targetPath} is not a normalised absolute path (resolves to ` +
        `${resolved}); refusing to write through a path containing ` +
        `traversal ('..') or non-normalised segments. A symlinked parent ` +
        `followed by '..' would let the kernel escape the verified prefix.`
    );
  }
  return resolved;
}

async function assertNoSymlinkInPath(
  targetPath: string,
  trustedRoot: string
): Promise<void> {
  const resolved = assertNormalisedTarget(targetPath);
  const root = resolve(trustedRoot);
  if (resolved !== root && !isWithin(resolved, root)) {
    throw new Error(
      `${targetPath} is not under the trusted root ${trustedRoot}; ` +
        `refusing to write through an unverified path.`
    );
  }
  // Components from root (exclusive) down to the leaf's parent (inclusive).
  const rel = resolved.slice(root.length).split(sep).filter(Boolean);
  // Drop the leaf — its no-follow open is the enforcement for that segment.
  rel.pop();
  let cursor = root;
  for (const segment of rel) {
    cursor = join(cursor, segment);
    let stats;
    try {
      stats = await lstat(cursor);
    } catch {
      // Missing ancestor: nothing to follow yet. A later mkdir/open creates
      // it under the verified prefix; re-walk before the sink re-checks.
      return;
    }
    if (stats.isSymbolicLink()) {
      throw new Error(
        `${cursor} is a symlink in the path to ${targetPath}; refusing to ` +
          `write through a symlinked parent directory. Replace the symlink ` +
          `with a regular directory and re-run.`
      );
    }
  }
}

/**
 * mkdir each missing segment from `trustedRoot` down to `dir`, refusing if
 * any EXISTING segment is a symlink (D4 round-3 P2: `mkdir(recursive:true)`
 * follows a symlinked ancestor and creates the tree wherever it points).
 * Each segment is created individually under the just-verified parent
 * instead of letting `recursive:true` walk blindly.
 */
async function mkdirNoFollowUnderRoot(
  dir: string,
  trustedRoot: string,
  mode = 0o700
): Promise<void> {
  // Normalise + reject traversal: the cursor below is rebuilt from `root` plus
  // the resolved segments, so the mkdir syscall already acts on a normalised
  // path; rejecting a non-normalised `dir` keeps the public mkdir sink on the
  // same path-identity discipline as the write/unlink sinks.
  const resolved = assertNormalisedTarget(dir);
  const root = resolve(trustedRoot);
  if (resolved !== root && !isWithin(resolved, root)) {
    throw new Error(
      `${dir} is not under the trusted root ${trustedRoot}; refusing to mkdir.`
    );
  }
  const rel = resolved.slice(root.length).split(sep).filter(Boolean);
  let cursor = root;
  for (const segment of rel) {
    cursor = join(cursor, segment);
    let stats;
    try {
      stats = await lstat(cursor);
    } catch {
      // Missing — create just this segment under the verified parent.
      await mkdir(cursor, { mode });
      continue;
    }
    if (stats.isSymbolicLink()) {
      throw new Error(
        `${cursor} is a symlink in the path to ${dir}; refusing to mkdir ` +
          `through a symlinked parent directory.`
      );
    }
  }
}

/**
 * Symlink-safe write that closes the ENTIRE redirection class (D4 round-3):
 * walk + verify no parent component is a symlink (re-walked here, right
 * before the open, to minimise the parent-race window), recreate any
 * missing parent segments individually under the verified prefix, then open
 * the leaf O_NOFOLLOW so the final component cannot be a swapped-in symlink
 * either. `trustedRoot` defaults to the operator HOME.
 */
export async function writeFileSafeUnderRoot(
  targetPath: string,
  data: string | Uint8Array,
  options: { mode?: number; trustedRoot?: string } = {}
): Promise<void> {
  // Normalise ONCE; both the symlink walk and the leaf open act on this exact
  // byte-identical value so the kernel cannot resolve a different path than
  // the one verified (D4 walk→sink path-identity gap).
  const resolved = assertNormalisedTarget(targetPath);
  const trustedRoot = options.trustedRoot ?? deriveTrustedRoot(resolved);
  await assertNoSymlinkInPath(resolved, trustedRoot);
  await mkdirNoFollowUnderRoot(dirname(resolved), trustedRoot);
  // Re-walk immediately before the open: minimises (does not eliminate, see
  // assertNoSymlinkInPath threat-model note) the walk→open parent window.
  await assertNoSymlinkInPath(resolved, trustedRoot);
  await writeFileNoFollow(resolved, data, options.mode ?? 0o600);
}

/**
 * Symlink-safe unlink (D4 round-3 P1-A): refuse to remove a target reached
 * through a symlinked parent directory before unlinking it. The created-by-
 * wrap unlink on unwrap (`~/.hermes/config.yaml`) was protected at
 * validate-time, but a symlink raced into the parent AFTER validation would
 * make the bare `unlink` remove a file in the link's destination. unlink()
 * itself does not follow a symlinked FINAL component (it removes the link,
 * not its target), so the leaf needs no O_NOFOLLOW; only the PARENT walk is
 * required. Re-walked here, immediately before the unlink, to minimise the
 * same parent-race window documented on assertNoSymlinkInPath.
 */
export async function unlinkSafeUnderRoot(
  targetPath: string,
  options: { trustedRoot?: string } = {}
): Promise<void> {
  // Normalise ONCE so the walk and the unlink syscall act on the identical
  // path (D4 walk→sink path-identity gap).
  const resolved = assertNormalisedTarget(targetPath);
  const trustedRoot = options.trustedRoot ?? deriveTrustedRoot(resolved);
  await assertNoSymlinkInPath(resolved, trustedRoot);
  await unlink(resolved);
}

/**
 * Public wrapper: refuse if any PARENT component of `targetPath` (from the
 * trusted root down to the leaf's parent) is a symlink. Exported so sibling
 * wrap sinks that do their own write (e.g. the Claude Code allowlist's
 * tmp-file + rename atomic write) share the one safe-path discipline instead
 * of re-deriving it. The leaf is NOT inspected — the caller is responsible
 * for the leaf (O_NOFOLLOW open, or a rename that replaces the link itself).
 */
export async function assertNoSymlinkParentUnderRoot(
  targetPath: string,
  trustedRoot?: string
): Promise<void> {
  await assertNoSymlinkInPath(targetPath, trustedRoot ?? deriveTrustedRoot(targetPath));
}

/**
 * Public wrapper: mkdir `dir` segment-by-segment under its trusted root,
 * refusing a symlinked ancestor (never `mkdir(recursive)` through a link).
 */
export async function mkdirSafeUnderRoot(
  dir: string,
  trustedRoot?: string,
  mode = 0o700
): Promise<void> {
  await mkdirNoFollowUnderRoot(dir, trustedRoot ?? deriveTrustedRoot(dir), mode);
}

/**
 * Restore a config from backup.
 *
 * D4 round-2 P1-A: the backup side is read normally (callers validate its
 * location), but the target is written through the no-follow primitive so
 * a symlink raced into place at the restore target cannot redirect the
 * write. D4 round-2 P2: a missing parent directory is recreated (0o700)
 * rather than stranding the operator mid-unwrap. D4 round-3 P1-A: the
 * target is now written through writeFileSafeUnderRoot, which additionally
 * refuses a SYMLINKED PARENT directory (the round-2 leaf-only O_NOFOLLOW
 * could be redirected by a symlinked `~/.hermes`) and recreates the parent
 * segment-by-segment instead of `mkdir(recursive)` following a link.
 */
export async function restoreConfig(backupPath: string, targetPath: string): Promise<void> {
  const data = await readFileCustody(backupPath, { verifyPathIdentity: true });
  await writeFileSafeUnderRoot(targetPath, data);
}

/** Canonical unwrap-meta filename — all new wraps write this. */
const WRAP_META_FILENAME = "wrap-meta.json";

/**
 * Legacy unwrap-meta filename written by releases before the vocabulary
 * sweep. Read-only fallback: agents wrapped by those releases must stay
 * unwrappable. This module is the only permitted carrier of the legacy
 * literal (enforced by test/vocabulary/no-retired-vocabulary.test.ts).
 */
const LEGACY_WRAP_META_FILENAME = "cocoon-meta.json";

/**
 * Surface-scoped wrap-meta slot: `wrap-meta-<surface-tag>.json`, keyed on
 * the same resolve()d-path hash the backup filenames embed.
 *
 * Fourth round (write-side surface scoping): every meta READ became
 * per-surface earlier in this sweep, but the WRITE still had exactly one
 * canonical slot - so wrapping a SECOND surface on the same tenant
 * silently overwrote the first surface's only unwrap pointer (wrap
 * claude-code, then wrap hermes: the hermes meta clobbered the claude-code
 * meta, a later second --unwrap reported "No Sanctuary wrap found" while
 * settings.json still routed traffic through Sanctuary). saveWrapMeta now
 * RELOCATES a canonical meta that names a different surface into that
 * surface's scoped slot before writing, and every reader scans the scoped
 * slots after the canonical + legacy filenames, so each wrapped surface
 * keeps a live pointer and sequential --unwrap runs restore them all.
 */
const WRAP_META_SURFACE_PREFIX = "wrap-meta-";
const WRAP_META_SURFACE_PATTERN = /^wrap-meta-[0-9a-f]{12}\.json$/;

function wrapMetaSurfaceFilename(originalPath: string): string {
  return `${WRAP_META_SURFACE_PREFIX}${backupSurfaceTag(originalPath)}.json`;
}

/**
 * Every wrap-meta pointer filename to consult, in read priority order:
 * canonical, legacy, then any surface-scoped slots found on disk (sorted
 * for determinism).
 *
 * Listing-error policy mirrors the per-file read policy (fifth round): an
 * ABSENT backup dir (ENOENT) genuinely holds no scoped slots and degrades
 * to the two fixed filenames, but any other readdir failure (EACCES,
 * EMFILE, EIO) makes the scoped slots INVISIBLE, not absent. On the
 * lenient read paths (`strict: false`, the default) that still degrades
 * best-effort. On the strict WRITE path (`strict: true`,
 * readWrapMetaFilesRaw -> saveWrapMeta's F6 preservation) it throws
 * WrapMetaUnreadableError: a degraded listing there made
 * readExistingWrapMetaRawForSurface answer "no meta names this surface"
 * while the surface's only pristine pointer sat in an unlisted scoped
 * slot, so saveWrapMeta skipped preservation AND its slot-cleanup unlink
 * (which needs no directory read) then deleted that pointer - the exact
 * never-destroy-on-a-read-error violation the per-file carve-outs closed.
 */
async function listWrapMetaFilenames(
  options: { strict?: boolean } = {},
): Promise<string[]> {
  const filenames = [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME];
  let entries: string[];
  try {
    entries = await readdir(backupDir());
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code !== "ENOENT" && options.strict) {
      throw new WrapMetaUnreadableError(
        [
          `${backupDir()} (directory listing failed; surface-scoped ` +
            `wrap-meta slots could not be enumerated)`,
        ],
        {
          // Class-appropriate advice: the failing path here is the backup
          // DIRECTORY holding every pristine backup and restore pointer;
          // the default file-oriented "remove it if you are certain it is
          // stale" would aim the operator at the exact asset this
          // fail-closed refusal protects.
          advice:
            `Fix the directory's permissions (it must be readable so the ` +
            `wrap-meta slots can be enumerated) and re-run. Do NOT remove ` +
            `the directory: it holds every pristine pre-wrap backup.`,
        },
      );
    }
    return filenames;
  }
  return filenames.concat(
    entries.filter((name) => WRAP_META_SURFACE_PATTERN.test(name)).sort(),
  );
}

/**
 * A secondary file the wrap modified or created alongside the primary
 * harness config. D4 staging, Bug 2: the Hermes wrap also edits
 * ~/.hermes/config.yaml, and unwrap must restore it too.
 */
export interface WrapMetaAuxiliaryFile {
  /** Path of the file the wrap touched. */
  originalPath: string;
  /**
   * Backup to restore on unwrap, or null when wrap created the file
   * fresh (unwrap then removes it to restore the pre-wrap state).
   */
  backupPath: string | null;
}

/**
 * A wrap-meta auxiliary entry that has passed validateWrapMetaAuxiliary.
 * D4 round-2 P2: `alreadyAbsent` marks a null-backup (created-by-wrap)
 * entry whose parent directory no longer exists — the file cannot exist,
 * so the desired end-state ("absent") is already satisfied and unwrap
 * treats the entry as an informational no-op instead of refusing.
 */
export interface ValidatedWrapMetaAuxiliaryFile extends WrapMetaAuxiliaryFile {
  alreadyAbsent?: boolean;
}

/**
 * Thrown when wrap-meta.json carries an `auxiliary` entry that fails
 * validation (D4 P1-2). The meta file is data at rest in the fortress, but
 * unwrap copies/unlinks the paths it names — a forged entry like
 * `{backupPath: "/anything/readable", originalPath: "/anything/writable"}`
 * would turn unwrap into an arbitrary-file write/delete primitive. Callers
 * must abort the unwrap with NOTHING modified and surface this loudly.
 */
export class WrapMetaValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrapMetaValidationError";
  }
}

/** realpath() that returns null instead of throwing for missing paths. */
async function realpathOrNull(path: string): Promise<string | null> {
  try {
    return await realpath(path);
  } catch {
    return null;
  }
}

/** True when `path` equals `dir` or sits beneath it (both pre-resolved). */
function isWithin(path: string, dir: string): boolean {
  if (path === dir) return true;
  // Strip any trailing separator from `dir` before appending one, so a root
  // of the filesystem root `/` (or any `…/`) does not become `//` and reject
  // a legitimate child via a `startsWith("//")` that can never match. A path
  // is "under" the filesystem root iff it is absolute, which the normalised
  // `dir === sep` case reduces to here.
  const base = dir.endsWith(sep) ? dir.slice(0, -sep.length) : dir;
  return path.startsWith(base + sep);
}

/**
 * Canonicalize a path for equality/containment checks even when a tail of
 * it does not exist (yet, or any more): realpath the deepest EXISTING
 * ancestor, then re-append the missing components lexically. The input is
 * resolve()d first, so the re-appended tail carries no `..` segments and
 * cannot traverse back out of the canonicalized ancestor. An existing
 * symlinked component is still resolved by realpath, so a link pointing
 * elsewhere fails any prefix/equality check against the legitimate
 * location exactly as before.
 */
async function canonicalizeAllowingMissingTail(path: string): Promise<string> {
  const resolved = resolve(path);
  let base = resolved;
  const missingTail: string[] = [];
  for (;;) {
    const real = await realpathOrNull(base);
    if (real !== null) {
      return missingTail.length === 0
        ? real
        : join(real, ...missingTail.reverse());
    }
    const parent = dirname(base);
    if (parent === base) return resolved; // hit the fs root without an existing ancestor
    missingTail.push(basename(base));
    base = parent;
  }
}

/**
 * Directories an auxiliary `originalPath` may live in: the per-platform
 * agent config directories (for Hermes: ~/.hermes and ~/.config/hermes).
 * Derived from the same path table wrap itself uses; the home directory
 * itself is excluded (it is the dirname of ~/.claude.json, and allowing it
 * would make the allowlist cover every path under $HOME). Returned
 * canonicalized so the prefix check compares like with like (macOS
 * tmpdirs, for example, live under the /var → /private/var symlink).
 * D4 round-2 P2: directories that do not exist are kept (canonicalized via
 * their deepest existing ancestor) — a backed auxiliary whose config
 * directory was deleted after wrap must still validate so unwrap can
 * recreate it instead of stranding the operator.
 */
async function allowedAuxiliaryConfigDirs(): Promise<string[]> {
  const home = resolve(homedir());
  const dirs = new Set<string>();
  for (const paths of Object.values(getPlatformPaths())) {
    for (const p of paths) {
      const dir = resolve(dirname(p));
      if (dir === home) continue;
      dirs.add(await canonicalizeAllowingMissingTail(dir));
    }
  }
  return [...dirs];
}

/**
 * The exact files wrap can CREATE fresh (recorded in wrap-meta with
 * `backupPath: null` and removed again on unwrap). D4 round-2 P1-B: a
 * null-backup auxiliary is a delete-on-unwrap instruction, so it must be
 * pinned byte-for-byte to this list — today only the Hermes config.yaml
 * surface — not merely to "anything under an agent config directory".
 * The round-1 rule let a forged meta name a LEGITIMATE file (e.g.
 * ~/.hermes/cli-config.json) as null-backup and have unwrap unlink it.
 *
 * D4 round-3 P1-B: this list is now LEXICAL (resolve only, NO realpath).
 * Round-2 canonicalized BOTH sides through realpath, so a symlinked
 * `~/.hermes -> /tmp/victim` made a forged `originalPath: "/tmp/victim/
 * config.yaml"` realpath-EQUAL to the canonicalized allowlist entry and let
 * unwrap unlink the outside file. The caller now first refuses any
 * symlinked component on the candidate path (assertNoSymlinkInPath), so a
 * symlinked `.hermes` is rejected before this lexical equality ever runs;
 * the equality itself compares the link-free lexical path against the
 * link-free lexical allowlist.
 */
function allowedCreatedByWrapPathsLexical(): string[] {
  return [resolve(hermesConfigYamlPath())];
}

/**
 * Validate wrap-meta `auxiliary` entries before ANY use (D4 P1-2, tightened
 * by round-2 P1-B/P2).
 *
 * Enforced invariants, each checked after path resolution (and realpath,
 * so symlink/traversal tricks cannot smuggle a path past the checks):
 *   - `backupPath` is either null (wrap created the file fresh) or a
 *     non-empty string that resolves strictly inside the wrap backup
 *     directory and exists there;
 *   - a BACKED entry's `originalPath` is a non-empty string whose parent
 *     directory canonicalizes strictly inside one of the known agent
 *     config directories (for Hermes: ~/.hermes). Round-2 P2: the parent
 *     may no longer exist — unwrap recreates it — but its deepest existing
 *     ancestor is still realpath-anchored, so symlinked parents that point
 *     elsewhere fail the prefix check exactly as before;
 *   - a NULL-backup entry is a delete-on-unwrap instruction, so round-2
 *     P1-B pins its `originalPath` byte-for-byte (after canonicalization)
 *     to the explicit list of files wrap can create fresh — today only
 *     hermesConfigYamlPath(). "Anywhere under an agent config dir" is NOT
 *     sufficient: it let a forged meta unlink legitimate files such as
 *     ~/.hermes/cli-config.json.
 *
 * Throws WrapMetaValidationError on anything else; never modifies state.
 * Returns the validated entries with both paths fully resolved.
 */
export async function validateWrapMetaAuxiliary(
  auxiliary: unknown
): Promise<ValidatedWrapMetaAuxiliaryFile[]> {
  if (auxiliary === undefined || auxiliary === null) return [];
  if (!Array.isArray(auxiliary)) {
    throw new WrapMetaValidationError(
      "wrap-meta auxiliary is not an array; refusing to unwrap."
    );
  }
  if (auxiliary.length === 0) return [];

  const backupRoot = await realpathOrNull(backupDir());
  const allowedDirs = await allowedAuxiliaryConfigDirs();
  const createdByWrapAllowlist = allowedCreatedByWrapPathsLexical();
  const validated: ValidatedWrapMetaAuxiliaryFile[] = [];

  for (const entry of auxiliary) {
    if (!entry || typeof entry !== "object") {
      throw new WrapMetaValidationError(
        "wrap-meta auxiliary entry is not an object; refusing to unwrap."
      );
    }
    const { originalPath, backupPath } = entry as Record<string, unknown>;

    if (typeof originalPath !== "string" || originalPath.trim() === "") {
      throw new WrapMetaValidationError(
        "wrap-meta auxiliary entry has a missing or non-string originalPath; refusing to unwrap."
      );
    }
    const resolvedOriginal = resolve(originalPath);
    const parentDir = dirname(resolvedOriginal);

    if (backupPath === null) {
      // Round-2 P1-B: null backup = created-by-wrap = delete-on-unwrap.
      // Round-3 P1-B: refuse FIRST if any component of the candidate path is
      // a symlink. Round-2 realpath-canonicalized both sides, so a symlinked
      // `~/.hermes -> /tmp/victim` made a forged originalPath of
      // "/tmp/victim/config.yaml" resolve EQUAL to the allowlist entry and
      // let unwrap unlink the outside file. With the symlink walk gating it,
      // a symlinked .hermes is rejected before the lexical equality runs.
      try {
        await assertNoSymlinkInPath(resolvedOriginal, deriveTrustedRoot(resolvedOriginal));
      } catch (err) {
        throw new WrapMetaValidationError(
          `wrap-meta auxiliary originalPath ${originalPath} has a symlinked ` +
            `parent directory; refusing to unwrap. ${(err as Error).message}`
        );
      }
      // Lexical byte-equality (resolve only, NO realpath on either side) so a
      // symlink cannot launder a forged outside path into an allowlist hit.
      if (!createdByWrapAllowlist.includes(resolvedOriginal)) {
        throw new WrapMetaValidationError(
          `wrap-meta auxiliary originalPath ${originalPath} carries a null ` +
            "backupPath but is not a file wrap creates; refusing to unwrap."
        );
      }
      // Round-2 P2: if the parent directory no longer exists, the file
      // cannot exist either — the delete-on-unwrap end-state is already
      // satisfied. Mark the entry so unwrap skips it as a no-op.
      const parentReal = await realpathOrNull(parentDir);
      validated.push({
        originalPath: resolvedOriginal,
        backupPath: null,
        ...(parentReal === null ? { alreadyAbsent: true } : {}),
      });
      continue;
    }

    // Backed entry: parent must canonicalize inside a known agent config
    // directory. Round-2 P2: a missing parent is tolerated (unwrap
    // recreates it); canonicalizeAllowingMissingTail still realpath-anchors
    // the deepest existing ancestor, so symlinked parents pointing outside
    // the allowlist fail the prefix check.
    const canonicalParent = await canonicalizeAllowingMissingTail(parentDir);
    if (!allowedDirs.some((dir) => isWithin(canonicalParent, dir))) {
      throw new WrapMetaValidationError(
        `wrap-meta auxiliary originalPath ${originalPath} is not inside a ` +
          "known agent config directory; refusing to unwrap."
      );
    }

    if (typeof backupPath !== "string" || backupPath.trim() === "") {
      throw new WrapMetaValidationError(
        "wrap-meta auxiliary entry has a non-string backupPath; refusing to unwrap."
      );
    }
    const backupReal = await realpathOrNull(resolve(backupPath));
    if (
      backupRoot === null ||
      backupReal === null ||
      !backupReal.startsWith(backupRoot + sep)
    ) {
      throw new WrapMetaValidationError(
        `wrap-meta auxiliary backupPath ${backupPath} is not inside the ` +
          "wrap backup directory; refusing to unwrap."
      );
    }

    validated.push({ originalPath: resolvedOriginal, backupPath: backupReal });
  }
  return validated;
}

/**
 * Find a restorable backup: the first wrap-meta pointer that reads and
 * parses, scanning the canonical meta filename, then the legacy name (so
 * installs wrapped by earlier releases can still unwrap), then any
 * surface-scoped wrap-meta-<tag>.json slots in deterministic name-sorted
 * order (see listWrapMetaFilenames).
 *
 * "First that reads", NOT "most recent": the canonical slot does hold the
 * most recently written wrap (saveWrapMeta relocates a different surface's
 * canonical meta into its scoped slot before writing), but once an unwrap
 * retires it, the remaining scoped slots are ordered by surface-tag
 * filename, not by wrappedAt. Sequential --unwrap runs restore every
 * wrapped surface and each run names exactly which surface it restored
 * (the two-surface case is pinned by test; with 3+ surfaces the same
 * scan applies but the order among the scoped slots is not
 * chronological). The `auxiliary` list is absent from
 * metas written by earlier releases; callers must treat it as optional.
 *
 * D4 P1-2: `auxiliary` entries are validated here on read (and again by
 * the unwrap path before use). A meta whose auxiliary list fails
 * validation throws WrapMetaValidationError — it is NOT swallowed like a
 * missing file, because silently falling through would hide a forged or
 * corrupted meta from the operator.
 */
export async function findLatestBackup(): Promise<{
  backupPath: string;
  originalPath: string;
  auxiliary?: ValidatedWrapMetaAuxiliaryFile[];
} | null> {
  for (const filename of await listWrapMetaFilenames()) {
    const metaPath = join(backupDir(), filename);
    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(
        await readFileCustody(metaPath, {
          encoding: "utf-8",
          verifyPathIdentity: true,
        }),
      );
    } catch {
      // Missing or unreadable — try the next candidate.
      continue;
    }
    const auxiliary = await validateWrapMetaAuxiliary(meta.auxiliary);
    return {
      backupPath: meta.backupPath as string,
      originalPath: meta.originalPath as string,
      ...(auxiliary.length > 0 ? { auxiliary } : {}),
    };
  }
  return null;
}

/**
 * A wrap-meta pointer file exists on disk but could not be READ (a
 * non-ENOENT failure: EACCES, EIO, a custody path-identity refusal). The
 * F6 pristine-pointer preservation in saveWrapMeta refuses to proceed in
 * this state rather than treat "unreadable" as "absent" and overwrite what
 * may be the only pointer to the pristine pre-wrap backup: the same
 * never-destroy-on-a-read-error discipline removeWrapMeta applies.
 */
export class WrapMetaUnreadableError extends Error {
  readonly unreadablePaths: string[];
  /**
   * `options.advice` overrides the default file-oriented remediation tail.
   * The default's hedged "remove it if you are certain it is stale" is
   * only safe when the unreadable path IS a single pointer file; the
   * directory-listing failure path (listWrapMetaFilenames strict) reports
   * the backup DIRECTORY itself, where "remove it" would point the
   * operator at every pristine backup this refusal exists to protect.
   */
  constructor(unreadablePaths: string[], options?: { advice?: string }) {
    super(
      `wrap metadata exists but could not be read: ` +
        `${unreadablePaths.join(", ")}. Refusing to overwrite it: it may be ` +
        `the only pointer to the pristine pre-wrap backup. ` +
        (options?.advice ??
          `Fix the file's permissions (or remove it if you are certain it ` +
            `is stale) and re-run.`),
    );
    this.name = "WrapMetaUnreadableError";
    this.unreadablePaths = unreadablePaths;
  }
}

/**
 * Read every parseable wrap-meta pointer file (canonical, legacy, then any
 * surface-scoped slots). Genuinely-absent (ENOENT) and affirmatively-unparseable
 * (successfully read, invalid JSON) candidates are skipped leniently;
 * validation still happens on the unwrap read path (findLatestBackup).
 *
 * 2026-07-02 hardening (third round): a candidate whose READ fails with
 * anything other than ENOENT (EACCES, EIO, a custody path-identity refusal)
 * is reported in `unreadablePaths` instead of being silently skipped: the
 * blanket catch here previously made the F6 preservation in saveWrapMeta
 * see "no existing meta" on a transient read error and clobber the pristine
 * pointer, the exact defect class removeWrapMeta's ENOENT carve-out closed.
 *
 * Fifth round: the directory LISTING gets the same discipline. This
 * collector feeds the strict write path, so a non-ENOENT readdir failure
 * throws WrapMetaUnreadableError (via `strict: true`) instead of silently
 * hiding the scoped slots and letting saveWrapMeta unlink an unconsulted
 * pristine pointer.
 */
async function readWrapMetaFilesRaw(): Promise<{
  metas: Record<string, unknown>[];
  unreadablePaths: string[];
}> {
  const metas: Record<string, unknown>[] = [];
  const unreadablePaths: string[] = [];
  for (const filename of await listWrapMetaFilenames({ strict: true })) {
    const metaPath = join(backupDir(), filename);
    let raw: string;
    try {
      raw = await readFileCustody(metaPath, {
        encoding: "utf-8",
        verifyPathIdentity: true,
      });
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      // ENOENT is genuinely absent; anything else is an unreadable pointer
      // the caller must not treat as "no meta".
      if (code !== "ENOENT") unreadablePaths.push(metaPath);
      continue;
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        metas.push(parsed as Record<string, unknown>);
      }
    } catch {
      // Affirmatively unparseable content (successfully read): it points at
      // nothing restorable; skip it, matching removeWrapMeta's judgment.
    }
  }
  return { metas, unreadablePaths };
}

/**
 * Read the existing wrap-meta FOR THIS SURFACE leniently, for the F6
 * re-wrap pointer-preservation check in saveWrapMeta. All pointer
 * filenames (canonical, legacy, then scoped slots) are scanned for the first meta whose
 * `originalPath` resolve()s to the same path - the identical per-surface
 * discipline hasExistingWrapMeta / removeWrapMeta use. Returns null when
 * no parseable meta names this surface.
 *
 * 2026-07-02 hardening (second round): the previous reader returned the
 * FIRST parseable meta regardless of surface, so in the mixed state the
 * module docs call out (legacy meta names surface X with the pristine
 * pointer, canonical meta names surface Y) a re-wrap of X compared against
 * Y's meta, failed the same-surface check, and clobbered the canonical
 * pointer with a fresh backup of the ALREADY-WRAPPED content - orphaning
 * X's pristine backup.
 *
 * Third round: throws {@link WrapMetaUnreadableError} when ANY pointer
 * file exists but could not be read (non-ENOENT). In that state "no meta
 * names this surface" cannot be proven, and answering null would let
 * saveWrapMeta overwrite what may be the only pristine pointer.
 */
async function readExistingWrapMetaRawForSurface(
  originalPath: string,
): Promise<Record<string, unknown> | null> {
  const { metas, unreadablePaths } = await readWrapMetaFilesRaw();
  if (unreadablePaths.length > 0) {
    throw new WrapMetaUnreadableError(unreadablePaths);
  }
  const resolved = resolve(originalPath);
  for (const meta of metas) {
    if (
      typeof meta.originalPath === "string" &&
      resolve(meta.originalPath) === resolved
    ) {
      return meta;
    }
  }
  return null;
}

/**
 * True when a wrap-meta pointer (canonical, legacy, or surface-scoped
 * wrap-meta-<tag>.json filename) exists FOR THIS SURFACE: it parses to an
 * object whose `originalPath` resolve()s to the same path as
 * `originalPath` (the scoping discipline removeWrapMeta already uses).
 * Read leniently, like the F6 preservation check; ALL pointer filenames
 * are consulted, so a legacy meta for this surface still counts even when
 * a canonical meta for a different surface exists, and a meta relocated
 * into this surface's scoped slot by a later wrap of another surface
 * still suppresses the crash-window warning on re-wrap.
 *
 * MED-2 (crash-window honesty): the wrap flow uses this to detect the
 * "config already carries the sanctuary entry but NO meta exists" state an
 * interrupted earlier wrap leaves behind, and warns that the pristine
 * pre-wrap config cannot be identified. 2026-07-02 hardening: the check
 * was previously tenant-global (any meta, for any surface, suppressed the
 * warning), so a wrap-meta for surface Y silently hid the crash-window
 * state of surface X.
 *
 * Third round: this is a thin wrapper over
 * readExistingWrapMetaRawForSurface, so the per-surface match predicate has
 * exactly ONE implementation and the crash-window warning can never
 * disagree with the F6 preservation about whether a surface is wrapped.
 * The read-ERROR policy deliberately differs from the write path: an
 * unreadable pointer reads as `false` here, failing toward the loud
 * crash-window warning (which points the operator at the timestamped
 * backups), while saveWrapMeta fails closed by refusing to overwrite.
 */
export async function hasExistingWrapMeta(
  originalPath: string,
): Promise<boolean> {
  try {
    return (await readExistingWrapMetaRawForSurface(originalPath)) !== null;
  } catch (err) {
    if (err instanceof WrapMetaUnreadableError) return false;
    throw err;
  }
}

/** True when the path names an existing, accessible file. */
async function fileExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Cross-process advisory lock serializing wrap-meta MUTATIONS (fifth
 * round). saveWrapMeta's read-relocate-write-cleanup and removeWrapMeta's
 * read-classify-unlink are multi-step sequences over shared pointer files;
 * two concurrent `sanctuary wrap` runs for DIFFERENT surfaces on the same
 * tenant could both read the canonical slot before either wrote, so the
 * second writer overwrote the first surface's just-written pointer WITHOUT
 * relocating it - recreating under concurrency the orphaned-pointer state
 * the relocation mechanism eliminates sequentially.
 *
 * Mechanics: O_EXCL creation of `wrap-meta.lock` in the backup dir (O_EXCL
 * also refuses a pre-placed symlink), short bounded retry while a live
 * holder finishes (these sections take milliseconds), a stale-age break so
 * a crashed holder cannot wedge every future wrap, and a fail-CLOSED
 * timeout: an unacquirable lock refuses the mutation with recovery advice
 * rather than proceeding unserialized (eighth round: the deadline gates
 * EVERY retry path, including the stale-break failure paths, so nothing
 * can spin past it). Release in finally is identity-verified (inode +
 * mtime captured at acquisition) and best-effort: a holder whose lock was
 * legitimately staleness-broken during a mid-section stall never evicts
 * its successor's live lock, and an unreleased lock ages into the stale
 * break.
 *
 * The stale break is rename-then-verify, not a blind unlink (sixth round):
 * the breaker atomically renames the lock to a waiter-unique name, checks
 * the taken file IS the stale lock it observed (inode + mtime), and only
 * then destroys it. Two waiters racing over the same stale lock therefore
 * cannot end up both inside the critical section via one of them unlinking
 * the other's freshly acquired lock.
 */
const WRAP_META_LOCK_FILENAME = "wrap-meta.lock";
const WRAP_META_LOCK_STALE_MS = 60_000;
const WRAP_META_LOCK_WAIT_MS = 15_000;
const WRAP_META_LOCK_RETRY_MS = 50;

/**
 * Test-only injection seam (same idiom as dashboard-standalone's
 * `__testFaultAfterLoads`). `onStaleLockObserved` runs after a waiter has
 * stat()ed the lock and judged it stale, BEFORE its rename-based break -
 * the exact TOCTOU window the rename-then-verify mechanism closes. The
 * cooperative single-process scheduling of the two-waiter Promise.all
 * test almost never lands in this window naturally, so a regression back
 * to a blind unlink would still pass end-state assertions; the seam lets
 * the deterministic pin in wrap-surface-scoped-meta.test.ts substitute a
 * FRESH lock inside the window and assert it survives.
 *
 * `onLockAcquired` runs after a holder acquires the lock, BEFORE the
 * critical section - the seam the verified-release pin uses to simulate a
 * holder that stalled past the stale threshold and was legitimately
 * broken by a waiter (its lock replaced by a successor's) while it was
 * still inside fn(). Both hooks are always undefined in production.
 */
export const __wrapMetaLockTestHooks: {
  onStaleLockObserved?: (lockPath: string) => void | Promise<void>;
  onLockAcquired?: (lockPath: string) => void | Promise<void>;
} = {};

async function withWrapMetaLock<T>(fn: () => Promise<T>): Promise<T> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const lockPath = join(dir, WRAP_META_LOCK_FILENAME);
  const deadline = Date.now() + WRAP_META_LOCK_WAIT_MS;
  // Identity of the lock THIS holder created (inode + mtime captured from
  // the open handle), consumed by the verified release in the finally.
  let acquired: { ino: number; mtimeMs: number } | undefined;
  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(`${process.pid}\n`);
        try {
          const written = await handle.stat();
          acquired = { ino: written.ino, mtimeMs: written.mtimeMs };
        } catch {
          // Identity unavailable; the release below degrades to the
          // pre-verify unconditional unlink rather than leaking the lock.
        }
      } finally {
        await handle.close();
      }
      break;
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      if (code !== "EEXIST") throw err;
      // Eighth round (bounded acquisition on EVERY retry path): the
      // deadline gates each iteration, so the stale-break failure paths
      // below can no longer spin past the documented fail-closed cap. A
      // persistently unrenameable stale lock (e.g. an immutable flag)
      // previously looped bare `continue`s forever, with neither the
      // deadline check nor the retry sleep - both lived only on the
      // fresh-lock wait path.
      if (Date.now() >= deadline) {
        throw new Error(
          `another sanctuary wrap/unwrap appears to be updating the wrap ` +
            `metadata (lock held: ${lockPath}). Re-run in a moment; if no ` +
            `other sanctuary process is running, delete the lock file and ` +
            `re-run.`,
          { cause: err },
        );
      }
      let observed: Stats;
      try {
        observed = await lstat(lockPath);
      } catch {
        // The holder released between our attempt and the stat; retry now.
        continue;
      }
      if (Date.now() - observed.mtimeMs > WRAP_META_LOCK_STALE_MS) {
        // Sixth round (stale-break TOCTOU guard): a blind unlink here
        // could remove a FRESH lock. Between this waiter's staleness stat
        // and its unlink, another waiter can break the same stale lock
        // and a new holder can acquire; unlinking then evicts that live
        // holder and lets two mutators run the meta critical section
        // concurrently (the exact unserialized clobber this lock exists
        // to prevent). Break by atomic rename to a waiter-unique name
        // instead: only one contender can take a given lock file, and
        // identity is verified AFTER the take (same inode + mtime as the
        // stale lock observed above) before anything is destroyed.
        if (__wrapMetaLockTestHooks.onStaleLockObserved) {
          await __wrapMetaLockTestHooks.onStaleLockObserved(lockPath);
        }
        const breakPath =
          `${lockPath}.break-${process.pid}-` + randomBytes(6).toString("hex");
        let renamed = false;
        try {
          await rename(lockPath, breakPath);
          renamed = true;
        } catch {
          // Another waiter took it (or the holder released) first, or the
          // lock cannot be renamed at all; fall through to the bounded
          // sleep below instead of hot-spinning.
        }
        if (renamed) {
          let tookStaleLock = false;
          try {
            const taken = await lstat(breakPath);
            tookStaleLock =
              taken.ino === observed.ino && taken.mtimeMs === observed.mtimeMs;
          } catch {
            // Cannot prove what was taken is the stale lock; restore it
            // below rather than destroy it.
          }
          if (tookStaleLock) {
            try {
              await unlink(breakPath);
            } catch {
              // The unique break name is exclusively ours; best-effort.
            }
            // The slot is genuinely vacated; contend for it immediately.
            continue;
          }
          // A live lock was taken by mistake (another waiter broke the
          // stale lock and a new holder acquired between our stat and
          // our rename). Put it back with link(), which fails EEXIST
          // rather than clobbering an even newer lock, then drop the
          // break name (link + unlink, not rename, so a newer lock is
          // never overwritten).
          try {
            await link(breakPath, lockPath);
          } catch {
            // A newer lock already occupies the slot; leave it alone.
          }
          try {
            await unlink(breakPath);
          } catch {
            // Best-effort cleanup of the unique break name.
          }
          // A live holder occupies the slot; wait like the fresh-lock path.
        }
      }
      await new Promise((resolveSleep) =>
        setTimeout(resolveSleep, WRAP_META_LOCK_RETRY_MS),
      );
    }
  }
  if (__wrapMetaLockTestHooks.onLockAcquired) {
    await __wrapMetaLockTestHooks.onLockAcquired(lockPath);
  }
  try {
    return await fn();
  } finally {
    // Eighth round (verified release): never evict a SUCCESSOR's lock. If
    // this holder stalls past the stale threshold mid-critical-section
    // (sleep/suspend, a 60s hang), a waiter legitimately breaks its lock
    // and a new holder acquires; an unconditional unlink here would then
    // remove that successor's LIVE lock and let a third contender run the
    // critical section alongside it. Release only a lock whose identity
    // matches the one this holder created, mirroring the
    // rename-then-verify stale break above.
    try {
      const current = await lstat(lockPath);
      if (
        acquired === undefined ||
        (current.ino === acquired.ino && current.mtimeMs === acquired.mtimeMs)
      ) {
        await unlink(lockPath);
      }
    } catch {
      // Best-effort release; a survivor ages into the stale break above.
    }
  }
}

/**
 * Save wrap metadata (original config path, backup path) for unwrap.
 *
 * F6 (v1.6.1 wrap safety): NEVER clobber the pristine pre-wrap backup
 * pointer on a re-wrap. A second `wrap` run backs up the ALREADY-WRAPPED
 * config; naively pointing the meta at that newest backup made `--unwrap`
 * "restore" a file that still contains the sanctuary entry, while the
 * pristine original survived on disk with nothing pointing at it. When a
 * wrap-meta already exists for the SAME originalPath (meaning: still
 * wrapped, since a completed unwrap removes the meta via removeWrapMeta),
 * the existing backupPath (the pristine one) is preserved; same per-entry
 * rule for `auxiliary` surfaces, where a preserved `backupPath: null`
 * keeps meaning "wrap created this file fresh; unwrap removes it".
 * Degradation: if the pristine backup file itself has been deleted from
 * disk, the fresh pointer is used (an unwrap that fails on a missing file
 * would strand the operator with no working pointer at all).
 *
 * Harden round (stale-meta guard): meta existence alone is NOT proof of
 * "still wrapped". Releases before removeWrapMeta existed left the meta in
 * place after every unwrap, and an operator can also remove the sanctuary
 * entry by hand. In both states a preserved pointer would pin an ancient
 * backup over weeks of live edits, and a later --unwrap would silently
 * restore the ancient content. The caller therefore passes
 * `configStillWrapped`, computed from the PRE-wrap config content (does it
 * genuinely contain the sanctuary entry?); when false, the fresh pointer
 * always wins. Defaults to true so direct callers keep the F6-safe
 * preservation semantics unless they know better.
 *
 * Throws {@link WrapMetaUnreadableError} when an existing pointer file
 * could not be read (non-ENOENT). Two read sites can throw: the
 * relocation check always reads the canonical slot (REGARDLESS of
 * `configStillWrapped` - "it names no other surface" cannot be proven
 * about a file that cannot be read), and when preservation is live the
 * per-surface F6 lookup reads the remaining pointer files. Either way,
 * overwriting a pointer that could not be inspected would silently orphan
 * a pristine backup on a transient error path. The wrap CLI's deferred
 * meta write already treats any throw here as "roll back the wrapped
 * surfaces and exit non-zero", which is exactly the fail-closed behavior
 * wanted.
 *
 * Fifth round: the whole read-relocate-write-cleanup sequence runs under
 * the cross-process wrap-meta lock (see withWrapMetaLock), so a concurrent
 * wrap of a DIFFERENT surface cannot interleave its canonical read before
 * this write and clobber the pointer without relocating it.
 */
export async function saveWrapMeta(
  meta: {
    backupPath: string;
    originalPath: string;
    platform: AgentPlatform;
    wrappedAt: string;
    auxiliary?: WrapMetaAuxiliaryFile[];
  },
  options: { configStillWrapped?: boolean } = {},
): Promise<void> {
  await withWrapMetaLock(() => saveWrapMetaLocked(meta, options));
}

/** saveWrapMeta's body; runs with the wrap-meta lock already held. */
async function saveWrapMetaLocked(
  meta: {
    backupPath: string;
    originalPath: string;
    platform: AgentPlatform;
    wrappedAt: string;
    auxiliary?: WrapMetaAuxiliaryFile[];
  },
  options: { configStillWrapped?: boolean } = {},
): Promise<void> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const metaPath = join(dir, WRAP_META_FILENAME);
  const toWrite = { ...meta };
  // Fourth round (write-side surface scoping): the canonical slot is about
  // to be overwritten. When it holds a parseable meta naming a DIFFERENT
  // surface, that meta is the only unwrap pointer to the other surface's
  // pristine backup; RELOCATE it into that surface's scoped slot before
  // writing instead of silently clobbering it (wrap claude-code then wrap
  // hermes previously orphaned the claude-code pointer, and the second
  // --unwrap reported "No Sanctuary wrap found" while settings.json still
  // routed traffic through Sanctuary). Runs regardless of
  // configStillWrapped: that flag is about THIS surface's staleness, not
  // about what the canonical slot currently points at. An unreadable
  // canonical (non-ENOENT) fails closed - "it names no other surface"
  // cannot be proven about a file that cannot be read - and a relocation
  // write failure propagates, which the wrap CLI's deferred meta write
  // already treats as roll-back-and-exit-non-zero. An affirmatively
  // unparseable canonical points at nothing restorable and may be
  // overwritten, matching removeWrapMeta's judgment.
  let canonicalRaw: string | null = null;
  try {
    canonicalRaw = await readFileCustody(metaPath, {
      encoding: "utf-8",
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code !== "ENOENT") throw new WrapMetaUnreadableError([metaPath]);
  }
  if (canonicalRaw !== null) {
    let otherSurfacePath: string | null = null;
    try {
      const parsed: unknown = JSON.parse(canonicalRaw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const existingOriginal = (parsed as Record<string, unknown>)
          .originalPath;
        if (
          typeof existingOriginal === "string" &&
          resolve(existingOriginal) !== resolve(meta.originalPath)
        ) {
          otherSurfacePath = existingOriginal;
        }
      }
    } catch {
      // Unparseable canonical content: nothing restorable to relocate.
    }
    if (otherSurfacePath !== null) {
      await writeFileCustody(
        join(dir, wrapMetaSurfaceFilename(otherSurfacePath)),
        canonicalRaw,
        { mode: 0o600, createParent: false },
      );
    }
  }
  // Surface scoping (2026-07-02 hardening): the lookup itself is per-surface
  // (resolve()-compare over BOTH pointer filenames, matching removeWrapMeta /
  // hasExistingWrapMeta), so a legacy meta naming this surface still
  // preserves the pristine pointer even when the canonical file names a
  // different surface.
  //
  // Third round (fail closed on an unreadable pointer): when preservation is
  // live (configStillWrapped) and a pointer file exists but cannot be READ
  // (non-ENOENT: EACCES, EIO, a custody path-identity refusal), the lookup
  // throws WrapMetaUnreadableError and this save REFUSES rather than
  // treating "unreadable" as "absent" and clobbering what may be the only
  // pristine pointer, mirroring removeWrapMeta's never-destroy-on-a-read-
  // error rule. When configStillWrapped is false the fresh pointer wins
  // unconditionally, so this preservation lookup is skipped entirely (the
  // relocation read of the canonical slot above still ran, and still
  // throws on a non-ENOENT read failure, even in that case).
  const existing = (options.configStillWrapped ?? true)
    ? await readExistingWrapMetaRawForSurface(meta.originalPath)
    : null;
  if (
    (options.configStillWrapped ?? true) &&
    existing !== null &&
    typeof existing.backupPath === "string" &&
    existing.backupPath.trim() !== "" &&
    (await fileExists(existing.backupPath))
  ) {
    toWrite.backupPath = existing.backupPath;
    if (meta.auxiliary && Array.isArray(existing.auxiliary)) {
      const priorAux = existing.auxiliary.filter(
        (e): e is Record<string, unknown> =>
          typeof e === "object" && e !== null && !Array.isArray(e),
      );
      toWrite.auxiliary = await Promise.all(
        meta.auxiliary.map(async (aux) => {
          const prior = priorAux.find(
            (e) =>
              typeof e.originalPath === "string" &&
              resolve(e.originalPath) === resolve(aux.originalPath) &&
              (e.backupPath === null || typeof e.backupPath === "string"),
          );
          if (!prior) return aux;
          if (prior.backupPath === null) {
            // Wrap created this surface fresh; the pristine state is
            // "absent", which unwrap honors by removing the file.
            return { ...aux, backupPath: null };
          }
          const priorBackup = prior.backupPath as string;
          return (await fileExists(priorBackup))
            ? { ...aux, backupPath: priorBackup }
            : aux;
        }),
      );
    }
  }
  await writeFileCustody(metaPath, JSON.stringify(toWrite, null, 2), {
    mode: 0o600,
    createParent: false,
  });
  // The canonical slot now names this surface, so a scoped slot left over
  // from an earlier relocation of THIS surface is a stale duplicate: when
  // preservation ran, the per-surface lookup above consulted it (and its
  // strict listing THREW rather than degrade, so "consulted" is guaranteed,
  // not assumed - a silently-degraded readdir previously made this unlink
  // delete an unconsulted pristine pointer); when configStillWrapped is
  // false, the surface is provably no longer wrapped and any old pointer is
  // stale by the stale-meta guard's own rule. Best effort: a survivor is
  // harmless, since every reader prefers the canonical slot and
  // removeWrapMeta retires all pointers naming this surface on unwrap.
  try {
    await unlink(join(dir, wrapMetaSurfaceFilename(meta.originalPath)));
  } catch {
    // Absent (the common case) or unremovable; nothing to do either way.
  }
}

/**
 * Remove the wrap-meta pointer files (canonical + legacy + any scoped slot)
 * naming the restored surface after a completed unwrap. This makes "a
 * wrap-meta exists" mean "currently wrapped", which
 * the F6 pristine-pointer preservation in saveWrapMeta relies on: without
 * it, a wrap AFTER an unwrap would preserve a stale pointer and a later
 * unwrap would restore a config the operator has since edited. The backup
 * files themselves are never deleted. Returns the pointers that could not
 * be retired (absent files are not failures), tagged by failure class so
 * the caller can warn with class-appropriate advice: an "unreadable"
 * pointer could not be READ and may name a DIFFERENT wrapped surface (a
 * successful read would have skipped it), so it must NOT be deleted; an
 * "unremovable" pointer was read, names the restored surface, and only
 * the unlink failed, so removing it manually is safe.
 *
 * Harden round (mixed legacy state): a meta file that parses and names a
 * DIFFERENT originalPath than `restoredOriginalPath` is left in place: it
 * is the only pointer to that OTHER surface's pristine backup (e.g. a
 * pre-sweep release wrote the legacy meta for Hermes and a newer wrap
 * wrote the canonical meta for Claude Code; unwrap restored only the
 * latter). An unparseable meta file points at nothing restorable and is
 * still removed. (The parameter is REQUIRED: an earlier optional-argument
 * "remove unconditionally" mode had no production caller and was deleted.)
 *
 * 2026-07-02 hardening (non-destructive on a read error): the pointer file
 * is only unlinked when it is genuinely absent-of-restorable-content: it
 * does not exist (ENOENT), or its content was successfully READ and is
 * affirmatively unparseable or names THIS surface. A transient read
 * failure (EACCES, EIO, a custody path-identity refusal) previously fell
 * through to the unlink, destroying what may be the only pointer to a
 * restorable backup on an error path; it now leaves the pointer in place
 * and reports the path as a failure the caller warns about.
 */
export interface WrapMetaRemovalFailure {
  /** Full path of the wrap-meta pointer file that could not be retired. */
  path: string;
  /**
   * "unreadable": the pointer could not be READ (EACCES, EIO, a custody
   * path-identity refusal). Had it been readable it might have named a
   * DIFFERENT wrapped surface and been skipped, so the caller's advice
   * must be "fix the read failure", never "delete it".
   * "unremovable": the pointer was read, names the restored surface, and
   * only the unlink failed; removing it manually is safe.
   */
  reason: "unreadable" | "unremovable";
}

export async function removeWrapMeta(
  restoredOriginalPath: string,
): Promise<WrapMetaRemovalFailure[]> {
  // Fifth round: serialized against saveWrapMeta (and other unwraps) via
  // the cross-process wrap-meta lock, so the read-classify-unlink sequence
  // cannot interleave with a concurrent wrap's read-relocate-write.
  return withWrapMetaLock(() => removeWrapMetaLocked(restoredOriginalPath));
}

/** removeWrapMeta's body; runs with the wrap-meta lock already held. */
async function removeWrapMetaLocked(
  restoredOriginalPath: string,
): Promise<WrapMetaRemovalFailure[]> {
  const failures: WrapMetaRemovalFailure[] = [];
  // Deterministic surface-slot candidate (needs no directory read): the
  // lenient listing (strict defaults false) degrades to the two fixed
  // filenames on a non-ENOENT readdir failure, hiding the scoped slots. When
  // the restored surface's ONLY pointer lives in its scoped slot (exactly
  // the state a relocation leaves after the canonical slot is retired),
  // that degradation used to return [] - clean success - while the stale
  // pointer survived, so a LATER --unwrap could silently re-restore
  // ancient content over post-unwrap operator edits. The scoped filename
  // is derivable from restoredOriginalPath alone, so always include it.
  const candidates = await listWrapMetaFilenames();
  const scopedSlot = wrapMetaSurfaceFilename(restoredOriginalPath);
  if (!candidates.includes(scopedSlot)) candidates.push(scopedSlot);
  for (const filename of candidates) {
    const metaPath = join(backupDir(), filename);
    let raw: string;
    try {
      raw = await readFileCustody(metaPath, {
        encoding: "utf-8",
        verifyPathIdentity: true,
      });
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      if (code === "ENOENT") continue; // Genuinely absent: nothing to remove.
      // Transient/permission read failure: the file may still be the only
      // pointer at a restorable backup (possibly another surface's). Never
      // unlink on an error path; report it so the caller warns loudly.
      failures.push({ path: metaPath, reason: "unreadable" });
      continue;
    }
    let pointsAtOtherSurface = false;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        typeof (parsed as Record<string, unknown>).originalPath === "string" &&
        resolve((parsed as Record<string, unknown>).originalPath as string) !==
          resolve(restoredOriginalPath)
      ) {
        pointsAtOtherSurface = true;
      }
    } catch {
      // Affirmatively unparseable content (successfully read): it points at
      // nothing restorable; fall through to the unlink.
    }
    if (pointsAtOtherSurface) continue;
    try {
      await unlink(metaPath);
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      if (code !== "ENOENT") {
        failures.push({ path: metaPath, reason: "unremovable" });
      }
    }
  }
  return failures;
}

/**
 * Find the newest wrap backup OF THE SAME SURFACE that is NEWER than
 * `backupPath`, or null when none exists. Backup filenames embed an
 * ISO-8601 timestamp (`config-backup-<timestamp>-<surface-tag><ext>`), so
 * lexical order on the filename is chronological order.
 *
 * Harden round (operator breadcrumb): the F6 pristine-pointer preservation
 * means an unwrap after a re-wrap restores the FIRST pre-wrap snapshot;
 * config edits made while wrapped survive only in the newer timestamped
 * backups nothing points at. Unwrap uses this to print where those edits
 * can be recovered from. Best-effort: any error reads as "none found".
 *
 * 2026-07-02 hardening (surface-scoped breadcrumbs): candidates are
 * filtered by the surface tag derived from `originalPath` (the resolve()d
 * config path this backup chain belongs to), not by extension alone -
 * prefix+extension matching in the shared per-tenant backup dir could point
 * the "recoverable from" breadcrumb at a DIFFERENT config file's backup.
 * Backups written by earlier releases carry no surface tag and cannot be
 * attributed to a surface, so they are excluded: a missing breadcrumb is
 * honest, a wrong-surface breadcrumb is the bug this fixes.
 */
export async function findNewerBackup(
  backupPath: string,
  originalPath: string,
): Promise<string | null> {
  try {
    const dir = backupDir();
    const resolved = resolve(backupPath);
    if (resolve(dirname(resolved)) !== resolve(dir)) return null;
    const name = basename(resolved);
    const ext = extname(name);
    const surfaceSuffix = `-${backupSurfaceTag(originalPath)}${ext}`;
    const newer = (await readdir(dir))
      .filter(
        (entry) =>
          entry.startsWith("config-backup-") &&
          entry.endsWith(surfaceSuffix) &&
          entry > name,
      )
      .sort();
    return newer.length > 0 ? join(dir, newer[newer.length - 1]) : null;
  } catch {
    return null;
  }
}

// ── Config Detection ────────────────────────────────────────────────

/**
 * Result from config detection — includes diagnostic info for error messages.
 */
export interface DetectionResult {
  config: AgentConfig | null;
  pathsChecked: string[];
  errors: Array<{ path: string; error: string }>;
}

/**
 * Detect the agent platform and read its MCP server config.
 * Returns diagnostics alongside the result for better error messages.
 */
export async function detectAgentConfig(
  platform?: AgentPlatform,
  configPath?: string
): Promise<AgentConfig | null> {
  const result = await detectAgentConfigWithDiagnostics(platform, configPath);
  return result.config;
}

/**
 * Detect with full diagnostics — used by CLI for informative errors.
 */
export async function detectAgentConfigWithDiagnostics(
  platform?: AgentPlatform,
  configPath?: string
): Promise<DetectionResult> {
  const pathsChecked: string[] = [];
  const errors: Array<{ path: string; error: string }> = [];

  // If explicit path given, try to read it
  if (configPath) {
    pathsChecked.push(configPath);
    const { config, error } = await readConfigFileWithError(configPath, platform);
    if (error) errors.push({ path: configPath, error });
    return { config, pathsChecked, errors };
  }

  // If platform specified, check its known paths
  if (platform) {
    const paths = getPlatformPaths()[platform];
    for (const path of paths) {
      pathsChecked.push(path);
      const { config, error } = await readConfigFileWithError(path, platform);
      if (error) errors.push({ path, error });
      if (config) return { config, pathsChecked, errors };
    }
    return { config: null, pathsChecked, errors };
  }

  // Auto-detect: try each platform in order
  for (const [plat, paths] of Object.entries(getPlatformPaths())) {
    for (const path of paths) {
      pathsChecked.push(path);
      const { config, error } = await readConfigFileWithError(path, plat as AgentPlatform);
      if (error) errors.push({ path, error });
      if (config) return { config, pathsChecked, errors };
    }
  }

  return { config: null, pathsChecked, errors };
}

// ── Config Parsing ──────────────────────────────────────────────────

async function readConfigFileWithError(
  path: string,
  platform?: AgentPlatform
): Promise<{ config: AgentConfig | null; error?: string }> {
  let raw: string;
  try {
    raw = await readFileCustody(path, {
      encoding: "utf-8",
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      return { config: null }; // File doesn't exist — not an error, just not found
    }
    return { config: null, error: `Cannot read file: ${(err as Error).message}` };
  }

  let config: unknown;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    return { config: null, error: `Invalid JSON: ${(err as Error).message}` };
  }

  const detectedPlatform =
    platform ??
    (config && typeof config === "object"
      ? detectHarnessSchema(path, config).kind
      : "generic");
  const servers = extractServers(config, detectedPlatform);
  return { config: { platform: detectedPlatform, configPath: path, servers, rawConfig: config } };
}

/**
 * Extract MCP server entries from a platform-specific config format.
 */
function extractServers(config: unknown, platform: AgentPlatform): MCPServerEntry[] {
  if (!config || typeof config !== "object") return [];

  const servers: MCPServerEntry[] = [];
  const obj = config as Record<string, unknown>;

  // OpenClaw format: either { mcp: { servers: { name: {...} } } } (nested)
  // or { mcpServers: { name: {...} } } (flat, used by some versions / shim configs)
  if (platform === "openclaw" || platform === "generic") {
    // Try nested format first: mcp.servers
    const mcp = obj.mcp as Record<string, unknown> | undefined;
    const nestedServers = mcp?.servers as Record<string, unknown> | undefined;
    if (nestedServers && typeof nestedServers === "object") {
      for (const [name, serverConfig] of Object.entries(nestedServers)) {
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }

    // Fall back to flat format: mcpServers
    if (servers.length === 0) {
      const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;
      if (mcpServers && typeof mcpServers === "object") {
        for (const [name, serverConfig] of Object.entries(mcpServers)) {
          const entry = parseServerEntry(name, serverConfig);
          if (entry) servers.push(entry);
        }
      }
    }
  }

  // Claude Code format: { mcpServers: { name: { command, args } } }
  if (platform === "claude-code") {
    const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;
    if (mcpServers && typeof mcpServers === "object") {
      for (const [name, serverConfig] of Object.entries(mcpServers)) {
        if (isCanonicalSanctuaryName(name)) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  // Cursor format: { mcpServers: { name: { command, args } } }
  if (platform === "cursor") {
    const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;
    if (mcpServers && typeof mcpServers === "object") {
      for (const [name, serverConfig] of Object.entries(mcpServers)) {
        if (isCanonicalSanctuaryName(name)) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  // Hermes format (per upstream docs): { mcp_servers: { name: { command, args, env, url, headers } } }
  // Note the snake_case top-level key; differs from Claude Code / Cursor's
  // camelCase `mcpServers`. Server entries carry the same command/args/env/url
  // fields that `parseServerEntry` already understands.
  if (platform === "hermes") {
    const mcpServers = obj.mcp_servers as Record<string, unknown> | undefined;
    if (mcpServers && typeof mcpServers === "object") {
      for (const [name, serverConfig] of Object.entries(mcpServers)) {
        if (isCanonicalSanctuaryName(name)) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  if (platform === "mastra") {
    const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;
    if (mcpServers && typeof mcpServers === "object") {
      for (const [name, serverConfig] of Object.entries(mcpServers)) {
        if (isCanonicalSanctuaryName(name)) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  // Cline format: { mcpServers: { name: { command, args } } } (same flat
  // shape as Claude Code and Cursor). Cline is a VS Code extension that
  // reads its MCP settings file from globalStorage; the file contents are
  // the same as the other flat-format harnesses.
  if (platform === "cline") {
    const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;
    if (mcpServers && typeof mcpServers === "object") {
      for (const [name, serverConfig] of Object.entries(mcpServers)) {
        if (isCanonicalSanctuaryName(name)) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  return servers;
}

/**
 * Identifies the canonical Sanctuary server entry (the one wrap installs).
 * Pre-v1.0 used a substring match on "sanctuary", which incorrectly
 * filtered legitimate operator-installed servers like `sanctuary-helper` or
 * `my-sanctuary-fork`. Re-wrap of an already-wrapped config also reported
 * "no MCP servers configured" because the substring match on the sole
 * remaining entry collapsed the upstream count to zero. Exact match keeps
 * stacked-entry prevention intact while letting operator-named siblings
 * pass through.
 */
function isCanonicalSanctuaryName(name: string): boolean {
  return name.toLowerCase() === "sanctuary";
}

function parseServerEntry(name: string, config: unknown): MCPServerEntry | null {
  if (!config || typeof config !== "object") return null;
  const c = config as Record<string, unknown>;

  // Sanitize name for use as upstream server name
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, "-").substring(0, 128);
  if (!safeName) return null;

  // SSE transport
  if (c.url && typeof c.url === "string") {
    return {
      name: safeName,
      transport: "sse",
      url: c.url,
      env: extractEnv(c.env),
    };
  }

  // Stdio transport
  if (c.command && typeof c.command === "string") {
    return {
      name: safeName,
      transport: "stdio",
      command: c.command,
      args: Array.isArray(c.args) ? c.args.filter(a => typeof a === "string") : undefined,
      env: extractEnv(c.env),
    };
  }

  return null;
}

function extractEnv(env: unknown): Record<string, string> | undefined {
  if (!env || typeof env !== "object") return undefined;
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(env as Record<string, unknown>)) {
    if (typeof v === "string") result[k] = v;
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * Description of an additional MCP server entry to register alongside
 * `sanctuary` in the harness config. v1.2.x F9 uses this for the
 * `sanctuary-chat` reply-hook subprocess; future companions (v1.3
 * SSE, v1.4+ federation gateway) plug in through the same shape.
 *
 * Idempotent on re-wrap: if a sibling entry with this name already
 * exists, it is overwritten with the new command/args/env (the wrap
 * CLI's source-of-truth posture). Existing user-named siblings are
 * preserved.
 */
export interface AuxiliaryMcpServerEntry {
  /** Server name as it appears in the harness MCP config map. */
  name: string;
  /** Stdio command (mirror of `sanctuaryCommand` shape). */
  command: string;
  /** Args list passed to the command. */
  args: string[];
  /**
   * Optional env vars passed alongside the entry. Critical-var
   * propagation (SANCTUARY_PASSPHRASE etc.) follows the same rules as
   * the main sanctuary entry: process.env wins when neither the caller
   * nor the existing entry provided a value.
   */
  env?: Record<string, string>;
}

/**
 * Rewrite an agent config to route through Sanctuary as the sole MCP server.
 * Returns the path to the rewritten config.
 *
 * v1.2.x F9: optional `additionalEntries` registers sibling MCP servers
 * (e.g. `sanctuary-chat`) alongside `sanctuary` in the harness config.
 * Each sibling is merged into the platform-specific MCP map; user-named
 * siblings already present in the config are preserved unchanged.
 */
export async function rewriteConfigForWrap(
  agentConfig: AgentConfig,
  sanctuaryCommand: string,
  sanctuaryArgs: string[],
  sanctuaryEnv?: Record<string, string>,
  additionalEntries?: AuxiliaryMcpServerEntry[]
): Promise<string> {
  const raw = agentConfig.rawConfig as Record<string, unknown>;

  // Resolve existing servers so we can preserve env vars from the original
  // sanctuary entry when no explicit sanctuaryEnv is provided.
  let existingServers: Record<string, unknown>;
  if (agentConfig.platform === "openclaw") {
    const existingMcp = (raw.mcp as Record<string, unknown>) ?? {};
    existingServers = (existingMcp.servers as Record<string, unknown>) ?? {};
  } else if (agentConfig.platform === "hermes") {
    existingServers = (raw.mcp_servers as Record<string, unknown>) ?? {};
  } else {
    existingServers = (raw.mcpServers as Record<string, unknown>) ?? {};
  }

  // If no explicit env was passed, inherit env vars from the existing sanctuary entry,
  // then fall back to process.env for the critical vars.
  let resolvedEnv: Record<string, string> | undefined = sanctuaryEnv;
  if (!resolvedEnv) {
    const existingSanctuary = existingServers.sanctuary as Record<string, unknown> | undefined;
    if (existingSanctuary?.env && typeof existingSanctuary.env === "object") {
      const extracted = extractEnv(existingSanctuary.env);
      if (extracted) resolvedEnv = extracted;
    }
  }
  // Ensure the critical env vars survive the rewrite even when
  // neither the caller nor the existing config provided them.
  const CRITICAL_VARS = [
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_DASHBOARD_AUTH_TOKEN",
    "SANCTUARY_DASHBOARD_ENABLED",
    "SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE",
  ] as const;
  for (const key of CRITICAL_VARS) {
    if (process.env[key] && (!resolvedEnv || !resolvedEnv[key])) {
      if (!resolvedEnv) resolvedEnv = {};
      resolvedEnv[key] = process.env[key]!;
    }
  }

  const sanctuaryEntry: Record<string, unknown> = {
    command: sanctuaryCommand,
    args: sanctuaryArgs,
  };
  if (resolvedEnv && Object.keys(resolvedEnv).length > 0) {
    sanctuaryEntry.env = resolvedEnv;
  }

  // v1.2.x F9: build the merged MCP map (existing + sanctuary + sibling
  // auxiliaries). Each auxiliary inherits the same critical-var pass-
  // through rules as the main sanctuary entry so passphrase + fortress
  // path travel into the sibling subprocess automatically.
  const auxiliaryMap: Record<string, Record<string, unknown>> = {};
  for (const aux of additionalEntries ?? []) {
    const auxEntry: Record<string, unknown> = {
      command: aux.command,
      args: aux.args,
    };
    let auxEnv: Record<string, string> | undefined = aux.env
      ? { ...aux.env }
      : undefined;
    // Inherit critical vars from process.env when the caller didn't supply
    // them explicitly. Mirrors the sanctuary-entry inheritance above.
    for (const key of CRITICAL_VARS) {
      if (process.env[key] && (!auxEnv || !auxEnv[key])) {
        if (!auxEnv) auxEnv = {};
        auxEnv[key] = process.env[key]!;
      }
    }
    if (auxEnv && Object.keys(auxEnv).length > 0) {
      auxEntry.env = auxEnv;
    }
    auxiliaryMap[aux.name] = auxEntry;
  }

  let rewritten: Record<string, unknown>;

  if (agentConfig.platform === "openclaw") {
    // OpenClaw uses nested mcp.servers format — preserve existing servers
    const existingMcp = (raw.mcp as Record<string, unknown>) ?? {};
    rewritten = {
      ...raw,
      mcp: {
        ...existingMcp,
        servers: {
          ...existingServers,
          sanctuary: sanctuaryEntry,
          ...auxiliaryMap,
        },
      },
    };
    // Remove flat mcpServers if it existed (from a shim)
    delete rewritten.mcpServers;
  } else if (agentConfig.platform === "hermes") {
    // Hermes uses flat snake_case mcp_servers; preserve top-level siblings
    // (model_provider, memory, telemetry, etc.) and existing servers.
    rewritten = {
      ...raw,
      mcp_servers: {
        ...existingServers,
        sanctuary: sanctuaryEntry,
        ...auxiliaryMap,
      },
    };
  } else {
    // Claude Code / Cursor / generic use flat mcpServers — preserve existing servers
    rewritten = {
      ...raw,
      mcpServers: {
        ...existingServers,
        sanctuary: sanctuaryEntry,
        ...auxiliaryMap,
      },
    };
  }

  // D4 round-3 P1-C: the primary-config write was a plain writeFile with NO
  // symlink protection — a symlinked config path (or a symlinked parent dir
  // such as ~/.hermes) redirected the rewritten config wherever the link
  // pointed. Route it through the same safe-path discipline as every other
  // wrap sink: refuse a symlinked parent (walk from the trusted root) and
  // open the leaf O_NOFOLLOW.
  await writeFileSafeUnderRoot(
    agentConfig.configPath,
    JSON.stringify(rewritten, null, 2),
    { mode: 0o600 }
  );
  return agentConfig.configPath;
}
