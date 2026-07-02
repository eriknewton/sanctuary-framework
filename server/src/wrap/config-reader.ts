/**
 * Sanctuary Wrap — Agent Config Reader
 *
 * Detects and reads MCP server configurations from various agent platforms.
 * Supports: OpenClaw, Claude Code, Cursor, Cline, Mastra, and generic MCP config files.
 *
 * Security invariant: Never modifies configs without explicit request.
 * All original configs are backed up before any modification.
 */

import { mkdir, realpath, open, lstat, unlink, readdir } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { createHash } from "node:crypto";
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
 * Find the most recent backup.
 *
 * Read-both, write-new: prefers the canonical meta filename, then falls
 * back to the legacy name so installs wrapped by earlier releases can
 * still unwrap. The `auxiliary` list is absent from metas written by
 * earlier releases; callers must treat it as optional.
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
  for (const filename of [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME]) {
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
 * Read every parseable wrap-meta pointer file (canonical then legacy
 * filename) leniently. Missing/unreadable/unparseable candidates are
 * skipped; validation still happens on the unwrap read path
 * (findLatestBackup).
 */
async function readWrapMetaFilesRaw(): Promise<Record<string, unknown>[]> {
  const metas: Record<string, unknown>[] = [];
  for (const filename of [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME]) {
    try {
      const parsed: unknown = JSON.parse(
        await readFileCustody(join(backupDir(), filename), {
          encoding: "utf-8",
          verifyPathIdentity: true,
        }),
      );
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        metas.push(parsed as Record<string, unknown>);
      }
    } catch {
      // Missing or unreadable: try the next candidate.
    }
  }
  return metas;
}

/**
 * Read the existing wrap-meta (canonical then legacy filename) leniently,
 * for the F6 re-wrap pointer-preservation check in saveWrapMeta. Returns
 * null when absent or unreadable.
 */
async function readExistingWrapMetaRaw(): Promise<Record<
  string,
  unknown
> | null> {
  const metas = await readWrapMetaFilesRaw();
  return metas.length > 0 ? metas[0]! : null;
}

/**
 * True when a wrap-meta pointer (canonical or legacy filename) exists FOR
 * THIS SURFACE: it parses to an object whose `originalPath` resolve()s to
 * the same path as `originalPath` (the scoping discipline removeWrapMeta
 * already uses). Read leniently, like the F6 preservation check; BOTH
 * pointer filenames are consulted, so a legacy meta for this surface still
 * counts even when a canonical meta for a different surface exists.
 *
 * MED-2 (crash-window honesty): the wrap flow uses this to detect the
 * "config already carries the sanctuary entry but NO meta exists" state an
 * interrupted earlier wrap leaves behind, and warns that the pristine
 * pre-wrap config cannot be identified. 2026-07-02 hardening: the check
 * was previously tenant-global (any meta, for any surface, suppressed the
 * warning), so a wrap-meta for surface Y silently hid the crash-window
 * state of surface X.
 */
export async function hasExistingWrapMeta(
  originalPath: string,
): Promise<boolean> {
  const resolved = resolve(originalPath);
  for (const meta of await readWrapMetaFilesRaw()) {
    if (
      typeof meta.originalPath === "string" &&
      resolve(meta.originalPath) === resolved
    ) {
      return true;
    }
  }
  return false;
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
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const metaPath = join(dir, WRAP_META_FILENAME);
  const toWrite = { ...meta };
  const existing = await readExistingWrapMetaRaw();
  if (
    (options.configStillWrapped ?? true) &&
    existing !== null &&
    // Surface scoping (2026-07-02 hardening): resolve()-compare, matching
    // removeWrapMeta / hasExistingWrapMeta, so a lexically-different spelling
    // of the same path still preserves the pristine pointer.
    typeof existing.originalPath === "string" &&
    resolve(existing.originalPath) === resolve(meta.originalPath) &&
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
}

/**
 * Remove the wrap-meta pointer files (canonical + legacy) after a completed
 * unwrap. This makes "a wrap-meta exists" mean "currently wrapped", which
 * the F6 pristine-pointer preservation in saveWrapMeta relies on: without
 * it, a wrap AFTER an unwrap would preserve a stale pointer and a later
 * unwrap would restore a config the operator has since edited. The backup
 * files themselves are never deleted. Returns the paths that could not be
 * removed (absent files are not failures) so the caller can warn loudly.
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
export async function removeWrapMeta(
  restoredOriginalPath: string,
): Promise<string[]> {
  const failures: string[] = [];
  for (const filename of [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME]) {
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
      // pointer at a restorable backup. Never unlink on an error path;
      // report it so the caller warns loudly.
      failures.push(metaPath);
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
      if (code !== "ENOENT") failures.push(metaPath);
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
