/**
 * Sanctuary Wrap — Claude Code Stop hook installer (v1.2.0 F10).
 *
 * Reads ~/.claude/settings.json (Claude Code's user-scoped settings file
 * where hook entries live; distinct from ~/.claude.json which holds the
 * MCP server registry), merges a Sanctuary-tagged Stop hook entry that
 * polls the operator chat inbox via `sanctuary chat-poll`, and writes
 * the file back atomically with a one-rolling backup at
 * ~/.claude/settings.json.sanctuary-backup.
 *
 * Install footprint per wrap:
 *   ~/.claude/settings.json — single Stop entry tagged with the
 *                             sentinel matcher "SanctuaryChatPoll".
 *   ~/.claude/settings.json.sanctuary-backup — pre-write snapshot.
 *
 * Coexistence rules:
 *   - If the operator already has Stop hooks (e.g. their own
 *     verification loop), Sanctuary APPENDS a new entry; existing
 *     entries are preserved verbatim. Both hooks fire on Claude
 *     turn-end; either may return decision=block.
 *   - Re-running `sanctuary wrap --install-hooks` against a settings
 *     file that already has the SanctuaryChatPoll entry is idempotent
 *     for the entry's structural shape, but the env values
 *     (SANCTUARY_FORTRESS_PATH, SANCTUARY_AGENT_ID, SANCTUARY_IDENTITY_ID,
 *     SANCTUARY_BIN) are updated to the most-recent wrap. Multi-fortress
 *     coexistence is single-fortress at v1.2.0; the most-recent wrap
 *     wins. Multi-fortress simultaneous chat is a v1.3 conversation.
 *
 * Failure modes:
 *   - Corrupt settings.json on disk: install throws with the parse
 *     error. The pre-write backup is the prior valid state and is
 *     preserved at .sanctuary-backup; operator can revert manually.
 *   - Bundled script not present (e.g. running from a stale install):
 *     install throws with "bundled hook script not found at <path>";
 *     operator runs `npm install -g @sanctuary-framework/mcp-server`
 *     to refresh.
 *   - Atomic write fails (disk full, permission denied): install
 *     throws; settings.json on disk is untouched (we write to a
 *     .tmp.<pid> sibling and rename).
 *
 * No SANCTUARY_PASSPHRASE handling, no key derivation, no fortress
 * unlock — this module is a pure file-merge installer. The hook
 * SCRIPT (which the entry points at) does the chat-inbox poll at
 * Claude-turn-end time via `sanctuary chat-poll`.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import { readFile, writeFile, rename, unlink, copyFile, mkdir, access } from "node:fs/promises";
import { accessSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";

// ── Constants ───────────────────────────────────────────────────────

/**
 * Sentinel matcher for Sanctuary-tagged Stop entries. Idempotent re-wrap
 * detects existing Sanctuary entries by this exact value; coexisting
 * operator hooks must not collide on this string.
 */
export const SANCTUARY_STOP_HOOK_MATCHER = "SanctuaryChatPoll";

/** Backup filename appended to the settings.json path. */
export const SANCTUARY_BACKUP_SUFFIX = ".sanctuary-backup";

// ── Types ───────────────────────────────────────────────────────────

export interface InstallClaudeCodeHookOptions {
  /** Wrapped agent identifier set on the hook entry's env block. */
  agentId: string;
  /** Operator identity id set on the hook entry's env block. */
  identityId: string;
  /** Operator fortress path set on the hook entry's env block. */
  fortressPath: string;
  /**
   * Override the path to ~/.claude/settings.json for tests. Production
   * resolves from `homedir()`.
   */
  settingsPath?: string;
  /**
   * Override the absolute path to the bundled hook script. Production
   * resolves it from `import.meta.url` to the npm-tarball-shipped
   * `scripts/sanctuary-chat-stop-hook.sh`.
   */
  hookScriptPath?: string;
  /**
   * Override the absolute path to the `sanctuary` binary (set on the
   * hook entry's env as SANCTUARY_BIN). When unset, the hook script
   * resolves `sanctuary` from PATH.
   */
  sanctuaryBin?: string;
}

export interface InstallClaudeCodeHookResult {
  installedAt: string;
  alreadyPresent: boolean;
  /**
   * True when Sanctuary updated an existing tagged entry's env values
   * (most-recent wrap wins). False when the entry was freshly added or
   * already present with identical env.
   */
  envUpdated: boolean;
}

export interface RemoveClaudeCodeHookOptions {
  settingsPath?: string;
}

export interface RemoveClaudeCodeHookResult {
  removedFrom: string | null;
}

interface ClaudeCodeHookCommandEntry {
  type: "command";
  command: string;
  env?: Record<string, string>;
}

interface ClaudeCodeStopMatcher {
  matcher: string;
  hooks: ClaudeCodeHookCommandEntry[];
}

interface ClaudeCodeSettings {
  hooks?: {
    Stop?: ClaudeCodeStopMatcher[];
    [otherMatcher: string]: ClaudeCodeStopMatcher[] | undefined;
  };
  [k: string]: unknown;
}

// ── Helpers ─────────────────────────────────────────────────────────

function defaultSettingsPath(): string {
  return join(homedir(), ".claude", "settings.json");
}

/**
 * Resolve the absolute path to the bundled hook script. Probes multiple
 * candidate locations because the layout differs between environments:
 *
 * Published npm tarball (tsup bundles into dist/cli.js):
 *   <pkgRoot>/dist/cli.js
 *   <pkgRoot>/scripts/sanctuary-chat-stop-hook.sh
 *
 * Dev worktree (tsx runs from source):
 *   <repoRoot>/server/src/cocoon/claude-code-hooks.ts
 *   <repoRoot>/server/scripts/sanctuary-chat-stop-hook.sh
 *
 * The function anchors off process.argv[1] (the executable entry point)
 * and walks up one directory from dist/ to pkgRoot. Falls back to
 * import.meta.url for test contexts where argv[1] may not be cli.js.
 *
 * @internal Exported for testing only.
 */
export function resolveBundledHookScriptPath(): string {
  const SCRIPT_NAME = "sanctuary-chat-stop-hook.sh";

  // Primary anchor: process.argv[1] is the entry point (dist/cli.js in
  // bundled mode, or the tsx loader target in dev).
  const entryFile = process.argv[1];
  const entryDir = entryFile ? dirname(resolve(entryFile)) : null;

  // Secondary anchor: import.meta.url (this file's location). In bundled
  // mode this resolves inside dist/cli.js; in source mode it resolves to
  // src/cocoon/claude-code-hooks.ts.
  const here = fileURLToPath(import.meta.url);

  // Build candidate list by walking up from each anchor.
  // We try up to 3 ancestor levels from each anchor point.
  const candidates: string[] = [];

  // Argv-based candidates first (most reliable for bundled execution).
  if (entryDir) {
    // dist/cli.js → walk up 1 level → <pkgRoot>/scripts/ (npm tarball)
    // src/cocoon/file.ts → walk up 1 = src/scripts (miss)
    //                     → walk up 2 = server/scripts (dev hit)
    //                     → walk up 3 = repo/scripts (unlikely but safe)
    let dir = entryDir;
    for (let i = 0; i < 3; i++) {
      dir = dirname(dir);
      candidates.push(resolve(dir, "scripts", SCRIPT_NAME));
    }
  }

  // import.meta.url-based candidates (fallback for test/non-argv contexts).
  const hereDir = dirname(here);
  let metaDir = hereDir;
  for (let i = 0; i < 3; i++) {
    metaDir = dirname(metaDir);
    candidates.push(resolve(metaDir, "scripts", SCRIPT_NAME));
  }

  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const c of candidates) {
    const normalized = resolve(c);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      unique.push(normalized);
    }
  }

  // Return the first candidate that exists on disk.
  for (const candidate of unique) {
    try {
      accessSync(candidate);
      return candidate;
    } catch {
      // Not found at this location; try next.
    }
  }

  throw new Error(
    `Sanctuary: bundled hook script not found. Probed:\n` +
      unique.map((p) => `  - ${p}`).join("\n") +
      `\nReinstall the npm package: npm install -g @sanctuary-framework/mcp-server@latest`,
  );
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

function parseSettingsOrThrow(text: string, settingsPath: string): ClaudeCodeSettings {
  if (text.trim().length === 0) return {};
  try {
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("settings.json must be a JSON object");
    }
    return parsed as ClaudeCodeSettings;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const wrapped = new Error(
      `Sanctuary: ${settingsPath} is not valid JSON (${msg}). The pre-write backup at ${settingsPath}${SANCTUARY_BACKUP_SUFFIX} is unchanged. Fix the file manually or restore from the backup, then retry sanctuary wrap.`,
    );
    (wrapped as Error & { cause?: unknown }).cause = e;
    throw wrapped;
  }
}

function stableEnvDiffers(
  current: Record<string, string> | undefined,
  next: Record<string, string>,
): boolean {
  if (!current) return true;
  const currentKeys = Object.keys(current).sort();
  const nextKeys = Object.keys(next).sort();
  if (currentKeys.length !== nextKeys.length) return true;
  for (let i = 0; i < currentKeys.length; i++) {
    if (currentKeys[i] !== nextKeys[i]) return true;
  }
  for (const k of currentKeys) {
    if (current[k] !== next[k]) return true;
  }
  return false;
}

// ── Install ─────────────────────────────────────────────────────────

/**
 * Install (or refresh) the Sanctuary Stop hook entry in
 * ~/.claude/settings.json. Atomic + idempotent. Existing operator
 * hooks are preserved verbatim. The pre-write file content is copied
 * to <settings>.sanctuary-backup before the rename.
 */
export async function installClaudeCodeStopHook(
  opts: InstallClaudeCodeHookOptions,
): Promise<InstallClaudeCodeHookResult> {
  const settingsPath = opts.settingsPath ?? defaultSettingsPath();
  const hookScriptPath =
    opts.hookScriptPath ?? resolveBundledHookScriptPath();
  if (!(await pathExists(hookScriptPath))) {
    throw new Error(
      `Sanctuary: bundled hook script not found at ${hookScriptPath}. ` +
        `Reinstall the npm package: npm install -g @sanctuary-framework/mcp-server@latest`,
    );
  }

  // Ensure the directory exists; fresh-install case has no ~/.claude/.
  await mkdir(dirname(settingsPath), { recursive: true, mode: 0o700 });

  const desiredEnv: Record<string, string> = {
    SANCTUARY_FORTRESS_PATH: opts.fortressPath,
    SANCTUARY_AGENT_ID: opts.agentId,
    SANCTUARY_IDENTITY_ID: opts.identityId,
  };
  if (opts.sanctuaryBin) {
    desiredEnv.SANCTUARY_BIN = opts.sanctuaryBin;
  }

  let priorText = "";
  let settings: ClaudeCodeSettings;
  if (await pathExists(settingsPath)) {
    priorText = await readFile(settingsPath, "utf8");
    settings = parseSettingsOrThrow(priorText, settingsPath);
  } else {
    settings = {};
  }

  if (!settings.hooks || typeof settings.hooks !== "object") {
    settings.hooks = {};
  }
  if (!Array.isArray(settings.hooks.Stop)) {
    settings.hooks.Stop = [];
  }

  const stopEntries: ClaudeCodeStopMatcher[] = settings.hooks.Stop;
  const sanctuaryIdx = stopEntries.findIndex(
    (e) => e && e.matcher === SANCTUARY_STOP_HOOK_MATCHER,
  );

  let alreadyPresent = false;
  let envUpdated = false;

  const desiredEntry: ClaudeCodeStopMatcher = {
    matcher: SANCTUARY_STOP_HOOK_MATCHER,
    hooks: [
      {
        type: "command",
        command: hookScriptPath,
        env: desiredEnv,
      },
    ],
  };

  if (sanctuaryIdx === -1) {
    stopEntries.push(desiredEntry);
  } else {
    alreadyPresent = true;
    const existing = stopEntries[sanctuaryIdx];
    const existingEnv = existing.hooks?.[0]?.env;
    const existingCommand = existing.hooks?.[0]?.command;
    if (
      stableEnvDiffers(existingEnv, desiredEnv) ||
      existingCommand !== hookScriptPath
    ) {
      stopEntries[sanctuaryIdx] = desiredEntry;
      envUpdated = true;
    }
  }

  // Backup before write. Best-effort: if the prior file did not exist,
  // skip the backup (no prior state to preserve).
  if (priorText.length > 0) {
    try {
      await copyFile(settingsPath, `${settingsPath}${SANCTUARY_BACKUP_SUFFIX}`);
    } catch {
      // Best-effort; do not block the install on backup failure.
    }
  }

  // Atomic write: write to .tmp.<pid>, then rename.
  const tmpPath = `${settingsPath}.tmp.${process.pid}`;
  const serialized = JSON.stringify(settings, null, 2) + "\n";
  await writeFile(tmpPath, serialized, { mode: 0o600 });
  try {
    await rename(tmpPath, settingsPath);
  } catch (e) {
    // Cleanup tmp on rename failure.
    try {
      await unlink(tmpPath);
    } catch {
      /* tmp may already be gone */
    }
    throw e;
  }

  return {
    installedAt: settingsPath,
    alreadyPresent,
    envUpdated,
  };
}

// ── Remove ──────────────────────────────────────────────────────────

/**
 * Remove the Sanctuary-tagged Stop hook entry from
 * ~/.claude/settings.json. Operator hooks present at the same Stop
 * matcher are preserved verbatim. No-op when no Sanctuary entry exists.
 *
 * Used by `sanctuary unwrap --remove-hooks` (CLI surface to be wired in
 * v1.2.x; v1.2.0 ships the helper so the unwrap surface can use it
 * before its own subcommand lands).
 */
export async function removeClaudeCodeStopHook(
  opts: RemoveClaudeCodeHookOptions = {},
): Promise<RemoveClaudeCodeHookResult> {
  const settingsPath = opts.settingsPath ?? defaultSettingsPath();
  if (!(await pathExists(settingsPath))) {
    return { removedFrom: null };
  }

  const priorText = await readFile(settingsPath, "utf8");
  const settings = parseSettingsOrThrow(priorText, settingsPath);

  const stopEntries = settings.hooks?.Stop;
  if (!Array.isArray(stopEntries) || stopEntries.length === 0) {
    return { removedFrom: null };
  }

  const filtered = stopEntries.filter(
    (e) => !(e && e.matcher === SANCTUARY_STOP_HOOK_MATCHER),
  );
  if (filtered.length === stopEntries.length) {
    return { removedFrom: null };
  }

  if (filtered.length === 0 && settings.hooks) {
    delete settings.hooks.Stop;
    if (Object.keys(settings.hooks).length === 0) {
      delete settings.hooks;
    }
  } else if (settings.hooks) {
    settings.hooks.Stop = filtered;
  }

  // Backup + atomic write, mirror of install.
  try {
    await copyFile(settingsPath, `${settingsPath}${SANCTUARY_BACKUP_SUFFIX}`);
  } catch {
    /* best-effort */
  }
  const tmpPath = `${settingsPath}.tmp.${process.pid}`;
  const serialized = JSON.stringify(settings, null, 2) + "\n";
  await writeFile(tmpPath, serialized, { mode: 0o600 });
  try {
    await rename(tmpPath, settingsPath);
  } catch (e) {
    try {
      await unlink(tmpPath);
    } catch {
      /* tmp may already be gone */
    }
    throw e;
  }

  return { removedFrom: settingsPath };
}
