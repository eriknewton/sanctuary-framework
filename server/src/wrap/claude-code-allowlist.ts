/**
 * Sanctuary Wrap, Claude Code permissions.allow installer (WP-V1.2 reshape).
 *
 * Reads ~/.claude/settings.json (Claude Code's user-global settings file)
 * and merges the `sanctuary-broker` MCP tool identifiers into the
 * `permissions.allow` list so secret-broker tool calls run without a
 * per-turn permission prompt for the operator.
 *
 * Why this companion install exists:
 *
 *   The secret broker exposes routine read-side tools (request_token,
 *   read_secret, list_grants, audit_query) the wrapped agent calls during
 *   normal operation. Without an allowlist entry, Claude Code prompts the
 *   operator on every tool call (the default safe-by-default tool model).
 *   Per-turn prompts on routine reads burn the operator's attention. The
 *   installer writes the allowlist entries at wrap time so the broker
 *   loop runs silently after the operator has wrapped once.
 *
 * Allowlist key shape:
 *
 *   Claude Code v2.x identifies MCP tools as `mcp__<server>__<tool>`,
 *   where slashes inside the tool name are replaced with double
 *   underscores. The `sanctuary-broker` server exposes four tools:
 *     - broker/request_token  -> mcp__sanctuary-broker__broker__request_token
 *     - broker/read_secret    -> mcp__sanctuary-broker__broker__read_secret
 *     - broker/list_grants    -> mcp__sanctuary-broker__broker__list_grants
 *     - broker/audit_query    -> mcp__sanctuary-broker__broker__audit_query
 *
 * Coexistence rules:
 *
 *   - Existing operator entries in `permissions.allow` are preserved
 *     byte-for-position; we only append the Sanctuary entries when
 *     they are not already present.
 *   - Existing keys outside `permissions` (theme, env, hooks, etc.) are
 *     preserved byte-for-key; we round-trip through JSON.parse / stringify
 *     so comments and original key ordering are not preserved (Claude Code
 *     settings.json is canonical JSON, not JSON-with-comments).
 *   - Atomic write: sibling .tmp.<pid> file + rename. Fails closed on
 *     write error (caller catches; wrap continues without the allowlist).
 *
 * Failure modes:
 *
 *   - settings.json is missing: creates a fresh file with just the
 *     Sanctuary permissions block.
 *   - settings.json is malformed JSON: install throws; the original file
 *     is untouched. Caller surfaces a stderr note; wrap proceeds.
 *   - permissions / permissions.allow has the wrong shape (e.g. a string
 *     where the array is expected): install throws with a precise
 *     diagnostic so the operator can repair manually.
 *   - All entries already present: true no-op; settings.json is not
 *     re-written.
 *
 * No SANCTUARY_PASSPHRASE handling, no key derivation, no fortress
 * unlock. This module is a pure file-edit installer.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import {
  readFile,
  rename,
  unlink,
  copyFile,
  access,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import {
  writeFileSafeUnderRoot,
  assertNoSymlinkParentUnderRoot,
  mkdirSafeUnderRoot,
} from "./config-reader.js";

// ── Constants ───────────────────────────────────────────────────────

/**
 * Allowlist entries the installer adds. Mirror Claude Code v2.x's
 * `mcp__<server>__<tool>` identifier shape (slash -> double underscore).
 *
 * Sourced from the broker tool registrations in
 * server/src/mcp/broker-server.ts. Keep this list in sync with the
 * shipped broker tool surface; the broker's policy gate stops any
 * write-side or destructive operation regardless of the allowlist.
 */
export const SANCTUARY_BROKER_ALLOWLIST_ENTRIES: readonly string[] = [
  "mcp__sanctuary-broker__broker__request_token",
  "mcp__sanctuary-broker__broker__read_secret",
  "mcp__sanctuary-broker__broker__list_grants",
  "mcp__sanctuary-broker__broker__audit_query",
];

/** Backup filename suffix appended to the settings.json path. */
export const SANCTUARY_SETTINGS_BACKUP_SUFFIX = ".sanctuary-backup";

// ── Types ───────────────────────────────────────────────────────────

export interface InstallClaudeCodeAllowlistOptions {
  /**
   * Override the settings.json path. Defaults to ~/.claude/settings.json.
   * Tests inject a temp path; production wraps omit and accept the default.
   */
  settingsJsonPath?: string;
}

export interface InstallClaudeCodeAllowlistResult {
  /** Absolute path the installer wrote (or skipped writing). */
  installedAt: string;
  /**
   * True when all Sanctuary entries were already present and no write
   * was performed. False on any partial install or fresh-file creation.
   */
  alreadyPresent: boolean;
  /**
   * Subset of SANCTUARY_BROKER_ALLOWLIST_ENTRIES that were added by this
   * call. Empty when alreadyPresent is true.
   */
  added: readonly string[];
}

export interface RemoveClaudeCodeAllowlistOptions {
  settingsJsonPath?: string;
}

export interface RemoveClaudeCodeAllowlistResult {
  /** Absolute path operated on, or null when the file did not exist. */
  removedFrom: string | null;
  /** Entries actually removed. Empty when no Sanctuary entries were present. */
  removed: readonly string[];
}

// ── Helpers ─────────────────────────────────────────────────────────

function defaultSettingsJsonPath(): string {
  return join(homedir(), ".claude", "settings.json");
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

async function atomicWrite(targetPath: string, content: string): Promise<void> {
  // D4 round-3: settings.json is an agent config surface (~/.claude/), so a
  // symlinked parent dir (~/.claude -> /tmp/victim) would redirect both the
  // tmp write and the rename. Refuse a symlinked parent first, then write the
  // tmp file through the same no-follow discipline as every other wrap sink.
  // rename() does not follow a symlinked FINAL component (it replaces the
  // link itself), so the parent walk is the enforcement here.
  await assertNoSymlinkParentUnderRoot(targetPath);
  const tmpPath = `${targetPath}.tmp.${process.pid}`;
  await writeFileSafeUnderRoot(tmpPath, content, { mode: 0o600 });
  try {
    await rename(tmpPath, targetPath);
  } catch (e) {
    try {
      await unlink(tmpPath);
    } catch {
      /* tmp may already be gone */
    }
    throw e;
  }
}

interface SettingsShape {
  permissions?: {
    allow?: unknown;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

function parseSettings(text: string, settingsPath: string): SettingsShape {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(
      `Sanctuary: ${settingsPath} is not valid JSON (${(e as Error).message}). Repair manually and retry sanctuary wrap.`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      `Sanctuary: ${settingsPath} top level must be a JSON object; found ${Array.isArray(parsed) ? "array" : typeof parsed}.`,
    );
  }
  return parsed as SettingsShape;
}

function readAllowList(
  settings: SettingsShape,
  settingsPath: string,
): string[] {
  const perms = settings.permissions;
  if (perms === undefined) return [];
  if (perms === null || typeof perms !== "object" || Array.isArray(perms)) {
    throw new Error(
      `Sanctuary: ${settingsPath} \`permissions\` must be an object; found ${Array.isArray(perms) ? "array" : typeof perms}.`,
    );
  }
  const allow = perms.allow;
  if (allow === undefined) return [];
  if (!Array.isArray(allow)) {
    throw new Error(
      `Sanctuary: ${settingsPath} \`permissions.allow\` must be an array of strings; found ${typeof allow}.`,
    );
  }
  for (const e of allow) {
    if (typeof e !== "string") {
      throw new Error(
        `Sanctuary: ${settingsPath} \`permissions.allow\` contains a non-string entry. Repair manually.`,
      );
    }
  }
  return allow as string[];
}

// ── Install ─────────────────────────────────────────────────────────

/**
 * Install (or detect-as-present) the Sanctuary broker-tool allowlist
 * entries in Claude Code's user-global settings.json. Atomic + idempotent.
 * Existing operator content above and below the allowlist additions is
 * preserved at the JSON-key level (the file is round-tripped through
 * JSON.parse / stringify; comments are not preserved because Claude Code
 * settings.json is canonical JSON).
 */
export async function installClaudeCodeAllowlist(
  opts: InstallClaudeCodeAllowlistOptions = {},
): Promise<InstallClaudeCodeAllowlistResult> {
  const settingsPath = opts.settingsJsonPath ?? defaultSettingsJsonPath();

  // Ensure the directory exists; fresh-install case has no ~/.claude/.
  // D4 round-3: segment-by-segment under the trusted root so a symlinked
  // ancestor cannot redirect the created tree (mkdir(recursive) follows it).
  await mkdirSafeUnderRoot(dirname(settingsPath));

  const fileExists = await pathExists(settingsPath);

  if (!fileExists) {
    // Fresh install: write a minimal settings.json with just the
    // Sanctuary permissions block.
    const fresh: SettingsShape = {
      permissions: {
        allow: [...SANCTUARY_BROKER_ALLOWLIST_ENTRIES],
      },
    };
    await atomicWrite(settingsPath, JSON.stringify(fresh, null, 2) + "\n");
    return {
      installedAt: settingsPath,
      alreadyPresent: false,
      added: [...SANCTUARY_BROKER_ALLOWLIST_ENTRIES],
    };
  }

  const priorText = await readFile(settingsPath, "utf8");
  const settings = parseSettings(priorText, settingsPath);
  const existingAllow = readAllowList(settings, settingsPath);
  const existingSet = new Set(existingAllow);

  const toAdd = SANCTUARY_BROKER_ALLOWLIST_ENTRIES.filter(
    (e) => !existingSet.has(e),
  );

  if (toAdd.length === 0) {
    // Idempotent path: all entries already present. True no-op; do not
    // re-write the file (preserves operator key ordering and any
    // formatting nuances that survived a round-trip).
    return { installedAt: settingsPath, alreadyPresent: true, added: [] };
  }

  // Append path: at least one Sanctuary entry is missing. Backup +
  // atomic write of the updated JSON. Backup is best-effort; do not
  // fail the install on backup error.
  try {
    await copyFile(
      settingsPath,
      `${settingsPath}${SANCTUARY_SETTINGS_BACKUP_SUFFIX}`,
    );
  } catch {
    /* best-effort */
  }

  const nextAllow = existingAllow.concat(toAdd);
  const nextSettings: SettingsShape = {
    ...settings,
    permissions: {
      ...(settings.permissions ?? {}),
      allow: nextAllow,
    },
  };

  await atomicWrite(
    settingsPath,
    JSON.stringify(nextSettings, null, 2) + "\n",
  );
  return { installedAt: settingsPath, alreadyPresent: false, added: toAdd };
}

// ── Remove ──────────────────────────────────────────────────────────

/**
 * Remove the Sanctuary broker-tool allowlist entries from Claude Code's
 * settings.json. Operator entries in `permissions.allow` (and all other
 * settings keys) are preserved. No-op when no Sanctuary entries are
 * present, or when the settings file is missing.
 *
 * Not yet wired into `sanctuary unwrap` at v1.2.0; exported for v1.2.5
 * unwrap-path completion (parallel to claude-code-augmentation.ts's
 * removeClaudeCodeAugmentation, also exported-but-not-wired).
 */
export async function removeClaudeCodeAllowlist(
  opts: RemoveClaudeCodeAllowlistOptions = {},
): Promise<RemoveClaudeCodeAllowlistResult> {
  const settingsPath = opts.settingsJsonPath ?? defaultSettingsJsonPath();

  if (!(await pathExists(settingsPath))) {
    return { removedFrom: null, removed: [] };
  }

  const priorText = await readFile(settingsPath, "utf8");
  const settings = parseSettings(priorText, settingsPath);
  const existingAllow = readAllowList(settings, settingsPath);

  const sanctuarySet = new Set(SANCTUARY_BROKER_ALLOWLIST_ENTRIES);
  const removed = existingAllow.filter((e) => sanctuarySet.has(e));

  if (removed.length === 0) {
    return { removedFrom: settingsPath, removed: [] };
  }

  const filtered = existingAllow.filter((e) => !sanctuarySet.has(e));
  const nextSettings: SettingsShape = {
    ...settings,
    permissions: {
      ...(settings.permissions ?? {}),
      allow: filtered,
    },
  };

  await atomicWrite(
    settingsPath,
    JSON.stringify(nextSettings, null, 2) + "\n",
  );
  return { removedFrom: settingsPath, removed };
}
