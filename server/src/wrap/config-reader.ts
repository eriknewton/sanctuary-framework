/**
 * Sanctuary Wrap — Agent Config Reader
 *
 * Detects and reads MCP server configurations from various agent platforms.
 * Supports: OpenClaw, Claude Code, Cursor, Cline, and generic MCP config files.
 *
 * Security invariant: Never modifies configs without explicit request.
 * All original configs are backed up before any modification.
 */

import { readFile, writeFile, mkdir, copyFile, access, realpath } from "node:fs/promises";
import { join, extname, resolve, dirname, sep } from "node:path";
import { homedir } from "node:os";
import { resolveStoragePath } from "../paths.js";
import { detectHarnessSchema } from "./harness-schema.js";

// ── Types ───────────────────────────────────────────────────────────

export type AgentPlatform =
  | "openclaw"
  | "claude-code"
  | "cursor"
  | "hermes"
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
 * Back up a config file before modification.
 * Returns the backup path.
 *
 * The backup keeps the source file's extension (D4 staging, Bug 2: the
 * Hermes wrap now also backs up ~/.hermes/config.yaml, and a .yaml backup
 * named .json would mislead manual recovery). JSON configs keep the
 * historical `config-backup-<timestamp>.json` name unchanged.
 */
export async function backupConfig(configPath: string): Promise<string> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const extension = extname(configPath) || ".json";
  const backupPath = join(dir, `config-backup-${timestamp}${extension}`);
  await copyFile(configPath, backupPath);
  return backupPath;
}

/**
 * Restore a config from backup.
 */
export async function restoreConfig(backupPath: string, targetPath: string): Promise<void> {
  await copyFile(backupPath, targetPath);
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
  return path === dir || path.startsWith(dir + sep);
}

/**
 * Directories an auxiliary `originalPath` may live in: the per-platform
 * agent config directories (for Hermes: ~/.hermes and ~/.config/hermes).
 * Derived from the same path table wrap itself uses; the home directory
 * itself is excluded (it is the dirname of ~/.claude.json, and allowing it
 * would make the allowlist cover every path under $HOME). Returned
 * realpath-resolved so the prefix check compares like with like (macOS
 * tmpdirs, for example, live under the /var → /private/var symlink);
 * directories that do not exist are dropped — nothing can live inside them.
 */
async function allowedAuxiliaryConfigDirs(): Promise<string[]> {
  const home = resolve(homedir());
  const dirs = new Set<string>();
  for (const paths of Object.values(getPlatformPaths())) {
    for (const p of paths) {
      const dir = resolve(dirname(p));
      if (dir === home) continue;
      const real = await realpathOrNull(dir);
      if (real !== null) dirs.add(real);
    }
  }
  return [...dirs];
}

/**
 * Validate wrap-meta `auxiliary` entries before ANY use (D4 P1-2).
 *
 * Enforced invariants, each checked after path resolution (and realpath,
 * so symlink/traversal tricks cannot smuggle a path past the prefix check):
 *   - `backupPath` is either null (wrap created the file fresh) or a
 *     non-empty string that resolves strictly inside the wrap backup
 *     directory and exists there;
 *   - `originalPath` is a non-empty string whose (existing) parent
 *     directory resolves strictly inside one of the known agent config
 *     directories (for Hermes: ~/.hermes).
 *
 * Throws WrapMetaValidationError on anything else; never modifies state.
 * Returns the validated entries with both paths fully resolved.
 */
export async function validateWrapMetaAuxiliary(
  auxiliary: unknown
): Promise<WrapMetaAuxiliaryFile[]> {
  if (auxiliary === undefined || auxiliary === null) return [];
  if (!Array.isArray(auxiliary)) {
    throw new WrapMetaValidationError(
      "wrap-meta auxiliary is not an array; refusing to unwrap."
    );
  }
  if (auxiliary.length === 0) return [];

  const backupRoot = await realpathOrNull(backupDir());
  const allowedDirs = await allowedAuxiliaryConfigDirs();
  const validated: WrapMetaAuxiliaryFile[] = [];

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
    // The parent must already exist (unwrap only restores into / removes
    // from directories the wrap touched) and must realpath-resolve inside
    // a known agent config directory — symlinked parents that point
    // elsewhere fail the prefix check.
    const parentReal = await realpathOrNull(dirname(resolvedOriginal));
    if (
      parentReal === null ||
      !allowedDirs.some((dir) => isWithin(parentReal, dir))
    ) {
      throw new WrapMetaValidationError(
        `wrap-meta auxiliary originalPath ${originalPath} is not inside a ` +
          "known agent config directory; refusing to unwrap."
      );
    }

    let resolvedBackup: string | null = null;
    if (backupPath !== null) {
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
      resolvedBackup = backupReal;
    }

    validated.push({ originalPath: resolvedOriginal, backupPath: resolvedBackup });
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
  auxiliary?: WrapMetaAuxiliaryFile[];
} | null> {
  for (const filename of [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME]) {
    const metaPath = join(backupDir(), filename);
    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(await readFile(metaPath, "utf-8"));
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
 * Save wrap metadata (original config path, backup path) for unwrap.
 */
export async function saveWrapMeta(meta: {
  backupPath: string;
  originalPath: string;
  platform: AgentPlatform;
  wrappedAt: string;
  auxiliary?: WrapMetaAuxiliaryFile[];
}): Promise<void> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const metaPath = join(dir, WRAP_META_FILENAME);
  await writeFile(metaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
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
  try {
    await access(path);
  } catch {
    return { config: null }; // File doesn't exist — not an error, just not found
  }

  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch (err) {
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
  // then fall back to process.env for the three critical vars.
  let resolvedEnv: Record<string, string> | undefined = sanctuaryEnv;
  if (!resolvedEnv) {
    const existingSanctuary = existingServers.sanctuary as Record<string, unknown> | undefined;
    if (existingSanctuary?.env && typeof existingSanctuary.env === "object") {
      const extracted = extractEnv(existingSanctuary.env);
      if (extracted) resolvedEnv = extracted;
    }
  }
  // Ensure the three critical env vars survive the rewrite even when
  // neither the caller nor the existing config provided them.
  const CRITICAL_VARS = [
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_DASHBOARD_AUTH_TOKEN",
    "SANCTUARY_DASHBOARD_ENABLED",
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

  await writeFile(agentConfig.configPath, JSON.stringify(rewritten, null, 2), { mode: 0o600 });
  return agentConfig.configPath;
}
