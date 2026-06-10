/**
 * Sanctuary Wrap — Agent Config Reader
 *
 * Detects and reads MCP server configurations from various agent platforms.
 * Supports: OpenClaw, Claude Code, Cursor, Cline, and generic MCP config files.
 *
 * Security invariant: Never modifies configs without explicit request.
 * All original configs are backed up before any modification.
 */

import { readFile, writeFile, mkdir, copyFile, access } from "node:fs/promises";
import { join } from "node:path";
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
    // Hermes Agent (NousResearch, v0.9.0) canonicals live under ~/.hermes.
    // Hermes ships `cli-config.yaml` as the primary surface per upstream docs.
    // Sanctuary wrap v1.0 detects the JSON variant only: operators who keep
    // YAML can still wrap via `sanctuary wrap --wrap <path>` after exporting
    // to JSON. YAML-native detection is flagged as a v1.x follow-up.
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
 */
export async function backupConfig(configPath: string): Promise<string> {
  const dir = backupDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = join(dir, `config-backup-${timestamp}.json`);
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
 * Find the most recent backup.
 *
 * Read-both, write-new: prefers the canonical meta filename, then falls
 * back to the legacy name so installs wrapped by earlier releases can
 * still unwrap.
 */
export async function findLatestBackup(): Promise<{ backupPath: string; originalPath: string } | null> {
  for (const filename of [WRAP_META_FILENAME, LEGACY_WRAP_META_FILENAME]) {
    const metaPath = join(backupDir(), filename);
    try {
      const raw = await readFile(metaPath, "utf-8");
      const meta = JSON.parse(raw);
      return {
        backupPath: meta.backupPath,
        originalPath: meta.originalPath,
      };
    } catch {
      // Missing or unreadable — try the next candidate.
    }
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
  let existingServers: Record<string, unknown> = {};
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
