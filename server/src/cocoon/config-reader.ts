/**
 * Sanctuary Cocoon — Agent Config Reader
 *
 * Detects and reads MCP server configurations from various agent platforms.
 * Supports: OpenClaw, Claude Code, Cursor, and generic MCP config files.
 *
 * Security invariant: Never modifies configs without explicit request.
 * All original configs are backed up before any modification.
 */

import { readFile, writeFile, mkdir, copyFile, access } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

// ── Types ───────────────────────────────────────────────────────────

export type AgentPlatform = "openclaw" | "claude-code" | "cursor" | "generic";

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

const PLATFORM_PATHS: Record<AgentPlatform, string[]> = {
  "openclaw": [
    join(homedir(), ".openclaw", "openclaw.json"),
    join(homedir(), ".openclaw", "config.json"),
    join(homedir(), "Library", "Application Support", "OpenClaw", "openclaw.json"),
    join(homedir(), "Library", "Application Support", "OpenClaw", "config.json"),
  ],
  "claude-code": [
    join(homedir(), ".claude", "settings.json"),
    join(homedir(), ".config", "claude-code", "settings.json"),
  ],
  "cursor": [
    join(homedir(), ".cursor", "mcp.json"),
  ],
  "generic": [],
};

// ── Backup ──────────────────────────────────────────────────────────

const BACKUP_DIR = join(homedir(), ".sanctuary", "backup");

/**
 * Back up a config file before modification.
 * Returns the backup path.
 */
export async function backupConfig(configPath: string): Promise<string> {
  await mkdir(BACKUP_DIR, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = join(BACKUP_DIR, `config-backup-${timestamp}.json`);
  await copyFile(configPath, backupPath);
  return backupPath;
}

/**
 * Restore a config from backup.
 */
export async function restoreConfig(backupPath: string, targetPath: string): Promise<void> {
  await copyFile(backupPath, targetPath);
}

/**
 * Find the most recent backup.
 */
export async function findLatestBackup(): Promise<{ backupPath: string; originalPath: string } | null> {
  const metaPath = join(BACKUP_DIR, "cocoon-meta.json");
  try {
    const raw = await readFile(metaPath, "utf-8");
    const meta = JSON.parse(raw);
    return {
      backupPath: meta.backupPath,
      originalPath: meta.originalPath,
    };
  } catch {
    return null;
  }
}

/**
 * Save cocoon metadata (original config path, backup path) for unwrap.
 */
export async function saveCocoonMeta(meta: {
  backupPath: string;
  originalPath: string;
  platform: AgentPlatform;
  wrappedAt: string;
}): Promise<void> {
  await mkdir(BACKUP_DIR, { recursive: true, mode: 0o700 });
  const metaPath = join(BACKUP_DIR, "cocoon-meta.json");
  await writeFile(metaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
}

// ── Config Detection ────────────────────────────────────────────────

/**
 * Detect the agent platform and read its MCP server config.
 */
export async function detectAgentConfig(
  platform?: AgentPlatform,
  configPath?: string
): Promise<AgentConfig | null> {
  // If explicit path given, try to read it
  if (configPath) {
    return readConfigFile(configPath, platform ?? "generic");
  }

  // If platform specified, check its known paths
  if (platform) {
    const paths = PLATFORM_PATHS[platform];
    for (const path of paths) {
      const config = await readConfigFile(path, platform);
      if (config) return config;
    }
    return null;
  }

  // Auto-detect: try each platform in order
  for (const [plat, paths] of Object.entries(PLATFORM_PATHS)) {
    for (const path of paths) {
      const config = await readConfigFile(path, plat as AgentPlatform);
      if (config) return config;
    }
  }

  return null;
}

// ── Config Parsing ──────────────────────────────────────────────────

async function readConfigFile(
  path: string,
  platform: AgentPlatform
): Promise<AgentConfig | null> {
  try {
    await access(path);
  } catch {
    return null;
  }

  try {
    const raw = await readFile(path, "utf-8");
    const config = JSON.parse(raw);
    const servers = extractServers(config, platform);
    return { platform, configPath: path, servers, rawConfig: config };
  } catch {
    return null;
  }
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
        // Skip Sanctuary itself if already listed
        if (name.toLowerCase().includes("sanctuary")) continue;
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
        if (name.toLowerCase().includes("sanctuary")) continue;
        const entry = parseServerEntry(name, serverConfig);
        if (entry) servers.push(entry);
      }
    }
  }

  return servers;
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
 * Rewrite an agent config to route through Sanctuary as the sole MCP server.
 * Returns the path to the rewritten config.
 */
export async function rewriteConfigForCocoon(
  agentConfig: AgentConfig,
  sanctuaryCommand: string,
  sanctuaryArgs: string[],
  sanctuaryEnv?: Record<string, string>
): Promise<string> {
  const raw = agentConfig.rawConfig as Record<string, unknown>;

  // Resolve existing servers so we can preserve env vars from the original
  // sanctuary entry when no explicit sanctuaryEnv is provided.
  let existingServers: Record<string, unknown> = {};
  if (agentConfig.platform === "openclaw") {
    const existingMcp = (raw.mcp as Record<string, unknown>) ?? {};
    existingServers = (existingMcp.servers as Record<string, unknown>) ?? {};
  } else {
    existingServers = (raw.mcpServers as Record<string, unknown>) ?? {};
  }

  // If no explicit env was passed, inherit env vars from the existing sanctuary entry
  let resolvedEnv: Record<string, string> | undefined = sanctuaryEnv;
  if (!resolvedEnv) {
    const existingSanctuary = existingServers.sanctuary as Record<string, unknown> | undefined;
    if (existingSanctuary?.env && typeof existingSanctuary.env === "object") {
      const extracted = extractEnv(existingSanctuary.env);
      if (extracted) resolvedEnv = extracted;
    }
  }

  const sanctuaryEntry: Record<string, unknown> = {
    command: sanctuaryCommand,
    args: sanctuaryArgs,
  };
  if (resolvedEnv && Object.keys(resolvedEnv).length > 0) {
    sanctuaryEntry.env = resolvedEnv;
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
        },
      },
    };
    // Remove flat mcpServers if it existed (from a shim)
    delete rewritten.mcpServers;
  } else {
    // Claude Code / Cursor / generic use flat mcpServers — preserve existing servers
    rewritten = {
      ...raw,
      mcpServers: {
        ...existingServers,
        sanctuary: sanctuaryEntry,
      },
    };
  }

  await writeFile(agentConfig.configPath, JSON.stringify(rewritten, null, 2), { mode: 0o600 });
  return agentConfig.configPath;
}
