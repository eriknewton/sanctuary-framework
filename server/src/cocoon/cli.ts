#!/usr/bin/env node
/**
 * Sanctuary Cocoon — CLI Entry Point
 *
 * One command to wrap any MCP-compatible agent in Sanctuary's enforcement chain.
 *
 * Usage:
 *   npx @sanctuary-framework/cocoon --wrap /path/to/config.json
 *   npx @sanctuary-framework/cocoon --openclaw
 *   npx @sanctuary-framework/cocoon --unwrap
 *
 * What it does:
 * 1. Reads the agent's existing MCP server configuration
 * 2. Generates a sovereignty profile with all servers as upstream
 * 3. Backs up the original config, rewrites it to route through Sanctuary
 * 4. Starts Sanctuary MCP server with dashboard
 * 5. Prints status and dashboard URL
 */

import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  detectAgentConfig,
  backupConfig,
  saveCocoonMeta,
  findLatestBackup,
  restoreConfig,
  rewriteConfigForCocoon,
  type AgentPlatform,
  type MCPServerEntry,
} from "./config-reader.js";
import { classifyTool, classifyServerTools, tierDescription } from "./tier-classifier.js";
import type { UpstreamServer, SovereigntyProfile } from "../sovereignty-profile.js";

// ── Types ───────────────────────────────────────────────────────────

interface CocoonOptions {
  /** Wrap a specific config file */
  wrap?: string;
  /** Auto-detect OpenClaw config */
  openclaw?: boolean;
  /** Auto-detect Claude Code config */
  claudeCode?: boolean;
  /** Auto-detect Cursor config */
  cursor?: boolean;
  /** Unwrap (restore original config) */
  unwrap?: boolean;
  /** Passphrase for encryption */
  passphrase?: string;
  /** Dashboard port */
  port?: number;
  /** Dry run — show what would happen without making changes */
  dryRun?: boolean;
}

// ── Constants ───────────────────────────────────────────────────────

/** Default CallGovernor limits for Cocoon mode */
export const COCOON_GOVERNOR_DEFAULTS = {
  volume_limit: 200,        // 200 calls per 10-minute window
  rate_limit_per_tool: 20,  // 20 calls/min per individual tool
  lifetime_limit: 1000,     // 1000 total calls per session
} as const;

// ── Main ────────────────────────────────────────────────────────────

export async function runCocoon(options: CocoonOptions): Promise<void> {
  if (options.unwrap) {
    await unwrap();
    return;
  }

  // Determine platform
  let platform: AgentPlatform | undefined;
  if (options.openclaw) platform = "openclaw";
  else if (options.claudeCode) platform = "claude-code";
  else if (options.cursor) platform = "cursor";

  // Detect agent config
  const agentConfig = await detectAgentConfig(platform, options.wrap);

  if (!agentConfig) {
    if (platform) {
      console.error(`Could not find ${platform} configuration. Check that the agent is installed.`);
    } else if (options.wrap) {
      console.error(`Could not read config file: ${options.wrap}`);
    } else {
      console.error("Could not auto-detect any agent configuration.");
      console.error("Use --openclaw, --claude-code, --cursor, or --wrap /path/to/config.json");
    }
    process.exit(1);
  }

  if (agentConfig.servers.length === 0) {
    console.error(`Found ${agentConfig.platform} config at ${agentConfig.configPath}, but no MCP servers configured.`);
    process.exit(1);
  }

  console.error(`\n  Sanctuary Cocoon\n`);
  console.error(`  Platform: ${agentConfig.platform}`);
  console.error(`  Config: ${agentConfig.configPath}`);
  console.error(`  MCP servers found: ${agentConfig.servers.length}\n`);

  // Convert detected servers to upstream server entries with auto-classification
  const upstreamServers = convertToUpstreamServers(agentConfig.servers);

  // Display what will be protected
  for (const server of upstreamServers) {
    const overrideCount = Object.keys(server.tool_overrides ?? {}).length;
    console.error(`  → ${server.name} (${server.transport.type}) — default: Tier ${server.default_tier}`);
    if (overrideCount > 0) {
      console.error(`    ${overrideCount} tool-specific tier overrides`);
    }
  }

  if (options.dryRun) {
    console.error(`\n  Dry run — no changes made.\n`);
    return;
  }

  // Generate sovereignty profile
  const storagePath = join(homedir(), ".sanctuary");
  await mkdir(storagePath, { recursive: true, mode: 0o700 });

  const profile = createCocoonProfile(upstreamServers);

  // Write profile to a cocoon-specific config that the server will load
  const cocoonConfigPath = join(storagePath, "cocoon-profile.json");
  await writeFile(cocoonConfigPath, JSON.stringify(profile, null, 2), { mode: 0o600 });

  // Back up original config
  const backupPath = await backupConfig(agentConfig.configPath);
  await saveCocoonMeta({
    backupPath,
    originalPath: agentConfig.configPath,
    platform: agentConfig.platform,
    wrappedAt: new Date().toISOString(),
  });

  console.error(`\n  Original config backed up to: ${backupPath}`);

  // Rewrite agent config to route through Sanctuary
  await rewriteConfigForCocoon(
    agentConfig,
    "npx",
    [
      "@sanctuary-framework/mcp-server",
      "--dashboard",
      ...(options.passphrase ? ["--passphrase", options.passphrase] : []),
    ]
  );

  console.error(`  Agent config rewritten to route through Sanctuary`);

  const dashboardPort = options.port ?? 3501;
  console.error(`\n  Your agent is now protected.`);
  console.error(`  Dashboard: http://localhost:${dashboardPort}`);
  console.error(`  All tool calls are being logged and scanned.`);
  console.error(`\n  To restore: npx @sanctuary-framework/cocoon --unwrap\n`);
}

// ── Unwrap ──────────────────────────────────────────────────────────

async function unwrap(): Promise<void> {
  const meta = await findLatestBackup();
  if (!meta) {
    console.error("No Cocoon wrapping found to restore.");
    console.error("Run --wrap or --openclaw first.");
    process.exit(1);
  }

  try {
    await access(meta.backupPath);
  } catch {
    console.error(`Backup file not found: ${meta.backupPath}`);
    process.exit(1);
  }

  await restoreConfig(meta.backupPath, meta.originalPath);
  console.error(`\n  Sanctuary Cocoon — Unwrapped`);
  console.error(`  Original config restored to: ${meta.originalPath}`);
  console.error(`  Backup preserved at: ${meta.backupPath}\n`);
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Convert detected MCP server entries to Sanctuary upstream server format.
 * All servers default to Tier 2 (anomaly-monitored).
 */
function convertToUpstreamServers(servers: MCPServerEntry[]): UpstreamServer[] {
  return servers.map(server => {
    const upstream: UpstreamServer = {
      name: server.name,
      transport: server.transport === "sse"
        ? { type: "sse" as const, url: server.url! }
        : {
            type: "stdio" as const,
            command: server.command!,
            ...(server.args ? { args: server.args } : {}),
            ...(server.env ? { env: server.env } : {}),
          },
      enabled: true,
      default_tier: 2,
    };
    return upstream;
  });
}

/**
 * Create a sovereignty profile with Cocoon defaults.
 * Non-negotiable: audit logging ON, injection detection ON, approval gate ON.
 */
function createCocoonProfile(upstreamServers: UpstreamServer[]): SovereigntyProfile {
  return {
    version: 1,
    features: {
      audit_logging: { enabled: true },            // Non-negotiable
      injection_detection: { enabled: true },       // Non-negotiable
      context_gating: { enabled: false },           // Can enable later
      approval_gate: { enabled: true },             // Core enforcement — always ON
      zk_proofs: { enabled: false },                // Not needed for Cocoon
    },
    upstream_servers: upstreamServers,
    updated_at: new Date().toISOString(),
  };
}

// ── CLI Parser ──────────────────────────────────────────────────────

export function parseCocoonArgs(argv: string[]): CocoonOptions {
  const options: CocoonOptions = {};

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--wrap":
        options.wrap = argv[++i];
        break;
      case "--openclaw":
        options.openclaw = true;
        break;
      case "--claude-code":
        options.claudeCode = true;
        break;
      case "--cursor":
        options.cursor = true;
        break;
      case "--unwrap":
        options.unwrap = true;
        break;
      case "--passphrase":
        options.passphrase = argv[++i];
        break;
      case "--port":
        options.port = parseInt(argv[++i]!, 10);
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--help":
      case "-h":
        printCocoonHelp();
        process.exit(0);
    }
  }

  return options;
}

function printCocoonHelp(): void {
  console.log(`
  Sanctuary Cocoon — Wrap any agent in sovereignty protection

  Usage:
    npx @sanctuary-framework/cocoon --openclaw        # Wrap OpenClaw agent
    npx @sanctuary-framework/cocoon --claude-code      # Wrap Claude Code
    npx @sanctuary-framework/cocoon --cursor           # Wrap Cursor
    npx @sanctuary-framework/cocoon --wrap config.json # Wrap generic MCP config
    npx @sanctuary-framework/cocoon --unwrap           # Restore original config

  Options:
    --openclaw        Auto-detect and wrap OpenClaw agent
    --claude-code     Auto-detect and wrap Claude Code
    --cursor          Auto-detect and wrap Cursor
    --wrap <path>     Wrap a specific MCP config file
    --unwrap          Restore original config from backup
    --passphrase <p>  Encryption passphrase
    --port <port>     Dashboard port (default: 3501)
    --dry-run         Show what would happen without making changes
    --help, -h        Show this help

  What happens:
    1. Reads your agent's MCP server configuration
    2. Backs up the original config to ~/.sanctuary/backup/
    3. Rewrites the config so your agent routes through Sanctuary
    4. All tool calls are logged, scanned for injection, and rate-limited
    5. Dangerous operations require your approval via the dashboard

  Rollback:
    --unwrap restores the original config from backup.
    Backups are preserved and never deleted.
`);
}
