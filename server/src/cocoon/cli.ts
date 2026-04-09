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

import { writeFile, readFile, mkdir, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveCocoonMeta,
  findLatestBackup,
  restoreConfig,
  rewriteConfigForCocoon,
  type AgentPlatform,
  type MCPServerEntry,
  type DetectionResult,
} from "./config-reader.js";
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

  // Detect agent config — with diagnostics for better error messages
  const detection = await detectAgentConfigWithDiagnostics(platform, options.wrap);
  const agentConfig = detection.config;

  if (!agentConfig) {
    console.error(`\n  Sanctuary Cocoon — Configuration Not Found\n`);

    if (platform) {
      console.error(`  Could not find ${platform} configuration.`);
    } else if (options.wrap) {
      console.error(`  Could not read config file: ${options.wrap}`);
    } else {
      console.error("  Could not auto-detect any agent configuration.");
      console.error("  Use --openclaw, --claude-code, --cursor, or --wrap /path/to/config.json");
    }

    // Show paths that were checked
    if (detection.pathsChecked.length > 0) {
      console.error(`\n  Paths checked:`);
      for (const p of detection.pathsChecked) {
        console.error(`    ${p}`);
      }
    }

    // Show specific errors (JSON parse failures, permission issues)
    if (detection.errors.length > 0) {
      console.error(`\n  Errors encountered:`);
      for (const e of detection.errors) {
        console.error(`    ${e.path}: ${e.error}`);
      }
    }

    console.error("");
    process.exit(1);
  }

  if (agentConfig.servers.length === 0) {
    console.error(`\n  Found ${agentConfig.platform} config at ${agentConfig.configPath},`);
    console.error(`  but no MCP servers are configured in it.`);
    console.error(`\n  Expected format: { "mcp": { "servers": { ... } } } (OpenClaw)`);
    console.error(`                or { "mcpServers": { ... } } (Claude Code, Cursor)\n`);
    process.exit(1);
  }

  // ── Double-wrap detection ──────────────────────────────────────
  const hasSanctuary = agentConfig.servers.some(
    s => s.name.toLowerCase() === "sanctuary"
  );
  if (hasSanctuary) {
    console.error(`\n  Warning: This agent already has a Sanctuary server configured.`);
    console.error(`  Re-wrapping will update the existing Sanctuary entry.`);
    console.error(`  Use --unwrap first if you want a clean wrap.\n`);
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

  // Rewrite agent config to route through Sanctuary.
  // IMPORTANT: Do NOT pass --dashboard here. When the agent harness (OpenClaw, etc.)
  // launches Sanctuary as a stdio subprocess, --dashboard opens an HTTP listener
  // that can interfere with stdio communication. Instead, the dashboard runs as
  // a separate standalone process (see below).
  await rewriteConfigForCocoon(
    agentConfig,
    "npx",
    [
      "@sanctuary-framework/mcp-server",
      ...(options.passphrase ? ["--passphrase", options.passphrase] : []),
    ]
  );

  // ── Post-wrap verification ─────────────────────────────────────
  const verifyOk = await verifyRewrittenConfig(agentConfig.configPath, backupPath);
  if (!verifyOk) {
    process.exit(1);
  }

  console.error(`  Agent config rewritten and verified.`);

  // Start the dashboard as a standalone process that reads from the same ~/.sanctuary/ storage.
  // This avoids the stdio + HTTP conflict that occurs when --dashboard is passed as a subprocess arg.
  const dashboardPort = options.port ?? 3501;
  console.error(`\n  Your agent is now protected.`);
  console.error(`  All tool calls are being logged and scanned.`);
  console.error(`\n  To view the dashboard, run in a separate terminal:`);
  console.error(`    npx @sanctuary-framework/mcp-server dashboard --port ${dashboardPort}`);
  console.error(`\n  To restore: npx @sanctuary-framework/mcp-server cocoon --unwrap\n`);
}

// ── Post-Wrap Verification ──────────────────────────────────────────

/**
 * Verify the rewritten config is valid JSON, contains a sanctuary entry,
 * and preserves original servers. On failure, auto-restores from backup.
 */
async function verifyRewrittenConfig(
  configPath: string,
  backupPath: string
): Promise<boolean> {
  try {
    const raw = await readFile(configPath, "utf-8");

    // Verify valid JSON
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      console.error(`\n  Verification FAILED: Rewritten config is not valid JSON.`);
      console.error(`  Error: ${(err as Error).message}`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    // Verify sanctuary entry exists
    const servers =
      (parsed.mcp as Record<string, unknown>)?.servers as Record<string, unknown> ??
      (parsed.mcpServers as Record<string, unknown>) ??
      {};

    if (!servers.sanctuary) {
      console.error(`\n  Verification FAILED: No sanctuary entry in rewritten config.`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    // Verify sanctuary entry has a command
    const sanctuaryEntry = servers.sanctuary as Record<string, unknown>;
    if (!sanctuaryEntry.command || typeof sanctuaryEntry.command !== "string") {
      console.error(`\n  Verification FAILED: Sanctuary entry has no command.`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    return true;
  } catch (err) {
    console.error(`\n  Verification FAILED: ${(err as Error).message}`);
    await restoreFromBackup(configPath, backupPath);
    return false;
  }
}

async function restoreFromBackup(configPath: string, backupPath: string): Promise<void> {
  try {
    await restoreConfig(backupPath, configPath);
    console.error(`  Original config restored from backup.`);
    console.error(`  Backup preserved at: ${backupPath}\n`);
  } catch (restoreErr) {
    console.error(`  CRITICAL: Could not restore backup from ${backupPath}`);
    console.error(`  Error: ${(restoreErr as Error).message}`);
    console.error(`  Manual recovery: copy ${backupPath} to ${configPath}\n`);
  }
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
    npx @sanctuary-framework/mcp-server cocoon --openclaw        # Wrap OpenClaw
    npx @sanctuary-framework/mcp-server cocoon --claude-code      # Wrap Claude Code
    npx @sanctuary-framework/mcp-server cocoon --cursor           # Wrap Cursor
    npx @sanctuary-framework/mcp-server cocoon --wrap config.json # Wrap generic MCP config
    npx @sanctuary-framework/mcp-server cocoon --unwrap           # Restore original config

  Options:
    --openclaw        Auto-detect and wrap OpenClaw agent
    --claude-code     Auto-detect and wrap Claude Code
    --cursor          Auto-detect and wrap Cursor
    --wrap <path>     Wrap a specific MCP config file
    --unwrap          Restore original config from backup
    --passphrase <p>  Encryption passphrase (prefer env var — see below)
    --port <port>     Dashboard port (default: 3501)
    --dry-run         Show what would happen without making changes
    --help, -h        Show this help

  Passphrase:
    Set the SANCTUARY_PASSPHRASE environment variable (recommended):

      export SANCTUARY_PASSPHRASE=$(openssl rand -base64 32)
      npx @sanctuary-framework/mcp-server cocoon --openclaw

    The --passphrase flag also works but is visible in shell history and
    process listings. Use the environment variable for production setups.

  What happens:
    1. Reads your agent's MCP server configuration
    2. Backs up the original config to ~/.sanctuary/backup/
    3. Rewrites the config so your agent routes through Sanctuary
    4. Verifies the rewritten config is valid before finishing
    5. All tool calls are logged, scanned for injection, and rate-limited
    6. Dangerous operations require your approval via the dashboard

  Rollback:
    --unwrap restores the original config from backup.
    Backups are preserved and never deleted.
`);
}
