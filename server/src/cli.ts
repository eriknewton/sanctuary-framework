#!/usr/bin/env node
/**
 * Sanctuary MCP Server — CLI Entry Point
 *
 * Starts the Sanctuary MCP server and connects it to the appropriate transport.
 *
 * Usage:
 *   sanctuary-mcp-server                     # stdio transport (default)
 *   sanctuary-mcp-server dashboard            # standalone dashboard (persistent HTTP)
 *   sanctuary-mcp-server --dashboard          # enable principal dashboard alongside MCP
 *   sanctuary-mcp-server --passphrase <pass>  # derive key from passphrase
 *
 * Environment variables override CLI flags. See --help for full list.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createSanctuaryServer } from "./index.js";
import { checkForUpdate } from "./update-check.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

async function main(): Promise<void> {
  // Parse CLI flags
  const args = process.argv.slice(2);
  let passphrase = process.env.SANCTUARY_PASSPHRASE;

  // Check for subcommands first
  if (args[0] === "dashboard") {
    await runStandaloneDashboard(args.slice(1));
    return;
  }

  if (args[0] === "cocoon") {
    const { parseCocoonArgs, runCocoon } = await import("./cocoon/cli.js");
    const cocoonOpts = parseCocoonArgs(args.slice(1));
    await runCocoon(cocoonOpts);
    return;
  }

  if (args[0] === "compliance") {
    const { runCompliance } = await import(
      "./compliance/eu_ai_act/cli.js"
    );
    await runCompliance(args.slice(1));
    return;
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--passphrase" && args[i + 1]) {
      passphrase = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printHelp();
      process.exit(0);
    } else if (args[i] === "--version" || args[i] === "-v") {
      console.log(`@sanctuary-framework/mcp-server ${PKG_VERSION}`);
      process.exit(0);
    }
  }

  const { server, config } = await createSanctuaryServer({ passphrase });

  if (config.transport === "stdio") {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`Sanctuary MCP Server v${config.version} running (stdio)`);
    console.error(`Storage: ${config.storage_path}`);
    console.error("Tools: all registered");

    // Non-blocking update check — fire and forget
    checkForUpdate(PKG_VERSION);
  } else {
    // HTTP transport — future implementation
    console.error("HTTP transport not yet implemented. Use stdio.");
    process.exit(1);
  }
}

/**
 * Standalone Dashboard Mode
 *
 * Starts ONLY the dashboard HTTP server — no MCP server, no stdio transport.
 * This is designed for deployments where the MCP server runs via stdio (e.g.,
 * OpenClaw), but the dashboard needs to persist independently.
 *
 * The standalone dashboard:
 * - Reads from the same ~/.sanctuary/ storage as the MCP server
 * - Shows audit log history, policy status, and baseline profile
 * - Auto-opens in the default browser
 * - Stays alive as a persistent HTTP process (suitable for launchd/systemd)
 *
 * Limitation: Live SSE events (tool calls, injection alerts) require the
 * MCP server and dashboard to be in the same process. In standalone mode,
 * the dashboard shows historical data from the audit log. Live monitoring
 * requires running the dashboard alongside the MCP server (--dashboard flag).
 */
async function runStandaloneDashboard(args: string[]): Promise<void> {
  let passphrase = process.env.SANCTUARY_PASSPHRASE;
  let port: number | undefined;
  let host: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--passphrase" && args[i + 1]) {
      passphrase = args[++i];
    } else if (args[i] === "--port" && args[i + 1]) {
      port = parseInt(args[++i]!, 10);
    } else if (args[i] === "--host" && args[i + 1]) {
      host = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printDashboardHelp();
      process.exit(0);
    }
  }

  const { startStandaloneDashboard } = await import("./dashboard-standalone.js");

  await startStandaloneDashboard({
    passphrase,
    port,
    host,
  });

  // Keep the process alive — the HTTP server is listening
  console.error(`\nSanctuary Dashboard running (standalone mode). Press Ctrl+C to stop.\n`);

  // Graceful shutdown
  const shutdown = () => {
    console.error("\nShutting down Sanctuary Dashboard...");
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

function printHelp(): void {
  console.log(`
@sanctuary-framework/mcp-server v${PKG_VERSION}

Sovereignty infrastructure for agents in the agentic economy.

Usage:
  sanctuary-mcp-server [options]          # MCP server (stdio)
  sanctuary-mcp-server dashboard [opts]   # Standalone dashboard
  sanctuary-mcp-server cocoon [opts]      # Wrap agent in Cocoon protection

Options:
  --dashboard          Enable the Principal Dashboard (web UI)
  --passphrase <pass>  Derive encryption key from passphrase
  --help, -h           Show this help
  --version, -v        Show version

Subcommands:
  dashboard            Start the dashboard as a standalone HTTP server.
                       Reads from the same storage as the MCP server.
                       Use "sanctuary-mcp-server dashboard --help" for options.

  cocoon               Wrap an existing agent in Sanctuary's enforcement chain.
                       One command to protect any MCP-compatible agent.
                       Use "sanctuary-mcp-server cocoon --help" for options.

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_DASHBOARD_ENABLED       "true" to enable dashboard
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_WEBHOOK_ENABLED         "true" to enable webhook approvals
  SANCTUARY_WEBHOOK_URL             Webhook target URL
  SANCTUARY_WEBHOOK_SECRET          HMAC-SHA256 shared secret
  SANCTUARY_NO_UPDATE_CHECK         "1" to disable startup update check

For more info: https://github.com/eriknewton/sanctuary-framework
`);
}

function printDashboardHelp(): void {
  console.log(`
@sanctuary-framework/mcp-server v${PKG_VERSION} — Standalone Dashboard

Start the Principal Dashboard as a persistent HTTP server without running
the MCP server. Use this when the MCP server runs via stdio (e.g., OpenClaw)
and the dashboard needs to stay alive independently.

Usage:
  sanctuary-mcp-server dashboard [options]

Options:
  --port <port>        Dashboard port (default: from config or 3501)
  --host <host>        Bind address (default: 127.0.0.1)
  --passphrase <pass>  Derive encryption key from passphrase
  --help, -h           Show this help

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_RECOVERY_KEY            Recovery key for existing installations
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"

Note: In standalone mode, the dashboard shows audit log history and policy
status. Live SSE events (tool calls, injection alerts) are only available
when the dashboard runs alongside the MCP server (--dashboard flag).

Examples:
  # Start with default settings
  sanctuary-mcp-server dashboard

  # Start on a custom port
  sanctuary-mcp-server dashboard --port 8080

  # Start with passphrase
  sanctuary-mcp-server dashboard --passphrase "my secret"

  # macOS launchd: add to ~/Library/LaunchAgents/ for auto-start
`);
}

main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
