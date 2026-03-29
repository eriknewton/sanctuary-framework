#!/usr/bin/env node
/**
 * Sanctuary MCP Server — CLI Entry Point
 *
 * Starts the Sanctuary MCP server and connects it to the appropriate transport.
 *
 * Usage:
 *   sanctuary-mcp-server                     # stdio transport (default)
 *   sanctuary-mcp-server --dashboard          # enable principal dashboard
 *   sanctuary-mcp-server --passphrase <pass>  # derive key from passphrase
 *
 * Environment variables override CLI flags. See --help for full list.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createSanctuaryServer } from "./index.js";

async function main(): Promise<void> {
  // Parse CLI flags
  const args = process.argv.slice(2);
  let passphrase = process.env.SANCTUARY_PASSPHRASE;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--passphrase" && args[i + 1]) {
      passphrase = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printHelp();
      process.exit(0);
    } else if (args[i] === "--version" || args[i] === "-v") {
      console.log("@sanctuary-framework/mcp-server 0.3.0");
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
  } else {
    // HTTP transport — future implementation
    console.error("HTTP transport not yet implemented. Use stdio.");
    process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
@sanctuary-framework/mcp-server v0.3.0

Sovereignty infrastructure for agents in the agentic economy.

Usage:
  sanctuary-mcp-server [options]

Options:
  --dashboard          Enable the Principal Dashboard (web UI)
  --passphrase <pass>  Derive encryption key from passphrase
  --help, -h           Show this help
  --version, -v        Show version

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_DASHBOARD_ENABLED       "true" to enable dashboard
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_WEBHOOK_ENABLED         "true" to enable webhook approvals
  SANCTUARY_WEBHOOK_URL             Webhook target URL
  SANCTUARY_WEBHOOK_SECRET          HMAC-SHA256 shared secret

For more info: https://github.com/eriknewton/sanctuary-framework
`);
}

main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
