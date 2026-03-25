#!/usr/bin/env node
/**
 * Sanctuary MCP Server — CLI Entry Point
 *
 * Starts the Sanctuary MCP server and connects it to the appropriate transport.
 * Usage: npx @sanctuary-framework/mcp-server
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createSanctuaryServer } from "./index.js";

async function main(): Promise<void> {
  const passphrase = process.env.SANCTUARY_PASSPHRASE;

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

main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
