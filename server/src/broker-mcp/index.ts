/**
 * Sanctuary Broker MCP - Public surface.
 *
 * Standalone MCP server that exposes the Secret Broker (four tools:
 * request_token / read_secret / list_grants / audit_query) so any
 * MCP-speaking harness can consume it as a drop-in sovereignty primitive.
 *
 * This barrel re-exports the library factory and its options type only.
 * The broker-server subcommand wiring (stdio transport, process.argv,
 * server.connect) lives in server/src/cli.ts; this module is pure API and
 * runs no code at import time.
 */

export * from "./broker-server.js";
