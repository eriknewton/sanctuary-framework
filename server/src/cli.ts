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

  if (args[0] === "wrap") {
    const { parseWrapArgs, runWrap } = await import("./cocoon/cli.js");
    const opts = parseWrapArgs(args.slice(1));
    await runWrap(opts);
    return;
  }

  if (args[0] === "cocoon") {
    // Hidden deprecated alias — one-release grace period before removal.
    console.error(
      `\n  Note: \`cocoon\` is renamed to \`wrap\`. Use \`sanctuary wrap\` next time.\n`
    );
    const { parseWrapArgs, runWrap } = await import("./cocoon/cli.js");
    const opts = parseWrapArgs(args.slice(1));
    await runWrap(opts);
    return;
  }

  if (args[0] === "export-passphrase") {
    await runExportPassphrase(args.slice(1));
    return;
  }

  if (args[0] === "compliance") {
    const { runCompliance } = await import(
      "./compliance/eu_ai_act/cli.js"
    );
    await runCompliance(args.slice(1));
    return;
  }

  if (args[0] === "secrets") {
    const { runSecretsCommand } = await import("./cli/secrets.js");
    const code = await runSecretsCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "template") {
    const { runTemplateCommand } = await import("./templates/cli.js");
    const code = await runTemplateCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "agents") {
    const { runAgentsCommand } = await import("./cli/agents/index.js");
    const code = await runAgentsCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "exit") {
    const { runExitCommand } = await import("./exit/index.js");
    const code = await runExitCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "reset-passphrase") {
    const { runResetPassphraseCommand } = await import(
      "./cli/reset-passphrase.js"
    );
    const code = await runResetPassphraseCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "broker-server") {
    const { openBroker } = await import("./l3-disclosure/broker/open.js");
    const { createBrokerMcpServer } = await import("./mcp/broker-server.js");
    const { broker } = await openBroker();
    const server = createBrokerMcpServer(broker, {
      agentId: process.env.SANCTUARY_AGENT_ID ?? "mcp-host",
      identityId: process.env.SANCTUARY_IDENTITY_ID ?? "sanctuary-broker",
    });
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Sanctuary Secret Broker MCP server running (stdio)");
    return;
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--passphrase" && args[i + 1]) {
      console.error(
        `  Deprecation: --passphrase is deprecated and will be removed in v1.0.` +
        `\n  Use SANCTUARY_PASSPHRASE env var or \`sanctuary wrap\` (auto-Keychain) instead.`
      );
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
  let multi = false;
  let tenant: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--passphrase" && args[i + 1]) {
      console.error(
        `  Deprecation: --passphrase is deprecated. Use SANCTUARY_PASSPHRASE env var instead.`
      );
      passphrase = args[++i];
    } else if (args[i] === "--port" && args[i + 1]) {
      port = parseInt(args[++i]!, 10);
    } else if (args[i] === "--host" && args[i + 1]) {
      host = args[++i];
    } else if (args[i] === "--multi") {
      multi = true;
    } else if (args[i] === "--tenant" && args[i + 1]) {
      tenant = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printDashboardHelp();
      process.exit(0);
    }
  }

  if (multi || process.env.SANCTUARY_MULTI_DASHBOARD === "true") {
    const { startMultiDashboardServer } = await import(
      "./dashboard/multi-server.js"
    );
    const envPort = process.env.SANCTUARY_MULTI_DASHBOARD_PORT;
    const resolvedPort =
      port ?? (envPort ? parseInt(envPort, 10) : undefined);
    const authToken =
      process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN &&
      process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN !== "auto"
        ? process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN
        : undefined;
    const handle = await startMultiDashboardServer({
      ...(resolvedPort !== undefined ? { port: resolvedPort } : {}),
      ...(host !== undefined ? { host } : {}),
      ...(authToken !== undefined ? { authToken } : {}),
    });
    console.error(
      `Sanctuary multi-agent dashboard running at ${handle.url} (press Ctrl+C to stop).`
    );
    const shutdown = () => {
      handle.stop().finally(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    return;
  }

  const { startStandaloneDashboard } = await import("./dashboard-standalone.js");

  await startStandaloneDashboard({
    passphrase,
    port,
    host,
    ...(tenant !== undefined ? { tenant } : {}),
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

async function runExportPassphrase(args: string[]): Promise<void> {
  let assumeYes = false;
  for (const a of args) {
    if (a === "--yes" || a === "-y") assumeYes = true;
    else if (a === "--help" || a === "-h") {
      console.log(`
  sanctuary export-passphrase. Print the stored passphrase to stdout.

  Usage:
    sanctuary export-passphrase [--yes]

  Options:
    --yes, -y    Skip confirmation prompt (for scripts)
    --help, -h   Show this help

  The passphrase derives every encryption key in ~/.sanctuary. Anyone who
  has it can decrypt your state. Store the output in a password manager
  and clear your terminal history afterwards.
`);
      process.exit(0);
    }
  }

  const { readStoredPassphrase, PassphraseUnreadableError } = await import(
    "./cocoon/passphrase.js"
  );
  let stored: Awaited<ReturnType<typeof readStoredPassphrase>> = null;
  try {
    stored = await readStoredPassphrase();
  } catch (err) {
    if (err instanceof PassphraseUnreadableError) {
      console.error(`\n  Sanctuary: Passphrase Unreadable`);
      console.error(`  ${err.message}\n`);
      process.exit(2);
    }
    throw err;
  }
  if (!stored) {
    console.error("No stored passphrase found. Run `sanctuary wrap` first.");
    process.exit(1);
  }

  if (!assumeYes) {
    const readline = await import("node:readline/promises");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    const answer = await rl.question(
      `\n  This will print your passphrase (from ${stored.location}) to stdout.\n  Continue? [y/N] `
    );
    rl.close();
    if (!/^y(es)?$/i.test(answer.trim())) {
      console.error("Aborted.");
      process.exit(1);
    }
  }

  process.stdout.write(stored.value + "\n");
}

function printHelp(): void {
  console.log(`
@sanctuary-framework/mcp-server v${PKG_VERSION}

Sovereignty infrastructure for agents in the agentic economy.

Usage:
  sanctuary [options]                     # MCP server (stdio)
  sanctuary dashboard [opts]              # Standalone dashboard
  sanctuary wrap [opts]                   # Wrap an agent in one command
  sanctuary export-passphrase             # Print stored passphrase

Options:
  --dashboard          Enable the Principal Dashboard (web UI)
  --help, -h           Show this help
  --version, -v        Show version

Subcommands:
  wrap                 Wrap an agent and start the dashboard in one command.
                       Auto-generates a passphrase, auto-opens the browser.
                       Use "sanctuary wrap --help" for options.

  dashboard            Start the dashboard as a standalone HTTP server.
                       Reads from the same storage as the MCP server.
                       Use "sanctuary dashboard --help" for options.
                       Pass --multi to render the multi-tenant overview.

  template             Manage policy templates (list, init).
                       Use "sanctuary template --help" for options.

  agents               List / inspect tenants on a multi-agent host.
                       Use "sanctuary agents --help" for options.

  exit                 Export, verify, and import SANCTUARY_EXIT_BUNDLE_V1
                       bundles. Use "sanctuary exit --help" for options.

  export-passphrase    Print the stored passphrase to stdout after
                       confirmation. Use this to back up or migrate.

  reset-passphrase     Recover a fortress whose passphrase has been lost
                       or corrupted. Three modes: shares (M-of-N
                       reconstruction), guardian (federation quorum), or
                       nuke (destroys all state, fresh start).
                       Use "sanctuary reset-passphrase --help" for options.

  cocoon               (deprecated, use "wrap")

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
@sanctuary-framework/mcp-server v${PKG_VERSION}. Standalone Dashboard.

Start the Principal Dashboard as a persistent HTTP server without running
the MCP server. Use this when the MCP server runs via stdio (e.g., OpenClaw)
and the dashboard needs to stay alive independently.

Usage:
  sanctuary-mcp-server dashboard [options]

Options:
  --port <port>        Dashboard port (default: from config or 3501; 3500 for --multi)
  --host <host>        Bind address (default: 127.0.0.1)
  --tenant <name>      Boot against a specific wrapped tenant by the name printed
                       by \`sanctuary agents\`. Resolves the per-tenant storage
                       path and Keychain entry automatically. Use this on multi-
                       tenant hosts instead of guessing SANCTUARY_PASSPHRASE.
  --multi              Start the multi-agent overview instead of a single-tenant
                       dashboard. Does not decrypt any tenant state; scans every
                       tenant on the host and deep-links into per-tenant dashboards.
  --help, -h           Show this help

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_RECOVERY_KEY            Recovery key for existing installations
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_MULTI_DASHBOARD         "true" to auto-enable multi-agent mode
  SANCTUARY_MULTI_DASHBOARD_PORT    Multi-agent dashboard port (default: 3500)
  SANCTUARY_AGENTS_EXTRA_PATHS      Colon-separated extra tenant storage paths

Note: In standalone mode, the dashboard shows audit log history and policy
status. Live SSE events (tool calls, injection alerts) are only available
when the dashboard runs alongside the MCP server (--dashboard flag).

Examples:
  # Start with default settings
  sanctuary-mcp-server dashboard

  # Start on a custom port
  sanctuary-mcp-server dashboard --port 8080

  # macOS launchd: add to ~/Library/LaunchAgents/ for auto-start
`);
}

main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
