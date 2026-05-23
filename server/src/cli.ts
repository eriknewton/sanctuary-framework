#!/usr/bin/env node
/**
 * Sanctuary MCP Server: CLI Entry Point
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
import { refuseMissingMcpChildFortressOrExit } from "./mcp-child-fortress-refusal.js";
import { checkForUpdate } from "./update-check.js";
import { createRequire } from "node:module";
import { basename } from "node:path";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

async function main(): Promise<void> {
  // Parse CLI flags
  const invokedAs = basename(process.argv[1] ?? "");
  let args = process.argv.slice(2);
  if (
    invokedAs === "verify-exit-bundle" ||
    invokedAs === "import-exit-bundle"
  ) {
    args = [invokedAs, ...args];
  }
  if (await handleHelpEarly(args)) {
    process.exit(0);
  }
  let passphrase = process.env.SANCTUARY_PASSPHRASE;

  // v1.1.2 hotfix (Finding W): the MCP-server-boot path documents
  // SANCTUARY_FORTRESS_PATH as an operator-friendly alias for
  // SANCTUARY_STORAGE_PATH (see help text below) but pre-fix never
  // promoted the env var, so a fortress persisted via `sanctuary wrap
  // --fortress <path>` never reached resolveStoragePath() / config.ts on
  // harness restart. Promote here once, before any subcommand or boot
  // path reads either var. Idempotent on re-run; STORAGE_PATH wins when
  // both are set.
  if (
    process.env.SANCTUARY_FORTRESS_PATH &&
    !process.env.SANCTUARY_STORAGE_PATH
  ) {
    process.env.SANCTUARY_STORAGE_PATH = process.env.SANCTUARY_FORTRESS_PATH;
  }

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

  if (args[0] === "init") {
    const { parseInitArgs, runInit, printInitHelp } = await import(
      "./cocoon/init.js"
    );
    const opts = parseInitArgs(args.slice(1));
    if (opts.helpRequested) {
      printInitHelp();
      process.exit(0);
    }
    try {
      await runInit(opts);
      process.exit(0);
    } catch {
      process.exit(1);
    }
  }

  if (args[0] === "cocoon") {
    // Hidden deprecated alias. One-release grace period before removal.
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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

  if (args[0] === "castle-wall") {
    const code = runCastleWallCommand(args.slice(1));
    drainAndExit(code);
  }

  if (args[0] === "secrets") {
    const { runSecretsCommand } = await import("./cli/secrets.js");
    const code = await runSecretsCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "template") {
    const { runTemplateCommand } = await import("./templates/cli.js");
    const code = await runTemplateCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "identity") {
    const { runIdentityCommand } = await import("./cli/identity.js");
    const code = await runIdentityCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "agents" || args[0] === "agent") {
    const { runAgentsCommand } = await import("./cli/agents/index.js");
    const code = await runAgentsCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "exit") {
    const { runExitCommand } = await import("./exit/index.js");
    const code = await runExitCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (
    args[0] === "verify-exit-bundle" ||
    args[0] === "import-exit-bundle"
  ) {
    const { runExitCommand } = await import("./exit/index.js");
    const code = await runExitCommand({ argv: args });
    drainAndExit(code);
  }

  if (args[0] === "reset-passphrase") {
    const { runResetPassphraseCommand } = await import(
      "./cli/reset-passphrase.js"
    );
    const code = await runResetPassphraseCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "intelligence") {
    const { runIntelligenceCommand } = await import(
      "./cli/intelligence.js"
    );
    const code = await runIntelligenceCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "sentinel") {
    const { runSentinelCommand } = await import("./cli/sentinel.js");
    const code = await runSentinelCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "did-web") {
    const { runDidWebCommand } = await import("./cli/did-web.js");
    const code = await runDidWebCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "anomaly") {
    const { runAnomalyCommand } = await import("./cli/anomaly.js");
    const code = await runAnomalyCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "policy") {
    const { runPolicyCommand } = await import("./cli/policy.js");
    const code = await runPolicyCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "auto-trigger") {
    const { runAutoTriggerCommand } = await import("./cli/auto-trigger.js");
    const code = await runAutoTriggerCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "erc8004") {
    const { runErc8004Command } = await import("./cli/erc8004.js");
    const code = await runErc8004Command({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "inbox") {
    const { runInboxCommand } = await import("./cli/inbox.js");
    const code = await runInboxCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "task") {
    const { runTaskCommand } = await import("./cli/task.js");
    const code = await runTaskCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "concierge") {
    const { runConciergeCommand } = await import("./cli/concierge.js");
    const code = await runConciergeCommand({ argv: args.slice(1) });
    drainAndExit(code);
  }

  if (args[0] === "audit-chain") {
    const verb = args[1];
    const subArgs = args.slice(2);
    const wantsHelp = verb === "--help" || verb === "-h" ||
      subArgs.includes("--help") || subArgs.includes("-h");
    if (verb === "export") {
      if (wantsHelp) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
        console.error(`Usage: sanctuary audit-chain export [options]

Options:
  --output <path>        Write JSONL to file (default: stdout)
  --fortress <path>      Override fortress path
  --storage-path <path>  Override state directory
  --help, -h             Show this help
`);
        process.exit(0);
      }
      const { parseExportArgs, runExport } = await import("./cli/audit-chain-export.js");
      const opts = parseExportArgs(subArgs, process.env);
      await runExport(opts);
      process.exit(0);
    } else if (verb === "verify") {
      if (wantsHelp) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
        console.error(`Usage: sanctuary audit-chain verify [options]

Options:
  --input <path>         JSONL file to verify (required)
  --public-key <key>     Ed25519 public key for signature check (base64url)
  --no-strict            Continue on verification failures
  --storage-path <path>  Override state directory
  --help, -h             Show this help
`);
        process.exit(0);
      }
      const { parseVerifyArgs, runVerify } = await import("./cli/audit-chain-verify.js");
      const opts = parseVerifyArgs(subArgs, process.env);
      await runVerify(opts);
      process.exit(0);
    } else {
      // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
      console.error(`Usage: sanctuary audit-chain <export|verify> [options]

Commands:
  export   Dump audit chain to JSONL (--output <path>, --storage-path <path>)
  verify   Verify a JSONL export  (--input <path>, --public-key <key>, --no-strict)
`);
      process.exit(wantsHelp ? 0 : 1);
    }
  }

  if (args[0] === "broker-server") {
    const { openBroker } = await import("./l3-disclosure/broker/open.js");
    const { createBrokerMcpServer } = await import("./mcp/broker-server.js");
    const { loadConfig } = await import("./config.js");
    const { fortressIdFromStoragePath } = await import("./dashboard/v1_1/wiring.js");
    const config = await loadConfig();
    const agentId = process.env.SANCTUARY_AGENT_ID ?? "mcp-host";
    const fortressId =
      process.env.SANCTUARY_FORTRESS_ID ?? fortressIdFromStoragePath(config.storage_path);
    const { broker } = await openBroker();
    const server = createBrokerMcpServer(broker, {
      skill: process.env.SANCTUARY_BROKER_SKILL ?? process.env.SANCTUARY_SKILL_NAME ?? agentId,
      agentId,
      identityId: process.env.SANCTUARY_IDENTITY_ID ?? "sanctuary-broker",
      tenantId: process.env.SANCTUARY_TENANT_ID ?? config.storage_path,
      fortressId,
      audience: process.env.SANCTUARY_BROKER_AUDIENCE ?? "sanctuary-broker",
    });
    const transport = new StdioServerTransport();
    await server.connect(transport);
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error("Sanctuary Secret Broker MCP server running (stdio)");
    return;
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--passphrase" && args[i + 1]) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Deprecation: --passphrase is deprecated and will be removed in v1.0.` +
        `\n  Use SANCTUARY_PASSPHRASE env var or \`sanctuary wrap\` (auto-Keychain) instead.`
      );
      passphrase = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printHelp();
      process.exit(0);
    } else if (args[i] === "--version" || args[i] === "-v") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.log(`@sanctuary-framework/mcp-server ${PKG_VERSION}`);
      process.exit(0);
    }
  }

  await refuseMissingMcpChildFortressOrExit();

  const { server, config } = await createSanctuaryServer({ passphrase });

  if (config.transport === "stdio") {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Sanctuary MCP Server v${config.version} running (stdio)`);
    console.error(`Storage: ${config.storage_path}`);
    console.error("Tools: all registered");

    // Non-blocking update check. Fire and forget.
    checkForUpdate(PKG_VERSION);
  } else {
    // HTTP transport (future implementation)
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error("HTTP transport not yet implemented. Use stdio.");
    process.exit(1);
  }
}

/**
 * Standalone Dashboard Mode
 *
 * Starts ONLY the dashboard HTTP server. No MCP server, no stdio transport.
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
  let noConfirm = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--passphrase" && args[i + 1]) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
    } else if (args[i] === "--no-confirm") {
      noConfirm = true;
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
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
    noConfirm,
  });

  // Keep the process alive. The HTTP server is listening.
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\nSanctuary Dashboard running (standalone mode). Press Ctrl+C to stop.\n`);

  // Graceful shutdown
  const shutdown = () => {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      printExportPassphraseHelp();
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Passphrase Unreadable`);
      console.error(`  ${err.message}\n`);
      process.exit(2);
    }
    throw err;
  }
  if (!stored) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("Aborted.");
      process.exit(1);
    }
  }

  process.stdout.write(stored.value + "\n");
}

function printHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
@sanctuary-framework/mcp-server v${PKG_VERSION}

Sovereignty infrastructure for agents in the agentic economy.

Usage:
  sanctuary [options]                     # MCP server (stdio)
  sanctuary init [opts]                   # Create a fresh fortress
  sanctuary dashboard [opts]              # Standalone dashboard
  sanctuary wrap [opts]                   # Wrap an agent in one command
  sanctuary export-passphrase             # Print stored passphrase

Options:
  --dashboard          Enable the Principal Dashboard (web UI)
  --help, -h           Show this help
  --version, -v        Show version

Subcommands:
  init                 Create a fresh fortress at a chosen path. Pairs
                       with --fortress to keep multiple fortresses
                       isolated on one host.
                       Use "sanctuary init --help" for options.

  wrap                 Wrap an agent and start the dashboard in one command.
                       Auto-generates a passphrase, auto-opens the browser.
                       Use "sanctuary wrap --help" for options.

  dashboard            Start the dashboard as a standalone HTTP server.
                       Reads from the same storage as the MCP server.
                       Use "sanctuary dashboard --help" for options.
                       Pass --multi to render the multi-tenant overview.

  identity             Inspect the active identity (DID, public key).
                       Use "sanctuary identity --help" for options.

  template             Manage policy templates (list, init).
                       Use "sanctuary template --help" for options.

  agents               List / inspect tenants on a multi-agent host.
                       Use "sanctuary agents --help" for options.

  exit                 Export, verify, and import SANCTUARY_EXIT_BUNDLE_V1
                       bundles. Use "sanctuary exit --help" for options.

  export-passphrase    Print the stored passphrase to stdout after
                       confirmation. Use this to back up or migrate.

  castle-wall          Inspect Castle Wall CLI commands.
                       Use "sanctuary castle-wall --help" for options.

  reset-passphrase     Recover a fortress whose passphrase has been lost
                       or corrupted. Three modes: shares (M-of-N
                       reconstruction), guardian (federation quorum), or
                       nuke (destroys all state, fresh start).
                       Use "sanctuary reset-passphrase --help" for options.

  cocoon               (deprecated, use "wrap")

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_FORTRESS_PATH           Operator-friendly alias for STORAGE_PATH
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
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
  --no-confirm         Skip the recovery-key confirmation prompt on first run.
                       Required for non-TTY callers (CI, launchd, systemd).
  --help, -h           Show this help

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_FORTRESS_PATH           Operator-friendly alias for STORAGE_PATH
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

async function handleHelpEarly(args: string[]): Promise<boolean> {
  if (!args.includes("--help") && !args.includes("-h")) {
    return false;
  }

  const command = args[0];
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return true;
  }

  switch (command) {
    case "dashboard":
      printDashboardHelp();
      return true;
    case "wrap":
    case "cocoon":
      printWrapHelpEarly();
      return true;
    case "init": {
      const { printInitHelp } = await import("./cocoon/init.js");
      printInitHelp();
      return true;
    }
    case "agents":
    case "agent": {
      const { printAgentsHelp } = await import("./cli/agents/index.js");
      printAgentsHelp();
      return true;
    }
    case "exit":
    case "verify-exit-bundle":
    case "import-exit-bundle": {
      const { printExitHelp } = await import("./exit/index.js");
      printExitHelp();
      return true;
    }
    case "export-passphrase":
      printExportPassphraseHelp();
      return true;
    case "castle-wall":
      printCastleWallHelp();
      return true;
    default:
      return false;
  }
}

function runCastleWallCommand(args: string[]): number {
  const command = args[0];
  if (!command || command === "--help" || command === "-h") {
    printCastleWallHelp();
    return 0;
  }

  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `Unknown subcommand: ${command}. Try: sanctuary castle-wall --help`
  );
  return 2;
}

function printCastleWallHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
  sanctuary castle-wall. Castle Wall command surface.

  Usage:
    sanctuary castle-wall [--help]

  Options:
    --help, -h   Show this help

  Status inspection is not available in this release.
`);
}

function printExportPassphraseHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
}

function printWrapHelpEarly(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
  sanctuary wrap. Wrap any agent in Sanctuary protection.

  Usage:
    sanctuary wrap --openclaw          Wrap OpenClaw
    sanctuary wrap --hermes            Wrap Hermes Agent (NousResearch)
    sanctuary wrap --claude-code       Wrap Claude Code
    sanctuary wrap --cursor            Wrap Cursor
    sanctuary wrap --cline             Wrap Cline (VS Code extension)
    sanctuary wrap --wrap <path>       Wrap a specific MCP config file
    sanctuary wrap --unwrap            Restore original config

  Options:
    --openclaw         Auto-detect and wrap OpenClaw
    --hermes           Auto-detect and wrap Hermes Agent
    --claude-code      Auto-detect and wrap Claude Code
    --cursor           Auto-detect and wrap Cursor
    --cline            Auto-detect and wrap Cline (VS Code extension)
    --wrap <path>      Wrap a specific MCP config file
    --unwrap           Restore original config from backup
    --passphrase <p>   Override the stored passphrase (one-off)
    --fortress <path>  Fortress directory (default: ~/.sanctuary). Honors
                       SANCTUARY_FORTRESS_PATH env var when the flag is
                       absent. Use to keep multiple fortresses isolated
                       on one host.
    --port <port>      Preferred dashboard port (default: 3501)
    --dry-run          Show what would happen without making changes
    --no-open          Do not auto-open the dashboard in a browser
    --no-dashboard     Do not spawn a per-call dashboard server. Wrap still
                       persists the agent record so a separately-running
                       \`sanctuary dashboard\` (or a later wrap) sees the
                       harness. Use this for the clean operator setup
                       (one persistent dashboard + many wraps).
    --dev-dist <path>  Dogfood path. Point the harness MCP entries at a
                       local Sanctuary build (\`node <path>\` instead of
                       \`npx @sanctuary-framework/mcp-server\`). Required
                       when testing an unpublished branch; the published
                       version doesn't have new subcommands yet, and
                       npx pulls from the registry, not your checkout.
                       Pass the absolute path to dist/cli.js.
    --help, -h         Show this help

  What happens:
    1. Reads your agent's MCP config
    2. Generates a passphrase (stored in Keychain on macOS, encrypted file elsewhere)
    3. Backs up and rewrites the config so calls route through Sanctuary
    4. Starts the Sovereignty Dashboard and opens it in your browser
    5. Every tool call is logged, scanned, and tier-gated
`);
}

/**
 * Drain stdout then exit. process.exit() can lose buffered writes when
 * stdout is a pipe or file redirect (e.g. `sanctuary task create --json > out.json`).
 * Writing an empty string and waiting for the callback ensures all prior
 * writes have been flushed to the OS before termination.
 */
function drainAndExit(code: number): void {
  if (!process.stdout.writable) {
    process.exit(code);
    return;
  }
  process.exitCode = code;
  process.stdout.write("", () => process.exit(code));
}

main().catch((err) => {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
