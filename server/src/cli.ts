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
import { checkForUpdate, checkForSignedUpdate } from "./update-check.js";
import { printFirstRunNoticeOnce } from "./first-run-notice.js";
import { assertSupportedNodeVersion } from "./cli/node-version.js";
import { extractTopLevelFortressFlag } from "./cli/top-level-fortress.js";
import { SUPERVISOR_KEY_FD_ENV } from "./supervisor/spawn-launcher.js";
import { createRequire } from "node:module";
import { basename } from "node:path";
export { TOP_LEVEL_SUBCOMMANDS } from "./cli/subcommands.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json");

/**
 * Fallback exit deadline for the broker daemon's clean shutdown. If the
 * stand-down audit flush wedges on a storage backend that never settles, the
 * SIGTERM/SIGINT handler would otherwise hang forever (the signal listener
 * suppresses Node's default termination). The watchdog forces `process.exit(0)`
 * after this window so the daemon dies promptly instead of waiting for an OS
 * SIGKILL. Generous enough that a healthy flush always finishes first.
 */
const BROKER_SHUTDOWN_WATCHDOG_MS = 5000;

async function main(): Promise<void> {
  assertSupportedNodeVersion();

  // Parse CLI flags
  const invokedAs = basename(process.argv[1] ?? "");
  let args = process.argv.slice(2);
  if (
    invokedAs === "verify-exit-bundle" ||
    invokedAs === "import-exit-bundle"
  ) {
    args = [invokedAs, ...args];
  }

  // v1.3.3 fix (F-1.3.2-N-001): honor the top-level --fortress flag for
  // state I/O. Pre-fix, `sanctuary --fortress <path> <subcommand>`
  // silently ignored BOTH the flag and the subcommand (dispatch matched
  // on args[0]) and booted the MCP server against ~/.sanctuary. Honoring
  // means promoting the flag to SANCTUARY_STORAGE_PATH before any
  // dispatch or env promotion below; every state I/O path already honors
  // that variable end-to-end (config.ts). The operator-typed flag wins
  // over both env vars. A malformed flag fails loud instead of being
  // ignored ("never silently degrade").
  const fortressFlag = extractTopLevelFortressFlag(args);
  if (fortressFlag.error) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module is in scope yet.
    console.error(`sanctuary: ${fortressFlag.error}`);
    process.exit(1);
  }
  if (fortressFlag.fortressPath !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag.fortressPath;
    // Keep the operator-friendly alias coherent for subcommands and child
    // processes that read SANCTUARY_FORTRESS_PATH directly.
    process.env.SANCTUARY_FORTRESS_PATH = fortressFlag.fortressPath;
  }
  args = fortressFlag.args;

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

  if (args[0] === "install") {
    const { runInstallCommand } = await import("./cli/install.js");
    const code = await runInstallCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "protect" || args[0] === "wrap") {
    // Phase S1 supervisor handoff (codex R3-H1): when launched BY the
    // split-process supervisor, the transient master key arrives on an
    // inherited one-shot fd (never env/argv). Consume + close it at the
    // earliest point so it cannot linger for a same-uid `/proc/<pid>/fd` race,
    // and FAIL CLOSED in supervisor mode: never silently fall through to the
    // passphrase/keychain path. Threading the raw master into wrap custody
    // (`establishWrapCustody`) is the drill-gated last mile (S1 acceptance is
    // Erik-present on the signing host); until that lands, supervisor mode
    // refuses rather than running an unintended custody path.
    if (process.env[SUPERVISOR_KEY_FD_ENV] !== undefined) {
      const { readSupervisorTransientKey } = await import("./supervisor/spawn-launcher.js");
      let transientKey: Uint8Array | null = null;
      try {
        transientKey = readSupervisorTransientKey();
      } catch (err) {
        // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
        console.error(`\n  Sanctuary wrap: supervisor key handoff failed`);
        console.error(`  ${(err as Error).message}\n`);
        process.exit(2);
      }
      // Drain succeeded: zero our copy immediately (the master-unlock wiring is
      // the drill last mile; we do NOT proceed on a half-wired custody path).
      if (transientKey) transientKey.fill(0);
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `\n  Sanctuary wrap: supervised launch detected (${SUPERVISOR_KEY_FD_ENV}).` +
          `\n  Transient-key custody establishment is the Erik-present S1 acceptance` +
          `\n  drill's last mile and is not yet wired into wrap custody. Refusing to` +
          `\n  boot on a fallback credential path. (Build: split-process supervisor,` +
          `\n  socket auth, idempotency, and rotation guards are complete + tested.)\n`,
      );
      process.exit(2);
    }
    const { parseWrapArgs, runWrap } = await import("./wrap/cli.js");
    const opts = parseWrapArgs(args.slice(1));
    if (args[0] === "protect") opts.protectCommand = true;
    // Dashboard-fold PR-4 (ratified decision 1): inject the ONE main
    // dashboard's in-process starter. `runWrap` detects-and-reuses a live
    // main dashboard for the fortress and only calls this when none exists.
    // The closure lives HERE because wrap/cli must not import
    // dashboard-standalone itself (that edge would introduce a new import
    // cycle; see test/structure/import-cycle-baseline.test.ts).
    await runWrap(opts, {
      startOwnedDashboard: async ({ storagePath, port, passphrase }) => {
        const { startStandaloneDashboard } = await import(
          "./dashboard-standalone.js"
        );
        await startStandaloneDashboard({
          storagePath,
          port,
          ...(passphrase !== undefined ? { passphrase } : {}),
          // Fix round 1, F1 (ratified decision 2): a protect-started
          // dashboard must never sit tokenless-open on the folded read
          // routes. When no source configures dashboard.auth_token, the
          // boot mints one (and prints it as "Operator token:"); a
          // configured token always wins. Loopback auto-auth after unlock
          // keeps the browser UX.
          mintAuthTokenIfAbsent: true,
        });
        // The standalone boot binds exactly the requested loopback port (no
        // silent walk) and writes the tenant's runtime.json itself — the
        // single production writer.
        return { url: `http://127.0.0.1:${port}`, port };
      },
    });
    return;
  }

  if (args[0] === "uninstall") {
    const { runUninstallCommand } = await import("./cli/uninstall.js");
    const code = await runUninstallCommand({ argv: args.slice(1) });
    process.exit(code);
  }

  if (args[0] === "init") {
    const { parseInitArgs, runInit, printInitHelp } = await import(
      "./wrap/init.js"
    );
    try {
      const opts = parseInitArgs(args.slice(1));
      if (opts.helpRequested) {
        printInitHelp();
        process.exit(0);
      }
      await runInit(opts);
      process.exit(0);
    } catch (err) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand; print only the error message, never any recovery-key material.
      console.error(`\n  Sanctuary init failed: ${formatCliError(err)}\n`);
      process.exit(1);
    }
  }

  if (args[0] === "export-passphrase") {
    await runExportPassphrase(args.slice(1));
    return;
  }

  if (args[0] === "status") {
    const { runStatusCommand } = await import("./cli/status.js");
    const code = await runStatusCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "doctor") {
    const { runDoctorCommand } = await import("./cli/doctor.js");
    const code = await runDoctorCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "check-updates") {
    const { runCheckUpdatesCommand } = await import("./cli/check-updates.js");
    const code = await runCheckUpdatesCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "completion") {
    const { runCompletionCommand } = await import("./cli/completion.js");
    const code = await runCompletionCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "audit") {
    const { runAuditCommand } = await import("./cli/audit.js");
    const code = await runAuditCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "distress") {
    const { runDistressCommand } = await import("./cli/distress.js");
    const code = await runDistressCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "cortex-export") {
    const { runCortexExportCommand } = await import("./cli/cortex-export.js");
    const code = await runCortexExportCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "generate") {
    const { runGenerateCommand } = await import("./cli/generate.js");
    const code = await runGenerateCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "deploy") {
    const { runDeployCommand } = await import("./cli/deploy.js");
    const code = await runDeployCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "compliance") {
    const { runCompliance } = await import(
      "./compliance/eu_ai_act/cli.js"
    );
    await runCompliance(args.slice(1));
    return;
  }

  if (args[0] === "evidence-pack") {
    const { runEvidencePack } = await import("./evidence-pack/cli.js");
    await runEvidencePack(args.slice(1));
    return;
  }

  if (args[0] === "castle-wall") {
    const code = await runCastleWallCommand(args.slice(1));
    drainAndExit(code);
  }

  if (args[0] === "secrets") {
    const { runSecretsCommand } = await import("./cli/secrets.js");
    const code = await runSecretsCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "template") {
    const { runTemplateCommand } = await import("./templates/cli.js");
    const code = await runTemplateCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "identity") {
    const { runIdentityCommand } = await import("./cli/identity.js");
    const code = await runIdentityCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "agents" || args[0] === "agent") {
    const { runAgentsCommand } = await import("./cli/agents/index.js");
    const code = await runAgentsCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "exit") {
    const { runExitCommand } = await import("./exit/index.js");
    const code = await runExitCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "federation") {
    const { runFederationCommand } = await import("./cli/federation.js");
    const code = await runFederationCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "file-grant") {
    const { runFileGrantCommand } = await import("./cli/file-grant.js");
    const code = await runFileGrantCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "checkpoint") {
    const { runCheckpointCommand } = await import("./cli/checkpoint.js");
    const code = await runCheckpointCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_ingest") {
    const { runMemoryIngestCommand } = await import("./cli/memory-file.js");
    const code = await runMemoryIngestCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_emit") {
    const { runMemoryEmitCommand } = await import("./cli/memory-file.js");
    const code = await runMemoryEmitCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_transcode") {
    const { runMemoryTranscodeCommand } = await import("./cli/memory-file.js");
    const code = await runMemoryTranscodeCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_transcode_restore") {
    const { runMemoryTranscodeRestoreCommand } = await import("./cli/memory-file.js");
    const code = await runMemoryTranscodeRestoreCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_archive_export") {
    const { runMemoryArchiveExportCommand } = await import("./cli/memory-archive.js");
    const code = await runMemoryArchiveExportCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "memory_archive_import") {
    const { runMemoryArchiveImportCommand } = await import("./cli/memory-archive.js");
    const code = await runMemoryArchiveImportCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "state_disclose_unattributed") {
    const { runStateDiscloseUnattributedCommand } = await import(
      "./cli/state-disclose.js"
    );
    const code = await runStateDiscloseUnattributedCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "license") {
    const { runLicenseCommand } = await import("./cli/license.js");
    const code = await runLicenseCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "liveness-probe") {
    const { runLivenessProbeCommand } = await import("./cli/liveness-probe.js");
    const code = await runLivenessProbeCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "fleet") {
    const { runFleetCommand } = await import("./cli/fleet.js");
    const code = await runFleetCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "plugin") {
    const { runPluginCommand } = await import("./cli/plugin.js");
    const code = await runPluginCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "nodes") {
    const { runNodesCommand } = await import("./cli/nodes.js");
    const code = await runNodesCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (
    args[0] === "verify-exit-bundle" ||
    args[0] === "import-exit-bundle"
  ) {
    const { runExitCommand } = await import("./exit/index.js");
    const code = await runExitCommand({ argv: args });
    return drainAndExit(code);
  }

  if (args[0] === "reset-passphrase") {
    const { runResetPassphraseCommand } = await import(
      "./cli/reset-passphrase.js"
    );
    const code = await runResetPassphraseCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "rotate-master") {
    const { runRotateMasterCommand } = await import(
      "./cli/rotate-master.js"
    );
    const code = await runRotateMasterCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "restore-attest") {
    const { runRestoreAttestCommand } = await import(
      "./cli/restore-attest.js"
    );
    const code = await runRestoreAttestCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "intelligence") {
    const { runIntelligenceCommand } = await import(
      "./cli/intelligence.js"
    );
    const code = await runIntelligenceCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "sentinel") {
    const { runSentinelCommand } = await import("./cli/sentinel.js");
    const code = await runSentinelCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "did-web") {
    const { runDidWebCommand } = await import("./cli/did-web.js");
    const code = await runDidWebCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "anomaly") {
    const { runAnomalyCommand } = await import("./cli/anomaly.js");
    const code = await runAnomalyCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "policy") {
    const { runPolicyCommand } = await import("./cli/policy.js");
    const code = await runPolicyCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "auto-trigger") {
    const { runAutoTriggerCommand } = await import("./cli/auto-trigger.js");
    const code = await runAutoTriggerCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "erc8004") {
    const { runErc8004Command } = await import("./cli/erc8004.js");
    const code = await runErc8004Command({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "inbox") {
    const { runInboxCommand } = await import("./cli/inbox.js");
    const code = await runInboxCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "task") {
    const { runTaskCommand } = await import("./cli/task.js");
    const code = await runTaskCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "concierge") {
    const { runConciergeCommand } = await import("./cli/concierge.js");
    const code = await runConciergeCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "transparency") {
    const { runTransparencyCommand } = await import("./cli/transparency.js");
    const code = await runTransparencyCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "verify-transparency") {
    const { runVerifyTransparencyCommand } = await import(
      "./cli/transparency.js"
    );
    const code = await runVerifyTransparencyCommand({ argv: args.slice(1) });
    return drainAndExit(code);
  }

  if (args[0] === "audit-chain") {
    const verb = args[1];
    const subArgs = args.slice(2);
    const wantsHelp = verb === "--help" || verb === "-h" ||
      subArgs.includes("--help") || subArgs.includes("-h");
    if (verb === "export") {
      if (wantsHelp) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
        console.error(`sanctuary audit-chain export. Dump audit chain records to JSONL.

Usage: sanctuary audit-chain export [--output <path>] [--fortress <path>] [--operator-only]

Options:
  --output <path>        Write JSONL to file (default: stdout)
  --fortress <path>      Override fortress path
  --storage-path <path>  Override state directory
  --operator-only        Acknowledge an operator-chain-only export on a fortress
                         that has a root daemon audit chain (_audit-daemon).
                         Required there; the export otherwise fails closed rather
                         than silently omitting the daemon chain.
  --help, -h             Show this help

Examples:
  sanctuary audit-chain export
  sanctuary audit-chain export --output chain.jsonl --fortress ~/.sanctuary-work
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
        console.error(`sanctuary audit-chain verify. Verify an exported Sanctuary audit chain.

Usage: sanctuary audit-chain verify --input <path> [--public-key <key>] [--trust-embedded] [--no-strict]

Options:
  --input <path>         JSONL file to verify (required)
  --public-key <key>     Ed25519 public key for signature check (base64url)
  --trust-embedded       Verify checkpoint signatures against embedded keys.
                         Proves internal consistency only, not signer identity.
  --no-strict            Report FAIL findings and exit 10 after verification
  --storage-path <path>  Override state directory
  --help, -h             Show this help

Exit codes:
  0  verification passed
  1  strict verification found one or more findings
 10  --no-strict verification completed with one or more findings

Examples:
  sanctuary audit-chain verify --input chain.jsonl
  sanctuary audit-chain verify --input chain.jsonl --public-key AbCd...
`);
        process.exit(0);
      }
      const { parseVerifyArgs, runVerify } = await import("./cli/audit-chain-verify.js");
      const opts = parseVerifyArgs(subArgs, process.env);
      return drainAndExit(await runVerify(opts));
    } else if (verb === "repair-plan") {
      if (wantsHelp) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
        console.error(`sanctuary audit-chain repair-plan. Describe a fortress's audit-chain state and what a repair would do.

Read-only. Changes nothing, decides nothing, and needs no authority. Runs
offline against the fortress directory, so it still works on a fortress whose
audit chain prevents the server from starting.

Usage: sanctuary audit-chain repair-plan [--fortress <path>] [--storage-path <path>]

Options:
  --fortress <path>      Fortress path (default: SANCTUARY_STORAGE_PATH, then
                         SANCTUARY_FORTRESS_PATH, then the home fortress)
  --storage-path <path>  Override the state directory
  --help, -h             Show this help

Exit codes:
  0  the chain verifies clean at this privilege; no repair applies
  1  the fortress state could not be read; NO verdict was produced
  2  usage error
  3  findings are present and fully readable here; a plan is printed
  4  part of the evidence was unreadable at this privilege, so the chain has
     NOT been shown to be damaged; re-read with more privilege

Examples:
  sanctuary audit-chain repair-plan
  sanctuary audit-chain repair-plan --fortress ~/.sanctuary-work
`);
        process.exit(0);
      }
      const { runAuditChainRepairPlan } = await import(
        "./cli/audit-chain-repair-plan.js"
      );
      return drainAndExit(await runAuditChainRepairPlan(subArgs));
    } else {
      // SAFETY: stderr / stdout is the operator-facing CLI channel; no logger module in scope.
      console.error(`Usage: sanctuary audit-chain <export|verify|repair-plan> [options]

Commands:
  export       Dump audit chain to JSONL (--output <path>, --storage-path <path>)
  verify       Verify a JSONL export  (--input <path>, --public-key <key>, --no-strict)
  repair-plan  Describe the chain's state and what a repair would do (read-only)
`);
      process.exit(wantsHelp ? 0 : 1);
    }
  }

  if (args[0] === "broker-server") {
    const { openBroker } = await import("./disclosure/broker/open.js");
    const { createBrokerMcpServer } = await import("./broker-mcp/broker-server.js");
    const { loadConfig } = await import("./config.js");
    const { fortressIdFromStoragePath } = await import("./dashboard/v1_1/wiring.js");
    const config = await loadConfig();
    const agentId = process.env.SANCTUARY_AGENT_ID ?? "mcp-host";
    const fortressId =
      process.env.SANCTUARY_FORTRESS_ID ?? fortressIdFromStoragePath(config.storage_path);
    const { broker, auditLog } = await openBroker();
    const server = createBrokerMcpServer(broker, {
      skill: process.env.SANCTUARY_BROKER_SKILL ?? process.env.SANCTUARY_SKILL_NAME ?? agentId,
      agentId,
      identityId: process.env.SANCTUARY_IDENTITY_ID ?? "sanctuary-broker",
      tenantId: process.env.SANCTUARY_TENANT_ID ?? config.storage_path,
      fortressId,
      audience: process.env.SANCTUARY_BROKER_AUDIENCE ?? "sanctuary-broker",
    });
    const { loadOrCreateBrokerProducerSigner } = await import(
      "./broker-mcp/producer-signature.js"
    );
    const producerSigner = await loadOrCreateBrokerProducerSigner(
      config.storage_path,
    );
    const transport = new StdioServerTransport();
    await server.connect(transport);

    // Observability (Option C): periodic process-liveness heartbeat for the
    // long-running broker daemon. A reader (principal-policy/feature-health.ts)
    // turns a MISSING heartbeat in a quiet window into an honest "broker daemon
    // silently died" alarm instead of `unknown`. HONEST SCOPE: this proves only
    // that this daemon PROCESS is alive, NOT that it would correctly mint/deny a
    // token and NOT that the keychain backend is reachable.
    const { startBrokerLivenessHeartbeat } = await import("./broker-mcp/liveness-heartbeat.js");
    const liveness = startBrokerLivenessHeartbeat({
      auditLog,
      fortressId,
      producerSigner,
    });

    // CRITICAL (the #657 false-RED lesson): a clean broker-server shutdown must
    // record an INTENTIONAL stand-down. Without it, every deliberate stop reads
    // as a silent death for the whole digest window. Wire it to SIGTERM / SIGINT
    // AND the transport/server close hook, then exit. `standDown()` is
    // idempotent, so overlapping triggers emit at most one stand-down.
    let shuttingDown = false;
    const shutdownBroker = (exit: boolean): void => {
      if (shuttingDown) return;
      shuttingDown = true;
      // Fire and forget: standDown() resolves even if the append/flush
      // *rejects* (fail toward the alarm), and process.exit owns the lifecycle
      // from here. But standDown() awaits auditLog.flush(), which awaits the
      // pending storage writes; a wedged backend that never SETTLES (neither
      // resolves nor rejects) would hang the flush, so the `.finally` never
      // fires. Installing a SIGTERM/SIGINT listener suppresses Node's default
      // termination, so without a fallback the daemon would hang on the signal
      // until the OS SIGKILLs it after its grace period. Arm a watchdog that
      // forces exit if the stand-down flush does not complete in time. It is
      // `.unref()`ed so it never keeps the event loop alive: a fast clean
      // stand-down still exits promptly via the `.finally` below.
      if (exit) {
        const watchdog = setTimeout(() => {
          // SAFETY: stderr is the operator-facing CLI channel; no logger in scope.
          console.error(
            "Sanctuary Secret Broker: stand-down flush did not complete in " +
            `${String(BROKER_SHUTDOWN_WATCHDOG_MS)}ms; forcing exit.`,
          );
          // Exit NON-ZERO on the watchdog path: a wedged stand-down flush is a
          // DEGRADED shutdown (the stand-down marker may not have been durably
          // written), not a clean one. Reporting it as exit 0 would tell a
          // process supervisor "clean exit" for what is really a storage wedge -
          // an overclaim on the very honesty surface this feature serves. The
          // clean `.finally` path below keeps exit 0.
          process.exit(1);
        }, BROKER_SHUTDOWN_WATCHDOG_MS);
        watchdog.unref();
        void liveness.standDown().finally(() => {
          clearTimeout(watchdog);
          process.exit(0);
        });
        return;
      }
      void liveness.standDown();
    };
    server.onclose = () => shutdownBroker(true);
    process.on("SIGTERM", () => shutdownBroker(true));
    process.on("SIGINT", () => shutdownBroker(true));

    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error("Sanctuary Secret Broker MCP server running (stdio)");
    return;
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--allow-plaintext-remote") {
      process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE = "true";
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

    // One-time zero-outbound-by-default notice (2026-07-05). Fire and
    // forget: fails open on any I/O error and never blocks startup.
    void printFirstRunNoticeOnce(config.storage_path);

    // Non-blocking update check. Fire and forget (checkForUpdate catches
    // all failures internally and never rejects).
    void checkForUpdate(PKG_VERSION);

    // Non-blocking AUTHENTICATED update check. Fetches the signed release
    // manifest from the GitHub Releases channel and verifies it against the
    // PINNED release-signing key, advising only on a verified newer version.
    // Inert (silent) while the pinned key is the all-zero placeholder; it
    // fails closed on any unsigned/wrong-key/tampered/absent manifest. Fire
    // and forget: it catches all failures internally and never rejects.
    void checkForSignedUpdate(PKG_VERSION);
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
  let recoveryOut: string | undefined;
  let allowPlaintextRemote = false;
  let allowPark = false;

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
    } else if (args[i] === "--allow-plaintext-remote") {
      allowPlaintextRemote = true;
    } else if (args[i] === "--recovery-out" && args[i + 1]) {
      recoveryOut = args[++i];
    } else if (args[i] === "--allow-park") {
      // Slice 2 (park-not-exit): opt-in. Set by the supervised LaunchAgent so
      // a locked-no-credential start boots PARKED (listener up, readiness
      // "locked", unlock door live) instead of throwing and crash-looping
      // under KeepAlive. Interactive `sanctuary dashboard` omits this and keeps
      // its loud remediation behavior.
      allowPark = true;
    } else if (args[i] === "--help" || args[i] === "-h") {
      printDashboardHelp();
      process.exit(0);
    }
  }

  if (multi || process.env.SANCTUARY_MULTI_DASHBOARD === "true") {
    const { startMultiDashboardServer } = await import(
      "./dashboard/multi-server.js"
    );
    const { loadConfig } = await import("./config.js");
    const config = await loadConfig();
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
      allowPlaintextRemote:
        allowPlaintextRemote || config.dashboard.allow_plaintext_remote,
    });
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `Sanctuary multi-agent dashboard running at ${handle.url} (press Ctrl+C to stop).`
    );
    const shutdown = () => {
      // Fire and forget: the finally callback exits the process whether or
      // not stop() rejects, so there is nothing left to propagate to.
      void handle.stop().finally(() => process.exit(0));
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
    ...(recoveryOut !== undefined ? { recoveryOut } : {}),
    ...(allowPlaintextRemote ? { allowPlaintextRemote } : {}),
    noConfirm,
    allowPark,
  });

  // Keep the process alive. The HTTP server is listening.
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\nSanctuary Dashboard running (standalone mode). Press Ctrl+C to stop.\n`);

  // Graceful shutdown: `startStandaloneDashboard` (dashboard-standalone.ts)
  // already installed its own SIGINT/SIGTERM listeners before returning
  // (`registerStandaloneProcessCleanup` -> `handleStandaloneShutdownSignal`),
  // which awaits every registered cleanup (tenant-runtime unlink, distress
  // listener stop, baseline save) and then exits with 128+signal. Registering
  // a second, synchronous listener here raced it: Node invokes listeners in
  // registration order, so this handler's synchronous `process.exit(0)` ran
  // on the same tick as the async handler's first `await`, killing the
  // process before any cleanup completed and before the async handler's own
  // exit code was ever reached. Do not add a second listener here.
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
    "./wrap/passphrase.js"
  );
  // Resolve the fortress HERE, at the CLI entry point, and pass it down.
  // Ambient resolution is correct at this layer -- for `sanctuary
  // export-passphrase` the operator's own environment IS the input -- but it
  // is stated rather than left implicit, so no leaf module has to reach for
  // process state on its own.
  const { resolveStoragePath } = await import("./paths.js");
  const storagePath = resolveStoragePath();
  let stored: Awaited<ReturnType<typeof readStoredPassphrase>>;
  try {
    stored = await readStoredPassphrase({ storagePath });
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
  sanctuary status [opts]                 # Daemon status over the /v1 API
  sanctuary doctor [opts]                 # Local environment diagnostic
  sanctuary check-updates                 # Explicitly check for updates
  sanctuary completion <bash|zsh|fish>    # Emit shell completion
  sanctuary audit search [opts]           # Search local audit log
  sanctuary checkpoint <cmd> [opts]       # Local encrypted memory checkpoints
  sanctuary memory_ingest [opts]          # Mirror harness memory into SDW
  sanctuary memory_emit [opts]            # Emit harness memory from SDW
  sanctuary memory_archive_export [opts]  # Export one SDW archive through Exit V2
  sanctuary state_disclose_unattributed [opts]
                                          # Tier-1: disclose one entry whose writer cannot be established
  sanctuary memory_archive_import [opts]  # Import one SDW archive through Exit V2
  sanctuary memory_transcode [opts]       # Project memory into another harness format
  sanctuary memory_transcode_restore [opts] # Restore an exact transcode source archive
  sanctuary transparency <cmd> [opts]     # Signed enforcement checkpoints
  sanctuary verify-transparency [opts]    # Verify a checkpoint chain offline
  sanctuary generate systemd [opts]       # Emit systemd service unit
  sanctuary deploy operator-cloud plan    # Emit operator-cloud deploy skeleton
  sanctuary install [opts]                # Resumable agent-guided install plan
  sanctuary protect [opts]                 # Protect an agent in one command
  sanctuary wrap [opts]                   # (alias for protect)
  sanctuary uninstall [opts]              # Remove installed enforcement footprint; preserve operator data
  sanctuary export-passphrase             # Print stored passphrase

Options:
  --fortress <path>    Fortress directory for state I/O (default:
                       ~/.sanctuary). Wins over SANCTUARY_STORAGE_PATH
                       and SANCTUARY_FORTRESS_PATH. Place it before the
                       subcommand: sanctuary --fortress <path> <cmd>
  --dashboard          Enable the Principal Dashboard (web UI)
  --help, -h           Show this help
  --version, -v        Show version

Subcommands:
  init                 Create a fresh fortress at a chosen path. Pairs
                       with --fortress to keep multiple fortresses
                       isolated on one host.
                       Use "sanctuary init --help" for options.

  install              Emit one observed-state next action for a shell-capable
                       installing agent. Supports memory and full profiles;
                       never emits recovery secrets.
                       Use "sanctuary install --help" for options.

  protect              Protect an agent and start the dashboard in one command.
                       Auto-generates a passphrase, auto-opens the browser.
                       Use "sanctuary protect --help" for options.

  wrap                 (alias for protect)

  uninstall            Remove Sanctuary's installed enforcement footprint
                       while preserving fortress state and keys. Reports
                       residue that needs sudo, host app action, or reboot.
                       Use "sanctuary uninstall --help" for options.

  dashboard            Start the dashboard as a standalone HTTP server.
                       Reads from the same storage as the MCP server.
                       Use "sanctuary dashboard --help" for options.
                       Pass --multi to render the multi-tenant overview.

  status               Report daemon status (version, listener,
                       federation, identity, Castle Wall) over the
                       /v1 API. Use "sanctuary status --help" for options.

  doctor               Run read-only local health diagnostics.
                       Use "sanctuary doctor --help" for options.

  check-updates        Explicitly check npmjs.org / GitHub Releases for a
                       newer version, right now, regardless of the
                       zero-outbound default. Sanctuary makes no unrequested
                       outbound connection otherwise.
                       Use "sanctuary check-updates --help" for options.

  completion           Emit shell completion for bash, zsh, or fish.

  audit                Search local audit history.
                       Use "sanctuary audit --help" for options.

  checkpoint           Create, list, show, prune, and restore local encrypted
                       memory checkpoints. Use "sanctuary checkpoint --help"
                       for options.

  memory_ingest        Manually mirror Claude Code or Codex memory files into the
                       encrypted SDW vault without touching the source dir.
                       Use "sanctuary memory_ingest --help" for options.

  memory_archive_export
                       Export one completed SDW archive through Exit V2 after
                       Tier-1 approval; a local OS dialog confirms key custody.
                       Use "sanctuary memory_archive_export --help" for options.

  memory_archive_import
                       Import one Exit V2 SDW archive after Tier-1 approval;
                       a local OS dialog reads hidden recovery material.
                       Use "sanctuary memory_archive_import --help" for options.

  memory_emit          Manually emit Claude Code or Codex memory files from the SDW
                       vault into an output dir. Existing files are refused.
                       Use "sanctuary memory_emit --help" for options.

  memory_transcode     Manually create a plaintext cross-harness projection plus
                       an encrypted exact-source recovery archive. This is not sync.
                       Use "sanctuary memory_transcode --help" for options.

  memory_transcode_restore
                       Restore exact source files from a completed encrypted
                       transcode archive. This is not sync.
                       Use "sanctuary memory_transcode_restore --help" for options.

  distress             Emit a distress signal through the reserved habeas
                       lane (operator test verb; same path the agent uses).
                       Use "sanctuary distress --help" for options.

  cortex-export        Export Castle Wall enforcement decisions to a security
                       console as a frozen metadata-only event stream (local by
                       default; outbound push is Tier-1 gated + pinned).
                       Use "sanctuary cortex-export --help" for options.

  transparency         Emit and export signed enforcement checkpoints
                       (verifiable evidence the wall is enforcing).
                       Use "sanctuary transparency --help" for options.

  verify-transparency  Verify an exported checkpoint chain offline, or
                       against the live audit log with --against-log.
                       Use "sanctuary verify-transparency --help" for options.

  generate             Emit local deployment templates.
                       Use "sanctuary generate --help" for options.

  deploy               Emit provider-neutral deployment skeletons.
                       Use "sanctuary deploy --help" for options.

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
  rotate-master        Rotate the fortress master key (re-encrypts all data;
                       interactive-only; "sanctuary rotate-master --help")
                       or corrupted. Three modes: shares (M-of-N
                       reconstruction), guardian (federation quorum), or
                       nuke (destroys all state, fresh start).
                       Use "sanctuary reset-passphrase --help" for options.

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_FORTRESS_PATH           Operator-friendly alias for STORAGE_PATH
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_RECOVERY_OUT            Init recovery-key plaintext output path
  SANCTUARY_DASHBOARD_ENABLED       "true" to enable dashboard
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE
                                      "true" allows plaintext remote dashboard
  SANCTUARY_WEBHOOK_ENABLED         "true" to enable webhook approvals
  SANCTUARY_WEBHOOK_URL             Webhook target URL
  SANCTUARY_WEBHOOK_SECRET          HMAC-SHA256 shared secret
  SANCTUARY_UPDATE_CHECK            "1" to opt in to the startup update check
                                      and wrap's pinned-version registry probe.
                                      Sanctuary makes NO unrequested outbound
                                      connection by default (zero-outbound);
                                      run "sanctuary check-updates" any time
                                      to check on demand regardless of this
                                      setting.
  SANCTUARY_NO_UPDATE_CHECK         "1" is a back-compat alias that also keeps
                                      the above checks off (cannot force them
                                      on)

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
  --no-confirm         Skip the interactive recovery-key off-host-capture
                       confirmation on first run. Required for non-TTY callers
                       (CI, launchd, systemd). When set, an off-host escrow
                       target MUST exist (--recovery-out / SANCTUARY_RECOVERY_OUT,
                       or SANCTUARY_PASSPHRASE for OS-keyring escrow) or the boot
                       fails closed rather than leaving the key uncaptured.
  --recovery-out <path>
                       On a first-run mint, write the plaintext recovery key to
                       this exact path OUTSIDE the fortress directory (durable
                       off-host escrow). Also honors SANCTUARY_RECOVERY_OUT.
  --allow-plaintext-remote
                       Allow plaintext HTTP on non-loopback dashboard bindings
                       when a separate network layer already encrypts transport.
  --allow-park         Park (do not exit) on a locked-no-credential start
                       instead of failing loudly: bind the listener, report
                       readiness "locked", serve the in-process unlock door,
                       and stay up. Intended for the supervised LaunchAgent so
                       KeepAlive does not crash-loop a locked fortress. The
                       process does NOT auto-unlock; an operator unlocks once.
  --help, -h           Show this help

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_FORTRESS_PATH           Operator-friendly alias for STORAGE_PATH
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_RECOVERY_KEY            Recovery key for existing installations
  SANCTUARY_RECOVERY_OUT            Off-host plaintext recovery-key path (first run)
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE
                                      "true" allows plaintext remote dashboard
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
    case "install": {
      const { runInstallCommand } = await import("./cli/install.js");
      await runInstallCommand({ argv: ["--help"] });
      return true;
    }
    case "protect":
    case "wrap":
      printWrapHelpEarly();
      return true;
    case "init": {
      const { printInitHelp } = await import("./wrap/init.js");
      printInitHelp();
      return true;
    }
    case "agents":
    case "agent": {
      const { printAgentsHelp, printAgentsListHelp } = await import("./cli/agents/index.js");
      if (args[1] === "list") {
        printAgentsListHelp();
      } else {
        printAgentsHelp();
      }
      return true;
    }
    case "exit": {
      const { printExitExportHelp, printExitHelp } = await import("./exit/index.js");
      if (args[1] === "export") {
        printExitExportHelp();
      } else {
        printExitHelp();
      }
      return true;
    }
    case "verify-exit-bundle":
    case "import-exit-bundle": {
      const { printExitHelp } = await import("./exit/index.js");
      printExitHelp();
      return true;
    }
    case "export-passphrase":
      printExportPassphraseHelp();
      return true;
    case "distress": {
      const { runDistressCommand } = await import("./cli/distress.js");
      await runDistressCommand({ argv: args.slice(1).concat("--help") });
      return true;
    }
    case "cortex-export": {
      const { runCortexExportCommand } = await import("./cli/cortex-export.js");
      await runCortexExportCommand({ argv: args.slice(1).concat("--help") });
      return true;
    }
    case "deploy": {
      const { runDeployCommand } = await import("./cli/deploy.js");
      await runDeployCommand({ argv: args.slice(1).concat("--help") });
      return true;
    }
    case "castle-wall":
      printCastleWallHelp();
      return true;
    case "uninstall": {
      const { runUninstallCommand } = await import("./cli/uninstall.js");
      await runUninstallCommand({ argv: args.slice(1).concat("--help") });
      return true;
    }
    default:
      return false;
  }
}

async function runCastleWallCommand(args: string[]): Promise<number> {
  const command = args[0];
  if (!command || command === "--help" || command === "-h") {
    printCastleWallHelp();
    return 0;
  }

  if (command === "provision-pin") {
    const { runProvisionPin } = await import("./cli/castle-wall.js");
    return runProvisionPin(args.slice(1));
  }

  if (command === "status") {
    const { runStatus } = await import("./cli/castle-wall.js");
    // O-07 (register): the trailing args (e.g. `--fortress <path>`) were
    // dropped here entirely -- unlike every other castle-wall verb below,
    // which forwards `args.slice(1)` -- so `castle-wall status --fortress
    // <path>` silently reported the DEFAULT fortress instead of the one
    // named. See runStatus's own doc for the fix.
    return runStatus(args.slice(1));
  }

  if (command === "enable") {
    const { runEnable } = await import("./cli/castle-wall.js");
    return runEnable(args.slice(1));
  }

  if (command === "disable") {
    const { runDisable } = await import("./cli/castle-wall.js");
    return runDisable(args.slice(1));
  }

  if (command === "setup-shared-dir") {
    const { runSetupSharedDir } = await import("./cli/castle-wall.js");
    return runSetupSharedDir();
  }

  if (command === "reload") {
    const { runReload } = await import("./cli/castle-wall.js");
    return runReload(args.slice(1));
  }

  if (command === "audit-dump") {
    const { runAuditDump } = await import("./cli/castle-wall.js");
    return runAuditDump(args.slice(1));
  }

  if (command === "audit-verify") {
    const { runAuditVerify } = await import("./cli/castle-wall.js");
    return runAuditVerify(args.slice(1));
  }

  if (command === "audit-findings") {
    const { runAuditFindings } = await import("./cli/castle-wall.js");
    return runAuditFindings(args.slice(1));
  }

  if (command === "audit-store-status") {
    const { runAuditStoreStatus } = await import("./cli/castle-wall.js");
    return runAuditStoreStatus(args.slice(1));
  }

  if (command === "manifest-preflight") {
    const { runManifestPreflight } = await import("./cli/castle-wall-manifest-preflight.js");
    return runManifestPreflight(args.slice(1));
  }

  if (command === "approve") {
    const { runApprove } = await import("./cli/castle-wall.js");
    return runApprove(args.slice(1));
  }

  if (command === "configure-origin") {
    const { runConfigureOrigin } = await import("./cli/castle-wall.js");
    return runConfigureOrigin(args.slice(1));
  }

  if (command === "re-pin") {
    const { runRePin } = await import("./cli/castle-wall.js");
    return runRePin(args.slice(1));
  }

  if (command === "daemon") {
    const { runDaemon } = await import("./cli/castle-wall.js");
    return runDaemon(args.slice(1));
  }

  if (command === "install-boot") {
    const { runInstallBoot } = await import("./cli/castle-wall-boot.js");
    return runInstallBoot(args.slice(1));
  }

  if (command === "uninstall-boot") {
    const { runUninstallBoot } = await import("./cli/castle-wall-boot.js");
    return runUninstallBoot(args.slice(1));
  }

  if (command === "provision-boot-token") {
    const { runProvisionBootToken } = await import("./cli/castle-wall-boot.js");
    return runProvisionBootToken(args.slice(1));
  }

  if (command === "repair-custody") {
    const { runRepairCustody } = await import("./cli/castle-wall-custody.js");
    return runRepairCustody(args.slice(1));
  }

  if (command === "signer-helper") {
    const sub = args[1];
    if (sub === "status" || sub === undefined) {
      const { runSignerHelperStatus } = await import("./cli/castle-wall-signer-helper.js");
      return runSignerHelperStatus(args.slice(2));
    }
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Unknown signer-helper subcommand: ${sub}. Try: sanctuary castle-wall signer-helper status`);
    return 2;
  }

  if (command === "observe") {
    const { runObserveCommand } = await import("./cli/castle-wall-observe.js");
    return runObserveCommand({ argv: args.slice(1) });
  }

  if (command === "egress-gate-daemon") {
    // Unified Protect Slice 5 S5-6: the long-lived exclusive-egress gate
    // daemon entrypoint. Spawned by launchd under the dedicated
    // `sanctuary-gate-<agentId>` service uid (NEVER root, NEVER the agent);
    // reads its gate-readable config copies from /var/db/sanctuary/
    // gate-runtime, binds EXACTLY the committed gate port, and serves with
    // the S5-3 TCB wiring (oracle liveness probe + fail-closed client auth +
    // peer runner). A bind/config failure exits non-zero (the gate refuses
    // to serve rather than squat another port; posture reads amber).
    const uidArg = args.slice(1).find((a) => a.startsWith("--agent-uid="));
    const agentUid = uidArg !== undefined ? Number(uidArg.slice("--agent-uid=".length)) : NaN;
    if (!Number.isInteger(agentUid) || agentUid <= 0) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error("egress-gate-daemon requires --agent-uid=<positive integer>");
      return 2;
    }
    const { runEgressGateDaemon } = await import("./egress-gate/gate-daemon.js");
    try {
      const handle = await runEgressGateDaemon({ agentUid });
      const stop = async (): Promise<void> => {
        try {
          await handle.close();
        } finally {
          process.exit(0);
        }
      };
      process.on("SIGTERM", () => {
        void stop();
      });
      process.on("SIGINT", () => {
        void stop();
      });
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(
        `[egress-gate] serving uid ${agentUid} on 127.0.0.1:${handle.gate.port} (generation ${handle.generationId})`,
      );
      // The gate server holds the event loop open; this promise never
      // resolves (shutdown exits via the signal handlers above).
      return await new Promise<number>(() => undefined);
    } catch (err) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(`egress-gate daemon failed to start: ${(err as Error).message}`);
      return 1;
    }
  }

  if (command === "peer-resolver-daemon") {
    // 2026-07-24 S5-3 fix (Option 1): the PRIVILEGED root helper the gate
    // daemon dials to resolve a loopback CONNECT peer's uid (the gate daemon
    // itself stays unprivileged and cannot see a different uid's socket --
    // see `peer-resolver-daemon.ts`). Spawned by launchd as ROOT (no
    // UserName in its plist), one per confined agent, alongside that agent's
    // gate daemon.
    const args1 = args.slice(1);
    const uidArg = args1.find((a) => a.startsWith("--agent-uid="));
    const gateUidArg = args1.find((a) => a.startsWith("--gate-uid="));
    const gatePortArg = args1.find((a) => a.startsWith("--gate-port="));
    const agentUid = uidArg !== undefined ? Number(uidArg.slice("--agent-uid=".length)) : NaN;
    const gateUid = gateUidArg !== undefined ? Number(gateUidArg.slice("--gate-uid=".length)) : NaN;
    const gatePort = gatePortArg !== undefined ? Number(gatePortArg.slice("--gate-port=".length)) : NaN;
    if (!Number.isInteger(agentUid) || agentUid <= 0) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error("peer-resolver-daemon requires --agent-uid=<positive integer>");
      return 2;
    }
    if (!Number.isInteger(gateUid) || gateUid <= 0) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error("peer-resolver-daemon requires --gate-uid=<positive integer>");
      return 2;
    }
    // 2026-07-24 fix-round BLOCKER: the gate port MUST come from this
    // daemon's OWN root-written startup config (this argv, baked into the
    // plist at arming time), never from a wire request -- see
    // peer-resolver-daemon.ts's module header.
    if (!Number.isInteger(gatePort) || gatePort <= 0 || gatePort > 65535) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error("peer-resolver-daemon requires --gate-port=<valid TCP port>");
      return 2;
    }
    const { runPeerResolverDaemon } = await import("./egress-gate/peer-resolver-daemon.js");
    try {
      const handle = await runPeerResolverDaemon({ agentUid, gateUid, gatePort });
      const stop = async (): Promise<void> => {
        try {
          await handle.close();
        } finally {
          process.exit(0);
        }
      };
      process.on("SIGTERM", () => {
        void stop();
      });
      process.on("SIGINT", () => {
        void stop();
      });
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(`[egress-gate-peer-resolver] serving uid ${agentUid} on ${handle.socketPath}`);
      // Holds the event loop open; shutdown exits via the signal handlers above.
      return await new Promise<number>(() => undefined);
    } catch (err) {
      // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
      console.error(`peer-resolver daemon failed to start: ${(err as Error).message}`);
      return 1;
    }
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
    sanctuary castle-wall <subcommand>
    sanctuary castle-wall [--help]

  Subcommands:
    provision-pin    Generate and pin the local Castle Wall keypair.
                     --fortress <path>  Target a specific fortress (defaults to
                                        SANCTUARY_FORTRESS_PATH / SANCTUARY_STORAGE_PATH).
    status           Show pinned-key fingerprint and sysext status.
    enable           Arm the content filter headlessly (macOS; SSH-safe after the one-time GUI consent).
                     Refuses without a reachable policy daemon; --force overrides.
                     --agent-uid=<uid> [--ceiling=<uid>]
                                      One-command arm: configure the agent-origin descriptor
                                      (same effect as 'configure-origin uid --agent-uid=<uid>')
                                      THEN arm, in a single command. --ceiling defaults to 500.
                                      The uid must be a plain positive integer AND >= the ceiling
                                      (root/0 and sub-ceiling uids are rejected; non-numeric values
                                      are never truncated). Explicit flag only - never auto-derived.
                                      Without --agent-uid, behavior is unchanged: enable still refuses
                                      to arm with no agent-origin descriptor already on disk unless
                                      --force (use 'configure-origin' first, or pass --agent-uid).
    disable          Disarm the content filter headlessly (macOS; unconditional dead-man lever).
    setup-shared-dir Create the privileged shared dir for the pinned key (run with sudo, macOS).
    reload           Reload policy in the running fortress daemon.
                     Exits 0 even when no daemon was reachable to reload (a
                     fresh fortress has nothing to reload; this is intentional).
                     --require-daemon  Exit non-zero instead when no daemon
                                       was reachable, so a script can tell
                                       "reloaded" apart from "nothing there".
    audit-dump       Emit Castle Wall audit events as JSONL. Read-only.
                     --by-rule        Roll recorded flows up per deciding rule:
                                      per-rule total + allow/deny/prompt split + sample flows.
                     --rule <id>      Show only flows the given rule decided
                                      (use --rule default-deny for flows that matched no rule).
                     Surfaces RECORDED per-flow rule attribution. It does NOT make the
                     audit trail tamper-evident: tamper-evidence (producer-signed audit
                     activation) is a separate capability, not yet active in production on Linux.
    audit-verify     Re-verify each enforcement entry's PRODUCER SIGNATURE against the
                     pinned audit-producer key and report verified / rejected / channel
                     counts. Read-only. This is the tamper-evidence reader: unlike
                     audit-dump it does NOT trust the cw_source marker; it cryptographically
                     re-verifies the signature, so a forged producer_signed entry is REJECTED.
                     With no published producer key it reports the honest channel-authenticated
                     floor and makes no per-producer claim. --json for machine output;
                     --since <dur>; --producer-pub-key <path> override.
    audit-findings   List audit-chain integrity findings for the fortress (read-only diagnostic).
    audit-store-status Report BOTH the operator and root-daemon audit chain verdicts (F2 Option A
                     writer-split), each honestly and separately; a daemon chain that exists but
                     is unreadable at this privilege reports as such, never as "verified". Read-only.
    manifest-preflight Read the persisted signed egress manifest and every validated referenced
                     rule body, reporting compatibility findings without changing policy. Read-only.
                     --fortress <path>  Target a specific fortress.
    approve          Approve a pending Castle Wall request.
    configure-origin Configure the agent-origin descriptor for origin-differential enforcement.
    re-pin           Migrate the trust anchor to the root signer helper's key (one-time, operator-approved).
    daemon           Start the enforcement daemon standalone (existing fortress key); foreground until Ctrl-C.
                     With --safe-mode, comes up from the boot token only (no master key) for the launchd boot service.
    provision-boot-token
                     Mint the software-protected boot token (root-owned 0600; run with sudo). Anti-brick
                     credential only, NOT the fortress passphrase. install-boot auto-provisions it; --rotate replaces.
    install-boot     Install the daemon as a launchd safe-mode boot service (run with sudo, macOS).
                     Options: --user <name> --fortress <path> --signer-client <path>
    uninstall-boot   Remove the launchd boot service (run with sudo, macOS; requires --yes). Does NOT disarm the filter.
    repair-custody   Hand a root-owned fortress back to the operator (run with sudo, macOS).
                     Observe-first: writes a timestamped manifest of every entry's uid/gid/mode
                     outside the fortress before changing anything; chowns root-owned entries only;
                     restores fortress 0700 / castle.sock 0600 where deviant; skips foreign-uid
                     entries. Idempotent. Exit codes: 0 changed, 3 already clean, 2 refused, 1 failed.
                     Options: --fortress <path>   --rollback <manifest> (replays recorded ownership)
    signer-helper status
                     Boot-readiness preflight for the root signer-helper LaunchDaemon: checks the
                     launchd job is loaded, the helper answers over XPC, its key matches the global
                     pin, and the custody directory is root-owned and not group/other-writable.
                     Exit 0 when ready, 1 otherwise. Does NOT prove reboot survival by itself; see
                     castle-wall-macos-boot-service.md for the required Erik-present reboot drill.
    observe start|status|candidates|promote|discard
                     Observe / Learn Allow-List v1: the wall stays armed and default-deny the
                     whole time; observe mode records denied novel destinations for review
                     instead of nagging per-flow. 'promote' is Tier-1 FORCED (requires the same
                     approval gate as state_export / key rotation) and is the ONLY verb that can
                     ever widen the live ruleset. Run 'sanctuary castle-wall observe --help' for
                     command-specific options.

  Options:
    --help, -h              Show this help
    --accept-broken-chain   (daemon, re-pin) Proceed past audit integrity findings,
                            recording an audited override entry first. Without it,
                            a fortress with findings fail-closes (default). Inspect
                            findings with 'sanctuary castle-wall audit-findings'.
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
  sanctuary protect. Protect any agent with Sanctuary.

  Usage:
    sanctuary protect --openclaw       Protect OpenClaw
    sanctuary protect --hermes         Protect Hermes Agent (NousResearch)
    sanctuary protect --claude-code    Protect Claude Code
    sanctuary protect --cursor         Protect Cursor
    sanctuary protect --cline          Protect Cline (VS Code extension)
    sanctuary protect --mastra         Protect Mastra
    sanctuary protect --wrap <path>    Protect a specific MCP config file
    sanctuary protect --unwrap         Restore original config

  "sanctuary wrap" is a deprecated alias that still works.

  Options:
    --openclaw         Auto-detect and wrap OpenClaw
    --hermes           Auto-detect and wrap Hermes Agent
    --claude-code      Auto-detect and wrap Claude Code
    --cursor           Auto-detect and wrap Cursor
    --cline            Auto-detect and wrap Cline (VS Code extension)
    --mastra           Auto-detect and wrap Mastra
    --wrap <path>      Wrap a specific MCP config file
    --unwrap           Restore original config from backup
    --passphrase <p>   Override the stored passphrase (one-off)
    --fortress <path>  Fortress directory (default: ~/.sanctuary). Honors
                       SANCTUARY_FORTRESS_PATH env var when the flag is
                       absent. Use to keep multiple fortresses isolated
                       on one host.
    --port <port>      Preferred dashboard port (default: 3501)
    --dashboard-port <port>
                       Preferred dashboard port (1024-65535). Overrides
                       SANCTUARY_DASHBOARD_PORT when both are set.
    --dry-run          Show what would happen without making changes
    --no-open          Do not auto-open the dashboard in a browser
    --no-dashboard     Do not spawn a per-call dashboard server. Wrap still
                       persists the agent record so a separately-running
                       \`sanctuary dashboard\` (or a later wrap) sees the
                       harness. Use this for the clean operator setup
                       (one persistent dashboard + many wraps).
    --dev-dist <path>  Dogfood path. Point the harness MCP entries at a
                       local Sanctuary build (\`node <path>\` instead of the
                       version-pinned npx registry entry). Required
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

function formatCliError(err: unknown): string {
  if (err instanceof Error) {
    const name =
      err.name && err.name !== "Error" ? `${err.name}: ` : "";
    return `${name}${err.message}`;
  }
  return String(err);
}

main().catch((err) => {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
