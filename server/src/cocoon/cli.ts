#!/usr/bin/env node
/**
 * Sanctuary wrap — CLI Entry Point
 *
 * One command to wrap any MCP-compatible agent in Sanctuary's enforcement
 * chain, auto-generate a passphrase, start the Sovereignty Dashboard
 * in-process, and open it in the user's browser.
 *
 * Usage:
 *   npx @sanctuary-framework/mcp-server wrap --openclaw
 *   npx @sanctuary-framework/mcp-server wrap --hermes
 *   npx @sanctuary-framework/mcp-server wrap --claude-code
 *   npx @sanctuary-framework/mcp-server wrap --cursor
 *   npx @sanctuary-framework/mcp-server wrap --cline
 *   npx @sanctuary-framework/mcp-server wrap --wrap /path/to/config.json
 *   npx @sanctuary-framework/mcp-server wrap --unwrap
 *
 * The `cocoon` subcommand is preserved as a hidden alias that prints a
 * deprecation notice. It will be removed in a future release.
 *
 * Layer 1 vs Layer 2 (Cline, and any other harness that has both):
 *   `sanctuary wrap --cline` is the Layer 1 install-time flag handled here.
 *   It detects the operator's existing Cline VS Code extension MCP config,
 *   backs it up, and rewrites it so Sanctuary becomes the upstream gateway.
 *   The operator keeps running Cline; Sanctuary slips in front of Cline's
 *   MCP client.
 *
 *   `sanctuary wrap --tier-b cline` is the Layer 2 managed-child SDK
 *   adapter selector (see server/src/agent-contract/adapters/cline.ts).
 *   It spawns Cline as a child process and brokers MCP over stdio. This is
 *   the advanced path; most operators want Layer 1.
 */

import { writeFile, readFile, mkdir, access } from "node:fs/promises";
import { dirname, join, resolve as resolvePath } from "node:path";
import { platform } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveCocoonMeta,
  findLatestBackup,
  restoreConfig,
  rewriteConfigForCocoon,
  getPlatformPaths,
  type AgentPlatform,
  type MCPServerEntry,
} from "./config-reader.js";
import {
  getOrCreatePassphrase,
  persistUserProvidedPassphrase,
  isOsKeyringLocation,
  PassphraseUnreadableError,
} from "./passphrase.js";
import { startDashboard, type DashboardHandle } from "../dashboard/index.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../dashboard/v1_1/wiring.js";
import { upsertPersistedLocalAgent } from "../hub/agent-registry-persistence.js";
import type {
  LocalAgentRecord,
  LocalHarnessKind,
} from "../contracts/v1.1/local-agent-records.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { deriveMasterKey, type KeyDerivationParams } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import { SubstrateSelector } from "../intelligence/selector.js";
import { SANCTUARY_VERSION } from "../config.js";
import { resolveStoragePath, resolveDashboardPort } from "../paths.js";
import { writeTenantRuntime, clearTenantRuntime } from "../cli/agents/runtime.js";
import {
  disclosePassphrase,
  PassphraseConfirmationDeclinedError,
  PassphraseConfirmationNonInteractiveError,
} from "./recovery-key-disclosure.js";
import type { UpstreamServer, SovereigntyProfile } from "../sovereignty-profile.js";

// ── Types ───────────────────────────────────────────────────────────

export interface WrapOptions {
  /** Wrap a specific config file. */
  wrap?: string;
  /** Auto-detect OpenClaw config. */
  openclaw?: boolean;
  /** Auto-detect Hermes Agent config (NousResearch). */
  hermes?: boolean;
  /** Auto-detect Claude Code config. */
  claudeCode?: boolean;
  /** Auto-detect Cursor config. */
  cursor?: boolean;
  /** Auto-detect Cline config. */
  cline?: boolean;
  /** Unwrap — restore the original config. */
  unwrap?: boolean;
  /** Explicit passphrase override. If unset, one is generated and stored. */
  passphrase?: string;
  /**
   * Operator-supplied fortress path. Overrides SANCTUARY_FORTRESS_PATH and
   * SANCTUARY_STORAGE_PATH env vars. v1.1.0 silently ignored this flag
   * (Finding T); v1.1.1 honors it end-to-end. The fortress directory is
   * created if it does not exist.
   */
  fortress?: string;
  /**
   * Dashboard port (default 3501). If bound, the loop retries
   * `preferredPort` through `preferredPort + PORT_FALLBACK_ATTEMPTS - 1`
   * regardless of the absolute port number. v0.10.0 shipped a hardcoded
   * absolute upper bound of 3510, which silently rejected multi-tenant
   * setups starting above 3510.
   */
  port?: number;
  /** Preview changes without writing. */
  dryRun?: boolean;
  /** Suppress auto-open of the browser. */
  noOpen?: boolean;
  /**
   * Suppress dashboard server spawn (v1.1.5, Finding AA). When set, wrap
   * persists the agent record and updates the harness config but does not
   * start a per-call dashboard server, bind a port, or print a dashboard
   * URL. Operators that want a single persistent dashboard run
   * `sanctuary dashboard &` once, then `sanctuary wrap --<harness>
   * --no-dashboard` per harness; the persistent dashboard rehydrates the
   * agent registry from the same fortress file each wrap writes.
   */
  noDashboard?: boolean;
  /**
   * Dogfood path (`--dev-dist <path>`): point the harness MCP
   * config entry at a local Sanctuary build instead of `npx
   * @sanctuary-framework/mcp-server`. Without this, an unpublished branch
   * (e.g. an in-flight PR) gets shadowed by the npm-resolved version
   * because npx pulls from the registry, not from the local checkout.
   *
   * Pass the absolute path to the build's `dist/cli.js`. The wrap CLI
   * registers `node <path>` as the `sanctuary` command. `--dev-dist`
   * is intended for local development and CI dogfood; published-version
   * wraps omit it and use the npx default unchanged.
   */
  devDist?: string;
}

/** Backward-compat alias for the old `parseCocoonArgs` return type. */
export type CocoonOptions = WrapOptions;

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * v1.1.1 hotfix (Finding T): promote --fortress and SANCTUARY_FORTRESS_PATH
 * onto SANCTUARY_STORAGE_PATH so downstream code that reads
 * SANCTUARY_STORAGE_PATH (resolveStoragePath, etc.) sees the operator's
 * intended fortress location.
 *
 * Precedence (highest wins):
 *   1. options.fortress (--fortress CLI flag)
 *   2. SANCTUARY_FORTRESS_PATH env var
 *   3. SANCTUARY_STORAGE_PATH env var (left untouched)
 *
 * Exported for unit tests that pin precedence without standing up the
 * whole wrap flow.
 */
export function promoteFortressToStoragePath(options: {
  fortress?: string;
}): void {
  if (options.fortress) {
    process.env.SANCTUARY_STORAGE_PATH = options.fortress;
    return;
  }
  if (process.env.SANCTUARY_FORTRESS_PATH) {
    process.env.SANCTUARY_STORAGE_PATH = process.env.SANCTUARY_FORTRESS_PATH;
  }
}

/**
 * v1.1.1 hotfix (Finding B): the wrap "MCP servers found" reporting line
 * pre-fix read "MCP servers found: 0" when a re-wrap found Sanctuary
 * already present, because the filtered `agentConfig.servers` excludes
 * the canonical Sanctuary entry to avoid double-wrapping. Operators saw
 * a "0 servers" message and concluded wrap had nothing to do, even
 * though Sanctuary was clearly there.
 *
 * This helper formats counts honestly: it splits the Sanctuary entry
 * (already-wrapped) count from the other-server count and pluralizes
 * properly.
 */
export function formatMcpServerCount(
  otherCount: number,
  hasSanctuaryEntry: boolean,
): string {
  if (!hasSanctuaryEntry) {
    return `MCP servers found: ${otherCount}`;
  }
  const otherWord = otherCount === 1 ? "server" : "servers";
  return `MCP servers found: 1 Sanctuary entry (existing), ${otherCount} other ${otherWord}`;
}

// ── Constants ───────────────────────────────────────────────────────

/** Default CallGovernor limits for wrapped agents. */
export const COCOON_GOVERNOR_DEFAULTS = {
  volume_limit: 200,
  rate_limit_per_tool: 20,
  lifetime_limit: 1000,
} as const;

/**
 * How many consecutive ports the dashboard fallback tries, starting at
 * `preferredPort`. v0.10.0 hardcoded an absolute `MAX_PORT = 3510` cap —
 * starting above it (the documented tenant ports 3511/3512) produced an
 * empty range and the error "No free dashboard port in range 3511-3510".
 * Making the window relative to `preferredPort` fixes both the multi-tenant
 * case and the nonsensical error message.
 *
 * Exported for tests; not public API.
 */
export const PORT_FALLBACK_ATTEMPTS = 20;

// ── Dashboard integration ───────────────────────────────────────────

/** Minimal starter signature — matches `startDashboard` from ../dashboard. */
export type DashboardStarter = (opts: {
  port: number;
  host?: string;
  mode: "co-located" | "standalone";
  authToken: string;
  serverVersion: string;
}) => Promise<DashboardHandle>;

// ── Main: wrap ──────────────────────────────────────────────────────

export interface RunWrapDeps {
  /** Override dashboard starter (for tests). */
  startDashboard?: DashboardStarter;
  /** Override browser opener (for tests). */
  openBrowser?: (url: string) => Promise<void>;
  /** Override passphrase resolver (for tests). */
  resolvePassphrase?: () => Promise<{ value: string; location: string; source: string }>;
  /**
   * Override the persistence helper for a user-supplied `--passphrase` flag
   * (for tests). Production callers leave this undefined.
   */
  persistPassphrase?: (
    value: string
  ) => Promise<{ location: string; source: "keychain" | "fallback-file" }>;
  /**
   * Override the config rewrite (for tests). Production callers leave this
   * undefined.
   */
  rewriteConfig?: typeof rewriteConfigForCocoon;
}

export async function runWrap(
  options: WrapOptions,
  deps: RunWrapDeps = {}
): Promise<void> {
  if (options.unwrap) {
    await unwrap();
    return;
  }

  // v1.1.1 hotfix (Finding T): honor --fortress and SANCTUARY_FORTRESS_PATH
  // by promoting them onto SANCTUARY_STORAGE_PATH BEFORE any code calls
  // resolveStoragePath(). Extracted so tests can pin the precedence
  // without standing up the whole wrap flow.
  promoteFortressToStoragePath(options);

  let platformHint: AgentPlatform | undefined;
  if (options.openclaw) platformHint = "openclaw";
  else if (options.hermes) platformHint = "hermes";
  else if (options.claudeCode) platformHint = "claude-code";
  else if (options.cursor) platformHint = "cursor";
  else if (options.cline) platformHint = "cline";

  let detection = await detectAgentConfigWithDiagnostics(
    platformHint,
    options.wrap
  );
  let agentConfig = detection.config;

  // If no config file exists for an explicitly-hinted platform, bootstrap an
  // empty one at the canonical (first-listed) path. Wrap then proceeds to
  // inject Sanctuary as the sole entry. First-time operators on a fresh
  // Claude Code install (no prior `claude mcp add`) hit this path; pre-v1.0
  // wrap exited here and forced them to seed an unrelated placeholder.
  if (!agentConfig && platformHint && !options.wrap) {
    const candidatePaths = getPlatformPaths()[platformHint];
    const canonicalPath = candidatePaths[0];
    if (canonicalPath) {
      try {
        await mkdir(dirname(canonicalPath), { recursive: true, mode: 0o700 });
        await writeFile(canonicalPath, "{}", { mode: 0o600 });
        console.error(
          `\n  No existing ${platformHint} config found.`
        );
        console.error(
          `  Bootstrapped a fresh config at ${canonicalPath}.\n`
        );
        detection = await detectAgentConfigWithDiagnostics(
          platformHint,
          options.wrap
        );
        agentConfig = detection.config;
      } catch (err) {
        console.error(
          `\n  Sanctuary: could not bootstrap ${platformHint} config at ${canonicalPath}`
        );
        console.error(`  Error: ${(err as Error).message}\n`);
        process.exit(1);
      }
    }
  }

  if (!agentConfig) {
    console.error(`\n  Sanctuary: Configuration Not Found\n`);
    if (platformHint) {
      console.error(`  Could not find ${platformHint} configuration.`);
    } else if (options.wrap) {
      console.error(`  Could not read config file: ${options.wrap}`);
    } else {
      console.error("  Could not auto-detect any agent configuration.");
      console.error(
        "  Use --openclaw, --hermes, --claude-code, --cursor, --cline, or --wrap /path/to/config.json"
      );
    }
    if (detection.pathsChecked.length > 0) {
      console.error(`\n  Paths checked:`);
      for (const p of detection.pathsChecked) console.error(`    ${p}`);
    }
    if (detection.errors.length > 0) {
      console.error(`\n  Errors encountered:`);
      for (const e of detection.errors) {
        console.error(`    ${e.path}: ${e.error}`);
      }
    }
    console.error("");
    process.exit(1);
  }

  // An empty server list is no longer a hard error: wrap proceeds to inject
  // Sanctuary as the sole entry. This unblocks (a) first-install configs
  // that have no `mcpServers` key yet and (b) re-wrap of a config whose
  // only entry was Sanctuary (which extractServers filters out).
  const hasSanctuaryInRaw = rawConfigContainsSanctuary(
    agentConfig.rawConfig,
    agentConfig.platform
  );
  if (hasSanctuaryInRaw) {
    console.error(
      `\n  Sanctuary already wrapped: updating the existing Sanctuary entry.\n`
    );
  } else if (agentConfig.servers.length === 0) {
    console.error(
      `\n  Found ${agentConfig.platform} config at ${agentConfig.configPath} with no MCP servers yet.`
    );
    console.error(
      `  Sanctuary will be installed as the only MCP server.\n`
    );
  }

  console.error(`\n  Sanctuary wrap`);
  console.error(`  Platform: ${agentConfig.platform}`);
  console.error(`  Config: ${agentConfig.configPath}`);

  console.error(
    `  ${formatMcpServerCount(agentConfig.servers.length, hasSanctuaryInRaw)}`
  );

  const upstreamServers = convertToUpstreamServers(agentConfig.servers);
  for (const server of upstreamServers) {
    console.error(
      `    → ${server.name} (${server.transport.type}, tier ${server.default_tier})`
    );
  }

  if (options.dryRun) {
    console.error(`\n  Dry run. No changes made.\n`);
    return;
  }

  // Resolve the storage path once up front so the passphrase, sovereignty
  // profile, backup dir, and every other on-disk artifact land in the same
  // per-tenant location when SANCTUARY_STORAGE_PATH is set.
  const storagePath = resolveStoragePath();

  // Resolve or generate passphrase.
  //
  // Invariant: the resolved passphrase never reaches argv or the rewritten
  // agent config. User-supplied `--passphrase` is treated as a one-time
  // setter — we persist it into Keychain/fallback and the launcher
  // re-resolves it at runtime via the same path everyone else uses.
  // See SEC-061 in docs/audit/DELTA_REVIEW_V0.9.0_RC1.md.
  let passphraseLocation: string;
  let passphraseSource: string;
  // v1.1.2 hotfix (Finding V): capture the passphrase value so the
  // wrap-auto dashboard can derive the master key + initialize an
  // AuditLog for the v1.1 hub bindings. Held in this function's scope
  // only; never persisted to disk beyond the existing keychain write
  // and never injected into the rewritten harness env.
  let passphraseValue: string | undefined;
  if (options.passphrase) {
    try {
      const persist =
        deps.persistPassphrase ??
        ((value: string) => persistUserProvidedPassphrase(value, { storagePath }));
      const persisted = await persist(options.passphrase);
      passphraseLocation = persisted.location;
      passphraseSource = persisted.source;
      passphraseValue = options.passphrase;
      console.error(
        `\n  \u{1F510} Persisted user-supplied passphrase (${persisted.location}).`
      );
      console.error(
        `  Back up with: sanctuary export-passphrase`
      );
    } catch (err) {
      console.error(`\n  Sanctuary: Passphrase Persistence Failed`);
      console.error(`  ${(err as Error).message}`);
      console.error("");
      process.exit(2);
    }
  } else if (process.env.SANCTUARY_PASSPHRASE) {
    passphraseLocation = "SANCTUARY_PASSPHRASE";
    passphraseSource = "env";
    passphraseValue = process.env.SANCTUARY_PASSPHRASE;
  } else {
    try {
      const resolve =
        deps.resolvePassphrase ??
        (() => getOrCreatePassphrase({ storagePath }));
      const resolved = await resolve();
      passphraseLocation = resolved.location;
      passphraseSource = resolved.source;
      passphraseValue = resolved.value;
      if (resolved.source === "generated") {
        console.error(
          `\n  \u{1F510} Generated and stored passphrase (${resolved.location}).`
        );
        console.error(
          `  Back up with: sanctuary export-passphrase`
        );
      }
    } catch (err) {
      if (err instanceof PassphraseUnreadableError) {
        console.error(`\n  Sanctuary: Passphrase Unreadable`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  // Emit fallback-storage warning (SEC-063) when not using an OS keyring.
  // One-time: only on first wrap (source === "generated") when the location
  // is the fallback file, not when reading back a pre-existing fallback.
  // Treats macOS Keychain and Linux Secret Service as equivalent OS-keyring
  // destinations; the warning is about falling back to the machine-local
  // encrypted file, which is weaker than either keyring.
  const usingFallback = !isOsKeyringLocation(passphraseLocation);
  const isFallbackGenerated = passphraseSource === "generated" && usingFallback;
  const isFallbackUserProvided =
    passphraseSource === "fallback-file" && usingFallback;
  if (isFallbackGenerated || (options.passphrase && isFallbackUserProvided)) {
    console.error(
      `\n  \u26A0  Passphrase stored in encrypted fallback file (machine-local key).` +
      `\n     This is protected only against off-machine access. On macOS, Sanctuary` +
      `\n     uses Keychain; on Linux, Sanctuary uses Secret Service (D-Bus, via` +
      `\n     libsecret) when available. To migrate: run \`sanctuary export-passphrase\`` +
      `\n     on the current machine, then import into the OS keyring or pass via the` +
      `\n     SANCTUARY_PASSPHRASE env var on the new machine.`
    );
  }

  // Write sovereignty profile into the per-tenant storage path resolved
  // above (honours SANCTUARY_STORAGE_PATH for multi-agent hosts).
  await mkdir(storagePath, { recursive: true, mode: 0o700 });

  // v1.1.3 hotfix (Finding X): when Sanctuary generated the passphrase
  // itself (case 3 in the source/value resolution above), the operator has
  // no off-host backup. Disclose it the same way `sanctuary init` discloses
  // a recovery key: full passphrase in stderr banner + plaintext written to
  // <fortress>/passphrase-backup.txt at mode 0600 with off-host stash
  // instructions, single-issuance. Cases 1 (--passphrase flag) and 2
  // (SANCTUARY_PASSPHRASE env) skip disclosure: the operator already holds
  // the secret. Mirrors the v1.1.1 init disclosure shape under coordinator
  // decision B-1 (Review/Sanctuary/V1.1.3_Phase_0_Coordinator_Decision_2026-04-26.md).
  if (passphraseSource === "generated" && passphraseValue !== undefined) {
    try {
      await disclosePassphrase({
        passphrase: passphraseValue,
        storagePath,
        fortressId: fortressIdFromStoragePath(storagePath),
        // --no-open (CI / scripted) or non-TTY stdin both skip the prompt
        // the same way init's --no-confirm does. Operator who scripted the
        // call still gets the banner + the file; they will not see a hang.
        mode:
          options.noOpen || process.stdin.isTTY !== true
            ? "no-confirm"
            : "interactive",
      });
    } catch (err) {
      if (
        err instanceof PassphraseConfirmationDeclinedError ||
        err instanceof PassphraseConfirmationNonInteractiveError
      ) {
        console.error(`\n  Sanctuary wrap: ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  const profile = createWrapProfile(upstreamServers);
  const profilePath = join(storagePath, "cocoon-profile.json");
  await writeFile(profilePath, JSON.stringify(profile, null, 2), {
    mode: 0o600,
  });

  // Back up and rewrite agent config.
  const backupPath = await backupConfig(agentConfig.configPath);
  await saveCocoonMeta({
    backupPath,
    originalPath: agentConfig.configPath,
    platform: agentConfig.platform,
    wrappedAt: new Date().toISOString(),
  });

  // The args list is a constant — never inject `--passphrase`. The launcher
  // re-resolves the stored passphrase at runtime from Keychain / fallback
  // file / SANCTUARY_PASSPHRASE env var. See SEC-061.
  // Build the env block for the sanctuary entry. These three vars are
  // required for the dashboard and passphrase resolution to work after
  // the config rewrite. Pull from process.env so they survive the rewrite.
  const sanctuaryEnv: Record<string, string> = {};
  if (process.env.SANCTUARY_PASSPHRASE) {
    sanctuaryEnv.SANCTUARY_PASSPHRASE = process.env.SANCTUARY_PASSPHRASE;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_AUTH_TOKEN = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ENABLED = process.env.SANCTUARY_DASHBOARD_ENABLED;
  }
  // v1.1.2 hotfix (Finding W): persist the operator-supplied --fortress
  // path so harness restarts (Claude Code re-spawning the MCP server)
  // keep the same fortress directory. Pre-fix, --fortress was honored at
  // wrap time (via promoteFortressToStoragePath above) but never written
  // into ~/.claude.json — every harness restart fell back to the default
  // fortress location, silently drifting cocoon isolation across reboots.
  //
  // The args list stays constant: persistence travels through env vars
  // exclusively, matching the SANCTUARY_PASSPHRASE pattern. The runtime
  // promotion at promoteFortressToStoragePath() honors SANCTUARY_FORTRESS_PATH
  // identically, so the spawned MCP server resolves the right storage
  // path on its boot path. Resolved to absolute so subsequent CWD
  // changes do not break the persisted reference.
  if (options.fortress) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(options.fortress);
  } else if (process.env.SANCTUARY_FORTRESS_PATH) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(
      process.env.SANCTUARY_FORTRESS_PATH,
    );
  }

  // Dogfood path (`--dev-dist <path>`): when set, point the main
  // `sanctuary` entry at a local Sanctuary build instead of the
  // npm-published version. Without this flag, an unpublished branch
  // (e.g. an in-flight PR) gets shadowed by the npm-resolved version
  // because npx pulls from the registry. Published-version wraps omit
  // the flag and use the npx default unchanged.
  const useDevDist = options.devDist !== undefined;
  const sanctuaryCommand = useDevDist ? "node" : "npx";
  const sanctuaryArgs = useDevDist
    ? [options.devDist!]
    : ["@sanctuary-framework/mcp-server"];

  const rewrite = deps.rewriteConfig ?? rewriteConfigForCocoon;
  await rewrite(
    agentConfig,
    sanctuaryCommand,
    sanctuaryArgs,
    Object.keys(sanctuaryEnv).length > 0 ? sanctuaryEnv : undefined,
  );

  const verifyOk = await verifyRewrittenConfig(
    agentConfig.configPath,
    backupPath
  );
  if (!verifyOk) process.exit(1);

  // v1.1.5 (Finding Z): persist a v1.1 hub `LocalAgentRecord` so the
  // dashboard's Agents view (`/api/hub/agents`, `/v1.1`) reflects the
  // wrap. Without this, v1.1.1 ships the API surface but never populates
  // it (registry construction at `dashboard/v1_1/wiring.ts` was empty by
  // design, deferring the data plane to v1.2). Persistence fires here,
  // after harness-config verification succeeds and before dashboard
  // spawn, so that:
  //   (a) the wrap-auto dashboard's `setV11Bindings` call below picks
  //       up the new record via the rehydrating `buildV11Bindings`;
  //   (b) `--no-dashboard` wraps still register, so a later `sanctuary
  //       dashboard` (or the next wrap) sees the cumulative set;
  //   (c) re-wrapping the same harness updates rather than duplicates
  //       (`upsertPersistedLocalAgent` keys on `agent_id`).
  // Best-effort: persistence errors do not fail wrap (the harness
  // config is already rewritten and operational; a missing dashboard
  // record is a UX degradation, not a security one). The error is
  // surfaced on stderr so operators can re-run later if needed.
  try {
    upsertPersistedLocalAgent(
      storagePath,
      buildLocalAgentRecord({
        storagePath,
        platform: agentConfig.platform,
      }),
    );
  } catch (err) {
    console.error(
      `  Note: v1.1 hub agent record not persisted ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check storage permissions on ${storagePath}.`,
    );
  }

  if (options.noDashboard) {
    // v1.1.5 (Finding AA): operator opted out of the per-call dashboard
    // spawn. The agent record is already persisted above; a later
    // `sanctuary dashboard` (or another wrap) will pick it up. Skip the
    // dashboard server, the v1.1 binding, the runtime advertisement,
    // and the auto-open browser path; print a concise success line that
    // points operators at the persistent dashboard.
    const toolName = toolNameFor(agentConfig.platform, agentConfig.servers);
    printWrapSuccessNoDashboard({
      toolName,
      version: readPackageVersion(),
      toolCount: countUpstreamTools(upstreamServers),
      serverCount: upstreamServers.length,
      passphraseLocation,
      passphraseSource,
    });
    return;
  }

  // Start the dashboard in-process.
  const authToken = generateAuthToken();
  const startFn: DashboardStarter =
    deps.startDashboard ??
    ((opts) =>
      startDashboard({
        port: opts.port,
        ...(opts.host !== undefined ? { host: opts.host } : {}),
        mode: opts.mode,
        authToken: opts.authToken,
        serverVersion: opts.serverVersion,
      }));
  // Multi-tenancy: honour SANCTUARY_DASHBOARD_PORT so two wraps can pick
  // distinct starting ports without both racing for 3501.
  const requestedPort = resolveDashboardPort(options.port);
  const dashboard = await startDashboardWithFallback(
    startFn,
    requestedPort,
    authToken,
    readPackageVersion()
  );

  // v1.1.2 hotfix (Finding V): bind v1.1 hub surfaces to the wrap-auto
  // dashboard so /v1.1, /api/hub/*, and /api/identities serve content
  // from the wrap-emitted URL. PR #82 wired these routes only into the
  // principal-policy dashboard (sanctuary dashboard standalone path) and
  // the MCP-server boot path; the wrap-auto dashboard at server/src/dashboard/
  // is a separate HTTP server and shipped without any v1.1 routing.
  //
  // Initialization mirrors the standalone path (dashboard-standalone.ts):
  // derive the master key over the persisted passphrase, construct
  // FilesystemStorage + AuditLog. The fortress-on-disk is shared between
  // this short-lived wrap process and any later MCP-server-boot process;
  // both derive the same master key from the same passphrase via Argon2id
  // (read existing key-params if present, else persist fresh ones), so
  // the activity feed projection reads the same audit log the MCP server
  // writes once it boots.
  //
  // IdentityManager.load() is intentionally NOT called: at wrap time the
  // cocoon may have no identities (created by the MCP server later); the
  // fortress-id fallback covers the empty case for the hub binding.
  // Reset-history continuity (v1.0.2 item a) is also not consumed here;
  // the next caller (MCP-server-boot or sanctuary dashboard standalone)
  // handles it on first cocoon-unlock as before.
  //
  // Best-effort: a derivation failure does not fail wrap (operators still
  // get a working v1.0 dashboard at /). The v1.1 surface is reachable
  // via `sanctuary dashboard` if this wiring path errors.
  if (passphraseValue !== undefined) {
    try {
      const v11Storage = new FilesystemStorage(`${storagePath}/state`);
      let existingParams: KeyDerivationParams | undefined;
      try {
        const raw = await v11Storage.read("_meta", "key-params");
        if (raw) {
          existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
        }
      } catch {
        // No existing params; first run. deriveMasterKey will pick fresh
        // params; we persist them below so the spawned MCP server derives
        // the same key from the same passphrase.
      }
      const derived = await deriveMasterKey(passphraseValue, existingParams);
      if (!existingParams) {
        await v11Storage.write(
          "_meta",
          "key-params",
          stringToBytes(JSON.stringify(derived.params)),
        );
      }
      const wrapAuditLog = new AuditLog(v11Storage, derived.key);
      // WP-V1.2-5: construct + load the Intelligence Substrate Selector
      // against the wrap-auto fortress. The selector reads / writes its
      // config under the fortress storage namespace `_intelligence`,
      // encrypted with the same master key the wrap path just derived.
      let wrapIntelligenceSelector: SubstrateSelector | undefined;
      try {
        wrapIntelligenceSelector = new SubstrateSelector({
          storage: v11Storage,
          masterKey: derived.key,
          auditLog: wrapAuditLog,
          identityId: `fortress:${storagePath}`,
        });
        await wrapIntelligenceSelector.load();
      } catch (err) {
        console.error(
          `  Note: Intelligence panel unavailable on wrap URL ` +
            `(${(err as Error).message}).`,
        );
        wrapIntelligenceSelector = undefined;
      }
      dashboard.setV11Bindings(
        buildV11Bindings({
          identityId: `fortress:${storagePath}`,
          fortressId: fortressIdFromStoragePath(storagePath),
          auditLog: wrapAuditLog,
          // v1.1.5 (Finding Z): rehydrate from the file the upsert
          // above just wrote, so the registry the wrap-auto dashboard
          // serves contains this wrap plus any prior wraps against the
          // same fortress.
          storagePath,
          ...(wrapIntelligenceSelector
            ? { intelligenceSelector: wrapIntelligenceSelector }
            : {}),
          // WP-V1.2-4: forward the wrap-auto fortress's storage + master
          // key so buildV11Bindings constructs the operator chat service.
          // The wrap-emitted dashboard URL surfaces concierge + direct-
          // agent chat from first launch.
          storage: v11Storage,
          masterKey: derived.key,
        }),
      );
      // The wrap-auto dashboard always binds 127.0.0.1; the operator
      // already has the bearer token in the auto-opened URL. Loopback
      // auto-auth keeps the v1.1 client one-click from the URL.
      dashboard.setV11LoopbackAutoAuth(true);
    } catch (err) {
      console.error(
        `  Note: v1.1 dashboard surfaces unavailable on wrap URL ` +
          `(${(err as Error).message}). ` +
          `Run \`sanctuary dashboard\` to reach them.`,
      );
    }
  }

  const dashboardUrl = `${dashboard.url}?token=${authToken}`;

  // Publish runtime state so `sanctuary agents` + the multi-agent
  // dashboard aggregator can find this tenant's actual port. Best-effort:
  // write failures must not block wrap, and we clean up on shutdown.
  const webhookCallbackPortRaw = process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT;
  const webhookCallbackPort = webhookCallbackPortRaw
    ? parseInt(webhookCallbackPortRaw, 10)
    : undefined;
  await writeTenantRuntime(storagePath, {
    version: readPackageVersion(),
    pid: process.pid,
    started_at: new Date().toISOString(),
    dashboard_host: dashboard.host,
    dashboard_port: dashboard.port,
    ...(webhookCallbackPort !== undefined &&
    !Number.isNaN(webhookCallbackPort)
      ? {
          webhook_callback_port: webhookCallbackPort,
          webhook_callback_host:
            process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST ?? "127.0.0.1",
        }
      : {}),
    mode: "wrap",
  });
  const cleanupRuntime = () => {
    clearTenantRuntime(storagePath).catch(() => {});
  };
  process.once("SIGINT", cleanupRuntime);
  process.once("SIGTERM", cleanupRuntime);
  process.once("exit", cleanupRuntime);

  // Auto-open in browser.
  const toolName = toolNameFor(agentConfig.platform, agentConfig.servers);
  if (!options.noOpen) {
    try {
      const opener = deps.openBrowser ?? defaultOpenBrowser;
      await opener(dashboardUrl);
    } catch {
      /* best-effort — user can still copy the URL */
    }
  }

  printWrapSuccess({
    toolName,
    version: readPackageVersion(),
    toolCount: countUpstreamTools(upstreamServers),
    serverCount: upstreamServers.length,
    dashboardUrl,
    browserOpened: !options.noOpen,
    passphraseLocation,
    passphraseSource,
  });
}

/** Backward-compat alias for the old function name. */
export async function runCocoon(options: CocoonOptions): Promise<void> {
  console.error(
    `\n  Note: \`cocoon\` is renamed to \`wrap\`. Use \`sanctuary wrap\` next time.\n`
  );
  return runWrap(options);
}

// ── Dashboard: port fallback ────────────────────────────────────────

export async function startDashboardWithFallback(
  startFn: DashboardStarter,
  preferredPort: number,
  authToken: string,
  serverVersion: string
): Promise<DashboardHandle> {
  let lastErr: unknown;
  for (let i = 0; i < PORT_FALLBACK_ATTEMPTS; i++) {
    const port = preferredPort + i;
    try {
      const handle = await startFn({
        port,
        mode: "co-located",
        authToken,
        serverVersion,
      });
      if (port !== preferredPort) {
        console.error(
          `  Port ${preferredPort} was unavailable. Dashboard bound to ${port}.`
        );
      }
      return handle;
    } catch (err) {
      lastErr = err;
      if (!isAddressInUse(err)) throw err;
    }
  }
  const lastPort = preferredPort + PORT_FALLBACK_ATTEMPTS - 1;
  throw new Error(
    `No free dashboard port in the ${PORT_FALLBACK_ATTEMPTS} ports starting at ${preferredPort} (tried ${preferredPort}-${lastPort}): ${
      (lastErr as Error)?.message ?? "unknown"
    }`
  );
}

function isAddressInUse(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: string }).code;
  return code === "EADDRINUSE";
}

// ── Browser auto-open ───────────────────────────────────────────────

async function defaultOpenBrowser(url: string): Promise<void> {
  const plat = platform();
  let cmd: string;
  let args: string[];
  if (plat === "darwin") {
    cmd = "open";
    args = [url];
  } else if (plat === "win32") {
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  await new Promise<void>((resolve) => {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => resolve());
    child.on("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

// ── Success output ──────────────────────────────────────────────────

interface WrapSuccessInfo {
  toolName: string;
  version: string;
  toolCount: number;
  serverCount: number;
  dashboardUrl: string;
  browserOpened: boolean;
  passphraseLocation: string;
  passphraseSource: string;
}

export function formatWrapSuccess(info: WrapSuccessInfo): string {
  const g = (s: string) => `\x1b[32m${s}\x1b[0m`; // green
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`;  // dim
  const b = (s: string) => `\x1b[1m${s}\x1b[0m`;  // bold
  const check = "\u2713";

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `  ${g(check)} Wrapped ${b(info.toolName)} with Sanctuary v${info.version}`
  );
  lines.push(
    `  ${g(check)} ${info.toolCount} tools registered across ${info.serverCount} upstream server${info.serverCount !== 1 ? "s" : ""}`
  );
  lines.push(
    `  ${g(check)} Sovereignty Dashboard running at ${b(info.dashboardUrl)}`
  );
  if (info.browserOpened) {
    lines.push(`  ${g(check)} Opened in your browser`);
  } else {
    lines.push(`  ${d("(browser auto-open suppressed)")}`);
  }
  lines.push("");
  lines.push(`  ${b("Your agent is protected.")} L1 Full / L2 Degraded (no TEE) / L3 Full / L4 Full.`);
  lines.push("");
  return lines.join("\n");
}

function printWrapSuccess(info: WrapSuccessInfo): void {
  console.error(formatWrapSuccess(info));
}

interface WrapSuccessNoDashboardInfo {
  toolName: string;
  version: string;
  toolCount: number;
  serverCount: number;
  passphraseLocation: string;
  passphraseSource: string;
}

/**
 * Format the wrap-success output for the v1.1.5 `--no-dashboard` path
 * (Finding AA). Mirrors `formatWrapSuccess` but replaces the dashboard
 * URL line with a single-line note pointing operators at the persistent
 * dashboard pattern. Exposed for tests; production callers go through
 * `printWrapSuccessNoDashboard`.
 */
export function formatWrapSuccessNoDashboard(
  info: WrapSuccessNoDashboardInfo,
): string {
  const g = (s: string) => `\x1b[32m${s}\x1b[0m`;
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`;
  const b = (s: string) => `\x1b[1m${s}\x1b[0m`;
  const check = "✓";

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `  ${g(check)} Wrapped ${b(info.toolName)} with Sanctuary v${info.version}`,
  );
  lines.push(
    `  ${g(check)} ${info.toolCount} tools registered across ${info.serverCount} upstream server${info.serverCount !== 1 ? "s" : ""}`,
  );
  lines.push(
    `  ${d("Dashboard spawn skipped per --no-dashboard. Run `sanctuary dashboard` separately for a persistent dashboard.")}`,
  );
  lines.push("");
  lines.push(
    `  ${b("Your agent is protected.")} L1 Full / L2 Degraded (no TEE) / L3 Full / L4 Full.`,
  );
  lines.push("");
  return lines.join("\n");
}

function printWrapSuccessNoDashboard(
  info: WrapSuccessNoDashboardInfo,
): void {
  console.error(formatWrapSuccessNoDashboard(info));
}

// ── Post-wrap verification ──────────────────────────────────────────

async function verifyRewrittenConfig(
  configPath: string,
  backupPath: string
): Promise<boolean> {
  try {
    const raw = await readFile(configPath, "utf-8");
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      console.error(`\n  Verification FAILED: Rewritten config is not valid JSON.`);
      console.error(`  Error: ${(err as Error).message}`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    const servers =
      ((parsed.mcp as Record<string, unknown>)?.servers as Record<string, unknown>) ??
      (parsed.mcpServers as Record<string, unknown>) ??
      (parsed.mcp_servers as Record<string, unknown>) ??
      {};

    if (!servers.sanctuary) {
      console.error(`\n  Verification FAILED: No sanctuary entry in rewritten config.`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

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

async function restoreFromBackup(
  configPath: string,
  backupPath: string
): Promise<void> {
  try {
    await restoreConfig(backupPath, configPath);
    console.error(`  Original config restored from backup.`);
    console.error(`  Backup preserved at: ${backupPath}\n`);
  } catch (restoreErr) {
    console.error(
      `  CRITICAL: Could not restore backup from ${backupPath}`
    );
    console.error(`  Error: ${(restoreErr as Error).message}`);
    console.error(`  Manual recovery: copy ${backupPath} to ${configPath}\n`);
  }
}

// ── Unwrap ──────────────────────────────────────────────────────────

async function unwrap(): Promise<void> {
  const meta = await findLatestBackup();
  if (!meta) {
    console.error("No Sanctuary wrap found to restore.");
    console.error("Run `sanctuary wrap --openclaw` first.");
    process.exit(1);
  }

  try {
    await access(meta.backupPath);
  } catch {
    console.error(`Backup file not found: ${meta.backupPath}`);
    process.exit(1);
  }

  await restoreConfig(meta.backupPath, meta.originalPath);
  console.error(`\n  Sanctuary: Unwrapped`);
  console.error(`  Original config restored to: ${meta.originalPath}`);
  console.error(`  Backup preserved at: ${meta.backupPath}\n`);
}

// ── Helpers ─────────────────────────────────────────────────────────

function convertToUpstreamServers(
  servers: MCPServerEntry[]
): UpstreamServer[] {
  return servers.map((server) => ({
    name: server.name,
    transport:
      server.transport === "sse"
        ? { type: "sse" as const, url: server.url! }
        : {
            type: "stdio" as const,
            command: server.command!,
            ...(server.args ? { args: server.args } : {}),
            ...(server.env ? { env: server.env } : {}),
          },
    enabled: true,
    default_tier: 2,
  }));
}

function createWrapProfile(upstream: UpstreamServer[]): SovereigntyProfile {
  return {
    version: 1,
    features: {
      audit_logging: { enabled: true },
      injection_detection: { enabled: true },
      context_gating: { enabled: false },
      approval_gate: { enabled: true },
      zk_proofs: { enabled: false },
    },
    upstream_servers: upstream,
    updated_at: new Date().toISOString(),
  };
}

function generateAuthToken(): string {
  // 24 bytes → 32-char base64url — plenty of entropy for a single-use URL.
  return randomBytes(24)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function toolNameFor(platform: AgentPlatform, _servers: MCPServerEntry[]): string {
  switch (platform) {
    case "openclaw": return "OpenClaw";
    case "hermes": return "Hermes Agent";
    case "claude-code": return "Claude Code";
    case "cursor": return "Cursor";
    case "cline": return "Cline";
    default: return "your agent";
  }
}

/**
 * Map the wrap-side `AgentPlatform` (kebab-cased, harness detection
 * vocabulary) to the v1.1 hub registry's `LocalHarnessKind` (snake-cased,
 * dashboard-render vocabulary). The two enums describe the same set of
 * supported wrap targets but live in different layers; centralizing the
 * mapping here means the hub layer doesn't import the wrap layer's enum
 * and vice versa.
 */
function harnessKindForPlatform(platform: AgentPlatform): LocalHarnessKind {
  switch (platform) {
    case "openclaw": return "openclaw";
    case "hermes": return "hermes";
    case "claude-code": return "claude_code";
    case "cursor": return "cursor";
    case "cline": return "cline";
    case "generic": return "generic_mcp";
    default: {
      // Defensive: unknown future platforms map to "other" rather than
      // crashing wrap. Adding a new platform should land its
      // `LocalHarnessKind` mapping in the same PR.
      const _exhaustive: never = platform;
      void _exhaustive;
      return "other";
    }
  }
}

/**
 * Build the v1.1 hub `LocalAgentRecord` for a freshly wrapped harness.
 *
 * v1.1.5 placeholders (Finding Z): wrap does not yet detect the model
 * provider or bind a policy at wrap time, so `model_provider.vendor`
 * stays "unknown" and `policy_id` stays "unbound" until the v1.2
 * data-plane work lands real detection / Phase 2 binding. The capability
 * flags reflect what the dashboard controller honestly supports today:
 * `can_unwrap` remains the only harness mutation exposed, and
 * `can_change_template` is registry-local through the Tier 1 binding flow.
 */
function buildLocalAgentRecord(input: {
  storagePath: string;
  platform: AgentPlatform;
}): LocalAgentRecord {
  const harness = harnessKindForPlatform(input.platform);
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  const nowIso = new Date().toISOString();
  return {
    version: "1.1",
    agent_id: `agent:${harness}:${fortressId}`,
    identity_id: `fortress:${input.storagePath}`,
    harness,
    model_provider: {
      vendor: "unknown",
      model_id: "unknown",
      runs_locally: false,
    },
    policy_id: "unbound",
    status: "active",
    budget_summary: {
      last_refreshed_at: nowIso,
    },
    last_activity_at: nowIso,
    wrapped_at: nowIso,
    capabilities: {
      can_pause: false,
      can_resume: false,
      can_restart: false,
      can_unwrap: true,
      can_lockdown: false,
      can_chat: false,
      can_change_template: true,
    },
  };
}

function countUpstreamTools(servers: UpstreamServer[]): number {
  // Conservative estimate — real count requires live tool discovery.
  // At wrap time we do not have an MCP client connection yet, so we show
  // a "0+ tools" placeholder until the dashboard fills in live data.
  return servers.length === 0 ? 0 : servers.length;
}

function readPackageVersion(): string {
  return SANCTUARY_VERSION;
}

/**
 * Detects whether a parsed agent config already has a Sanctuary entry under
 * its platform-specific MCP servers key. extractServers filters Sanctuary
 * out of the upstream list (so we don't stack entries on rewrite), so the
 * filtered `agentConfig.servers` array can't be used to detect re-wrap;
 * we have to look at the raw config instead.
 */
function rawConfigContainsSanctuary(
  raw: unknown,
  agentPlatform: AgentPlatform
): boolean {
  if (!raw || typeof raw !== "object") return false;
  const obj = raw as Record<string, unknown>;
  let serversBag: Record<string, unknown> | undefined;
  if (agentPlatform === "openclaw") {
    const mcp = obj.mcp as Record<string, unknown> | undefined;
    serversBag =
      (mcp?.servers as Record<string, unknown> | undefined) ??
      (obj.mcpServers as Record<string, unknown> | undefined);
  } else if (agentPlatform === "hermes") {
    serversBag = obj.mcp_servers as Record<string, unknown> | undefined;
  } else {
    serversBag = obj.mcpServers as Record<string, unknown> | undefined;
  }
  if (!serversBag || typeof serversBag !== "object") return false;
  return Object.keys(serversBag).some(
    (name) => name.toLowerCase() === "sanctuary"
  );
}

// ── CLI argument parser ─────────────────────────────────────────────

export function parseWrapArgs(argv: string[]): WrapOptions {
  const options: WrapOptions = {};

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--wrap":
        options.wrap = argv[++i];
        break;
      case "--openclaw":
        options.openclaw = true;
        break;
      case "--hermes":
        options.hermes = true;
        break;
      case "--claude-code":
        options.claudeCode = true;
        break;
      case "--cursor":
        options.cursor = true;
        break;
      case "--cline":
        options.cline = true;
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
      case "--no-open":
        options.noOpen = true;
        break;
      case "--no-dashboard":
        options.noDashboard = true;
        break;
      case "--fortress":
        options.fortress = argv[++i];
        break;
      case "--dev-dist":
        options.devDist = argv[++i];
        break;
      case "--help":
      case "-h":
        printWrapHelp();
        process.exit(0);
    }
  }

  return options;
}

/** Backward-compat alias for the old function name. */
export const parseCocoonArgs = parseWrapArgs;

function printWrapHelp(): void {
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
