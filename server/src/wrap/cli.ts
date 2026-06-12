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

import { writeFile, readFile, mkdir, access, lstat } from "node:fs/promises";
import { dirname, join, resolve as resolvePath } from "node:path";
import { Writable } from "node:stream";
import { platform } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveWrapMeta,
  findLatestBackup,
  restoreConfig,
  rewriteConfigForWrap,
  getPlatformPaths,
  validateWrapMetaAuxiliary,
  writeFileSafeUnderRoot,
  unlinkSafeUnderRoot,
  WrapMetaValidationError,
  type AgentPlatform,
  type MCPServerEntry,
  type WrapMetaAuxiliaryFile,
  type ValidatedWrapMetaAuxiliaryFile,
} from "./config-reader.js";
import {
  hermesConfigYamlPath,
  planHermesYamlInjection,
  yamlContainsSanctuaryEntry,
  HermesYamlUnsupportedError,
  type HermesYamlPlan,
} from "./hermes-yaml.js";
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
  registerHostTenant,
  TENANTS_REGISTRY_FILE_NAME,
} from "../cli/agents/tenant-registry.js";
import {
  disclosePassphrase,
  PassphraseConfirmationDeclinedError,
  PassphraseConfirmationNonInteractiveError,
} from "./recovery-key-disclosure.js";
import type { UpstreamServer, SovereigntyProfile } from "../sovereignty-profile.js";
import { runProvisionPin } from "../cli/castle-wall.js";
import type { MacOSCastleWallDaemonHandle } from "../castle-wall/runtime/index.js";

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
  /**
   * Opt-in plaintext passphrase backup file path. When set, writes the
   * generated passphrase to this file at mode 0600. Default behavior
   * (unset): Keychain-only, no plaintext file on disk. v1.2.1 change:
   * previously wrap wrote passphrase-backup.txt by default.
   */
  writePassphraseBackup?: string;
  /**
   * Opt-in transparency anchoring at setup (PR-2). OFF by default. When
   * set, wrap records consent and enables publishing a salted hash
   * commitment of each enforcement checkpoint to the public Sigstore
   * Rekor transparency log. Only the salted hash, a signature from a
   * dedicated derived key, and that key's public half are ever
   * published; never checkpoint contents, counts, policy data, or
   * fortress identifiers. Passing the flag IS the explicit consent
   * action; the consent statement is printed and its hash recorded.
   * If the flag is passed and enabling fails, wrap fails LOUDLY
   * (exit 2) rather than silently continuing without anchoring.
   */
  anchorTransparency?: boolean;
}

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

/**
 * Build the env block for the sanctuary entry. These vars are required for
 * the dashboard and passphrase resolution to work after the config rewrite.
 * Pulled from process.env so they survive the rewrite.
 *
 * v1.1.2 hotfix (Finding W): persist the operator-supplied --fortress
 * path so harness restarts (Claude Code re-spawning the MCP server)
 * keep the same fortress directory. Pre-fix, --fortress was honored at
 * wrap time (via promoteFortressToStoragePath) but never written
 * into ~/.claude.json — every harness restart fell back to the default
 * fortress location, silently drifting fortress isolation across reboots.
 *
 * The args list stays constant: persistence travels through env vars
 * exclusively, matching the SANCTUARY_PASSPHRASE pattern. The runtime
 * promotion at promoteFortressToStoragePath() honors SANCTUARY_FORTRESS_PATH
 * identically, so the spawned MCP server resolves the right storage
 * path on its boot path. Resolved to absolute so subsequent CWD
 * changes do not break the persisted reference.
 */
function buildSanctuaryEnv(options: WrapOptions): Record<string, string> {
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
  if (options.fortress) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(options.fortress);
  } else if (process.env.SANCTUARY_FORTRESS_PATH) {
    sanctuaryEnv.SANCTUARY_FORTRESS_PATH = resolvePath(
      process.env.SANCTUARY_FORTRESS_PATH,
    );
  }
  return sanctuaryEnv;
}

/**
 * Resolve the command + args registered for the `sanctuary` MCP entry.
 *
 * Dogfood path (`--dev-dist <path>`): when set, point the main
 * `sanctuary` entry at a local Sanctuary build instead of the
 * npm-published version. Without this flag, an unpublished branch
 * (e.g. an in-flight PR) gets shadowed by the npm-resolved version
 * because npx pulls from the registry. Published-version wraps omit
 * the flag and use the npx default unchanged.
 */
function resolveSanctuaryCommand(options: WrapOptions): {
  command: string;
  args: string[];
} {
  const useDevDist = options.devDist !== undefined;
  return {
    command: useDevDist ? "node" : "npx",
    args: useDevDist ? [options.devDist!] : ["@sanctuary-framework/mcp-server"],
  };
}

/** Operator-facing one-liner for what the YAML injection did / would do. */
function formatHermesYamlAction(plan: HermesYamlPlan, yamlPath: string): string {
  const preserved =
    plan.preservedEntryNames.length > 0
      ? ` (${plan.preservedEntryNames.length} existing ${
          plan.preservedEntryNames.length === 1 ? "entry" : "entries"
        } preserved)`
      : "";
  switch (plan.action) {
    case "create-file":
      return `create ${yamlPath} with the sanctuary entry under mcp_servers`;
    case "add-key":
      return `add mcp_servers with the sanctuary entry to ${yamlPath}${preserved}`;
    case "append-entry":
      return `add the sanctuary entry to mcp_servers in ${yamlPath}${preserved}`;
    case "replace-entry":
      return `update the existing sanctuary entry in ${yamlPath}${preserved}`;
  }
}

/**
 * D4 staging, Bugs 1+2: dry-run preview of the Hermes config.yaml
 * injection. Read-only by construction (planHermesYamlInjection is pure;
 * the only filesystem touch is the readFile probe), and previews the
 * exact entry the real run would write because it shares
 * buildSanctuaryEnv / resolveSanctuaryCommand with the write path.
 */
async function reportHermesYamlDryRun(options: WrapOptions): Promise<void> {
  const yamlPath = hermesConfigYamlPath();
  let existingYaml: string | null = null;
  try {
    existingYaml = await readFile(yamlPath, "utf-8");
  } catch {
    // File absent — the plan would create it.
  }
  const sanctuaryEnv = buildSanctuaryEnv(options);
  const { command, args } = resolveSanctuaryCommand(options);
  try {
    const plan = planHermesYamlInjection(existingYaml, {
      command,
      args,
      ...(Object.keys(sanctuaryEnv).length > 0 ? { env: sanctuaryEnv } : {}),
    });
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Hermes MCP routing: would ${formatHermesYamlAction(plan, yamlPath)}`
    );
  } catch (err) {
    if (err instanceof HermesYamlUnsupportedError) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Hermes MCP routing: wrap would FAIL before modifying anything: ${err.message}`
      );
      return;
    }
    throw err;
  }
}

/**
 * D4 P2-3: refuse to write through a symlinked config target. writeFile
 * and copyFile follow symlinks, so a symlinked ~/.hermes/config.yaml (or a
 * symlinked restore target on unwrap) would redirect the write to an
 * arbitrary path outside the agent's config directory. lstat sees the link
 * itself; an absent path is fine (the write creates it).
 */
async function refuseSymlinkTarget(path: string, surface: string): Promise<void> {
  let isLink: boolean;
  try {
    isLink = (await lstat(path)).isSymbolicLink();
  } catch {
    return; // Absent — nothing to refuse.
  }
  if (isLink) {
    throw new Error(
      `${surface} at ${path} is a symlink; refusing to write through it. ` +
        `Replace the symlink with a regular file and re-run.`
    );
  }
}

// ── Constants ───────────────────────────────────────────────────────

/** Default CallGovernor limits for wrapped agents. */
export const WRAP_GOVERNOR_DEFAULTS = {
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
  rewriteConfig?: typeof rewriteConfigForWrap;
  /**
   * Override the Claude Code permissions.allow installer (WP-V1.2 reshape).
   * Production uses the bundled `installClaudeCodeAllowlist`; tests
   * inject a stub to assert the call shape without touching the
   * developer's real ~/.claude/settings.json.
   */
  installClaudeCodeAllowlist?: (
    opts: import("./claude-code-allowlist.js").InstallClaudeCodeAllowlistOptions,
  ) => Promise<
    import("./claude-code-allowlist.js").InstallClaudeCodeAllowlistResult
  >;
}

export async function runWrap(
  options: WrapOptions,
  deps: RunWrapDeps = {}
): Promise<void> {
  // D4 P2-2: --unwrap honors --dry-run too — pre-fix, the unwrap dispatch
  // sat above the dry-run gate, so `--unwrap --dry-run` restored backups
  // for real. The gate travels into unwrap() so it can report what WOULD
  // be restored/removed while writing nothing.
  if (options.unwrap) {
    await unwrap(options.dryRun === true);
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
    // D4 staging, Bug 1: --dry-run must guarantee ZERO filesystem writes.
    // This bootstrap ran BEFORE the dry-run gate below, so `protect
    // --hermes --dry-run` on a host with no config still created the file.
    // Report what would be bootstrapped and stop before any write path.
    if (canonicalPath && options.dryRun) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  No existing ${platformHint} config found.`);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`  Would bootstrap a fresh config at ${canonicalPath}.`);
      if (platformHint === "hermes") {
        await reportHermesYamlDryRun(options);
      }
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Dry run. No changes made.\n`);
      return;
    }
    if (canonicalPath) {
      try {
        // Round-3 P1-A: the fresh-config bootstrap used mkdir(recursive) +
        // plain writeFile, both of which follow a symlinked parent (e.g.
        // ~/.hermes -> /tmp/victim). Route it through the same safe-path
        // discipline as every other wrap sink.
        await writeFileSafeUnderRoot(canonicalPath, "{}", { mode: 0o600 });
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  No existing ${platformHint} config found.`
        );
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Bootstrapped a fresh config at ${canonicalPath}.\n`
        );
        detection = await detectAgentConfigWithDiagnostics(
          platformHint,
          options.wrap
        );
        agentConfig = detection.config;
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Sanctuary: could not bootstrap ${platformHint} config at ${canonicalPath}`
        );
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Error: ${(err as Error).message}\n`);
        process.exit(1);
      }
    }
  }

  if (!agentConfig) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Configuration Not Found\n`);
    if (platformHint) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Paths checked:`);
      for (const p of detection.pathsChecked) console.error(`    ${p}`);
    }
    if (detection.errors.length > 0) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Errors encountered:`);
      for (const e of detection.errors) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary already wrapped: updating the existing Sanctuary entry.\n`
    );
  } else if (agentConfig.servers.length === 0) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Found ${agentConfig.platform} config at ${agentConfig.configPath} with no MCP servers yet.`
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Sanctuary will be installed as the only MCP server.\n`
    );
  }

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary wrap`);
  console.error(`  Platform: ${agentConfig.platform}`);
  console.error(`  Config: ${agentConfig.configPath}`);

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `  ${formatMcpServerCount(agentConfig.servers.length, hasSanctuaryInRaw)}`
  );

  const upstreamServers = convertToUpstreamServers(agentConfig.servers);
  for (const server of upstreamServers) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `    → ${server.name} (${server.transport.type}, tier ${server.default_tier})`
    );
  }

  if (options.dryRun) {
    // D4 staging, Bug 2: report what WOULD be written to Hermes's
    // config.yaml so the dry run previews the full wrap, while Bug 1
    // keeps this path guaranteed write-free (the gate sits above every
    // write: config bootstrap, fortress state, agent-record persistence).
    if (agentConfig.platform === "hermes") {
      await reportHermesYamlDryRun(options);
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
  // See SEC-061 in Archive/DELTA_REVIEW_V0.9.0_RC1.md.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  \u{1F510} Persisted user-supplied passphrase (${persisted.location}).`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Back up with: sanctuary export-passphrase`
      );
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  \u{1F510} Generated and stored passphrase (${resolved.location}).`
        );
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Back up with: sanctuary export-passphrase`
        );
      }
    } catch (err) {
      if (err instanceof PassphraseUnreadableError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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

  if (passphraseValue !== undefined) {
    // Auto-bootstrap pinned-key state for the IPC handshake. Failures here
    // warn but do not abort wrap: a missing pin surfaces cleanly at handshake
    // time (sysext refuses connection) rather than as a wrap-startup abort.
    // First-integration discipline: do no harm to the wrap critical path.
    try {
      const pinResult = await runProvisionPin({
        out: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
        err: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
        env: {
          ...process.env,
          SANCTUARY_STORAGE_PATH: storagePath,
          SANCTUARY_PASSPHRASE: passphraseValue,
        },
      });
      if (pinResult !== 0) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Sanctuary wrap: Castle Wall provision-pin auto-bootstrap exited ${pinResult}.` +
          `\n  Wrap continues; run 'sanctuary castle-wall provision-pin' manually if IPC handshake fails.`
        );
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary wrap: Castle Wall provision-pin auto-bootstrap threw (${msg}).` +
        `\n  Wrap continues; run 'sanctuary castle-wall provision-pin' manually if IPC handshake fails.`
      );
    }
  }

  let castleWallDaemon: MacOSCastleWallDaemonHandle | undefined;
  const registerCastleWallCleanup = () => {
    if (!castleWallDaemon) return;
    const stop = () => {
      castleWallDaemon?.stop().catch(() => {});
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    process.once("exit", stop);
  };
  const startCastleWallForWrap = async (auditLog: AuditLog, masterKey: Uint8Array) => {
    if (castleWallDaemon) return;
    const { startMacOSCastleWallDaemon } = await import("../castle-wall/runtime/index.js");
    castleWallDaemon = await startMacOSCastleWallDaemon({
      fortressPath: storagePath,
      fortressId: fortressIdFromStoragePath(storagePath),
      masterKey,
      auditLog,
    });
    registerCastleWallCleanup();
  };

  // v1.2.1 (Finding GGG): plaintext passphrase backup file is now opt-in.
  // Default: Keychain-only on macOS. The plaintext file is written ONLY when
  // --write-passphrase-backup <path> is supplied. The stderr banner still
  // prints so the operator sees the passphrase once.
  if (passphraseSource === "generated" && passphraseValue !== undefined) {
    if (options.writePassphraseBackup) {
      try {
        await disclosePassphrase({
          passphrase: passphraseValue,
          storagePath: dirname(options.writePassphraseBackup),
          fortressId: fortressIdFromStoragePath(storagePath),
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
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(`\n  Sanctuary wrap: ${err.message}\n`);
          process.exit(2);
        }
        throw err;
      }
    } else {
      // Keychain-only: print the passphrase banner to stderr but do NOT
      // write a plaintext file to disk.
      process.stderr.write(
        `\n  Passphrase stored in macOS Keychain.` +
        `\n  Run 'sanctuary export-passphrase' to retrieve it.` +
        `\n  To write a plaintext backup: sanctuary wrap ... --write-passphrase-backup <path>\n`,
      );
    }
  }

  const profile = createWrapProfile(upstreamServers);
  // Read-both, write-new: new wraps write this canonical name; tenant
  // discovery (cli/agents/discovery.ts) also recognizes the legacy
  // pre-vocabulary-sweep filename so existing installs keep working.
  const profilePath = join(storagePath, "wrap-profile.json");
  await writeFile(profilePath, JSON.stringify(profile, null, 2), {
    mode: 0o600,
  });

  // The args list is a constant — never inject `--passphrase`. The launcher
  // re-resolves the stored passphrase at runtime from Keychain / fallback
  // file / SANCTUARY_PASSPHRASE env var. See SEC-061. Env-block and
  // command/args construction live in buildSanctuaryEnv /
  // resolveSanctuaryCommand so the dry-run reporter previews the exact
  // entry the real run writes.
  const sanctuaryEnv = buildSanctuaryEnv(options);
  const { command: sanctuaryCommand, args: sanctuaryArgs } =
    resolveSanctuaryCommand(options);

  // D4 staging, Bug 2: Hermes v0.16.0 loads MCP servers from
  // ~/.hermes/config.yaml (`mcp_servers:` key, upstream
  // hermes_cli/mcp_config.py and mcp_startup.py), not from the JSON
  // cli-config.json wrap rewrites below. Without the YAML injection the
  // wrap records the agent but Hermes MCP traffic silently bypasses the
  // Sanctuary proxy. The plan is computed BEFORE any harness config is
  // touched so an unsupported YAML shape aborts with both surfaces
  // untouched; the JSON write is kept for forward-compat with the
  // documented cli-config.json surface.
  let hermesYaml:
    | { yamlPath: string; existedBefore: boolean; plan: HermesYamlPlan }
    | undefined;
  if (agentConfig.platform === "hermes") {
    const yamlPath = hermesConfigYamlPath();
    // D4 P2-3: a symlinked config.yaml would redirect the writeFile below
    // outside ~/.hermes. Checked here, before ANY surface is backed up or
    // rewritten, so the refusal leaves everything untouched.
    try {
      await refuseSymlinkTarget(yamlPath, "Hermes config.yaml");
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Hermes config.yaml Not Editable`);
      console.error(`  ${(err as Error).message}`);
      console.error(`  Nothing was modified.\n`);
      process.exit(1);
    }
    let existingYaml: string | null = null;
    try {
      existingYaml = await readFile(yamlPath, "utf-8");
    } catch {
      // File absent — the plan creates it.
    }
    try {
      const plan = planHermesYamlInjection(existingYaml, {
        command: sanctuaryCommand,
        args: sanctuaryArgs,
        ...(Object.keys(sanctuaryEnv).length > 0 ? { env: sanctuaryEnv } : {}),
      });
      hermesYaml = { yamlPath, existedBefore: existingYaml !== null, plan };
    } catch (err) {
      if (err instanceof HermesYamlUnsupportedError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Hermes config.yaml Not Editable`);
        console.error(`  ${err.message}`);
        console.error(
          `  Nothing was modified. Hermes routes MCP traffic through ${yamlPath};` +
            `\n  wrap will not proceed without updating it (a JSON-only wrap would` +
            `\n  silently leave Hermes traffic outside the Sanctuary proxy).\n`
        );
        process.exit(1);
      }
      throw err;
    }
  }

  // Back up and rewrite agent config. For Hermes, config.yaml is backed up
  // alongside cli-config.json and recorded in the wrap meta so unwrap
  // restores both surfaces.
  const backupPath = await backupConfig(agentConfig.configPath);
  let hermesYamlBackupPath: string | null = null;
  if (hermesYaml?.existedBefore) {
    hermesYamlBackupPath = await backupConfig(hermesYaml.yamlPath);
  }
  await saveWrapMeta({
    backupPath,
    originalPath: agentConfig.configPath,
    platform: agentConfig.platform,
    wrappedAt: new Date().toISOString(),
    ...(hermesYaml
      ? {
          auxiliary: [
            {
              originalPath: hermesYaml.yamlPath,
              backupPath: hermesYamlBackupPath,
            },
          ] satisfies WrapMetaAuxiliaryFile[],
        }
      : {}),
  });

  const rewrite = deps.rewriteConfig ?? rewriteConfigForWrap;
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

  // D4 staging, Bug 2: apply the precomputed config.yaml injection now that
  // the JSON surface verified. D4 P1-1: the ENTIRE write+verify is inside
  // one rollback scope — a thrown writeFile (unwritable file, bad symlink)
  // previously escaped the verify-only rollback and left the wrap partially
  // applied (JSON wrapped, YAML not: the exact silent-bypass state this fix
  // exists to prevent). Any failure now rolls BOTH surfaces back and exits
  // non-zero, so the wrap is atomic: fully applied or fully rolled back.
  if (hermesYaml) {
    const yamlSurface = hermesYaml;
    const rollbackBothSurfaces = async (): Promise<void> => {
      if (hermesYamlBackupPath) {
        await restoreFromBackup(yamlSurface.yamlPath, hermesYamlBackupPath);
      } else {
        try {
          // Round-3 P1-A: parent-walk-safe even on the rollback path.
          await unlinkSafeUnderRoot(yamlSurface.yamlPath);
        } catch {
          // Best-effort removal of the file this wrap created (it may not
          // exist when the write itself was what failed, or be refused if a
          // symlink was raced into its parent).
        }
      }
      await restoreFromBackup(agentConfig.configPath, backupPath);
    };
    let yamlVerified = false;
    try {
      // D4 P2-3 courtesy re-check at write time. Round-2 P1-A: lstat-then-
      // write is TOCTOU-raceable, so the no-follow open is the leaf
      // enforcement. Round-3 P1-A: the leaf-only O_NOFOLLOW could STILL be
      // redirected by a symlinked PARENT (`~/.hermes -> /tmp/victim`), so
      // writeFileSafeUnderRoot walks every parent component from HOME and
      // refuses a symlinked ancestor, recreates missing parents segment-by-
      // segment (no recursive mkdir following a link), then opens the leaf
      // O_NOFOLLOW.
      await refuseSymlinkTarget(yamlSurface.yamlPath, "Hermes config.yaml");
      await writeFileSafeUnderRoot(yamlSurface.yamlPath, yamlSurface.plan.content, {
        mode: 0o600,
      });
      yamlVerified = yamlContainsSanctuaryEntry(
        await readFile(yamlSurface.yamlPath, "utf-8")
      );
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Hermes config.yaml write FAILED: ${(err as Error).message}`
      );
      await rollbackBothSurfaces();
      process.exit(1);
    }
    if (!yamlVerified) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Verification FAILED: No sanctuary entry in rewritten ${yamlSurface.yamlPath}.`
      );
      await rollbackBothSurfaces();
      process.exit(1);
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Hermes MCP routing: ${formatHermesYamlAction(yamlSurface.plan, yamlSurface.yamlPath)}`
    );
  }

  // WP-V1.2 reshape: write the broker-tool identifiers to Claude Code's
  // permissions.allow list at wrap time so the wrapped agent's routine
  // broker calls (request_token, read_secret, list_grants, audit_query)
  // run without a per-turn permission prompt for the operator. The
  // broker's policy gate stops any write-side or destructive operation
  // regardless of the allowlist; the allowlist only suppresses the
  // Claude Code UI confirmation flow on routine reads. Best-effort:
  // failure logs to stderr but does not fail wrap (operator can still
  // grant permission interactively on first call).
  if (agentConfig.platform === "claude-code") {
    try {
      const allowFn =
        deps.installClaudeCodeAllowlist ??
        (async (o) => {
          const { installClaudeCodeAllowlist } = await import(
            "./claude-code-allowlist.js"
          );
          return installClaudeCodeAllowlist(o);
        });
      const allowResult = await allowFn({});
      if (allowResult.alreadyPresent) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Sanctuary broker tool allowlist already present at ${allowResult.installedAt}. No change.`,
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Sanctuary broker tool allowlist updated at ${allowResult.installedAt} ` +
            `(${allowResult.added.length} ${allowResult.added.length === 1 ? "entry" : "entries"} added; ` +
            `routine broker calls run without per-turn prompts).`,
        );
      }
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Note: broker tool allowlist write failed (${(err as Error).message}). ` +
          `Wrap is otherwise complete; Claude Code will prompt to approve ` +
          `broker/request_token, broker/read_secret, broker/list_grants, ` +
          `and broker/audit_query on first call. ` +
          `Click "Always allow" once per tool to suppress future prompts.`,
      );
    }
  }

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
    await registerHostTenant(storagePath);
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: host tenant registry not updated ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check permissions on ~/.sanctuary/${TENANTS_REGISTRY_FILE_NAME}.`,
    );
  }

  try {
    upsertPersistedLocalAgent(
      storagePath,
      buildLocalAgentRecord({
        storagePath,
        platform: agentConfig.platform,
      }),
    );
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: v1.1 hub agent record not persisted ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check storage permissions on ${storagePath}.`,
    );
  }

  // PR-2 transparency anchoring opt-in (default OFF). Set to true only
  // when consent is recorded and the MAC'd config is written; checked
  // LOUDLY before each success exit so a requested opt-in can never be
  // silently dropped by a best-effort failure above it.
  let anchorTransparencyEnabled = false;
  const enableAnchorTransparencyForWrap = async (
    storageForWrap: import("../storage/interface.js").StorageBackend,
    masterKeyForWrap: Uint8Array,
    auditLogForWrap: AuditLog,
  ): Promise<void> => {
    if (!options.anchorTransparency || anchorTransparencyEnabled) return;
    const { ANCHOR_CONSENT_TEXT, enableAnchoring } = await import(
      "../transparency/anchoring.js"
    );
    // Print the exact consent statement the flag agreed to; its hash is
    // recorded in the MAC'd config and the audit log.
    process.stderr.write(`\n  ${ANCHOR_CONSENT_TEXT}\n`);
    await enableAnchoring({
      storage: storageForWrap,
      masterKey: masterKeyForWrap,
      auditLog: auditLogForWrap,
      fortressId: fortressIdFromStoragePath(storagePath),
    });
    anchorTransparencyEnabled = true;
    process.stderr.write(
      `\n  Transparency anchoring ENABLED (consent recorded in the audit log).\n` +
        `  Manage it with: sanctuary transparency anchor status|disable|now\n`,
    );
  };
  const failIfAnchorOptInDropped = (): void => {
    if (options.anchorTransparency && !anchorTransparencyEnabled) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  ERROR: --anchor-transparency was requested but anchoring could not be enabled.` +
          `\n  Nothing was transmitted. Fix the error above, or enable it on the existing fortress with:` +
          `\n    sanctuary transparency anchor enable\n`,
      );
      process.exit(2);
    }
  };

  if (options.noDashboard) {
    // v1.1.5 (Finding AA): operator opted out of the per-call dashboard
    // spawn. The agent record is already persisted above; a later
    // `sanctuary dashboard` (or another wrap) will pick it up. Skip the
    // dashboard server, the v1.1 binding, the runtime advertisement,
    // and the auto-open browser path; print a concise success line that
    // points operators at the persistent dashboard.

    // v1.3.0 (WWWWW, NNN regression): --no-dashboard wraps previously
    // skipped identity bootstrap because the creation lived after the
    // dashboard startup path. Derive the master key and create a default
    // identity so CLI surfaces (exit export, identity show) work
    // immediately after wrap without launching the dashboard first.
    if (passphraseValue !== undefined) {
      try {
        const ndStorage = new FilesystemStorage(`${storagePath}/state`);
        let existingParams: KeyDerivationParams | undefined;
        try {
          const raw = await ndStorage.read("_meta", "key-params");
          if (raw) {
            existingParams = JSON.parse(bytesToString(raw)) as KeyDerivationParams;
          }
        } catch {
          // No existing params; deriveMasterKey will pick fresh params.
        }
        const ndDerived = await deriveMasterKey(passphraseValue, existingParams);
        if (!existingParams) {
          await ndStorage.write(
            "_meta",
            "key-params",
            stringToBytes(JSON.stringify(ndDerived.params)),
          );
        }
        const ndAuditLog = new AuditLog(ndStorage, ndDerived.key);
        // Best-effort: daemon failure does not block identity bootstrap.
        // See parallel block below (line ~939) for full rationale.
        try {
          await startCastleWallForWrap(ndAuditLog, ndDerived.key);
        } catch (err) {
          warnCastleWallDaemonNotStarted(err);
        }

        // PR-2: setup opt-in for transparency anchoring (default OFF).
        // NOT best-effort: a failure here is caught by the loud check
        // before the success exit below.
        await enableAnchorTransparencyForWrap(ndStorage, ndDerived.key, ndAuditLog);

        const { IdentityManager } = await import("../l1-cognitive/tools.js");
        const { createIdentity } = await import("../core/identity.js");
        const { derivePurposeKey } = await import("../core/key-derivation.js");
        const identityMgr = new IdentityManager(ndStorage, ndDerived.key);
        const loadResult = await identityMgr.load();
        if (loadResult.loaded === 0) {
          const identityEncKey = derivePurposeKey(ndDerived.key, "identity-encryption");
          const { storedIdentity, publicIdentity } = createIdentity(
            "default",
            identityEncKey,
            "passphrase",
          );
          await identityMgr.save(storedIdentity);
          await ndAuditLog.append("l1", "identity_create", publicIdentity.identity_id, {
            label: "default",
            source: "wrap-auto",
          });
        }
        await ndAuditLog.flush();
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel.
        console.error(
          `  Note: default identity not created at wrap time ` +
            `(${(err as Error).message}).`,
        );
      }
    }

    failIfAnchorOptInDropped();
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

  // v1.2.1 (Finding III): track intelligence subsystem health for the
  // success banner. Updated below when the substrate selector loads.
  let intelligenceHealthy: boolean | undefined;
  let intelligenceError: string | undefined;
  let wrapAuditLog: AuditLog | undefined;

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
  // v1.2.1 (Finding NNN): create a default identity at wrap time so
  // `sanctuary exit export` works immediately. IdentityManager.load()
  // is called to check if an identity already exists before creating.
  // Reset-history continuity (v1.0.2 item a) is also not consumed here;
  // the next caller (MCP-server-boot or sanctuary dashboard standalone)
  // handles it on first fortress-unlock as before.
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
      wrapAuditLog = new AuditLog(v11Storage, derived.key);
      // Best-effort: a Castle Wall daemon startup failure (e.g. EACCES on
      // Linux when the fortress-scoped socket dir requires root, or any
      // platform where the pinned key is unavailable) does not fail wrap.
      // The agent harness still gets wrapped; the IPC daemon will surface
      // its absence at handshake time. This mirrors the surrounding
      // best-effort discipline for v1.1 dashboard wiring.
      try {
        await startCastleWallForWrap(wrapAuditLog, derived.key);
      } catch (err) {
        warnCastleWallDaemonNotStarted(err);
      }

      // PR-2: setup opt-in for transparency anchoring (default OFF).
      // NOT best-effort: if this throws, the outer catch prints the
      // error and the loud check below exits 2 rather than letting a
      // requested opt-in be silently dropped.
      await enableAnchorTransparencyForWrap(v11Storage, derived.key, wrapAuditLog);

      // v1.2.1 (Finding NNN): auto-create default identity at wrap time.
      try {
        const { IdentityManager } = await import("../l1-cognitive/tools.js");
        const { createIdentity } = await import("../core/identity.js");
        const { derivePurposeKey } = await import("../core/key-derivation.js");
        const identityMgr = new IdentityManager(v11Storage, derived.key);
        const loadResult = await identityMgr.load();
        if (loadResult.loaded === 0) {
          const identityEncKey = derivePurposeKey(derived.key, "identity-encryption");
          const { storedIdentity, publicIdentity } = createIdentity(
            "default",
            identityEncKey,
            "passphrase",
          );
          await identityMgr.save(storedIdentity);
          await wrapAuditLog.append("l1", "identity_create", publicIdentity.identity_id, {
            label: "default",
            source: "wrap-auto",
          });
        }
        dashboard.updateSources?.({
          auditLog: wrapAuditLog,
          identityManager: identityMgr,
        });
      } catch (err) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Note: default identity not created at wrap time ` +
            `(${(err as Error).message}).`,
        );
      }

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
        intelligenceHealthy = true;
      } catch (err) {
        intelligenceHealthy = false;
        intelligenceError = (err as Error).message;
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Note: v1.1 dashboard surfaces unavailable on wrap URL ` +
          `(${(err as Error).message}). ` +
          `Run \`sanctuary dashboard\` to reach them.`,
      );
    }
  }

  failIfAnchorOptInDropped();

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

  if (wrapAuditLog) {
    await wrapAuditLog.flush();
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
    intelligenceHealthy,
    intelligenceError,
  });
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
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
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
  const l2Status = info.intelligenceHealthy === false
    ? "L2 Degraded (intelligence disabled)"
    : "L2 Degraded (no TEE)";
  lines.push(`  ${b("Your agent is protected.")} L1 Full / ${l2Status} / L3 Full / L4 Full.`);
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`; // yellow
    lines.push("");
    lines.push(`  ${w("\u26A0")} L2 intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Concierge chat and substrate-driven explanations will not work until this is resolved.`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push("");
  return lines.join("\n");
}

function printWrapSuccess(info: WrapSuccessInfo): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(formatWrapSuccess(info));
}

interface WrapSuccessNoDashboardInfo {
  toolName: string;
  version: string;
  toolCount: number;
  serverCount: number;
  passphraseLocation: string;
  passphraseSource: string;
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
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
  const l2Status = info.intelligenceHealthy === false
    ? "L2 Degraded (intelligence disabled)"
    : "L2 Degraded (no TEE)";
  lines.push(
    `  ${b("Your agent is protected.")} L1 Full / ${l2Status} / L3 Full / L4 Full.`,
  );
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`;
    lines.push("");
    lines.push(`  ${w("\u26A0")} L2 intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push("");
  return lines.join("\n");
}

function printWrapSuccessNoDashboard(
  info: WrapSuccessNoDashboardInfo,
): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: No sanctuary entry in rewritten config.`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    const sanctuaryEntry = servers.sanctuary as Record<string, unknown>;
    if (!sanctuaryEntry.command || typeof sanctuaryEntry.command !== "string") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: Sanctuary entry has no command.`);
      await restoreFromBackup(configPath, backupPath);
      return false;
    }

    return true;
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
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
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  Original config restored from backup.`);
    console.error(`  Backup preserved at: ${backupPath}\n`);
  } catch (restoreErr) {
    console.error(
      `  CRITICAL: Could not restore backup from ${backupPath}`
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  Error: ${(restoreErr as Error).message}`);
    console.error(`  Manual recovery: copy ${backupPath} to ${configPath}\n`);
  }
}

// ── Unwrap ──────────────────────────────────────────────────────────

async function unwrap(dryRun: boolean): Promise<void> {
  // D4 P1-2: findLatestBackup validates wrap-meta `auxiliary` entries on
  // read and throws WrapMetaValidationError on a forged or corrupted list
  // (arbitrary backupPath/originalPath would turn the restore loop below
  // into an arbitrary-file write/delete primitive). Abort loudly with
  // nothing modified.
  let meta: Awaited<ReturnType<typeof findLatestBackup>>;
  try {
    meta = await findLatestBackup();
  } catch (err) {
    if (err instanceof WrapMetaValidationError) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary: Unwrap REFUSED`);
      console.error(`  ${err.message}`);
      console.error(
        `  Nothing was modified. Inspect the wrap metadata in your fortress` +
          `\n  backup directory before retrying.\n`
      );
      process.exit(1);
    }
    throw err;
  }
  if (!meta) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error("No Sanctuary wrap found to restore.");
    console.error("Run `sanctuary wrap --openclaw` first.");
    process.exit(1);
  }

  try {
    await access(meta.backupPath);
  } catch {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Backup file not found: ${meta.backupPath}`);
    process.exit(1);
  }

  // D4 P1-2 (validate before use) + P2-3 (no symlinked restore targets):
  // re-validate every auxiliary entry and refuse symlinked targets BEFORE
  // any restore runs, so a forged or symlinked entry aborts the whole
  // unwrap with nothing modified — including the primary config. Round-2
  // P1-A: the lstat loop below is a courtesy early refusal; the atomic
  // enforcement is the O_NOFOLLOW open inside restoreConfig itself.
  let auxiliary: ValidatedWrapMetaAuxiliaryFile[] = [];
  try {
    auxiliary = await validateWrapMetaAuxiliary(meta.auxiliary);
    for (const aux of auxiliary) {
      await refuseSymlinkTarget(aux.originalPath, "Restore target");
    }
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Unwrap REFUSED`);
    console.error(`  ${(err as Error).message}`);
    console.error(`  Nothing was modified.\n`);
    process.exit(1);
  }

  // D4 P2-2: --unwrap --dry-run reports what WOULD be restored/removed
  // and writes nothing. All checks above are read-only, so the dry run
  // surfaces the same refusals the real unwrap would.
  if (dryRun) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary: Unwrap (dry run)`);
    console.error(`  Would restore ${meta.originalPath} from ${meta.backupPath}`);
    for (const aux of auxiliary) {
      if (aux.backupPath) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Would restore ${aux.originalPath} from ${aux.backupPath}`);
      } else if (aux.alreadyAbsent) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Would skip ${aux.originalPath} (created by wrap; already absent)`
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Would remove ${aux.originalPath} (created by wrap; no pre-wrap version existed)`
        );
      }
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Dry run. No changes made.\n`);
    return;
  }

  await restoreConfig(meta.backupPath, meta.originalPath);
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary: Unwrapped`);
  console.error(`  Original config restored to: ${meta.originalPath}`);
  console.error(`  Backup preserved at: ${meta.backupPath}`);

  // D4 staging, Bug 2: restore auxiliary files the wrap touched (the
  // Hermes config.yaml surface). A null backupPath means wrap created the
  // file fresh; restoring the pre-wrap state removes it. Best-effort: the
  // primary config restore above already succeeded, so an auxiliary
  // failure reports loudly with the manual recovery path instead of
  // aborting the unwrap.
  for (const aux of auxiliary) {
    try {
      if (aux.backupPath) {
        // Round-2 P1-A/P2: restoreConfig writes the target O_NOFOLLOW
        // (atomic symlink refusal) and recreates a missing parent (0o700).
        await restoreConfig(aux.backupPath, aux.originalPath);
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Original config restored to: ${aux.originalPath}`);
        console.error(`  Backup preserved at: ${aux.backupPath}`);
      } else if (aux.alreadyAbsent) {
        // Round-2 P2: created-by-wrap file whose parent directory is gone —
        // the "absent" end-state already holds; informational no-op.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Skipped ${aux.originalPath} (created by wrap; already absent)`
        );
      } else {
        // Round-3 P1-A: refuse the unlink if a symlink was raced into the
        // parent dir after validate-time; unlink() does not follow a
        // symlinked leaf, so only the parent walk is needed.
        await unlinkSafeUnderRoot(aux.originalPath);
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Removed ${aux.originalPath} (created by wrap; no pre-wrap version existed)`
        );
      }
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  WARNING: could not restore ${aux.originalPath}: ${(err as Error).message}`
      );
      if (aux.backupPath) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Manual recovery: copy ${aux.backupPath} to ${aux.originalPath}`
        );
      }
    }
  }
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("");
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Operator-facing warning when the Castle Wall enforcement daemon fails to
 * start during `wrap`. Wrap is best-effort with respect to the daemon (a start
 * failure never blocks wrapping the agent), but a silent "Note:" let an
 * upgrade quietly leave a previously-armed host UNARMED. This makes the
 * not-armed state loud, and — on macOS, when the failure is the A2/B2
 * helper-signing default having no reachable signer — prints the exact
 * migration path (install the helper + point at the shim, or opt back into the
 * legacy local-signing key). See the A2/B2 re-drill verdict's migration caveat.
 */
function warnCastleWallDaemonNotStarted(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  const helperMigration =
    process.platform === "darwin" &&
    /helper signing is unavailable|signer helper is unreachable|without a signer/i.test(
      message,
    );
  const lines = [
    "",
    "  ====================================================================",
    "  WARNING: Castle Wall is NOT armed. Your agent is wrapped, but the",
    "  enforcement wall did not start, so outbound traffic is NOT filtered.",
    `  Reason: ${message}`,
  ];
  if (helperMigration) {
    lines.push(
      "",
      "  Castle Wall now signs through a root helper by default (A2/B2). To",
      "  arm the wall, do ONE of:",
      '    1. Install the Castle Wall app (one-time "Allow background item"',
      "       approval), then set SANCTUARY_CASTLE_SIGNER_CLIENT to its shim:",
      "       /Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client",
      "    2. To keep the legacy local-signing key, set SANCTUARY_CASTLE_LOCAL_SIGN=1",
      "  then re-run 'sanctuary wrap'.",
    );
  } else {
    lines.push(
      "  Wrap continues; the IPC daemon will surface its absence at handshake.",
    );
  }
  lines.push(
    "  ====================================================================",
    "",
  );
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(lines.join("\n"));
}

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

/** Known flags that take a value argument (the next argv element). */
const WRAP_VALUE_FLAGS = new Set([
  "--wrap",
  "--passphrase",
  "--port",
  "--dashboard-port",
  "--fortress",
  "--dev-dist",
  "--write-passphrase-backup",
]);

/** Known boolean flags. */
const WRAP_BOOLEAN_FLAGS = new Set([
  "--openclaw",
  "--hermes",
  "--claude-code",
  "--cursor",
  "--cline",
  "--unwrap",
  "--dry-run",
  "--no-open",
  "--no-dashboard",
  "--anchor-transparency",
  "--help",
  "-h",
]);

/** Known harness flags (for "did you mean" suggestions). */
const WRAP_HARNESS_FLAGS = ["--openclaw", "--hermes", "--claude-code", "--cursor", "--cline"];

function parseDashboardPortFlag(flag: string, value: string | undefined): number {
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`${flag} requires a port value (1024-65535).`);
  }
  if (!/^\d+$/.test(value)) {
    throw new Error(`${flag} must be a positive integer from 1024 to 65535.`);
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`${flag} must be a positive integer from 1024 to 65535.`);
  }
  return port;
}

export function parseWrapArgs(argv: string[]): WrapOptions {
  const options: WrapOptions = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;

    // Reject unknown positional arguments
    if (!arg.startsWith("-")) {
      const suggestion = WRAP_HARNESS_FLAGS.find(
        (f) => f.replace(/^--/, "") === arg,
      );
      const hint = suggestion ? ` Did you mean ${suggestion}?` : "";
      throw new Error(
        `Unrecognized argument '${arg}'.${hint} Run 'sanctuary wrap --help' for valid flags.`,
      );
    }

    // Reject unknown flags
    if (!WRAP_BOOLEAN_FLAGS.has(arg) && !WRAP_VALUE_FLAGS.has(arg)) {
      throw new Error(
        `Unrecognized flag '${arg}'. Run 'sanctuary wrap --help' for valid flags.`,
      );
    }

    switch (arg) {
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
      case "--dashboard-port":
        options.port = parseDashboardPortFlag(arg, argv[++i]);
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
      case "--anchor-transparency":
        options.anchorTransparency = true;
        break;
      case "--fortress":
        options.fortress = argv[++i];
        break;
      case "--dev-dist":
        options.devDist = argv[++i];
        break;
      case "--write-passphrase-backup":
        options.writePassphraseBackup = argv[++i];
        break;
      case "--help":
      case "-h":
        printWrapHelp();
        process.exit(0);
    }
  }

  return options;
}

function printWrapHelp(): void {
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
    --anchor-transparency
                       Opt in to transparency anchoring at setup (OFF by
                       default). Publishes a salted hash commitment of each
                       enforcement checkpoint to the public Sigstore Rekor
                       transparency log so the enforcement history becomes
                       fork-evident. Only the salted hash, a signature from
                       a dedicated derived key, and that key's public half
                       ever leave the machine; never checkpoint contents,
                       counts, policy data, or fortress identifiers.
                       Equivalent to running
                       \`sanctuary transparency anchor enable\` later.
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
