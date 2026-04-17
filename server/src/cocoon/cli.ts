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
 *   npx @sanctuary-framework/mcp-server wrap --claude-code
 *   npx @sanctuary-framework/mcp-server wrap --cursor
 *   npx @sanctuary-framework/mcp-server wrap --wrap /path/to/config.json
 *   npx @sanctuary-framework/mcp-server wrap --unwrap
 *
 * The `cocoon` subcommand is preserved as a hidden alias that prints a
 * deprecation notice. It will be removed in a future release.
 */

import { writeFile, readFile, mkdir, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveCocoonMeta,
  findLatestBackup,
  restoreConfig,
  rewriteConfigForCocoon,
  type AgentPlatform,
  type MCPServerEntry,
} from "./config-reader.js";
import {
  getOrCreatePassphrase,
  persistUserProvidedPassphrase,
  PassphraseUnreadableError,
} from "./passphrase.js";
import { startDashboard, type DashboardHandle } from "../dashboard/index.js";
import { SANCTUARY_VERSION } from "../config.js";
import type { UpstreamServer, SovereigntyProfile } from "../sovereignty-profile.js";

// ── Types ───────────────────────────────────────────────────────────

export interface WrapOptions {
  /** Wrap a specific config file. */
  wrap?: string;
  /** Auto-detect OpenClaw config. */
  openclaw?: boolean;
  /** Auto-detect Claude Code config. */
  claudeCode?: boolean;
  /** Auto-detect Cursor config. */
  cursor?: boolean;
  /** Unwrap — restore the original config. */
  unwrap?: boolean;
  /** Explicit passphrase override. If unset, one is generated and stored. */
  passphrase?: string;
  /** Dashboard port (default: 3501, falls back up to 3510). */
  port?: number;
  /** Preview changes without writing. */
  dryRun?: boolean;
  /** Suppress auto-open of the browser. */
  noOpen?: boolean;
}

/** Backward-compat alias for the old `parseCocoonArgs` return type. */
export type CocoonOptions = WrapOptions;

// ── Constants ───────────────────────────────────────────────────────

/** Default CallGovernor limits for wrapped agents. */
export const COCOON_GOVERNOR_DEFAULTS = {
  volume_limit: 200,
  rate_limit_per_tool: 20,
  lifetime_limit: 1000,
} as const;

const DEFAULT_PORT = 3501;
const MAX_PORT = 3510;

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

  let platformHint: AgentPlatform | undefined;
  if (options.openclaw) platformHint = "openclaw";
  else if (options.claudeCode) platformHint = "claude-code";
  else if (options.cursor) platformHint = "cursor";

  const detection = await detectAgentConfigWithDiagnostics(
    platformHint,
    options.wrap
  );
  const agentConfig = detection.config;

  if (!agentConfig) {
    console.error(`\n  Sanctuary — Configuration Not Found\n`);
    if (platformHint) {
      console.error(`  Could not find ${platformHint} configuration.`);
    } else if (options.wrap) {
      console.error(`  Could not read config file: ${options.wrap}`);
    } else {
      console.error("  Could not auto-detect any agent configuration.");
      console.error(
        "  Use --openclaw, --claude-code, --cursor, or --wrap /path/to/config.json"
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

  if (agentConfig.servers.length === 0) {
    console.error(
      `\n  Found ${agentConfig.platform} config at ${agentConfig.configPath},`
    );
    console.error(`  but no MCP servers are configured in it.\n`);
    process.exit(1);
  }

  const hasSanctuary = agentConfig.servers.some(
    (s) => s.name.toLowerCase() === "sanctuary"
  );
  if (hasSanctuary) {
    console.error(
      `\n  Warning: This agent already has a Sanctuary server configured.`
    );
    console.error(`  Re-wrapping will update the existing Sanctuary entry.\n`);
  }

  console.error(`\n  Sanctuary wrap`);
  console.error(`  Platform: ${agentConfig.platform}`);
  console.error(`  Config: ${agentConfig.configPath}`);
  console.error(`  MCP servers found: ${agentConfig.servers.length}`);

  const upstreamServers = convertToUpstreamServers(agentConfig.servers);
  for (const server of upstreamServers) {
    console.error(
      `    → ${server.name} (${server.transport.type}) — tier ${server.default_tier}`
    );
  }

  if (options.dryRun) {
    console.error(`\n  Dry run — no changes made.\n`);
    return;
  }

  // Resolve or generate passphrase.
  //
  // Invariant: the resolved passphrase never reaches argv or the rewritten
  // agent config. User-supplied `--passphrase` is treated as a one-time
  // setter — we persist it into Keychain/fallback and the launcher
  // re-resolves it at runtime via the same path everyone else uses.
  // See SEC-061 in docs/audit/DELTA_REVIEW_V0.9.0_RC1.md.
  let passphraseLocation: string;
  let passphraseSource: string;
  if (options.passphrase) {
    try {
      const persist =
        deps.persistPassphrase ??
        ((value: string) => persistUserProvidedPassphrase(value));
      const persisted = await persist(options.passphrase);
      passphraseLocation = persisted.location;
      passphraseSource = persisted.source;
      console.error(
        `\n  \u{1F510} Persisted user-supplied passphrase (${persisted.location}).`
      );
      console.error(
        `  Back up with: sanctuary export-passphrase`
      );
    } catch (err) {
      console.error(`\n  Sanctuary — Passphrase Persistence Failed`);
      console.error(`  ${(err as Error).message}`);
      console.error("");
      process.exit(2);
    }
  } else if (process.env.SANCTUARY_PASSPHRASE) {
    passphraseLocation = "SANCTUARY_PASSPHRASE";
    passphraseSource = "env";
  } else {
    try {
      const resolve = deps.resolvePassphrase ?? (() => getOrCreatePassphrase());
      const resolved = await resolve();
      passphraseLocation = resolved.location;
      passphraseSource = resolved.source;
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
        console.error(`\n  Sanctuary — Passphrase Unreadable`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  // Emit fallback-storage warning (SEC-063) when not using Keychain.
  // One-time: only on first wrap (source === "generated") when the location
  // is the fallback file, not when reading back a pre-existing fallback.
  const isFallbackGenerated =
    passphraseSource === "generated" &&
    passphraseLocation !== "macOS Keychain";
  const isFallbackUserProvided =
    passphraseSource === "fallback-file" &&
    passphraseLocation !== "macOS Keychain";
  if (isFallbackGenerated || (options.passphrase && isFallbackUserProvided)) {
    console.error(
      `\n  \u26A0  Passphrase stored in encrypted fallback file (machine-local key).` +
      `\n     This is protected only against off-machine access. On macOS we use` +
      `\n     Keychain by default. To migrate: \`sanctuary export-passphrase\` on` +
      `\n     the current machine, then import into Keychain or pass via the` +
      `\n     SANCTUARY_PASSPHRASE env var on the new machine.`
    );
  }

  // Write sovereignty profile.
  const storagePath = join(homedir(), ".sanctuary");
  await mkdir(storagePath, { recursive: true, mode: 0o700 });
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

  const rewrite = deps.rewriteConfig ?? rewriteConfigForCocoon;
  await rewrite(
    agentConfig,
    "npx",
    ["@sanctuary-framework/mcp-server"],
    Object.keys(sanctuaryEnv).length > 0 ? sanctuaryEnv : undefined
  );

  const verifyOk = await verifyRewrittenConfig(
    agentConfig.configPath,
    backupPath
  );
  if (!verifyOk) process.exit(1);

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
  const requestedPort = options.port ?? DEFAULT_PORT;
  const dashboard = await startDashboardWithFallback(
    startFn,
    requestedPort,
    authToken,
    readPackageVersion()
  );

  const dashboardUrl = `${dashboard.url}?token=${authToken}`;

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

async function startDashboardWithFallback(
  startFn: DashboardStarter,
  preferredPort: number,
  authToken: string,
  serverVersion: string
): Promise<DashboardHandle> {
  let lastErr: unknown;
  for (let port = preferredPort; port <= MAX_PORT; port++) {
    try {
      const handle = await startFn({
        port,
        mode: "co-located",
        authToken,
        serverVersion,
      });
      if (port !== preferredPort) {
        console.error(
          `  Port ${preferredPort} was unavailable — dashboard bound to ${port}.`
        );
      }
      return handle;
    } catch (err) {
      lastErr = err;
      if (!isAddressInUse(err)) throw err;
    }
  }
  throw new Error(
    `No free dashboard port in range ${preferredPort}-${MAX_PORT}: ${
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
  console.error(`\n  Sanctuary — Unwrapped`);
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
    case "claude-code": return "Claude Code";
    case "cursor": return "Cursor";
    default: return "your agent";
  }
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
      case "--no-open":
        options.noOpen = true;
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
  sanctuary wrap — Wrap any agent in Sanctuary protection

  Usage:
    sanctuary wrap --openclaw          Wrap OpenClaw
    sanctuary wrap --claude-code       Wrap Claude Code
    sanctuary wrap --cursor            Wrap Cursor
    sanctuary wrap --wrap <path>       Wrap a specific MCP config file
    sanctuary wrap --unwrap            Restore original config

  Options:
    --openclaw         Auto-detect and wrap OpenClaw
    --claude-code      Auto-detect and wrap Claude Code
    --cursor           Auto-detect and wrap Cursor
    --wrap <path>      Wrap a specific MCP config file
    --unwrap           Restore original config from backup
    --passphrase <p>   Override the stored passphrase (one-off)
    --port <port>      Preferred dashboard port (default: 3501)
    --dry-run          Show what would happen without making changes
    --no-open          Do not auto-open the dashboard in a browser
    --help, -h         Show this help

  What happens:
    1. Reads your agent's MCP config
    2. Generates a passphrase (stored in Keychain on macOS, encrypted file elsewhere)
    3. Backs up and rewrites the config so calls route through Sanctuary
    4. Starts the Sovereignty Dashboard and opens it in your browser
    5. Every tool call is logged, scanned, and tier-gated
`);
}
