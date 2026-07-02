#!/usr/bin/env node
/**
 * Sanctuary wrap - CLI Entry Point
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
 *   npx @sanctuary-framework/mcp-server wrap --mastra
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
import { platform, homedir } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { get as httpsGet } from "node:https";
import { get as httpGet } from "node:http";
import {
  detectAgentConfigWithDiagnostics,
  backupConfig,
  saveWrapMeta,
  hasExistingWrapMeta,
  findLatestBackup,
  findNewerBackup,
  removeWrapMeta,
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
  PassphraseKeyringUnreachableError,
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
import { CustodyUnlockError } from "../core/master-custody.js";
import {
  establishWrapCustody,
  type WrapCustodyResult,
} from "./custody-flow.js";
import { AuditLog } from "../operational/audit-log.js";
import { SubstrateSelector } from "../intelligence/selector.js";
import { installConsentGatedRedactor } from "../intelligence/privacy-tier2-redactor.js";
import { SANCTUARY_VERSION } from "../config.js";
import { recordWrappedHarnessRegistration } from "../workload-lifecycle/index.js";
import {
  formatFortressPathWritableError,
  preflightFortressPathWritable,
  resolveStoragePath,
  resolveDashboardPort,
} from "../paths.js";
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
  /** Auto-detect Mastra MCP config. */
  mastra?: boolean;
  /** Unwrap - restore the original config. */
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
  /**
   * Persist the plaintext-remote dashboard opt-in into the wrapped harness
   * environment. The approval channel still refuses by default unless this
   * reaches the later MCP boot path.
   */
  allowPlaintextRemote?: boolean;
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
   * config entry at a local Sanctuary build instead of the
   * version-pinned npx registry entry. Without this, an unpublished
   * branch (e.g. an in-flight PR) gets shadowed by the npm-resolved
   * version because npx pulls from the registry, not from the local
   * checkout.
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
 * into ~/.claude.json - every harness restart fell back to the default
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
  if (options.allowPlaintextRemote) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE = "true";
  } else if (process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE) {
    sanctuaryEnv.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE =
      process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE;
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
 *
 * Published-version form (v1.6.1 install-path hardening, F2): the entry
 * is PINNED to the version of the server that performed the wrap and
 * names the `sanctuary` bin explicitly via `-p <pkg>@<version> sanctuary`.
 * Two failure modes of the previous bare
 * `npx @sanctuary-framework/mcp-server` form drove this:
 * 1. npm's multi-bin resolution could not pick an executable for the
 *    bare package name (dead at spawn on npm >= 7 for v1.4.0..v1.6.0).
 * 2. An unpinned entry re-resolves to `latest` at every cold npx run,
 *    so what the operator approved at wrap time is silently swapped
 *    for whatever the registry serves later (no version custody).
 * `-y` keeps the non-interactive MCP spawn from wedging on the npx
 * install prompt. Upgrades re-run `sanctuary protect`, which rewrites
 * the pin to the new version.
 */
function resolveSanctuaryCommand(options: WrapOptions): {
  command: string;
  args: string[];
} {
  const useDevDist = options.devDist !== undefined;
  return {
    command: useDevDist ? "node" : "npx",
    args: useDevDist
      ? [options.devDist!]
      : [
          "-y",
          "-p",
          `@sanctuary-framework/mcp-server@${SANCTUARY_VERSION}`,
          "sanctuary",
        ],
  };
}

/**
 * Validate a `--dev-dist <path>` before it is written into the harness config
 * (Finding 4, 2026-06-25). The dogfood path registers `node <path>` as the
 * `sanctuary` MCP command; a typo'd or non-existent path produces a wrap that
 * "verifies" (the JSON check only requires a non-empty command string) but
 * whose harness entry silently fails at MCP spawn time, with no wrap-time
 * signal. Fail loudly at wrap time instead: the file must exist and end in
 * `.js`. Throws {@link DevDistInvalidError} with an actionable message.
 */
export class DevDistInvalidError extends Error {
  readonly devDist: string;
  constructor(devDist: string, reason: string) {
    super(
      `--dev-dist path is invalid: ${reason}\n` +
        `  path: ${devDist}\n` +
        `  --dev-dist must point at a built Sanctuary entrypoint .js file ` +
        `(e.g. dist/index.js). It is registered as 'node <path>' for the ` +
        `sanctuary MCP entry; a missing path would fail silently at spawn time.`
    );
    this.name = "DevDistInvalidError";
    this.devDist = devDist;
  }
}

export async function validateDevDist(devDist: string): Promise<void> {
  const resolved = resolvePath(devDist);
  if (!resolved.endsWith(".js")) {
    throw new DevDistInvalidError(devDist, "path does not end in '.js'");
  }
  try {
    await access(resolved);
  } catch {
    throw new DevDistInvalidError(devDist, "no such file");
  }
  // Reject a directory masquerading as the entrypoint.
  try {
    const st = await lstat(resolved);
    if (!st.isFile()) {
      throw new DevDistInvalidError(devDist, "path is not a regular file");
    }
  } catch (err) {
    if (err instanceof DevDistInvalidError) throw err;
    throw new DevDistInvalidError(devDist, "could not stat the path");
  }
}

/**
 * Outcome of the wrap-time pinned-version resolvability probe (2026-07-02
 * install-path hardening).
 *
 *   - "resolvable":  the registry affirmatively serves the pinned version.
 *   - "unpublished": the registry (as resolved at wrap time) is reachable
 *                    and affirmatively does NOT have the pinned version -
 *                    the MCP entry this wrap writes would be dead at spawn
 *                    time, unless the harness's own spawn directory routes
 *                    the scope to a different registry this probe cannot
 *                    see. Advisory, never a hard block.
 *   - "unreachable": the registry could not be consulted (offline, DNS,
 *                    timeout), or resolution is indirected through config
 *                    the probe cannot faithfully reproduce (a non-default
 *                    registry that may hide packages from unauthenticated
 *                    requests, or proxy-only egress) and the answer was
 *                    not an affirmative 200. Honest-unknown, never treated
 *                    as either of the affirmative outcomes.
 *   - "skipped":     the probe was disabled (SANCTUARY_NO_UPDATE_CHECK=1,
 *                    the documented zero-outbound knob - this probe is the
 *                    same registry-metadata class of egress as the update
 *                    check, so the one knob silences both).
 */
export type PinnedVersionResolvability =
  | "resolvable"
  | "unpublished"
  | "unreachable"
  | "skipped";

/** The registry `npx` consults when nothing overrides it. */
const DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org";

/** Trim + validate an npm registry URL; strip trailing slashes. */
function normalizeRegistryUrl(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (!trimmed.startsWith("https://") && !trimmed.startsWith("http://")) {
    return null;
  }
  return trimmed.replace(/\/+$/, "");
}

/** Lenient `.npmrc` scan for the two registry keys the probe cares about. */
async function readNpmrcRegistryKeys(
  npmrcPath: string,
): Promise<{ scoped: string | null; registry: string | null }> {
  let raw: string;
  try {
    raw = await readFile(npmrcPath, "utf-8");
  } catch {
    return { scoped: null, registry: null };
  }
  let scoped: string | null = null;
  let registry: string | null = null;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    // Last occurrence wins, matching npm's ini semantics: a first-wins scan
    // here read the OLD value of a key that tooling later re-appended
    // (`registry=` twice in one file), probed the wrong registry, and could
    // re-create the false-affirmative "unpublished" dead-pin warning.
    if (key === "@sanctuary-framework:registry") {
      scoped = value;
    } else if (key === "registry") {
      registry = value;
    }
  }
  return { scoped, registry };
}

/**
 * Best-effort, WRAP-TIME approximation of the npm registry the
 * wrap-written `npx` entry will consult at spawn time (2026-07-02 fix
 * round). The probe previously hard-coded the public registry, so in a
 * private-mirror / corporate environment (registry override in `.npmrc`
 * or the npm config env) it asked the WRONG registry and rendered a false
 * dead-pin warning for an entry npx would start fine.
 *
 * Honesty limit: this resolves from the wrap process's OWN env and cwd.
 * The harness spawns the MCP entry later, possibly from a different
 * working directory whose project `.npmrc` this probe cannot see (e.g. a
 * scope override pointing at a private mirror). A direct-default result
 * here therefore does NOT guarantee spawn-time resolution also hits the
 * default registry; callers must keep the resulting "unpublished" verdict
 * advisory, never a hard block.
 *
 * Mirrors npm's per-key precedence approximately: the package-scope key
 * (`@sanctuary-framework:registry`) beats the plain `registry` key, and
 * within each key the env override beats the project `.npmrc` beats the
 * user `~/.npmrc`; duplicate keys within one file are last-wins, matching
 * npm's ini semantics. Never throws; a winning override this probe cannot
 * interpret (npm env-var expansion like `registry=${NPM_MIRROR}`, or a
 * non-http(s) value) falls back to the public default marked `indirect`,
 * so a 404 stays honest-unknown instead of the affirmative "unpublished".
 *
 * `indirect` is true when resolution goes through machinery this bare
 * node:http(s) probe cannot faithfully reproduce - a non-default registry
 * (which may require auth npx has and the probe deliberately never sends)
 * or proxy egress (npx honors HTTPS_PROXY/HTTP_PROXY; node:https does not).
 * The caller then treats a 404 as honest-unknown instead of affirmative.
 *
 * `seams` (env/cwd/home) exist for tests; production callers pass nothing.
 */
export async function resolveNpmRegistryForProbe(
  seams: { env?: NodeJS.ProcessEnv; cwd?: string; home?: string } = {},
): Promise<{ base: string; indirect: boolean }> {
  const env = seams.env ?? process.env;
  // Guard the cwd lookup: process.cwd() THROWS (uv_cwd ENOENT) when the
  // wrap runs from a deleted directory (removed worktree, cleaned tmp
  // dir). This probe's contract is never-throws / never-blocks-the-wrap,
  // so an unresolvable cwd degrades to user-level config only (same
  // semantics as an absent project .npmrc) instead of crashing the wrap.
  let cwd: string | undefined = seams.cwd;
  if (cwd === undefined) {
    try {
      cwd = process.cwd();
    } catch {
      cwd = undefined;
    }
  }
  const files = [
    cwd !== undefined
      ? await readNpmrcRegistryKeys(join(cwd, ".npmrc"))
      : { scoped: null as string | null, registry: null as string | null },
    await readNpmrcRegistryKeys(join(seams.home ?? homedir(), ".npmrc")),
  ];
  // Per-key precedence: first PRESENT raw value wins (env beats project
  // .npmrc beats user ~/.npmrc), and only then is the winner normalized.
  // Normalizing each candidate and taking the first that PARSED silently
  // skipped a higher-precedence override this probe cannot faithfully
  // reproduce (npm env-var expansion like `registry=${NPM_MIRROR}`) and
  // fell back to default+direct, where a 404 reads as the affirmative
  // "unpublished". A present-but-unnormalizable winner now resolves to the
  // default registry marked `indirect`, so a 404 stays honest-unknown.
  const firstPresent = (
    ...candidates: Array<string | null | undefined>
  ): string | null => {
    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate.trim() !== "") {
        return candidate;
      }
    }
    return null;
  };
  const scopedRaw = firstPresent(
    env["npm_config_@sanctuary-framework:registry"],
    files[0].scoped,
    files[1].scoped,
  );
  const plainRaw = firstPresent(
    env.npm_config_registry,
    env.NPM_CONFIG_REGISTRY,
    files[0].registry,
    files[1].registry,
  );
  const winningRaw = scopedRaw ?? plainRaw;
  const normalized = normalizeRegistryUrl(winningRaw ?? undefined);
  const unresolvableOverride = winningRaw !== null && normalized === null;
  const base = normalized ?? DEFAULT_NPM_REGISTRY;
  const proxied = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
  ].some((key) => {
    const value = env[key];
    return typeof value === "string" && value.trim() !== "";
  });
  return {
    base,
    indirect:
      proxied || unresolvableOverride || base !== DEFAULT_NPM_REGISTRY,
  };
}

/**
 * Wrap-time check that the version-pinned MCP entry
 * (`-p @sanctuary-framework/mcp-server@<version> sanctuary`) actually
 * resolves on the npm registry (2026-07-02 hardening): an unpublished pin
 * - e.g. a wrap run from a not-yet-published release build without
 * `--dev-dist` - writes a dead MCP entry behind a success banner, and the
 * harness only discovers it at spawn time.
 *
 * Fail HONEST, not fail-open and not fail-closed: the caller never blocks
 * the wrap on this probe (an unreachable registry must not take wrap
 * availability down), but it downgrades the success claim with an explicit
 * warning on "unpublished" and an honest could-not-verify note on
 * "unreachable". Never throws.
 *
 * 2026-07-02 fix round (registry-config honesty): the probe consults the
 * registry npx will most likely use, resolved at WRAP time
 * (resolveNpmRegistryForProbe: npm config env, project/user `.npmrc`;
 * the harness's spawn-time cwd can differ, so even an affirmative
 * "unpublished" stays advisory), and when resolution is `indirect` (non-default
 * registry, which may hide packages from this deliberately unauthenticated
 * probe, or proxy-only egress the bare GET does not traverse) a 404 is NOT
 * affirmative: it maps to "unreachable" (honest could-not-verify) instead
 * of the loud "unpublished" dead-pin warning. Only the public default
 * registry, consulted directly, can affirm "unpublished". No credential is
 * ever attached to the probe request.
 *
 * `registryBaseUrl` / `timeoutMs` are test seams; production callers use
 * the defaults. An explicit `registryBaseUrl` is treated as authoritative
 * (404 stays affirmative), preserving the seam's stub-registry semantics.
 */
export async function checkPinnedVersionResolvable(
  version: string,
  opts: { registryBaseUrl?: string; timeoutMs?: number } = {},
): Promise<PinnedVersionResolvability> {
  if (process.env.SANCTUARY_NO_UPDATE_CHECK === "1") return "skipped";
  let base: string;
  let notFoundIsAffirmative: boolean;
  if (opts.registryBaseUrl !== undefined) {
    base = opts.registryBaseUrl;
    notFoundIsAffirmative = true;
  } else {
    const resolved = await resolveNpmRegistryForProbe();
    base = resolved.base;
    notFoundIsAffirmative = !resolved.indirect;
  }
  const timeoutMs = opts.timeoutMs ?? 3000;
  const url = `${base}/@sanctuary-framework/mcp-server/${encodeURIComponent(version)}`;
  const getFn = base.startsWith("http://") ? httpGet : httpsGet;
  return new Promise((resolve) => {
    try {
      const req = getFn(
        url,
        { headers: { Accept: "application/json" }, timeout: timeoutMs },
        (res) => {
          // Only the response STATUS is consulted; drain the body.
          res.resume();
          if (res.statusCode === 200) resolve("resolvable");
          else if (res.statusCode === 404)
            resolve(notFoundIsAffirmative ? "unpublished" : "unreachable");
          else resolve("unreachable");
        },
      );
      req.on("error", () => resolve("unreachable"));
      req.on("timeout", () => {
        req.destroy();
        resolve("unreachable");
      });
    } catch {
      resolve("unreachable");
    }
  });
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
 * Read-only existence probe. Returns true if `path` is reachable, false on
 * any error (absent, permission, etc.). Used to decide first-run messaging;
 * never mutates the filesystem.
 */
async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
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
    // File absent - the plan would create it.
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
    return; // Absent - nothing to refuse.
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
 * `preferredPort`. v0.10.0 hardcoded an absolute `MAX_PORT = 3510` cap -
 * starting above it (the documented tenant ports 3511/3512) produced an
 * empty range and the error "No free dashboard port in range 3511-3510".
 * Making the window relative to `preferredPort` fixes both the multi-tenant
 * case and the nonsensical error message.
 *
 * Exported for tests; not public API.
 */
export const PORT_FALLBACK_ATTEMPTS = 20;

// ── Dashboard integration ───────────────────────────────────────────

/** Minimal starter signature - matches `startDashboard` from ../dashboard. */
export type DashboardStarter = (opts: {
  port: number;
  host?: string;
  mode: "co-located" | "standalone";
  authToken: string;
  serverVersion: string;
}) => Promise<DashboardHandle>;

// ── Main: wrap ──────────────────────────────────────────────────────

/**
 * F4 (v1.6.1 first-run honesty): the affirmative "Your agent is protected. /
 * Castle Wall Full" hero is reserved for OBSERVED enforcement, judged by the
 * SAME adjudicated-flow-evidence standard the dashboard uses (feature-health
 * panel: only fresh, provenance- and producer-signature-gated
 * egress_allowed / egress_blocked / operator_decision evidence arms the
 * wall; daemon presence, heartbeats, and policy loads never do). A started
 * userspace daemon proves nothing about the system extension actually
 * filtering traffic; on a sysext-less Mac the daemon starts and filters
 * nothing. Fail-closed: any probe failure reads as not-observed.
 *
 * Known bounded staleness (accepted tradeoff, harden round): the panel's
 * evidence-freshness window is DEFAULT_ENFORCEMENT_FRESHNESS_MS (10
 * minutes) - the SAME standard the dashboard applies - so adjudicated-flow
 * evidence written by a PRIOR daemon/extension instance inside that window
 * still reads "active". An operator who tears enforcement down and re-runs
 * wrap within minutes can therefore see the one-shot protected banner off
 * the dead instance's evidence; the dashboard self-corrects when the
 * window expires, this banner does not. A stricter banner-only window
 * would diverge from the dashboard standard and false-negative on
 * genuinely-armed hosts whose most recent adjudicated flow is minutes old.
 *
 * Exported (module-level, not a runWrap closure) so the fail-closed gating
 * is unit-testable against a real audit log without standing up the whole
 * wrap flow.
 */
export async function probeCastleWallEnforcementObserved(
  auditLog: AuditLog,
  storagePath: string,
): Promise<boolean> {
  try {
    const { buildFeatureHealthPanel } = await import(
      "../principal-policy/feature-health.js"
    );
    const { loadFortressProducerKey } = await import(
      "../castle-wall/runtime/producer-signature.js"
    );
    const keyLoad = await loadFortressProducerKey(storagePath);
    // Eager-read scope: same one-verified-view discipline as the dashboard
    // callers of buildFeatureHealthPanel (H4 chokepoint).
    const panel = await auditLog.runEagerReads(() =>
      buildFeatureHealthPanel({
        auditLog,
        originMachine: fortressIdFromStoragePath(storagePath),
        pinnedProducerKeyB64url:
          keyLoad.status === "present" ? keyLoad.keyB64url : null,
        ...(keyLoad.status === "unreadable"
          ? { producerKeyExpectedButUnavailable: true }
          : {}),
      }),
    );
    const row = panel.rows.find(
      (r) => r.feature_id === "castle_wall_egress",
    );
    return row?.status === "active";
  } catch {
    return false;
  }
}

/**
 * THE banner honesty gate (F4, v1.6.1 first-run honesty), deduplicated
 * (2026-07-02 hardening: the same predicate was hand-computed in four
 * places, so a future edit could weaken one copy and desynchronize the
 * banners). The affirmative "Your agent is protected. / Castle Wall Full"
 * hero is earned ONLY when BOTH hold:
 *   - the Castle Wall daemon started during this wrap (`armed === true`), AND
 *   - real enforcement evidence was observed (`enforcementObserved === true`,
 *     per probeCastleWallEnforcementObserved's fail-closed standard).
 * Anything else (false, undefined, or an absent signal) reads NOT
 * confirmed. SECURITY/HONESTY INVARIANT: refactor-only; never weaken this
 * predicate (truth table pinned in test/wrap/wrap-surface-scoped-meta.test.ts;
 * the rendered-banner combinations are pinned in test/wrap/wrap-cli.test.ts).
 */
export function castleWallProtectionConfirmed(
  armed: boolean | undefined,
  enforcementObserved: boolean | undefined,
): boolean {
  return armed === true && enforcementObserved === true;
}

/**
 * The evidence-probe half of the banner honesty gate, shared by the
 * dashboard and --no-dashboard wrap paths (2026-07-02 dedupe): the F4
 * probe only runs when the daemon actually started this wrap AND an audit
 * log is available to read evidence from; every other state is fail-closed
 * false (never "observed").
 */
async function probeEnforcementObservedIfArmed(
  daemon: { stop(): Promise<void> } | undefined,
  auditLog: AuditLog | undefined,
  storagePath: string,
): Promise<boolean> {
  if (daemon === undefined || auditLog === undefined) return false;
  return probeCastleWallEnforcementObserved(auditLog, storagePath);
}

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
  /**
   * Override the wrap-meta persistence (for tests). Production callers
   * leave this undefined. Tests inject a throwing stub to pin the
   * meta-write failure paths: full rollback of every wrapped surface, and
   * the orphan-wrap guard's fallback meta write when a rollback restore
   * itself fails.
   */
  saveWrapMeta?: typeof saveWrapMeta;
  /**
   * Override the wrap-time pinned-version resolvability probe (for tests).
   * Production callers leave this undefined and get
   * `checkPinnedVersionResolvable` (a real registry-metadata HEAD-class
   * probe with a short timeout).
   */
  checkPinResolvability?: (
    version: string,
  ) => Promise<PinnedVersionResolvability>;
}

export async function runWrap(
  options: WrapOptions,
  deps: RunWrapDeps = {}
): Promise<void> {
  // D4 P2-2: --unwrap honors --dry-run too - pre-fix, the unwrap dispatch
  // sat above the dry-run gate, so `--unwrap --dry-run` restored backups
  // for real. The gate travels into unwrap() so it can report what WOULD
  // be restored/removed while writing nothing.
  if (options.unwrap) {
    await unwrap(options.dryRun === true);
    return;
  }

  // Finding 4 (2026-06-25): validate --dev-dist BEFORE anything is previewed or
  // written. The dry-run reporter previews the exact 'node <path>' harness
  // entry this would write, so a typo'd path must fail the dry run too, not
  // just the real wrap. Fail loudly here rather than at deferred MCP spawn time.
  if (options.devDist !== undefined) {
    try {
      await validateDevDist(options.devDist);
    } catch (err) {
      if (err instanceof DevDistInvalidError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary wrap: ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
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
  else if (options.mastra) platformHint = "mastra";

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
    // Honesty fix: for Hermes, the JSON surface detected above
    // (cli-config.json / config.json) is NOT where Hermes routes MCP
    // traffic. v0.16.0 reads ~/.hermes/config.yaml (see hermes-yaml.ts
    // header). A host that already has a populated config.yaml (e.g. a
    // `venice` entry) has a REAL Hermes MCP config, so claiming "No
    // existing hermes config found" is false and confusing on the exact
    // install target. When config.yaml exists we say so, name the
    // authoritative file, and note existing entries are preserved; the
    // per-entry preserved count is reported by the config.yaml routing
    // line (reportHermesYamlDryRun / the real injection below).
    const hermesYamlExists =
      platformHint === "hermes" && (await pathExists(hermesConfigYamlPath()));
    // D4 staging, Bug 1: --dry-run must guarantee ZERO filesystem writes.
    // This bootstrap ran BEFORE the dry-run gate below, so `protect
    // --hermes --dry-run` on a host with no config still created the file.
    // Report what would be bootstrapped and stop before any write path.
    if (canonicalPath && options.dryRun) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      if (hermesYamlExists) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Found your Hermes MCP config at ${hermesConfigYamlPath()}.` +
            `\n  Existing MCP servers there are preserved; Sanctuary routing will be added.`
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  No existing ${platformHint} config found.`);
      }
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
        // DEBT (hermes cli-config.json): this JSON file is a legacy compat
        // artifact. Hermes v0.16.0 does NOT consult it for MCP routing
        // (hermes-yaml.ts:4-10). It is kept because the generic wrap flow
        // keys off `agentConfig`, which detectAgentConfigWithDiagnostics
        // derives from the JSON surface, and unwrap unlinks it
        // (config-reader.ts). The authoritative surface is config.yaml.
        await writeFileSafeUnderRoot(canonicalPath, "{}", { mode: 0o600 });
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        if (hermesYamlExists) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `\n  Found your Hermes MCP config at ${hermesConfigYamlPath()}.` +
              `\n  Existing MCP servers there are preserved; Sanctuary routing will be added.`
          );
        } else {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(`\n  No existing ${platformHint} config found.`);
        }
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
        "  Use --openclaw, --hermes, --claude-code, --cursor, --cline, --mastra, or --wrap /path/to/config.json"
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
    if (agentConfig.platform === "hermes") {
      // F7 (v1.6.1 first-run honesty): the empty surface here is the legacy
      // cli-config.json artifact Hermes does NOT consult for MCP routing
      // (see the DEBT note in the bootstrap path above). Printing "installed
      // as the only MCP server" contradicted the config.yaml message printed
      // moments earlier ("existing MCP servers there are preserved"), so
      // point at the authoritative YAML surface instead.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Hermes routes MCP traffic through ${hermesConfigYamlPath()}.` +
          `\n  Sanctuary will be added there; existing MCP entries are preserved.\n`
      );
    } else {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Found ${agentConfig.platform} config at ${agentConfig.configPath} with no MCP servers yet.`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Sanctuary will be installed as the only MCP server.\n`
      );
    }
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
  const fortressWritable = await preflightFortressPathWritable(storagePath);
  if (!fortressWritable.ok) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary wrap: ${formatFortressPathWritableError(
        storagePath,
        fortressWritable,
      )}\n`,
    );
    process.exit(2);
  }

  // Resolve or generate passphrase.
  //
  // Invariant: the resolved passphrase never reaches argv or the rewritten
  // agent config. User-supplied `--passphrase` is treated as a one-time
  // setter - we persist it into Keychain/fallback and the launcher
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
      if (err instanceof PassphraseKeyringUnreachableError) {
        // Locked / unreachable OS keyring (error 36 / no D-Bus): fail closed
        // with the actionable unlock message. Sanctuary did NOT regenerate or
        // overwrite the stored passphrase, so retrying after unlocking the
        // keyring recovers cleanly.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary: Keyring Locked`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
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

  // Establish the fortress's unified custody (core/master-custody.ts) BEFORE
  // anything trust-bearing is written: one master, wrapped under the
  // resolved passphrase AND a minted recovery key (a wrap of that same
  // master - never a parallel one). Legacy fortresses migrate in place on
  // this unlock. Interactive runs force recovery-key capture + re-entry
  // verification; non-interactive runs are recorded as an audited headless
  // install. Fail closed on a credential that does not unlock (#5).
  let wrapCustody: WrapCustodyResult | undefined;
  if (passphraseValue !== undefined) {
    try {
      wrapCustody = await establishWrapCustody({
        storagePath,
        passphrase: passphraseValue,
        interactive: !options.noOpen && process.stdin.isTTY === true,
      });
    } catch (err) {
      if (err instanceof CustodyUnlockError) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`\n  Sanctuary wrap: Custody Establishment Failed`);
        console.error(`  ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  if (passphraseValue !== undefined) {
    // Auto-bootstrap pinned-key state for the IPC handshake. Failures here
    // warn but do not abort wrap: a missing pin surfaces cleanly at handshake
    // time (sysext refuses connection) rather than as a wrap-startup abort.
    // First-integration discipline: do no harm to the wrap critical path.
    try {
      const pinResult = await runProvisionPin([], {
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

  // The active Castle Wall bring-up: the macOS daemon (channel basis, default) OR
  // the opt-in Linux producer-signed activation (FIX 3). Both expose `stop()`; we
  // keep only the common shape so the cleanup is uniform.
  let castleWallDaemon: { stop(): Promise<void> } | undefined;
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
    const fortressId = fortressIdFromStoragePath(storagePath);
    const runtime = await import("../castle-wall/runtime/index.js");

    // FIX 3 (codex HIGH - wire the opt-in producer-signed close into production).
    // On Linux WITH the explicit opt-in flag, route through the producer-signed
    // activation gate (fail-closed, drill-pending, off by default). macOS - and
    // Linux WITHOUT the flag - keep the existing macOS daemon / channel basis.
    // The gate itself re-checks platform + opt-in, so this is belt-and-suspenders.
    if (
      process.platform === "linux" &&
      runtime.isLinuxProducerSignedActivationRequested()
    ) {
      const key = await runtime.buildLinuxIpcClientKeyMaterial({
        fortressPath: storagePath,
        fortressId,
        masterKey,
      });
      const outcome = await runtime.maybeActivateLinuxProducerSignedCastleWall({
        fortressId,
        fortressStoragePath: storagePath,
        key,
        auditSink: auditLog,
      });
      // The gate returns activated:false only when NOT opted in / not Linux -
      // neither is possible here (we just checked both), so an inactive outcome
      // means a logic drift; treat it as a no-op rather than a fake-arm.
      if (outcome.activated) {
        castleWallDaemon = outcome.activation;
        registerCastleWallCleanup();
      }
      return;
    }

    castleWallDaemon = await runtime.startMacOSCastleWallDaemon({
      fortressPath: storagePath,
      fortressId,
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

  // The args list is a constant - never inject `--passphrase`. The launcher
  // re-resolves the stored passphrase at runtime from Keychain / fallback
  // file / SANCTUARY_PASSPHRASE env var. See SEC-061. Env-block and
  // command/args construction live in buildSanctuaryEnv /
  // resolveSanctuaryCommand so the dry-run reporter previews the exact
  // entry the real run writes.
  const sanctuaryEnv = buildSanctuaryEnv(options);
  const { command: sanctuaryCommand, args: sanctuaryArgs } =
    resolveSanctuaryCommand(options);

  // 2026-07-02 hardening: the MCP entry written below is PINNED to
  // SANCTUARY_VERSION with no prior guarantee that version is actually
  // published - an unpublished pin yields a dead entry behind a success
  // banner. Probe the registry (short timeout) and downgrade the claim
  // honestly. NEVER blocks the wrap: "unpublished" and "unreachable" both
  // warn and continue (availability); `--dev-dist` entries point at a local
  // build validated above and involve no registry, so they skip the probe.
  // The outcome is ALSO threaded into the terminal-final success banner
  // (WrapSuccessInfo.pinnedVersionResolvability): the early warning here
  // scrolls above dozens of lines of subsequent flow output, and a success
  // surface that ends byte-identical to the resolvable case would re-create
  // the exact dead-entry-behind-a-success-banner defect the probe exists to
  // close.
  let pinResolvability: PinnedVersionResolvability | undefined;
  if (options.devDist === undefined) {
    const checkPin = deps.checkPinResolvability ?? checkPinnedVersionResolvable;
    pinResolvability = await checkPin(SANCTUARY_VERSION);
    if (pinResolvability === "unpublished") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  WARNING: the harness MCP entry this wrap writes is pinned to` +
          `\n  @sanctuary-framework/mcp-server@${SANCTUARY_VERSION}, but the npm registry` +
          `\n  (as resolved from this directory) does not have that version. Unless your` +
          `\n  agent's own project config routes the package scope to another registry,` +
          `\n  the MCP entry will fail to start until it is published. If you are running` +
          `\n  an unpublished build, re-run with --dev-dist <path-to-dist/cli.js> to point` +
          `\n  the entry at your local build instead.`
      );
    } else if (pinResolvability === "unreachable") {
      // "unreachable" also covers a REACHED custom registry whose
      // unauthenticated 404 the probe declines to treat as authoritative
      // (see checkPinnedVersionResolvable), so the stated cause must not
      // claim the registry could not be reached.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Note: could not confirm with the npm registry that the pinned version` +
          `\n  ${SANCTUARY_VERSION} resolves: the registry was unreachable (offline or` +
          `\n  blocked), or a custom registry gave an answer this unauthenticated probe` +
          `\n  cannot treat as authoritative. This wrap cannot verify the MCP entry it` +
          `\n  writes will start; if the agent fails to start, re-run 'sanctuary protect'` +
          `\n  once the registry confirms the version.`
      );
    }
  }

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
      // File absent - the plan creates it.
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

  // `configStillWrapped` carries the PRE-wrap detection result (did ANY
  // wrapped surface genuinely still carry the sanctuary entry? for Hermes
  // that includes the authoritative config.yaml, whose plan action
  // `replace-entry` means it did). Computed BEFORE the backup below so the
  // crash-window warning next to it can fire before the already-wrapped
  // content is captured as "the" backup; consumed by the deferred wrap-meta
  // write at the end of the wrap.
  const configStillWrapped =
    hasSanctuaryInRaw || hermesYaml?.plan.action === "replace-entry";

  // MED-2 (crash-window honesty): a config that already carries the
  // sanctuary entry while NO wrap-meta exists on disk is exactly what an
  // interrupted earlier wrap leaves behind (surfaces committed, then a
  // crash before the deferred meta write). In that state the pristine
  // pre-wrap config CANNOT be identified: the condition is
  // indistinguishable from an operator who authored the sanctuary entry by
  // hand, so no automatic recovery is attempted. The backup this wrap is
  // about to take captures the CURRENT (already-wrapped) contents, and a
  // later --unwrap restores THAT. Say so loudly, and point at the backup
  // directory where an older pristine snapshot from the interrupted wrap
  // may still exist (findNewerBackup's inverse breadcrumb: backup
  // filenames embed timestamps, so older snapshots sort below the fresh
  // one).
  //
  // 2026-07-02 hardening (MED-2 residual): the meta check is scoped to THIS
  // surface (resolve()d configPath). The previous tenant-global check let a
  // wrap-meta belonging to a DIFFERENT surface suppress the warning while
  // this surface was in exactly the crash-window state.
  //
  // Copy honesty (fifth round): hasExistingWrapMeta deliberately reads an
  // UNREADABLE pointer as false (failing toward this warning), so the text
  // says "no READABLE wrap metadata" - in the unreadable-pointer state the
  // meta likely IS on disk and the deferred meta write later in this same
  // run will refuse with "wrap metadata exists but could not be read";
  // the unhedged wording flatly contradicted that message.
  if (
    configStillWrapped &&
    !(await hasExistingWrapMeta(agentConfig.configPath))
  ) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  WARNING: this config already contains a Sanctuary entry, but no` +
        `\n  readable wrap metadata exists for it, so the pristine pre-wrap` +
        `\n  config could not be identified. The backup taken by THIS wrap` +
        `\n  captures the current (already-wrapped) contents, and --unwrap` +
        `\n  will restore that state. If this follows an interrupted wrap, check` +
        `\n  ${join(storagePath, "backup")}` +
        `\n  for an older pristine backup (timestamped config-backup-* files)` +
        `\n  before relying on --unwrap.`
    );
  }

  // Back up and rewrite agent config. For Hermes, config.yaml is backed up
  // alongside cli-config.json and recorded in the wrap meta so unwrap
  // restores both surfaces.
  const backupPath = await backupConfig(agentConfig.configPath);
  let hermesYamlBackupPath: string | null = null;
  if (hermesYaml?.existedBefore) {
    hermesYamlBackupPath = await backupConfig(hermesYaml.yamlPath);
  }

  // Harden round: the wrap-meta write is DEFERRED until every wrapped
  // surface below is verified-committed. Writing it here (as earlier
  // revisions did) violated the F6 invariant ("a wrap-meta exists" means
  // "currently wrapped"): every rollback path after the write left the
  // meta behind, and the next SUCCESSFUL wrap then preserved that stale
  // pristine pointer, so a later --unwrap restored pre-failed-wrap content
  // and silently discarded operator edits made between the failed wrap and
  // the retry (worse for the created-fresh Hermes config.yaml, where a
  // stale `backupPath: null` made unwrap DELETE an operator-authored file).

  // Rollback for every post-rewrite failure: restore the primary config
  // and, for Hermes, the config.yaml surface (or remove it when this wrap
  // created it fresh). Defined here so the deferred wrap-meta write below
  // shares the exact rollback the YAML block uses. Returns false when ANY
  // surface could not be restored (MED-1: the wrap-meta failure path must
  // know, because a still-wrapped surface with no meta on disk is an
  // orphan --unwrap cannot find).
  const rollbackWrapSurfaces = async (): Promise<boolean> => {
    let allRestored = true;
    if (hermesYaml) {
      if (hermesYamlBackupPath) {
        if (
          !(await restoreFromBackup(hermesYaml.yamlPath, hermesYamlBackupPath))
        ) {
          allRestored = false;
        }
      } else {
        try {
          // Round-3 P1-A: parent-walk-safe even on the rollback path.
          await unlinkSafeUnderRoot(hermesYaml.yamlPath);
        } catch (err) {
          // Best-effort removal of the file this wrap created. ENOENT means
          // the write itself never landed (the end-state "absent" already
          // holds); any OTHER failure (a symlink raced into its parent, an
          // unwritable directory) leaves the created file in place, which
          // counts as a failed restore for the orphan-wrap guard below.
          const code =
            err && typeof err === "object" && "code" in err
              ? (err as NodeJS.ErrnoException).code
              : undefined;
          if (code !== "ENOENT") allRestored = false;
        }
      }
    }
    if (!(await restoreFromBackup(agentConfig.configPath, backupPath))) {
      allRestored = false;
    }
    return allRestored;
  };

  // The unwrap pointer this wrap will persist once every surface verifies
  // (see the deferred-write rationale at the persist site below). Built
  // here, right after the backups, so the orphan-wrap guard can fall back
  // to writing it from EVERY rollback path, not just the meta-write-failure
  // one.
  const wrapMetaPayload = {
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
  };
  const persistWrapMeta = deps.saveWrapMeta ?? saveWrapMeta;

  // MED-1 orphan-wrap guard, extended to ALL rollback paths (2026-07-02
  // hardening; the #843 fix covered only the meta-write-failure rollback,
  // leaving the three earlier rollback call sites able to end
  // wrapped-with-no-meta). When ANY surface restore fails, the live config
  // may STILL route traffic through Sanctuary while nothing on disk points
  // at the pre-wrap backup; `--unwrap` would report "No Sanctuary wrap
  // found". A meta pointing at the pre-wrap backup is strictly better than
  // that orphan state (unwrap restores are idempotent, so re-restoring an
  // already-restored surface is harmless - including a null-backup aux file
  // this failed wrap never created or already removed, which unwrap's
  // removal branch tolerates as already-absent ENOENT), so write it; if
  // even that fails
  // (e.g. disk full), never end silently: spell out exactly what --unwrap
  // will (not) do and the manual restore for every surface.
  const guardOrphanWrapAfterRollback = async (
    fullyRolledBack: boolean,
  ): Promise<void> => {
    if (fullyRolledBack) return;
    try {
      await persistWrapMeta(wrapMetaPayload, { configStillWrapped });
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `  Wrap metadata was written after the failed restore: run the` +
          `\n  unwrap command (--unwrap) to retry restoring the pre-wrap config.`
      );
    } catch {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  CRITICAL: the config is STILL WRAPPED and no wrap metadata` +
          `\n  could be written. --unwrap will NOT find this wrap; traffic` +
          `\n  keeps routing through Sanctuary until you restore manually:`
      );
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `    cp "${backupPath}" "${agentConfig.configPath}"`
      );
      if (hermesYaml) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          hermesYamlBackupPath
            ? `    cp "${hermesYamlBackupPath}" "${hermesYaml.yamlPath}"`
            : `    rm "${hermesYaml.yamlPath}" (this wrap created it fresh)`
        );
      }
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("");
    }
  };

  const rewrite = deps.rewriteConfig ?? rewriteConfigForWrap;
  // Harden round: the primary rewrite writes the live config IN PLACE
  // (O_TRUNC via writeFileNoFollow, not temp+rename), so a throw mid-write
  // (disk full, EIO) can leave the config truncated. With the wrap-meta
  // write deferred until after verification, an uncaught throw here would
  // propagate out of runWrap with no rollback AND no meta, so
  // `--unwrap` would report nothing to restore. Catch, restore the
  // pre-wrap surfaces, and exit non-zero, matching the YAML-write path.
  try {
    await rewrite(
      agentConfig,
      sanctuaryCommand,
      sanctuaryArgs,
      Object.keys(sanctuaryEnv).length > 0 ? sanctuaryEnv : undefined,
    );
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Config rewrite FAILED: ${(err as Error).message}`
    );
    await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
    process.exit(1);
  }

  const verifyResult = await verifyRewrittenConfig(
    agentConfig.configPath,
    backupPath
  );
  if (!verifyResult.verified) {
    // 2026-07-02 hardening: verification failure rolls back internally; if
    // THAT restore failed, the live config is in an unknown (possibly still
    // wrapped) state with no meta - run the orphan-wrap guard here too.
    await guardOrphanWrapAfterRollback(verifyResult.restoredOnFailure);
    process.exit(1);
  }

  // D4 staging, Bug 2: apply the precomputed config.yaml injection now that
  // the JSON surface verified. D4 P1-1: the ENTIRE write+verify is inside
  // one rollback scope - a thrown writeFile (unwritable file, bad symlink)
  // previously escaped the verify-only rollback and left the wrap partially
  // applied (JSON wrapped, YAML not: the exact silent-bypass state this fix
  // exists to prevent). Any failure now rolls BOTH surfaces back and exits
  // non-zero, so the wrap is atomic: fully applied or fully rolled back.
  if (hermesYaml) {
    const yamlSurface = hermesYaml;
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
      await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
      process.exit(1);
    }
    if (!yamlVerified) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Verification FAILED: No sanctuary entry in rewritten ${yamlSurface.yamlPath}.`
      );
      await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
      process.exit(1);
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Hermes MCP routing: ${formatHermesYamlAction(yamlSurface.plan, yamlSurface.yamlPath)}`
    );
  }

  // F6 + harden round: persist the unwrap pointer ONLY now, after every
  // wrapped surface is verified-committed, so no failure path can leave a
  // meta behind for a wrap that did not stick. `configStillWrapped`
  // (computed pre-backup above) keeps a stale meta left by a pre-1.6.1
  // unwrap - which never removed metas - or by a by-hand unwrap from
  // pinning an ancient pristine pointer over a config the operator has
  // since edited, while a re-wrap over a partially-unwrapped Hermes install
  // (JSON restored, YAML restore failed and retained the meta) still
  // preserves the good pristine pointers. If the meta write itself fails,
  // roll both surfaces back: a wrapped config with no unwrap pointer would
  // strand --unwrap entirely.
  //
  // Honest crash window (MED-2): deferring the meta write opens the inverse
  // hazard. Between the surface commits above and this write, a crash or
  // power loss leaves the config WRAPPED with NO meta. A retry wrap then
  // sees configStillWrapped=true with no existing meta to preserve, so the
  // fresh pointer wins and the fresh backup captures the ALREADY-WRAPPED
  // content; the pristine pre-wrap state survives only in the older
  // timestamped backups nothing points at. Perfect detection is impossible
  // (that state is indistinguishable from a hand-authored sanctuary entry),
  // so the wrap prints the loud pre-backup warning above in exactly that
  // condition instead of guessing.
  try {
    await persistWrapMeta(wrapMetaPayload, { configStillWrapped });
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Wrap metadata write FAILED: ${(err as Error).message}`
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Rolling back: a wrapped config without an unwrap pointer would strand --unwrap.`
    );
    // MED-1 (orphan-wrap guard): when a surface restore fails here, the
    // guard retries the meta write once before giving up (a meta pointing
    // at the pre-wrap backup beats the orphan state), then prints the
    // CRITICAL manual-restore message on a double failure.
    await guardOrphanWrapAfterRollback(await rollbackWrapSurfaces());
    process.exit(1);
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
  const localAgentRecord = buildLocalAgentRecord({
    storagePath,
    platform: agentConfig.platform,
  });
  try {
    // The host tenant registry must live under the *resolved* storage root,
    // not the hardcoded ~/.sanctuary default. When SANCTUARY_STORAGE_PATH is
    // set (an isolated/drill fortress), `storagePath` is that override and the
    // registry row lands in `<override>/tenants.json` - it must never pollute
    // the real operator fortress's `~/.sanctuary/tenants.json`. When the env
    // var is unset, `storagePath` already equals `~/.sanctuary`, so default
    // behavior (and the existing host-level cross-fortress index) is unchanged.
    // The read side (`sanctuary agents list`) resolves the same root from the
    // same env var, so read and write always agree.
    await registerHostTenant(storagePath, { root: storagePath });
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: host tenant registry not updated ` +
        `(${(err as Error).message}). ` +
        `Re-run \`sanctuary wrap\` to retry, or check permissions on ${storagePath}/${TENANTS_REGISTRY_FILE_NAME}.`,
    );
  }

  try {
    upsertPersistedLocalAgent(storagePath, localAgentRecord);
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

    // F4: enforcement-evidence signal for the success banner; false unless
    // the fail-closed probe below observes dashboard-standard evidence.
    let ndEnforcementObserved = false;

    // v1.3.0 (WWWWW, NNN regression): --no-dashboard wraps previously
    // skipped identity bootstrap because the creation lived after the
    // dashboard startup path. Derive the master key and create a default
    // identity so CLI surfaces (exit export, identity show) work
    // immediately after wrap without launching the dashboard first.
    if (passphraseValue !== undefined && wrapCustody !== undefined) {
      try {
        const ndStorage = new FilesystemStorage(`${storagePath}/state`);
        // Unified custody: the master was established (or migrated) above;
        // re-deriving from key-params here could produce a DIFFERENT master
        // than the envelope holds - exactly the divergence this build ends.
        const ndDerived = { key: wrapCustody.masterKey };
        const ndAuditLog = new AuditLog(ndStorage, ndDerived.key);
        await bestEffortRecordWrapWorkloadRegistration({
          auditLog: ndAuditLog,
          storagePath,
          record: localAgentRecord,
        });
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

        const { IdentityManager } = await import("../cognitive/tools.js");
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
        // F4: probe for real enforcement evidence (adjudicated flows) so the
        // banner can distinguish "daemon started" from "observed enforcing".
        ndEnforcementObserved = await probeEnforcementObservedIfArmed(
          castleWallDaemon,
          ndAuditLog,
          storagePath,
        );
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
      platform: agentConfig.platform,
      passphraseLocation,
      passphraseSource,
      // Honest arm outcome: castleWallDaemon is only defined when
      // startCastleWallForWrap succeeded; on a start failure the catch above
      // ran warnCastleWallDaemonNotStarted and left it undefined. Daemon
      // start alone never renders "protected"; that needs the F4 evidence
      // signal below.
      castleWallArmed: castleWallDaemon !== undefined,
      castleWallEnforcementObserved: ndEnforcementObserved,
      // 2026-07-02 hardening: the dead-pin warning must survive to the
      // terminal-final success surface, not only the mid-flow warning.
      pinnedVersionResolvability: pinResolvability,
    });
    return;
  }

  // v1.2.1 (Finding III): track intelligence subsystem health for the
  // success banner. Updated below when the substrate selector loads.
  let intelligenceHealthy: boolean | undefined;
  let intelligenceError: string | undefined;
  // Rho-2.5: whether the consent-gated Tier B redactor was installed on the
  // wrap-auto selector. Threaded into buildV11Bindings so the wrap-emitted
  // dashboard's /api/query-anonymity/pii route reports the truthful state.
  let wrapTierBPiiRedactorInstalled = false;
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
  if (passphraseValue !== undefined && wrapCustody !== undefined) {
    try {
      const v11Storage = new FilesystemStorage(`${storagePath}/state`);
      // Unified custody: reuse the master established above (envelope-backed)
      // instead of re-deriving from key-params - the spawned MCP server
      // unlocks the same envelope with the same passphrase.
      const derived = { key: wrapCustody.masterKey };
      wrapAuditLog = new AuditLog(v11Storage, derived.key);
      await bestEffortRecordWrapWorkloadRegistration({
        auditLog: wrapAuditLog,
        storagePath,
        record: localAgentRecord,
      });

      // HIGH never-overclaim fix (honesty/dashboard-rollup seam #2): resolve the
      // pinned producer key over the SAME canonical storage path the wrap-auto
      // Castle Wall daemon publishes it to (`<storagePath>/policy/egress/
      // audit-producer.pub`, via loadFortressProducerKey) and feed it into the
      // snapshot server's sources. Without this the wrap-auto dashboard read the
      // wall posture on the bare channel basis, so on a key-bearing host a forged
      // marker-only audit entry would arm the hero shield green. With the key
      // present the reader re-verifies the producer signature and a forgery fails
      // closed to amber, identical to the DashboardApprovalChannel path. `absent`
      // (macOS / pre-provision) → honest channel basis; `unreadable` (a key is
      // expected but malformed/locked) → fail honestly to amber via
      // producerKeyExpectedButUnavailable, never the weaker channel basis.
      try {
        const { loadFortressProducerKey } = await import(
          "../castle-wall/runtime/producer-signature.js"
        );
        const { loadBrokerProducerKey } = await import(
          "../broker-mcp/producer-signature.js"
        );
        const producerKeyLoad = await loadFortressProducerKey(storagePath);
        const brokerProducerKeyLoad = await loadBrokerProducerKey(storagePath);
        dashboard.updateSources?.({
          resolvePinnedProducerKey: () =>
            producerKeyLoad.status === "present"
              ? producerKeyLoad.keyB64url
              : null,
          ...(producerKeyLoad.status === "unreadable"
            ? { producerKeyExpectedButUnavailable: true }
            : {}),
          resolveBrokerPinnedProducerKey: () =>
            brokerProducerKeyLoad.status === "present"
              ? brokerProducerKeyLoad.keyB64url
              : null,
          ...(brokerProducerKeyLoad.status === "unreadable"
            ? { brokerProducerKeyExpectedButUnavailable: true }
            : {}),
        });
      } catch {
        // Never let the producer-key probe fail wrap. On any unexpected throw the
        // snapshot server keeps its honest default (no producer key → channel
        // basis); it never silently arms green on a forged entry because the
        // aggregator's wall reader treats absent-key as the channel floor.
      }
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
        const { IdentityManager } = await import("../cognitive/tools.js");
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
        // Rho-2.5 (HIGH privacy-leak fix): the wrap-auto dashboard mounts
        // the /api/query-anonymity/pii route and serves concierge over the
        // frontier substrate. Without this install the selector kept the
        // passthrough IDENTITY_REDACTOR, so an operator who opted into
        // Tier B here egressed query + context UNSCRUBBED. Route through
        // THE shared chokepoint with the SAME hashed fortressId that the
        // buildV11Bindings call below uses, so the route's PATCH and the
        // live scrub read the same encrypted config.
        wrapTierBPiiRedactorInstalled = installConsentGatedRedactor({
          selector: wrapIntelligenceSelector,
          storage: v11Storage,
          masterKey: derived.key,
          fortressId: fortressIdFromStoragePath(storagePath),
        });
        intelligenceHealthy = true;
      } catch (err) {
        intelligenceHealthy = false;
        intelligenceError = (err as Error).message;
        // wrapTierBPiiRedactorInstalled stays false (its initialized value):
        // the install assignment above only completes when no throw occurred.
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
          // Rho-2.5: the consent-gated redactor is installed on the
          // wrap-auto selector, so report the truthful effective state.
          tierBPiiRedactorInstalled: wrapTierBPiiRedactorInstalled,
        }),
      );
      // The wrap-auto dashboard always binds 127.0.0.1. The printed URL
      // carries only a short-lived session; loopback auto-auth keeps the
      // v1.1 client one-click without putting the bearer token in a URL.
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

  const dashboardUrl = dashboard.createSessionUrl?.() ?? dashboard.url;

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
      /* best-effort - user can still copy the URL */
    }
  }

  if (wrapAuditLog) {
    await wrapAuditLog.flush();
  }

  // F4: probe for real enforcement evidence (adjudicated flows) so the banner
  // can distinguish "daemon started" from "observed enforcing". Fail-closed.
  const enforcementObserved = await probeEnforcementObservedIfArmed(
    castleWallDaemon,
    wrapAuditLog,
    storagePath,
  );

  printWrapSuccess({
    toolName,
    version: readPackageVersion(),
    toolCount: countUpstreamTools(upstreamServers),
    serverCount: upstreamServers.length,
    platform: agentConfig.platform,
    dashboardUrl,
    browserOpened: !options.noOpen,
    passphraseLocation,
    passphraseSource,
    intelligenceHealthy,
    intelligenceError,
    // Honest arm outcome: defined only when startCastleWallForWrap succeeded.
    // Daemon start alone never renders "protected"; that needs the F4
    // evidence signal below.
    castleWallArmed: castleWallDaemon !== undefined,
    castleWallEnforcementObserved: enforcementObserved,
    // 2026-07-02 hardening: the dead-pin warning must survive to the
    // terminal-final success surface, not only the mid-flow warning.
    pinnedVersionResolvability: pinResolvability,
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
    `No free dashboard port in the range ${preferredPort}-${lastPort} (all ${PORT_FALLBACK_ATTEMPTS} tried): ${
      (lastErr as Error)?.message ?? "unknown"
    }. Stop the other Sanctuary instance, or choose a port with: sanctuary wrap <your-flags> --port <port>.`
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
  /**
   * Wrap platform, used for platform-specific banner copy (F7: on Hermes with
   * an empty legacy JSON surface, the upstream-count line would read
   * "0 tools registered across 0 upstream servers" and appear to contradict
   * the authoritative config.yaml routing message).
   */
  platform?: AgentPlatform;
  dashboardUrl: string;
  browserOpened: boolean;
  passphraseLocation: string;
  passphraseSource: string;
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
  /**
   * Whether the Castle Wall USERSPACE DAEMON started during this wrap.
   * `true` => daemon started - which says NOTHING about enforcement (on a
   * Mac with no approved system extension the daemon starts and filters
   * nothing); `false` => the loud "NOT armed" warning fired and traffic is
   * not being filtered; `undefined` => no signal was threaded into the
   * banner (treated conservatively). Daemon start alone NEVER earns the
   * affirmative "protected / Castle Wall Full" hero; that requires
   * `castleWallEnforcementObserved` (F4, v1.6.1 first-run honesty).
   */
  castleWallArmed?: boolean;
  /**
   * Whether REAL enforcement evidence was observed: fresh adjudicated-flow
   * evidence (egress_allowed / egress_blocked / operator_decision), judged
   * by the SAME provenance- and producer-signature-gated standard the
   * dashboard's feature-health panel uses. ONLY this (together with
   * `castleWallArmed === true`) earns the affirmative "Your agent is
   * protected. / Castle Wall Full" hero; daemon presence, heartbeats, and
   * policy loads never do.
   */
  castleWallEnforcementObserved?: boolean;
  /**
   * Wrap-time registry probe outcome for the version-pinned MCP entry
   * (2026-07-02 hardening). "unpublished" renders a loud warning INSIDE the
   * final banner (the entry cannot start until the version is published);
   * "unreachable" renders an honest could-not-verify note. `undefined`
   * means the probe did not run (`--dev-dist` local-build entries involve
   * no registry) and, conservatively, "resolvable"/"skipped" add no noise.
   * The mid-flow warning alone is NOT enough: it scrolls far above the
   * banner, and the banner is the success claim the operator acts on.
   */
  pinnedVersionResolvability?: PinnedVersionResolvability;
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
  lines.push(`  ${g(check)} ${renderUpstreamCountLine(info)}`);
  lines.push(
    `  ${g(check)} Sovereignty Dashboard running at ${b(info.dashboardUrl)}`
  );
  if (info.browserOpened) {
    lines.push(`  ${g(check)} Opened in your browser`);
  } else {
    lines.push(`  ${d("(browser auto-open suppressed)")}`);
  }
  lines.push("");
  // Named enforcement layers (L1-L4 numbering retired 2026-05-24). Mapping
  // matches the Castle Architecture surface in server/README.md and the
  // sovereignty manifesto: Castle Wall (OS-level egress), Sentinels (internal
  // observation / intelligence \u2014 the TEE/intelligence-dependent slot), Charter
  // (Cooperative MCP), Heralds (receipts + cross-castle reputation).
  const sentinelsStatus = info.intelligenceHealthy === false
    ? "Sentinels Degraded (intelligence disabled)"
    : "Sentinels Degraded (no TEE)";
  // Honesty: the load-bearing enforcement layer is Castle Wall. Reserve the
  // affirmative "Castle Wall Full" hero claim for OBSERVED ENFORCEMENT
  // (F4, v1.6.1): fresh adjudicated-flow evidence on the dashboard's
  // standard, never daemon start alone. A daemon that merely started
  // (`castleWallArmed === true`, no evidence) renders the honest
  // "wrapped, but enforcement is not confirmed" hero; a failed start
  // (`false`) or an absent signal (`undefined`) never renders "Full".
  const enforcementObserved = castleWallProtectionConfirmed(
    info.castleWallArmed,
    info.castleWallEnforcementObserved,
  );
  const castleWallLabel = renderCastleWallBannerLabel(
    info.castleWallArmed,
    enforcementObserved,
  );
  const heroPrefix = enforcementObserved
    ? b("Your agent is protected.")
    : b("Your agent is wrapped, but enforcement is not confirmed.");
  // Honesty (Finding 3, 2026-06-25): Charter and Heralds are "ready" after a
  // wrap, not "Full". "Full" is a superlative reserved for observed/verified
  // state (as Castle Wall and Sentinels already are); printing "Charter Full /
  // Heralds Full" unconditionally (even under --no-dashboard, even when nothing
  // was exercised) was the same overclaim the load-bearing-layer fix removed.
  lines.push(
    `  ${heroPrefix} ${castleWallLabel} / ${sentinelsStatus} / Charter: ready / Heralds: ready.`,
  );
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`; // yellow
    lines.push("");
    lines.push(`  ${w("\u26A0")} Sentinels intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Concierge chat and substrate-driven explanations will not work until this is resolved.`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push(...renderPinResolvabilityBannerLines(info));
  lines.push("");
  return lines.join("\n");
}

/**
 * Banner lines for the pinned-MCP-entry resolvability outcome, shared by
 * both success surfaces (2026-07-02 hardening). An "unpublished" pin means
 * the MCP entry this wrap just wrote CANNOT start \u2014 saying so only in a
 * mid-flow warning that scrolls above the banner left the terminal-final
 * success surface byte-identical to a working wrap (the dead-entry-behind-
 * a-success-banner defect the probe exists to close). "unreachable" gets
 * the honest could-not-verify note; "resolvable"/"skipped"/absent add
 * nothing.
 */
function renderPinResolvabilityBannerLines(info: {
  version: string;
  pinnedVersionResolvability?: PinnedVersionResolvability;
}): string[] {
  const w = (s: string) => `\x1b[33m${s}\x1b[0m`; // yellow
  const d = (s: string) => `\x1b[2m${s}\x1b[0m`; // dim
  if (info.pinnedVersionResolvability === "unpublished") {
    return [
      "",
      `  ${w("\u26A0")} The MCP entry this wrap wrote is pinned to ` +
        `@sanctuary-framework/mcp-server@${info.version},`,
      `    which is not on the npm registry (as resolved from this directory): unless`,
      `    your agent's project config routes the scope to another registry, it cannot`,
      `    start until that version is published. For an unpublished build, re-run`,
      `    with --dev-dist <path-to-dist/cli.js> to point the entry at your local build.`,
    ];
  }
  if (info.pinnedVersionResolvability === "unreachable") {
    // "unreachable" also covers a REACHED custom registry whose 404 the
    // unauthenticated probe declines to trust, so the cause line says
    // "could not confirm", never "could not be reached".
    return [
      "",
      `  ${d(
        `Note: the npm registry could not confirm the pinned MCP entry (v${info.version})`,
      )}`,
      `  ${d(
        "resolves (unreachable, or a custom registry this probe cannot verify against),",
      )}`,
      `  ${d(
        "so this wrap could not verify it. If the agent fails to start, re-run",
      )}`,
      `  ${d("'sanctuary protect' once the registry confirms the version.")}`,
    ];
  }
  return [];
}

/**
 * Render the Castle Wall segment of the wrap success banner from the real
 * outcome. Honesty discipline (F4, v1.6.1): "Castle Wall Full" is only
 * printed on OBSERVED ENFORCEMENT (fresh adjudicated-flow evidence on the
 * dashboard's standard). A daemon that merely started renders "daemon
 * started (enforcement not confirmed)"; a failed start renders a loud
 * "NOT ARMED"; an absent signal renders "status unknown". Never "Full" on
 * daemon presence alone.
 */
function renderCastleWallBannerLabel(
  armed: boolean | undefined,
  enforcementObserved: boolean,
): string {
  if (castleWallProtectionConfirmed(armed, enforcementObserved)) {
    return "Castle Wall Full";
  }
  if (armed === true) {
    return "Castle Wall daemon started (enforcement not confirmed)";
  }
  if (armed === false) return "Castle Wall NOT ARMED (traffic not filtered)";
  return "Castle Wall status unknown (not confirmed armed)";
}

/**
 * Render the upstream tools/servers count line. F7 (v1.6.1 first-run
 * honesty): on Hermes the counts derive from the legacy cli-config.json
 * surface Hermes does not consult for MCP routing, so a first run would
 * print "0 tools registered across 0 upstream servers" moments after the
 * (correct) message that config.yaml entries are preserved. When the
 * authoritative surface is the Hermes YAML and the legacy surface is empty,
 * say what actually happened instead.
 */
function renderUpstreamCountLine(info: {
  toolCount: number;
  serverCount: number;
  platform?: AgentPlatform;
}): string {
  if (info.platform === "hermes" && info.serverCount === 0) {
    return "Sanctuary MCP routing installed in Hermes config.yaml (existing entries preserved)";
  }
  return `${info.toolCount} tools registered across ${info.serverCount} upstream server${info.serverCount !== 1 ? "s" : ""}`;
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
  /** See WrapSuccessInfo.platform; same platform-specific copy rules. */
  platform?: AgentPlatform;
  passphraseLocation: string;
  passphraseSource: string;
  intelligenceHealthy?: boolean;
  intelligenceError?: string;
  /** See WrapSuccessInfo.castleWallArmed; same daemon-start-only semantics. */
  castleWallArmed?: boolean;
  /**
   * See WrapSuccessInfo.castleWallEnforcementObserved; same
   * evidence-only-affirmative discipline.
   */
  castleWallEnforcementObserved?: boolean;
  /**
   * See WrapSuccessInfo.pinnedVersionResolvability; same banner-honesty
   * discipline (an unpublished pin must be visible on the terminal-final
   * success surface, not only in a mid-flow warning).
   */
  pinnedVersionResolvability?: PinnedVersionResolvability;
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
  lines.push(`  ${g(check)} ${renderUpstreamCountLine(info)}`);
  lines.push(
    `  ${d("Dashboard spawn skipped per --no-dashboard. Run `sanctuary dashboard` separately for a persistent dashboard.")}`,
  );
  lines.push("");
  // Named enforcement layers (L1-L4 numbering retired 2026-05-24). See the
  // mapping note in formatWrapSuccess above; both surfaces must agree.
  const sentinelsStatus = info.intelligenceHealthy === false
    ? "Sentinels Degraded (intelligence disabled)"
    : "Sentinels Degraded (no TEE)";
  // Honesty: same outcome discipline as formatWrapSuccess (F4, v1.6.1) \u2014
  // reserve the affirmative "protected" / "Castle Wall Full" hero for
  // observed enforcement evidence, never daemon start alone.
  const enforcementObserved = castleWallProtectionConfirmed(
    info.castleWallArmed,
    info.castleWallEnforcementObserved,
  );
  const castleWallLabel = renderCastleWallBannerLabel(
    info.castleWallArmed,
    enforcementObserved,
  );
  const heroPrefix = enforcementObserved
    ? b("Your agent is protected.")
    : b("Your agent is wrapped, but enforcement is not confirmed.");
  lines.push(
    `  ${heroPrefix} ${castleWallLabel} / ${sentinelsStatus} / Charter: ready / Heralds: ready.`,
  );
  if (info.intelligenceHealthy === false && info.intelligenceError) {
    const w = (s: string) => `\x1b[33m${s}\x1b[0m`;
    lines.push("");
    lines.push(`  ${w("\u26A0")} Sentinels intelligence disabled: ${info.intelligenceError}`);
    lines.push(`    Run 'sanctuary intelligence diagnose' to inspect substrate config.`);
  }
  lines.push(...renderPinResolvabilityBannerLines(info));
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

/**
 * Verify the rewritten primary config and roll it back on failure.
 * `restoredOnFailure` reports whether the internal rollback restore
 * succeeded (meaningful only when `verified` is false) so the caller's
 * orphan-wrap guard can detect a failed restore (2026-07-02 hardening;
 * previously the restore result was discarded here).
 */
async function verifyRewrittenConfig(
  configPath: string,
  backupPath: string
): Promise<{ verified: boolean; restoredOnFailure: boolean }> {
  try {
    const raw = await readFile(configPath, "utf-8");
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: Rewritten config is not valid JSON.`);
      console.error(`  Error: ${(err as Error).message}`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    const servers =
      ((parsed.mcp as Record<string, unknown>)?.servers as Record<string, unknown>) ??
      (parsed.mcpServers as Record<string, unknown>) ??
      (parsed.mcp_servers as Record<string, unknown>) ??
      {};

    if (!servers.sanctuary) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: No sanctuary entry in rewritten config.`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    const sanctuaryEntry = servers.sanctuary as Record<string, unknown>;
    if (!sanctuaryEntry.command || typeof sanctuaryEntry.command !== "string") {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Verification FAILED: Sanctuary entry has no command.`);
      return {
        verified: false,
        restoredOnFailure: await restoreFromBackup(configPath, backupPath),
      };
    }

    return { verified: true, restoredOnFailure: true };
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Verification FAILED: ${(err as Error).message}`);
    return {
      verified: false,
      restoredOnFailure: await restoreFromBackup(configPath, backupPath),
    };
  }
}

/**
 * Restore `configPath` from `backupPath`, reporting failure to the operator
 * without throwing. Returns false when the restore FAILED (the live config
 * keeps its current, possibly-wrapped contents); callers that must not end
 * in a wrapped-with-no-meta orphan state (MED-1, the wrap-meta failure
 * rollback) branch on it. Other callers may ignore the result: the CRITICAL
 * manual-recovery message has already printed.
 */
async function restoreFromBackup(
  configPath: string,
  backupPath: string
): Promise<boolean> {
  try {
    await restoreConfig(backupPath, configPath);
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  Original config restored from backup.`);
    console.error(`  Backup preserved at: ${backupPath}\n`);
    return true;
  } catch (restoreErr) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`  CRITICAL: Could not restore backup from ${backupPath}`);
    console.error(`  Error: ${(restoreErr as Error).message}`);
    console.error(`  Manual recovery: copy ${backupPath} to ${configPath}\n`);
    return false;
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
  // unwrap with nothing modified - including the primary config. Round-2
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
        // Fifth round (preview parity): the real unwrap snapshots this
        // file's final contents into a timestamped backup BEFORE removing
        // it (the recovery breadcrumb below); a dry run that omitted the
        // snapshot read scarier than reality for an operator judging
        // whether post-wrap edits would be lost.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Would remove ${aux.originalPath} (created by wrap; no pre-wrap version existed;` +
            `\n  its final contents would first be preserved as a timestamped backup)`
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
  // Harden round (operator breadcrumb): the restored snapshot is the FIRST
  // pre-wrap backup (F6 pristine-pointer preservation); config edits made
  // while wrapped survive only in the newer timestamped backups that
  // nothing points at. Say where they are so the discard is recoverable.
  const newerPrimaryBackup = await findNewerBackup(
    meta.backupPath,
    meta.originalPath,
  );
  if (newerPrimaryBackup) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: this restored the pristine pre-wrap snapshot. Newer backups exist;` +
        `\n  config changes made while wrapped may be recoverable from: ${newerPrimaryBackup}`
    );
  }

  // D4 staging, Bug 2: restore auxiliary files the wrap touched (the
  // Hermes config.yaml surface). A null backupPath means wrap created the
  // file fresh; restoring the pre-wrap state removes it. Best-effort: the
  // primary config restore above already succeeded, so an auxiliary
  // failure reports loudly with the manual recovery path instead of
  // aborting the unwrap. Failures are counted: the wrap-meta retirement
  // below is gated on ALL restores having succeeded.
  let auxiliaryRestoreFailures = 0;
  for (const aux of auxiliary) {
    try {
      if (aux.backupPath) {
        // Round-2 P1-A/P2: restoreConfig writes the target O_NOFOLLOW
        // (atomic symlink refusal) and recreates a missing parent (0o700).
        await restoreConfig(aux.backupPath, aux.originalPath);
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  Original config restored to: ${aux.originalPath}`);
        console.error(`  Backup preserved at: ${aux.backupPath}`);
        const newerAuxBackup = await findNewerBackup(
          aux.backupPath,
          aux.originalPath,
        );
        if (newerAuxBackup) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Note: newer backups of this file exist; changes made while wrapped` +
              `\n  may be recoverable from: ${newerAuxBackup}`
          );
        }
      } else if (aux.alreadyAbsent) {
        // Round-2 P2: created-by-wrap file whose parent directory is gone -
        // the "absent" end-state already holds; informational no-op.
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  Skipped ${aux.originalPath} (created by wrap; already absent)`
        );
      } else {
        // 2026-07-02 hardening (recovery breadcrumb): a created-by-wrap file
        // (e.g. the Hermes config.yaml) is removed wholesale here, but the
        // operator may have added their own MCP entries to it AFTER the
        // wrap. Preserve the file's final contents as a timestamped backup
        // before removing it and say where it is. Best-effort: a failed
        // pre-removal snapshot warns but does not change the restore
        // semantics (the file is still removed, exactly as before).
        let preRemovalBackup: string | null = null;
        try {
          preRemovalBackup = await backupConfig(aux.originalPath);
        } catch (err) {
          // ENOENT is silent: the file is already gone (see the removal
          // carve-out below), so there is nothing to snapshot and a WARNING
          // would misread as a real failure.
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
            console.error(
              `  WARNING: could not snapshot ${aux.originalPath} before removal: ` +
                `${(err as Error).message}`
            );
          }
        }
        // Round-3 P1-A: refuse the unlink if a symlink was raced into the
        // parent dir after validate-time; unlink() does not follow a
        // symlinked leaf, so only the parent walk is needed.
        //
        // 2026-07-02 hardening (second round): ENOENT means the delete-on-
        // unwrap end-state ALREADY holds - mirror the rollbackWrapSurfaces
        // carve-out instead of counting it as an auxiliaryRestoreFailure.
        // The orphan-wrap guard can persist a null-backup entry for a file
        // the failed wrap never created (or that its rollback already
        // removed) while the parent dir still exists (so validate-time
        // `alreadyAbsent` does not fire); treating that phantom file as a
        // restore failure kept the wrap-meta alive forever and wedged every
        // --unwrap re-run on a cause that is a nonexistent file.
        let removed = true;
        try {
          await unlinkSafeUnderRoot(aux.originalPath);
        } catch (err) {
          const code =
            err && typeof err === "object" && "code" in err
              ? (err as NodeJS.ErrnoException).code
              : undefined;
          if (code !== "ENOENT") throw err;
          removed = false;
        }
        if (removed) {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Removed ${aux.originalPath} (created by wrap; no pre-wrap version existed)`
          );
          if (preRemovalBackup) {
            // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
            console.error(
              `  Its final contents were preserved at: ${preRemovalBackup}` +
                `\n  (in case you added entries to it after the wrap).`
            );
          }
        } else {
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `  Skipped ${aux.originalPath} (created by wrap; already absent)`
          );
        }
      }
    } catch (err) {
      auxiliaryRestoreFailures += 1;
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

  // F6 (v1.6.1 wrap safety): a COMPLETED unwrap retires the wrap-meta
  // pointer files, so "a wrap-meta exists" means "currently wrapped" and a
  // FUTURE wrap records a fresh pristine backup instead of preserving a
  // stale pointer (see saveWrapMeta). The backup files themselves stay.
  //
  // Harden round: retirement is gated on every auxiliary restore having
  // succeeded. Removing the meta after a partial restore stranded the CLI
  // retry path: a re-run of --unwrap reported "No Sanctuary wrap found"
  // while e.g. the Hermes config.yaml still routed traffic through
  // Sanctuary, and a subsequent wrap recorded that still-wrapped file as
  // the new "pristine" backup. Keeping the meta keeps --unwrap re-runnable.
  // The retirement is also scoped to the originalPath just restored, so a
  // legacy meta naming a DIFFERENT wrapped surface keeps its pointer.
  if (auxiliaryRestoreFailures > 0) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  WARNING: ${auxiliaryRestoreFailures} auxiliary ` +
        `${auxiliaryRestoreFailures === 1 ? "restore" : "restores"} failed; ` +
        `keeping the wrap metadata so 'sanctuary wrap --unwrap' can be ` +
        `re-run after fixing the cause above.`
    );
  } else {
    const metaRemovalFailures = await removeWrapMeta(meta.originalPath);
    for (const failure of metaRemovalFailures) {
      // The advice must match the failure class: an UNREADABLE pointer may
      // be a DIFFERENT wrapped surface's only restore pointer (a successful
      // read would have skipped it), so telling the operator to delete it
      // could orphan that surface's pristine backup.
      if (failure.reason === "unreadable") {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  WARNING: could not read wrap metadata ${failure.path}; it was ` +
            `left in place because it may be another wrapped surface's only ` +
            `restore pointer. Do NOT delete it; fix the read failure (for ` +
            `example file permissions) and re-run 'sanctuary wrap --unwrap' ` +
            `if a surface remains wrapped.`
        );
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `  WARNING: could not remove wrap metadata ${failure.path}; a ` +
            `future re-wrap may preserve a stale restore pointer. Remove it ` +
            `manually.`
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
 * not-armed state loud, and - on macOS, when the failure is the A2/B2
 * helper-signing default having no reachable signer - prints the exact
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
      "  start the userspace daemon, do ONE of:",
      '    1. Install the Castle Wall app (one-time "Allow background item"',
      "       approval), then set SANCTUARY_CASTLE_SIGNER_CLIENT to its shim:",
      "       /Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client",
      "    2. To keep the legacy local-signing key, set SANCTUARY_CASTLE_LOCAL_SIGN=1",
      "  then re-run 'sanctuary wrap'.",
      "",
      "  NOTE: either option only starts the userspace daemon; that alone does",
      "  NOT mean traffic is being filtered. Enforcement also needs the approved",
      "  system extension, and is confirmed only by observed flow evidence on",
      "  the dashboard's Castle Wall panel.",
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
  // 24 bytes → 32-char base64url - plenty of entropy for a single-use URL.
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
    case "mastra": return "Mastra";
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
export function harnessKindForPlatform(platform: AgentPlatform): LocalHarnessKind {
  switch (platform) {
    case "openclaw": return "openclaw";
    case "hermes": return "hermes";
    case "claude-code": return "claude_code";
    case "cursor": return "cursor";
    case "cline": return "cline";
    case "mastra": return "mastra";
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

async function recordWrapWorkloadRegistration(input: {
  auditLog: AuditLog;
  storagePath: string;
  record: LocalAgentRecord;
}): Promise<void> {
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  await recordWrappedHarnessRegistration({
    auditLog: input.auditLog,
    fortressId,
    agentId: input.record.agent_id,
  });
}

async function bestEffortRecordWrapWorkloadRegistration(input: {
  auditLog: AuditLog;
  storagePath: string;
  record: LocalAgentRecord;
}): Promise<void> {
  try {
    await recordWrapWorkloadRegistration(input);
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: workload-lifecycle registration not recorded ` +
        `(${(err as Error).message}). ` +
        `Wrap is otherwise complete; re-run \`sanctuary wrap\` to retry after fixing the audit log.`,
    );
  }
}

function countUpstreamTools(servers: UpstreamServer[]): number {
  // Conservative estimate - real count requires live tool discovery.
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
  "--mastra",
  "--unwrap",
  "--dry-run",
  "--no-open",
  "--no-dashboard",
  "--allow-plaintext-remote",
  "--anchor-transparency",
  "--help",
  "-h",
]);

/** Known harness flags (for "did you mean" suggestions). */
const WRAP_HARNESS_FLAGS = [
  "--openclaw",
  "--hermes",
  "--claude-code",
  "--cursor",
  "--cline",
  "--mastra",
];

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
      case "--mastra":
        options.mastra = true;
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
      case "--allow-plaintext-remote":
        options.allowPlaintextRemote = true;
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
    sanctuary wrap --mastra            Wrap Mastra
    sanctuary wrap --wrap <path>       Wrap a specific MCP config file
    sanctuary wrap --unwrap            Restore original config

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
    --allow-plaintext-remote
                       Persist SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE=true
                       into the wrapped harness environment. Use only when a
                       separate network layer already encrypts transport.
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
