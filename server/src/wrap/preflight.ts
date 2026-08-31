import { execFile as nodeExecFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, lstat, open, readFile, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, join, resolve as resolvePath } from "node:path";
import { promisify } from "node:util";

import { CASTLE_WALL_BOOT_LABEL } from "../cli/castle-wall-boot.js";
import { parseCastleWallState, type SysextState } from "../cli/castle-wall.js";
import {
  CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH,
  CASTLE_WALL_ACTIVE_CONFIG_PATH,
  resolveCastleWallSocketPath,
} from "../castle-wall/runtime/socket-path.js";
import { resolveSudoIdentityDecision } from "./auto-provision.js";

export type ProtectPreflightStatus = "PASS" | "FAIL" | "UNDETERMINED";

export type ProtectPreflightCheckId =
  | "castle_sock_holder"
  | "fortress_custody"
  | "root_path_sanctuary"
  | "signer_client"
  | "sysext_approval"
  | "full_disk_access"
  | "provider_liveness"
  | "operator_twin_services"
  | "boot_runtime_devtools";

export interface ProtectPreflightProviderDetail {
  provider: string;
  source: string;
  status: ProtectPreflightStatus;
  state: string;
  detail: string;
  /**
   * True exactly when this provider's own endpoint returned a genuine 2xx
   * to the CONFIGURED credential (proving the endpoint is reachable) and
   * the only reason `status` is UNDETERMINED is that the endpoint cannot
   * independently prove the credential's validity. Required (not derived
   * from `state` strings or `detail` prose) so a strict-arm consumer has
   * one explicit fact to key on instead of enumerating state names; every
   * call site must set it, so a new UNDETERMINED cause defaults to
   * non-reachable rather than silently becoming non-blocking.
   *
   * defect.strict-arm-blocks-on-reachable-unverifiable-provider
   */
  reachableUnverifiable: boolean;
}

export interface ProtectPreflightRow {
  id: ProtectPreflightCheckId;
  check: string;
  status: ProtectPreflightStatus;
  state: string;
  detail: string;
  remedy: string;
  findings: string[];
  providers?: ProtectPreflightProviderDetail[];
}

export interface ProtectPreflightSummary {
  pass: number;
  fail: number;
  undetermined: number;
}

export interface ProtectPreflightReport {
  command: "sanctuary protect preflight";
  generated_at: string;
  strict: boolean;
  summary: ProtectPreflightSummary;
  rows: ProtectPreflightRow[];
}

export interface ExecFileResult {
  code: number;
  stdout: string;
  stderr: string;
  errorCode?: string;
  signal?: string;
  /**
   * True when the subprocess was killed (timeout, maxBuffer, or an explicit
   * signal) rather than exiting on its own. A killed process proves nothing
   * about the command's own outcome, so a consumer must check this (and
   * `signal`) before treating a nonzero `code` as a confirmed result.
   */
  killed?: boolean;
}

export type AccessKind = "read" | "execute";

export type FsEntry =
  | {
      kind: "present";
      isFile: boolean;
      isDirectory: boolean;
      isSymbolicLink: boolean;
    }
  | { kind: "absent" }
  | { kind: "unknown"; reason: string; code?: string };

export type AccessResult =
  | { ok: true }
  | { ok: false; reason: string; code?: string };

export interface ProviderHttpRequest {
  method: string;
  headers?: Record<string, string>;
}

export interface ProviderHttpResponse {
  status: number;
}

export interface ProtectPreflightOps {
  now: () => Date;
  platform: () => NodeJS.Platform | string;
  cwd: () => string;
  env: () => NodeJS.ProcessEnv;
  homeDir: () => string;
  getuid: () => number | undefined;
  execFile: (cmd: string, args: string[]) => Promise<ExecFileResult>;
  entry: (path: string) => Promise<FsEntry>;
  /**
   * Owner uid/gid of a path (lstat, never following a symlink). Backs the
   * `fortress_custody` row (fortress-ownership spec 2026-07-30 §4(a2)(2)).
   */
  owner: (
    path: string,
  ) => Promise<
    | { ok: true; uid: number; gid: number }
    | { ok: false; reason: string; code?: string }
  >;
  access: (path: string, kind: AccessKind) => Promise<AccessResult>;
  readText: (path: string) => Promise<{ ok: true; text: string } | { ok: false; reason: string; code?: string }>;
  readDir: (path: string) => Promise<{ ok: true } | { ok: false; reason: string; code?: string }>;
  readFileSample: (path: string) => Promise<{ ok: true } | { ok: false; reason: string; code?: string }>;
  fetch: (url: string, request: ProviderHttpRequest) => Promise<ProviderHttpResponse>;
}

export interface RunProtectPreflightInput {
  strict?: boolean;
  /**
   * Automatic full-install retries may continue past the exact launchd
   * safe-mode daemon for this fortress. The provisioning flow immediately
   * re-verifies the persistent service before any arm. Explicit preflight
   * commands and unknown/transient holders keep the fail-closed refusal.
   */
  allowMatchingBootDaemon?: boolean;
  /**
   * Canonical app-sealed launcher selected by the caller. The mutating protect
   * path validates its signature and sealed runtime before passing this path;
   * this read-only preflight independently checks only canonical location and
   * executability so it never substitutes PATH availability for app custody.
   */
  sealedLauncherPath?: string;
  ops?: Partial<ProtectPreflightOps>;
}

interface ProtectPreflightContext {
  strict: boolean;
  ops: ProtectPreflightOps;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform | string;
  cwd: string;
  operator: OperatorContext;
  fortressPath?: string;
  sealedLauncherPath?: string;
  allowMatchingBootDaemon: boolean;
}

interface OperatorContext {
  uid?: number;
  gid?: number;
  user?: string;
  home?: string;
  reason?: string;
}

interface ProviderDefinition {
  id: string;
  label: string;
  envNames: string[];
  buildRequest: (credential: string) => { url: string; request: ProviderHttpRequest };
  /**
   * A credential matching this provider's documented format (prefix and
   * length), so it reaches the provider's own credential check rather than
   * being rejected earlier on shape alone. Never a real secret; never
   * derived from operator input; never logged or persisted -- it exists
   * only to be presented to the provider and rejected.
   *
   * defect.preflight-provider-liveness-probe-not-authenticated
   */
  invalidCredentialProbe: string;
}

interface ConfiguredProvider {
  definition: ProviderDefinition;
  source: string;
  credential: string;
}

const execFileAsync = promisify(nodeExecFile);
const PREFLIGHT_FETCH_TIMEOUT_MS = 5_000;
const NO_REMEDY = "none";
// Must match CASTLE_WALL_SEALED_LAUNCHER in wrap/cli.ts. The CLI performs the
// signature/runtime verification; this preflight only reports availability.
const CASTLE_WALL_SEALED_LAUNCHER =
  "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary";
const HERMES_GATEWAY_LABEL = "ai.hermes.gateway";
const HERMES_GATEWAY_PROCESS_MARKER = "hermes_cli.main gateway";
const FULL_DISK_ACCESS_PROBE_RELPATHS = [
  "Library/Caches/com.apple.containermanagerd",
];

const PROVIDER_CONFIG_RELPATHS = [
  ".hermes/.env",
  ".hermes/config.yaml",
  ".hermes/auth.json",
  ".config/hermes/.env",
  ".config/hermes/config.yaml",
  ".config/hermes/auth.json",
];

const BILLING_DEAD_STATE = "billing_dead";
// A provider's liveness probe must prove the *credential* was checked, not
// merely that the endpoint is reachable. See ProviderDefinition.invalidCredentialProbe
// and probeCredentialDiscrimination.
//
// defect.preflight-provider-liveness-probe-not-authenticated

const PROVIDERS: ProviderDefinition[] = [
  {
    id: "venice",
    label: "Venice",
    envNames: ["VENICE_API_KEY"],
    buildRequest: (credential) => ({
      url: "https://api.venice.ai/api/v1/models",
      request: {
        method: "GET",
        headers: { Authorization: `Bearer ${credential}` },
      },
    }),
    // No fixed public key-length spec; length matches an opaque bearer
    // token of typical size so it is at least plausible in shape.
    invalidCredentialProbe: "preflight0preflight0preflight0preflight0preflight0preflight0pref",
  },
  {
    id: "openai",
    label: "OpenAI",
    envNames: ["OPENAI_API_KEY"],
    buildRequest: (credential) => ({
      url: "https://api.openai.com/v1/models",
      request: {
        method: "GET",
        headers: { Authorization: `Bearer ${credential}` },
      },
    }),
    // 51 = "sk-" (3) + 48-char body, the documented classic key length.
    invalidCredentialProbe: "sk-preflight0preflight0preflight0preflight0prefligh",
  },
  {
    id: "anthropic",
    label: "Anthropic",
    envNames: ["ANTHROPIC_API_KEY"],
    buildRequest: (credential) => ({
      url: "https://api.anthropic.com/v1/models",
      request: {
        method: "GET",
        headers: {
          "anthropic-version": "2023-06-01",
          "x-api-key": credential,
        },
      },
    }),
    // 108 = "sk-ant-api03-" (13) + 95-char body, matching the documented key length.
    invalidCredentialProbe:
      "sk-ant-api03-preflight0preflight0preflight0preflight0preflight0preflight0preflight0preflight0preflight0prefl",
  },
  {
    id: "google_gemini",
    label: "Google Gemini",
    envNames: ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
    buildRequest: (credential) => ({
      url: "https://generativelanguage.googleapis.com/v1beta/models",
      request: {
        method: "GET",
        headers: { "x-goog-api-key": credential },
      },
    }),
    // 39 = "AIza" (4) + 35-char body, the documented fixed key length. This
    // provider's endpoint does not distinguish an invalid credential from
    // any other unregistered one, so this shape does not make the provider
    // verifiable; see probeCredentialDiscrimination.
    invalidCredentialProbe: "AIzapreflight0preflight0preflight0prefl", // gitleaks:allow — deliberately-invalid non-secret preflight sentinel
  },
  {
    id: "telegram",
    label: "Telegram",
    envNames: ["TELEGRAM_BOT_TOKEN"],
    buildRequest: (credential) => ({
      url: `https://api.telegram.org/bot${encodeURIComponent(credential)}/getMe`,
      request: { method: "GET" },
    }),
    // 46 = 10-digit bot id + ":" (11) + 35-char secret, the documented shape.
    invalidCredentialProbe: "0000000000:preflight0preflight0preflight0prefl",
  },
];

export function createProtectPreflightOps(): ProtectPreflightOps {
  return {
    now: () => new Date(),
    platform: () => process.platform,
    cwd: () => process.cwd(),
    env: () => process.env,
    homeDir: () => homedir(),
    getuid: () => process.getuid?.(),
    execFile: defaultExecFile,
    entry: defaultEntry,
    owner: defaultOwner,
    access: defaultAccess,
    readText: defaultReadText,
    readDir: defaultReadDir,
    readFileSample: defaultReadFileSample,
    fetch: defaultFetch,
  };
}

async function buildProtectPreflightContext(
  input: RunProtectPreflightInput,
): Promise<ProtectPreflightContext> {
  const baseOps = createProtectPreflightOps();
  const ops: ProtectPreflightOps = { ...baseOps, ...input.ops };
  const env = ops.env();
  const operator = await resolveOperatorContext(ops, env);
  return {
    strict: input.strict === true,
    ops,
    env,
    platform: ops.platform(),
    cwd: ops.cwd(),
    operator,
    fortressPath: resolvePreflightFortressPath(env, operator.home),
    sealedLauncherPath: input.sealedLauncherPath,
    allowMatchingBootDaemon: input.allowMatchingBootDaemon === true,
  };
}

/**
 * Run the authoritative operator-twin check without triggering unrelated
 * provider/network probes. The install planner uses this same check so a
 * later observed-state rerun cannot declare completion over an unconfined
 * operator gateway.
 */
export async function runOperatorTwinPreflight(
  input: RunProtectPreflightInput = {},
): Promise<ProtectPreflightRow> {
  return checkOperatorTwinServices(await buildProtectPreflightContext(input));
}

export async function runProtectPreflight(
  input: RunProtectPreflightInput = {},
): Promise<ProtectPreflightReport> {
  const context = await buildProtectPreflightContext(input);

  const rows = [
    await checkCastleSockHolder(context),
    await checkFortressCustody(context),
    await checkRootPathSanctuary(context),
    await checkSignerClient(context),
    await checkSysextApproval(context),
    await checkFullDiskAccess(context),
    await checkProviderLiveness(context),
    await checkOperatorTwinServices(context),
    await checkBootRuntimeDevTools(context),
  ];
  const summary = summarizeRows(rows);

  return {
    command: "sanctuary protect preflight",
    generated_at: context.ops.now().toISOString(),
    strict: context.strict,
    summary,
    rows,
  };
}

interface ProtectPreflightBlockingRows {
  failRows: ProtectPreflightRow[];
  undeterminedBlockingRows: ProtectPreflightRow[];
}

/**
 * True only for the provider_liveness row's specific reachable-but-
 * credential-unverifiable shape: every provider the row reports is either
 * PASS or an UNDETERMINED whose own `reachableUnverifiable` flag is set (a
 * row with no `providers` array, e.g. no_configured_provider, never proved
 * reachability and cannot qualify). Strict-arm reads this instead of the
 * row's `state` string or `check` name so a new UNDETERMINED cause defaults
 * to blocking until it explicitly proves reachability through the typed
 * field.
 *
 * defect.strict-arm-blocks-on-reachable-unverifiable-provider
 */
function isProviderLivenessReachableUnverifiable(row: ProtectPreflightRow): boolean {
  if (row.id !== "provider_liveness" || row.status !== "UNDETERMINED") return false;
  if (row.providers === undefined || row.providers.length === 0) return false;
  return row.providers.every(
    (provider) => provider.status === "PASS" || provider.reachableUnverifiable,
  );
}

/**
 * The single source of truth for "which rows are why this preflight
 * blocks". protectPreflightExitCode and describeProtectPreflightBlockers
 * both call this instead of each independently recomputing the blocking
 * set, so an exit code and a refusal message can never disagree about why a
 * run refused. `strict` is taken as an explicit parameter rather than read
 * off `report.strict` internally, so a caller cannot accidentally compute
 * the exit code with one strict value and the message with another; cli.ts
 * resolves `strict` once and passes that same value to both.
 *
 * defect.protect-preflight-refusal-copy-wrong-under-strict
 */
function protectPreflightBlockingRows(
  report: ProtectPreflightReport,
  strict: boolean,
): ProtectPreflightBlockingRows {
  return {
    failRows: report.rows.filter((candidate) => candidate.status === "FAIL"),
    undeterminedBlockingRows: strict
      ? report.rows.filter(
          (candidate) =>
            candidate.status === "UNDETERMINED" &&
            // A reachable-but-credential-unverifiable provider is proven
            // reachable and never proven bad; strict blocks on unreachable
            // or provably-bad, not on an honest bound the endpoint itself
            // cannot resolve. Every other UNDETERMINED cause still blocks.
            !isProviderLivenessReachableUnverifiable(candidate),
        )
      : [],
  };
}

/**
 * Operator-facing WARN lines for provider_liveness rows that strict allowed
 * through specifically because of the reachable-unverifiable carve-out
 * above -- printed only under strict, since that is the only mode in which
 * this state would otherwise have blocked and the operator needs to know
 * arming proceeded on an unverified credential.
 *
 * defect.strict-arm-blocks-on-reachable-unverifiable-provider
 */
export function describeProtectPreflightStrictWarnings(
  report: ProtectPreflightReport,
  strict: boolean,
): string[] {
  if (!strict) return [];
  const warnings: string[] = [];
  for (const candidate of report.rows) {
    if (!isProviderLivenessReachableUnverifiable(candidate)) continue;
    for (const provider of candidate.providers ?? []) {
      if (provider.status === "UNDETERMINED" && provider.reachableUnverifiable) {
        warnings.push(
          `${provider.provider}: credential could not be verified at this endpoint (${provider.detail}); --strict is allowing arming to proceed because the endpoint is reachable.`,
        );
      }
    }
  }
  return warnings;
}

export function protectPreflightExitCode(
  report: ProtectPreflightReport,
  strict = report.strict,
): number {
  const { failRows, undeterminedBlockingRows } = protectPreflightBlockingRows(report, strict);
  return failRows.length > 0 || undeterminedBlockingRows.length > 0 ? 2 : 0;
}

/**
 * Names the rows actually responsible for a nonzero protectPreflightExitCode:
 * under --strict an UNDETERMINED row blocks like a FAIL row (except the
 * provider_liveness reachable-unverifiable carve-out in
 * protectPreflightBlockingRows), so a refusal message that only ever says
 * "Fix the FAIL rows" is actively wrong on a FAIL-0/UNDETERMINED-1 strict
 * refusal -- the operator sees no FAIL row and no instruction that matches
 * what is on screen.
 */
export function describeProtectPreflightBlockers(
  report: ProtectPreflightReport,
  strict = report.strict,
): string {
  const { failRows, undeterminedBlockingRows } = protectPreflightBlockingRows(report, strict);
  const parts: string[] = [];
  if (failRows.length > 0) {
    parts.push(`FAIL: ${failRows.map((candidate) => candidate.check).join(", ")}`);
  }
  if (undeterminedBlockingRows.length > 0) {
    parts.push(
      `UNDETERMINED, which --strict also blocks on: ${undeterminedBlockingRows.map((candidate) => candidate.check).join(", ")}`,
    );
  }
  return parts.join("; ");
}

export function renderProtectPreflightJson(report: ProtectPreflightReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function renderProtectPreflightReport(report: ProtectPreflightReport): string {
  const rows = report.rows.map((row) => [
    row.status,
    row.check,
    row.state,
    row.detail,
    row.remedy,
  ]);
  const headers = ["Status", "Check", "State", "Detail", "Remedy"];
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => sanitizeCell(row[index] ?? "").length)),
  );
  const renderRow = (cells: string[]): string =>
    `| ${cells.map((cell, index) => sanitizeCell(cell).padEnd(widths[index] ?? 0)).join(" | ")} |`;
  const divider = `| ${widths.map((width) => "-".repeat(width)).join(" | ")} |`;
  return [
    "Sanctuary protect preflight (read-only)",
    `Summary: PASS ${report.summary.pass}, FAIL ${report.summary.fail}, UNDETERMINED ${report.summary.undetermined}`,
    renderRow(headers),
    divider,
    ...rows.map(renderRow),
    "",
  ].join("\n");
}

async function defaultExecFile(cmd: string, args: string[]): Promise<ExecFileResult> {
  try {
    const result = await execFileAsync(cmd, args, {
      encoding: "utf8",
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
    });
    return {
      code: 0,
      stdout: String(result.stdout ?? ""),
      stderr: String(result.stderr ?? ""),
    };
  } catch (err) {
    const error = err as NodeJS.ErrnoException & {
      stdout?: unknown;
      stderr?: unknown;
      signal?: unknown;
      killed?: unknown;
    };
    return {
      code: typeof error.code === "number" ? error.code : 1,
      stdout: String(error.stdout ?? ""),
      stderr: String(error.stderr ?? error.message ?? ""),
      errorCode: typeof error.code === "string" ? error.code : undefined,
      signal: typeof error.signal === "string" ? error.signal : undefined,
      // A timeout/maxBuffer kill reports code:null (neither a number nor a
      // string), so it falls through to code:1 above with no errorCode --
      // `killed` is what actually distinguishes it from a genuine exit 1.
      killed: typeof error.killed === "boolean" ? error.killed : undefined,
    };
  }
}

async function defaultEntry(path: string): Promise<FsEntry> {
  try {
    const stat = await lstat(path);
    return {
      kind: "present",
      isFile: stat.isFile(),
      isDirectory: stat.isDirectory(),
      isSymbolicLink: stat.isSymbolicLink(),
    };
  } catch (err) {
    const code = errorCode(err);
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return {
      kind: "unknown",
      reason: safeErrorReason(err),
      code,
    };
  }
}

async function defaultOwner(
  path: string,
): Promise<
  | { ok: true; uid: number; gid: number }
  | { ok: false; reason: string; code?: string }
> {
  try {
    const stats = await lstat(path);
    return { ok: true, uid: stats.uid, gid: stats.gid };
  } catch (err) {
    return {
      ok: false,
      reason: safeErrorReason(err),
      code: errorCode(err),
    };
  }
}

async function defaultAccess(path: string, kind: AccessKind): Promise<AccessResult> {
  const mode = kind === "execute" ? fsConstants.X_OK : fsConstants.R_OK;
  try {
    await access(path, mode);
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: safeErrorReason(err),
      code: errorCode(err),
    };
  }
}

async function defaultReadText(path: string): Promise<{ ok: true; text: string } | { ok: false; reason: string; code?: string }> {
  try {
    const text = await readFile(path, "utf8");
    return { ok: true, text };
  } catch (err) {
    return {
      ok: false,
      reason: safeErrorReason(err),
      code: errorCode(err),
    };
  }
}

async function defaultReadDir(path: string): Promise<{ ok: true } | { ok: false; reason: string; code?: string }> {
  try {
    await readdir(path);
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: safeErrorReason(err),
      code: errorCode(err),
    };
  }
}

async function defaultReadFileSample(path: string): Promise<{ ok: true } | { ok: false; reason: string; code?: string }> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, "r");
    await handle.read(Buffer.alloc(1), 0, 1, 0);
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: safeErrorReason(err),
      code: errorCode(err),
    };
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function defaultFetch(
  url: string,
  request: ProviderHttpRequest,
): Promise<ProviderHttpResponse> {
  if (typeof fetch !== "function") {
    throw new Error("global fetch is unavailable");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PREFLIGHT_FETCH_TIMEOUT_MS);
  try {
    const init: Parameters<typeof fetch>[1] = {
      method: request.method,
      headers: request.headers,
      signal: controller.signal,
    };
    const response = await fetch(url, init);
    return { status: response.status };
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveOperatorContext(
  ops: ProtectPreflightOps,
  env: NodeJS.ProcessEnv,
): Promise<OperatorContext> {
  const sudoDecision = resolveSudoIdentityDecision(env);
  if (sudoDecision !== undefined) {
    if (sudoDecision.user === undefined) {
      return {
        uid: sudoDecision.uid,
        gid: sudoDecision.gid,
        reason: "sudo identity lacks SUDO_USER, so operator home cannot be resolved safely",
      };
    }
    const home = await lookupDarwinHome(ops, sudoDecision.user);
    return {
      uid: sudoDecision.uid,
      gid: sudoDecision.gid,
      user: sudoDecision.user,
      home: home.home,
      reason: home.reason,
    };
  }

  const uid = ops.getuid();
  if (uid === 0) {
    return {
      uid,
      reason:
        "running as root without a valid non-root sudo identity; refusing to infer the operator home from root",
    };
  }

  return {
    uid,
    home: ops.homeDir(),
  };
}

async function lookupDarwinHome(
  ops: ProtectPreflightOps,
  user: string,
): Promise<{ home?: string; reason?: string }> {
  const result = await ops.execFile("/usr/bin/dscl", [
    ".",
    "-read",
    `/Users/${user}`,
    "NFSHomeDirectory",
  ]);
  if (result.code !== 0) {
    return {
      reason: `dscl could not resolve ${user}'s home directory (${formatExecFailure(result)})`,
    };
  }
  const match = result.stdout.match(/NFSHomeDirectory:\s*(.+)/);
  const home = match?.[1]?.trim();
  if (!home) {
    return { reason: `dscl returned no NFSHomeDirectory for ${user}` };
  }
  return { home };
}

function resolvePreflightFortressPath(
  env: NodeJS.ProcessEnv,
  operatorHome?: string,
): string | undefined {
  const override = env.SANCTUARY_STORAGE_PATH ?? env.SANCTUARY_FORTRESS_PATH;
  if (override !== undefined && override.length > 0) return resolvePath(override);
  if (operatorHome !== undefined && operatorHome.length > 0) {
    return `${operatorHome.replace(/\/+$/, "")}/.sanctuary`;
  }
  return undefined;
}

function summarizeRows(rows: ProtectPreflightRow[]): ProtectPreflightSummary {
  return {
    pass: rows.filter((row) => row.status === "PASS").length,
    fail: rows.filter((row) => row.status === "FAIL").length,
    undetermined: rows.filter((row) => row.status === "UNDETERMINED").length,
  };
}

async function checkCastleSockHolder(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "Castle Wall protect preflight is defined for macOS arm/provision hosts.",
      remedy: "Run this preflight on the macOS host that will be armed.",
      findings: ["F-1"],
    });
  }
  if (context.fortressPath === undefined) {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "UNDETERMINED",
      state: "operator_home_unknown",
      detail: context.operator.reason ?? "Could not resolve the fortress path that owns castle.sock.",
      remedy: "Run from a normal sudo session so SUDO_USER/SUDO_UID/SUDO_GID resolve to the operator account.",
      findings: ["F-1"],
    });
  }

  const socketPath = resolveCastleWallSocketPath({
    platform: context.platform,
    fortressPath: context.fortressPath,
    homeDir: context.operator.home,
    explicitOverride: context.env.SANCTUARY_CASTLE_SOCKET,
  }).path;
  const socketEntry = await context.ops.entry(socketPath);
  if (socketEntry.kind === "absent") {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "PASS",
      state: "no_socket",
      detail: `No castle.sock exists at ${socketPath}.`,
      remedy: NO_REMEDY,
      findings: ["F-1"],
    });
  }
  if (socketEntry.kind === "unknown") {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "UNDETERMINED",
      state: "socket_stat_unknown",
      detail: `Could not inspect ${socketPath}: ${socketEntry.reason}.`,
      remedy: `Inspect the socket manually: lsof -nP -U ${socketPath}`,
      findings: ["F-1"],
    });
  }

  const lsof = await runLsof(context.ops, socketPath);
  if (lsof.kind === "unknown") {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "UNDETERMINED",
      state: "holder_probe_unknown",
      detail: `Could not run lsof for ${socketPath}: ${lsof.reason}.`,
      remedy: `Inspect the socket manually: lsof -nP -U ${socketPath}`,
      findings: ["F-1"],
    });
  }

  if (lsof.holders.length === 0) {
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "PASS",
      state: "no_live_holder",
      detail: `The socket exists at ${socketPath}, but no live holder was reported by lsof.`,
      remedy: NO_REMEDY,
      findings: ["F-1"],
    });
  }

  const safeMode = await classifySafeModeCastleDaemon(context, lsof.holders);
  if (safeMode.safe) {
    if (
      context.allowMatchingBootDaemon &&
      safeMode.source === "launchd" &&
      safeMode.fortressMatches
    ) {
      return row({
        id: "castle_sock_holder",
        check: "castle.sock holder",
        status: "PASS",
        state: "matching_launchd_safe_mode_boot_daemon",
        detail:
          `${holderList(lsof.holders)} holds ${socketPath}; launchd confirms the ` +
          "Castle Wall safe-mode boot daemon targets this fortress. The provisioning flow will re-verify it before arming.",
        remedy: NO_REMEDY,
        findings: ["F-1"],
      });
    }
    return row({
      id: "castle_sock_holder",
      check: "castle.sock holder",
      status: "FAIL",
      state: "launchd_safe_mode_boot_daemon",
      detail: `${holderList(lsof.holders)} holds ${socketPath}; launchd classifies it as the Castle Wall safe-mode boot daemon.`,
      remedy: `sudo launchctl bootout system/${CASTLE_WALL_BOOT_LABEL}`,
      findings: ["F-1"],
    });
  }

  return row({
    id: "castle_sock_holder",
    check: "castle.sock holder",
    status: "FAIL",
    state: "unknown_socket_holder",
    detail: `${holderList(lsof.holders)} holds ${socketPath}; ${safeMode.reason}`,
    remedy: `Stop the holder before arming. Inspect with: lsof -nP -U ${socketPath}`,
    findings: ["F-1"],
  });
}

async function runLsof(
  ops: ProtectPreflightOps,
  socketPath: string,
): Promise<{ kind: "ok"; holders: LsofHolder[] } | { kind: "unknown"; reason: string }> {
  let result = await ops.execFile("/usr/sbin/lsof", ["-nP", "-U", socketPath]);
  if (result.errorCode === "ENOENT") {
    result = await ops.execFile("lsof", ["-nP", "-U", socketPath]);
  }
  if (result.code !== 0 && result.stdout.trim() === "") {
    if (result.errorCode === "ENOENT") {
      return { kind: "unknown", reason: "lsof is not available on PATH or at /usr/sbin/lsof" };
    }
    return { kind: "ok", holders: [] };
  }
  return { kind: "ok", holders: parseLsofHolders(result.stdout, socketPath) };
}

interface LsofHolder {
  command: string;
  pid?: number;
  user?: string;
}

function parseLsofHolders(raw: string, socketPath: string): LsofHolder[] {
  const holders: LsofHolder[] = [];
  for (const line of raw.split(/\r?\n/).slice(1)) {
    if (!line.includes(socketPath)) continue;
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const pid = Number(parts[1]);
    holders.push({
      command: parts[0] ?? "unknown",
      pid: Number.isSafeInteger(pid) ? pid : undefined,
      user: parts[2],
    });
  }
  return holders;
}

async function classifySafeModeCastleDaemon(
  context: ProtectPreflightContext,
  holders: LsofHolder[],
): Promise<
  | { safe: true; source: "launchd"; fortressMatches: boolean }
  | { safe: true; source: "active-config"; fortressMatches: false }
  | { safe: false; reason: string }
> {
  const holderPids = new Set(
    holders
      .map((holder) => holder.pid)
      .filter((pid): pid is number => pid !== undefined),
  );
  const launchd = await context.ops.execFile("launchctl", [
    "print",
    `system/${CASTLE_WALL_BOOT_LABEL}`,
  ]);
  if (launchd.code === 0) {
    const pid = parseLaunchctlPid(launchd.stdout);
    if (pid !== undefined && holderPids.has(pid)) {
      return {
        safe: true,
        source: "launchd",
        fortressMatches:
          context.fortressPath !== undefined &&
          parseLaunchctlFortressPath(launchd.stdout) ===
            resolvePath(context.fortressPath),
      };
    }
  }

  for (const path of [
    CASTLE_WALL_ACTIVE_CONFIG_PATH,
    CASTLE_WALL_ACTIVE_CONFIG_LEGACY_PATH,
  ]) {
    const config = await context.ops.readText(path);
    if (!config.ok) continue;
    const active = parseActiveCastleConfig(config.text);
    if (active?.mode === "safe" && active.pid !== undefined && holderPids.has(active.pid)) {
      // Active-config holders never qualify for the automatic-retry allowance.
      return { safe: true, source: "active-config", fortressMatches: false };
    }
  }

  return {
    safe: false,
    reason:
      launchd.code === 0
        ? `launchd job ${CASTLE_WALL_BOOT_LABEL} is loaded but did not match the holder pid`
        : `launchd job ${CASTLE_WALL_BOOT_LABEL} was not confirmed (${formatExecFailure(launchd)})`,
  };
}

function parseLaunchctlFortressPath(raw: string): string | undefined {
  const match =
    /"?SANCTUARY_STORAGE_PATH"?\s*=>\s*"?([^\n"]+)"?/.exec(raw) ??
    /"?SANCTUARY_STORAGE_PATH"?\s*=\s*"?([^\n"]+)"?/.exec(raw);
  const value = match?.[1]?.trim().replace(/[;,]+$/, "");
  return value?.startsWith("/") ? resolvePath(value) : undefined;
}

function parseLaunchctlPid(raw: string): number | undefined {
  const match = raw.match(/\bpid\s*=\s*(\d+)/);
  if (!match?.[1]) return undefined;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) ? pid : undefined;
}

function parseActiveCastleConfig(raw: string): { pid?: number; mode?: string } | undefined {
  try {
    const parsed = JSON.parse(raw) as { pid?: unknown; mode?: unknown };
    return {
      pid: typeof parsed.pid === "number" && Number.isSafeInteger(parsed.pid)
        ? parsed.pid
        : undefined,
      mode: typeof parsed.mode === "string" ? parsed.mode : undefined,
    };
  } catch {
    return undefined;
  }
}

function holderList(holders: LsofHolder[]): string {
  return holders
    .map((holder) => {
      const pid = holder.pid === undefined ? "pid unknown" : `pid ${holder.pid}`;
      const user = holder.user === undefined ? "" : ` user ${holder.user}`;
      return `${holder.command} (${pid}${user})`;
    })
    .join(", ");
}

const REPAIR_CUSTODY_REMEDY = "Run: sudo sanctuary castle-wall repair-custody";

/**
 * Fortress-custody row (fortress-ownership spec 2026-07-30 §4(a2)(2)): FAIL
 * when the fortress exists and its owner is not the resolved operator --
 * LOUDLY when the owner is uid 0 (the Mini2 state: enforcement fine, every
 * operator surface dark, the dead-man lever unable to reach castle.sock).
 * An absent fortress is a PASS (protect creates it, and the euid-0 flows'
 * custody-normalize chokepoint hands it to the operator).
 */
async function checkFortressCustody(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "fortress_custody",
      check: "fortress custody",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "Fortress-ownership preflight is defined for macOS arm/provision hosts.",
      remedy: "Run this preflight on the macOS host that will be armed.",
      findings: ["F-13"],
    });
  }
  if (context.fortressPath === undefined || context.operator.uid === undefined) {
    return row({
      id: "fortress_custody",
      check: "fortress custody",
      status: "UNDETERMINED",
      state: "operator_identity_unknown",
      detail:
        context.operator.reason ??
        "Could not resolve the operator identity or fortress path for the custody check.",
      remedy:
        "Run from a normal sudo session so SUDO_USER/SUDO_UID/SUDO_GID resolve to the operator account.",
      findings: ["F-13"],
    });
  }

  const owner = await context.ops.owner(context.fortressPath);
  if (!owner.ok) {
    if (isAbsentCode(owner.code)) {
      return row({
        id: "fortress_custody",
        check: "fortress custody",
        status: "PASS",
        state: "no_fortress",
        detail: `No fortress exists at ${context.fortressPath} yet; protect will create it operator-owned.`,
        remedy: NO_REMEDY,
        findings: ["F-13"],
      });
    }
    return row({
      id: "fortress_custody",
      check: "fortress custody",
      status: "UNDETERMINED",
      state: "owner_probe_unknown",
      detail: `Could not stat ${context.fortressPath}: ${owner.reason}.`,
      remedy: `Inspect the fortress owner manually: stat -f '%Su %u' ${context.fortressPath}`,
      findings: ["F-13"],
    });
  }

  if (owner.uid === context.operator.uid) {
    return row({
      id: "fortress_custody",
      check: "fortress custody",
      status: "PASS",
      state: "operator_owned",
      detail: `The fortress at ${context.fortressPath} is owned by the operator (uid ${owner.uid}).`,
      remedy: NO_REMEDY,
      findings: ["F-13"],
    });
  }
  if (owner.uid === 0) {
    return row({
      id: "fortress_custody",
      check: "fortress custody",
      status: "FAIL",
      state: "root_owned_fortress",
      detail:
        `The fortress at ${context.fortressPath} is owned by ROOT (uid 0). The operator cannot read their own state, ` +
        "operator status surfaces are blind (connect EACCES), and the 'disable' dead-man lever cannot reach castle.sock. " +
        "Arming refuses in this state.",
      remedy: REPAIR_CUSTODY_REMEDY,
      findings: ["F-13"],
    });
  }
  return row({
    id: "fortress_custody",
    check: "fortress custody",
    status: "FAIL",
    state: "owner_mismatch",
    detail: `The fortress at ${context.fortressPath} is owned by uid ${owner.uid}, not the resolved operator (uid ${context.operator.uid}).`,
    remedy: REPAIR_CUSTODY_REMEDY,
    findings: ["F-13"],
  });
}

async function checkRootPathSanctuary(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.sealedLauncherPath !== undefined) {
    if (context.sealedLauncherPath !== CASTLE_WALL_SEALED_LAUNCHER) {
      return row({
        id: "root_path_sanctuary",
        check: "sanctuary entrypoint",
        status: "FAIL",
        state: "sealed_launcher_noncanonical",
        detail: `The requested sealed launcher is not the canonical app path (${CASTLE_WALL_SEALED_LAUNCHER}).`,
        remedy:
          "Rerun the agent-guided installer so it supplies the canonical signed-app launcher.",
        findings: ["F-2"],
      });
    }
    const executable = await context.ops.access(context.sealedLauncherPath, "execute");
    if (executable.ok) {
      return row({
        id: "root_path_sanctuary",
        check: "sanctuary entrypoint",
        status: "PASS",
        state: "canonical_sealed_launcher",
        detail: `The canonical app launcher is executable at ${context.sealedLauncherPath}; this install has no root PATH dependency.`,
        remedy: NO_REMEDY,
        findings: ["F-2"],
      });
    }
    if (isAbsentCode(executable.code)) {
      return row({
        id: "root_path_sanctuary",
        check: "sanctuary entrypoint",
        status: "FAIL",
        state: "sealed_launcher_not_executable",
        detail: `The canonical app launcher is not executable at ${context.sealedLauncherPath}.`,
        remedy:
          "Reinstall the verified Sanctuary Castle Wall app, then rerun the agent-guided installer.",
        findings: ["F-2"],
      });
    }
    return row({
      id: "root_path_sanctuary",
      check: "sanctuary entrypoint",
      status: "UNDETERMINED",
      state: "sealed_launcher_probe_unknown",
      detail: `The canonical app launcher could not be inspected: ${executable.reason}.`,
      remedy:
        "Verify the signed app is installed and executable, then rerun the agent-guided installer.",
      findings: ["F-2"],
    });
  }

  const pathValue = context.env.PATH;
  const legacyRemedy =
    "Run the agent-guided installer with the canonical signed-app launcher, or install the sanctuary bin into root's PATH for a source install.";
  if (pathValue === undefined || pathValue.trim() === "") {
    return row({
      id: "root_path_sanctuary",
      check: "root PATH sanctuary",
      status: "FAIL",
      state: "path_empty",
      detail: "PATH is empty in the current privilege context, so root cannot resolve the sanctuary bin.",
      remedy: legacyRemedy,
      findings: ["F-2"],
    });
  }

  const unknowns: string[] = [];
  for (const dir of pathValue.split(delimiter).filter((part) => part.length > 0)) {
    const candidate = join(dir, "sanctuary");
    const executable = await context.ops.access(candidate, "execute");
    if (executable.ok) {
      return row({
        id: "root_path_sanctuary",
        check: "root PATH sanctuary",
        status: "PASS",
        state: "resolved",
        detail: `sanctuary resolves as an executable at ${candidate}.`,
        remedy: NO_REMEDY,
        findings: ["F-2"],
      });
    }
    if (!isAbsentCode(executable.code)) {
      unknowns.push(`${candidate}: ${executable.reason}`);
    }
  }

  if (unknowns.length > 0) {
    return row({
      id: "root_path_sanctuary",
      check: "root PATH sanctuary",
      status: "UNDETERMINED",
      state: "path_probe_unknown",
      detail: `No sanctuary bin was found, and some PATH entries could not be inspected: ${unknowns.join("; ")}.`,
      remedy: `Resolve the PATH permissions. ${legacyRemedy}`,
      findings: ["F-2"],
    });
  }

  return row({
    id: "root_path_sanctuary",
    check: "root PATH sanctuary",
    status: "FAIL",
    state: "not_found",
    detail: "No executable named sanctuary was found in the current privilege context's PATH.",
    remedy: legacyRemedy,
    findings: ["F-2"],
  });
}

async function checkSignerClient(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "signer_client",
      check: "signer client",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "The Castle Wall signer-client helper is only meaningful on the macOS arm path.",
      remedy: "Run this preflight on the macOS host that will be armed.",
      findings: ["F-3"],
    });
  }

  const signerPath = context.env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (signerPath === undefined || signerPath.trim() === "") {
    return row({
      id: "signer_client",
      check: "signer client",
      status: "FAIL",
      state: "env_missing",
      detail: "SANCTUARY_CASTLE_SIGNER_CLIENT is not set; arm would degrade to wrapped-but-not-armed.",
      remedy:
        "Export SANCTUARY_CASTLE_SIGNER_CLIENT to the signed host-app helper path and make sure it is executable.",
      findings: ["F-3"],
    });
  }

  const executable = await context.ops.access(signerPath, "execute");
  if (executable.ok) {
    return row({
      id: "signer_client",
      check: "signer client",
      status: "PASS",
      state: "executable",
      detail: `SANCTUARY_CASTLE_SIGNER_CLIENT points at an executable helper (${signerPath}).`,
      remedy: NO_REMEDY,
      findings: ["F-3"],
    });
  }
  if (isAbsentCode(executable.code)) {
    return row({
      id: "signer_client",
      check: "signer client",
      status: "FAIL",
      state: "not_found",
      detail: `SANCTUARY_CASTLE_SIGNER_CLIENT points at ${signerPath}, but that path does not exist.`,
      remedy:
        "Install the Castle Wall host app helper and export SANCTUARY_CASTLE_SIGNER_CLIENT to its signer-client binary.",
      findings: ["F-3"],
    });
  }
  if (executable.code === "EACCES" || executable.code === "EPERM") {
    return row({
      id: "signer_client",
      check: "signer client",
      status: "FAIL",
      state: "not_executable",
      detail: `SANCTUARY_CASTLE_SIGNER_CLIENT points at ${signerPath}, but it is not executable (${executable.reason}).`,
      remedy: `Make the helper executable: chmod +x ${signerPath}`,
      findings: ["F-3"],
    });
  }
  return row({
    id: "signer_client",
    check: "signer client",
    status: "UNDETERMINED",
    state: "executable_probe_unknown",
    detail: `Could not determine whether ${signerPath} is executable: ${executable.reason}.`,
    remedy:
      "Inspect the helper permissions and export SANCTUARY_CASTLE_SIGNER_CLIENT to an executable signer-client binary.",
    findings: ["F-3"],
  });
}

async function checkSysextApproval(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "sysext_approval",
      check: "sysext approval",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "systemextensionsctl is only available on the macOS arm path.",
      remedy: "Run this preflight on the macOS host that will be armed.",
      findings: ["F-5"],
    });
  }

  const result = await context.ops.execFile("systemextensionsctl", ["list"]);
  if (result.code !== 0) {
    return row({
      id: "sysext_approval",
      check: "sysext approval",
      status: "UNDETERMINED",
      state: "systemextensionsctl_failed",
      detail: `Could not read system extension state: ${formatExecFailure(result)}.`,
      remedy: "Run systemextensionsctl list locally and approve the Castle Wall system extension if macOS prompts.",
      findings: ["F-5"],
    });
  }

  const state = parseCastleWallState(result.stdout);
  return sysextRowForState(state);
}

function sysextRowForState(state: SysextState): ProtectPreflightRow {
  if (state === "[activated enabled]") {
    return row({
      id: "sysext_approval",
      check: "sysext approval",
      status: "PASS",
      state,
      detail: "Castle Wall system extension is activated and enabled.",
      remedy: NO_REMEDY,
      findings: ["F-5"],
    });
  }
  if (state === "[activated waiting for user]") {
    return row({
      id: "sysext_approval",
      check: "sysext approval",
      status: "FAIL",
      state,
      detail: "Castle Wall system extension is activated but waiting for user approval; arm will trigger the System Settings prompt.",
      remedy: "Open System Settings > Privacy & Security and approve the Castle Wall system extension before arming.",
      findings: ["F-5"],
    });
  }
  if (state === "[activated disabled]") {
    return row({
      id: "sysext_approval",
      check: "sysext approval",
      status: "FAIL",
      state,
      detail: "Castle Wall system extension is installed but disabled.",
      remedy: "Re-enable the Castle Wall system extension in System Settings before arming.",
      findings: ["F-5"],
    });
  }
  return row({
    id: "sysext_approval",
    check: "sysext approval",
    status: "FAIL",
    state,
    detail: "Castle Wall system extension is not loaded.",
    remedy: "Install and approve the Castle Wall system extension before arming.",
    findings: ["F-5"],
  });
}

async function checkFullDiskAccess(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "full_disk_access",
      check: "Full Disk Access",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "Full Disk Access vault probes are only meaningful on macOS.",
      remedy: "Run this preflight on the macOS host whose data vault will be re-homed.",
      findings: ["F-4"],
    });
  }
  if (context.operator.home === undefined) {
    return row({
      id: "full_disk_access",
      check: "Full Disk Access",
      status: "UNDETERMINED",
      state: "operator_home_unknown",
      detail: context.operator.reason ?? "Could not resolve the operator home for the TCC vault probe.",
      remedy: "Run from a normal sudo session so the operator home can be resolved before re-home.",
      findings: ["F-4"],
    });
  }

  const outcomes: string[] = [];
  let sawDenied = false;
  let sawUnknown = false;
  let sawReadable = false;
  for (const relPath of FULL_DISK_ACCESS_PROBE_RELPATHS) {
    const fullPath = join(context.operator.home, relPath);
    const entry = await context.ops.entry(fullPath);
    if (entry.kind === "absent") {
      outcomes.push(`${fullPath}: absent`);
      sawUnknown = true;
      continue;
    }
    if (entry.kind === "unknown") {
      outcomes.push(`${fullPath}: ${entry.reason}`);
      sawUnknown = true;
      continue;
    }
    const probe = entry.isDirectory
      ? await context.ops.readDir(fullPath)
      : await context.ops.readFileSample(fullPath);
    if (probe.ok) {
      outcomes.push(`${fullPath}: readable`);
      sawReadable = true;
      continue;
    }
    outcomes.push(`${fullPath}: ${probe.reason}`);
    if (probe.code === "EACCES" || probe.code === "EPERM") {
      sawDenied = true;
    } else {
      sawUnknown = true;
    }
  }

  if (sawDenied) {
    return row({
      id: "full_disk_access",
      check: "Full Disk Access",
      status: "FAIL",
      state: "full_disk_access_denied",
      detail: outcomes.join("; "),
      remedy: "Grant Full Disk Access to the terminal or host app that runs sanctuary protect, then rerun preflight.",
      findings: ["F-4"],
    });
  }
  if (sawReadable && !sawUnknown) {
    return row({
      id: "full_disk_access",
      check: "Full Disk Access",
      status: "PASS",
      state: "vault_readable",
      detail: outcomes.join("; "),
      remedy: NO_REMEDY,
      findings: ["F-4"],
    });
  }
  return row({
    id: "full_disk_access",
    check: "Full Disk Access",
    status: "UNDETERMINED",
    state: "vault_probe_unknown",
    detail: outcomes.join("; "),
    remedy:
      "Verify Full Disk Access for the terminal or host app before re-home; this preflight could not prove vault readability.",
    findings: ["F-4"],
  });
}

async function checkProviderLiveness(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  const discovery = await discoverConfiguredProviders(context);
  if (discovery.providers.length === 0) {
    return row({
      id: "provider_liveness",
      check: "provider liveness",
      status: "UNDETERMINED",
      state: "no_configured_provider",
      detail:
        discovery.readErrors.length === 0
          ? "No supported provider credentials were found in the operator environment or Hermes config files."
          : `No supported provider credentials were found; some config files were unreadable: ${discovery.readErrors.join("; ")}.`,
      remedy:
        "Configure a supported provider credential before arming, or verify provider liveness manually from the operator side.",
      findings: ["F-12"],
    });
  }

  const providerRows: ProtectPreflightProviderDetail[] = [];
  for (const configured of discovery.providers) {
    providerRows.push(await probeProvider(context.ops, configured));
  }

  const failures = providerRows.filter((provider) => provider.status === "FAIL");
  const unknowns = providerRows.filter((provider) => provider.status === "UNDETERMINED");
  if (failures.length > 0) {
    const billingDead = failures.filter((provider) => provider.state === BILLING_DEAD_STATE);
    return row({
      id: "provider_liveness",
      check: "provider liveness",
      status: "FAIL",
      state: billingDead.length > 0 ? BILLING_DEAD_STATE : "provider_unhealthy",
      detail: providerRows.map(formatProviderDetail).join("; "),
      remedy:
        billingDead.length > 0
          ? `Restore billing for ${billingDead.map((provider) => provider.provider).join(", ")} before arming Castle Wall.`
          : "Refresh provider credentials or restore operator-side provider reachability before arming Castle Wall.",
      findings: ["F-12"],
      providers: providerRows,
    });
  }
  if (unknowns.length > 0) {
    return row({
      id: "provider_liveness",
      check: "provider liveness",
      status: "UNDETERMINED",
      state: "provider_probe_unknown",
      detail: providerRows.map(formatProviderDetail).join("; "),
      remedy:
        "Verify each configured provider from the operator account before arming Castle Wall.",
      findings: ["F-12"],
      providers: providerRows,
    });
  }
  return row({
    id: "provider_liveness",
    check: "provider liveness",
    status: "PASS",
    state: "all_configured_providers_live",
    detail: providerRows.map(formatProviderDetail).join("; "),
    remedy: NO_REMEDY,
    findings: ["F-12"],
    providers: providerRows,
  });
}

async function discoverConfiguredProviders(
  context: ProtectPreflightContext,
): Promise<{ providers: ConfiguredProvider[]; readErrors: string[] }> {
  const byProvider = new Map<string, ConfiguredProvider>();
  const readErrors: string[] = [];
  for (const definition of PROVIDERS) {
    for (const envName of definition.envNames) {
      const credential = normalizeCredential(context.env[envName]);
      if (credential !== undefined && !byProvider.has(definition.id)) {
        byProvider.set(definition.id, {
          definition,
          source: `env:${envName}`,
          credential,
        });
      }
    }
  }

  if (context.operator.home !== undefined) {
    for (const relPath of PROVIDER_CONFIG_RELPATHS) {
      const path = join(context.operator.home, relPath);
      const read = await context.ops.readText(path);
      if (!read.ok) {
        if (!isAbsentCode(read.code)) readErrors.push(`${path}: ${read.reason}`);
        continue;
      }
      for (const definition of PROVIDERS) {
        if (byProvider.has(definition.id)) continue;
        for (const envName of definition.envNames) {
          const credential = normalizeCredential(extractCredential(read.text, envName));
          if (credential === undefined) continue;
          byProvider.set(definition.id, {
            definition,
            source: `${path}:${envName}`,
            credential,
          });
          break;
        }
      }
    }
  }

  return { providers: [...byProvider.values()], readErrors };
}

function normalizeCredential(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  const lower = trimmed.toLowerCase();
  if (["changeme", "change-me", "todo", "placeholder", "none", "null"].includes(lower)) {
    return undefined;
  }
  return trimmed;
}

function extractCredential(raw: string, key: string): string | undefined {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `(?:^|[\\n\\r,{\\s])["']?${escaped}["']?\\s*(?:=|:)\\s*["']?([^"',#}\\s]+)`,
    "i",
  );
  return raw.match(pattern)?.[1];
}

// rule 7: a row may claim only what the evidence proves. Reachability alone
// (a success response to the configured credential) is not evidence of
// validity; only a genuine rejection of a known-wrong credential at the same
// endpoint is. Where an endpoint cannot produce that evidence, the honest
// bound is UNDETERMINED -- "reachable, not verifiable" -- never a PASS.
//
// defect.preflight-provider-liveness-probe-not-authenticated
async function probeProvider(
  ops: ProtectPreflightOps,
  configured: ConfiguredProvider,
): Promise<ProtectPreflightProviderDetail> {
  try {
    const request = configured.definition.buildRequest(configured.credential);
    const response = await ops.fetch(request.url, request.request);
    if (response.status >= 200 && response.status < 300) {
      const discrimination = await probeCredentialDiscrimination(
        ops,
        configured.definition,
      );
      if (discrimination.kind === "rejected") {
        return {
          provider: configured.definition.label,
          source: configured.source,
          status: "PASS",
          state: "live",
          detail: "the provider rejected an invalid credential at this endpoint, so the configured credential's success reflects a real check",
          reachableUnverifiable: false,
        };
      }
      if (discrimination.kind === "not_discriminating") {
        return {
          provider: configured.definition.label,
          source: configured.source,
          status: "UNDETERMINED",
          state: "credential_not_verifiable",
          detail:
            "provider endpoint reachable; credential validity not verifiable at the available endpoint (it accepted an invalid credential too)",
          // The 2xx above already proved this endpoint is reachable; the
          // endpoint itself, not a probe failure, is why validity can't be
          // proven -- the reachable-unverifiable shape strict-arm allows.
          reachableUnverifiable: true,
        };
      }
      if (discrimination.kind === "inconclusive") {
        return {
          provider: configured.definition.label,
          source: configured.source,
          status: "UNDETERMINED",
          state: "credential_discrimination_inconclusive",
          detail:
            "provider endpoint reachable; credential validity not verifiable at the available endpoint (the invalid-credential probe did not return a recognized rejection)",
          reachableUnverifiable: true,
        };
      }
      return {
        provider: configured.definition.label,
        source: configured.source,
        status: "UNDETERMINED",
        state: "credential_discrimination_probe_failed",
        detail: `provider endpoint reachable; credential validity not verifiable at the available endpoint (the follow-up probe could not complete: ${discrimination.reason})`,
        // The configured credential's own request already returned 2xx, so
        // the endpoint is proven reachable even though the follow-up probe
        // itself could not run.
        reachableUnverifiable: true,
      };
    }
    if (response.status === 402) {
      return {
        provider: configured.definition.label,
        source: configured.source,
        status: "FAIL",
        state: BILLING_DEAD_STATE,
        detail: "provider returned HTTP 402 billing_dead",
        reachableUnverifiable: false,
      };
    }
    const state =
      response.status === 401 || response.status === 403
        ? "auth_failed"
        : `http_${response.status}`;
    return {
      provider: configured.definition.label,
      source: configured.source,
      status: "FAIL",
      state,
      detail: `provider returned HTTP ${response.status}`,
      reachableUnverifiable: false,
    };
  } catch (err) {
    return {
      provider: configured.definition.label,
      source: configured.source,
      status: "FAIL",
      state: "network_error",
      detail: `operator-side provider probe failed (${safeProviderError(err)})`,
      // The request itself never completed, so this is the unreachable
      // case, not the reachable-but-unverifiable one.
      reachableUnverifiable: false,
    };
  }
}

type CredentialDiscrimination =
  | { kind: "rejected"; status: number }
  | { kind: "not_discriminating" }
  | { kind: "inconclusive"; status: number }
  | { kind: "probe_failed"; reason: string };

/**
 * Re-probe the same provider endpoint with a credential guaranteed to be
 * wrong, applied uniformly to every provider descriptor so an unverified
 * provider degrades to UNDETERMINED rather than a false PASS. Only a
 * genuine authentication-rejection status counts as proof the credential
 * was checked; any other non-success status is not evidence of that and is
 * treated as inconclusive.
 *
 * defect.preflight-provider-liveness-probe-not-authenticated
 */
async function probeCredentialDiscrimination(
  ops: ProtectPreflightOps,
  definition: ProviderDefinition,
): Promise<CredentialDiscrimination> {
  try {
    const probeRequest = definition.buildRequest(definition.invalidCredentialProbe);
    const response = await ops.fetch(probeRequest.url, probeRequest.request);
    if (response.status >= 200 && response.status < 300) {
      return { kind: "not_discriminating" };
    }
    if (response.status === 401 || response.status === 403) {
      return { kind: "rejected", status: response.status };
    }
    return { kind: "inconclusive", status: response.status };
  } catch (err) {
    return { kind: "probe_failed", reason: safeProviderError(err) };
  }
}

function formatProviderDetail(provider: ProtectPreflightProviderDetail): string {
  return `${provider.provider}: ${provider.state} (${provider.detail}; source ${provider.source})`;
}

async function checkOperatorTwinServices(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "operator_twin_services",
      check: "operator twin services",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "LaunchAgent contention checks are only meaningful on macOS.",
      remedy: "Run this preflight on the macOS host whose Hermes gateway will be re-homed.",
      findings: ["F-10"],
    });
  }
  if (context.operator.home === undefined || context.operator.uid === undefined) {
    return row({
      id: "operator_twin_services",
      check: "operator twin services",
      status: "UNDETERMINED",
      state: "operator_identity_unknown",
      detail: context.operator.reason ?? "Could not resolve the operator uid/home for LaunchAgent inspection.",
      remedy: "Run from a normal sudo session so the operator uid and home can be resolved before re-home.",
      findings: ["F-10"],
    });
  }

  const plist = join(context.operator.home, "Library/LaunchAgents", `${HERMES_GATEWAY_LABEL}.plist`);
  const findings: string[] = [];
  const unknowns: string[] = [];
  const plistEntry = await context.ops.entry(plist);
  if (plistEntry.kind === "present") {
    findings.push(`plist exists at ${plist}`);
  } else if (plistEntry.kind === "unknown") {
    unknowns.push(`${plist}: ${plistEntry.reason}`);
  }

  const serviceName = `gui/${context.operator.uid}/${HERMES_GATEWAY_LABEL}`;
  const launchctl = await context.ops.execFile("launchctl", ["print", serviceName]);
  if (launchctl.code === 0) {
    findings.push(`LaunchAgent is loaded as ${serviceName}`);
  } else if (!launchctlMissingService(launchctl)) {
    unknowns.push(`launchctl print ${serviceName}: ${formatExecFailure(launchctl)}`);
  }

  const ps = await runPs(context.ops);
  if (ps.kind === "ok") {
    const running = parseHermesGatewayProcesses(ps.stdout, context.operator.uid);
    findings.push(...running.map((proc) => `process pid ${proc.pid} uid ${proc.uid}: ${proc.command}`));
  } else {
    unknowns.push(ps.reason);
  }

  const stopDisablePlan =
    `launchctl bootout gui/${context.operator.uid} ${plist}; launchctl disable gui/${context.operator.uid}/${HERMES_GATEWAY_LABEL}`;
  if (findings.length > 0) {
    return row({
      id: "operator_twin_services",
      check: "operator twin services",
      status: "FAIL",
      state: "operator_gateway_would_contend",
      detail: findings.join("; "),
      remedy: `Plan only, not executed by preflight: ${stopDisablePlan}`,
      findings: ["F-10"],
    });
  }
  if (unknowns.length > 0) {
    return row({
      id: "operator_twin_services",
      check: "operator twin services",
      status: "UNDETERMINED",
      state: "twin_probe_unknown",
      detail: unknowns.join("; "),
      remedy: `Verify no operator Hermes gateway is loaded; if found, use: ${stopDisablePlan}`,
      findings: ["F-10"],
    });
  }
  return row({
    id: "operator_twin_services",
    check: "operator twin services",
    status: "PASS",
    state: "no_operator_gateway",
    detail: `No ${HERMES_GATEWAY_LABEL} LaunchAgent plist, launchd job, or gateway process was found for uid ${context.operator.uid}.`,
    remedy: NO_REMEDY,
    findings: ["F-10"],
  });
}

async function runPs(
  ops: ProtectPreflightOps,
): Promise<{ kind: "ok"; stdout: string } | { kind: "unknown"; reason: string }> {
  let result = await ops.execFile("/bin/ps", ["-axo", "uid,pid,command"]);
  if (result.errorCode === "ENOENT") {
    result = await ops.execFile("ps", ["-axo", "uid,pid,command"]);
  }
  if (result.code !== 0) {
    return { kind: "unknown", reason: `ps probe failed: ${formatExecFailure(result)}` };
  }
  return { kind: "ok", stdout: result.stdout };
}

function parseHermesGatewayProcesses(
  raw: string,
  uid: number,
): { uid: number; pid: number; command: string }[] {
  const matches: { uid: number; pid: number; command: string }[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/);
    if (!match?.[1] || !match[2] || !match[3]) continue;
    const rowUid = Number(match[1]);
    const pid = Number(match[2]);
    if (rowUid !== uid || !Number.isSafeInteger(pid)) continue;
    const command = match[3];
    if (command.includes(HERMES_GATEWAY_PROCESS_MARKER) || command.includes(HERMES_GATEWAY_LABEL)) {
      matches.push({ uid: rowUid, pid, command });
    }
  }
  return matches;
}

function launchctlMissingService(result: ExecFileResult): boolean {
  const combined = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return (
    result.code !== 0 &&
    (combined.includes("could not find service") ||
      combined.includes("no such process") ||
      combined.includes("service is not loaded"))
  );
}

const XCODE_SELECT_PATH = "/usr/bin/xcode-select";
const OTOOL_PATH = "/usr/bin/otool";
// A binary guaranteed present on any macOS host, safe to inspect read-only
// (no side effects), used only as an otool target -- never executed.
const OTOOL_PROBE_TARGET = "/bin/ls";
// Must match the developer-tools dependency in castle-wall-boot-runtime.ts:
// installBootRuntimeSnapshot() calls verifySystemOnlyDynamicLibraries(),
// which shells out to otool -L.
//
// defect.boot-installer-requires-devtools-unchecked-by-preflight
const XCODE_CLT_REMEDY = "Run: xcode-select --install";

/**
 * FAIL when the Castle Wall boot-runtime install's otool-based
 * dynamic-library inspection would hit a missing or broken Command Line
 * Tools dependency, so a cold operator learns the gap here (read-only)
 * instead of mid-install. This preflight only detects the gap; removing the
 * otool dependency from the installer is a separate, larger change.
 */
async function checkBootRuntimeDevTools(
  context: ProtectPreflightContext,
): Promise<ProtectPreflightRow> {
  if (context.platform !== "darwin") {
    return row({
      id: "boot_runtime_devtools",
      check: "boot runtime devtools",
      status: "UNDETERMINED",
      state: "not_darwin",
      detail: "The Castle Wall boot-runtime install's otool dependency is only meaningful on macOS.",
      remedy: "Run this preflight on the macOS host that will install the boot runtime.",
      findings: ["F-14"],
    });
  }

  const xcodeSelect = await context.ops.execFile(XCODE_SELECT_PATH, ["-p"]);
  if (!(xcodeSelect.code === 0 && xcodeSelect.stdout.trim().length > 0)) {
    // xcode-select ran and reported no active developer directory (its real
    // exit shape when Command Line Tools are absent) -- a genuine, confirmed
    // FAIL, distinct from the probe itself failing to run OR being killed
    // (a timeout/maxBuffer kill reports no errorCode but sets signal/killed,
    // and proves nothing about xcode-select's own outcome).
    if (!execProbeWasInconclusive(xcodeSelect)) {
      return row({
        id: "boot_runtime_devtools",
        check: "boot runtime devtools",
        status: "FAIL",
        state: "developer_tools_missing",
        detail:
          `Command Line Tools are not installed (xcode-select -p: ${formatExecFailure(xcodeSelect)}); ` +
          "the Castle Wall boot-runtime install shells out to otool -L and will fail mid-mutation without them.",
        remedy: XCODE_CLT_REMEDY,
        findings: ["F-14"],
      });
    }
    // The probe itself could not run (e.g. xcode-select missing or blocked
    // outright) -- this preflight cannot distinguish "absent" from
    // "blocked", so it reports UNDETERMINED rather than a FAIL it cannot
    // back up.
    return row({
      id: "boot_runtime_devtools",
      check: "boot runtime devtools",
      status: "UNDETERMINED",
      state: "developer_tools_probe_unknown",
      detail: `Could not run xcode-select -p to check for Command Line Tools: ${formatExecFailure(xcodeSelect)}.`,
      remedy: "Run `xcode-select -p` manually and install Command Line Tools if it reports none.",
      findings: ["F-14"],
    });
  }

  // xcode-select reporting an active developer directory does not prove the
  // exact tool the boot-runtime install invokes still works: a partial or
  // stale toolchain can leave xcode-select pointed at a directory whose
  // otool is broken. Exercise otool -L itself, read-only, against a stable
  // system binary, before this row can PASS.
  const otoolProbe = await context.ops.execFile(OTOOL_PATH, ["-L", OTOOL_PROBE_TARGET]);
  const otoolProducedDependencyOutput =
    otoolProbe.code === 0 && /\(compatibility version/.test(otoolProbe.stdout);
  if (otoolProducedDependencyOutput) {
    return row({
      id: "boot_runtime_devtools",
      check: "boot runtime devtools",
      status: "PASS",
      state: "developer_tools_present",
      detail:
        `Command Line Tools are installed (active developer directory: ${xcodeSelect.stdout.trim()}) ` +
        `and otool -L ${OTOOL_PROBE_TARGET} produced dependency output; the boot-runtime install's otool dependency will resolve.`,
      remedy: NO_REMEDY,
      findings: ["F-14"],
    });
  }
  if (!execProbeWasInconclusive(otoolProbe)) {
    return row({
      id: "boot_runtime_devtools",
      check: "boot runtime devtools",
      status: "FAIL",
      state: "developer_tools_broken",
      detail:
        `xcode-select reports an active developer directory (${xcodeSelect.stdout.trim()}), but ` +
        `otool -L ${OTOOL_PROBE_TARGET} did not produce usable dependency output (${formatExecFailure(otoolProbe)}); ` +
        "the Castle Wall boot-runtime install shells out to this exact command and would fail mid-mutation.",
      remedy: XCODE_CLT_REMEDY,
      findings: ["F-14"],
    });
  }
  return row({
    id: "boot_runtime_devtools",
    check: "boot runtime devtools",
    status: "UNDETERMINED",
    state: "otool_probe_unknown",
    detail: `xcode-select reports an active developer directory, but otool -L could not be run to confirm it works: ${formatExecFailure(otoolProbe)}.`,
    remedy: `Run \`otool -L ${OTOOL_PROBE_TARGET}\` manually and reinstall Command Line Tools if it fails.`,
    findings: ["F-14"],
  });
}

function row(input: ProtectPreflightRow): ProtectPreflightRow {
  return input;
}

function sanitizeCell(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\r?\n/g, " ").replace(/\|/g, "\\|");
}

function isAbsentCode(code: string | undefined): boolean {
  return code === "ENOENT" || code === "ENOTDIR";
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error
    ? String((error as NodeJS.ErrnoException).code)
    : undefined;
}

function safeErrorReason(error: unknown): string {
  const code = errorCode(error);
  if (code !== undefined) return code;
  if (error instanceof Error) return error.name;
  return "unknown_error";
}

function safeProviderError(error: unknown): string {
  const code = errorCode(error);
  const name = error instanceof Error ? error.name : "unknown_error";
  return code === undefined ? name : `${name}:${code}`;
}

/**
 * True when a subprocess result cannot be read as the command's own
 * outcome: a spawn-level error (errorCode), a signal, or an explicit
 * `killed` flag all mean something outside the command's own logic ended
 * it (a timeout kill is exactly this shape: no errorCode, `signal` set).
 * A consumer must treat this as "the probe didn't run to a real result"
 * (UNDETERMINED), never as a confirmed pass or fail.
 */
function execProbeWasInconclusive(result: ExecFileResult): boolean {
  return result.errorCode !== undefined || result.signal !== undefined || result.killed === true;
}

function formatExecFailure(result: ExecFileResult): string {
  if (result.errorCode !== undefined) return result.errorCode;
  if (result.signal !== undefined) return `signal ${result.signal}`;
  const stderr = result.stderr.trim();
  return stderr.length > 0 ? stderr : `exit ${result.code}`;
}
