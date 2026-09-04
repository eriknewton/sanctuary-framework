import { execFile as nodeExecFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { Writable } from "node:stream";
import { promisify } from "node:util";
import { join, resolve } from "node:path";

import { resolveStoragePath } from "../paths.js";
import { getSanctuaryVersion } from "../version.js";
import { agentGuidedRecoveryOutputPath } from "../wrap/custody-flow.js";
import {
  probeExistingCustodyMaterial,
  readStoredPassphrase,
  PassphraseKeyringUnreachableError,
  PassphraseUnreadableError,
  type ExistingCustodyMaterialStatus,
} from "../wrap/passphrase.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  probeKernelBackedCrossProcessLockCapability,
  type KernelLockCapability,
} from "../storage/cross-process-lock.js";
import {
  CustodyCredentialMissingError,
  CustodyUnlockError,
  readCustodyEnvelope,
  unlockExistingMasterReadOnly,
} from "../core/master-custody.js";
import {
  readKeychainCustodyKeyStatus,
  type KeychainReadResult,
} from "../wrap/keychain-custody.js";
import {
  getPlatformPaths,
  hasExistingWrapMetaStrict,
} from "../wrap/config-reader.js";
import { runOperatorTwinPreflight } from "../wrap/preflight.js";
import {
  CASTLE_WALL_BOOT_PLIST_PATH,
  bootServicePlistPresent,
  bootServiceReady,
} from "./castle-wall-boot.js";
import { parseCastleWallState, runStatus, type SysextState } from "./castle-wall.js";

declare const __SANCTUARY_SOURCE_SHA__: string;

const execFileAsync = promisify(nodeExecFile);

export const AGENT_INSTALL_CONTRACT = "sanctuary.agent-install.v1";
// Must match DEFAULT_DEPLOY_DEST_APP in server/src/cli/castle-wall.ts (that
// module cannot import this one without a cycle): install observation and the
// deploy-preflight verb must name the same canonical bundle path.
export const DEFAULT_CASTLE_WALL_APP = "/Applications/Sanctuary-CastleWall.app";
export const DEFAULT_CASTLE_WALL_NODE = join(
  DEFAULT_CASTLE_WALL_APP,
  "Contents",
  "Resources",
  "boot-runtime",
  "node",
);
export const DEFAULT_CASTLE_WALL_CLI = join(
  DEFAULT_CASTLE_WALL_APP,
  "Contents",
  "Resources",
  "cli-runtime",
  "dist",
  "cli.js",
);
export const DEFAULT_CASTLE_WALL_LAUNCHER = join(
  DEFAULT_CASTLE_WALL_APP,
  "Contents",
  "MacOS",
  "sanctuary",
);
export const DEFAULT_CASTLE_WALL_RUNTIME_MANIFEST = join(
  DEFAULT_CASTLE_WALL_APP,
  "Contents",
  "Resources",
  "cli-runtime-manifest.json",
);
const INSTALLER_VERSION = getSanctuaryVersion();
// Must match CASTLE_WALL_SYSTEM_EXTENSION_TEAM_ID in castle-wall.ts and
// SignerConstants.teamID in castle-wall-macos/Sources/CastleWallSigner/SignerConstants.swift.
const CASTLE_WALL_TEAM_ID = "YFQSWQ9BJN";
const CASTLE_WALL_APP_IDENTIFIER = "ai.sanctuaryprotocol.macos";
const CASTLE_WALL_LAUNCHER_IDENTIFIER =
  "ai.sanctuaryprotocol.macos.castle-wall.sanctuary-launcher";
const CASTLE_WALL_HEADLESS_CONTRACT = "3";
const INSTALLER_SOURCE_SHA =
  typeof __SANCTUARY_SOURCE_SHA__ === "string" ? __SANCTUARY_SOURCE_SHA__ : null;
const CASTLE_WALL_SIGNER_CLIENT =
  "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client";

interface CastleWallRuntimeManifest {
  schema: string;
  source_sha: string;
  cli_version: string;
  node_version: string;
  inventory: {
    file_count: number;
    total_bytes: number;
    package_count: number;
    package_json_count: number;
    package_internal_json_count: number;
    nested_package_count: number;
    packages: Array<{ path: string; name: string; version: string }>;
    mach_o_count: number;
    mach_o: string[];
  };
  files: Array<{ path: string; sha256: string; size: number }>;
}

const CASTLE_WALL_RUNTIME_MAX_FILES = 30_000;
// Logical bytes (not APFS allocation). The current pruned closure is ~382 MiB
// logical / ~219 MiB on disk; keep a narrow deterministic regression ceiling.
const CASTLE_WALL_RUNTIME_MAX_BYTES = 420 * 1024 * 1024;

function isInstalledPackageManifestPath(path: string): boolean {
  if (path === "Resources/cli-runtime/package.json") return true;
  const segments = path.split("/");
  if (segments.at(-1) !== "package.json") return false;
  return (
    segments.at(-3) === "node_modules" ||
    (segments.at(-4) === "node_modules" && (segments.at(-3)?.startsWith("@") ?? false))
  );
}

export async function verifyCastleWallRuntimeManifest(
  bytes: Buffer,
  contents: string,
  expected: { sourceSha: string; nodeVersion: string },
): Promise<boolean> {
  let manifest: CastleWallRuntimeManifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8")) as CastleWallRuntimeManifest;
  } catch {
    return false;
  }
  if (
    manifest.schema !== "sanctuary.castle-wall-cli-runtime.v1" ||
    manifest.source_sha !== expected.sourceSha ||
    manifest.cli_version !== INSTALLER_VERSION ||
    manifest.node_version !== expected.nodeVersion ||
    !Array.isArray(manifest.files) ||
    manifest.inventory === null || typeof manifest.inventory !== "object" ||
    !Array.isArray(manifest.inventory.packages) ||
    !Array.isArray(manifest.inventory.mach_o)
  ) return false;
  // The dist entries here must match the `kind: "file"` rows of
  // server/scripts/sealed-cli-runtime-entries.mjs (reconciled by
  // test/structure/sealed-cli-runtime-contents.test.ts). The worker is required
  // because a runtime without it boots an existing fortress and cannot create
  // one; the installer must refuse such a runtime rather than plan against it.
  const required = new Set([
    "MacOS/sanctuary",
    "Resources/boot-runtime/node",
    "Resources/cli-runtime/dist/cli.js",
    "Resources/cli-runtime/dist/directory-capability-worker.js",
  ]);
  const filePaths = new Set<string>();
  let totalBytes = 0;
  for (const entry of manifest.files) {
    if (
      typeof entry.path !== "string" ||
      !/^[a-f0-9]{64}$/.test(entry.sha256) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0
    ) return false;
    if (filePaths.has(entry.path)) return false;
    filePaths.add(entry.path);
    totalBytes += entry.size;
    const target = resolve(contents, entry.path);
    if (!target.startsWith(`${contents}/`)) return false;
    let handle;
    try {
      handle = await open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.size !== BigInt(entry.size)) return false;
      const digest = createHash("sha256").update(await handle.readFile()).digest("hex");
      const after = await handle.stat({ bigint: true });
      if (
        before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
        before.ctimeNs !== after.ctimeNs || digest !== entry.sha256
      ) return false;
    } catch {
      return false;
    } finally {
      await handle?.close();
    }
    required.delete(entry.path);
  }
  const inventory = manifest.inventory;
  const nativeSet = new Set(inventory.mach_o);
  const expectedPackagePaths = new Set(
    manifest.files.map((entry) => entry.path).filter(isInstalledPackageManifestPath),
  );
  const packageJsonCount = manifest.files.filter(
    (entry) => entry.path.endsWith("/package.json"),
  ).length;
  const nestedPackageCount = [...expectedPackagePaths].filter(
    (path) => path.split("/node_modules/").length > 2,
  ).length;
  const packagePaths = new Set<string>();
  for (const entry of inventory.packages) {
    if (
      entry === null || typeof entry !== "object" ||
      typeof entry.path !== "string" || typeof entry.name !== "string" ||
      typeof entry.version !== "string" || !expectedPackagePaths.has(entry.path) ||
      packagePaths.has(entry.path)
    ) return false;
    packagePaths.add(entry.path);
  }
  return (
    required.size === 0 &&
    inventory.file_count === manifest.files.length &&
    inventory.file_count <= CASTLE_WALL_RUNTIME_MAX_FILES &&
    inventory.total_bytes === totalBytes &&
    inventory.total_bytes <= CASTLE_WALL_RUNTIME_MAX_BYTES &&
    inventory.package_count === inventory.packages.length &&
    packagePaths.size === expectedPackagePaths.size &&
    inventory.package_json_count === packageJsonCount &&
    inventory.package_internal_json_count === packageJsonCount - packagePaths.size &&
    inventory.nested_package_count === nestedPackageCount &&
    inventory.mach_o_count === inventory.mach_o.length &&
    nativeSet.size === inventory.mach_o.length &&
    inventory.mach_o.every((path) => filePaths.has(path)) &&
    [...nativeSet].some((path) => path.includes("/@lmdb/") && path.endsWith(".node")) &&
    [...nativeSet].some((path) => path.includes("/@msgpackr-extract/") && path.endsWith(".node"))
  );
}

function hasExactCodesignField(text: string, field: string, value: string): boolean {
  return text.split(/\r?\n/).some((line) => line === `${field}=${value}`);
}

export type InstallProfile = "memory" | "full";
export type InstallHarness =
  | "openclaw"
  | "hermes"
  | "claude-code"
  | "cursor"
  | "cline"
  | "mastra";
export type InstallObservation =
  | "present"
  | "absent"
  | "mismatch"
  | "unknown"
  | "not-applicable";
// The trust-anchor verdict as `castle-wall status` reports it. `broken` is
// produced ONLY by the signer-helper-authoritative verdict line; the softer
// local-key comparison (a non-authoritative fallback that can differ after a
// legitimate re-pin or when the helper is momentarily unavailable) reads as
// `unknown` and never drives the Tier-1 re-pin remedy.
// `unknown` is the honest fallback when the pin is unreadable or no comparison
// key is reachable; the planner never treats `unknown` as broken (no fabricated
// remedy) or as consistent.
export type TrustAnchorObservation =
  | "consistent"
  | "broken"
  | "unprovisioned"
  | "unknown"
  | "not-applicable";

/**
 * Whether this host can UNLOCK the fortress today through the exact-fortress
 * stored credential — the daily-UX question Rung 1 fresh-host onboarding turns
 * on. Read-only and ambient-env-blind: the probe reads the OS keyring / fallback
 * NAMESPACED to this fortress and tries the unwrap, and it deliberately does NOT
 * consult SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY, so a passphrase that
 * happens to be exported in the installing shell can never make a copied host
 * look "usable" when the daily driver (no ambient secret) could not open it.
 *  - "usable":         the stored credential reads AND unlocks the custody
 *                      envelope — the operator can run memory verbs with no
 *                      secret typed.
 *  - "absent":         the fortress has envelope custody but this host holds NO
 *                      stored credential for it (the just-copied second host,
 *                      before a recovery-key rekey / import).
 *  - "locked":         the OS keyring is locked / unreachable in this session
 *                      (SSH, fresh reboot) — unlock it and re-probe.
 *  - "mismatch":       a stored credential exists but does NOT unlock this
 *                      fortress (a stale credential after a restore), or the
 *                      encrypted fallback will not decrypt on this host.
 *  - "missing":        no envelope custody exists yet (virgin fortress); the
 *                      Rung 1 custody prerequisite is not complete.
 *  - "unavailable":    this platform has no supported exact-fortress stored
 *                      credential path; hands-free opening is not proven.
 *  - "unknown":        an indeterminate read error; no remedy is invented.
 */
export type CustodyAccessObservation =
  | "usable"
  | "absent"
  | "locked"
  | "mismatch"
  | "missing"
  | "unavailable"
  | "unknown";

/** Whether this runtime can perform crash-recoverable custody mutations. */
export type CustodyMutationObservation =
  | "available"
  | "unavailable"
  | "unknown";

/**
 * Whether the fortress carries a human-held recovery factor (a recovery-key
 * custody wrap) — the factor that makes a second-host recovery or a
 * `reset-passphrase --mode recovery-key` possible. Read from the envelope's wrap
 * types only after the envelope is authenticated under an unwrapped master;
 * otherwise the observation is `unknown`.
 *  - "present": at least one authenticated, operator-verified recovery-key
 *               wrap exists.
 *  - "absent":  no recovery-key wrap (or no envelope custody yet).
 *  - "unknown": the envelope could not be authenticated, or it contains only
 *               an unverified recovery wrap.
 */
export type RecoveryFactorObservation = "present" | "absent" | "unknown";

export interface AgentInstallAction {
  id: string;
  actor: "agent" | "human";
  description: string;
  argv?: string[];
  completion: string;
  secret_boundary?: string;
  /**
   * Declared transition when this agent action exits nonzero. The caller must
   * execute an agent action once only: on zero it reruns the planner; on
   * nonzero it stops autonomous execution and hands this exact action to the
   * named actor. No transcript or failure receipt is trusted as machine state.
   */
  on_nonzero?: AgentInstallAction;
}

export interface AgentInstallPlan {
  contract: typeof AGENT_INSTALL_CONTRACT;
  status: "agent_action" | "human_action" | "complete" | "blocked";
  profile: InstallProfile;
  harness: InstallHarness;
  fortress: string;
  observations: {
    cooperative_wrap: InstallObservation;
    persistent_cli: InstallObservation;
    persistent_cli_path: string | null;
    persistent_cli_version: string | null;
    package_manager_path: string | null;
    existing_custody: ExistingCustodyMaterialStatus;
    // Rung 1 fresh-host onboarding: can this host open the fortress today via
    // the exact-fortress stored credential (custody_access), and does the
    // fortress carry a human-held recovery factor (recovery_factor)?
    custody_access: CustodyAccessObservation;
    custody_mutation: CustodyMutationObservation;
    recovery_factor: RecoveryFactorObservation;
    castle_wall_app: InstallObservation;
    castle_wall_build_sha: string | null;
    system_extension: SysextState | "unknown" | "not-applicable";
    boot_service: InstallObservation;
    content_filter: "enabled" | "disabled" | "unknown" | "not-applicable";
    enforcement: "live" | "unavailable" | "undetermined" | "not-applicable";
    // Consistency of the root-owned global enforcement pin against the live
    // signer-helper key, parsed from `castle-wall status`. ONLY the
    // signer-helper-authoritative verdict yields `broken`/`consistent`; the
    // softer fortress-local comparison is not definitive and reads as `unknown`.
    // `broken` is the fresh-install crash-loop cause (pin != helper key; the boot
    // daemon cannot sign a manifest and KeepAlive restarts it forever), and the
    // planner names re-pin as the remedy instead of leaving only the crash-loop
    // observable.
    trust_anchor: TrustAnchorObservation;
    operator_twin: InstallObservation;
  };
  next_action: AgentInstallAction | null;
  operator_actions: AgentInstallAction[];
  notes: string[];
}

interface ParsedInstallArgs {
  help: boolean;
  json: boolean;
  profile: InstallProfile;
  harness?: InstallHarness;
  error?: string;
}

export interface InstallProbeResult {
  cooperativeWrap: InstallObservation;
  persistentCli: InstallObservation;
  persistentCliPath: string | null;
  persistentCliVersion: string | null;
  packageManagerPath: string | null;
  existingCustody: ExistingCustodyMaterialStatus;
  custodyAccess: CustodyAccessObservation;
  custodyMutation: CustodyMutationObservation;
  recoveryFactor: RecoveryFactorObservation;
  nodePath: string;
  castleWallApp: InstallObservation;
  castleWallBuildSha: string | null;
  systemExtension: SysextState | "unknown" | "not-applicable";
  bootService: InstallObservation;
  contentFilter: "enabled" | "disabled" | "unknown" | "not-applicable";
  enforcement: "live" | "unavailable" | "undetermined" | "not-applicable";
  trustAnchor: TrustAnchorObservation;
  operatorTwin: InstallObservation;
}

export interface AgentInstallOps {
  probe(input: {
    profile: InstallProfile;
    harness: InstallHarness;
    fortress: string;
  }): Promise<InstallProbeResult>;
}

export interface InstallCommandContext {
  argv?: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  ops?: Partial<AgentInstallOps>;
}

const HARNESSES = new Set<InstallHarness>([
  "openclaw",
  "hermes",
  "claude-code",
  "cursor",
  "cline",
  "mastra",
]);

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function parseInstallArgs(argv: string[]): ParsedInstallArgs {
  const parsed: ParsedInstallArgs = {
    help: false,
    json: false,
    profile: "memory",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") parsed.help = true;
    else if (arg === "--json") parsed.json = true;
    else if (arg === "--full") parsed.profile = "full";
    else if (arg === "--profile") {
      const value = argv[++i];
      if (value !== "memory" && value !== "full") {
        parsed.error = "--profile must be memory or full";
        break;
      }
      parsed.profile = value;
    } else if (arg === "--harness") {
      const value = argv[++i];
      if (value === undefined || !HARNESSES.has(value as InstallHarness)) {
        parsed.error = `--harness must be one of: ${[...HARNESSES].join(", ")}`;
        break;
      }
      parsed.harness = value as InstallHarness;
    } else if (arg.startsWith("--") && HARNESSES.has(arg.slice(2) as InstallHarness)) {
      parsed.harness = arg.slice(2) as InstallHarness;
    } else {
      parsed.error = `Unknown install option: ${arg}`;
      break;
    }
  }
  if (!parsed.help && parsed.error === undefined && parsed.harness === undefined) {
    parsed.error = `--harness is required (${[...HARNESSES].join(", ")})`;
  }
  return parsed;
}

async function pathObservation(
  path: string,
  expected: "file" | "directory",
): Promise<InstallObservation> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) return "mismatch";
    return (expected === "file" ? stats.isFile() : stats.isDirectory())
      ? "present"
      : "mismatch";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unknown";
  }
}

async function probeCastleWallApp(): Promise<{
  status: InstallObservation;
  buildSha: string | null;
}> {
  const shape = await pathObservation(DEFAULT_CASTLE_WALL_APP, "directory");
  if (shape !== "present") return { status: shape, buildSha: null };
  try {
    await execFileAsync("/usr/bin/codesign", [
      "--verify",
      "--deep",
      "--strict",
      DEFAULT_CASTLE_WALL_APP,
    ], { encoding: "utf8", timeout: 15_000 });
    const identity = await execFileAsync("/usr/bin/codesign", [
      "-dv",
      "--verbose=4",
      DEFAULT_CASTLE_WALL_APP,
    ], { encoding: "utf8", timeout: 10_000 });
    const identityText = `${identity.stdout}\n${identity.stderr}`;
    if (
      !hasExactCodesignField(identityText, "Identifier", CASTLE_WALL_APP_IDENTIFIER) ||
      !hasExactCodesignField(identityText, "TeamIdentifier", CASTLE_WALL_TEAM_ID)
    ) {
      return { status: "mismatch", buildSha: null };
    }
    await execFileAsync("/usr/bin/codesign", [
      "--verify",
      "--strict",
      `--requirement=anchor apple generic and certificate leaf[subject.OU] = "${CASTLE_WALL_TEAM_ID}" and identifier "ai.sanctuaryprotocol.macos.castle-wall.node"`,
      DEFAULT_CASTLE_WALL_NODE,
    ], { encoding: "utf8", timeout: 10_000 });
    await execFileAsync("/usr/bin/codesign", [
      "--verify",
      "--strict",
      `--requirement=anchor apple generic and certificate leaf[subject.OU] = "${CASTLE_WALL_TEAM_ID}" and identifier "${CASTLE_WALL_LAUNCHER_IDENTIFIER}"`,
      DEFAULT_CASTLE_WALL_LAUNCHER,
    ], { encoding: "utf8", timeout: 10_000 });
    await execFileAsync("/usr/sbin/spctl", [
      "--assess",
      "--type",
      "execute",
      DEFAULT_CASTLE_WALL_APP,
    ], { encoding: "utf8", timeout: 15_000 });
    const plistPath = join(DEFAULT_CASTLE_WALL_APP, "Contents", "Info.plist");
    const [contract, buildSha, sourceSha, cliVersion, nodeVersion, manifestDigest] = await Promise.all([
      execFileAsync("/usr/bin/plutil", [
        "-extract",
        "SanctuaryCastleWallHeadlessContractVersion",
        "raw",
        "-o",
        "-",
        plistPath,
      ], { encoding: "utf8", timeout: 5_000 }),
      execFileAsync("/usr/bin/plutil", [
        "-extract",
        "SanctuaryCastleWallGitSHA",
        "raw",
        "-o",
        "-",
        plistPath,
      ], { encoding: "utf8", timeout: 5_000 }),
      ...[
        "SanctuaryCastleWallSourceSHA",
        "SanctuaryCliRuntimeVersion",
        "SanctuaryCliRuntimeNodeVersion",
        "SanctuaryCliRuntimeManifestSHA256",
      ].map((key) => execFileAsync("/usr/bin/plutil", [
        "-extract", key, "raw", "-o", "-", plistPath,
      ], { encoding: "utf8", timeout: 5_000 })),
    ]);
    const sha = buildSha.stdout.trim();
    const manifestBytes = await readFile(DEFAULT_CASTLE_WALL_RUNTIME_MANIFEST);
    const actualManifestDigest = createHash("sha256").update(manifestBytes).digest("hex");
    const actualNodeVersion = (await execFileAsync(DEFAULT_CASTLE_WALL_NODE, ["--version"], {
      encoding: "utf8", timeout: 5_000,
    })).stdout.trim();
    if (
      contract.stdout.trim() !== CASTLE_WALL_HEADLESS_CONTRACT ||
      !/^[a-f0-9]{12}$/.test(sha) ||
      !/^[a-f0-9]{40}$/.test(sourceSha.stdout.trim()) ||
      !sourceSha.stdout.trim().startsWith(sha) ||
      sourceSha.stdout.trim() !== INSTALLER_SOURCE_SHA ||
      cliVersion.stdout.trim() !== INSTALLER_VERSION ||
      nodeVersion.stdout.trim() !== actualNodeVersion ||
      manifestDigest.stdout.trim() !== actualManifestDigest
    ) {
      return { status: "mismatch", buildSha: null };
    }
    if (!(await verifyCastleWallRuntimeManifest(
      manifestBytes,
      join(DEFAULT_CASTLE_WALL_APP, "Contents"),
      {
        sourceSha: sourceSha.stdout.trim(),
        nodeVersion: actualNodeVersion,
      },
    ))) {
      return { status: "mismatch", buildSha: null };
    }
    return { status: "present", buildSha: sha };
  } catch {
    return { status: "mismatch", buildSha: null };
  }
}

export async function verifyCastleWallSealedRuntime(): Promise<boolean> {
  return (await probeCastleWallApp()).status === "present";
}

async function probeBootService(fortress: string): Promise<InstallObservation> {
  if (!(await bootServicePlistPresent(CASTLE_WALL_BOOT_PLIST_PATH))) return "absent";
  try {
    return (await bootServiceReady(CASTLE_WALL_BOOT_PLIST_PATH, fortress))
      ? "present"
      : "mismatch";
  } catch {
    return "unknown";
  }
}

function captureWritable(chunks: string[]): Writable {
  return new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
}

async function probePersistentCli(): Promise<{
  status: InstallObservation;
  path: string | null;
  version: string | null;
}> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/which", ["sanctuary"], {
      encoding: "utf8",
      timeout: 5_000,
    });
    const candidate = stdout.trim();
    if (!candidate.startsWith("/")) {
      return { status: "unknown", path: null, version: null };
    }
    const path = await realpath(candidate);
    const versionResult = await execFileAsync(process.execPath, [path, "--version"], {
      encoding: "utf8",
      timeout: 5_000,
    });
    const match = /@sanctuary-framework\/mcp-server\s+(\S+)/.exec(
      versionResult.stdout,
    );
    const version = match?.[1] ?? null;
    return {
      status: version === INSTALLER_VERSION ? "present" : "mismatch",
      path,
      version,
    };
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    return {
      status: code === 1 ? "absent" : "unknown",
      path: null,
      version: null,
    };
  }
}

async function probeExecutableOnPath(name: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/which", [name], {
      encoding: "utf8",
      timeout: 5_000,
    });
    const candidate = stdout.trim();
    if (!candidate.startsWith("/")) return null;
    return await realpath(candidate);
  } catch {
    return null;
  }
}

async function probeBundledCliRuntime(): Promise<{
  status: InstallObservation;
  path: string | null;
  version: string | null;
}> {
  const [nodeShape, cliShape, launcherShape, manifestShape] = await Promise.all([
    pathObservation(DEFAULT_CASTLE_WALL_NODE, "file"),
    pathObservation(DEFAULT_CASTLE_WALL_CLI, "file"),
    pathObservation(DEFAULT_CASTLE_WALL_LAUNCHER, "file"),
    pathObservation(DEFAULT_CASTLE_WALL_RUNTIME_MANIFEST, "file"),
  ]);
  if ([nodeShape, cliShape, launcherShape, manifestShape].some((shape) => shape !== "present")) {
    return {
      status: [nodeShape, cliShape, launcherShape, manifestShape].includes("unknown") ? "unknown" : "absent",
      path: null,
      version: null,
    };
  }
  try {
    const versionResult = await execFileAsync(DEFAULT_CASTLE_WALL_LAUNCHER, ["--version"], {
      encoding: "utf8",
      timeout: 5_000,
      env: { PATH: "/usr/bin:/bin" },
    });
    const match = /@sanctuary-framework\/mcp-server\s+(\S+)/.exec(
      versionResult.stdout,
    );
    const version = match?.[1] ?? null;
    return {
      status: version === INSTALLER_VERSION ? "present" : "mismatch",
      path: DEFAULT_CASTLE_WALL_LAUNCHER,
      version,
    };
  } catch {
    return { status: "mismatch", path: null, version: null };
  }
}

async function probeWrap(harness: InstallHarness): Promise<InstallObservation> {
  try {
    for (const path of getPlatformPaths()[harness]) {
      if (await hasExistingWrapMetaStrict(resolve(path))) return "present";
    }
    return "absent";
  } catch {
    return "unknown";
  }
}

export function parseInstallSystemExtensionState(stdout: string): SysextState {
  // macOS can retain an old terminated version beside its active replacement;
  // every matching row must participate so list order never hides live enforcement.
  const bundleId = "ai.sanctuaryprotocol.macos.castle-wall";
  const matching = stdout
    .split("\n")
    .filter((line) => line.trim().split(/\s+/).includes(bundleId))
    .join("\n");
  return parseCastleWallState(matching);
}

async function probeSystemExtension(): Promise<SysextState | "unknown"> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/systemextensionsctl", ["list"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    return parseInstallSystemExtensionState(stdout);
  } catch {
    return "unknown";
  }
}

// The COMPLETE authoritative verdict lines `reportGlobalPinAndVerdict` in
// castle-wall.ts emits from the live signer-helper `get-pubkey` comparison. Must
// match those two lines byte-for-byte (trimmed): the whole point is that only the
// helper-authoritative verdict is definitive, so a bare `.includes("BROKEN")`
// would be wrong — a non-authoritative line that merely CONTAINS the token (e.g.
// "Trust anchor: BROKEN against local fortress key (non-authoritative fallback)")
// must NOT drive the Tier-1 re-pin remedy. Pinned on both sides: a drift in the
// producer's wording downgrades every read to `unknown` (a silent no-remedy),
// never a false `broken`/`consistent`.
const TRUST_ANCHOR_AUTHORITATIVE_CONSISTENT =
  "Trust anchor: CONSISTENT (global pin == signer-helper key)";
const TRUST_ANCHOR_AUTHORITATIVE_BROKEN =
  "Trust anchor: BROKEN (global pin != signer-helper key; box cannot arm until re-pinned)";
const TRUST_ANCHOR_UNPROVISIONED =
  "Trust anchor: no global pin provisioned (run 'sanctuary castle-wall re-pin' to install it)";

// ONLY the signer-helper-authoritative verdict is definitive. The softer
// `global pin DIFFERS/matches from local fortress key` lines are the
// NON-AUTHORITATIVE fallback castle-wall.ts prints when the helper query is
// unreachable; they compare the retained fortress-local key, not the helper's
// key, and are not safe to act on: a legitimate re-pin makes the fortress-local
// key legitimately differ from the helper-owned global pin, so `DIFFERS` on a
// momentarily-unreachable helper would falsely accuse a healthy box, and
// `matches` could falsely assert consistency. Both soft lines therefore fall
// through to `unknown` so the planner never fabricates a Tier-1 re-pin remedy
// from a non-authoritative comparison. Match is against COMPLETE trimmed lines,
// not substrings, so a decorated near-collision cannot impersonate the verdict.
export function parseTrustAnchor(text: string): TrustAnchorObservation {
  const lines = text.split("\n").map((line) => line.trim());
  if (lines.includes(TRUST_ANCHOR_AUTHORITATIVE_BROKEN)) {
    return "broken";
  }
  if (lines.includes(TRUST_ANCHOR_AUTHORITATIVE_CONSISTENT)) {
    return "consistent";
  }
  if (lines.includes(TRUST_ANCHOR_UNPROVISIONED)) {
    return "unprovisioned";
  }
  // Non-authoritative fallback (`global pin DIFFERS/matches local fortress key`),
  // "cannot verify", "unreadable" (root-owned pin, no elevation), or an absent
  // verdict line: the AUTHORITATIVE helper==pin check is not observable from here,
  // so report the honest unknown rather than driving a remedy off a soft signal.
  return "unknown";
}

async function probeWallStatus(
  env: NodeJS.ProcessEnv,
): Promise<Pick<InstallProbeResult, "contentFilter" | "enforcement" | "trustAnchor">> {
  const chunks: string[] = [];
  try {
    await runStatus([], { out: captureWritable(chunks), env, platform: "darwin" });
  } catch {
    return { contentFilter: "unknown", enforcement: "undetermined", trustAnchor: "unknown" };
  }
  const text = chunks.join("");
  const contentFilter = text.includes("Content filter: enabled")
    ? "enabled"
    : text.includes("Content filter: disabled")
      ? "disabled"
      : "unknown";
  const enforcement = text.includes("Enforcement availability: live")
    ? "live"
    : text.includes("Enforcement availability: unavailable")
      ? "unavailable"
      : "undetermined";
  return { contentFilter, enforcement, trustAnchor: parseTrustAnchor(text) };
}

async function probeOperatorTwin(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): Promise<InstallObservation> {
  const row = await runOperatorTwinPreflight({
    ops: {
      env: () => env,
      platform: () => platform,
    },
  });
  if (row.status === "PASS") return "absent";
  if (row.status === "FAIL") return "present";
  return "unknown";
}

/**
 * Read-only, ambient-env-blind daily-UX probe for Rung 1 fresh-host onboarding.
 * Answers "can this host open the fortress today, and does it carry a recovery
 * factor?" WITHOUT typing or reading any credential from the environment:
 *  - reads both exact-fortress local factors (stored passphrase and the
 *    interactive-init custody key) and tries each unwrap to decide
 *    custody_access; passphrase is tried first and custody key is fallback,
 *  - reports recovery_factor ONLY from an envelope that has passed its MAC under
 *    the unwrapped master; without authenticated custody recovery_factor is
 *    "unknown", so an attacker-added plaintext recovery wrap cannot change it.
 * It never consults SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY, never
 * generates custody or mutates the fortress. The independent mutation-capability
 * probe creates and removes a private runtime socket and may create its 0700
 * runtime directory; that bounded host-local probe is not fortress state.
 * Any decrypted master is zeroed.
 */
export async function probeCustodyAccess(
  fortress: string,
  platform: NodeJS.Platform,
  // Test seam: the exact-fortress stored-credential reader. Defaults to the real
  // keyring/fallback read; tests inject an in-memory reader so the suite never
  // spawns the OS keyring subprocess against the operator's keyring. (The binary
  // names are intentionally not quoted here: the keychain-exec-guard source scan
  // flags any quoted credential-binary literal outside the chokepoint.)
  readStored: typeof readStoredPassphrase = readStoredPassphrase,
  probeLock: (
    host: NodeJS.Platform,
    targetLockDirectory?: string,
  ) => Promise<KernelLockCapability> = (host, targetLockDirectory) =>
    probeKernelBackedCrossProcessLockCapability(
      host,
      undefined,
      targetLockDirectory,
    ),
  readCustody: (
    storagePath: string,
  ) => Promise<KeychainReadResult> = (storagePath) =>
    readKeychainCustodyKeyStatus(storagePath, { platformOverride: platform }),
): Promise<{
  custodyAccess: CustodyAccessObservation;
  custodyMutation: CustodyMutationObservation;
  recoveryFactor: RecoveryFactorObservation;
}> {
  const storage = new FilesystemStorage(join(fortress, "state"));
  let custodyMutation: CustodyMutationObservation;
  try {
    custodyMutation = (
      await probeLock(platform, join(fortress, "state", "_meta"))
    ).available
      ? "available"
      : "unavailable";
  } catch {
    custodyMutation = "unknown";
  }
  let envelope: Awaited<ReturnType<typeof readCustodyEnvelope>>;
  try {
    envelope = await readCustodyEnvelope(storage);
  } catch {
    // Unreadable/tampered envelope: indeterminate. No remedy invented.
    return { custodyAccess: "unknown", custodyMutation, recoveryFactor: "unknown" };
  }
  if (!envelope) {
    // Virgin fortress: no custody envelope, so nothing to open and no recovery
    // wrap can exist. Both observations are authentic with no unlock needed.
    return { custodyAccess: "missing", custodyMutation, recoveryFactor: "absent" };
  }

  // recovery_factor is NEVER read from the envelope's plaintext wrap list until
  // the envelope MAC has verified under an unwrapped master. An attacker with
  // bare write access to the custody file can append a plaintext
  // { type: "recovery-key" } wrap whose payload need not decrypt; trusting
  // `wraps[].type` before authentication would flip recovery_factor to
  // "present" and (once observations drive the planner) steer it toward a
  // recovery path that does not exist (AGENTS.md rule 7). So every branch that
  // has NOT authenticated custody reports recovery_factor: "unknown".

  let stored: Awaited<ReturnType<typeof readStoredPassphrase>> = null;
  let passphraseState: "absent" | "locked" | "unreadable" | "unknown" = "absent";
  try {
    stored = await readStored({
      storagePath: fortress,
      platformOverride: platform,
      readOnly: true,
    });
  } catch (error) {
    if (error instanceof PassphraseKeyringUnreachableError) {
      passphraseState = "locked";
    } else if (error instanceof PassphraseUnreadableError) {
      passphraseState = "unreadable";
    } else {
      passphraseState = "unknown";
    }
  }
  const custody = await readCustody(fortress).catch(() => ({
    status: "unreachable" as const,
    detail: "custody-key identity could not be determined",
  }));
  const custodyKey =
    custody.status === "found" && custody.key !== undefined
      ? custody.key
      : undefined;
  let authenticatedMaster: Uint8Array | null = null;
  let integrityIndeterminate = false;
  let sawMismatch =
    passphraseState === "unreadable" ||
    (custody.status === "found" && custody.key === undefined);
  try {
    if (stored && stored.value.length > 0) {
      let candidate: Uint8Array | null = null;
      try {
        candidate = await unlockExistingMasterReadOnly(storage, {
          passphrase: stored.value,
          storagePathHint: fortress,
        });
        authenticatedMaster = candidate;
        candidate = null;
      } catch (error) {
        if (error instanceof CustodyUnlockError && !(error instanceof CustodyCredentialMissingError)) {
          sawMismatch = true;
        } else {
          integrityIndeterminate = true;
        }
      } finally {
        candidate?.fill(0);
      }
    }
    if (authenticatedMaster === null && custodyKey) {
      let candidate: Uint8Array | null = null;
      try {
        candidate = await unlockExistingMasterReadOnly(storage, {
          keychainKey: custodyKey,
          storagePathHint: fortress,
        });
        authenticatedMaster = candidate;
        candidate = null;
      } catch (error) {
        if (error instanceof CustodyUnlockError && !(error instanceof CustodyCredentialMissingError)) {
          sawMismatch = true;
        } else {
          integrityIndeterminate = true;
        }
      } finally {
        candidate?.fill(0);
      }
    }
    if (authenticatedMaster === null) {
      if (integrityIndeterminate) {
        return { custodyAccess: "unknown", custodyMutation, recoveryFactor: "unknown" };
      }
      // An inaccessible factor may still be the valid one. Report the
      // actionable locked state ahead of a different local factor's mismatch;
      // never claim the fortress has no usable local credential while the OS
      // keyring's answer is indeterminate. custody.status === "unreachable"
      // is a genuine, transient "unlock and re-probe" signal only on a
      // platform where custody keys are OS-keyring-backed (darwin, linux):
      // readKeyClassified has no non-keyring path for custody keys, so on
      // every other platform (e.g. Windows) that same status is a structural
      // "no OS-keyring integration on this platform" answer, not a lock.
      // Folding it into "locked" there would tell the operator to unlock a
      // login Keychain that does not exist, so it is excluded from the
      // locked check outside darwin/linux; the platform falls through to the
      // passphrase-fallback-file signals below (Windows's real
      // exact-fortress credential path), landing on "unavailable" only when
      // none of those signals apply either.
      const custodyKeyGenuinelyLocked =
        custody.status === "unreachable" &&
        (platform === "darwin" || platform === "linux");
      if (passphraseState === "locked" || custodyKeyGenuinelyLocked) {
        return { custodyAccess: "locked", custodyMutation, recoveryFactor: "unknown" };
      }
      if (sawMismatch) {
        return { custodyAccess: "mismatch", custodyMutation, recoveryFactor: "unknown" };
      }
      if (passphraseState === "unknown") {
        return { custodyAccess: "unknown", custodyMutation, recoveryFactor: "unknown" };
      }
      if (platform !== "darwin" && platform !== "linux") {
        return { custodyAccess: "unavailable", custodyMutation, recoveryFactor: "unknown" };
      }
      return { custodyAccess: "absent", custodyMutation, recoveryFactor: "unknown" };
    }
    const hasVerifiedRecovery = envelope.wraps.some(
      (w) => w.type === "recovery-key" && w.verified === true,
    );
    const hasUnverifiedRecovery = envelope.wraps.some(
      (w) => w.type === "recovery-key" && w.verified !== true,
    );
    const recoveryFactor: RecoveryFactorObservation = hasVerifiedRecovery
      ? "present"
      : hasUnverifiedRecovery
        ? "unknown"
        : "absent";
    return {
      custodyAccess: "usable",
      custodyMutation,
      recoveryFactor,
    };
  } finally {
    authenticatedMaster?.fill(0);
    custodyKey?.fill(0);
  }
}

function createInstallOps(ctx: InstallCommandContext): AgentInstallOps {
  const platform = ctx.platform ?? process.platform;
  const env = ctx.env ?? process.env;
  return {
    probe: async ({ profile, harness, fortress }) => {
      const cooperativeWrap = await probeWrap(harness);
      const [pathCli, packageManagerPath, existingCustody, custodyAccessProbe] =
        await Promise.all([
          probePersistentCli(),
          probeExecutableOnPath("npm"),
          platform === "darwin"
            ? probeExistingCustodyMaterial(fortress)
            : Promise.resolve("absent" as const),
          // Read-only, ambient-env-blind daily-UX probe — runs on every profile
          // (Rung 1 IS the memory profile) and every platform.
          probeCustodyAccess(fortress, platform),
        ]);
      const { custodyAccess, custodyMutation, recoveryFactor } = custodyAccessProbe;
      let persistentCli = pathCli;
      let nodePath = process.execPath;
      let verifiedCastleWallApp: Awaited<ReturnType<typeof probeCastleWallApp>> | null = null;
      if (platform === "darwin" && profile === "full") {
        verifiedCastleWallApp = await probeCastleWallApp();
        if (verifiedCastleWallApp.status === "present") {
          const bundledCli = await probeBundledCliRuntime();
          if (bundledCli.status === "present") {
            persistentCli = bundledCli;
            nodePath = DEFAULT_CASTLE_WALL_LAUNCHER;
          } else {
            persistentCli = bundledCli;
          }
        } else {
          persistentCli = { status: verifiedCastleWallApp.status, path: null, version: null };
        }
      }
      if (profile !== "full" || platform !== "darwin") {
        return {
          cooperativeWrap,
          persistentCli: persistentCli.status,
          persistentCliPath: persistentCli.path,
          persistentCliVersion: persistentCli.version,
          packageManagerPath,
          existingCustody,
          custodyAccess,
          custodyMutation,
          recoveryFactor,
          nodePath,
          castleWallApp: "not-applicable",
          castleWallBuildSha: null,
          systemExtension: "not-applicable",
          bootService: "not-applicable",
          contentFilter: "not-applicable",
          enforcement: "not-applicable",
          trustAnchor: "not-applicable",
          operatorTwin: "not-applicable",
        };
      }
      const [castleWallApp, systemExtension, bootService, wall, operatorTwin] = await Promise.all([
        verifiedCastleWallApp === null ? probeCastleWallApp() : verifiedCastleWallApp,
        probeSystemExtension(),
        probeBootService(fortress),
        probeWallStatus(env),
        harness === "hermes"
          ? probeOperatorTwin(env, platform)
          : Promise.resolve("not-applicable" as const),
      ]);
      return {
        cooperativeWrap,
        persistentCli: persistentCli.status,
        persistentCliPath: persistentCli.path,
        persistentCliVersion: persistentCli.version,
        packageManagerPath,
        existingCustody,
        custodyAccess,
        custodyMutation,
        recoveryFactor,
        nodePath,
        castleWallApp: castleWallApp.status,
        castleWallBuildSha: castleWallApp.buildSha,
        systemExtension,
        bootService,
        ...wall,
        operatorTwin,
      };
    },
  };
}

function recoveryCustodyAction(fortress: string): AgentInstallAction {
  const stagedPath = agentGuidedRecoveryOutputPath(fortress);
  return {
    id: "private_recovery_custody",
    actor: "human",
    description:
      `In a private local session, move the staged recovery file at ${stagedPath} into a password manager, then delete the file. ` +
      "For an older install with no staged file, run 'sanctuary export-passphrase' privately instead.",
    completion: "The operator confirms custody without pasting the secret into chat.",
    secret_boundary:
      "The installing agent must not run the command, capture its output, or ask the operator to paste recovery material.",
  };
}

/**
 * Rung 1 restart-persistence acceptance. A HUMAN action because it needs a real
 * host restart, after which sovereign memory must still open from the
 * exact-fortress stored credential with NO secret typed. The verification uses
 * the EXISTING policy-enforcing MCP tools: memory_insert / memory_search /
 * memory_get prove the exact content, and sdw_memory_provenance separately
 * proves the signer and admission bindings. Never a new CLI verb, so the proof
 * runs through the same Tier gate and provenance signing as daily use. No argv:
 * these are MCP calls, not a shell command.
 */
function restartAndVerifyRung1Action(): AgentInstallAction {
  return {
    id: "restart_and_verify_rung1",
    actor: "human",
    description:
      "Rung 1 acceptance: restart this host, then prove sovereign memory survives " +
      "and still opens with no secret typed. Using the MCP tools (not a new CLI): " +
      "before restarting, memory_insert a marker record; after the restart, " +
      "memory_search for it and memory_get it back byte-faithfully. Then call " +
      "sdw_memory_provenance for that passage id and require verified signer and " +
      "admission bindings; memory_get itself does not carry signer data. The fortress " +
      "must unlock from the " +
      "exact-fortress stored credential (custody_access=usable) with no " +
      "SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY in the environment.",
    completion:
      "After a restart, memory_get returns the pre-restart record and " +
      "sdw_memory_provenance verifies its signer/admission bindings, with no ambient " +
      "credential env set.",
    secret_boundary:
      "Do not set SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY for this proof, and do " +
      "not paste any passphrase, recovery key, or keychain contents into chat.",
  };
}

/**
 * Locked-keyring remedy for a fortress this host CAN open but not in this
 * session. custody_access=locked means a stored credential exists but the OS
 * keyring is locked / unreachable here (SSH, fresh reboot) — nothing is wrong
 * with custody, so the remedy is a human unlock + re-probe, NOT a rekey.
 */
function unlockLocalKeyringAction(): AgentInstallAction {
  return {
    id: "unlock_local_keyring",
    actor: "human",
    description:
      "This host holds a stored credential for the fortress, but the OS keyring is locked " +
      "or unreachable in this session (a common SSH or fresh-reboot state), so daily " +
      "hands-free open cannot be confirmed. In a local desktop session, unlock the login " +
      "Keychain (macOS) or start/unlock the Secret Service (Linux), then rerun the planner. " +
      "No secret is typed here.",
    completion: "A rerun observes custody_access=usable.",
    secret_boundary:
      "Do not paste a login password, passphrase, recovery key, or keychain contents into chat or an agent command.",
  };
}

/**
 * Attended, NONDESTRUCTIVE recovery ATTEMPT for the common copied/stale host
 * where custody could not be authenticated (custody_access absent/mismatch,
 * recovery_factor UNKNOWN). Because the envelope could not be MAC-verified from
 * here, the planner must NOT claim a recovery factor exists (AGENTS.md rule 7 /
 * finding 1: "never a recovery-factor claim"). It names the recovery-key rekey
 * as an ATTEMPT the operator can safely try: it is nondestructive and a wrong or
 * absent key changes nothing, so attempting it leaks nothing and risks nothing.
 * The action id itself states that this is only an attempt; no parallel
 * "proven factor" branch exists because the probe cannot emit that composition.
 */
function attemptCustodyRecoveryAction(
  fortress: string,
  access: "absent" | "mismatch",
): AgentInstallAction {
  return {
    id: "attempt_custody_recovery",
    actor: "human",
    description:
      (access === "absent"
        ? "This host holds no stored credential for the installed fortress yet (a just-copied second host). "
        : "This host's stored credential does not open the installed fortress (stale after a restore/copy). ") +
      "Whether the fortress carries a recovery factor cannot be confirmed from here without a " +
      "credential, so this is an ATTEMPT, not a guarantee. If you saved a recovery key at first " +
      "custody, in a private local desktop Terminal execute the exact structured argv attached " +
      "to this action (do not reconstruct it as an unquoted shell string). The recovery key " +
      "is read from a hidden prompt (never argv, environment, or a pipe). It is nondestructive: a " +
      "wrong or absent key changes nothing. If you have no recovery key, open the fortress on a host " +
      "that already holds its credential.",
    argv: [
      "sanctuary",
      "reset-passphrase",
      "--mode",
      "recovery-key",
      "--fortress",
      fortress,
    ],
    completion:
      "A rerun observes custody_access=usable (the recovery key was present and enrolled a fresh " +
      "passphrase), or the attempt reported the key does not unlock this fortress.",
    secret_boundary:
      "Type the recovery key only at the hidden prompt. Never place it in argv, an environment " +
      "variable, a pipe, or a chat, and never paste keychain contents.",
  };
}

/**
 * Rung 1 fresh-host gate on a mechanically-complete cooperative surface.
 *
 * `cooperative_wrap=present` proves a wrap surface EXISTS on disk, but a
 * just-copied second host can carry that surface and still be unable to OPEN it
 * hands-free (`custody_access !== usable`). Daily-UX completion is the stronger
 * claim, so this gate decides — from the AUTHENTICATED custody_access,
 * independent custody_mutation, and recovery_factor observations — whether to declare `complete` or route to the
 * exact nondestructive recovery/unlock step. It never claims a recovery path
 * the observations do not prove: recovery_factor is `present` only after the
 * envelope MAC verifies (probeCustodyAccess), so an attacker-added wrap cannot
 * influence the plan. `completeNotes` are the profile-specific notes appended
 * only on the genuine-complete path. Mutates and returns `plan`.
 */
function applyRung1CustodyCompletion(
  input: { fortress: string; observed: InstallProbeResult },
  plan: AgentInstallPlan,
  completeNotes: string[],
): AgentInstallPlan {
  const access = input.observed.custodyAccess;
  // Completion means the exact-fortress stored credential demonstrably opens
  // custody. Missing custody and platforms without a supported hands-free store
  // are never a green mechanical substitute for that proof.
  if (access === "usable") {
    if (input.observed.custodyMutation !== "available") {
      plan.status = input.observed.custodyMutation === "unavailable"
        ? "blocked"
        : "human_action";
      plan.next_action = {
        id: "restore_custody_lock_capability",
        actor: "human",
        description:
          input.observed.custodyMutation === "unavailable"
            ? "The stored credential authenticated, but this runtime lacks the reviewed process-owned custody mutation lock. Install or select a supported Sanctuary runtime, then rerun."
            : "The stored credential authenticated, but the custody mutation lock probe was indeterminate. Re-run locally and inspect the secure runtime-directory/socket capability before mutating custody.",
        completion:
          "A rerun observes custody_access=usable and custody_mutation=available.",
      };
      plan.notes.push(
        "Daily hands-free authentication succeeded, but custody mutation readiness is a separate requirement and is not yet proven.",
      );
      return plan;
    }
    plan.status = "complete";
    plan.operator_actions = [
      recoveryCustodyAction(input.fortress),
      restartAndVerifyRung1Action(),
    ];
    for (const note of completeNotes) plan.notes.push(note);
    return plan;
  }
  if (access === "locked") {
    plan.status = "human_action";
    plan.next_action = unlockLocalKeyringAction();
    plan.notes.push(
      "The cooperative surface is installed, but this session's OS keyring is locked or " +
        "unreachable, so daily hands-free open cannot be confirmed. Unlock it and rerun the planner.",
    );
    return plan;
  }
  if (access === "missing" || access === "unavailable") {
    plan.status = "blocked";
    plan.notes.push(
      access === "missing"
        ? "The cooperative wrap metadata is present but the custody envelope is missing; Rung 1 cannot open and must not be declared complete. Restore authenticated custody before retrying."
        : "This platform has no supported exact-fortress hands-free credential store, so restart persistence cannot be proved and Rung 1 is not complete.",
    );
    if (access === "unavailable") {
      plan.next_action = {
        id: "restore_custody_access_capability",
        actor: "human",
        description:
          "This platform has no supported exact-fortress stored credential path. Install or select a supported Sanctuary runtime and credential store, then rerun.",
        completion:
          "A rerun observes custody_access=usable.",
      };
    }
    return plan;
  }
  if (access === "absent" || access === "mismatch") {
    if (input.observed.recoveryFactor === "unknown") {
      // This is the only probe-produced absent/mismatch composition: without an
      // opening credential the envelope cannot be authenticated, so the factor
      // remains unproven. Offer only the nondestructive attended attempt.
      plan.status = "human_action";
      plan.next_action = attemptCustodyRecoveryAction(input.fortress, access);
      plan.notes.push(
        "The cooperative surface is installed but this host cannot open it, and custody could not " +
          "be authenticated from here to confirm a recovery factor. A nondestructive recovery-key " +
          "attempt is offered; whether a recovery key exists is not claimed.",
      );
      return plan;
    }
    // present/absent alongside absent/mismatch is not emitted by
    // probeCustodyAccess: authentication sufficient to assert a factor would
    // also make custody_access usable. Treat injected/stale observations as an
    // inconsistent trust input, never as a definite recovery path.
    plan.status = "blocked";
    plan.notes.push(
      "The custody observations are internally inconsistent: absent/mismatch custody cannot carry an authenticated recovery-factor verdict. Rerun the read-only probe before taking recovery action.",
    );
    return plan;
  }
  // access === "unknown": an indeterminate custody read. Never claim a recovery
  // factor (probeCustodyAccess reports recovery_factor=unknown here) and never
  // fabricate a path; ask for an attended diagnostic re-probe.
  plan.status = "human_action";
  plan.next_action = {
    id: "diagnose_custody_access",
    actor: "human",
    description:
      "The cooperative surface is installed, but this host's ability to open the fortress could " +
      "not be determined (an indeterminate custody read). In a private local desktop session, " +
      "verify the fortress storage path and OS keyring are reachable, then rerun the planner. Do " +
      "not assume a recovery path exists until custody_access reads a definite value.",
    completion:
      "A rerun observes custody_access as a definite value (usable / absent / locked / mismatch).",
    secret_boundary:
      "Do not paste a passphrase, recovery key, or keychain contents into chat while diagnosing.",
  };
  return plan;
}

function basePlan(
  profile: InstallProfile,
  harness: InstallHarness,
  fortress: string,
  observed: InstallProbeResult,
): AgentInstallPlan {
  return {
    contract: AGENT_INSTALL_CONTRACT,
    status: "blocked",
    profile,
    harness,
    fortress,
    observations: {
      cooperative_wrap: observed.cooperativeWrap,
      persistent_cli: observed.persistentCli,
      persistent_cli_path: observed.persistentCliPath,
      persistent_cli_version: observed.persistentCliVersion,
      package_manager_path: observed.packageManagerPath,
      existing_custody: observed.existingCustody,
      custody_access: observed.custodyAccess,
      custody_mutation: observed.custodyMutation,
      recovery_factor: observed.recoveryFactor,
      castle_wall_app: observed.castleWallApp,
      castle_wall_build_sha: observed.castleWallBuildSha,
      system_extension: observed.systemExtension,
      boot_service: observed.bootService,
      content_filter: observed.contentFilter,
      enforcement: observed.enforcement,
      trust_anchor: observed.trustAnchor,
      operator_twin: observed.operatorTwin,
    },
    next_action: null,
    operator_actions: [],
    notes: [
      "Rerun this command after each action; progress is derived from observed state, not a transcript.",
    ],
  };
}

export function buildAgentInstallPlan(input: {
  profile: InstallProfile;
  harness: InstallHarness;
  fortress: string;
  platform: NodeJS.Platform;
  observed: InstallProbeResult;
}): AgentInstallPlan {
  const plan = basePlan(input.profile, input.harness, input.fortress, input.observed);
  const sealedFullRuntime =
    input.profile === "full" &&
    input.platform === "darwin" &&
    input.observed.persistentCliPath === DEFAULT_CASTLE_WALL_LAUNCHER;
  const commandPrefix = sealedFullRuntime
    ? [DEFAULT_CASTLE_WALL_LAUNCHER]
    : [input.observed.nodePath, input.observed.persistentCliPath ?? "sanctuary"];
  const protectArgs = [
    ...commandPrefix,
    "--fortress",
    input.fortress,
    "protect",
    `--${input.harness}`,
    "--no-open",
    "--agent-guided",
    ...(sealedFullRuntime ? ["--sealed-launcher", DEFAULT_CASTLE_WALL_LAUNCHER] : []),
  ];
  const protectFailureAction = (): AgentInstallAction => ({
    id: "complete_cooperative_surface_locally",
    actor: "human",
    description:
      input.platform === "darwin"
        ? "The agent-run protect command failed. In a private local desktop Terminal, unlock the login Keychain if prompted, then run this exact signed protect command once."
        : "The agent-run protect command failed. In a private local desktop Terminal with the user Secret Service available, run this exact protect command once.",
    argv: [
      ...protectArgs,
      ...(input.platform === "darwin" ? ["--operator-custody"] : []),
      "--no-provision-agent-account",
    ],
    completion: "A planner rerun observes cooperative_wrap=present.",
    secret_boundary:
      input.platform === "darwin"
        ? "Do not paste a login password, passphrase, recovery key, Keychain contents, or command output into chat. Do not let the agent retry this action."
        : "Do not paste a login password, passphrase, recovery key, Secret Service contents, or command output into chat. Do not let the agent retry this action.",
  });
  const firstMacCustodyAction = (): AgentInstallAction => ({
    id: "prepare_local_keychain_session",
    actor: "human",
    description:
      input.observed.existingCustody === "unknown"
        ? "Existing custody could not be safely identified. In a private local desktop Terminal, unlock the login Keychain if prompted, then run this exact signed protect command once."
        : "First custody is an operator ceremony on macOS. In a private local desktop Terminal, unlock the login Keychain if prompted, then run this exact signed protect command once.",
    argv: [
      ...protectArgs,
      "--operator-custody",
      "--no-provision-agent-account",
    ],
    completion: "A planner rerun observes cooperative_wrap=present.",
    secret_boundary:
      "Do not paste a login password, passphrase, recovery key, or Keychain contents into chat or an agent command.",
  });

  if (input.observed.persistentCli !== "present" || input.observed.persistentCliPath === null) {
    if (input.observed.persistentCli === "unknown") {
      plan.notes.push("The persistent CLI probe failed; unknown is not treated as an installable command path.");
      return plan;
    }
    if (input.profile === "full" || input.observed.packageManagerPath === null) {
      plan.notes.push(
        input.profile === "full"
          ? `No trusted full-profile CLI bootstrap is available. Install a current verified signed Castle Wall app with its sealed runtime at ${DEFAULT_CASTLE_WALL_APP}; the full path never falls back to npm or a PATH-resolved CLI.`
          : "No trusted CLI bootstrap is available: npm is absent. Have the operator choose and install a Node/npm distribution before retrying.",
      );
      return plan;
    }
    plan.status = "agent_action";
    plan.next_action = {
      id: "install_persistent_cli",
      actor: "agent",
      description: "Install a persistent CLI rather than relying on an ephemeral npx path.",
      argv: [
        input.observed.packageManagerPath,
        "install",
        "-g",
        `@sanctuary-framework/mcp-server@${INSTALLER_VERSION}`,
      ],
      completion: "A rerun observes persistent_cli=present and an absolute persistent_cli_path.",
    };
    return plan;
  }

  if (input.profile === "memory") {
    if (input.observed.cooperativeWrap === "present") {
      // The wrap surface exists; the Rung 1 custody gate decides whether THIS
      // host can open it hands-free (complete) or must run the exact
      // nondestructive recovery/unlock step first. This runs AFTER the virgin/
      // mechanical branches below, so it never disturbs first-custody flow.
      return applyRung1CustodyCompletion(input, plan, [
        "The cooperative encrypted-memory and policy surface is installed.",
      ]);
    }
    if (input.observed.cooperativeWrap === "unknown") {
      plan.next_action = {
        id: "repair_wrap_observation",
        actor: "human",
        description: "The current wrap state could not be read. Repair fortress custody before retrying.",
        completion: "The installer can positively observe whether a wrap exists.",
      };
      plan.status = "human_action";
      return plan;
    }
    if (input.platform === "darwin" && input.observed.existingCustody !== "present") {
      plan.status = "human_action";
      plan.next_action = firstMacCustodyAction();
      return plan;
    }
    plan.status = "agent_action";
    plan.next_action = {
      id: "install_cooperative_surface",
      actor: "agent",
      description: "Run Sanctuary's idempotent protect flow for the selected harness.",
      argv: [...protectArgs, "--no-provision-agent-account"],
      completion: "A rerun observes cooperative_wrap=present.",
      secret_boundary: "Do not add --passphrase or --write-passphrase-backup; default custody does not disclose the generated passphrase.",
      on_nonzero: protectFailureAction(),
    };
    return plan;
  }

  if (input.platform !== "darwin") {
    plan.notes.push("The full profile has no shipped live-enforcement path on this platform.");
    return plan;
  }
  if (!sealedFullRuntime) {
    plan.notes.push(
      `The full macOS profile requires the verified signed launcher at ${DEFAULT_CASTLE_WALL_LAUNCHER}; global or PATH-resolved CLI installations are not accepted for this path.`,
    );
    return plan;
  }
  if (input.harness !== "hermes") {
    plan.notes.push("The full one-flow dedicated-account installer currently supports Hermes only.");
    return plan;
  }
  if (
    input.observed.cooperativeWrap === "absent" &&
    input.observed.existingCustody !== "present"
  ) {
    plan.status = "human_action";
    plan.next_action = firstMacCustodyAction();
    return plan;
  }
  if (input.observed.cooperativeWrap === "absent") {
    plan.status = "agent_action";
    plan.next_action = {
      id: "install_cooperative_surface",
      actor: "agent",
      description:
        "Install the encrypted-memory/cooperative surface as the operator account before any root provisioning.",
      argv: [...protectArgs, "--no-provision-agent-account"],
      completion: "A rerun observes cooperative_wrap=present.",
      secret_boundary:
        "Recovery is staged outside the fortress without being printed. The agent must not read the staged file.",
      on_nonzero: protectFailureAction(),
    };
    return plan;
  }
  if (input.observed.castleWallApp === "absent") {
    plan.notes.push(
      `A trusted signed Castle Wall candidate must be verified and installed at ${DEFAULT_CASTLE_WALL_APP}; the planner never guesses or downloads an enforcement artifact.`,
    );
    return plan;
  }
  if (input.observed.castleWallApp === "unknown") {
    plan.notes.push(`The planner could not inspect ${DEFAULT_CASTLE_WALL_APP}; repair access before retrying.`);
    return plan;
  }
  if (
    input.observed.castleWallApp === "mismatch" ||
    input.observed.castleWallBuildSha === null ||
    !/^[a-f0-9]{12}$/.test(input.observed.castleWallBuildSha)
  ) {
    plan.notes.push(
      `The Castle Wall app failed signature, Gatekeeper, bundle-identity, build-identity, or headless-contract validation. Replace it with a verified current candidate at ${DEFAULT_CASTLE_WALL_APP}.`,
    );
    return plan;
  }
  if (
    input.observed.systemExtension === "not loaded" ||
    input.observed.systemExtension === "[activated waiting for user]" ||
    input.observed.systemExtension === "[activated disabled]"
  ) {
    plan.status = "human_action";
    plan.next_action = {
      id: "approve_macos_enforcement",
      actor: "human",
      description:
        "Have the agent open Sanctuary-CastleWall.app, then approve the system extension/background item and enable the Network Extension in System Settings.",
      completion: "A rerun observes system_extension=[activated enabled].",
    };
    return plan;
  }
  if (input.observed.systemExtension === "unknown") {
    plan.notes.push("The authoritative system-extension probe failed; unknown is never treated as approval.");
    return plan;
  }
  if (input.observed.operatorTwin !== "absent") {
    plan.notes.push(
      input.observed.operatorTwin === "present"
        ? "An operator-side Hermes twin is present; stand it down and rerun the planner before declaring or installing the full surface."
        : "The operator-side Hermes twin probe is unknown; repair that observation before declaring or installing the full surface.",
    );
    return plan;
  }
  // Finding B: a fresh install can provision a root-owned global pin that does
  // not match the live signer-helper key, so the boot daemon cannot sign a
  // manifest and KeepAlive crash-loops it forever (observed as
  // boot_service=mismatch with no named remedy). Re-pin is the fix and MUST be
  // named before any further mutating retry: re-running the privileged protect
  // flow does not migrate the anchor, so leaving install_full_surface as the
  // only action would loop the operator through the crash-loop. Keyed on the
  // authoritative `trust_anchor=broken` verdict; `unknown` (pin unreadable, no
  // reachable comparison key) is never treated as broken, so no remedy is
  // fabricated when the mismatch cannot actually be observed from here. Re-pin
  // is a Tier-1 operator-present migration and is never agent-triggerable, so
  // this is a human action naming the exact command (no sudo: the root signer
  // helper writes the pin, the CLI only asks it to).
  if (input.observed.trustAnchor === "broken") {
    const repinCliPath = input.observed.persistentCliPath;
    if (repinCliPath === null) {
      plan.notes.push("The trust anchor is broken but the persistent CLI path disappeared after it was observed; refusing to construct a re-pin command.");
      return plan;
    }
    plan.status = "human_action";
    plan.next_action = {
      id: "repin_trust_anchor",
      actor: "human",
      description:
        "The Castle Wall boot daemon is crash-looping: the root-owned global enforcement pin does not match the live signer-helper key, so it cannot sign a policy manifest and macOS keeps restarting it. Run this exact 'castle-wall re-pin' command in a private local Terminal to migrate the trust anchor to the signer helper, then rerun the planner. Arming cannot proceed until this is repaired.",
      argv: [
        "/usr/bin/env",
        `SANCTUARY_STORAGE_PATH=${input.fortress}`,
        `SANCTUARY_CASTLE_SIGNER_CLIENT=${CASTLE_WALL_SIGNER_CLIENT}`,
        input.observed.nodePath,
        ...(sealedFullRuntime ? [] : [repinCliPath]),
        "castle-wall",
        "re-pin",
      ],
      completion:
        "A rerun observes trust_anchor consistent and the boot service stable (no longer crash-looping).",
      secret_boundary:
        "Re-pin is operator-present and never agent-triggerable. The agent must not run it, retry it, or automate the operator's approval of the signer helper.",
    };
    return plan;
  }
  const fullMechanicsComplete =
    input.observed.cooperativeWrap === "present" &&
    input.observed.systemExtension === "[activated enabled]" &&
    input.observed.bootService === "present" &&
    input.observed.contentFilter === "enabled" &&
    input.observed.enforcement === "live";
  if (fullMechanicsComplete) {
    // The full profile contains the Rung 1 cooperative memory surface, so the
    // same custody gate applies: enforcement can be live while a copied host
    // still cannot open memory hands-free. Only usable custody yields
    // `complete` (with the reboot-survival note); every other custody state
    // routes to the exact recovery/unlock/diagnostic step.
    return applyRung1CustodyCompletion(input, plan, [
      "The full mechanical install is observed: wrap, boot service, content filter, and live enforcement.",
      "Only an attended reboot drill proves boot survival on this specific machine.",
    ]);
  }
  if (
    input.observed.cooperativeWrap === "unknown" ||
    input.observed.bootService === "unknown"
  ) {
    plan.notes.push("A safety-bearing local observation is unknown; repair access before any mutating retry.");
    return plan;
  }
  const persistentCliPath = input.observed.persistentCliPath;
  if (persistentCliPath === null) {
    plan.notes.push("The persistent CLI path disappeared after it was observed; refusing to construct a privileged command.");
    return plan;
  }
  const privilegedInstallArgv = [
    "sudo",
    "/usr/bin/env",
    `SANCTUARY_CASTLE_BUILD_SHA=${input.observed.castleWallBuildSha}`,
    `SANCTUARY_CASTLE_SIGNER_CLIENT=${CASTLE_WALL_SIGNER_CLIENT}`,
    input.observed.nodePath,
    ...(sealedFullRuntime ? [] : [persistentCliPath]),
    "--fortress",
    input.fortress,
    "protect",
    "--hermes",
    "--no-open",
    "--provision-agent-account",
    "--agent-guided",
    "--strict",
    "--sealed-launcher",
    DEFAULT_CASTLE_WALL_LAUNCHER,
  ];
  plan.status = "human_action";
  // Finding A: this privileged flow arms the content filter, and the FIRST arm
  // on a host raises a one-time macOS "would like to filter network content"
  // approval dialog inside saveToPreferences. Unapproved, the arm blocks until
  // it times out (observed live: two silent timeouts before the operator clicked
  // Allow). The dialog is only raised WHILE the arm runs, and the approval is not
  // separately observable from here: `castle-wall status` collapses the
  // pre-approval state to content_filter=disabled/unknown, indistinguishable
  // from a filter that is simply not armed yet. So the honest signal for "the
  // arm has not yet succeeded on this host" is content_filter != enabled, and the
  // named action both runs the arm and tells the operator to expect and approve
  // the dialog (rather than a bare command that appears to hang). Once approved,
  // a rerun observes content_filter=enabled and advances. When the filter is
  // already armed, no dialog is pending and the plain privileged action stands.
  const contentFilterArmPending = input.observed.contentFilter !== "enabled";
  plan.next_action = contentFilterArmPending
    ? {
        id: "approve_content_filter",
        actor: "human",
        description:
          "Run this exact command in a private local Terminal and authorize sudo there. The FIRST time the content filter arms, macOS raises a one-time 'Sanctuary-CastleWall would like to filter network content' dialog (also reachable at System Settings > General > Login Items & Extensions > Network Extensions). Click Allow. Until you do, the command appears to hang and will time out. The agent must not execute the command or receive a reusable sudo timestamp.",
        argv: privilegedInstallArgv,
        completion:
          "A rerun observes the cooperative wrap and boot service present, the content filter enabled, and enforcement live.",
        secret_boundary:
          "The operator enters the administrator password directly into sudo and clicks Allow on the macOS filter dialog. The agent must not request, store, relay, or automate that password, the dialog approval, or the resulting authorization.",
      }
    : {
        id: "install_full_surface",
        actor: "human",
        description:
          "Run this exact command in a private local Terminal and authorize sudo there. The agent must not execute it or receive a reusable sudo timestamp.",
        argv: privilegedInstallArgv,
        completion:
          "A rerun observes the cooperative wrap and boot service present, the content filter enabled, and enforcement live.",
        secret_boundary:
          "The operator enters the administrator password directly into sudo. The agent must not request, store, relay, or automate that password or the resulting authorization.",
      };
  return plan;
}

function printHelp(out: Writable): void {
  write(
    out,
    `sanctuary install. Resumable, observed-state installation contract for shell-capable agents.\n\n` +
      `Usage:\n` +
      `  sanctuary install --profile memory --harness <name> [--json]\n` +
      `  sanctuary install --profile full --harness hermes [--json]\n\n` +
      `The command does not mutate the host. It returns exactly one next action. Rerun it after that action.\n` +
      `Full profile is currently macOS + Hermes only and requires a separately verified signed Castle Wall app.\n` +
      `Recovery secrets are never emitted by this contract.\n`,
  );
}

function renderHuman(plan: AgentInstallPlan): string {
  const lines = [
    `Sanctuary agent install: ${plan.status}`,
    `Profile: ${plan.profile}; harness: ${plan.harness}; fortress: ${plan.fortress}`,
  ];
  if (plan.next_action !== null) {
    lines.push(`Next (${plan.next_action.actor}): ${plan.next_action.description}`);
    if (plan.next_action.argv !== undefined) {
      lines.push(`Argv: ${JSON.stringify(plan.next_action.argv)}`);
    }
  }
  for (const action of plan.operator_actions) lines.push(`Operator: ${action.description}`);
  for (const note of plan.notes) lines.push(`Note: ${note}`);
  return `${lines.join("\n")}\n`;
}

export async function runInstallCommand(ctx: InstallCommandContext = {}): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const parsed = parseInstallArgs(ctx.argv ?? []);
  if (parsed.help) {
    printHelp(out);
    return 0;
  }
  if (parsed.error !== undefined || parsed.harness === undefined) {
    write(err, `${parsed.error ?? "--harness is required"}\n`);
    return 2;
  }
  const env = ctx.env ?? process.env;
  const fortress = resolveStoragePath(env);
  const ops = { ...createInstallOps(ctx), ...(ctx.ops ?? {}) };
  const observed = await ops.probe({
    profile: parsed.profile,
    harness: parsed.harness,
    fortress,
  });
  const plan = buildAgentInstallPlan({
    profile: parsed.profile,
    harness: parsed.harness,
    fortress,
    platform: ctx.platform ?? process.platform,
    observed,
  });
  write(out, parsed.json ? `${JSON.stringify(plan, null, 2)}\n` : renderHuman(plan));
  return 0;
}
