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
  getPlatformPaths,
  hasExistingWrapMetaStrict,
} from "../wrap/config-reader.js";
import {
  CASTLE_WALL_BOOT_PLIST_PATH,
  bootServicePlistPresent,
  bootServiceReady,
} from "./castle-wall-boot.js";
import { parseCastleWallState, runStatus, type SysextState } from "./castle-wall.js";

declare const __SANCTUARY_SOURCE_SHA__: string;

const execFileAsync = promisify(nodeExecFile);

export const AGENT_INSTALL_CONTRACT = "sanctuary.agent-install.v1";
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
  const required = new Set([
    "MacOS/sanctuary",
    "Resources/boot-runtime/node",
    "Resources/cli-runtime/dist/cli.js",
  ]);
  let totalBytes = 0;
  for (const entry of manifest.files) {
    if (
      typeof entry.path !== "string" ||
      !/^[a-f0-9]{64}$/.test(entry.sha256) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0
    ) return false;
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
  return (
    required.size === 0 &&
    inventory.file_count === manifest.files.length &&
    inventory.file_count <= CASTLE_WALL_RUNTIME_MAX_FILES &&
    inventory.total_bytes === totalBytes &&
    inventory.total_bytes <= CASTLE_WALL_RUNTIME_MAX_BYTES &&
    inventory.package_count === inventory.packages.length &&
    inventory.mach_o_count === inventory.mach_o.length &&
    inventory.mach_o.every((path) => manifest.files.some((entry) => entry.path === path)) &&
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

export interface AgentInstallAction {
  id: string;
  actor: "agent" | "human";
  description: string;
  argv?: string[];
  completion: string;
  secret_boundary?: string;
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
    castle_wall_app: InstallObservation;
    castle_wall_build_sha: string | null;
    system_extension: SysextState | "unknown" | "not-applicable";
    boot_service: InstallObservation;
    content_filter: "enabled" | "disabled" | "unknown" | "not-applicable";
    enforcement: "live" | "unavailable" | "undetermined" | "not-applicable";
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
  nodePath: string;
  castleWallApp: InstallObservation;
  castleWallBuildSha: string | null;
  systemExtension: SysextState | "unknown" | "not-applicable";
  bootService: InstallObservation;
  contentFilter: "enabled" | "disabled" | "unknown" | "not-applicable";
  enforcement: "live" | "unavailable" | "undetermined" | "not-applicable";
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

async function probeSystemExtension(): Promise<SysextState | "unknown"> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/systemextensionsctl", ["list"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    const matching = stdout
      .split("\n")
      .find((line) => line.includes("ai.sanctuaryprotocol.macos.castle-wall"));
    return parseCastleWallState(matching ?? "");
  } catch {
    return "unknown";
  }
}

async function probeWallStatus(
  env: NodeJS.ProcessEnv,
): Promise<Pick<InstallProbeResult, "contentFilter" | "enforcement">> {
  const chunks: string[] = [];
  try {
    await runStatus({ out: captureWritable(chunks), env, platform: "darwin" });
  } catch {
    return { contentFilter: "unknown", enforcement: "undetermined" };
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
  return { contentFilter, enforcement };
}

function createInstallOps(ctx: InstallCommandContext): AgentInstallOps {
  const platform = ctx.platform ?? process.platform;
  const env = ctx.env ?? process.env;
  return {
    probe: async ({ profile, harness, fortress }) => {
      const cooperativeWrap = await probeWrap(harness);
      const [pathCli, packageManagerPath] = await Promise.all([
        probePersistentCli(),
        probeExecutableOnPath("npm"),
      ]);
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
          nodePath,
          castleWallApp: "not-applicable",
          castleWallBuildSha: null,
          systemExtension: "not-applicable",
          bootService: "not-applicable",
          contentFilter: "not-applicable",
          enforcement: "not-applicable",
        };
      }
      const [castleWallApp, systemExtension, bootService, wall] = await Promise.all([
        verifiedCastleWallApp === null ? probeCastleWallApp() : verifiedCastleWallApp,
        probeSystemExtension(),
        probeBootService(fortress),
        probeWallStatus(env),
      ]);
      return {
        cooperativeWrap,
        persistentCli: persistentCli.status,
        persistentCliPath: persistentCli.path,
        persistentCliVersion: persistentCli.version,
        packageManagerPath,
        nodePath,
        castleWallApp: castleWallApp.status,
        castleWallBuildSha: castleWallApp.buildSha,
        systemExtension,
        bootService,
        ...wall,
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
      castle_wall_app: observed.castleWallApp,
      castle_wall_build_sha: observed.castleWallBuildSha,
      system_extension: observed.systemExtension,
      boot_service: observed.bootService,
      content_filter: observed.contentFilter,
      enforcement: observed.enforcement,
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
      plan.status = "complete";
      plan.operator_actions = [recoveryCustodyAction(input.fortress)];
      plan.notes.push("The cooperative encrypted-memory and policy surface is installed.");
      return plan;
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
    plan.status = "agent_action";
    plan.next_action = {
      id: "install_cooperative_surface",
      actor: "agent",
      description: "Run Sanctuary's idempotent protect flow for the selected harness.",
      argv: [...protectArgs, "--no-provision-agent-account"],
      completion: "A rerun observes cooperative_wrap=present.",
      secret_boundary: "Do not add --passphrase or --write-passphrase-backup; default custody does not disclose the generated passphrase.",
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
  const fullMechanicsComplete =
    input.observed.cooperativeWrap === "present" &&
    input.observed.systemExtension === "[activated enabled]" &&
    input.observed.bootService === "present" &&
    input.observed.contentFilter === "enabled" &&
    input.observed.enforcement === "live";
  if (fullMechanicsComplete) {
    plan.status = "complete";
    plan.operator_actions = [recoveryCustodyAction(input.fortress)];
    plan.notes.push("The full mechanical install is observed: wrap, boot service, content filter, and live enforcement.");
    plan.notes.push("Only an attended reboot drill proves boot survival on this specific machine.");
    return plan;
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
  plan.status = "human_action";
  plan.next_action = {
    id: "install_full_surface",
    actor: "human",
    description:
      "Run this exact command in a private local Terminal and authorize sudo there. The agent must not execute it or receive a reusable sudo timestamp.",
    argv: [
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
      "--sealed-launcher",
      DEFAULT_CASTLE_WALL_LAUNCHER,
    ],
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
