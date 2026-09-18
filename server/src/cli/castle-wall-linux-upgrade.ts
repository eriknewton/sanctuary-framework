/** Privileged, offline replacement of an already provisioned fixed Linux unit. */
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, normalize } from "node:path";
import {
  openDirectoryCustodyWithinBase,
  readFileCustodyWithStats,
  verifyDirectoryCustodyWithinBase,
} from "../storage/custody-fs.js";
import {
  executeLinuxUpgradeRoute,
  realUpgradeCommandRunner,
  type LinuxUpgradeRoute,
  type UpgradeCommandRunner,
} from "../castle-wall/runtime/linux-upgrade-routes.js";
import {
  CASTLE_WALL_DAEMON_BINARY_DEFAULT,
  CASTLE_WALL_SYSTEMD_UNIT,
} from "../castle-wall/runtime/linux-daemon.js";

const SYSTEMCTL = "/usr/bin/systemctl";
const UNIT_FRAGMENT = "/etc/systemd/system/sanctuary-castle-wall.service";
const UNIT_ENV = "/etc/sanctuary/castle-wall.env";
const INSTALLED_CLI = "/usr/local/libexec/sanctuary/server/dist/cli.js";
const MAX_BINARY_BYTES = 128 * 1024 * 1024;
export interface FixedUpgradePaths {
  systemctl: string;
  fragment: string;
  environment: string;
  cli: string;
  binary: string;
}
const INSTALLED_PATHS: FixedUpgradePaths = {
  systemctl: SYSTEMCTL, fragment: UNIT_FRAGMENT, environment: UNIT_ENV,
  cli: INSTALLED_CLI, binary: CASTLE_WALL_DAEMON_BINARY_DEFAULT,
};
/** Internal transaction seam: the CLI always supplies INSTALLED_PATHS and root custody. */
export interface LinuxUpgradeTransactionDependencies {
  paths: FixedUpgradePaths;
  custodyBase: string;
  custodyUid: number;
  runner: UpgradeCommandRunner;
  /** Existing FD custody seam, used by tests to race a pathname after fstat. */
  onDescriptorVerified?: (path: string) => void | Promise<void>;
}
const SHOW_PROPERTIES = [
  "LoadState", "FragmentPath", "DropInPaths", "NeedDaemonReload",
  "EnvironmentFiles", "Environment", "ExecStart", "ExecStartPre", "ExecStartPreEx",
  "ExecCondition", "ExecConditionEx", "ExecStartPost", "ExecStartPostEx",
  "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx",
] as const;

export interface LinuxUpgradeUnitIdentity {
  fortressId: string;
  trustedServiceUid: string;
  unitShow: string;
  environment: string;
  environmentDev: number;
  environmentIno: number;
  fragmentDev: number;
  fragmentIno: number;
  fragmentDigest: string;
}

function reject(message: string): never {
  throw new Error(`Linux upgrade refused: ${message}`);
}

function assertFixedCommands(
  value: string, field: string,
  expected: readonly { path: string; argv: readonly string[]; control: string }[],
): void {
  const records = value.match(/\{ (?:[^{}\r\n]|\$\{[A-Z_]+\})* \}/g);
  if (!records || records.length !== expected.length || records.join(" ") !== value) {
    reject(`effective ${field} differs from the shipped commands`);
  }
  for (const [index, record] of records.entries()) {
    const command = expected[index];
    const parts = record.slice(2, -2).split(" ; ");
    if (parts[0] !== `path=${command.path}` ||
        !parts[1]?.startsWith("argv[]=") ||
        !command.argv.includes(parts[1].slice("argv[]=".length)) ||
        parts[2] !== command.control) {
      reject(`effective ${field} differs from the shipped commands`);
    }
    const allowedMetadata = new Set(["start_time", "stop_time", "pid", "code", "status"]);
    const seen = new Set<string>();
    for (const part of parts.slice(3)) {
      // cli-argv-indexof-allowed: scans systemd command metadata, not CLI argv tokens.
      const separator = part.indexOf("=");
      const key = part.slice(0, separator);
      const metadata = part.slice(separator + 1);
      if (separator < 1 || !allowedMetadata.has(key) || seen.has(key) ||
          !/^[\w\s.[\]:/+()-]*$/.test(metadata)) {
        reject(`unsupported ${field} metadata`);
      }
      seen.add(key);
    }
    if (seen.size !== allowedMetadata.size) reject(`incomplete ${field} metadata`);
  }
}

/** Reject any systemd output outside the one supported fixed-unit grammar. */
export function parseFixedUnitShow(
  raw: string, fortressId: string, trustedServiceUid: string,
  paths: FixedUpgradePaths = INSTALLED_PATHS,
): void {
  const properties = new Map<string, string>();
  for (const line of raw.replace(/\n$/, "").split("\n")) {
    // cli-argv-indexof-allowed: scans a systemctl show property line, not CLI argv tokens.
    const separator = line.indexOf("=");
    if (separator < 1 || line.includes("\r")) reject("invalid systemctl show output");
    const key = line.slice(0, separator);
    if (!SHOW_PROPERTIES.includes(key as typeof SHOW_PROPERTIES[number]) || properties.has(key)) {
      reject("unknown or duplicate systemctl property");
    }
    properties.set(key, line.slice(separator + 1));
  }
  if (properties.size !== SHOW_PROPERTIES.length ||
      properties.get("LoadState") !== "loaded" ||
      properties.get("FragmentPath") !== paths.fragment ||
      properties.get("DropInPaths") !== "" ||
      properties.get("NeedDaemonReload") !== "no" ||
      properties.get("Environment") !== "" ||
      ![paths.environment, `${paths.environment} (ignore_errors=no)`].includes(properties.get("EnvironmentFiles") ?? "")) {
    reject("effective systemd unit differs from the fixed supported unit");
  }
  for (const hook of ["ExecCondition", "ExecConditionEx", "ExecStartPost", "ExecStartPostEx",
    "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx"] as const) {
    if (properties.get(hook) !== "") reject(`unsupported effective ${hook} hook`);
  }
  const literalArgv = `${paths.binary} --fortress-id \${SANCTUARY_FORTRESS_ID} --trusted-service-uid \${SANCTUARY_TRUSTED_SERVICE_UID}`;
  const expandedArgv = `${paths.binary} --fortress-id ${fortressId} --trusted-service-uid ${trustedServiceUid}`;
  assertFixedCommands(properties.get("ExecStart") ?? "", "ExecStart", [{
    path: paths.binary,
    argv: [literalArgv, expandedArgv],
    control: "ignore_errors=no",
  }]);
  const firstPreLiteral = "/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/${SANCTUARY_FORTRESS_ID}";
  const firstPreExpanded = `/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/${fortressId}`;
  const pre = [
    { path: "/usr/bin/install", argv: [firstPreLiteral, firstPreExpanded] },
    { path: "/usr/bin/install", argv: ["/usr/bin/install -d -o root -g sanctuary -m 0700 /run/sanctuary/locks"] },
  ];
  assertFixedCommands(properties.get("ExecStartPre") ?? "", "ExecStartPre", pre.map((command) => ({
    ...command, control: "ignore_errors=no",
  })));
  assertFixedCommands(properties.get("ExecStartPreEx") ?? "", "ExecStartPreEx", pre.map((command, index) => ({
    ...command, control: index === 0 ? "flags=" : "flags=privileged",
  })));
}

/** Only two plain assignments are supported by the shipped unit. */
export function parseFixedUnitEnvironment(raw: string): { fortressId: string; trustedServiceUid: string } {
  const lines = raw.replace(/\n$/, "").split("\n");
  if (lines.length !== 2 || lines.some((line) => line.includes("\r"))) {
    reject("environment file must contain exactly two plain assignments");
  }
  const values = new Map<string, string>();
  for (const line of lines) {
    const match = /^([A-Z_]+)=([a-z0-9]+)$/.exec(line);
    if (!match || values.has(match[1])) reject("invalid or duplicate environment assignment");
    values.set(match[1], match[2]);
  }
  const fortressId = values.get("SANCTUARY_FORTRESS_ID") ?? "";
  const trustedServiceUid = values.get("SANCTUARY_TRUSTED_SERVICE_UID") ?? "";
  if (!/^[a-f0-9]{8,64}$/.test(fortressId) || !/^[1-9][0-9]{0,9}$/.test(trustedServiceUid) ||
      Number(trustedServiceUid) >= 4294967295 ||
      values.size !== 2) {
    reject("environment identity or trusted service UID is invalid");
  }
  return { fortressId, trustedServiceUid };
}

/** Reject C0 and DEL in the candidate pathname without weakening the lint rule. */
function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

export function parseLinuxUpgradeArgv(
  argv: readonly string[], installedBinary = CASTLE_WALL_DAEMON_BINARY_DEFAULT,
): { route: LinuxUpgradeRoute; candidate: string } {
  if (argv.length !== 4 || argv[0] !== "--route" ||
      (argv[1] !== "disarm" && argv[1] !== "reboot") || argv[2] !== "--candidate" ||
      !isAbsolute(argv[3]) || normalize(argv[3]) !== argv[3] || hasAsciiControl(argv[3]) ||
      argv[3] === installedBinary) {
    reject("usage: sanctuary castle-wall upgrade-linux --route disarm|reboot --candidate ABSOLUTE_PATH");
  }
  return { route: argv[1] as LinuxUpgradeRoute, candidate: argv[3] };
}

async function checkedRootFile(
  path: string, maxBytes: number, deps: LinuxUpgradeTransactionDependencies,
  exactMode?: number, requireExecute = true,
): Promise<{ bytes: Buffer; dev: number; ino: number }> {
  await verifyDirectoryCustodyWithinBase(dirname(path), deps.custodyBase, {
    uid: deps.custodyUid, mode: { rejectGroupOrOtherWrite: true }, verifyEveryComponent: true,
  });
  const { data, stats } = await readFileCustodyWithStats(path, {
    uid: deps.custodyUid,
    mode: exactMode === undefined ? { rejectGroupOrOtherWrite: true } : { exact: exactMode },
    parent: { uid: deps.custodyUid, mode: { rejectGroupOrOtherWrite: true } },
    verifyPathIdentity: true,
    onDescriptorVerified: ({ stats: opened }) => {
      if (opened.size < 1 || opened.size > maxBytes ||
          (requireExecute && (opened.mode & 0o111) === 0)) {
        reject(`unsafe size or mode for ${path}`);
      }
      return deps.onDescriptorVerified?.(path);
    },
  });
  return { bytes: data, dev: stats.dev, ino: stats.ino };
}

async function fixedUnitIdentity(deps: LinuxUpgradeTransactionDependencies): Promise<LinuxUpgradeUnitIdentity> {
  const result = await deps.runner.run(deps.paths.systemctl, ["show", CASTLE_WALL_SYSTEMD_UNIT,
    `--property=${SHOW_PROPERTIES.join(",")}`]);
  if (result.code !== 0) reject(`systemctl show failed: ${result.stderr || result.stdout}`);
  const envFile = await checkedRootFile(deps.paths.environment, 4096, deps, 0o600, false);
  const environment = envFile.bytes.toString("utf8");
  const { fortressId, trustedServiceUid } = parseFixedUnitEnvironment(environment);
  parseFixedUnitShow(result.stdout, fortressId, trustedServiceUid, deps.paths);
  const fragment = await checkedRootFile(deps.paths.fragment, 128 * 1024, deps, undefined, false);
  return {
    fortressId, trustedServiceUid, unitShow: result.stdout, environment,
    environmentDev: envFile.dev, environmentIno: envFile.ino,
    fragmentDev: fragment.dev, fragmentIno: fragment.ino,
    fragmentDigest: createHash("sha256").update(fragment.bytes).digest("hex"),
  };
}

async function assertSameFile(
  path: string, dev: number, ino: number, digest: string, deps: LinuxUpgradeTransactionDependencies,
): Promise<void> {
  const current = await checkedRootFile(path, MAX_BINARY_BYTES, deps);
  if (current.dev !== dev || current.ino !== ino ||
      createHash("sha256").update(current.bytes).digest("hex") !== digest) {
    reject(`staged or installed binary changed: ${path}`);
  }
}

/** A real route invocation. No caller-selected unit, target, or command path. */
export async function runCastleWallLinuxUpgrade(argv: readonly string[]): Promise<number> {
  try {
    if (process.platform !== "linux" || process.geteuid?.() !== 0 ||
        process.argv[1] !== INSTALLED_CLI || !isAbsolute(process.execPath) ||
        process.env.NODE_OPTIONS !== undefined || process.env.NODE_PATH !== undefined) {
      reject("requires Linux root and the trusted installed CLI under a sanitized absolute Node invocation");
    }
    return await runCastleWallLinuxUpgradeTransaction(argv, {
      paths: INSTALLED_PATHS, custodyBase: "/", custodyUid: 0,
      runner: realUpgradeCommandRunner(),
    });
  } catch (err) {
    // SAFETY: stderr is the operator-facing failure channel for this offline CLI.
    console.error(err instanceof Error ? err.message : String(err));
    console.error("Linux upgrade stopped. Check the fixed unit, installed binary, and service state before manual recovery.");
    return 1;
  }
}

/** @internal Exercise the actual privileged caller against controlled custody fixtures. */
export async function runCastleWallLinuxUpgradeTransaction(
  argv: readonly string[], deps: LinuxUpgradeTransactionDependencies,
): Promise<number> {
  let stagePath: string | undefined;
  try {
    const { route, candidate } = parseLinuxUpgradeArgv(argv, deps.paths.binary);
    await checkedRootFile(deps.paths.cli, 32 * 1024 * 1024, deps, undefined, false);
    await checkedRootFile(deps.paths.systemctl, MAX_BINARY_BYTES, deps);
    const identity = await fixedUnitIdentity(deps);
    const old = await checkedRootFile(deps.paths.binary, MAX_BINARY_BYTES, deps);
    const oldDigest = createHash("sha256").update(old.bytes).digest("hex");
    const incoming = await checkedRootFile(candidate, MAX_BINARY_BYTES, deps);
    if (incoming.dev === old.dev && incoming.ino === old.ino) {
      reject("candidate is the installed daemon inode");
    }
    const destination = dirname(deps.paths.binary);
    const guard = await openDirectoryCustodyWithinBase(destination, deps.custodyBase, {
      uid: deps.custodyUid, mode: { rejectGroupOrOtherWrite: true }, verifyEveryComponent: true,
    });
    try {
      stagePath = join(destination, `.castle-wall-upgrade-${randomBytes(16).toString("hex")}`);
      await guard.revalidate();
      const stage = await open(stagePath, fsConstants.O_WRONLY | fsConstants.O_CREAT |
        fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
      try {
        if (deps.custodyUid === 0) await stage.chown(0, 0);
        await stage.chmod(0o755);
        await stage.writeFile(incoming.bytes);
        await stage.sync();
      } finally {
        await stage.close();
      }
      const staged = await lstat(stagePath);
      const digest = createHash("sha256").update(incoming.bytes).digest("hex");
      const stagedPath = stagePath;
      const guardedRunner: UpgradeCommandRunner = {
        run: async (command, args) => {
          if (command === deps.paths.systemctl && args[0] === "stop") {
            const current = await fixedUnitIdentity(deps);
            if (current.unitShow !== identity.unitShow || current.environment !== identity.environment ||
                current.environmentDev !== identity.environmentDev || current.environmentIno !== identity.environmentIno ||
                current.fragmentDev !== identity.fragmentDev || current.fragmentIno !== identity.fragmentIno ||
                current.fragmentDigest !== identity.fragmentDigest ||
                current.fortressId !== identity.fortressId) {
              reject("effective unit or environment changed before stop");
            }
            await assertSameFile(stagedPath, staged.dev, staged.ino, digest, deps);
            await assertSameFile(deps.paths.binary, old.dev, old.ino, oldDigest, deps);
          }
          return deps.runner.run(command, args);
        },
      };
      const result = await executeLinuxUpgradeRoute({
        route, newBinaryPath: stagedPath, installedBinaryPath: deps.paths.binary,
        target: { kind: "fortress_id", fortressId: identity.fortressId },
        runner: guardedRunner, systemctlBinary: deps.paths.systemctl,
        replaceBinary: async () => {
          await assertSameFile(stagedPath, staged.dev, staged.ino, digest, deps);
          await guard.revalidate();
          await rename(stagedPath, deps.paths.binary);
          const dir = await open(destination, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
          try { await dir.sync(); } finally { await dir.close(); }
          const replaced = await checkedRootFile(deps.paths.binary, MAX_BINARY_BYTES, deps);
          if (replaced.dev !== staged.dev || replaced.ino !== staged.ino ||
              createHash("sha256").update(replaced.bytes).digest("hex") !== digest) {
            reject("replacement verification failed after rename");
          }
        },
      });
      if (result.outcome === "aborted") {
        // SAFETY: stderr reports the aborted upgrade step for manual recovery.
        console.error(`Linux upgrade aborted at ${result.abort?.step} (exit ${result.abort?.exit_code ?? "unknown"}): ${result.abort?.output}`);
        console.error(`Completed: ${result.completed_steps.join(", ") || "none"}. Recover manually; do not start an unverified binary.`);
        return 1;
      }
      // SAFETY: stdout reports the requested operation without claiming verified health.
      console.log(route === "reboot" ? "Linux upgrade: reboot requested; health after boot is not verified." :
        "Linux upgrade: fixed unit started; verify service health manually.");
      return 0;
    } finally {
      await guard.close();
    }
  } catch (err) {
    // SAFETY: stderr is the operator-facing failure channel for this offline CLI.
    console.error(err instanceof Error ? err.message : String(err));
    console.error("Linux upgrade stopped. Check the fixed unit, installed binary, and service state before manual recovery.");
    return 1;
  } finally {
    if (stagePath !== undefined) await unlink(stagePath).catch((err: NodeJS.ErrnoException) => {
      // SAFETY: stderr surfaces a failed temporary-stage cleanup for manual recovery.
      if (err.code !== "ENOENT") console.error(`Could not remove upgrade stage ${stagePath}: ${err.message}`);
    });
  }
}
