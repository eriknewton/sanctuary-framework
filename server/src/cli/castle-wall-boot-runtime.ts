import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";

export const CASTLE_WALL_PROTECTED_DIR =
  "/Library/Application Support/Sanctuary";
export const CASTLE_WALL_BOOT_RUNTIME_DIR = join(
  CASTLE_WALL_PROTECTED_DIR,
  "boot-runtime",
);

const DEFAULT_TRUSTED_ANCESTOR = "/Library/Application Support";
const MAX_NODE_BYTES = 512 * 1024 * 1024;
const MAX_CLI_BYTES = 128 * 1024 * 1024;
const MAX_SIGNER_BYTES = 64 * 1024 * 1024;
const SIGNER_REQUIREMENT =
  'anchor apple generic and certificate leaf[subject.OU] = "YFQSWQ9BJN" and identifier "ai.sanctuaryprotocol.macos.castle-wall.signer-client"';
const NODE_REQUIREMENT =
  'anchor apple generic and certificate leaf[subject.OU] = "YFQSWQ9BJN" and identifier "ai.sanctuaryprotocol.macos.castle-wall.node"';
const APP_IDENTIFIER = "ai.sanctuaryprotocol.macos";
const APP_HEADLESS_CONTRACT = "3";
const APP_NODE_RELATIVE = "Contents/Resources/boot-runtime/node";
const APP_DAEMON_RELATIVE = "Contents/Resources/boot-runtime/castle-wall-boot-daemon.js";
const APP_SIGNER_RELATIVE = "Contents/MacOS/castle-wall-signer-client";
const CONTENT_HASH_RE = /^[a-f0-9]{64}$/;

function hasExactCodesignField(text: string, field: string, value: string): boolean {
  return text.split(/\r?\n/).some((line) => line === `${field}=${value}`);
}

export interface BootRuntimeExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface BootRuntimeSnapshot {
  nodePath: string;
  cliPath: string;
  signerClientPath: string;
  programArguments: string[];
}

export interface InstallBootRuntimeOptions {
  cliSourcePath: string;
  nodeSourcePath: string;
  signerClientSourcePath: string;
  execFileFn: (cmd: string, args: string[]) => BootRuntimeExecResult;
  signedAppPath?: string;
  runtimeDir?: string;
  protectedDir?: string;
  trustedAncestorDir?: string;
  expectedOwnerUid?: number;
}

export interface RemoveBootRuntimeOptions {
  runtimeDir?: string;
  protectedDir?: string;
  trustedAncestorDir?: string;
  expectedOwnerUid?: number;
}

function modeOf(mode: number): number {
  return mode & 0o777;
}

async function ensureCustodyDirectory(
  path: string,
  expectedOwnerUid: number,
  create: boolean,
): Promise<void> {
  if (create) {
    await mkdir(path, { mode: 0o755 }).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") throw error;
    });
  }
  const stats = await lstat(path);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error(`${path} must be a real directory, not a link or other file type.`);
  }
  if (stats.uid !== expectedOwnerUid) {
    throw new Error(`${path} must be owned by uid ${expectedOwnerUid}.`);
  }
  if ((modeOf(stats.mode) & 0o022) !== 0) {
    throw new Error(`${path} must not be writable by group or other users.`);
  }
}

async function ensureBootRuntimeDirectory(options: {
  trustedAncestorDir: string;
  protectedDir: string;
  runtimeDir: string;
  expectedOwnerUid: number;
}): Promise<void> {
  const ancestor = resolve(options.trustedAncestorDir);
  const protectedDir = resolve(options.protectedDir);
  const runtimeDir = resolve(options.runtimeDir);
  if (dirname(protectedDir) !== ancestor || dirname(runtimeDir) !== protectedDir) {
    throw new Error("Boot runtime directories must be direct descendants of the declared custody roots.");
  }
  await ensureCustodyDirectory(ancestor, options.expectedOwnerUid, false);
  await ensureCustodyDirectory(protectedDir, options.expectedOwnerUid, true);
  await ensureCustodyDirectory(ancestor, options.expectedOwnerUid, false);
  await ensureCustodyDirectory(runtimeDir, options.expectedOwnerUid, true);
  await ensureCustodyDirectory(protectedDir, options.expectedOwnerUid, false);
}

async function readRegularSource(
  sourcePath: string,
  label: string,
  maxBytes: number,
  custodyRoot?: string,
): Promise<Buffer> {
  const pathStats = await lstat(sourcePath);
  if (pathStats.isSymbolicLink()) {
    throw new Error(`${label} source must not be a symbolic link.`);
  }
  const canonicalPath = await realpath(sourcePath);
  if (custodyRoot !== undefined) {
    const canonicalRoot = await realpath(custodyRoot);
    if (!canonicalPath.startsWith(`${canonicalRoot}/`)) {
      throw new Error(`${label} source escaped the root-owned signed-app snapshot.`);
    }
  }
  const data = await readFileCustody(canonicalPath, { verifyPathIdentity: true });
  if (data.length === 0 || data.length > maxBytes) {
    throw new Error(`${label} has an invalid size (${data.length} bytes).`);
  }
  return data;
}

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

async function writeAndVerifySnapshot(options: {
  path: string;
  data: Buffer;
  mode: number;
  expectedOwnerUid: number;
  runtimeDir: string;
}): Promise<void> {
  await writeFileCustody(options.path, options.data, {
    mode: options.mode,
    createParent: false,
    parent: {
      uid: options.expectedOwnerUid,
      mode: { rejectGroupOrOtherWrite: true },
    },
  });
  const installed = await readFileCustody(options.path, {
    uid: options.expectedOwnerUid,
    mode: { exact: options.mode },
    parent: {
      uid: options.expectedOwnerUid,
      mode: { rejectGroupOrOtherWrite: true },
    },
    verifyPathIdentity: true,
  });
  if (!installed.equals(options.data)) {
    throw new Error(`Boot runtime snapshot verification failed for ${options.path}.`);
  }
  await ensureCustodyDirectory(options.runtimeDir, options.expectedOwnerUid, false);
}

function verifySystemOnlyDynamicLibraries(
  executablePath: string,
  label: string,
  execFileFn: InstallBootRuntimeOptions["execFileFn"],
): void {
  const result = execFileFn("/usr/bin/otool", ["-L", executablePath]);
  if (result.code !== 0) {
    throw new Error(
      `${label} dynamic-library inspection failed: ${result.stderr.trim() || result.stdout.trim()}`,
    );
  }
  const dependencies = [...result.stdout.matchAll(/^\s+(\S+)\s+\(compatibility version/gm)]
    .map((match) => match[1]!)
    .filter((path) => path !== executablePath);
  if (dependencies.length === 0) {
    throw new Error(`${label} dynamic-library inspection returned no verifiable dependencies.`);
  }
  const unsafe = dependencies.find(
    (path) => !path.startsWith("/System/Library/") && !path.startsWith("/usr/lib/"),
  );
  if (unsafe !== undefined) {
    throw new Error(`${label} depends on non-system dynamic library ${unsafe}.`);
  }
}

function verifyCodeRequirement(
  executablePath: string,
  label: string,
  requirement: string,
  execFileFn: InstallBootRuntimeOptions["execFileFn"],
): void {
  const result = execFileFn("/usr/bin/codesign", [
    "--verify",
    "--strict",
    `--requirement=${requirement}`,
    executablePath,
  ]);
  if (result.code !== 0) {
    throw new Error(
      `${label} code-signing verification failed: ${result.stderr.trim() || result.stdout.trim()}`,
    );
  }
}

function verifySignedApp(
  appPath: string,
  execFileFn: InstallBootRuntimeOptions["execFileFn"],
): void {
  const verified = execFileFn("/usr/bin/codesign", ["--verify", "--deep", "--strict", appPath]);
  if (verified.code !== 0) {
    throw new Error(`Castle Wall app signature verification failed: ${verified.stderr.trim() || verified.stdout.trim()}`);
  }
  const identity = execFileFn("/usr/bin/codesign", ["-dv", "--verbose=4", appPath]);
  const identityText = `${identity.stdout}\n${identity.stderr}`;
  if (
    identity.code !== 0 ||
    !hasExactCodesignField(identityText, "Identifier", APP_IDENTIFIER) ||
    !hasExactCodesignField(identityText, "TeamIdentifier", "YFQSWQ9BJN")
  ) {
    throw new Error("Castle Wall app does not have Sanctuary's required bundle and team identity.");
  }
  const gatekeeper = execFileFn("/usr/sbin/spctl", ["--assess", "--type", "execute", appPath]);
  if (gatekeeper.code !== 0) {
    throw new Error(`Castle Wall app failed Gatekeeper assessment: ${gatekeeper.stderr.trim() || gatekeeper.stdout.trim()}`);
  }
  const plistPath = join(appPath, "Contents", "Info.plist");
  const contract = execFileFn("/usr/bin/plutil", [
    "-extract",
    "SanctuaryCastleWallHeadlessContractVersion",
    "raw",
    "-o",
    "-",
    plistPath,
  ]);
  const buildSha = execFileFn("/usr/bin/plutil", [
    "-extract",
    "SanctuaryCastleWallGitSHA",
    "raw",
    "-o",
    "-",
    plistPath,
  ]);
  if (
    contract.code !== 0 ||
    contract.stdout.trim() !== APP_HEADLESS_CONTRACT ||
    buildSha.code !== 0 ||
    !/^[a-f0-9]{12}$/.test(buildSha.stdout.trim())
  ) {
    throw new Error("Castle Wall app does not carry the required headless contract and build identity.");
  }
}

function requireSignedAppSources(options: InstallBootRuntimeOptions, appPath: string): void {
  const expected = [
    [options.nodeSourcePath, join(appPath, APP_NODE_RELATIVE), "Node executable"],
    [options.cliSourcePath, join(appPath, APP_DAEMON_RELATIVE), "Castle Wall boot daemon"],
    [options.signerClientSourcePath, join(appPath, APP_SIGNER_RELATIVE), "Castle Wall signer client"],
  ] as const;
  for (const [actual, required, label] of expected) {
    if (resolve(actual) !== resolve(required)) {
      throw new Error(`${label} must come from the verified Castle Wall app at ${required}.`);
    }
  }
}

export function isContentAddressedBootRuntimePath(
  path: string,
  kind: "node" | "cli" | "signer-client",
  runtimeDir: string = CASTLE_WALL_BOOT_RUNTIME_DIR,
): boolean {
  const prefix = kind === "cli" ? "cli-" : `${kind}-`;
  const suffix = kind === "cli" ? ".js" : "";
  if (dirname(path) !== runtimeDir) return false;
  const name = path.slice(runtimeDir.length + 1);
  if (!name.startsWith(prefix) || !name.endsWith(suffix)) return false;
  const digest = name.slice(prefix.length, suffix.length === 0 ? undefined : -suffix.length);
  return CONTENT_HASH_RE.test(digest);
}

export async function installBootRuntimeSnapshot(
  options: InstallBootRuntimeOptions,
): Promise<BootRuntimeSnapshot> {
  const runtimeDir = resolve(options.runtimeDir ?? CASTLE_WALL_BOOT_RUNTIME_DIR);
  const protectedDir = resolve(options.protectedDir ?? CASTLE_WALL_PROTECTED_DIR);
  const trustedAncestorDir = resolve(
    options.trustedAncestorDir ?? DEFAULT_TRUSTED_ANCESTOR,
  );
  const expectedOwnerUid = options.expectedOwnerUid ?? 0;
  await ensureBootRuntimeDirectory({
    trustedAncestorDir,
    protectedDir,
    runtimeDir,
    expectedOwnerUid,
  });
  let stagingRoot: string | undefined;
  let sourceRoot: string | undefined;
  let nodeSourcePath = options.nodeSourcePath;
  let cliSourcePath = options.cliSourcePath;
  let signerClientSourcePath = options.signerClientSourcePath;
  try {
    if (options.signedAppPath !== undefined) {
      const signedAppPath = resolve(options.signedAppPath);
      requireSignedAppSources(options, signedAppPath);
      stagingRoot = await mkdtemp(join(protectedDir, ".boot-runtime-source-"));
      await ensureCustodyDirectory(stagingRoot, expectedOwnerUid, false);
      sourceRoot = join(stagingRoot, "Sanctuary-CastleWall.app");
      const copied = options.execFileFn("/usr/bin/ditto", [signedAppPath, sourceRoot]);
      if (copied.code !== 0) {
        throw new Error(
          `Could not snapshot the Castle Wall app into root custody: ${copied.stderr.trim() || copied.stdout.trim()}`,
        );
      }
      await ensureCustodyDirectory(stagingRoot, expectedOwnerUid, false);
      verifySignedApp(sourceRoot, options.execFileFn);
      nodeSourcePath = join(sourceRoot, APP_NODE_RELATIVE);
      cliSourcePath = join(sourceRoot, APP_DAEMON_RELATIVE);
      signerClientSourcePath = join(sourceRoot, APP_SIGNER_RELATIVE);
    }

    const [nodeData, cliData, signerData] = await Promise.all([
      readRegularSource(nodeSourcePath, "Node executable", MAX_NODE_BYTES, sourceRoot),
      readRegularSource(cliSourcePath, "Castle Wall boot daemon", MAX_CLI_BYTES, sourceRoot),
      readRegularSource(signerClientSourcePath, "Castle Wall signer client", MAX_SIGNER_BYTES, sourceRoot),
    ]);
    const nodePath = join(runtimeDir, `node-${sha256(nodeData)}`);
    const cliPath = join(runtimeDir, `cli-${sha256(cliData)}.js`);
    const signerClientPath = join(runtimeDir, `signer-client-${sha256(signerData)}`);

    await writeAndVerifySnapshot({
      path: nodePath,
      data: nodeData,
      mode: 0o555,
      expectedOwnerUid,
      runtimeDir,
    });
    await writeAndVerifySnapshot({
      path: cliPath,
      data: cliData,
      mode: 0o444,
      expectedOwnerUid,
      runtimeDir,
    });
    await writeAndVerifySnapshot({
      path: signerClientPath,
      data: signerData,
      mode: 0o555,
      expectedOwnerUid,
      runtimeDir,
    });

    verifySystemOnlyDynamicLibraries(nodePath, "Node executable", options.execFileFn);
    verifySystemOnlyDynamicLibraries(
      signerClientPath,
      "Castle Wall signer client",
      options.execFileFn,
    );
    verifyCodeRequirement(
      nodePath,
      "App-bundled Node runtime",
      NODE_REQUIREMENT,
      options.execFileFn,
    );
    verifyCodeRequirement(
      signerClientPath,
      "Signer client",
      SIGNER_REQUIREMENT,
      options.execFileFn,
    );

    return {
      nodePath,
      cliPath,
      signerClientPath,
      programArguments: [
        nodePath,
        cliPath,
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
    };
  } finally {
    if (stagingRoot !== undefined) {
      await rm(stagingRoot, { recursive: true });
    }
  }
}

export async function removeBootRuntimeSnapshot(
  options: RemoveBootRuntimeOptions = {},
): Promise<boolean> {
  const runtimeDir = resolve(options.runtimeDir ?? CASTLE_WALL_BOOT_RUNTIME_DIR);
  const protectedDir = resolve(options.protectedDir ?? CASTLE_WALL_PROTECTED_DIR);
  const trustedAncestorDir = resolve(
    options.trustedAncestorDir ?? DEFAULT_TRUSTED_ANCESTOR,
  );
  const expectedOwnerUid = options.expectedOwnerUid ?? 0;
  if (dirname(protectedDir) !== trustedAncestorDir || dirname(runtimeDir) !== protectedDir) {
    throw new Error("Boot runtime directories must be direct descendants of the declared custody roots.");
  }
  try {
    await ensureCustodyDirectory(trustedAncestorDir, expectedOwnerUid, false);
    await ensureCustodyDirectory(protectedDir, expectedOwnerUid, false);
    await ensureCustodyDirectory(runtimeDir, expectedOwnerUid, false);
  } catch (error) {
    const code = error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return false;
    throw error;
  }
  await rm(runtimeDir, { recursive: true });
  await ensureCustodyDirectory(protectedDir, expectedOwnerUid, false);
  try {
    await lstat(runtimeDir);
  } catch (error) {
    const code = error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
    if (code === "ENOENT") return true;
    throw error;
  }
  throw new Error(`Boot runtime removal did not remove ${runtimeDir}.`);
}
