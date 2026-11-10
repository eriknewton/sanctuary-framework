/**
 * Stable runtime selection for `install-full`: choose a lexical Node and CLI
 * path that survives a Homebrew upgrade, validate custody without mutating
 * anything, and keep the lexical path (never its Cellar realpath) for the
 * saved LaunchAgent arguments. It never checks for an observer, never shells
 * out to a package manager, and never searches PATH.
 */
import * as fs from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, normalize, sep } from "node:path";
import { IPC_DEADLINE } from "../castle-wall/liveness/constants.js";

// Must match STABLE_RUNTIME_REFUSAL_EXIT_CODE in server/src/castle-wall/liveness/constants.ts.
export { STABLE_RUNTIME_REFUSAL_EXIT_CODE } from "../castle-wall/liveness/constants.js";

/** Automatic Node candidates, in order: maintained `opt` aliases first, then the prefix bin links. */
export const DEFAULT_NODE_CANDIDATES: readonly string[] = Object.freeze([
  "/opt/homebrew/opt/node/bin/node",
  "/usr/local/opt/node/bin/node",
  "/opt/homebrew/bin/node",
  "/usr/local/bin/node",
]);
/** Stable global-package CLI entry points, in order. */
export const DEFAULT_CLI_CANDIDATES: readonly string[] = Object.freeze([
  "/opt/homebrew/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
  "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
]);
export const SANCTUARY_PACKAGE_NAME = "@sanctuary-framework/mcp-server";

/** Group or other write permission. */
const GROUP_OTHER_WRITE = 0o022;
/** Any execute permission bit. */
const ANY_EXECUTE = 0o111;
/** The sticky bit, which lets a root-owned shared directory refuse cross-user replacement. */
const STICKY = 0o1000;
const ROOT_UID = 0;
/** Path segments that name a version-specific install rather than a maintained alias. */
const UNSTABLE_SEGMENTS: readonly string[] = Object.freeze(["Cellar", ".nvm", ".volta", ".asdf", ".fnm", ".nodenv", ".n"]);
/** A `node@<major>` keg segment is allowed only directly under a maintained `opt` directory. */
const VERSIONED_OPT = /^node@\d+$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/;
/** Bytes of `node --version` output accepted; a version line is a few dozen bytes. */
const VERSION_MAX_BUFFER = 1024;

export interface StableRuntimeFs {
  realpathSync(path: string): string;
  statSync(path: string): { uid: number; mode: number; isFile(): boolean; isDirectory(): boolean };
  readFileSync(path: string, encoding: "utf8"): string;
}

export interface StableRuntimeOptions {
  /** The running interpreter path (`process.execPath`). */
  execPath: string;
  /** The running CLI entry (`process.argv[1]`). */
  cliPath: string;
  operatorUid: number;
  /** A deliberately supplied absolute Node candidate; it may name another installed runtime. */
  explicitNode?: string;
  explicitCli?: string;
  nodeCandidates?: readonly string[];
  cliCandidates?: readonly string[];
  /** Temporary roots a stable path may never live under. */
  tempRoots?: readonly string[];
  runningNodeVersion?: string;
  /** Probe an explicit runtime's version under IPC_DEADLINE; null on any failure. */
  versionProbe?: (node: string) => string | null;
  fs?: StableRuntimeFs;
}

export type StableRuntimeResult =
  | { ok: true; node: string; cli: string; nodeVersion: string }
  | { ok: false; reason: string };

function defaultVersionProbe(node: string): string | null {
  try {
    return execFileSync(node, ["--version"], { encoding: "utf8", timeout: IPC_DEADLINE, maxBuffer: VERSION_MAX_BUFFER, stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function defaultTempRoots(): string[] {
  return [tmpdir(), "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders"];
}

function within(path: string, root: string): boolean {
  const normalizedRoot = normalize(root).replace(/\/+$/, "");
  return normalizedRoot.length > 0 && (path === normalizedRoot || path.startsWith(`${normalizedRoot}${sep}`));
}

/** Lexical checks only: absolute, no control characters, no temporary root, no version directory. */
function lexicalRefusal(path: string, tempRoots: readonly string[]): string | null {
  if (!isAbsolute(path)) return "path is not absolute";
  if (CONTROL.test(path)) return "path contains control characters";
  if (normalize(path) !== path) return "path is not normalized";
  if (tempRoots.some(root => within(path, root))) return "path is under a temporary directory";
  const segments = path.split(sep);
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!;
    if (UNSTABLE_SEGMENTS.includes(segment)) return `path names a version-specific install (${segment})`;
    if (VERSIONED_OPT.test(segment) && segments[i - 1] !== "opt") return "versioned node directory outside a maintained opt alias";
  }
  return null;
}

/** Custody of a resolved file and of each ancestor of its lexical path. */
function custodyRefusal(io: StableRuntimeFs, lexical: string, resolved: string, operatorUid: number): string | null {
  const owned = (uid: number) => uid === ROOT_UID || uid === operatorUid;
  const file = io.statSync(resolved);
  if (!file.isFile()) return "target is not a regular file";
  if (!owned(file.uid) || (file.mode & GROUP_OTHER_WRITE) !== 0) return "target is writable by another principal";
  for (const start of [lexical, resolved]) {
    let dir = dirname(start);
    for (;;) {
      const info = io.statSync(dir);
      // A shared root-owned sticky directory cannot have entries replaced by another user; anything else writable by group or other is unsafe.
      const shared = (info.mode & GROUP_OTHER_WRITE) !== 0;
      const stickyRoot = info.uid === ROOT_UID && (info.mode & STICKY) !== 0;
      if (!info.isDirectory()) return "ancestor is not a directory";
      if (!owned(info.uid) || (shared && !stickyRoot)) return `unsafe parent custody at ${dir}`;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return null;
}

function majorOf(version: string): number | null {
  const match = /^v?(\d+)\./.exec(version.trim());
  return match ? Number(match[1]) : null;
}

/** The minimum major from a `>=N` engines range; any other range shape is not understood. */
function minimumMajor(range: string): number | null {
  const match = /^>=\s*(\d+)(\.\d+){0,2}$/.exec(range.trim());
  return match ? Number(match[1]) : null;
}

/**
 * Select and validate the stable runtime (selection steps one to four). Step
 * five, comparing rendered and loaded arguments, runs after bootstrap in a
 * normal install only.
 */
export function resolveStableRuntime(options: StableRuntimeOptions): StableRuntimeResult {
  const io = options.fs ?? fs;
  const tempRoots = options.tempRoots ?? defaultTempRoots();
  const resolveOrNull = (path: string): string | null => {
    try { return io.realpathSync(path); } catch { return null; }
  };
  const validate = (lexical: string, executable: boolean): string | null => {
    const lexicalIssue = lexicalRefusal(lexical, tempRoots);
    if (lexicalIssue) return lexicalIssue;
    const resolved = resolveOrNull(lexical);
    if (resolved === null) return "path is missing or loops";
    try {
      const custody = custodyRefusal(io, lexical, resolved, options.operatorUid);
      if (custody) return custody;
      if (executable && (io.statSync(resolved).mode & ANY_EXECUTE) === 0) return "target is not executable";
    } catch {
      return "path is missing or unreadable";
    }
    return null;
  };

  // Step 1 and 2: Node.
  let node: string | null = null;
  let nodeVersion: string | null;
  if (options.explicitNode !== undefined) {
    const issue = validate(options.explicitNode, true);
    if (issue) return { ok: false, reason: `explicit Node ${issue}` };
    nodeVersion = (options.versionProbe ?? defaultVersionProbe)(options.explicitNode);
    if (nodeVersion === null) return { ok: false, reason: "explicit Node did not report a version" };
    node = options.explicitNode;
  } else {
    const running = resolveOrNull(options.execPath);
    if (running === null) return { ok: false, reason: "running Node path cannot be resolved" };
    // The running interpreter's realpath is matched, never relabelled: the saved path is the lexical candidate.
    for (const candidate of options.nodeCandidates ?? DEFAULT_NODE_CANDIDATES) {
      if (resolveOrNull(candidate) !== running) continue;
      if (validate(candidate, true) === null) { node = candidate; break; }
    }
    if (node === null) return { ok: false, reason: "no stable Node candidate resolves to the running Node" };
    nodeVersion = options.runningNodeVersion ?? process.versions.node;
  }

  // Step 4: the CLI lexical path, its package identity and its Node range.
  let cli: string | null = null;
  if (options.explicitCli !== undefined) {
    const issue = validate(options.explicitCli, false);
    if (issue) return { ok: false, reason: `explicit CLI ${issue}` };
    cli = options.explicitCli;
  } else {
    const running = resolveOrNull(options.cliPath);
    if (running === null) return { ok: false, reason: "running CLI path cannot be resolved" };
    for (const candidate of options.cliCandidates ?? DEFAULT_CLI_CANDIDATES) {
      if (resolveOrNull(candidate) !== running) continue;
      if (validate(candidate, false) === null) { cli = candidate; break; }
    }
    if (cli === null) return { ok: false, reason: "no stable CLI candidate resolves to the running CLI" };
  }
  let manifest: { name?: unknown; engines?: { node?: unknown } };
  try {
    manifest = JSON.parse(io.readFileSync(join(dirname(dirname(cli)), "package.json"), "utf8")) as typeof manifest;
  } catch {
    return { ok: false, reason: "CLI package manifest is unreadable" };
  }
  if (manifest.name !== SANCTUARY_PACKAGE_NAME) return { ok: false, reason: "CLI package identity does not match" };
  const required = typeof manifest.engines?.node === "string" ? minimumMajor(manifest.engines.node) : null;
  const major = majorOf(nodeVersion);
  if (required === null || major === null || major < required) return { ok: false, reason: "Node version is outside the package's supported range" };
  return { ok: true, node, cli, nodeVersion };
}
