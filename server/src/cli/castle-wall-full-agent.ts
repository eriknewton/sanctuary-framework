/** Attended installation and observation of the operator-user full daemon. */
import * as fs from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Writable } from "node:stream";
import { resolveStoragePath } from "../paths.js";
import { observeStoredPassphrase } from "../wrap/passphrase.js";
import { consumeFlagValue } from "./argv.js";
import {
  CASTLE_WALL_BOOT_LABEL,
  FORBIDDEN_PLIST_ENV,
} from "./castle-wall-boot.js";
import {
  FullAgentStateStore,
  FULL_AGENT_THROTTLE_INTERVAL_S,
  FULL_AGENT_START_TO_ARMED_BUDGET_S,
} from "./castle-wall-full-agent-state.js";
export { FULL_AGENT_THROTTLE_INTERVAL_S } from "./castle-wall-full-agent-state.js";

// must match FULL_AGENT_LABEL in server/reorg-surface-manifest.md.
export const FULL_AGENT_LABEL = "ai.sanctuaryprotocol.castle-wall.full";
const MS_PER_SECOND = 1000; // Milliseconds in one second.
// launchctl print exits 113 with empty stdout for a label launchd does not hold (captured 2026-11-03 on macOS 26.6.2: stderr "Could not find service ... in domain for user gui: 501"); the Mini2 drill re-verifies it.
export const LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS = 113;
const LAUNCHD_PID = 1; // macOS launchd is the system's initial process.
const LAUNCHCTL_TIMEOUT_MS = 10 * MS_PER_SECOND; // One local launchctl request budget.
const STABLE_SAMPLE_INTERVAL_MS = MS_PER_SECOND;
/** Distinguish incomplete rollback from success (0), ordinary failure (1) and usage refusal (2). */
export const FULL_AGENT_ROLLBACK_INCOMPLETE_EXIT_CODE = 3;
const PROGRAM_ARGUMENT_COUNT = 7; // Interpreter, CLI, group, verb, fortress flag, fortress path, supervision flag.
// must match FULL_AGENT_THROTTLE_INTERVAL_S derivation in server/src/cli/castle-wall-full-agent-state.ts.
// Observe one full sample interval beyond the restart throttle.
const STABLE_WINDOW_MS = FULL_AGENT_THROTTLE_INTERVAL_S * MS_PER_SECOND + STABLE_SAMPLE_INTERVAL_MS;

function escapeXml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
function unescapeXml(value: string): string {
  return value.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
function assertSafeText(value: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(value)) throw new Error("Control characters are not allowed in LaunchAgent values.");
}

/** Render only the fixed full-daemon command, with PATH as its sole environment entry. */
export function generateFullAgentPlist(programArguments: readonly string[]): string {
  // must match --launch-agent consumption in runDaemon in server/src/cli/castle-wall.ts.
  if (programArguments.length !== PROGRAM_ARGUMENT_COUNT || programArguments[2] !== "castle-wall" || programArguments[3] !== "daemon" || programArguments[4] !== "--fortress" || programArguments[6] !== "--launch-agent") {
    throw new Error("Full LaunchAgent arguments must identify the supervised full daemon.");
  }
  for (const argument of programArguments) assertSafeText(argument);
  const [node, cli] = programArguments;
  const fortress = programArguments[5]!;
  if (!node || !cli || !isAbsolute(node) || !isAbsolute(cli) || !isAbsolute(fortress)) {
    throw new Error("Full LaunchAgent executable, CLI and fortress paths must be absolute.");
  }
  const environment = [["PATH", [...new Set([dirname(node), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])].join(":")]];
  for (const [key, value] of environment) {
    if (key !== "PATH" || FORBIDDEN_PLIST_ENV.includes(key!)) throw new Error("Forbidden LaunchAgent environment name.");
    assertSafeText(value!);
  }
  // Must match CASTLE_WALL_STOP_DEADLINE_MS and CASTLE_WALL_STOP_EXIT_DEADLINE_MS in castle-wall/constants.ts: the plist sets no ExitTimeOut, so launchd's default 20-second window applies and STOP < EXIT < that window.
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${FULL_AGENT_LABEL}</string>
\t<key>ProgramArguments</key>
\t<array>
${programArguments.map(argument => `\t\t<string>${escapeXml(argument)}</string>`).join("\n")}
\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>KeepAlive</key>
\t<dict>
\t\t<key>SuccessfulExit</key>
\t\t<false/>
\t</dict>
\t<key>ThrottleInterval</key>
\t<integer>${FULL_AGENT_THROTTLE_INTERVAL_S}</integer>
\t<key>LimitLoadToSessionType</key>
\t<string>Aqua</string>
\t<key>EnvironmentVariables</key>
\t<dict>
\t\t<key>PATH</key>
\t\t<string>${escapeXml(environment[0]![1]!)}</string>
\t</dict>
\t<key>StandardOutPath</key>
\t<string>${escapeXml(join(fortress, "logs", "castle-wall-full.log"))}</string>
\t<key>StandardErrorPath</key>
\t<string>${escapeXml(join(fortress, "logs", "castle-wall-full.err.log"))}</string>
\t<key>WorkingDirectory</key>
\t<string>/</string>
</dict>
</plist>
`;
}

function plistProgramArguments(contents: string): string[] {
  const array = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(contents)?.[1] ?? "";
  return [...array.matchAll(/<string>([\s\S]*?)<\/string>/g)].map(match => unescapeXml(match[1]!));
}

/** Accept exactly the renderer's fixed contract, rejecting duplicate or additional keys too. */
export function fullAgentLaunchAgentWellFormed(contents: string): boolean {
  if (FORBIDDEN_PLIST_ENV.some(name => contents.includes(name))) return false;
  const args = plistProgramArguments(contents);
  try { return generateFullAgentPlist(args) === contents; }
  catch { return false; }
}

/** Preserve normal exit, signal termination and spawn failure as separate observations. */
export interface FullAgentExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  signal?: NodeJS.Signals | null;
  error?: Error;
}
type AgentFs = Pick<typeof fs, "mkdirSync" | "writeFileSync" | "openSync" | "closeSync" | "fchmodSync" | "unlinkSync" | "realpathSync" | "readFileSync">;
export interface FullAgentCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  home?: string;
  platform?: NodeJS.Platform;
  euid?: number;
  isTTY?: boolean;
  cliPath?: string;
  execPath?: string;
  fs?: AgentFs;
  execFileFn?: (command: string, args: string[]) => FullAgentExecResult;
  observePassphrase?: typeof observeStoredPassphrase;
  sleep?: (ms: number) => Promise<void>;
  stateStore?: (fortress: string) => FullAgentStateStore;
}

function launchctl(command: string, args: string[]): FullAgentExecResult {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: LAUNCHCTL_TIMEOUT_MS });
  return { code: result.status, signal: result.signal, error: result.error, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
function context(argv: string[], input: FullAgentCommandContext) {
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error) throw new Error(fortress.error);
  const env = input.env ?? process.env;
  const home = input.home ?? homedir();
  const uid = input.euid ?? process.geteuid!();
  const requestedFortress = fortress.value ?? resolveStoragePath(env, home);
  if (!isAbsolute(requestedFortress)) throw new Error("Full LaunchAgent fortress path must be absolute.");
  const fortressPath = resolve(requestedFortress);
  return {
    out: input.out ?? process.stdout,
    err: input.err ?? process.stderr,
    home, uid, fortressPath,
    platform: input.platform ?? process.platform,
    isTTY: input.isTTY ?? process.stdin.isTTY === true,
    io: input.fs ?? fs,
    exec: input.execFileFn ?? launchctl,
    sleep: input.sleep ?? ((ms: number) => new Promise<void>(resolveWait => setTimeout(resolveWait, ms))),
    target: `gui/${uid}/${FULL_AGENT_LABEL}`,
    domain: `gui/${uid}`,
    plist: join(home, "Library", "LaunchAgents", `${FULL_AGENT_LABEL}.plist`),
    state: (input.stateStore ?? (path => new FullAgentStateStore(path)))(fortressPath),
  };
}
type AgentContext = ReturnType<typeof context>;
function refuseUnsupported(ctx: AgentContext): boolean {
  if (ctx.platform !== "darwin" || ctx.uid === 0) {
    ctx.err.write("Full daemon LaunchAgent commands require a non-root macOS operator session.\n");
    return true;
  }
  return false;
}
/** Interpret only service-level fields and the service's own arguments block. */
function parseFullAgentPrint(stdout: string): { valid: boolean; pid: number | null; arguments: string[] } {
  const blocks: string[] = [];
  const args: string[] = [];
  let pid: number | null = null;
  let pidFields = 0;
  let argumentBlocks = 0;
  let state_CLOSED = false;
  // Only depth-1 service fields describe this job; nested dictionaries and argument text cannot establish a running pid.
  for (const raw of stdout.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (state_CLOSED) return { valid: false, pid: null, arguments: [] };
    if (line === "}") {
      if (blocks.length === 0) return { valid: false, pid: null, arguments: [] };
      blocks.pop();
      if (blocks.length === 0) state_CLOSED = true;
      continue;
    }
    if (blocks.length === 2 && blocks[1] === "arguments") {
      const argument = line.replace(/^\d+\s*=\s*/, "");
      if (argument.startsWith('"')) {
        try {
          const decoded: unknown = JSON.parse(argument);
          if (typeof decoded !== "string") return { valid: false, pid: null, arguments: [] };
          args.push(decoded);
        } catch { return { valid: false, pid: null, arguments: [] }; }
      } else args.push(argument);
      continue;
    }
    const opening = /^(.*?)\s*=\s*\{$/.exec(line);
    if (opening) {
      const name = opening[1]!;
      if (blocks.length === 1 && name === "arguments") argumentBlocks++;
      blocks.push(name);
      continue;
    }
    if (blocks.length === 1) {
      const field = /^pid\s*=\s*(.*)$/.exec(line);
      if (field) {
        pidFields++;
        const value = /^\d+$/.test(field[1]!) ? Number(field[1]) : NaN;
        pid = Number.isSafeInteger(value) && value > 0 ? value : null;
      }
    }
  }
  if (!state_CLOSED || blocks.length !== 0) return { valid: false, pid: null, arguments: [] };
  return { valid: true, pid: pidFields === 1 && argumentBlocks === 1 ? pid : null, arguments: argumentBlocks === 1 ? args : [] };
}

type FullAgentPrint =
  | { state: "state_LOADED"; pid: number | null; arguments: string[] }
  | { state: "state_UNLOADED" }
  | { state: "state_INDETERMINATE"; spawnFailure: boolean };

function observeJob(exec: NonNullable<FullAgentCommandContext["execFileFn"]>, target: string): FullAgentPrint {
  let printed: FullAgentExecResult;
  try { printed = exec("launchctl", ["print", target]); }
  catch { return { state: "state_INDETERMINATE", spawnFailure: true }; }
  // Only a normal not-found exit without a service block establishes absence; payload phrases carry no lifecycle authority.
  if (!printed.error && !printed.signal && printed.code === LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS &&
      !/^[^\n]*=\s*\{\s*$/m.test(printed.stdout)) return { state: "state_UNLOADED" };
  const parsed = parseFullAgentPrint(printed.stdout);
  if (!printed.error && !printed.signal && printed.code === 0 && parsed.valid) {
    return { state: "state_LOADED", pid: parsed.pid, arguments: parsed.arguments };
  }
  return { state: "state_INDETERMINATE", spawnFailure: !!printed.error };
}

/** Refuse counter access unless launchd identifies this process as the full label's instance. */
export function fullAgentAdmissionRefusal(ppid: number, pid: number, uid: number, exec = launchctl): string | null {
  if (ppid !== LAUNCHD_PID) return "--launch-agent requires a launchd-spawned process (parent pid 1).";
  const printed = observeJob(exec, `gui/${uid}/${FULL_AGENT_LABEL}`);
  if (printed.state === "state_INDETERMINATE") {
    return printed.spawnFailure ? "--launch-agent launchctl spawn failure (INDETERMINATE)." : "--launch-agent launchctl print is INDETERMINATE.";
  }
  if (printed.state !== "state_LOADED" || printed.pid === null) return "--launch-agent launchd record has no pid.";
  // PID 1 parentage is shared by every reparented process; only launchd's own record of this label's pid identifies the supervised instance.
  if (printed.pid !== pid) return "--launch-agent launchd record has a different pid.";
  return null;
}

function loadedPid(ctx: AgentContext): number | null {
  const printed = observeJob(ctx.exec, ctx.target);
  if (printed.state === "state_INDETERMINATE") throw new Error("Full LaunchAgent job state is INDETERMINATE.");
  return printed.state === "state_LOADED" ? printed.pid : null;
}

type BoundJob = { state: "state_LOADED"; pid: number | null } | { state: "state_UNLOADED"; plistAbsent: boolean };
function boundJob(ctx: AgentContext, allowUnloaded = false): BoundJob | null {
  const printed = observeJob(ctx.exec, ctx.target);
  if (printed.state === "state_INDETERMINATE") {
    ctx.err.write("Full LaunchAgent job state is INDETERMINATE.\n");
    return null;
  }
  let plist: string;
  try { plist = ctx.io.readFileSync(ctx.plist, "utf8"); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    // Without an installed identity, only confirmed absence permits clearing the requested fortress without bootstrap.
    if (allowUnloaded && printed.state === "state_UNLOADED") return { state: "state_UNLOADED", plistAbsent: true };
    ctx.err.write("Full LaunchAgent plist is absent.\n");
    return null;
  }
  if (!fullAgentLaunchAgentWellFormed(plist)) {
    ctx.err.write("Full LaunchAgent plist is malformed.\n");
    return null;
  }
  const fortressArgument = (args: string[]): string | undefined => {
    // cli-argv-indexof-allowed: searches launchd ProgramArguments read from the plist and launchctl print, not CLI argv tokens.
    const index = args.indexOf("--fortress"), last = args.lastIndexOf("--fortress");
    return index >= 0 && last === index ? args[index + 1] : undefined;
  };
  const canonical = (path: string): string => {
    try { return ctx.io.realpathSync(path); } catch { return path; }
  };
  const installedFortress = fortressArgument(plistProgramArguments(plist))!;
  if (canonical(installedFortress) !== canonical(ctx.fortressPath)) {
    ctx.err.write("the installed full LaunchAgent serves a different fortress\n");
    return null;
  }
  // A loaded job binds both identities; an unloaded reset binds the installed identity before bootstrap.
  if (printed.state === "state_UNLOADED") {
    if (allowUnloaded) return { state: "state_UNLOADED", plistAbsent: false };
    ctx.err.write("Full LaunchAgent job is UNLOADED.\n");
    return null;
  }
  const loadedFortress = fortressArgument(printed.arguments);
  if (!loadedFortress || !isAbsolute(loadedFortress)) {
    ctx.err.write("Full LaunchAgent fortress binding is unavailable.\n");
    return null;
  }
  if (canonical(installedFortress) !== canonical(loadedFortress)) {
    ctx.err.write("the installed full LaunchAgent serves a different fortress\n");
    return null;
  }
  return { state: "state_LOADED", pid: printed.pid };
}

function removePlist(ctx: AgentContext): void {
  try { ctx.io.unlinkSync(ctx.plist); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}

async function state_CONFIRM_UNLOADED(ctx: AgentContext): Promise<boolean> {
  // Reuse the local launchctl request budget and sample cadence to bound unload observation.
  for (let elapsed = 0; elapsed <= LAUNCHCTL_TIMEOUT_MS; elapsed += STABLE_SAMPLE_INTERVAL_MS) {
    const printed = observeJob(ctx.exec, ctx.target);
    if (printed.state === "state_INDETERMINATE") throw new Error("Full LaunchAgent job state is INDETERMINATE; unload refused.");
    if (printed.state === "state_UNLOADED") return true;
    if (elapsed < LAUNCHCTL_TIMEOUT_MS) await ctx.sleep(STABLE_SAMPLE_INTERVAL_MS);
  }
  return false;
}

async function rollbackInstall(ctx: AgentContext): Promise<boolean> {
  try {
    const printed = observeJob(ctx.exec, ctx.target);
    if (printed.state !== "state_UNLOADED") ctx.exec("launchctl", ["bootout", ctx.target]);
    return await state_CONFIRM_UNLOADED(ctx);
  } finally { removePlist(ctx); }
}

async function stablePid(ctx: AgentContext, sleep: (ms: number) => Promise<void>): Promise<number | null> {
  const budget = FULL_AGENT_START_TO_ARMED_BUDGET_S * MS_PER_SECOND + STABLE_WINDOW_MS;
  let pid: number | null = null;
  let stableMs = 0;
  for (let elapsed = 0; elapsed <= budget; elapsed += STABLE_SAMPLE_INTERVAL_MS) {
    const observed = loadedPid(ctx);
    if (pid !== null && observed !== pid) return null;
    if (observed !== null) {
      if (pid === null) pid = observed;
      else stableMs += STABLE_SAMPLE_INTERVAL_MS;
      if (stableMs >= STABLE_WINDOW_MS) return pid;
    }
    if (elapsed < budget) await sleep(STABLE_SAMPLE_INTERVAL_MS);
  }
  return null;
}

/** Install after an attended credential preflight; a stable positive pid is required for success. */
export async function runInstallFull(argv: string[] = [], input: FullAgentCommandContext = {}): Promise<number> {
  const err = input.err ?? process.stderr;
  let rollback: AgentContext | undefined;
  try {
    // state_PREFLIGHT: no host mutation precedes session, job and credential checks.
    const ctx = context(argv, input);
    if (refuseUnsupported(ctx)) return 1;
    if (!ctx.isTTY) { err.write("install-full requires an attended TTY session.\n"); return 2; }
    const bootJob = observeJob(ctx.exec, `system/${CASTLE_WALL_BOOT_LABEL}`);
    if (bootJob.state === "state_INDETERMINATE") throw new Error("Safe-mode boot daemon job state is INDETERMINATE.");
    if (bootJob.state === "state_LOADED") {
      err.write(`The safe-mode boot daemon is loaded. Run 'sudo launchctl bootout system/${CASTLE_WALL_BOOT_LABEL}' before install-full.\n`);
      return 1;
    }
    const fullJob = observeJob(ctx.exec, ctx.target);
    if (fullJob.state === "state_INDETERMINATE") throw new Error("Full LaunchAgent job state is INDETERMINATE.");
    if (fullJob.state === "state_LOADED") {
      err.write("already installed; run uninstall-full first\n");
      return 1;
    }
    const credential = await (input.observePassphrase ?? observeStoredPassphrase)({
      storagePath: ctx.fortressPath, home: ctx.home, readOnly: true, platformOverride: "darwin",
    });
    if (credential.status !== "found") { err.write("No stored credential is available for this fortress.\n"); return 1; }
    const cli = ctx.io.realpathSync(input.cliPath ?? process.argv[1]!);
    const plist = generateFullAgentPlist([input.execPath ?? process.execPath, cli, "castle-wall", "daemon", "--fortress", ctx.fortressPath, "--launch-agent"]);
    if (!fullAgentLaunchAgentWellFormed(plist)) throw new Error("Full LaunchAgent validation failed.");
    // state_INSTALL: any failure after opening the plist enters rollback.
    ctx.io.mkdirSync(dirname(ctx.plist), { recursive: true });
    ctx.io.mkdirSync(join(ctx.fortressPath, "logs"), { recursive: true, mode: 0o700 });
    // The authorized destination is the plist itself; a symlink must not redirect this configuration write.
    const fd = ctx.io.openSync(ctx.plist, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o644);
    rollback = ctx;
    try {
      ctx.io.writeFileSync(fd, plist);
      ctx.io.fchmodSync(fd, 0o644);
    } finally { ctx.io.closeSync(fd); }
    const bootstrapped = ctx.exec("launchctl", ["bootstrap", ctx.domain, ctx.plist]);
    if (bootstrapped.code !== 0) throw new Error("Full LaunchAgent bootstrap failed.");
    // state_ARM: success requires a stable positive service-level pid.
    const pid = await stablePid(ctx, ctx.sleep);
    if (pid === null) throw new Error("Full LaunchAgent did not maintain a stable running pid; inspect full-status and its logs.");
    ctx.out.write(`Full LaunchAgent installed; running pid=${pid}.\n`);
    rollback = undefined;
    return 0;
  } catch (error) {
    // state_ROLLBACK: only confirmed unload may return the ordinary failure status.
    if (rollback) {
      let state_UNLOADED = false;
      try { state_UNLOADED = await rollbackInstall(rollback); }
      catch (error) { err.write(`Full LaunchAgent rollback failed: ${error instanceof Error ? error.message : String(error)}\n`); }
      if (!state_UNLOADED) {
        err.write("rollback incomplete: the job was not confirmed unloaded or its plist was not removed; run full-status, then uninstall-full\n");
        return FULL_AGENT_ROLLBACK_INCOMPLETE_EXIT_CODE;
      }
    }
    err.write(`install-full failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

/** Remove the user job and plist only after explicit --yes consent. */
export async function runUninstallFull(argv: string[] = [], input: FullAgentCommandContext = {}): Promise<number> {
  const err = input.err ?? process.stderr;
  if (!argv.includes("--yes")) { err.write("uninstall-full requires --yes.\n"); return 2; }
  try {
    const ctx = context(argv, input);
    if (refuseUnsupported(ctx)) return 1;
    ctx.exec("launchctl", ["bootout", ctx.target]);
    if (!await state_CONFIRM_UNLOADED(ctx)) { err.write("Full LaunchAgent bootout failed; its plist was retained.\n"); return 1; }
    removePlist(ctx);
    ctx.out.write("Full LaunchAgent uninstalled.\n");
    return 0;
  } catch (error) { err.write(`uninstall-full failed: ${error instanceof Error ? error.message : String(error)}\n`); return 1; }
}

/** Report both persistent admission state and an observed positive launchd pid. */
export async function runFullStatus(argv: string[] = [], input: FullAgentCommandContext = {}): Promise<number> {
  const err = input.err ?? process.stderr;
  try {
    const ctx = context(argv, input);
    if (refuseUnsupported(ctx)) return 1;
    const printed = boundJob(ctx);
    if (!printed) return 1;
    const state = ctx.state.read();
    const pid = printed.state === "state_LOADED" ? printed.pid : null;
    ctx.out.write(`Full LaunchAgent state=${state?.state ?? "state_ABSENT"} charges=${state?.charges_ms.length ?? 0} pid=${pid ?? "none"}\n`);
    return state?.state === "state_RUNNING" && pid !== null ? 0 : 1;
  } catch { err.write("Full LaunchAgent state is unavailable; inspect its counter and logs.\n"); return 1; }
}

/** Clear stopped accounting only in an attended --yes session, then ask launchd to start it. */
export async function runResetFull(argv: string[] = [], input: FullAgentCommandContext = {}): Promise<number> {
  const err = input.err ?? process.stderr;
  if (!argv.includes("--yes")) { err.write("reset-full requires --yes.\n"); return 2; }
  try {
    const ctx = context(argv, input);
    if (refuseUnsupported(ctx)) return 1;
    if (!ctx.isTTY) { err.write("reset-full requires an attended TTY session.\n"); return 2; }
    // state_BIND: verify the installed identity when present; absence permits unloaded recovery only.
    const state_BOUND = boundJob(ctx, true);
    if (!state_BOUND) return 1;
    if (state_BOUND.state === "state_LOADED") ctx.exec("launchctl", ["bootout", ctx.target]);
    // The unloaded observation is a snapshot. Two operator lifecycle commands run at once (reset, install or uninstall) are unsupported: they can stop the wall or erase every crash charge recorded since the other command started the job, including a fresh latch. Admission requires launchd's own pid for this label, so they do not admit a second daemon writer provided launchd keeps a booted-out job's record until its process exits; the Mini2 drill verifies that premise.
    if (!await state_CONFIRM_UNLOADED(ctx)) {
      err.write("Full LaunchAgent is still loaded; counter reset refused.\n");
      return 1;
    }
    // state_CLEAR: no record content is trusted on the attended recovery path.
    ctx.state.reset();
    if (state_BOUND.state === "state_UNLOADED" && state_BOUND.plistAbsent) {
      ctx.out.write(`Counter reset at ${ctx.state.directory}. No full LaunchAgent is installed; run install-full to start it.\n`);
      return 0;
    }
    // state_BOOTSTRAP: only the cleared, unloaded label may start again.
    const result = ctx.exec("launchctl", ["bootstrap", ctx.domain, ctx.plist]);
    if (result.code !== 0) { err.write("Counter reset, but full LaunchAgent bootstrap failed.\n"); return 1; }
    ctx.out.write("Full LaunchAgent counter reset; start requested.\n");
    return 0;
  } catch (error) { err.write(`reset-full failed: ${error instanceof Error ? error.message : String(error)}\n`); return 1; }
}
