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
  bootServiceLoadState,
  CASTLE_WALL_BOOT_LABEL,
  FORBIDDEN_PLIST_ENV,
  serviceRunningPid,
  type ExecFileResult,
} from "./castle-wall-boot.js";
import {
  FullAgentStateStore,
  FULL_AGENT_THROTTLE_INTERVAL_S,
  FULL_AGENT_START_TO_ARMED_BUDGET_S,
} from "./castle-wall-full-agent-state.js";
export { FULL_AGENT_THROTTLE_INTERVAL_S } from "./castle-wall-full-agent-state.js";

// must match FULL_AGENT_LABEL in server/reorg-surface-manifest.md.
export const FULL_AGENT_LABEL = "ai.sanctuaryprotocol.castle-wall.full";
const MS_PER_SECOND = 1000;
const LAUNCHCTL_TIMEOUT_MS = 10 * MS_PER_SECOND; // One local launchctl request budget.
const STABLE_SAMPLE_INTERVAL_MS = MS_PER_SECOND;
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
  execFileFn?: (command: string, args: string[]) => ExecFileResult;
  observePassphrase?: typeof observeStoredPassphrase;
  sleep?: (ms: number) => Promise<void>;
  stateStore?: (fortress: string) => FullAgentStateStore;
}

function launchctl(command: string, args: string[]): ExecFileResult {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: LAUNCHCTL_TIMEOUT_MS });
  return { code: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
function context(argv: string[], input: FullAgentCommandContext) {
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error) throw new Error(fortress.error);
  const env = input.env ?? process.env;
  const home = input.home ?? homedir();
  const uid = input.euid ?? process.geteuid!();
  const fortressPath = resolve(fortress.value ?? resolveStoragePath(env, home));
  return {
    out: input.out ?? process.stdout,
    err: input.err ?? process.stderr,
    home, uid, fortressPath,
    platform: input.platform ?? process.platform,
    isTTY: input.isTTY ?? process.stdin.isTTY === true,
    io: input.fs ?? fs,
    exec: input.execFileFn ?? launchctl,
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
function loadedPid(ctx: AgentContext): number | null {
  // Reuse the boot parser; this transport adapter selects the user-domain target.
  // The boot-daemon label is imported above, so guidance and its load probe cannot drift.
  return serviceRunningPid(() => ctx.exec("launchctl", ["print", ctx.target]));
}
function boundJob(ctx: AgentContext): ExecFileResult | null {
  const printed = ctx.exec("launchctl", ["print", ctx.target]);
  let plist = "";
  try { plist = ctx.io.readFileSync(ctx.plist, "utf8"); } catch { /* Missing installed identity refuses binding. */ }
  const installed = plistProgramArguments(plist);
  const block = /^\s*arguments = \{\s*\n([\s\S]*?)^\s*\}/m.exec(printed.stdout)?.[1];
  const loaded = block?.split("\n").map(line => line.trim().replace(/^\d+\s*=\s*/, "").replace(/^"(.*)"$/, "$1")).filter(Boolean) ?? [];
  const fortressArgument = (args: string[]): string | undefined => {
    // cli-argv-indexof-allowed: searches launchd ProgramArguments read from the plist and launchctl print, not CLI argv tokens.
    const index = args.indexOf("--fortress"), last = args.lastIndexOf("--fortress");
    return index >= 0 && last === index ? args[index + 1] : undefined;
  };
  const canonical = (path: string): string => {
    try { return ctx.io.realpathSync(path); } catch { return path; }
  };
  const installedFortress = fortressArgument(installed), loadedFortress = fortressArgument(loaded);
  // The pid and counter describe the same fortress only when installed and loaded arguments both bind to the requested path.
  if (printed.code !== 0 || !fullAgentLaunchAgentWellFormed(plist) || !installedFortress || !loadedFortress ||
      canonical(installedFortress) !== canonical(loadedFortress) || canonical(installedFortress) !== canonical(ctx.fortressPath)) {
    ctx.err.write("the installed full LaunchAgent serves a different fortress\n");
    return null;
  }
  return printed;
}

function removePlist(ctx: AgentContext): void {
  try { ctx.io.unlinkSync(ctx.plist); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}

function bootoutSucceeded(result: ExecFileResult): boolean {
  // Adapt the result through the existing load-state classifier, including its fail-closed treatment of unknown errors.
  return result.code === 0 || !bootServiceLoadState(() => result).loaded;
}

function rollbackInstall(ctx: AgentContext): void {
  try {
    const printed = ctx.exec("launchctl", ["print", ctx.target]);
    if (bootServiceLoadState(() => printed).loaded && !bootoutSucceeded(ctx.exec("launchctl", ["bootout", ctx.target]))) {
      ctx.err.write("Full LaunchAgent rollback bootout failed.\n");
    }
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
    const ctx = context(argv, input);
    if (refuseUnsupported(ctx)) return 1;
    if (!ctx.isTTY) { err.write("install-full requires an attended TTY session.\n"); return 2; }
    if (bootServiceLoadState(ctx.exec).loaded) {
      err.write(`The safe-mode boot daemon is loaded. Run 'sudo launchctl bootout system/${CASTLE_WALL_BOOT_LABEL}' before install-full.\n`);
      return 1;
    }
    const credential = await (input.observePassphrase ?? observeStoredPassphrase)({
      storagePath: ctx.fortressPath, home: ctx.home, readOnly: true, platformOverride: "darwin",
    });
    if (credential.status !== "found") { err.write("No stored credential is available for this fortress.\n"); return 1; }
    const cli = ctx.io.realpathSync(input.cliPath ?? process.argv[1]!);
    const plist = generateFullAgentPlist([input.execPath ?? process.execPath, cli, "castle-wall", "daemon", "--fortress", ctx.fortressPath, "--launch-agent"]);
    if (!fullAgentLaunchAgentWellFormed(plist)) throw new Error("Full LaunchAgent validation failed.");
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
    const pid = await stablePid(ctx, input.sleep ?? (ms => new Promise(resolveWait => setTimeout(resolveWait, ms))));
    if (pid === null) throw new Error("Full LaunchAgent did not maintain a stable running pid; inspect full-status and its logs.");
    ctx.out.write(`Full LaunchAgent installed; running pid=${pid}.\n`);
    rollback = undefined;
    return 0;
  } catch (error) {
    if (rollback) {
      try { rollbackInstall(rollback); }
      catch { err.write("Full LaunchAgent rollback failed; inspect the job and plist.\n"); }
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
    const result = ctx.exec("launchctl", ["bootout", ctx.target]);
    if (!bootoutSucceeded(result)) { err.write("Full LaunchAgent bootout failed; its plist was retained.\n"); return 1; }
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
    const pid = serviceRunningPid(() => printed);
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
    const printed = boundJob(ctx);
    if (!printed) return 1;
    if (serviceRunningPid(() => printed) !== null) { err.write("Stop the running full daemon before resetting its counter.\n"); return 1; }
    ctx.state.reset();
    const result = ctx.exec("launchctl", ["kickstart", ctx.target]);
    if (result.code !== 0) { err.write("Counter reset, but full LaunchAgent kickstart failed.\n"); return 1; }
    ctx.out.write("Full LaunchAgent counter reset; start requested.\n");
    return 0;
  } catch (error) { err.write(`reset-full failed: ${error instanceof Error ? error.message : String(error)}\n`); return 1; }
}
