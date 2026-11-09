/**
 * `castle-wall install-watch`, `run-watch` and `uninstall-watch`: the
 * observer LaunchAgent, the staged canary for the attended root install, and
 * the production observer composition. No verb here runs anything as root,
 * writes `config.json`, or reads a credential.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { homedir, hostname as osHostname, uptime as osUptime } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Writable } from "node:stream";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";
import {
  CANARY_LABEL,
  CONFIG_RECORD_FILE,
  LIVENESS_DIRECTORY,
  OBSERVER_LABEL,
  OBSERVER_RECORD_FILE,
  CHILD_READ_DEADLINE,
  KILL_REAP_GRACE,
  SECOND,
  TERM_GRACE,
  WATCH_THROTTLE_INTERVAL_S,
} from "../castle-wall/liveness/constants.js";
import { checkCanaryIntegrity, type CanaryIntegrityFacts } from "../castle-wall/liveness/canary-integrity.js";
import { CensusSampler, CensusSeries } from "../castle-wall/liveness/census-sampler.js";
import type { RecordRead } from "../castle-wall/liveness/evaluate.js";
import {
  CANARY_INSTALLED_PLIST_PATH,
  CANARY_STAGED_PLIST_NAME,
  canaryAccountNameValid,
  generateCanaryPlist,
  generateWatchAgentPlist,
  parseSystemJobPrint,
  systemJobNotFound,
  watchAgentLaunchAgentWellFormed,
} from "../castle-wall/liveness/launchd-plists.js";
import { LivenessObserver, observerHostId, type LivenessObserverDeps, type ObserverClock, type ObserverTimers } from "../castle-wall/liveness/observer.js";
import { readLivenessRecords } from "../castle-wall/liveness/read-status.js";
import { LivenessRecordPublisher } from "../castle-wall/liveness/record-store.js";
import { parseConfigRecord } from "../castle-wall/liveness/schema.js";
import { livenessFortressId } from "./castle-wall-liveness-status.js";
import { LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS, parseFullAgentPrint } from "./castle-wall-full-agent.js";
import { resolveStableRuntime, STABLE_RUNTIME_REFUSAL_EXIT_CODE, type StableRuntimeResult } from "./stable-runtime-path.js";
import {
  BoundedChildRunner,
  createWatchCollectors,
  nodeWatchSpawn,
  realRunnerTimers,
  type RunnerTimers,
  type WatchChildResult,
  type WatchFs,
} from "./castle-wall-watch-collectors.js";

// ---------------------------------------------------------------------------
// Exit codes.
// ---------------------------------------------------------------------------
/** Installer result: observer loaded and canary integrity passing in this run. Not a liveness reading. */
export const WATCH_EXIT_INSTALLED = 0;
export const WATCH_EXIT_FAILED = 1;
/** Usage refusal, the shared CLI convention. */
export const WATCH_EXIT_USAGE = 2;
/** Must match FULL_AGENT_ROLLBACK_INCOMPLETE_EXIT_CODE in server/src/cli/castle-wall-full-agent.ts. */
export const WATCH_EXIT_ROLLBACK_INCOMPLETE = 3;
/**
 * Exits 5 and 6 are installer outcomes. They must not equal any value in the
 * liveness exit block in server/src/castle-wall/liveness/constants.ts, or 2 or 78.
 */
export const WATCH_EXIT_CANARY_PENDING = 5;
export const WATCH_EXIT_CANARY_STILL_INSTALLED = 6;
export { STABLE_RUNTIME_REFUSAL_EXIT_CODE };

// ---------------------------------------------------------------------------
// Attended text.
// ---------------------------------------------------------------------------
/** The attended root install, with the staged path single-quoted (preflight refuses a quote or control character in it). */
export function attendedCanaryInstallText(fortressPath: string): string {
  return "Run these two commands as root (for example with sudo):\n" +
    `/usr/bin/install -o root -g wheel -m 0644 '${join(fortressPath, LIVENESS_DIRECTORY, CANARY_STAGED_PLIST_NAME)}' ${CANARY_INSTALLED_PLIST_PATH}\n` +
    `/bin/launchctl bootstrap system ${CANARY_INSTALLED_PLIST_PATH}\n`;
}
export function attendedCanaryRemovalText(): string {
  return "Run these two commands as root (for example with sudo):\n" +
    `/bin/launchctl bootout system/${CANARY_LABEL}\n` +
    `/bin/rm ${CANARY_INSTALLED_PLIST_PATH}\n`;
}
/**
 * Appended to a failure after the observer is bootstrapped: rollback covers only the write and bootstrap steps, so a
 * canary staging failure leaves the observer loaded and the operator is told so rather than left to assume nothing runs.
 */
export const OBSERVER_STAYS_LOADED_LINE = "The observer LaunchAgent stays loaded; fix the cause and run install-watch again, or run uninstall-watch to remove it.\n";
export const COMMISSIONING_LINE = "Canary not staged: config.json must first be written by the attended commissioning; then run install-watch again.\n";

// ---------------------------------------------------------------------------
// Context.
// ---------------------------------------------------------------------------
export type WatchVerbFs = WatchFs & Pick<typeof fs, "statSync" | "mkdirSync" | "writeSync" | "fsyncSync" | "renameSync" | "unlinkSync" | "fchmodSync">;

export interface WatchCommandContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  home?: string;
  platform?: NodeJS.Platform | string;
  euid?: number;
  execPath?: string;
  cliPath?: string;
  fs?: WatchVerbFs;
  runner?: BoundedChildRunner;
  timers?: RunnerTimers & ObserverTimers;
  sleep?: (ms: number) => Promise<void>;
  stableRuntime?: (running: { execPath: string; cliPath: string; operatorUid: number }) => StableRuntimeResult;
  /** INTERNAL/TEST: replaces the canary integrity fact collector. */
  collectCanaryFacts?: (agentUid: number) => Promise<Omit<CanaryIntegrityFacts, "agentUid">>;
  /** INTERNAL/TEST: replaces the config read through the shared reader. */
  readConfig?: () => Promise<RecordRead>;
  /** INTERNAL/TEST: run-watch composition and stop signal. */
  compose?: (input: ProductionWatchInput) => { start(): void; stop(): Promise<void> };
  waitForStop?: () => Promise<void>;
  nowMs?: () => number;
}

/** Sampling interval while waiting for a stable observer pid. */
const STABLE_SAMPLE_INTERVAL_MS = SECOND;
// Observe one full sample interval beyond the observer's restart throttle, as install-full does for its job.
export const STABLE_WINDOW_MS = WATCH_THROTTLE_INTERVAL_S * SECOND + STABLE_SAMPLE_INTERVAL_MS;
/** Twice the stable window: a job that restarts once inside it still has room to settle. */
const STABLE_BUDGET_MS = 2 * STABLE_WINDOW_MS;
/** Bytes of randomness in an observer instance label: 32 hex characters plus the prefix stay inside LABEL_BYTES. */
const INSTANCE_RANDOM_BYTES = 16;
/** Poll interval while waiting for children to exit at shutdown: a tenth of the termination grace. */
const REAP_POLL_MS = TERM_GRACE / 10;
/** Bytes of randomness in a staging temp name. */
const TEMP_RANDOM_BYTES = 8;
const PLIST_MODE = 0o644;
// eslint-disable-next-line no-control-regex
const UNSAFE_PATH_TEXT = /['\x00-\x1f\x7f]/;

type Parsed = { ok: true; fortressPath: string; launchAgent: boolean } | { ok: false; message: string };

/** Parse `--fortress <path>` and, for run-watch, `--launch-agent`; an unknown token is refused without being echoed. */
function parseArgs(argv: string[], ctx: Required<Pick<WatchCommandContext, "env" | "home">>, allowLaunchAgent: boolean): Parsed {
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error) return { ok: false, message: fortress.error };
  const rest = fortress.argv.filter(token => !(allowLaunchAgent && token === "--launch-agent"));
  if (rest.length > 0) return { ok: false, message: "an unknown argument was given; it is not shown" };
  const requested = fortress.value ?? resolveStoragePath(ctx.env, ctx.home);
  if (!isAbsolute(requested)) return { ok: false, message: "the fortress path must be absolute" };
  return { ok: true, fortressPath: resolve(requested), launchAgent: allowLaunchAgent && fortress.argv.length !== rest.length };
}

function resolved(input: WatchCommandContext) {
  const timers = input.timers ?? realRunnerTimers;
  return {
    out: input.out ?? process.stdout,
    err: input.err ?? process.stderr,
    env: input.env ?? process.env,
    home: input.home ?? homedir(),
    platform: input.platform ?? process.platform,
    euid: input.euid ?? process.geteuid?.() ?? -1,
    io: input.fs ?? (fs as unknown as WatchVerbFs),
    timers,
    runner: input.runner ?? new BoundedChildRunner({ spawn: nodeWatchSpawn, timers }),
    sleep: input.sleep ?? ((ms: number) => new Promise<void>(done => { timers.setTimeout(done, ms); })),
    nowMs: input.nowMs ?? Date.now,
  };
}
type Resolved = ReturnType<typeof resolved>;

const okCode = (result: WatchChildResult): boolean => result.status === "ok" && result.code === 0 && result.signal === null;

type ObserverJob = { state: "watch_LOADED"; pid: number | null } | { state: "watch_UNLOADED" } | { state: "watch_INDETERMINATE" };

/** Observe the observer job the way observeJob observes the full agent, through the bounded runner. */
async function observeWatchJob(ctx: Resolved): Promise<ObserverJob> {
  const result = await ctx.runner.run({ command: "launchctl_print_gui", uid: ctx.euid, label: OBSERVER_LABEL }, CHILD_READ_DEADLINE);
  if (result.status !== "ok" || result.signal !== null) return { state: "watch_INDETERMINATE" };
  if (result.code === LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS && !/^[^\n]*=\s*\{\s*$/m.test(result.stdout)) return { state: "watch_UNLOADED" };
  const parsed = parseFullAgentPrint(result.stdout);
  return result.code === 0 && parsed.valid ? { state: "watch_LOADED", pid: parsed.pid } : { state: "watch_INDETERMINATE" };
}

async function stableObserverPid(ctx: Resolved): Promise<number | null> {
  let last: number | null = null;
  let stableMs = 0;
  for (let elapsed = 0; elapsed <= STABLE_BUDGET_MS; elapsed += STABLE_SAMPLE_INTERVAL_MS) {
    const job = await observeWatchJob(ctx);
    const pid = job.state === "watch_LOADED" ? job.pid : null;
    if (pid === null || pid !== last) { last = pid; stableMs = 0; }
    else stableMs += STABLE_SAMPLE_INTERVAL_MS;
    if (pid !== null && stableMs >= STABLE_WINDOW_MS) return pid;
    if (elapsed < STABLE_BUDGET_MS) await ctx.sleep(STABLE_SAMPLE_INTERVAL_MS);
  }
  return null;
}

function observerPlistPath(ctx: Resolved): string {
  return join(ctx.home, "Library", "LaunchAgents", `${OBSERVER_LABEL}.plist`);
}

/** Write through a temp file and rename in the same directory, so a reader never sees a partial file. */
function writeAtomic(io: WatchVerbFs, path: string, contents: string): void {
  const temp = `${path}.${randomBytes(TEMP_RANDOM_BYTES).toString("hex")}.tmp`;
  const fd = io.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, PLIST_MODE);
  try {
    io.writeSync(fd, Buffer.from(contents), 0, Buffer.byteLength(contents), null);
    io.fchmodSync(fd, PLIST_MODE);
    io.fsyncSync(fd);
  } finally { io.closeSync(fd); }
  try { io.renameSync(temp, path); }
  catch (error) { try { io.unlinkSync(temp); } catch { /* the rename failure is reported */ } throw error; }
}

function unlinkIfPresent(io: WatchVerbFs, path: string): void {
  try { io.unlinkSync(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}

function readBack(io: WatchVerbFs, path: string, cap: number): Buffer | null {
  let fd: number;
  try { fd = io.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch { return null; }
  try {
    const buffer = Buffer.alloc(cap + 1);
    let total = 0;
    while (total < buffer.length) {
      const n = io.readSync(fd, buffer, total, buffer.length - total, null);
      if (n === 0) break;
      total += n;
    }
    return total > cap ? null : buffer.subarray(0, total);
  } catch { return null; }
  finally { try { io.closeSync(fd); } catch { /* the read result already stands */ } }
}

async function readConfig(input: WatchCommandContext, ctx: Resolved, fortressPath: string): Promise<RecordRead> {
  if (input.readConfig) return input.readConfig();
  return (await readLivenessRecords({ fortressPath, operatorUid: ctx.euid })).config;
}

function livenessDirectoryExists(io: WatchVerbFs, fortressPath: string): boolean {
  try { return io.lstatSync(join(fortressPath, LIVENESS_DIRECTORY)).isDirectory(); }
  catch { return false; }
}

/** `id -un <uid>` then `id -u <name>` under one shared deadline. */
async function resolveAccountName(ctx: Resolved, agentUid: number): Promise<string | null> {
  const startedAt = ctx.nowMs();
  const first = await ctx.runner.run({ command: "id_name", uid: agentUid }, CHILD_READ_DEADLINE);
  const name = okCode(first) && first.status === "ok" ? first.stdout.trim() : "";
  if (!canaryAccountNameValid(name)) return null;
  const remaining = CHILD_READ_DEADLINE - (ctx.nowMs() - startedAt);
  if (remaining <= 0) return null;
  const second = await ctx.runner.run({ command: "id_uid", name }, remaining);
  return okCode(second) && second.status === "ok" && second.stdout.trim() === String(agentUid) ? name : null;
}

// ---------------------------------------------------------------------------
// install-watch.
// ---------------------------------------------------------------------------
export async function runInstallWatch(argv: string[] = [], input: WatchCommandContext = {}): Promise<number> {
  const ctx = resolved(input);
  // watch_PREFLIGHT: every refusal here happens before any write or launchctl call.
  if (ctx.platform !== "darwin") { ctx.err.write("install-watch refused: unsupported_adapter (the observer runs on macOS only).\n"); return WATCH_EXIT_FAILED; }
  if (ctx.euid === 0) { ctx.err.write("install-watch refused: run it as the operator, not as root.\n"); return WATCH_EXIT_FAILED; }
  const args = parseArgs(argv, ctx, false);
  if (!args.ok) { ctx.err.write(`install-watch usage: ${args.message}\n`); return WATCH_EXIT_USAGE; }
  const fortressPath = args.fortressPath;
  if (UNSAFE_PATH_TEXT.test(fortressPath)) { ctx.err.write("install-watch refused: the fortress path contains a quote or control character.\n"); return WATCH_EXIT_FAILED; }
  let owned: boolean;
  try { const s = ctx.io.statSync(fortressPath); owned = s.isDirectory() && s.uid === ctx.euid; } catch { owned = false; }
  if (!owned) { ctx.err.write("install-watch refused: the fortress is not a directory owned by this user.\n"); return WATCH_EXIT_FAILED; }
  const configRead = await readConfig(input, ctx, fortressPath);
  const parsedConfig = configRead.status === "present" ? parseConfigRecord(configRead.value) : null;
  const agentUid = parsedConfig !== null && parsedConfig.ok ? parsedConfig.value.agent_uid : undefined;
  if (agentUid !== undefined && agentUid === ctx.euid) {
    ctx.err.write("install-watch refused: config.json names this operator as the agent; the agent and operator accounts must differ.\n");
    return WATCH_EXIT_FAILED;
  }
  const runtime = (input.stableRuntime ?? resolveStableRuntime)({ execPath: input.execPath ?? process.execPath, cliPath: input.cliPath ?? process.argv[1]!, operatorUid: ctx.euid });
  if (!runtime.ok) { ctx.err.write(`install-watch refused an unstable runtime: ${runtime.reason}\n`); return STABLE_RUNTIME_REFUSAL_EXIT_CODE; }

  // watch_WRITE: the plist is generated and checked before any write or launchctl call.
  let plist: string;
  try { plist = generateWatchAgentPlist([runtime.node, runtime.cli, "castle-wall", "run-watch", "--fortress", fortressPath, "--launch-agent"]); }
  catch { ctx.err.write("install-watch refused: the observer LaunchAgent could not be generated for these paths.\n"); return WATCH_EXIT_FAILED; }
  if (!watchAgentLaunchAgentWellFormed(plist)) { ctx.err.write("install-watch refused: the generated observer LaunchAgent failed its check.\n"); return WATCH_EXIT_FAILED; }
  const plistPath = observerPlistPath(ctx);
  let rollbackArmed = false;
  try {
    const existing = await observeWatchJob(ctx);
    if (existing.state === "watch_INDETERMINATE") throw new Error("the observer job state could not be read");
    if (existing.state === "watch_LOADED") {
      const out = await ctx.runner.run({ command: "launchctl_bootout_gui", uid: ctx.euid, label: OBSERVER_LABEL }, CHILD_READ_DEADLINE);
      if (!okCode(out)) throw new Error("the loaded observer job could not be booted out");
    }
    ctx.io.mkdirSync(dirname(plistPath), { recursive: true });
    rollbackArmed = true;
    writeAtomic(ctx.io, plistPath, plist);
    // watch_BOOTSTRAP.
    const boot = await ctx.runner.run({ command: "launchctl_bootstrap_gui", uid: ctx.euid, plistPath }, CHILD_READ_DEADLINE);
    if (!okCode(boot)) throw new Error("launchctl bootstrap failed");
    const pid = await stableObserverPid(ctx);
    if (pid === null) throw new Error("the observer did not keep a stable running pid");
    ctx.out.write(`Observer LaunchAgent installed; running pid=${pid}.\n`);
    rollbackArmed = false;
  } catch (error) {
    // watch_ROLLBACK: only a confirmed unload and removal returns the ordinary failure.
    if (rollbackArmed) {
      let clean: boolean;
      try {
        await ctx.runner.run({ command: "launchctl_bootout_gui", uid: ctx.euid, label: OBSERVER_LABEL }, CHILD_READ_DEADLINE);
        unlinkIfPresent(ctx.io, plistPath);
        clean = (await observeWatchJob(ctx)).state === "watch_UNLOADED";
      } catch { clean = false; }
      if (!clean) {
        ctx.err.write("install-watch rollback incomplete: the observer job was not confirmed unloaded or its plist was not removed; run uninstall-watch.\n");
        return WATCH_EXIT_ROLLBACK_INCOMPLETE;
      }
    }
    ctx.err.write(`install-watch failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    return WATCH_EXIT_FAILED;
  }

  // watch_CANARY_STAGE: install-watch never creates the liveness directory and never writes config.json.
  if (agentUid === undefined || !livenessDirectoryExists(ctx.io, fortressPath)) {
    ctx.out.write(COMMISSIONING_LINE);
    return WATCH_EXIT_CANARY_PENDING;
  }
  const name = await resolveAccountName(ctx, agentUid);
  if (name === null) { ctx.err.write(`install-watch failed: the agent account name could not be resolved in both directions.\n${OBSERVER_STAYS_LOADED_LINE}`); return WATCH_EXIT_FAILED; }
  const expected = generateCanaryPlist(name);
  const stagedPath = join(fortressPath, LIVENESS_DIRECTORY, CANARY_STAGED_PLIST_NAME);
  try { writeAtomic(ctx.io, stagedPath, expected); }
  catch { ctx.err.write(`install-watch failed: the canary plist could not be staged.\n${OBSERVER_STAYS_LOADED_LINE}`); return WATCH_EXIT_FAILED; }
  // The staged bytes are re-read and compared before any attended text is printed, so the root install copies exactly the generator's output.
  const staged = readBack(ctx.io, stagedPath, Buffer.byteLength(expected));
  if (staged === null || !staged.equals(Buffer.from(expected))) {
    ctx.err.write(`install-watch failed: the staged canary plist does not match the generated bytes.\n${OBSERVER_STAYS_LOADED_LINE}`);
    return WATCH_EXIT_FAILED;
  }

  // watch_CANARY_CHECK.
  const collect = input.collectCanaryFacts ?? createWatchCollectors({ runner: ctx.runner, timers: ctx.timers, fortressPath, operatorUid: ctx.euid, fs: ctx.io }).collectCanaryFacts;
  let integrity: ReturnType<typeof checkCanaryIntegrity>;
  try { integrity = checkCanaryIntegrity({ agentUid, ...(await collect(agentUid)) }, ctx.nowMs()); }
  catch { integrity = null; }
  if (integrity !== null && integrity.passed) {
    ctx.out.write("Canary integrity passes. This is an installer result; read liveness with `castle-wall liveness-status`.\n");
    return WATCH_EXIT_INSTALLED;
  }
  ctx.out.write(attendedCanaryInstallText(fortressPath));
  return WATCH_EXIT_CANARY_PENDING;
}

// ---------------------------------------------------------------------------
// uninstall-watch.
// ---------------------------------------------------------------------------
export async function runUninstallWatch(argv: string[] = [], input: WatchCommandContext = {}): Promise<number> {
  const ctx = resolved(input);
  if (ctx.platform !== "darwin") { ctx.err.write("uninstall-watch refused: unsupported_adapter (the observer runs on macOS only).\n"); return WATCH_EXIT_FAILED; }
  if (ctx.euid === 0) { ctx.err.write("uninstall-watch refused: run it as the operator, not as root.\n"); return WATCH_EXIT_FAILED; }
  const args = parseArgs(argv, ctx, false);
  if (!args.ok) { ctx.err.write(`uninstall-watch usage: ${args.message}\n`); return WATCH_EXIT_USAGE; }
  const plistPath = observerPlistPath(ctx);
  const job = await observeWatchJob(ctx);
  if (job.state === "watch_INDETERMINATE") { ctx.err.write("uninstall-watch failed: the observer job state could not be read.\n"); return WATCH_EXIT_FAILED; }
  if (job.state === "watch_LOADED") {
    const out = await ctx.runner.run({ command: "launchctl_bootout_gui", uid: ctx.euid, label: OBSERVER_LABEL }, CHILD_READ_DEADLINE);
    const after = await observeWatchJob(ctx);
    if (!okCode(out) || after.state !== "watch_UNLOADED") { ctx.err.write("uninstall-watch failed: the observer job was not confirmed unloaded.\n"); return WATCH_EXIT_FAILED; }
  }
  // observer.json is never removed: stale evidence reads DOWN on its own.
  try {
    unlinkIfPresent(ctx.io, plistPath);
    unlinkIfPresent(ctx.io, join(args.fortressPath, LIVENESS_DIRECTORY, CANARY_STAGED_PLIST_NAME));
  } catch {
    ctx.err.write("uninstall-watch incomplete: the observer job is unloaded but a plist could not be removed; run uninstall-watch again.\n");
    return WATCH_EXIT_ROLLBACK_INCOMPLETE;
  }
  let filePresent: boolean;
  try { ctx.io.lstatSync(CANARY_INSTALLED_PLIST_PATH); filePresent = true; }
  catch (error) { filePresent = (error as NodeJS.ErrnoException).code !== "ENOENT"; }
  const print = await ctx.runner.run({ command: "launchctl_print_system", label: CANARY_LABEL }, CHILD_READ_DEADLINE);
  const notFound = print.status === "ok" && print.signal === null && systemJobNotFound(print, CANARY_LABEL);
  const shown = print.status === "ok" && print.code === 0 && print.signal === null && parseSystemJobPrint(print.stdout).valid;
  if (filePresent || shown) {
    ctx.out.write("The canary LaunchDaemon is still installed. A canary left loaded keeps producing drops that no observer reads.\n");
    ctx.out.write(attendedCanaryRemovalText());
    return WATCH_EXIT_CANARY_STILL_INSTALLED;
  }
  if (!notFound) { ctx.err.write("uninstall-watch could not read the canary state, so it cannot confirm the canary is gone.\n"); return WATCH_EXIT_FAILED; }
  ctx.out.write("Observer removed; the canary is not installed.\n");
  return 0;
}

// ---------------------------------------------------------------------------
// run-watch and the production composition.
// ---------------------------------------------------------------------------
export interface ProductionWatchInput {
  fortressPath: string;
  operatorUid: number;
  runner: BoundedChildRunner;
  timers: RunnerTimers & ObserverTimers;
  clock: ObserverClock;
  hostname: string;
}

export const productionObserverClock: ObserverClock = {
  nowMs: () => Date.now(),
  uptimeMs: () => Math.floor(osUptime() * SECOND),
};

/** Build the observer with every collector, the sampler, the publisher and the clock as required arguments. */
export function composeProductionWatch(input: ProductionWatchInput): { observer: LivenessObserver; sampler: CensusSampler; deps: LivenessObserverDeps; start(): void; stop(): Promise<void> } {
  const collectors = createWatchCollectors({ runner: input.runner, timers: input.timers, fortressPath: input.fortressPath, operatorUid: input.operatorUid });
  const series = new CensusSeries();
  const instance = `observer-${randomBytes(INSTANCE_RANDOM_BYTES).toString("hex")}`;
  let observer: LivenessObserver | null = null;
  const sampler = new CensusSampler({
    series,
    runNetstat: () => collectors.runNetstat(),
    context: () => observer?.samplingContext() ?? { gateway: null, gatewayAlive: false, ipv4Set: null, bootId: null },
    clock: input.clock,
    timers: input.timers,
  });
  const publisher = new LivenessRecordPublisher({ fortressPath: input.fortressPath, fileName: OBSERVER_RECORD_FILE, instance, operatorUid: input.operatorUid });
  const deps: LivenessObserverDeps = {
    fortressId: livenessFortressId(input.fortressPath),
    hostId: observerHostId(input.hostname),
    operatorUid: input.operatorUid,
    collectors,
    sampler,
    series,
    publisher,
    clock: input.clock,
    timers: input.timers,
    instance,
  };
  observer = new LivenessObserver(deps);
  const built = observer;
  return { observer: built, sampler, deps, start: () => built.start(), stop: () => built.stop() };
}

function waitForSignal(): Promise<void> {
  return new Promise(done => {
    const finish = (): void => { process.off("SIGTERM", finish); process.off("SIGINT", finish); done(); };
    process.once("SIGTERM", finish);
    process.once("SIGINT", finish);
  });
}

export async function runRunWatch(argv: string[] = [], input: WatchCommandContext = {}): Promise<number> {
  const ctx = resolved(input);
  const launchAgent = argv.includes("--launch-agent");
  // In --launch-agent mode nothing is written to stdout or stderr: the plist names no log file, and launchd would append to one without bound.
  const say = (stream: Writable, text: string): void => { if (!launchAgent) stream.write(text); };
  if (ctx.platform !== "darwin") { say(ctx.err, "run-watch refused: unsupported_adapter (the observer runs on macOS only).\n"); return WATCH_EXIT_FAILED; }
  if (ctx.euid === 0) { say(ctx.err, "run-watch refused: the observer runs as the operator, never as root.\n"); return WATCH_EXIT_FAILED; }
  const args = parseArgs(argv, ctx, true);
  if (!args.ok) { say(ctx.err, `run-watch usage: ${args.message}\n`); return WATCH_EXIT_USAGE; }
  let owned: boolean;
  try { const s = ctx.io.statSync(args.fortressPath); owned = s.isDirectory() && s.uid === ctx.euid; } catch { owned = false; }
  if (!owned) { say(ctx.err, "run-watch refused: the fortress is not a directory owned by this user.\n"); return WATCH_EXIT_FAILED; }
  const composition = (input.compose ?? composeProductionWatch)({
    fortressPath: args.fortressPath, operatorUid: ctx.euid, runner: ctx.runner, timers: ctx.timers,
    clock: productionObserverClock, hostname: osHostname(),
  });
  say(ctx.out, `Observer running for ${args.fortressPath}; stop with Ctrl-C.\n`);
  composition.start();
  await (input.waitForStop ?? waitForSignal)();
  await composition.stop();
  // Reap: wait for every child to be observed exiting, bounded by the termination allocation; a poisoned slot is left to the process exit.
  for (let waited = 0; ctx.runner.liveChildren() > 0 && waited < TERM_GRACE + KILL_REAP_GRACE; waited += REAP_POLL_MS) await ctx.sleep(REAP_POLL_MS);
  return 0;
}

/** Paths the verbs never open for writing; the config is written only by the attended commissioning. */
export function watchConfigPath(fortressPath: string): string {
  return join(fortressPath, LIVENESS_DIRECTORY, CONFIG_RECORD_FILE);
}
