/**
 * The observer's bounded child runner and its production collectors. Every
 * child the observer, the census sampler and the watch verbs start goes
 * through `BoundedChildRunner`: a closed command enum, absolute argv built
 * here, a fixed environment, per-command output caps, and at most
 * MAX_COLLECTION_CHILDREN slots that are never released while a child lives.
 */
import { spawn as nodeSpawn } from "node:child_process";
import * as fs from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  CENSUS_INPUT_BYTES,
  CENSUS_REREAD,
  CHILD_READ_DEADLINE,
  IPC_DEADLINE,
  KILL_REAP_GRACE,
  LABEL_BYTES,
  MAX_COLLECTION_CHILDREN,
  PROCESS_BYTES,
  PROCESS_READ_DEADLINE,
  STATUS_BYTES,
  TERM_GRACE,
  CANARY_LABEL,
  LIVENESS_DIRECTORY,
} from "../castle-wall/liveness/constants.js";
import {
  CANARY_INSTALLED_PLIST_PATH,
  CANARY_PLIST_BYTES,
  CANARY_STAGED_PLIST_NAME,
  canaryAccountNameValid,
  parseSystemJobPrint,
} from "../castle-wall/liveness/launchd-plists.js";
import type { CanaryIntegrityFacts, CanaryPlistStat, CollectedFact } from "../castle-wall/liveness/canary-integrity.js";
import type { CensusChildResult } from "../castle-wall/liveness/census-sampler.js";
import type { AvailabilityStatus, ObserverCollectors, ObserverTimers } from "../castle-wall/liveness/observer.js";
import { parseProcessRead, type ProcessRow } from "../castle-wall/liveness/process-census.js";
import { readLivenessRecords, type LivenessReadResult } from "../castle-wall/liveness/read-status.js";
import { queryMacOSEnforcementAvailability } from "../castle-wall/runtime/enforcement-availability.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import { FULL_AGENT_LABEL, LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS, parseFullAgentPrint } from "./castle-wall-full-agent.js";
import { FullAgentStateStore } from "./castle-wall-full-agent-state.js";

// ---------------------------------------------------------------------------
// Closed command enum and argv.
// ---------------------------------------------------------------------------
export const WATCH_COMMANDS = Object.freeze([
  "launchctl_print_gui", "launchctl_print_system", "launchctl_bootstrap_gui", "launchctl_bootout_gui",
  "ps", "id_name", "id_uid", "sysctl_boot", "netstat",
] as const);
export type WatchCommand = (typeof WATCH_COMMANDS)[number];

export type WatchCommandOperand =
  | { command: "launchctl_print_gui"; uid: number; label: string }
  | { command: "launchctl_print_system"; label: string }
  | { command: "launchctl_bootstrap_gui"; uid: number; plistPath: string }
  | { command: "launchctl_bootout_gui"; uid: number; label: string }
  | { command: "ps" }
  | { command: "id_name"; uid: number }
  | { command: "id_uid"; name: string }
  | { command: "sysctl_boot" }
  | { command: "netstat" };

/** The child environment: no inherited variable can change what a child reads, prints or loads. */
export const WATCH_CHILD_ENV: Readonly<Record<string, string>> = Object.freeze({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C" });
const LAUNCHCTL = "/bin/launchctl";
const LAUNCHD_LABEL_TEXT = /^[A-Za-z0-9._-]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL_TEXT = /[\x00-\x1f\x7f]/;
/** Unix uids are 32-bit unsigned. */
const UINT32_MAX = 0xffffffff;

function checkedUid(uid: number): string {
  if (!Number.isSafeInteger(uid) || uid < 0 || uid > UINT32_MAX) throw new Error("watch child uid operand is invalid");
  return String(uid);
}
function checkedLabel(label: string): string {
  if (label.length === 0 || label.length > LABEL_BYTES || !LAUNCHD_LABEL_TEXT.test(label)) throw new Error("watch child label operand is invalid");
  return label;
}

/** Build the absolute argv for one closed command; no caller passes an executable or a shell string. */
export function watchCommandArgv(operand: WatchCommandOperand): { file: string; args: string[] } {
  switch (operand.command) {
    case "launchctl_print_gui": return { file: LAUNCHCTL, args: ["print", `gui/${checkedUid(operand.uid)}/${checkedLabel(operand.label)}`] };
    case "launchctl_print_system": return { file: LAUNCHCTL, args: ["print", `system/${checkedLabel(operand.label)}`] };
    case "launchctl_bootstrap_gui":
      if (!isAbsolute(operand.plistPath) || CONTROL_TEXT.test(operand.plistPath)) throw new Error("watch child plist operand is invalid");
      return { file: LAUNCHCTL, args: ["bootstrap", `gui/${checkedUid(operand.uid)}`, operand.plistPath] };
    case "launchctl_bootout_gui": return { file: LAUNCHCTL, args: ["bootout", `gui/${checkedUid(operand.uid)}/${checkedLabel(operand.label)}`] };
    case "ps": return { file: "/bin/ps", args: ["-axww", "-o", "pid=,ppid=,uid=,lstart=,command="] };
    case "id_name": return { file: "/usr/bin/id", args: ["-un", checkedUid(operand.uid)] };
    case "id_uid":
      if (!canaryAccountNameValid(operand.name)) throw new Error("watch child account operand is invalid");
      return { file: "/usr/bin/id", args: ["-u", operand.name] };
    case "sysctl_boot": return { file: "/usr/sbin/sysctl", args: ["-n", "kern.bootsessionuuid"] };
    case "netstat": return { file: "/usr/sbin/netstat", args: ["-anv", "-p", "tcp"] };
  }
}

/** Output cap per command: the process and census caps, else STATUS_BYTES. */
export function watchCommandOutputCap(command: WatchCommand): number {
  if (command === "ps") return PROCESS_BYTES;
  if (command === "netstat") return CENSUS_INPUT_BYTES;
  return STATUS_BYTES;
}

// ---------------------------------------------------------------------------
// Runner.
// ---------------------------------------------------------------------------
/** The child surface the runner uses; production is `child_process.spawn`. */
export interface WatchChild {
  readonly pid?: number | undefined;
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  stderr: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  on(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
  kill(signal: NodeJS.Signals): boolean;
}
export type WatchSpawn = (file: string, args: readonly string[], options: { env: Record<string, string>; cwd: string; stdio: ["ignore", "pipe", "pipe"]; shell: false }) => WatchChild;

export type WatchChildResult =
  | { status: "ok"; code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }
  | { status: "failed"; reason: "no_slot" | "deadline" | "over_cap" | "spawn_error" };

export type SlotState = "slot_IDLE" | "slot_RUNNING" | "slot_SETTLED" | "slot_EXPIRED" | "slot_TERMINATING" | "slot_POISONED";

/** `owner` names the run that holds the slot, so a late event from an earlier child can never change a reused slot. */
interface Slot { state: SlotState; exited: boolean; owner: object | null }

export interface RunnerTimers {
  setTimeout(fire: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}
/**
 * The production timers for the observer, the sampler, the runner and the watch verbs. Every handle is REFERENCED:
 * these timers are what keeps the process alive through the process reread gap, the idle time between cycles and the
 * installer's stability sleeps, because nothing else holds the event loop open there. An unreferenced handle lets
 * Node exit 0 mid-cycle or mid-install, which reads as success to launchd and to the operator. The handles end by
 * explicit cancellation instead: on settlement, at observer and sampler stop, and when a child's exit is observed.
 */
export const realRunnerTimers: RunnerTimers & ObserverTimers = {
  setTimeout: (fire, ms) => setTimeout(fire, ms),
  clearTimeout: handle => clearTimeout(handle as NodeJS.Timeout),
  setInterval: (fire, ms) => setInterval(fire, ms),
  clearInterval: handle => clearInterval(handle as NodeJS.Timeout),
};

export class BoundedChildRunner {
  private readonly slots: Slot[];

  constructor(private readonly options: { spawn: WatchSpawn; timers: RunnerTimers; maxSlots?: number }) {
    if (typeof options.spawn !== "function" || options.timers === undefined) throw new Error("bounded child runner requires spawn and timers");
    this.slots = Array.from({ length: options.maxSlots ?? MAX_COLLECTION_CHILDREN }, () => ({ state: "slot_IDLE" as SlotState, exited: true, owner: null }));
  }

  /** Slots currently owned by a child (every state but slot_IDLE). */
  liveChildren(): number {
    return this.slots.filter(slot => slot.state !== "slot_IDLE").length;
  }
  slotStates(): SlotState[] {
    return this.slots.map(slot => slot.state);
  }

  /** Run one closed command under `deadlineMs`; a collector that cannot get a slot fails now and never queues. */
  run(operand: WatchCommandOperand, deadlineMs: number): Promise<WatchChildResult> {
    let argv: { file: string; args: string[] };
    try { argv = watchCommandArgv(operand); }
    catch { return Promise.resolve({ status: "failed", reason: "spawn_error" }); }
    const slot = this.slots.find(candidate => candidate.state === "slot_IDLE");
    if (slot === undefined) return Promise.resolve({ status: "failed", reason: "no_slot" });
    const cap = watchCommandOutputCap(operand.command);
    const { timers } = this.options;
    return new Promise<WatchChildResult>(resolve => {
      let settled = false;
      const settle = (result: WatchChildResult): void => { if (!settled) { settled = true; resolve(result); } };
      const run = {};
      slot.state = "slot_RUNNING";
      slot.exited = false;
      slot.owner = run;
      // Every child event below first checks that this run still owns the slot: once the slot is idle and handed to a
      // later run, an exit, close, output or timer of this child must not settle, release or poison the later child's slot.
      const owns = (): boolean => slot.owner === run;
      let child: WatchChild;
      try {
        child = this.options.spawn(argv.file, argv.args, { env: { ...WATCH_CHILD_ENV }, cwd: "/", stdio: ["ignore", "pipe", "pipe"], shell: false });
      } catch {
        slot.state = "slot_IDLE";
        slot.exited = true;
        settle({ status: "failed", reason: "spawn_error" });
        return;
      }
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let bytes = 0;
      let deadlineHandle: unknown = null;
      let killHandle: unknown = null;
      let reapHandle: unknown = null;
      const observedExit = (): void => {
        if (!owns()) return;
        slot.exited = true;
        timers.clearTimeout(killHandle);
        timers.clearTimeout(reapHandle);
        // A slot returns to idle only on a positively observed exit; a poisoned slot is never replaced by a new one.
        if (slot.state !== "slot_RUNNING") slot.state = "slot_IDLE";
      };
      const terminate = (reason: "deadline" | "over_cap"): void => {
        if (!owns() || slot.state !== "slot_RUNNING") return;
        timers.clearTimeout(deadlineHandle);
        // The collector fails immediately; the slot stays owned until the child's exit is observed.
        settle({ status: "failed", reason });
        if (slot.exited) { slot.state = "slot_IDLE"; return; }
        slot.state = "slot_EXPIRED";
        try { child.kill("SIGTERM"); } catch { /* the exit observation decides the slot */ }
        slot.state = "slot_TERMINATING";
        killHandle = timers.setTimeout(() => {
          if (!owns() || slot.exited) return;
          try { child.kill("SIGKILL"); } catch { /* the exit observation decides the slot */ }
          reapHandle = timers.setTimeout(() => { if (owns() && !slot.exited) slot.state = "slot_POISONED"; }, KILL_REAP_GRACE);
        }, TERM_GRACE);
      };
      const collect = (into: Buffer[]) => (chunk: Buffer | string): void => {
        if (!owns() || slot.state !== "slot_RUNNING") return;
        const buffer = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        bytes += buffer.byteLength;
        // Over the cap the read fails and the child is terminated; no truncated prefix is ever returned.
        if (bytes > cap) { terminate("over_cap"); return; }
        into.push(buffer);
      };
      child.stdout?.on("data", collect(stdout));
      child.stderr?.on("data", collect(stderr));
      child.on("error", () => {
        if (owns() && child.pid === undefined) {
          timers.clearTimeout(deadlineHandle);
          slot.exited = true;
          slot.state = "slot_IDLE";
          settle({ status: "failed", reason: "spawn_error" });
        }
      });
      child.on("exit", () => { if (!owns()) return; if (slot.state !== "slot_RUNNING") observedExit(); else slot.exited = true; });
      child.on("close", (code, signal) => {
        if (owns() && slot.state === "slot_RUNNING") {
          timers.clearTimeout(deadlineHandle);
          slot.state = "slot_SETTLED";
          settle({ status: "ok", code, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
        }
        observedExit();
      });
      deadlineHandle = timers.setTimeout(() => terminate("deadline"), deadlineMs);
    });
  }
}

export const nodeWatchSpawn: WatchSpawn = (file, args, options) => nodeSpawn(file, [...args], options);

// ---------------------------------------------------------------------------
// Production collectors.
// ---------------------------------------------------------------------------
export interface WatchFs {
  lstatSync(path: string): fs.Stats;
  /** Required: the canary bytes are accepted only from the inode the lstat described. */
  fstatSync(fd: number): fs.Stats;
  openSync(path: string, flags: number, mode?: number): number;
  readSync(fd: number, buffer: Uint8Array, offset: number, length: number, position: number | null): number;
  closeSync(fd: number): void;
}

export interface WatchCollectorOptions {
  runner: BoundedChildRunner;
  timers: RunnerTimers;
  fortressPath: string;
  operatorUid: number;
  fs?: WatchFs;
  /** INTERNAL/TEST: replaces the socket query. */
  queryAvailability?: () => Promise<AvailabilityStatus>;
  /** INTERNAL/TEST: replaces the shared record reader. */
  readRecords?: () => Promise<LivenessReadResult>;
  /** The clock the shared id-chain deadline is measured on; defaults to Date.now. */
  nowMs?: () => number;
  /** INTERNAL/TEST: replaces the full agent state store read. */
  readFullAgentState?: () => Promise<{ latched: boolean; charges_ms: readonly number[] } | null>;
}

function okText(result: WatchChildResult): string | null {
  return result.status === "ok" && result.code === 0 && result.signal === null ? result.stdout : null;
}

const delay = (timers: RunnerTimers, ms: number): Promise<void> => new Promise(resolve => { timers.setTimeout(resolve, ms); });

/**
 * Read at most `cap + 1` bytes of a file opened with O_NOFOLLOW, so an extended file is detected without unbounded work.
 * The opened descriptor must be the inode `expected` names: a file replaced between the lstat and the open fails the read.
 */
function readCapped(io: WatchFs, path: string, cap: number, expected: { dev: number; ino: number }): CollectedFact<Uint8Array> {
  let fd: number;
  try { fd = io.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch { return { status: "failed" }; }
  try {
    // The ownership, mode and size facts come from the lstat, so the bytes are accepted only from that same file.
    const opened = io.fstatSync(fd);
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) return { status: "failed" };
    const buffer = Buffer.alloc(cap + 1);
    let total = 0;
    while (total < buffer.length) {
      const n = io.readSync(fd, buffer, total, buffer.length - total, null);
      if (n === 0) break;
      total += n;
    }
    return total > cap ? { status: "failed" } : { status: "ok", value: buffer.subarray(0, total) };
  } catch { return { status: "failed" }; }
  finally { try { io.closeSync(fd); } catch { /* the read result already stands */ } }
}

/** The observer's production collectors over the bounded runner. */
export function createWatchCollectors(options: WatchCollectorOptions): ObserverCollectors & { runNetstat(): Promise<CensusChildResult> } {
  const { runner, timers, fortressPath, operatorUid } = options;
  const io = options.fs ?? fs;
  const nowMs = options.nowMs ?? Date.now;
  const psRead = async (): Promise<ProcessRow[]> => {
    const text = okText(await runner.run({ command: "ps" }, PROCESS_READ_DEADLINE));
    if (text === null) throw new Error("process read failed");
    const parsed = parseProcessRead(text);
    if (parsed.status !== "ok") throw new Error("process read refused");
    return parsed.rows;
  };
  const printSystem = async (label: string) => {
    const text = okText(await runner.run({ command: "launchctl_print_system", label }, CHILD_READ_DEADLINE));
    if (text === null) throw new Error("system print failed");
    const parsed = parseSystemJobPrint(text);
    if (!parsed.valid) throw new Error("system print unparsable");
    return parsed;
  };
  const fact = async <T>(start: () => Promise<T>): Promise<CollectedFact<T>> => {
    try { return { status: "ok", value: await start() }; }
    catch { return { status: "failed" }; }
  };
  return {
    readRecords: options.readRecords ?? (() => readLivenessRecords({ fortressPath, operatorUid })),
    async readBootId() {
      const text = okText(await runner.run({ command: "sysctl_boot" }, CHILD_READ_DEADLINE));
      const bootId = text?.trim() ?? "";
      if (bootId.length === 0 || bootId.length > LABEL_BYTES || CONTROL_TEXT.test(bootId)) throw new Error("boot id read failed");
      return bootId;
    },
    queryAvailability: options.queryAvailability ?? (async () => {
      const socket = resolveCastleWallSocketPath({ platform: "darwin", fortressPath });
      return (await queryMacOSEnforcementAvailability(socket.path, { timeoutMs: IPC_DEADLINE })).status;
    }),
    async printFullAgent() {
      const result = await runner.run({ command: "launchctl_print_gui", uid: operatorUid, label: FULL_AGENT_LABEL }, CHILD_READ_DEADLINE);
      if (result.status !== "ok") throw new Error("full agent print failed");
      // Only a normal not-found exit without a service block establishes absence, matching observeJob in castle-wall-full-agent.ts.
      if (result.signal === null && result.code === LAUNCHCTL_PRINT_SERVICE_NOT_FOUND_STATUS && !/^[^\n]*=\s*\{\s*$/m.test(result.stdout)) return { loaded: false, pid: null };
      const parsed = parseFullAgentPrint(result.stdout);
      if (result.code !== 0 || result.signal !== null || !parsed.valid) throw new Error("full agent print unparsable");
      return { loaded: true, pid: parsed.pid };
    },
    readFullAgentState: options.readFullAgentState ?? (async () => {
      const record = new FullAgentStateStore(fortressPath).read();
      return record === null ? null : { latched: record.state === "state_LATCHED", charges_ms: record.charges_ms };
    }),
    async readProcesses() {
      const first = await psRead();
      await delay(timers, CENSUS_REREAD);
      const second = await psRead();
      return [first, second];
    },
    async printHarness(label) {
      return (await printSystem(label)).pid;
    },
    async collectCanaryFacts(agentUid): Promise<Omit<CanaryIntegrityFacts, "agentUid">> {
      let plistStat: CollectedFact<CanaryPlistStat> = { status: "failed" };
      let identity: { dev: number; ino: number } | null = null;
      try {
        const s = io.lstatSync(CANARY_INSTALLED_PLIST_PATH);
        identity = { dev: s.dev, ino: s.ino };
        plistStat = { status: "ok", value: { isFile: s.isFile(), isSymbolicLink: s.isSymbolicLink(), uid: s.uid, gid: s.gid, mode: s.mode, size: s.size } };
      } catch { /* an absent or unreadable plist reads failed */ }
      const plistBytes: CollectedFact<Uint8Array> = identity === null
        ? { status: "failed" } : readCapped(io, CANARY_INSTALLED_PLIST_PATH, CANARY_PLIST_BYTES, identity);
      // The id chain and the system print hold separate slots (OBSERVER_CYCLE_CHILD_SET counts them apart) and run
      // concurrently, so the facts need one CHILD_READ_DEADLINE, not two, and fit inside COLLECT_DEADLINE.
      // Both id calls share one CHILD_READ_DEADLINE: the second runs only with the time the first left.
      const accountP = fact(async () => {
        const startedAt = nowMs();
        const name = okText(await runner.run({ command: "id_name", uid: agentUid }, CHILD_READ_DEADLINE))?.trim() ?? "";
        if (!canaryAccountNameValid(name)) throw new Error("account name read failed");
        const remaining = CHILD_READ_DEADLINE - (nowMs() - startedAt);
        if (remaining <= 0) throw new Error("account chain deadline");
        const uidText = okText(await runner.run({ command: "id_uid", name }, remaining))?.trim() ?? "";
        if (!/^\d+$/.test(uidText)) throw new Error("account uid read failed");
        return { name, reverseUid: Number(uidText) };
      });
      const printP = fact(() => printSystem(CANARY_LABEL));
      const [account, print] = await Promise.all([accountP, printP]);
      return { plistStat, plistBytes, account, print };
    },
    async runNetstat(): Promise<CensusChildResult> {
      const text = okText(await runner.run({ command: "netstat" }, CHILD_READ_DEADLINE));
      return text === null ? { status: "failed" } : { status: "ok", stdout: text };
    },
  };
}

/** The staged canary path inside a fortress. */
export function stagedCanaryPath(fortressPath: string): string {
  return join(fortressPath, LIVENESS_DIRECTORY, CANARY_STAGED_PLIST_NAME);
}
