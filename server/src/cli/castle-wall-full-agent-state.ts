/** Durable admission for the operator's full-daemon LaunchAgent. */
import * as fs from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import {
  DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS,
  type AuditProcessExitFence,
  type AuditProcessExitFenceEvent,
} from "../operational/audit-log.js";

// EX_IOERR; must match CASTLE_WALL_DAEMON_AUDIT_FENCE_EXIT_CODE in server/reorg-surface-manifest.md.
// storage/cross-process-lock.ts also uses 74, but only for a helper child's
// status consumed by its parent, never as the daemon status seen by launchd.
export const CASTLE_WALL_DAEMON_AUDIT_FENCE_EXIT_CODE = 74;
export const FULL_AGENT_STOP_EXIT_CODE = 0;
export const FULL_AGENT_CRASH_BUDGET = 5; // Initial run plus four recoveries.
export const FULL_AGENT_START_TO_ARMED_BUDGET_S = 15; // Ratified start-to-armed allocation within the restart target.
export const FULL_AGENT_RESTART_BUDGET_S = 20; // Ratified restart target; Mini2 measurement remains pending.
// must match FULL_AGENT_THROTTLE_INTERVAL_S usage in server/src/cli/castle-wall-full-agent.ts.
export const FULL_AGENT_THROTTLE_INTERVAL_S =
  FULL_AGENT_RESTART_BUDGET_S - FULL_AGENT_START_TO_ARMED_BUDGET_S;
const MS_PER_SECOND = 1000;
// At least 5 * (300 + 5 + 15) = 1600 seconds, rounded up to 30 minutes.
// The window is also the healthy-uptime reset: all earlier charges age out by W.
export const FULL_AGENT_CRASH_WINDOW_S = 30 * 60;
const WINDOW_MS = FULL_AGENT_CRASH_WINDOW_S * MS_PER_SECOND;

/** Terminate synchronously; a graceful drain would wait behind the stalled audit. */
export function exitWallDaemonOnAuditFence(event: AuditProcessExitFenceEvent): void {
  try {
    // must match AUDIT-EXIT-FENCE in server/reorg-surface-manifest.md.
    fs.writeSync(2, `[castle-wall] AUDIT-EXIT-FENCE fence=${event.fence} deadline_ms=${event.deadlineMs} - exiting 74 so no abandoned audit write can publish after another writer proceeds\n`);
  } finally {
    // Even an unavailable stderr must not let this writer survive the fence.
    process.exit(CASTLE_WALL_DAEMON_AUDIT_FENCE_EXIT_CODE);
  }
}

/** The single opt-in fence used by the macOS full daemon's composition root. */
export const WALL_DAEMON_AUDIT_EXIT_FENCE: AuditProcessExitFence = Object.freeze({
  // Provisional: 300 s is about 2.7 times the only recorded stall (112 s).
  // A Mini2 measurement is owed; the existing hold deadline stays at 30 s.
  firstLoadDeadlineMs: 10 * DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS,
  exit: exitWallDaemonOnAuditFence,
});

const timestampSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const recordSchema = z.object({
  version: z.literal(1),
  state: z.enum(["state_RUNNING", "state_STOPPED_CLEAN", "state_LATCHED"]),
  attempt_started_at_ms: timestampSchema,
  charges_ms: z.array(timestampSchema).max(FULL_AGENT_CRASH_BUDGET),
  latched_reason: z.literal("crash_budget").nullable(),
}).strict().refine(record =>
  (record.state === "state_LATCHED") === (record.latched_reason !== null),
);
export type FullAgentRecord = z.infer<typeof recordSchema>;
// Longest state, maximum integer widths, maximum array length and longest reason.
export const FULL_AGENT_STATE_READ_CAP_BYTES = Buffer.byteLength(JSON.stringify({
  version: 1,
  state: "state_STOPPED_CLEAN",
  attempt_started_at_ms: Number.MAX_SAFE_INTEGER,
  charges_ms: Array<number>(FULL_AGENT_CRASH_BUDGET).fill(Number.MAX_SAFE_INTEGER),
  latched_reason: "crash_budget",
}));

type StateFs = Pick<typeof fs,
  "mkdirSync" | "lstatSync" | "openSync" | "fstatSync" | "readSync" |
  "writeFileSync" | "fsyncSync" | "closeSync" | "renameSync" | "unlinkSync" | "writeSync"
>;
export interface FullAgentStateOptions {
  /** Injectable filesystem and clock keep tests out of operator-owned state. */
  fs?: StateFs;
  now?: () => number;
  euid?: number;
}
type StopReason = "crash_budget" | "state_corrupt" | "state_oversized" | "state_unsafe" | "state_io";
class StateError extends Error {
  constructor(readonly reason: StopReason) { super(reason); }
}
export type FullAgentAdmission =
  | { admitted: true; record: FullAgentRecord }
  | { admitted: false; exitCode: typeof FULL_AGENT_STOP_EXIT_CODE; reason: StopReason; charges: number };

/** One bounded record per fortress; launchd supplies the single admitted process. */
export class FullAgentStateStore {
  readonly directory: string;
  readonly path: string;
  private readonly io: StateFs;
  private readonly now: () => number;
  private readonly euid: number;

  constructor(fortress: string, options: FullAgentStateOptions = {}) {
    this.directory = join(fortress, "supervision");
    this.path = join(this.directory, "full-agent.json");
    this.io = options.fs ?? fs;
    this.now = options.now ?? Date.now;
    this.euid = options.euid ?? process.geteuid!();
  }

  private directoryIdentity(create: boolean): fs.Stats {
    if (create) {
      try { this.io.mkdirSync(this.directory, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
    const stats = this.io.lstatSync(this.directory);
    // Private, owned directory custody prevents another principal replacing the counter.
    if (!stats.isDirectory() || stats.isSymbolicLink() || stats.uid !== this.euid || (stats.mode & 0o777) !== 0o700) {
      throw new StateError("state_unsafe");
    }
    return stats;
  }

  /** Read without creating or repairing anything; missing state is distinct from corruption. */
  read(): FullAgentRecord | null {
    try { this.directoryIdentity(false); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    let fd: number;
    try { fd = this.io.openSync(this.path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new StateError("state_unsafe");
      throw error;
    }
    try {
      const stats = this.io.fstatSync(fd);
      if (!stats.isFile() || stats.uid !== this.euid || (stats.mode & 0o777) !== 0o600 || stats.nlink !== 1) {
        throw new StateError("state_unsafe");
      }
      if (stats.size > FULL_AGENT_STATE_READ_CAP_BYTES) throw new StateError("state_oversized");
      // One extra byte detects a concurrent extension without unbounded allocation or work.
      const bytes = Buffer.alloc(FULL_AGENT_STATE_READ_CAP_BYTES + 1);
      let offset = 0;
      while (offset < bytes.length) {
        const n = this.io.readSync(fd, bytes, offset, bytes.length - offset, offset);
        if (n === 0) break;
        offset += n;
      }
      if (offset > FULL_AGENT_STATE_READ_CAP_BYTES) throw new StateError("state_oversized");
      try { return recordSchema.parse(JSON.parse(bytes.subarray(0, offset).toString("utf8"))); }
      catch { throw new StateError("state_corrupt"); }
    } finally { this.io.closeSync(fd); }
  }

  private persist(record: FullAgentRecord): void {
    const bytes = JSON.stringify(recordSchema.parse(record));
    if (Buffer.byteLength(bytes) > FULL_AGENT_STATE_READ_CAP_BYTES) throw new StateError("state_oversized");
    const identity = this.directoryIdentity(true);
    const dir = this.io.openSync(this.directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    // One fixed publication slot bounds crash-orphan state; an occupied slot refuses admission until an attended reset.
    const temporary = join(this.directory, ".full-agent.tmp");
    let fd: number | undefined;
    let createdTemporary = false;
    try {
      const opened = this.io.fstatSync(dir);
      if (opened.dev !== identity.dev || opened.ino !== identity.ino) throw new StateError("state_unsafe");
      fd = this.io.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      createdTemporary = true;
      this.io.writeFileSync(fd, bytes);
      this.io.fsyncSync(fd);
      this.io.closeSync(fd);
      fd = undefined;
      const current = this.directoryIdentity(false);
      if (current.dev !== identity.dev || current.ino !== identity.ino) throw new StateError("state_unsafe");
      this.io.renameSync(temporary, this.path);
      createdTemporary = false;
      this.io.fsyncSync(dir);
    } finally {
      try {
        if (fd !== undefined) this.io.closeSync(fd);
      } finally {
        try {
          // Never remove a pre-existing publication slot. Failed cleanup leaves one bounded orphan that blocks admission.
          if (createdTemporary) {
            try { this.io.unlinkSync(temporary); }
            catch { /* A failed publication already refuses; its orphan requires explicit reset. */ }
          }
        } finally { this.io.closeSync(dir); }
      }
    }
  }

  private stop(reason: StopReason, charges: number): FullAgentAdmission {
    try {
      // must match FULL-AGENT-CRASH-LOOP-STOP in server/reorg-surface-manifest.md.
      this.io.writeSync(2, `[castle-wall] FULL-AGENT-CRASH-LOOP-STOP reason=${reason} charges=${charges} window_s=${FULL_AGENT_CRASH_WINDOW_S} - automatic restart stopped; run 'sanctuary castle-wall reset-full --yes'\n`);
    } catch { /* The durable refusal must still stop launchd when stderr is unavailable. */ }
    // 0 is the only status `KeepAlive {SuccessfulExit:false}` does not respawn; the durable latch, not the status, is the failure record.
    return { admitted: false, exitCode: FULL_AGENT_STOP_EXIT_CODE, reason, charges };
  }

  /**
   * Charge the preceding unclean attempt before any credential or daemon work.
   * Continuing paths: absent, RUNNING below budget, or STOPPED_CLEAN below budget
   * must each durably publish RUNNING before admission.
   * Refusal paths: an existing latch stops; reaching budget persists LATCHED and
   * stops; any read, custody, schema or publication error stops without admission.
   */
  admit(): FullAgentAdmission {
    let charges: number[] = [];
    try {
      const prior = this.read();
      if (prior?.state === "state_LATCHED") return this.stop("crash_budget", prior.charges_ms.length);
      const now = timestampSchema.parse(this.now());
      charges = (prior?.charges_ms ?? []).filter(charge => now - charge <= WINDOW_MS);
      if (prior?.state === "state_RUNNING") charges.push(now);
      const latched = charges.length >= FULL_AGENT_CRASH_BUDGET;
      const record: FullAgentRecord = {
        version: 1,
        state: latched ? "state_LATCHED" : "state_RUNNING",
        attempt_started_at_ms: now,
        charges_ms: charges,
        latched_reason: latched ? "crash_budget" : null,
      };
      this.persist(record);
      return latched ? this.stop("crash_budget", charges.length) : { admitted: true, record };
    } catch (error) {
      // Never replenish on corrupt or inaccessible state: absence of trustworthy accounting is a terminal stop.
      return this.stop(error instanceof StateError ? error.reason : "state_io", charges.length);
    }
  }

  /** Mark only an admitted, fully released session as clean; failures retain the running record. */
  stoppedClean(): void {
    const prior = this.read();
    if (prior?.state !== "state_RUNNING") throw new StateError("state_corrupt");
    const now = timestampSchema.parse(this.now());
    this.persist({ ...prior, state: "state_STOPPED_CLEAN", charges_ms: prior.charges_ms.filter(charge => now - charge <= WINDOW_MS) });
  }

  /** Explicit attended reset is the sole operation allowed to replace corrupt accounting. */
  reset(): void {
    this.directoryIdentity(true);
    try {
      const stats = this.io.lstatSync(this.path);
      if (!stats.isFile() || stats.isSymbolicLink() || stats.uid !== this.euid || (stats.mode & 0o777) !== 0o600 || stats.nlink !== 1) {
        throw new StateError("state_unsafe");
      }
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const temporary = join(this.directory, ".full-agent.tmp");
    try {
      const stats = this.io.lstatSync(temporary);
      if (!stats.isFile() || stats.isSymbolicLink() || stats.uid !== this.euid || (stats.mode & 0o777) !== 0o600 || stats.nlink !== 1) {
        throw new StateError("state_unsafe");
      }
      this.io.unlinkSync(temporary);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    this.persist({ version: 1, state: "state_STOPPED_CLEAN", attempt_started_at_ms: timestampSchema.parse(this.now()), charges_ms: [], latched_reason: null });
  }
}
