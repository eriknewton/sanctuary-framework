/**
 * Preparatory full-supervision ledger, with no production consumer. Failures spaced
 * wider than W never latch: this is a sliding incident window, not a lifetime cap.
 * A caller supplies a private existing directory and trustworthy clock/identity
 * readers, and uses a fresh attempt id for each admission. No path is inferred.
 * A writer interrupted inside an IO transaction leaves an exclusive lock and
 * refuses further mutation; attended lock recovery belongs to the later wrapper.
 */
import * as realFs from "node:fs/promises";
import { constants, writeSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { FullSupervisionExitClassification } from "./full-supervision-exit.js";

/** PRD_DESIGN.md item 4: initial attempt + four recoveries; provisional pending PR-A's measured ceiling. */
export const FULL_SUPERVISION_CRASH_BUDGET = 5;
/** PRD_DESIGN.md item 4: 5 * 300 s + 4 * 5 s = 1,520 s, rounded to 30 minutes; provisional pending PR-A. */
export const FULL_SUPERVISION_WINDOW_SECONDS = 1800;
/** PRD_DESIGN.md item 4: 5 s between recoveries; provisional pending PR-A's measured ceiling. */
export const FULL_SUPERVISION_THROTTLE_SECONDS = 5;
const MILLISECONDS_PER_SECOND = 1000;
/** One provisional throttle interval bounds a ledger transaction, independently of daemon IO. */
export const FULL_SUPERVISION_WRITE_DEADLINE_MS = FULL_SUPERVISION_THROTTLE_SECONDS * MILLISECONDS_PER_SECOND;
/** Permit at most one provisional throttle interval of wall-clock adjustment, never monotonic regression. */
export const FULL_SUPERVISION_CLOCK_SKEW_MS = FULL_SUPERVISION_THROTTLE_SECONDS * MILLISECONDS_PER_SECOND;
/** Every refused admission emits exactly this fixed text; durability, not notification count, is authoritative. */
export const FULL_SUPERVISION_REFUSAL_LINE = "full-supervision: admission refused; inspect the durable ledger\n";

const PRIVATE_FILE_MODE = 0o600; // Owner read/write only.
const GROUP_OTHER_WRITE = 0o022; // POSIX group-write and other-write permission bits.
const TOKEN_LIMIT = 2 * 64; // Room for two 64-character hex identity components.
const token = z.string().min(1).max(TOKEN_LIMIT).regex(/^[A-Za-z0-9._:-]+$/);
const timestamp = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const clockSchema = z.object({ wall: timestamp, monotonic: timestamp, bootId: token }).strict();
const chargeSchema = clockSchema.extend({ attemptId: token }).strict();
const identitySchema = z.object({ pid: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), startToken: token }).strict();
const pendingSchema = z.object({ attemptId: token, identity: identitySchema.nullable(), clock: clockSchema }).strict();
const settingsSchema = z.object({ budget: z.number().int().positive(), windowMs: timestamp.positive(), skewMs: timestamp }).strict();
type Clock = z.infer<typeof clockSchema>;
type Charge = z.infer<typeof chargeSchema>;

/** IO facade uses real file descriptors, enabling precise write/rename fault injection. */
export type FullSupervisionFs = Pick<typeof realFs, "open" | "lstat" | "rename" | "unlink">;
/** Only an ESRCH result from a process probe may be represented as dead; permission failures are unknown. */
export type FullSupervisionLiveness = "alive" | "dead" | "unknown";
/** Required provenance providers must return null when they cannot establish their fact. Times are integer milliseconds. */
export interface FullSupervisionDependencies {
  directory: string;
  fs?: FullSupervisionFs;
  wallClock: () => number | null;
  monotonicClock: () => number | null;
  bootIdentity: () => Promise<string | null>;
  processLiveness: (pid: number) => Promise<FullSupervisionLiveness>;
  processStartToken: (pid: number) => Promise<string | null>;
  budget?: number;
  windowSeconds?: number;
  throttleSeconds?: number;
  clockSkewMs?: number;
  writeDeadlineMs?: number;
}
/** State names distinguish a possible unidentified child from an identified pending attempt. */
export type FullSupervisionState = "state_IDLE" | "state_PENDING_UNIDENTIFIED" | "state_PENDING_IDENTIFIED" | "state_LATCHED";
/** Refusals never grant permission, including IO whose completion is still outstanding. */
export type FullSupervisionRefusalReason =
  | "unsafe_state_dir" | "corrupt_state" | "enrolled_ledger_missing" | "clock_rollback"
  | "unknown_clock_provenance" | "unidentified_attempt" | "child_alive" | "child_unknown"
  | "stale_temp" | "latched" | "ledger_write_stalled" | "ledger_busy" | "invalid_attempt" | "throttled";
/** Successful mutations expose the durable state; admitted is true only on a successful admit call. */
export type FullSupervisionResult =
  | { ok: true; admitted: boolean; state: FullSupervisionState; charges: readonly Charge[] }
  | { ok: false; reason: FullSupervisionRefusalReason };

class Refusal extends Error {
  constructor(readonly reason: FullSupervisionRefusalReason) { super(reason); }
}
function refuse(reason: FullSupervisionRefusalReason): never { throw new Refusal(reason); }
function errorCode(error: unknown): string | undefined { return (error as NodeJS.ErrnoException)?.code; }

/**
 * Durable admission library. Operations are serialized without an unbounded queue:
 * concurrent callers refuse. The disk lock remains held until late IO actually
 * finishes, even after a deadline. A crashed transaction's lock is never guessed stale.
 * resetLatch is an explicit caller-authorized recovery operation, not an automatic path.
 */
export class FullSupervisionLedger {
  private readonly fs: FullSupervisionFs;
  private readonly settings: z.infer<typeof settingsSchema>;
  private readonly schema;
  private readonly deadlineMs: number;
  private readonly throttleMs: number;
  private readonly uid: number | undefined;
  private busy = false;
  /** K retained charges suffice: the Kth latches and no further admission can add another. */
  readonly chargeCap: number;
  /** Maximum canonical JSON bytes, derived from the bounded schema and K; reads allow one overflow byte. */
  readonly readCapBytes: number;

  constructor(private readonly deps: FullSupervisionDependencies) {
    this.fs = deps.fs ?? realFs;
    this.settings = settingsSchema.parse({
      budget: deps.budget ?? FULL_SUPERVISION_CRASH_BUDGET,
      windowMs: (deps.windowSeconds ?? FULL_SUPERVISION_WINDOW_SECONDS) * MILLISECONDS_PER_SECOND,
      skewMs: deps.clockSkewMs ?? FULL_SUPERVISION_CLOCK_SKEW_MS,
    });
    this.throttleMs = timestamp.parse((deps.throttleSeconds ?? FULL_SUPERVISION_THROTTLE_SECONDS) * MILLISECONDS_PER_SECOND);
    this.deadlineMs = timestamp.positive().parse(deps.writeDeadlineMs ?? FULL_SUPERVISION_WRITE_DEADLINE_MS);
    this.uid = process.getuid?.();
    this.chargeCap = this.settings.budget;
    this.schema = z.object({
      version: z.literal(1), settings: settingsSchema,
      pending: pendingSchema.nullable(), charges: z.array(chargeSchema).max(this.chargeCap),
      latched: z.boolean(), lastClock: clockSchema, lastSettled: token.nullable(), resetReason: token.nullable(),
    }).strict();
    const widestToken = "x".repeat(TOKEN_LIMIT);
    const widestClock = { wall: Number.MAX_SAFE_INTEGER, monotonic: Number.MAX_SAFE_INTEGER, bootId: widestToken };
    const widestCharge = { ...widestClock, attemptId: widestToken };
    // ASCII-only strings cannot expand through escaping, so serialized maxima bound every accepted record.
    this.readCapBytes = Buffer.byteLength(JSON.stringify({
      version: 1, settings: this.settings,
      pending: { attemptId: widestToken, identity: { pid: Number.MAX_SAFE_INTEGER, startToken: widestToken }, clock: widestClock },
      charges: Array.from({ length: this.chargeCap }, () => widestCharge), latched: false,
      lastClock: widestClock, lastSettled: widestToken, resetReason: widestToken,
    }));
  }

  private path(name: string): string { return join(this.deps.directory, name); }
  private async directoryCheck(): Promise<void> {
    const stat = await this.fs.lstat(this.deps.directory);
    // Only the current uid may control state: another writer could replenish the crash budget.
    if (!stat.isDirectory() || stat.isSymbolicLink() || this.uid === undefined || stat.uid !== this.uid || (stat.mode & GROUP_OTHER_WRITE)) {
      refuse("unsafe_state_dir");
    }
  }
  private async read(name: string, enrolled = false): Promise<string | null> {
    let handle;
    try { handle = await this.fs.open(this.path(name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) {
      if (errorCode(error) === "ENOENT") return null;
      if (enrolled && ["EACCES", "EPERM", "EIO"].includes(errorCode(error) ?? "")) refuse("enrolled_ledger_missing");
      refuse("corrupt_state");
    }
    try {
      const stat = await handle.stat();
      // Check the opened inode, not merely a path that could refer to a symlink or another owner.
      if (!stat.isFile() || stat.uid !== this.uid || stat.nlink !== 1 || (stat.mode & GROUP_OTHER_WRITE) || stat.size > this.readCapBytes) refuse("corrupt_state");
      const bytes = Buffer.alloc(this.readCapBytes + 1); // One extra byte detects growth since fstat.
      let used = 0;
      while (used < bytes.length) {
        const { bytesRead } = await handle.read(bytes, used, bytes.length - used, used);
        if (!bytesRead) break;
        used += bytesRead;
      }
      if (used > this.readCapBytes) refuse("corrupt_state");
      return bytes.subarray(0, used).toString("utf8");
    } catch (error) {
      if (enrolled && !(error instanceof Refusal)) refuse("enrolled_ledger_missing");
      throw error;
    } finally { await handle.close(); }
  }
  private async syncDirectory(): Promise<void> {
    const dir = await this.fs.open(this.deps.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await dir.sync(); } finally { await dir.close(); }
  }
  private async write(name: string, value: unknown): Promise<void> {
    const temp = this.path(`${name}.next`);
    let handle;
    try { handle = await this.fs.open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, PRIVATE_FILE_MODE); }
    catch (error) {
      // A pre-existing temp belongs to an interrupted writer and must not be overwritten or removed.
      if (errorCode(error) === "EEXIST") refuse("stale_temp");
      throw error;
    }
    let renamed = false;
    try {
      await handle.writeFile(JSON.stringify(value));
      await handle.sync();
      await this.fs.rename(temp, this.path(name));
      renamed = true;
      await this.syncDirectory();
    } finally {
      try {
        if (!renamed) {
          // Cleanup may unlink only this writer's inode, never a replacement at the same path.
          try {
            const owned = await handle.stat();
            const current = await this.fs.lstat(temp);
            if (current.dev === owned.dev && current.ino === owned.ino) await this.fs.unlink(temp);
          } catch { /* An unprovable cleanup leaves a typed stale-temp refusal on the next write. */ }
        }
      } finally { await handle.close(); }
    }
  }
  private async clock(): Promise<Clock> {
    let result;
    try { result = clockSchema.safeParse({ wall: this.deps.wallClock(), monotonic: this.deps.monotonicClock(), bootId: await this.deps.bootIdentity() }); }
    catch { refuse("unknown_clock_provenance"); }
    if (!result.success) refuse("unknown_clock_provenance");
    return result.data;
  }
  private checkClock(now: Clock, previous: Clock): void {
    // Rollback is checked before pruning; a changed boot cannot erase the wall-clock floor.
    if (now.wall < previous.wall - this.settings.skewMs) refuse("clock_rollback");
    if (now.bootId === previous.bootId && now.monotonic < previous.monotonic) refuse("clock_rollback");
  }
  private async load(now: Clock) {
    const marker = await this.read("enrolled.json");
    // Unreadable enrolled data cannot become a fresh budget; malformed files still name corruption.
    const contents = await this.read("ledger.json", marker !== null);
    if (marker === null) {
      if (contents !== null) refuse("corrupt_state");
      return null;
    }
    if (marker !== JSON.stringify({ version: 1, settings: this.settings })) refuse("corrupt_state");
    // Enrollment is separate so deleting the ledger never replenishes the budget.
    if (contents === null) refuse("enrolled_ledger_missing");
    let parsed;
    try { parsed = this.schema.safeParse(JSON.parse(contents)); } catch { refuse("corrupt_state"); }
    if (!parsed.success) refuse("corrupt_state");
    const record = parsed.data;
    if (JSON.stringify(record.settings) !== JSON.stringify(this.settings)) refuse("corrupt_state");
    this.checkClock(now, record.lastClock);
    // Settlement writes a latch only while clearing pending; accepting both could replay beyond K.
    if (record.latched && record.pending) refuse("corrupt_state");
    const ids = new Set(record.charges.map((charge) => charge.attemptId));
    if (ids.size !== record.charges.length || (record.pending && ids.has(record.pending.attemptId))) refuse("corrupt_state");
    for (const charge of record.charges) this.checkClock(now, charge);
    if (record.pending) this.checkClock(now, record.pending.clock);
    if (!record.latched && record.charges.length >= this.chargeCap) refuse("corrupt_state");
    return record;
  }
  private snapshot(record: NonNullable<Awaited<ReturnType<FullSupervisionLedger["load"]>>>, admitted = false): FullSupervisionResult {
    const state: FullSupervisionState = record.latched ? "state_LATCHED" : record.pending
      ? record.pending.identity ? "state_PENDING_IDENTIFIED" : "state_PENDING_UNIDENTIFIED" : "state_IDLE";
    return { ok: true, admitted, state, charges: record.charges };
  }
  private async transaction(work: () => Promise<FullSupervisionResult>, admission = false): Promise<FullSupervisionResult> {
    const notify = (reason: FullSupervisionRefusalReason): FullSupervisionResult => {
      // All refused starts synchronously report the same fixed line, even if disk IO is stalled.
      if (admission) writeSync(2, FULL_SUPERVISION_REFUSAL_LINE);
      return { ok: false, reason };
    };
    if (this.busy) return notify("ledger_busy");
    let started: number;
    try { started = timestamp.parse(this.deps.monotonicClock()); }
    catch { return notify("unknown_clock_provenance"); }
    this.busy = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const operation = (async () => {
      let lock;
      try {
        await this.directoryCheck();
        try { lock = await this.fs.open(this.path("writer.lock"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, PRIVATE_FILE_MODE); }
        catch (error) { if (errorCode(error) === "EEXIST") refuse("ledger_busy"); throw error; }
        await lock.sync();
        await this.syncDirectory();
        return await work();
      } finally {
        try {
          if (lock) { await lock.close(); await this.fs.unlink(this.path("writer.lock")); await this.syncDirectory(); }
        } finally { this.busy = false; }
      }
    })().catch((error: unknown): FullSupervisionResult => ({ ok: false, reason: error instanceof Refusal ? error.reason : "corrupt_state" }));
    // A deadline never cancels ownership: late IO retains the lock until its actual completion.
    const stalled = new Promise<FullSupervisionResult>((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, reason: "ledger_write_stalled" }), this.deadlineMs);
    });
    const result = await Promise.race([operation, stalled]);
    if (timer) clearTimeout(timer);
    // Promise continuations can beat an overdue timer; elapsed time gates every successful return.
    let finished: number;
    try { finished = timestamp.parse(this.deps.monotonicClock()); }
    catch { return notify("unknown_clock_provenance"); }
    if (finished < started) return notify("clock_rollback");
    if (finished - started >= this.deadlineMs) return notify("ledger_write_stalled");
    return result.ok ? result : notify(result.reason);
  }

  /** Persist unidentified pending before allowing a caller to spawn exactly one child. */
  admit(attemptId: string): Promise<FullSupervisionResult> {
    return this.transaction(async () => {
      if (!token.safeParse(attemptId).success) refuse("invalid_attempt");
      const now = await this.clock();
      let record = await this.load(now);
      if (record === null) {
        // Marker precedes even the first ledger write: interrupted enrollment fails closed.
        await this.write("enrolled.json", { version: 1, settings: this.settings });
        record = { version: 1, settings: this.settings, pending: null, charges: [], latched: false, lastClock: now, lastSettled: null, resetReason: null };
      }
      if (record.pending) {
        const identity = record.pending.identity;
        if (!identity) refuse("unidentified_attempt");
        let live: FullSupervisionLiveness = "unknown";
        try { live = await this.deps.processLiveness(identity.pid); } catch { /* Unknown is never death evidence. */ }
        if (live === "alive") refuse("child_alive");
        if (live !== "dead") refuse("child_unknown");
        // Only proven death replays a charge; the atomic replacement clears pending with that charge.
        record = this.charge(record, now);
        await this.write("ledger.json", record);
      }
      if (record.latched) refuse("latched");
      if (record.lastSettled === attemptId || record.charges.some((charge) => charge.attemptId === attemptId)) refuse("invalid_attempt");
      const latest = record.charges.at(-1);
      if (this.throttleMs > 0 && latest && now.wall - latest.wall < this.throttleMs) refuse("throttled");
      record.pending = { attemptId, identity: null, clock: now };
      record.lastClock = this.highWater(now, record.lastClock);
      // The pending record must be durable before permission, so wrapper death cannot grant a free retry.
      await this.write("ledger.json", record);
      return this.snapshot(record, true);
    }, true);
  }

  private highWater(now: Clock, previous: Clock): Clock { return { ...now, wall: Math.max(now.wall, previous.wall) }; }
  private charge(record: NonNullable<Awaited<ReturnType<FullSupervisionLedger["load"]>>>, now: Clock) {
    if (!record.pending) refuse("invalid_attempt");
    // Retain only the incident window, with K as the hard ceiling; healthy completions never clear charges.
    record.charges = record.charges.filter((charge) => {
      // Within one boot, a wall-clock step cannot erase charges that monotonic time still retains.
      const elapsed = charge.bootId === now.bootId
        ? Math.min(now.wall - charge.wall, now.monotonic - charge.monotonic)
        : now.wall - charge.wall;
      return elapsed <= this.settings.windowMs;
    });
    record.charges.push({ ...now, attemptId: record.pending.attemptId });
    record.lastSettled = record.pending.attemptId;
    record.pending = null;
    record.lastClock = this.highWater(now, record.lastClock);
    record.latched = record.latched || record.charges.length >= this.chargeCap;
    return record;
  }

  /** Bind the admitted attempt to an observed process identity before relying on its later death. */
  recordIdentity(attemptId: string, pid: number, startToken: string): Promise<FullSupervisionResult> {
    return this.transaction(async () => {
      const now = await this.clock();
      const record = await this.load(now);
      const identity = identitySchema.safeParse({ pid, startToken });
      if (!record?.pending || record.pending.attemptId !== attemptId || !identity.success) refuse("invalid_attempt");
      // The start token describes this child, verified by the injected OS reader, not by caller assertion.
      let observed: string | null = null;
      try { observed = await this.deps.processStartToken(pid); } catch { /* Refuse unverifiable identity. */ }
      if (observed !== startToken) refuse("child_unknown");
      if (record.pending.identity && JSON.stringify(record.pending.identity) !== JSON.stringify(identity.data)) refuse("invalid_attempt");
      record.pending.identity = identity.data;
      record.lastClock = this.highWater(now, record.lastClock);
      await this.write("ledger.json", record);
      return this.snapshot(record);
    });
  }

  /** Settle only the named pending attempt; duplicate settlement cannot add a second charge. Terminal exits latch. */
  settle(attemptId: string, classification: FullSupervisionExitClassification): Promise<FullSupervisionResult> {
    return this.transaction(async () => {
      const now = await this.clock();
      const record = await this.load(now);
      if (!record || classification.decidedBy.attemptId !== attemptId) refuse("invalid_attempt");
      if (!record.pending) {
        if (record.lastSettled === attemptId || record.charges.some((charge) => charge.attemptId === attemptId)) return this.snapshot(record);
        refuse("invalid_attempt");
      }
      if (record.pending.attemptId !== attemptId) refuse("invalid_attempt");
      switch (classification.kind) {
        case "charged_restart":
        case "charged_unverified_exit": this.charge(record, now); break;
        case "terminal": record.latched = true; break;
        case "uncharged_clean":
        case "uncharged_stop": break;
        default: {
          const unreachable: never = classification;
          void unreachable;
          // Unknown runtime classifications cannot clear a pending attempt or manufacture success.
          refuse("invalid_attempt");
        }
      }
      record.pending = null;
      record.lastSettled = attemptId;
      record.lastClock = this.highWater(now, record.lastClock);
      await this.write("ledger.json", record);
      return this.snapshot(record);
    });
  }

  /** Inspect durable state without replaying a pending child or silently enrolling the directory. */
  status(): Promise<FullSupervisionResult> {
    return this.transaction(async () => {
      const record = await this.load(await this.clock());
      return record ? this.snapshot(record) : { ok: true, admitted: false, state: "state_IDLE", charges: [] };
    });
  }

  /** Explicit recovery with a bounded reason token; cannot discard an unresolved pending child. */
  resetLatch(reason: string): Promise<FullSupervisionResult> {
    return this.transaction(async () => {
      const now = await this.clock();
      const record = await this.load(now);
      if (!record || !token.safeParse(reason).success) refuse("invalid_attempt");
      if (record.pending) refuse("unidentified_attempt");
      record.latched = false;
      record.charges = [];
      record.resetReason = reason;
      record.lastClock = this.highWater(now, record.lastClock);
      await this.write("ledger.json", record);
      return this.snapshot(record);
    });
  }
}
