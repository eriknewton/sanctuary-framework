/**
 * The read-only liveness reader. It opens `<fortress>` and `<fortress>/liveness/`
 * descriptor-first, then each record without following links and without
 * blocking, checks the descriptor before reading, and bounds every operation
 * by STATUS_READ_DEADLINE. It never writes, repairs, chmods, renews or
 * advances anything, and it never spawns a process: the current boot and
 * uptime come from an injected provider.
 *
 * Only owner and mode bits are checked here; ACL verification is a
 * commissioning step.
 */
import { constants as fsConstants, promises as fsPromises } from "node:fs";
import { join } from "node:path";
import {
  CONFIG_BYTES,
  CONFIG_RECORD_FILE,
  DAEMON_RECORD_FILE,
  LIVENESS_DIRECTORY,
  OBSERVER_RECORD_FILE,
  STATUS_BYTES,
  STATUS_READ_DEADLINE,
} from "./constants.js";
import { evaluateLiveness, type CustodyCause, type HostClock, type LivenessEnvelope, type LivenessInput, type RecordRead } from "./evaluate.js";

/** Group or other write permission on a directory. */
const GROUP_OTHER_WRITE = 0o022;
/** Any group or other permission on a record file (records are mode 0600). */
const GROUP_OTHER_BITS = 0o077;

export interface ReaderStat {
  uid: number;
  mode: number;
  size: number;
  isFile(): boolean;
  isDirectory(): boolean;
}
export interface ReaderFileHandle {
  stat(): Promise<ReaderStat>;
  read(buffer: Uint8Array, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}
/** Asynchronous open, injectable so a stalled or hostile filesystem can be simulated. */
export interface ReaderFs {
  open(path: string, flags: number): Promise<ReaderFileHandle>;
}
export const nodeReaderFs: ReaderFs = {
  open: (path, flags) => fsPromises.open(path, flags),
};

/** Schedules the read deadline; injectable so a test can fire it deterministically. */
export interface DeadlineClock {
  after(ms: number, fire: () => void): { cancel(): void };
}
export const realDeadlineClock: DeadlineClock = {
  after(ms, fire) {
    const timer = setTimeout(fire, ms);
    timer.unref?.();
    return { cancel: () => clearTimeout(timer) };
  },
};

/** Provides the reader's current boot identity and uptime. */
export interface HostClockProvider {
  read(): Promise<HostClock>;
  /** Current uptime alone, used when no record is present and the boot identity cannot matter. */
  uptimeMs?(): number;
}

/** Placeholder boot for an evaluation with no record present; nothing is ever compared with it. */
export const NO_RECORD_BOOT = "no-record-present";

export interface LivenessReadResult {
  directory: LivenessInput["directory"];
  daemon: RecordRead;
  observer: RecordRead;
  config: RecordRead;
  readDeadlineHit: boolean;
}

class DeadlineHit extends Error {}

const FILE_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
const DIRECTORY_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_DIRECTORY ?? 0);

/** Read the three records under one deadline; a timeout or non-regular file reads custody_invalid. */
export async function readLivenessRecords(options: {
  fortressPath: string;
  operatorUid: number;
  fs?: ReaderFs;
  deadline?: DeadlineClock;
}): Promise<LivenessReadResult> {
  const fs = options.fs ?? nodeReaderFs;
  const clock = options.deadline ?? realDeadlineClock;
  let expired = false;
  let fireDeadline: () => void = () => undefined;
  const deadlinePromise = new Promise<never>((_resolve, reject) => {
    fireDeadline = () => { expired = true; reject(new DeadlineHit()); };
  });
  deadlinePromise.catch(() => undefined);
  // Every reader operation races this one deadline, so a stalled filesystem cannot hold a status command.
  const timer = clock.after(STATUS_READ_DEADLINE, () => fireDeadline());
  const bounded = <T>(operation: Promise<T>): Promise<T> => {
    // A late completion after the deadline is discarded, and a late handle is closed rather than leaked.
    operation.then(value => {
      if (expired && value !== null && typeof value === "object" && "close" in value) {
        void (value as { close(): Promise<void> }).close().catch(() => undefined);
      }
    }, () => undefined);
    if (expired) return Promise.reject(new DeadlineHit());
    return Promise.race([operation, deadlinePromise]);
  };
  const deadlineRecord: RecordRead = { status: "custody_invalid", cause: "read_deadline" };
  try {
    const directory = await checkDirectories(fs, bounded, options.fortressPath, options.operatorUid);
    if (directory.status !== "ok") {
      const absent: RecordRead = { status: "absent" };
      return { directory, daemon: absent, observer: absent, config: absent, readDeadlineHit: false };
    }
    const base = join(options.fortressPath, LIVENESS_DIRECTORY);
    const daemon = await readRecord(fs, bounded, join(base, DAEMON_RECORD_FILE), options.operatorUid, STATUS_BYTES);
    const observer = await readRecord(fs, bounded, join(base, OBSERVER_RECORD_FILE), options.operatorUid, STATUS_BYTES);
    const config = await readRecord(fs, bounded, join(base, CONFIG_RECORD_FILE), options.operatorUid, CONFIG_BYTES);
    return { directory, daemon, observer, config, readDeadlineHit: false };
  } catch (error) {
    if (!(error instanceof DeadlineHit)) throw error;
    return { directory: { status: "ok" }, daemon: deadlineRecord, observer: deadlineRecord, config: deadlineRecord, readDeadlineHit: true };
  } finally {
    timer.cancel();
  }
}

type Bounded = <T>(operation: Promise<T>) => Promise<T>;

async function closeQuietly(handle: ReaderFileHandle): Promise<void> {
  await handle.close().catch(() => undefined);
}

async function checkDirectory(fs: ReaderFs, bounded: Bounded, path: string, operatorUid: number): Promise<"ok" | "absent" | CustodyCause> {
  let handle: ReaderFileHandle;
  try {
    handle = await bounded(fs.open(path, DIRECTORY_FLAGS));
  } catch (error) {
    if (error instanceof DeadlineHit) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return "absent";
    return "not_directory";
  }
  try {
    const info = await bounded(handle.stat());
    if (!info.isDirectory()) return "not_directory";
    if (info.uid !== operatorUid) return "owner";
    if ((info.mode & GROUP_OTHER_WRITE) !== 0) return "mode";
    return "ok";
  } finally {
    await closeQuietly(handle);
  }
}

async function checkDirectories(fs: ReaderFs, bounded: Bounded, fortressPath: string, operatorUid: number): Promise<LivenessInput["directory"]> {
  const fortress = await checkDirectory(fs, bounded, fortressPath, operatorUid);
  if (fortress === "absent") return { status: "absent" };
  if (fortress !== "ok") return { status: "custody_invalid", cause: fortress };
  const liveness = await checkDirectory(fs, bounded, join(fortressPath, LIVENESS_DIRECTORY), operatorUid);
  if (liveness === "absent") return { status: "absent" };
  if (liveness !== "ok") return { status: "custody_invalid", cause: liveness };
  return { status: "ok" };
}

async function readRecord(fs: ReaderFs, bounded: Bounded, path: string, operatorUid: number, cap: number): Promise<RecordRead> {
  let handle: ReaderFileHandle;
  try {
    // O_NONBLOCK keeps a FIFO from blocking the open; O_NOFOLLOW refuses a substituted link.
    handle = await bounded(fs.open(path, FILE_FLAGS));
  } catch (error) {
    if (error instanceof DeadlineHit) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { status: "absent" };
    return { status: "custody_invalid", cause: "not_regular_file" };
  }
  try {
    const info = await bounded(handle.stat());
    // The descriptor must be a regular file before any byte is read; a FIFO, device or directory is refused here.
    if (!info.isFile()) return { status: "custody_invalid", cause: "not_regular_file" };
    if (info.uid !== operatorUid) return { status: "custody_invalid", cause: "owner" };
    if ((info.mode & GROUP_OTHER_BITS) !== 0) return { status: "custody_invalid", cause: "mode" };
    if (info.size > cap) return { status: "custody_invalid", cause: "size" };
    const buffer = new Uint8Array(cap + 1);
    let total = 0;
    while (total <= cap) {
      const { bytesRead } = await bounded(handle.read(buffer, total, cap + 1 - total, total));
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > cap) return { status: "custody_invalid", cause: "size" };
    try {
      return { status: "present", value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total))) };
    } catch {
      return { status: "unparsable" };
    }
  } finally {
    await closeQuietly(handle);
  }
}

/** Read and evaluate one fortress. The reader stores nothing and writes nothing. */
export async function readAndEvaluateLiveness(options: {
  fortressPath: string;
  fortressId: string;
  operatorUid: number;
  platform: string;
  nowMs: () => number;
  host: HostClockProvider;
  fs?: ReaderFs;
  deadline?: DeadlineClock;
}): Promise<LivenessEnvelope> {
  const local = { fortress_id: options.fortressId, platform: options.platform, operator_uid: options.operatorUid };
  const absent: RecordRead = { status: "absent" };
  if (options.platform !== "darwin") {
    // Off darwin the provider is never called; the wall reads unsupported_adapter.
    return evaluateLiveness({ nowMs: options.nowMs(), platform: options.platform, host: { ok: false }, local, directory: { status: "absent" }, daemon: absent, observer: absent, config: absent });
  }
  const read = await readLivenessRecords({ fortressPath: options.fortressPath, operatorUid: options.operatorUid, fs: options.fs, deadline: options.deadline });
  const nothingPresent = read.directory.status !== "custody_invalid" && !read.readDeadlineHit &&
    read.daemon.status === "absent" && read.observer.status === "absent" && read.config.status === "absent";
  let host: HostClock;
  try {
    // With no record present the boot identity cannot change the verdict, so the boot provider is not consulted.
    host = nothingPresent && options.host.uptimeMs !== undefined
      ? { ok: true, bootId: NO_RECORD_BOOT, uptimeMs: options.host.uptimeMs() }
      : await options.host.read();
  } catch {
    host = { ok: false };
  }
  return evaluateLiveness({
    nowMs: options.nowMs(),
    platform: options.platform,
    host,
    local,
    directory: read.directory,
    daemon: read.daemon,
    observer: read.observer,
    config: read.config,
    readDeadlineHit: read.readDeadlineHit,
  });
}
