/**
 * Single-flight publication of one liveness record under `<fortress>/liveness/`.
 *
 * Each publish writes an exclusive same-directory temp file named for this
 * publisher instance, checks owner and mode on the descriptor, then renames it
 * over the target. The old target survives any failure, and a publisher keeps
 * at most one temp file.
 *
 * A publication fence keeps an earlier instance from overwriting a later one.
 * The first publish of an instance claims `<file>.publisher` under the
 * exclusive `<file>.lock`, and every rename over the target happens under that
 * same lock after checking that the claim still names this instance. An
 * instance that finds itself superseded, or that its owner retires, reaches
 * state_RETIRED: it discards its waiting snapshot and never commits again.
 */
import { constants as fsConstants, promises as fsPromises } from "node:fs";
import { join } from "node:path";
import { IPC_DEADLINE, LIVENESS_DIRECTORY, STATUS_BYTES } from "./constants.js";

/** Owner-only directory mode: rwx for the operator, nothing for group or other. */
const DIRECTORY_MODE = 0o700;
/** Owner-only file mode: rw for the operator, nothing for group or other. */
const FILE_MODE = 0o600;
/** Any group or other permission bit. */
const GROUP_OTHER_BITS = 0o077;
/** Group or other write permission. */
const GROUP_OTHER_WRITE = 0o022;
const TEMP_SUFFIX = ".tmp";
/** The exclusive publication lock beside the target; it exists only while one publisher is inside its critical section. */
const LOCK_SUFFIX = ".lock";
/** The current-instance publication claim beside the target: it names the one instance allowed to commit. */
const OWNER_SUFFIX = ".publisher";
/**
 * How long a publisher waits on a live holder's lock before failing this snapshot. IPC_DEADLINE is shorter than
 * DAEMON_PERIOD, so a wait ends before the next tick's snapshot replaces the waiting one.
 */
const PUBLICATION_LOCK_WAIT = IPC_DEADLINE;
/** 20 ms between lock attempts: long against a held critical section of one small read and one rename, short against the wait. */
const PUBLICATION_LOCK_POLL = 20;
/** Attempts inside PUBLICATION_LOCK_WAIT, derived so the wait bound and the poll interval cannot drift apart. */
const PUBLICATION_LOCK_ATTEMPTS = Math.ceil(PUBLICATION_LOCK_WAIT / PUBLICATION_LOCK_POLL);

export interface PublisherFileHandle {
  stat(): Promise<{ uid: number; mode: number; isFile(): boolean }>;
  writeFile(data: string): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}
/** The filesystem surface the publisher uses, injectable so tests can pause or fail any step. */
export interface PublisherFs {
  mkdir(path: string, options: { mode: number }): Promise<unknown>;
  lstat(path: string): Promise<{ uid: number; mode: number; isDirectory(): boolean }>;
  open(path: string, flags: number, mode: number): Promise<PublisherFileHandle>;
  rename(from: string, to: string): Promise<void>;
  unlink(path: string): Promise<void>;
  readdir(path: string): Promise<string[]>;
  /** Hard link; fails with EEXIST when the new path exists, which is what makes the lock exclusive. */
  link(existing: string, newPath: string): Promise<void>;
  /** Read a small file without following a link. */
  readFile(path: string): Promise<string>;
}

export const nodePublisherFs: PublisherFs = {
  mkdir: (path, options) => fsPromises.mkdir(path, options),
  lstat: path => fsPromises.lstat(path),
  open: (path, flags, mode) => fsPromises.open(path, flags, mode),
  rename: (from, to) => fsPromises.rename(from, to),
  unlink: path => fsPromises.unlink(path),
  readdir: path => fsPromises.readdir(path),
  link: (existing, newPath) => fsPromises.link(existing, newPath),
  readFile: async path => {
    const handle = await fsPromises.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    try { return await handle.readFile("utf8"); } finally { await handle.close().catch(() => undefined); }
  },
};

/** True while a process with this pid exists; a pid owned by another user still exists (EPERM). */
export function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

export interface LivenessPublisherOptions {
  fortressPath: string;
  fileName: string;
  /** Unique per daemon instance; it names this publisher's one temp file. */
  instance: string;
  operatorUid: number;
  fs?: PublisherFs;
  /** INTERNAL/TEST: the pid recorded in this publisher's lock claim; defaults to this process. */
  pid?: number;
  /** INTERNAL/TEST: whether a lock holder's process still exists; defaults to a signal-0 probe. */
  processExists?: (pid: number) => boolean;
}

export class LivenessPublicationError extends Error {}

/** state_ACTIVE publishes; state_RETIRED is terminal and holds no snapshot. */
type PublisherState = "state_ACTIVE" | "state_RETIRED";
type LockHolder = "held_live" | "held_stale" | "gone";

/** Single-flight publisher: one write in flight, and at most one newer record waiting behind it. */
export class LivenessRecordPublisher {
  private readonly fs: PublisherFs;
  private readonly directory: string;
  private readonly target: string;
  private readonly temp: string;
  private readonly lock: string;
  private readonly lockTemp: string;
  private readonly owner: string;
  private readonly ownerTemp: string;
  private readonly pid: number;
  private readonly holderExists: (pid: number) => boolean;
  private state: PublisherState = "state_ACTIVE";
  private inFlight: Promise<void> | null = null;
  private waiting: string | null = null;
  private firstPublish = true;
  private published = 0;
  private failures = 0;

  constructor(private readonly options: LivenessPublisherOptions) {
    this.fs = options.fs ?? nodePublisherFs;
    this.directory = join(options.fortressPath, LIVENESS_DIRECTORY);
    this.target = join(this.directory, options.fileName);
    this.temp = join(this.directory, `${options.fileName}.${options.instance}${TEMP_SUFFIX}`);
    this.lock = join(this.directory, `${options.fileName}${LOCK_SUFFIX}`);
    this.lockTemp = join(this.directory, `${options.fileName}.${options.instance}${LOCK_SUFFIX}${TEMP_SUFFIX}`);
    this.owner = join(this.directory, `${options.fileName}${OWNER_SUFFIX}`);
    this.ownerTemp = join(this.directory, `${options.fileName}.${options.instance}${OWNER_SUFFIX}${TEMP_SUFFIX}`);
    this.pid = options.pid ?? process.pid;
    this.holderExists = options.processExists ?? processExists;
  }

  /**
   * Retire this publisher: the waiting snapshot is discarded and no later
   * snapshot is created or committed. The recorder calls it at daemon stop, and
   * the publisher calls it on itself when another instance holds the claim.
   */
  retire(): void {
    this.state = "state_RETIRED";
    this.waiting = null;
  }

  isRetired(): boolean {
    return this.state === "state_RETIRED";
  }

  /** Publish a record; a call during an in-flight write replaces any older waiting record. */
  publish(record: unknown): Promise<void> {
    if (this.state === "state_RETIRED") {
      this.failures += 1;
      return Promise.reject(new LivenessPublicationError("liveness publisher retired"));
    }
    const text = `${JSON.stringify(record)}\n`;
    if (Buffer.byteLength(text) > STATUS_BYTES) {
      this.failures += 1;
      return Promise.reject(new LivenessPublicationError("record exceeds the status byte cap"));
    }
    if (this.inFlight !== null) {
      this.waiting = text;
      return this.inFlight;
    }
    this.inFlight = this.drain(text).finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  stats(): { published: number; failures: number } {
    return { published: this.published, failures: this.failures };
  }

  private async drain(first: string): Promise<void> {
    let next: string | null = first;
    let lastError: unknown = null;
    // A retired publisher stops between snapshots; retire() already dropped the waiting one.
    while (next !== null && this.state === "state_ACTIVE") {
      const text: string = next;
      this.waiting = null;
      try {
        await this.writeOnce(text);
        this.published += 1;
        lastError = null;
      } catch (error) {
        this.failures += 1;
        lastError = error;
      }
      next = this.waiting;
    }
    if (lastError !== null) throw lastError;
  }

  private async ensureDirectory(): Promise<void> {
    try {
      await this.fs.mkdir(this.directory, { mode: DIRECTORY_MODE });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const info = await this.fs.lstat(this.directory);
    // Never publish into a directory another principal controls; readers refuse it the same way.
    if (!info.isDirectory() || info.uid !== this.options.operatorUid || (info.mode & GROUP_OTHER_WRITE) !== 0) {
      throw new LivenessPublicationError("liveness directory custody refused");
    }
  }

  /** Remove temp files left by earlier instances; an old temp is never trusted or renamed. */
  private async removeStaleTemps(): Promise<void> {
    const prefix = `${this.options.fileName}.`;
    for (const name of await this.fs.readdir(this.directory)) {
      if (name.startsWith(prefix) && name.endsWith(TEMP_SUFFIX)) {
        await this.fs.unlink(join(this.directory, name)).catch(() => undefined);
      }
    }
  }

  private assertActive(): void {
    if (this.state !== "state_ACTIVE") throw new LivenessPublicationError("liveness publisher retired");
  }

  /** Create `path` exclusively with `text`, checking custody on the descriptor; nothing is left behind on failure. */
  private async writeExclusive(path: string, text: string): Promise<void> {
    await this.fs.unlink(path).catch(() => undefined);
    const handle = await this.fs.open(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      FILE_MODE,
    );
    let written = false;
    try {
      const info = await handle.stat();
      // The descriptor, not the path, proves what was created: a regular operator-owned owner-only file.
      if (!info.isFile() || info.uid !== this.options.operatorUid || (info.mode & GROUP_OTHER_BITS) !== 0) {
        throw new LivenessPublicationError("liveness temp file custody refused");
      }
      await handle.writeFile(text);
      await handle.sync();
      await handle.close();
      written = true;
    } finally {
      if (!written) {
        await handle.close().catch(() => undefined);
        await this.fs.unlink(path).catch(() => undefined);
      }
    }
  }

  /** Who holds the lock now. Only a holder whose process no longer exists is stale; a live holder, even a paused one, is waited on. */
  private async lockHolder(): Promise<LockHolder> {
    let text: string;
    try {
      text = await this.fs.readFile(this.lock);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return "gone";
      throw error;
    }
    let claim: unknown;
    try { claim = JSON.parse(text); } catch { return "held_stale"; }
    const pid = (claim as { pid?: unknown } | null)?.pid;
    // A claim this code never writes names no holder at all.
    if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return "held_stale";
    return this.holderExists(pid) ? "held_live" : "held_stale";
  }

  /** Take the exclusive publication lock, or fail this snapshot after PUBLICATION_LOCK_WAIT. */
  private async acquireLock(): Promise<void> {
    const claim = `${JSON.stringify({ pid: this.pid, instance: this.options.instance })}\n`;
    for (let attempt = 1; ; attempt++) {
      // The lock appears with its complete holder claim: written to this instance's own temp first, then hard-linked,
      // and the link fails while any lock exists.
      await this.writeExclusive(this.lockTemp, claim);
      try {
        await this.fs.link(this.lockTemp, this.lock);
        return;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        // ENOENT: another instance's startup sweep removed this temp; try again.
        if (code !== "EEXIST" && code !== "ENOENT") throw error;
      } finally {
        await this.fs.unlink(this.lockTemp).catch(() => undefined);
      }
      const holder = await this.lockHolder();
      if (holder === "held_stale") await this.fs.unlink(this.lock).catch(() => undefined);
      if (attempt >= PUBLICATION_LOCK_ATTEMPTS) throw new LivenessPublicationError("liveness publication lock busy");
      if (holder === "held_live") await new Promise(resolve => setTimeout(resolve, PUBLICATION_LOCK_POLL));
    }
  }

  private async withLock<T>(work: () => Promise<T>): Promise<T> {
    await this.acquireLock();
    try {
      return await work();
    } finally {
      await this.fs.unlink(this.lock).catch(() => undefined);
    }
  }

  /** True when the publication claim names this instance. A missing or unreadable claim is not ownership. */
  private async ownsPublication(): Promise<boolean> {
    const text = await this.fs.readFile(this.owner).catch(() => null);
    return text === `${this.options.instance}\n`;
  }

  private async writeOnce(text: string): Promise<void> {
    this.assertActive();
    await this.ensureDirectory();
    if (this.firstPublish) {
      // Startup establishes this instance as the current publisher; from here an earlier instance can no longer commit.
      await this.withLock(async () => {
        this.assertActive();
        await this.removeStaleTemps();
        await this.writeExclusive(this.ownerTemp, `${this.options.instance}\n`);
        await this.fs.rename(this.ownerTemp, this.owner);
      });
      this.firstPublish = false;
    }
    this.assertActive();
    let committed = false;
    try {
      await this.writeExclusive(this.temp, text);
      this.assertActive();
      await this.withLock(async () => {
        // The fence: the claim check and the rename happen under one lock, so no other instance can claim the target
        // between them, and a superseded instance retires instead of overwriting a newer record.
        if (this.state !== "state_ACTIVE" || !await this.ownsPublication()) {
          this.retire();
          throw new LivenessPublicationError("liveness publisher superseded");
        }
        await this.fs.rename(this.temp, this.target);
      });
      committed = true;
    } finally {
      if (!committed) await this.fs.unlink(this.temp).catch(() => undefined);
    }
  }
}
