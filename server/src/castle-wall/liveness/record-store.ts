/**
 * Single-flight publication of one liveness record under `<fortress>/liveness/`.
 *
 * Each publish writes an exclusive same-directory temp file named for this
 * publisher instance, checks owner and mode on the descriptor, then renames it
 * over the target. The old target survives any failure, and a publisher keeps
 * at most one temp file.
 */
import { constants as fsConstants, promises as fsPromises } from "node:fs";
import { join } from "node:path";
import { LIVENESS_DIRECTORY, STATUS_BYTES } from "./constants.js";

/** Owner-only directory mode: rwx for the operator, nothing for group or other. */
const DIRECTORY_MODE = 0o700;
/** Owner-only file mode: rw for the operator, nothing for group or other. */
const FILE_MODE = 0o600;
/** Any group or other permission bit. */
const GROUP_OTHER_BITS = 0o077;
/** Group or other write permission. */
const GROUP_OTHER_WRITE = 0o022;
const TEMP_SUFFIX = ".tmp";

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
}

export const nodePublisherFs: PublisherFs = {
  mkdir: (path, options) => fsPromises.mkdir(path, options),
  lstat: path => fsPromises.lstat(path),
  open: (path, flags, mode) => fsPromises.open(path, flags, mode),
  rename: (from, to) => fsPromises.rename(from, to),
  unlink: path => fsPromises.unlink(path),
  readdir: path => fsPromises.readdir(path),
};

export interface LivenessPublisherOptions {
  fortressPath: string;
  fileName: string;
  /** Unique per daemon instance; it names this publisher's one temp file. */
  instance: string;
  operatorUid: number;
  fs?: PublisherFs;
}

export class LivenessPublicationError extends Error {}

/** Single-flight publisher: one write in flight, and at most one newer record waiting behind it. */
export class LivenessRecordPublisher {
  private readonly fs: PublisherFs;
  private readonly directory: string;
  private readonly target: string;
  private readonly temp: string;
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
  }

  /** Publish a record; a call during an in-flight write replaces any older waiting record. */
  publish(record: unknown): Promise<void> {
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
    while (next !== null) {
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

  private async writeOnce(text: string): Promise<void> {
    await this.ensureDirectory();
    if (this.firstPublish) {
      await this.removeStaleTemps();
      this.firstPublish = false;
    }
    await this.fs.unlink(this.temp).catch(() => undefined);
    const handle = await this.fs.open(
      this.temp,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      FILE_MODE,
    );
    let renamed = false;
    try {
      const info = await handle.stat();
      // The descriptor, not the path, proves what was created: a regular operator-owned owner-only file.
      if (!info.isFile() || info.uid !== this.options.operatorUid || (info.mode & GROUP_OTHER_BITS) !== 0) {
        throw new LivenessPublicationError("liveness temp file custody refused");
      }
      await handle.writeFile(text);
      await handle.sync();
      await handle.close();
      await this.fs.rename(this.temp, this.target);
      renamed = true;
    } finally {
      if (!renamed) {
        await handle.close().catch(() => undefined);
        await this.fs.unlink(this.temp).catch(() => undefined);
      }
    }
  }
}
