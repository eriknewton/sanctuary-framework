/**
 * Single-flight publication of one liveness record under `<fortress>/liveness/`.
 *
 * Each publish writes an exclusive same-directory temp file named for this
 * publisher instance, checks owner and mode on the descriptor, then renames it
 * over the target. The old target survives any failure, and a publisher keeps
 * at most one temp file.
 *
 * A publication claim, `<file>.publisher`, orders daemon instances. It carries
 * the instance, the boot identity and the instance-start uptime the recorder
 * fixed before its first publication. An instance claims the record on its
 * first publish unless the stored claim names a newer instance of the same boot:
 * an absent claim is created with a non-replacing link, so of two first claims
 * only one lands and the other re-reads it, and an older claim is replaced by
 * rename. Before every rename over the target the publisher re-reads the claim
 * and issues the rename with no await after that final check. A claim naming a
 * newer instance of the same boot retires the publisher (state_RETIRED): it
 * drops its waiting snapshot and never creates or commits anything again. A
 * claim that cannot be read and parsed grants nothing and deletes nothing; on a
 * first publish it refuses that snapshot, and at a commit check it also retires
 * the publisher. Claims are never deleted.
 *
 * Exclusion between concurrent daemons is not provided. A superseded instance's
 * rename issued after its final check can still land over its successor's
 * record, and two instances replacing the same older claim at once can each
 * pass one check before the newer re-claims; readers then refuse wall OK
 * because the stored record's instance differs from the one the observer
 * references.
 */
import { constants as fsConstants, promises as fsPromises } from "node:fs";
import { join } from "node:path";
import { IPC_DEADLINE, LABEL_BYTES, LIVENESS_DIRECTORY, STATUS_BYTES } from "./constants.js";

/** Owner-only directory mode: rwx for the operator, nothing for group or other. */
const DIRECTORY_MODE = 0o700;
/** Owner-only file mode: rw for the operator, nothing for group or other. */
const FILE_MODE = 0o600;
/** Any group or other permission bit. */
const GROUP_OTHER_BITS = 0o077;
/** Group or other write permission. */
const GROUP_OTHER_WRITE = 0o022;
const TEMP_SUFFIX = ".tmp";
/** The publication claim beside the target. */
const CLAIM_SUFFIX = ".publisher";
/** A claim read is a single small descriptor read; IPC_DEADLINE bounds it like any other local reader operation. */
const PUBLICATION_CLAIM_READ_DEADLINE = IPC_DEADLINE;
/**
 * Claim reads per establishment: one creation lost to a concurrent creator, one replacement of the older claim that
 * won, and the confirming read. Two instances that each supersede the other (only possible across boots, where each
 * takes its own boot as current) therefore cannot alternate without bound.
 */
const CLAIM_ROUNDS = 3;
/** The claim's characters: the instance's hex and a boot-session identifier's UUID text both fit. */
const CLAIM_LABEL = /^[A-Za-z0-9._-]+$/;

export interface PublicationClaim {
  instance: string;
  boot_id: string | null;
  instance_started_uptime_ms: number;
}

/** The one serialization of a claim; the parser accepts only bytes equal to it. */
export function serializePublicationClaim(claim: PublicationClaim): string {
  return `${JSON.stringify({ instance: claim.instance, boot_id: claim.boot_id, instance_started_uptime_ms: claim.instance_started_uptime_ms })}\n`;
}

const claimLabel = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= LABEL_BYTES && CLAIM_LABEL.test(value);

/** Strictly parse claim bytes: exactly the canonical serialization of a valid claim, else null. */
export function parsePublicationClaim(text: string): PublicationClaim | null {
  let value: unknown;
  try { value = JSON.parse(text); } catch { return null; }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (!claimLabel(o.instance) || !(o.boot_id === null || claimLabel(o.boot_id))) return null;
  const uptime = o.instance_started_uptime_ms;
  if (typeof uptime !== "number" || !Number.isSafeInteger(uptime) || uptime < 0) return null;
  const claim: PublicationClaim = { instance: o.instance, boot_id: o.boot_id, instance_started_uptime_ms: uptime };
  // Canonical bytes only: an unknown field, a reordered or padded claim, or a missing newline is not a claim.
  return serializePublicationClaim(claim) === text ? claim : null;
}

/** The largest claim the parser accepts: both labels at LABEL_BYTES and the largest safe uptime. */
export const PUBLICATION_CLAIM_BYTES = Buffer.byteLength(serializePublicationClaim({
  instance: "x".repeat(LABEL_BYTES), boot_id: "x".repeat(LABEL_BYTES), instance_started_uptime_ms: Number.MAX_SAFE_INTEGER,
}));

export interface PublisherFileHandle {
  stat(): Promise<{ uid: number; mode: number; isFile(): boolean }>;
  read(buffer: Uint8Array, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
  writeFile(data: string): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}
/** The filesystem surface the publisher uses, injectable so tests can pause or fail any step. */
export interface PublisherFs {
  mkdir(path: string, options: { mode: number }): Promise<unknown>;
  lstat(path: string): Promise<{ uid: number; mode: number; isDirectory(): boolean }>;
  open(path: string, flags: number, mode: number): Promise<PublisherFileHandle>;
  /** Non-replacing: fails with EEXIST when `to` exists. */
  link(from: string, to: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

export const nodePublisherFs: PublisherFs = {
  mkdir: (path, options) => fsPromises.mkdir(path, options),
  lstat: path => fsPromises.lstat(path),
  open: (path, flags, mode) => fsPromises.open(path, flags, mode),
  link: (from, to) => fsPromises.link(from, to),
  rename: (from, to) => fsPromises.rename(from, to),
  unlink: path => fsPromises.unlink(path),
};

/** Schedules the claim-read deadline; injectable so a test can fire it deterministically. */
export interface PublisherDeadlineClock {
  after(ms: number, fire: () => void): { cancel(): void };
}
const realPublisherDeadlineClock: PublisherDeadlineClock = {
  after(ms, fire) {
    const timer = setTimeout(fire, ms);
    timer.unref?.();
    return { cancel: () => clearTimeout(timer) };
  },
};

export interface LivenessPublisherOptions {
  fortressPath: string;
  fileName: string;
  /** Unique per daemon instance; it names this publisher's temp files and its claim. */
  instance: string;
  /** The daemon's boot identity, read once at start; null means this instance cannot order itself against another. */
  bootId: string | null;
  /** The daemon instance's start on the boot uptime clock; a later start on the same boot is a newer instance. */
  instanceStartedUptimeMs: number;
  operatorUid: number;
  fs?: PublisherFs;
  /** INTERNAL/TEST: the claim-read deadline clock. */
  claimReadDeadline?: PublisherDeadlineClock;
}

export class LivenessPublicationError extends Error {}

/** state_ACTIVE publishes; state_RETIRED is terminal and holds no snapshot. */
type PublisherState = "state_ACTIVE" | "state_RETIRED";
/** What a bounded claim read found. Anything not a valid claim or a clean absence is indeterminate. */
type ClaimRead = { status: "absent" } | { status: "claim"; claim: PublicationClaim } | { status: "indeterminate" };
/** This instance against the stored claim. */
type ClaimStanding = "standing_OWNER" | "standing_SUPERSEDES" | "standing_SUPERSEDED" | "standing_INDETERMINATE";

class ClaimReadDeadline extends Error {}

/** Single-flight publisher: one write in flight, and at most one newer record waiting behind it. */
export class LivenessRecordPublisher {
  private readonly fs: PublisherFs;
  private readonly directory: string;
  private readonly target: string;
  private readonly temp: string;
  private readonly claimPath: string;
  private readonly claimTemp: string;
  private readonly mine: PublicationClaim;
  private readonly claimDeadline: PublisherDeadlineClock;
  private state: PublisherState = "state_ACTIVE";
  private inFlight: Promise<void> | null = null;
  private waiting: string | null = null;
  private claimed = false;
  private published = 0;
  private failures = 0;

  constructor(private readonly options: LivenessPublisherOptions) {
    this.fs = options.fs ?? nodePublisherFs;
    this.directory = join(options.fortressPath, LIVENESS_DIRECTORY);
    this.target = join(this.directory, options.fileName);
    this.temp = this.tempFor(options.instance);
    this.claimPath = join(this.directory, `${options.fileName}${CLAIM_SUFFIX}`);
    this.claimTemp = this.claimTempFor(options.instance);
    // A boot identity the claim format cannot carry orders nothing, exactly like a failed boot read.
    this.mine = {
      instance: options.instance,
      boot_id: claimLabel(options.bootId) ? options.bootId : null,
      instance_started_uptime_ms: Math.max(0, Math.floor(options.instanceStartedUptimeMs)),
    };
    if (parsePublicationClaim(serializePublicationClaim(this.mine)) === null) {
      throw new LivenessPublicationError("liveness publisher instance is not a valid claim label");
    }
    this.claimDeadline = options.claimReadDeadline ?? realPublisherDeadlineClock;
  }

  /**
   * Retire this publisher: the waiting snapshot is discarded and no later
   * snapshot is created or committed. The recorder calls it at daemon stop, and
   * the publisher calls it on itself when the claim shows a newer instance or
   * cannot be read.
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

  private tempFor(instance: string): string {
    return join(this.directory, `${this.options.fileName}.${instance}${TEMP_SUFFIX}`);
  }

  private claimTempFor(instance: string): string {
    return join(this.directory, `${this.options.fileName}.${instance}${CLAIM_SUFFIX}${TEMP_SUFFIX}`);
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

  /** Every effect is preceded by this check after its last await, so a retirement during any awaited step stops the next effect. */
  private assertActive(): void {
    if (this.state !== "state_ACTIVE") throw new LivenessPublicationError("liveness publisher retired");
  }

  private refuse(reason: string): never {
    this.retire();
    throw new LivenessPublicationError(reason);
  }

  /** Create `path` exclusively with `text`, checking custody on the descriptor; nothing is left behind on failure. */
  private async writeExclusive(path: string, text: string): Promise<void> {
    this.assertActive();
    await this.fs.unlink(path).catch(() => undefined);
    this.assertActive();
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

  /**
   * Read the claim within PUBLICATION_CLAIM_READ_DEADLINE. A late result is discarded: the caller has already
   * treated the read as indeterminate, which grants no ownership and deletes nothing.
   */
  private async readClaim(): Promise<ClaimRead> {
    let fire: () => void = () => undefined;
    const deadline = new Promise<never>((_resolve, reject) => { fire = () => reject(new ClaimReadDeadline()); });
    deadline.catch(() => undefined);
    const timer = this.claimDeadline.after(PUBLICATION_CLAIM_READ_DEADLINE, () => fire());
    const work = this.readClaimOnce();
    work.catch(() => undefined);
    try {
      return await Promise.race([work, deadline]);
    } catch {
      return { status: "indeterminate" };
    } finally {
      timer.cancel();
    }
  }

  private async readClaimOnce(): Promise<ClaimRead> {
    let handle: PublisherFileHandle;
    try {
      // O_NONBLOCK keeps a FIFO from blocking the open; O_NOFOLLOW refuses a substituted link.
      handle = await this.fs.open(this.claimPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK, FILE_MODE);
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT" ? { status: "absent" } : { status: "indeterminate" };
    }
    try {
      const info = await handle.stat();
      // The descriptor must be a regular operator-owned owner-only file before any byte is read.
      if (!info.isFile() || info.uid !== this.options.operatorUid || (info.mode & GROUP_OTHER_BITS) !== 0) return { status: "indeterminate" };
      // At most PUBLICATION_CLAIM_BYTES + 1 bytes are ever read; one byte over the cap proves the claim oversized.
      const buffer = new Uint8Array(PUBLICATION_CLAIM_BYTES + 1);
      let total = 0;
      while (total < buffer.length) {
        const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      if (total > PUBLICATION_CLAIM_BYTES) return { status: "indeterminate" };
      let text: string;
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total)); } catch { return { status: "indeterminate" }; }
      const claim = parsePublicationClaim(text);
      return claim === null ? { status: "indeterminate" } : { status: "claim", claim };
    } catch {
      return { status: "indeterminate" };
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  /**
   * Order this instance against a stored claim. The same boot orders by instance-start uptime; another boot loses to
   * this one, which is running on the current boot; a claim with no boot recorded untrusted time and loses to an
   * instance that has a boot. Equal starts of distinct instances, or this instance lacking a boot, cannot be ordered.
   */
  private standing(read: ClaimRead): ClaimStanding {
    if (read.status === "absent") return "standing_SUPERSEDES";
    if (read.status === "indeterminate") return "standing_INDETERMINATE";
    const other = read.claim;
    const mine = this.mine;
    if (other.instance === mine.instance) {
      return other.boot_id === mine.boot_id && other.instance_started_uptime_ms === mine.instance_started_uptime_ms
        ? "standing_OWNER" : "standing_INDETERMINATE";
    }
    if (mine.boot_id === null) return "standing_INDETERMINATE";
    if (other.boot_id === null || other.boot_id !== mine.boot_id) return "standing_SUPERSEDES";
    if (other.instance_started_uptime_ms < mine.instance_started_uptime_ms) return "standing_SUPERSEDES";
    if (other.instance_started_uptime_ms > mine.instance_started_uptime_ms) return "standing_SUPERSEDED";
    return "standing_INDETERMINATE";
  }

  /**
   * Write this instance's claim over a superseded one. An absent claim is created by a non-replacing link, so a
   * concurrent creator that landed first is kept and re-read; an older claim is replaced, after removing only that
   * instance's temps, which are never trusted or renamed.
   */
  private async writeClaim(superseded: ClaimRead): Promise<void> {
    if (superseded.status === "claim") {
      for (const path of [this.tempFor(superseded.claim.instance), this.claimTempFor(superseded.claim.instance)]) {
        this.assertActive();
        await this.fs.unlink(path).catch(() => undefined);
      }
    }
    await this.writeExclusive(this.claimTemp, serializePublicationClaim(this.mine));
    try {
      this.assertActive();
      if (superseded.status === "claim") {
        await this.fs.rename(this.claimTemp, this.claimPath);
        return;
      }
      try {
        await this.fs.link(this.claimTemp, this.claimPath);
      } catch (error) {
        // Another instance created the claim first; the caller re-reads and orders against it.
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    } finally {
      // Only this instance's own claim temp is removed; after a rename it is already gone.
      await this.fs.unlink(this.claimTemp).catch(() => undefined);
    }
  }

  /** Establish this instance as the claim's owner on its first publish, or refuse; an unorderable claim is retried next tick. */
  private async establishClaim(): Promise<void> {
    for (let round = 1; ; round++) {
      this.assertActive();
      const read = await this.readClaim();
      this.assertActive();
      const standing = this.standing(read);
      if (standing === "standing_OWNER") return;
      if (standing === "standing_SUPERSEDED") this.refuse("liveness publisher superseded");
      // An unreadable or unorderable claim refuses this snapshot, grants nothing and deletes nothing.
      if (standing === "standing_INDETERMINATE") throw new LivenessPublicationError("liveness publication claim indeterminate");
      if (round >= CLAIM_ROUNDS) throw new LivenessPublicationError("liveness publication claim contested");
      await this.writeClaim(read);
    }
  }

  private async writeOnce(text: string): Promise<void> {
    this.assertActive();
    await this.ensureDirectory();
    if (!this.claimed) {
      await this.establishClaim();
      this.claimed = true;
    }
    let committed = false;
    try {
      await this.writeExclusive(this.temp, text);
      for (let round = 1; ; round++) {
        this.assertActive();
        const read = await this.readClaim();
        const standing = this.standing(read);
        if (standing === "standing_OWNER") {
          // The final check: ownership was read into a local and retirement is settled here; the rename is issued with no await between.
          this.assertActive();
          await this.fs.rename(this.temp, this.target);
          committed = true;
          return;
        }
        // A newer instance's claim, or a claim that cannot be read or ordered, ends this publisher.
        if (standing === "standing_SUPERSEDED") this.refuse("liveness publisher superseded");
        if (standing === "standing_INDETERMINATE") this.refuse("liveness publication claim indeterminate");
        if (round >= CLAIM_ROUNDS) throw new LivenessPublicationError("liveness publication claim contested");
        await this.writeClaim(read);
      }
    } finally {
      if (!committed) await this.fs.unlink(this.temp).catch(() => undefined);
    }
  }
}
