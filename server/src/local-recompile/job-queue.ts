/**
 * The worker's job queue: at most WORKER_QUEUE_MAX jobs across seats and
 * WORKER_QUEUE_PER_SEAT_MAX for one seat, the running job included in both,
 * with one running at a time. It holds the parsed
 * request only (refs, instruction, kind, request id, seat), never record text.
 * A full queue or a full seat is an operator-side drop; the caller logs it.
 */
import { WORKER_QUEUE_MAX, WORKER_QUEUE_PER_SEAT_MAX, WORKER_RUNNING_MAX } from "./limits.js";
import type { JobDropCause } from "./oplog.js";
import type { LocalTaskJob } from "./worker-protocol.js";

export interface QueuedJob {
  job: LocalTaskJob;
  /** When the worker took the job; the job deadline counts from here. */
  queued_at: number;
}

export class LocalJobQueue {
  private readonly queued: QueuedJob[] = [];
  private readonly perSeat = new Map<string, number>();
  private running = 0;

  constructor(
    private readonly run: (entry: QueuedJob) => Promise<void>,
    private readonly now: () => number = Date.now,
  ) {}

  get depth(): number {
    return this.queued.length;
  }

  get runningCount(): number {
    return this.running;
  }

  /** A copy of the queued entries, for inspection only. */
  snapshot(): QueuedJob[] {
    return this.queued.map((entry) => ({ job: { ...entry.job, refs: entry.job.refs.map((ref) => ({ ...ref })) }, queued_at: entry.queued_at }));
  }

  /** Queue one job, or name why it is dropped. Constant work per call. */
  offer(job: LocalTaskJob): { queued: true; depth: number } | { queued: false; cause: JobDropCause } {
    if (this.queued.length + this.running >= WORKER_QUEUE_MAX) return { queued: false, cause: "queue_full" };
    const seatCount = this.perSeat.get(job.seat) ?? 0;
    if (seatCount >= WORKER_QUEUE_PER_SEAT_MAX) return { queued: false, cause: "seat_full" };
    this.perSeat.set(job.seat, seatCount + 1);
    this.queued.push({ job, queued_at: this.now() });
    const depth = this.queued.length;
    queueMicrotask(() => this.pump());
    return { queued: true, depth };
  }

  private pump(): void {
    while (this.running < WORKER_RUNNING_MAX && this.queued.length > 0) {
      const entry = this.queued.shift()!;
      this.running += 1;
      // The seat's share is released when its job finishes, not when it starts.
      this.run(entry)
        .catch(() => undefined)
        .finally(() => {
          const remaining = (this.perSeat.get(entry.job.seat) ?? 1) - 1;
          if (remaining <= 0) this.perSeat.delete(entry.job.seat);
          else this.perSeat.set(entry.job.seat, remaining);
          this.running -= 1;
          this.pump();
        });
    }
  }
}
