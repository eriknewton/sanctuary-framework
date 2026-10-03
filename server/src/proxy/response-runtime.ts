import { randomUUID } from "node:crypto";
import { RESPONSE_LIMITS as L } from "./response-limits.js";

interface RecordState { observed: boolean; active: number; touched: number }

/** A reservation outlives cancellation until every underlying operation settles. */
export class ResponseReservation {
  readonly abort = new AbortController();
  private pending = 0;
  private finished = false;
  private released = false;
  private fenced = false;
  private resolveDrained!: () => void;
  readonly drained = new Promise<void>(resolve => { this.resolveDrained = resolve; });
  constructor(private readonly release: () => void, private readonly onObserve: () => void) {}
  observe(): void { this.onObserve(); }
  assertLive(): void {
    if (this.abort.signal.aborted || this.finished) throw new Error("Response cancelled");
  }
  cancel(): void { this.abort.abort(); }
  /** Uncertain termination retains capacity permanently rather than admitting replacement work. */
  fence(): void { this.fenced = true; this.cancel(); this.maybeRelease(); }
  track<T>(work: Promise<T>): Promise<T> {
    this.pending++;
    // Rejection is observed even when cancellation has already returned the generic denial.
    void work.then(() => this.settled(), () => this.settled());
    return work;
  }
  async wait<T>(work: Promise<T>): Promise<T> {
    this.track(work);
    this.assertLive();
    let cancel!: () => void;
    const cancelled = new Promise<never>((_, reject) => {
      cancel = () => reject(new Error("Response cancelled"));
      this.abort.signal.addEventListener("abort", cancel, { once: true });
    });
    try {
      const result = await Promise.race([work, cancelled]);
      this.assertLive();
      return result;
    } finally { this.abort.signal.removeEventListener("abort", cancel); }
  }
  finish(): void { this.finished = true; this.maybeRelease(); }
  private settled(): void { this.pending--; this.maybeRelease(); }
  private maybeRelease(): void {
    // A deadline ends caller admission, not the underlying work's ownership of capacity.
    if (!this.released && this.finished && this.pending === 0) {
      this.released = true;
      // A fenced worker cannot regain capacity, but must not hold persistence or key cleanup hostage.
      if (!this.fenced) this.release();
      this.resolveDrained();
    }
  }
}

/** Host-created lifetime handle; no request identity can reset taint or mint capacity. */
export class ResponseSession {
  readonly id = randomUUID();
  private stopped = false;
  private readonly leases = new Set<ResponseReservation>();
  constructor(private readonly controller: ResponseController) { controller.register(this.id); }
  get exposure(): { state: "state_TAINTED"; tainted: true; observed: boolean | "unknown" } {
    return { state: "state_TAINTED", tainted: true, observed: this.controller.observed(this.id) };
  }
  reserve(): ResponseReservation {
    if (this.stopped) throw new Error("Response admission stopped");
    const done = this.controller.admit(this.id);
    const lease = new ResponseReservation(() => {
      done(); this.leases.delete(lease);
    }, () => this.controller.observe(this.id));
    this.leases.add(lease);
    return lease;
  }
  stop(): void {
    this.stopped = true;
    for (const lease of this.leases) lease.cancel();
  }
  async close(): Promise<void> {
    this.stop();
    await Promise.all([...this.leases].map(lease => lease.drained));
    this.controller.drop(this.id);
  }
}

/** One shared process controller; inactive records expire, active records never evict. */
export class ResponseController {
  private readonly records = new Map<string, RecordState>();
  private readonly unknown: RecordState = { observed: false, active: 0, touched: 0 };
  private active = 0;
  constructor(private readonly now: () => number = () => performance.now()) {}
  register(id: string): void {
    this.prune();
    if (this.records.size < L.RUNTIME_SLOTS) {
      this.records.set(id, { observed: false, active: 0, touched: this.now() });
    }
  }
  observed(id: string): boolean | "unknown" { this.prune(); return this.records.get(id)?.observed ?? "unknown"; }
  observe(id: string): void {
    const record = this.records.get(id);
    if (record) { record.observed = true; record.touched = this.now(); }
  }
  admit(id: string): () => void {
    this.prune();
    const record = this.records.get(id) ?? this.unknown;
    // Overflow sessions share one quota; allocating another unknown record would bypass the process bound.
    if (record.active >= L.ACTIVE_PER_SESSION || this.active >= L.ACTIVE_PER_PROCESS) {
      throw new Error("Response admission capacity exceeded");
    }
    record.active++; this.active++;
    return () => { record.active--; this.active--; record.touched = this.now(); };
  }
  drop(id: string): void { if (!this.records.get(id)?.active) this.records.delete(id); }
  snapshot(): { active: number; records: number; unknownActive: number } {
    this.prune();
    return { active: this.active, records: this.records.size, unknownActive: this.unknown.active };
  }
  private prune(): void {
    for (const [id, record] of this.records) {
      if (record.active === 0 && this.now() - record.touched >= L.IDLE_MS) this.records.delete(id);
    }
  }
}
// ESM/CJS copies in the same host must share capacity; module caching alone is not process isolation.
const RUNTIME_KEY = Symbol.for("sanctuary.content-ingress.runtime");
const runtimeRegistry = globalThis as unknown as Record<symbol, ResponseController | undefined>;
export const processResponseController = runtimeRegistry[RUNTIME_KEY] ??= new ResponseController();
