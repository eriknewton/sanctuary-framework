/** One bounded read shared by concurrent surfaces, with no settled projection cache. */
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "./evaluate.js";
import { buildLivenessSchedule, verdicts, type LivenessProjection } from "./browser-contract.js";
import { STATUS_READ_DEADLINE } from "./constants.js";
import { readAndEvaluateLivenessWithInput, nodeReaderFs, realDeadlineClock,
  type HostClockProvider, type ReaderFs, type ReaderFileHandle, type DeadlineClock } from "./read-status.js";

// No account has this uid, so custody refuses on hosts without getuid.
const NO_PROCESS_UID = -1;

export function project(envelope: LivenessEnvelope, input: LivenessInput, nowMs = Date.now()): LivenessProjection {
  // The exact evaluated input owns the timestamp; serving never reparses its presentation string.
  return { evaluated_at: envelope.evaluated_at, served_age_ms: Math.max(0, nowMs - input.nowMs),
    ...verdicts(envelope), schedule: buildLivenessSchedule(input) };
}

type Snapshot = { envelope: LivenessEnvelope; input: LivenessInput; projection?: LivenessProjection };
export class LivenessSurfaceSource {
  private flight: Promise<Snapshot> | undefined;
  private expired: Snapshot | undefined;
  private readonly now: () => number;
  constructor(private readonly options: {
    fortressPath: string;
    fortressId: string;
    host: HostClockProvider;
    operatorUid?: number;
    platform?: string;
    nowMs?: () => number;
    fs?: ReaderFs;
    deadline?: DeadlineClock;
  }) { this.now = options.nowMs ?? Date.now; }

  async readProjection(): Promise<LivenessProjection> {
    // Concurrent requests share one read; an expired read retains admission until all raw operations settle.
    const snapshot = this.expired ?? await (this.flight ?? this.start());
    // Schedule work belongs to the read; only served age varies between callers.
    snapshot.projection ??= project(snapshot.envelope, snapshot.input, snapshot.input.nowMs);
    return { ...snapshot.projection, served_age_ms: Math.max(0, this.now() - snapshot.input.nowMs) };
  }

  private start(): Promise<Snapshot> {
    const pending = new Set<Promise<unknown>>();
    const track = <T>(operation: Promise<T>): Promise<T> => {
      pending.add(operation);
      void operation.then(() => pending.delete(operation), () => pending.delete(operation));
      return operation;
    };
    const filesystem = this.options.fs ?? nodeReaderFs;
    const wrap = (handle: ReaderFileHandle): ReaderFileHandle => ({
      stat: () => track(handle.stat()),
      read: (...args) => track(handle.read(...args)),
      close: () => track(handle.close()),
    });
    const fs: ReaderFs = { open: (path, flags) => track(filesystem.open(path, flags)).then(wrap) };
    const host: HostClockProvider = { ...this.options.host, read: () => track(this.options.host.read()) };
    let finish!: (snapshot: Snapshot) => void;
    const flight = new Promise<Snapshot>(resolve => { finish = resolve; });
    this.flight = flight;
    const deadline = this.options.deadline ?? realDeadlineClock;
    const timer = deadline.after(STATUS_READ_DEADLINE, () => {
      // A released read cannot expire a later read or retain its admission.
      if (this.flight !== flight) return;
      this.expired = this.deadlineSnapshot();
      finish(this.expired);
    });
    const work = readAndEvaluateLivenessWithInput({ ...this.options, fs, host,
      operatorUid: this.options.operatorUid ?? process.getuid?.() ?? NO_PROCESS_UID,
      platform: this.options.platform ?? process.platform, nowMs: this.now });
    const release = () => {
      if (this.flight === flight) { this.flight = undefined; this.expired = undefined; }
    };
    void work.then(snapshot => {
      timer.cancel();
      if (snapshot.input.readDeadlineHit) this.expired ??= snapshot;
      if (pending.size === 0) {
        const result = this.expired ?? snapshot;
        release(); finish(result);
      } else {
        this.expired ??= this.deadlineSnapshot();
        finish(snapshot);
      }
    }, () => {
      timer.cancel();
      this.expired ??= this.deadlineSnapshot(); finish(this.expired);
      if (pending.size === 0) release();
    }).then(async () => {
      if (this.flight !== flight) return;
      // The shared reader can return before a raw open, read, close or host-clock operation settles.
      do {
        await Promise.allSettled([...pending]);
        // One event-loop turn lets late cleanup register its remaining operations.
        await new Promise<void>(resolve => setTimeout(resolve, 0));
      } while (pending.size > 0);
      release();
    }).catch(() => {
      // If settlement tracking fails, retain admission and fail closed for every caller.
      timer.cancel();
      this.expired ??= this.deadlineSnapshot();
      finish(this.expired);
    });
    return flight;
  }

  private deadlineSnapshot(): Snapshot {
    const platform = this.options.platform ?? process.platform;
    const input: LivenessInput = { nowMs: this.now(), platform, host: { ok: false },
      local: { fortress_id: this.options.fortressId, platform, operator_uid: this.options.operatorUid ?? process.getuid?.() ?? NO_PROCESS_UID },
      directory: { status: "ok" }, daemon: { status: "custody_invalid", cause: "read_deadline" },
      observer: { status: "custody_invalid", cause: "read_deadline" }, config: { status: "absent" }, readDeadlineHit: true };
    return { envelope: evaluateLiveness(input), input };
  }
}

// One owner retains at most one source; weak ownership bounds lifetime to the server/configuration.
const sources = new WeakMap<object, { path: string; source: LivenessSurfaceSource }>();
export function surfaceSourceFor(owner: object, fortressPath: string, fortressId: string, host: HostClockProvider): LivenessSurfaceSource {
  const existing = sources.get(owner);
  if (existing?.path === fortressPath) return existing.source;
  const source = new LivenessSurfaceSource({ fortressPath, fortressId, host,
    // An unwired fortress path supplies absence, never an ambient home-directory read.
    ...(fortressPath ? {} : { fs: { open: async () => { throw Object.assign(new Error("absent"), { code: "ENOENT" }); } } }),
  });
  sources.set(owner, { path: fortressPath, source });
  return source;
}
