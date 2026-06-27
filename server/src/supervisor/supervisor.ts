/**
 * Phase S1 — Supervisor subsystem (split-process, Tier A).
 *
 * The supervisor owns the per-agent child-process lifecycle: launch, monitor,
 * restart-with-backoff, and HONEST health (enforcement-evidenced, not
 * pid-liveness alone — review/dashboard H3). It holds the TRANSIENT master key
 * only in memory and only while a supervised agent is up (Tier A: survives an
 * agent crash via restart; does NOT survive a host reboot / supervisor restart
 * — those park agents `needs-unlock` until the operator re-unlocks).
 *
 * Split-process boundary: this code runs in the small supervisor process, NOT
 * the dashboard. It never touches the browser-facing HTTP surface. It receives
 * protect/unprotect/status requests over the authenticated local socket
 * (protocol.ts) and drives an injectable {@link AgentLauncher} so the state
 * machine is fully unit-testable without spawning real processes.
 *
 * The two launch-time gates the brief makes load-bearing:
 *   - rotation safety (M3): refuse to launch while a master rotation journal
 *     exists — checked via {@link SupervisorDeps.isRotationInProgress};
 *   - idempotency at the resource level (M2): "protect an already-supervised
 *     agent" is a no-op acknowledgement, never a double-launch.
 */

import type {
  SupervisedAgentState,
  SupervisedAgentStatus,
  SupervisorErrorReason,
} from "./protocol.js";

/** Thrown internally when a launch is refused because a rotation is in flight. */
class RotationRefusedError extends Error {
  constructor() {
    super("master rotation in progress; refusing to launch supervised agent");
    this.name = "RotationRefusedError";
  }
}

/** Handle to a launched child the supervisor can monitor and stop. */
export interface LaunchedChild {
  /** Stop the child (SIGTERM → SIGKILL on a grace timeout). Idempotent. */
  stop(): Promise<void>;
  /**
   * Register the exit callback. Called once when the child exits for any
   * reason (clean, crash, killed). The supervisor uses this to drive restart.
   */
  onExit(cb: (info: { code: number | null; signal: string | null }) => void): void;
}

/** Spec the supervisor launches a child from. */
export interface SupervisionSpec {
  agent_id: string;
  harness: string;
  config_path: string;
  /**
   * The transient master key (raw bytes). The launcher hands it to the child's
   * enforcement chain. Residency (honest — codex S1): on a SUCCESSFUL launch the
   * supervisor RETAINS this raw key in `entry.spec` for the agent lifetime to
   * support restart-on-crash under Tier A (the resident-master window is bounded
   * to the agent lifetime by design — review H2); it is zeroed on
   * unprotect/shutdown/burst-park. On a FAILED/refused/timed-out/superseded
   * launch it is zeroed immediately. It is NOT zeroed "after a successful
   * launch" — that would defeat crash-restart.
   */
  transientKey: Uint8Array;
}

/** Launches a supervised child. Injectable so the state machine is testable. */
export interface AgentLauncher {
  launch(spec: SupervisionSpec): Promise<LaunchedChild>;
}

/** Restart-backoff policy. Defaults give up after a rapid-failure burst. */
export interface RestartPolicy {
  /** Base backoff (ms) before the first restart. */
  baseDelayMs: number;
  /** Cap on the exponential backoff (ms). */
  maxDelayMs: number;
  /**
   * After this many restarts inside `burstWindowMs`, stop hammering and park
   * the agent `crashed` (surface it; do not loop — design §4.1).
   */
  maxRestartsInBurst: number;
  /** Window over which `maxRestartsInBurst` is counted (ms). */
  burstWindowMs: number;
}

export const DEFAULT_RESTART_POLICY: RestartPolicy = {
  baseDelayMs: 500,
  maxDelayMs: 30_000,
  maxRestartsInBurst: 5,
  burstWindowMs: 60_000,
};

export interface SupervisorDeps {
  launcher: AgentLauncher;
  /** Refuse-to-launch gate: true ⇒ a master rotation is in flight (M3). */
  isRotationInProgress: () => Promise<boolean>;
  /**
   * Enforcement-evidence freshness check (H3). Returns the ISO8601 timestamp
   * of the most recent allow/deny audit evidence for this agent, or null if
   * there is none. The supervisor renders `protected` (green) ONLY when this
   * is fresh; process-alive-without-evidence is `degraded`, never green.
   */
  latestEnforcementAt: (agentId: string) => string | null;
  /** Freshness window (ms) for enforcement evidence. */
  enforcementFreshnessMs?: number;
  restartPolicy?: RestartPolicy;
  /**
   * Bound (ms) on a single protect's rotation-check + launch. If a dependency
   * hangs (a wedged storage read, a stuck spawn), the protect fails closed
   * with `unavailable` and the agent is dropped (key zeroed) rather than
   * pinning the key inside an unresolved in-flight promise forever (codex
   * R2-M1). Defaults to 30s.
   */
  launchTimeoutMs?: number;
  /** Injectable clock (ms). */
  now?: () => number;
  /** Injectable timer (returns a cancel fn). Defaults to setTimeout. */
  schedule?: (fn: () => void, delayMs: number) => () => void;
  /** Structured log sink; defaults to no-op (never logs the transient key). */
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

/** Default enforcement-evidence freshness window: 90s. */
export const DEFAULT_ENFORCEMENT_FRESHNESS_MS = 90_000;

/** Default bound on a single protect's rotation-check + launch: 30s. */
export const DEFAULT_LAUNCH_TIMEOUT_MS = 30_000;

interface SupervisedEntry {
  spec: SupervisionSpec;
  child: LaunchedChild | null;
  /** Coarse lifecycle state (the wire-level state derives health on read). */
  base: "protecting" | "running" | "crashed" | "needs-unlock" | "stopping" | "stopped";
  restarts: number;
  /** Timestamps (ms) of recent restarts, for burst detection. */
  restartTimes: number[];
  launchId: string;
  cancelTimer: (() => void) | null;
  /**
   * Monotonic launch generation (codex R4). Every launch attempt captures the
   * generation at its start; a launch that resolves only attaches its child if
   * the generation is UNCHANGED. Any terminal/park/timeout/drop/re-protect
   * bumps it, so a late-resolving launch from a superseded attempt can never
   * attach an orphan child — regardless of the entry's current `base`.
   */
  generation: number;
}

/** Outcome of a protect request handled by the supervisor. */
export type ProtectResult =
  | { ok: true; kind: "protecting"; agent_id: string; launch_id: string }
  | { ok: true; kind: "already-protected"; agent_id: string }
  | { ok: false; reason: SupervisorErrorReason };

export class Supervisor {
  private readonly deps: Required<
    Omit<SupervisorDeps, "log">
  > & { log: NonNullable<SupervisorDeps["log"]> };
  private readonly agents = new Map<string, SupervisedEntry>();
  private launchCounter = 0;
  /**
   * Per-agent in-flight protect reservations (codex H1). A protect that has
   * passed the "already up" check but not yet settled holds its promise here
   * so a CONCURRENT duplicate for the same agent_id awaits the SAME result
   * instead of racing into a second launch. Synchronously reserved before the
   * first await, so two concurrent calls can never both observe "no entry".
   */
  private readonly inflightProtect = new Map<string, Promise<ProtectResult>>();
  /** Set during shutdown so a child exit cannot schedule a restart (R5-L1). */
  private shuttingDown = false;

  constructor(deps: SupervisorDeps) {
    this.deps = {
      launcher: deps.launcher,
      isRotationInProgress: deps.isRotationInProgress,
      latestEnforcementAt: deps.latestEnforcementAt,
      enforcementFreshnessMs: deps.enforcementFreshnessMs ?? DEFAULT_ENFORCEMENT_FRESHNESS_MS,
      restartPolicy: deps.restartPolicy ?? DEFAULT_RESTART_POLICY,
      launchTimeoutMs: deps.launchTimeoutMs ?? DEFAULT_LAUNCH_TIMEOUT_MS,
      now: deps.now ?? Date.now,
      schedule:
        deps.schedule ??
        ((fn, delayMs): (() => void) => {
          const t = setTimeout(fn, delayMs);
          // Do not keep the event loop alive solely for a restart timer.
          if (typeof t.unref === "function") t.unref();
          return () => clearTimeout(t);
        }),
      log: deps.log ?? ((): void => {}),
    };
  }

  /**
   * Handle a protect request. Resource-level idempotent (M2): protecting an
   * agent that is already supervised (protecting/running) is a no-op
   * acknowledgement — NEVER a second launch. A crashed/stopped agent under the
   * same id re-launches. Refuses with `rotation_in_progress` if a master
   * rotation is in flight (M3).
   */
  async protect(spec: SupervisionSpec): Promise<ProtectResult> {
    // ORDER MATTERS (codex S1 R7-H1): the in-flight reservation check MUST come
    // BEFORE the "already protecting/running" resource-level no-op. `runProtect`
    // synchronously sets entry.base = "protecting" before its first await, so a
    // concurrent duplicate that checked the entry FIRST would see "protecting"
    // and return a premature `already-protected` success — WITHOUT awaiting the
    // real launch outcome. If that launch then failed, the duplicate would have
    // received a FALSE success. Coalescing onto the in-flight promise first
    // makes the duplicate inherit the winner's ACTUAL result (success OR
    // failure). Both checks are reached synchronously (no await) before any
    // entry mutation, so two concurrent protects can never both reach a launch.
    const inflight = this.inflightProtect.get(spec.agent_id);
    if (inflight) {
      // A launch is in flight for this agent. The duplicate did not launch; its
      // key copy is zeroed (the winner's spec carries the live key). It awaits
      // and returns the winner's real outcome — a failed launch propagates as a
      // failure here too (no false success), a successful one as the no-op ack.
      this.zero(spec.transientKey);
      const result = await inflight;
      if (result.ok) return { ok: true, kind: "already-protected", agent_id: spec.agent_id };
      return result;
    }

    // No launch in flight. Resource-level idempotent no-op for an agent that is
    // genuinely already up (M2): a SEPARATE, later protect of a running/
    // protecting agent (whose prior launch fully settled) is a no-op ack, never
    // a second launch. Checked synchronously so it cannot interleave.
    const existing = this.agents.get(spec.agent_id);
    if (existing && (existing.base === "protecting" || existing.base === "running")) {
      this.zero(spec.transientKey);
      return { ok: true, kind: "already-protected", agent_id: spec.agent_id };
    }

    // Reserve the in-flight slot in the SAME synchronous turn as runProtect's
    // body (codex S1 R9). Precise mechanics (honest — do not over-claim): the
    // thunk `(async () => this.runProtect(spec))()` invokes runProtect's
    // synchronous prefix (which sets entry.base="protecting" + agents.set) up to
    // its first await, THEN the next line registers the promise. Both the entry
    // mutation AND the inflight reservation therefore become visible within one
    // uninterrupted synchronous turn, before any await yields control — so a
    // concurrent protect() for the same agent_id cannot interleave until BOTH
    // are set, and (per the ordered checks above) it coalesces onto the inflight
    // promise. The concurrent-duplicate-fails test pins the concrete invariant.
    const promise = (async () => this.runProtect(spec))();
    this.inflightProtect.set(spec.agent_id, promise);
    try {
      return await promise;
    } finally {
      this.inflightProtect.delete(spec.agent_id);
    }
  }

  /** The actual protect body; runs at most once per agent_id at a time. */
  private async runProtect(spec: SupervisionSpec): Promise<ProtectResult> {
    const launchId = `launch-${++this.launchCounter}-${this.deps.now()}`;
    const entry: SupervisedEntry = this.agents.get(spec.agent_id) ?? {
      spec,
      child: null,
      base: "protecting",
      restarts: 0,
      restartTimes: [],
      launchId,
      cancelTimer: null,
      generation: 0,
    };
    // Re-protecting a crashed/stopped agent: refresh the spec + reset state +
    // bump the generation so any superseded in-flight launch cannot attach.
    entry.spec = spec;
    entry.base = "protecting";
    entry.launchId = launchId;
    entry.restarts = 0;
    entry.restartTimes = [];
    entry.generation++;
    this.agents.set(spec.agent_id, entry);
    const generation = entry.generation;

    try {
      // guardedLaunch re-checks rotation immediately before spawn (codex H3
      // TOCTOU narrowing + the M3 guard). A rotation that began after the
      // socket request still refuses here, fail-closed. Bounded by
      // launchTimeoutMs so a wedged dependency cannot pin the key inside an
      // unresolved in-flight promise forever (codex R2-M1). The generation
      // token guards against a late-resolving launch attaching after timeout.
      await this.withTimeout(this.guardedLaunch(entry, generation));
    } catch (err) {
      if (err instanceof RotationRefusedError) {
        // M3: a rotation is in flight. Do NOT keep the key resident — drop the
        // entry entirely so a retry must present a fresh authenticated key.
        this.dropEntry(spec.agent_id);
        this.deps.log("protect.refused.rotation", { agent_id: spec.agent_id });
        return { ok: false, reason: "rotation_in_progress" };
      }
      // Codex H4: initial launch failed and no child is running. Zero the key
      // and drop the entry — a retry delivers a fresh transient key anyway, so
      // never extend master-key heap residency on a failed launch.
      this.dropEntry(spec.agent_id);
      this.deps.log("protect.launch_failed", {
        agent_id: spec.agent_id,
        error: err instanceof Error ? err.message : String(err),
      });
      return { ok: false, reason: "unavailable" };
    }

    return { ok: true, kind: "protecting", agent_id: spec.agent_id, launch_id: launchId };
  }

  /**
   * Stop supervising an agent: stop the child and remove the spec so it is not
   * restarted. Idempotent. Returns not_found for an unknown agent.
   */
  async unprotect(agentId: string): Promise<{ ok: true } | { ok: false; reason: "not_found" }> {
    const entry = this.agents.get(agentId);
    if (!entry) return { ok: false, reason: "not_found" };
    entry.base = "stopping";
    if (entry.cancelTimer) {
      entry.cancelTimer();
      entry.cancelTimer = null;
    }
    if (entry.child) {
      await entry.child.stop();
    }
    entry.base = "stopped";
    this.zero(entry.spec.transientKey);
    this.agents.delete(agentId);
    return { ok: true };
  }

  /** Snapshot the status of one agent or all (enforcement-evidenced health). */
  status(agentId?: string): SupervisedAgentStatus[] {
    const out: SupervisedAgentStatus[] = [];
    for (const [id, entry] of this.agents) {
      if (agentId !== undefined && id !== agentId) continue;
      out.push(this.statusOf(entry));
    }
    return out;
  }

  /** Number of agents whose health is enforcement-evidenced green right now. */
  protectedCount(): number {
    let n = 0;
    for (const entry of this.agents.values()) {
      if (this.statusOf(entry).state === "protected") n++;
    }
    return n;
  }

  /**
   * Reboot/supervisor-restart entry point (Tier A): the supervisor came back
   * up but holds no master, so every previously-supervised spec is parked
   * `needs-unlock` until the operator re-unlocks. Distinct from `crashed` so
   * the dashboard can say "waiting for you" not "broken" (design §4.3).
   */
  parkAllNeedsUnlock(specs: Array<Pick<SupervisionSpec, "agent_id" | "harness" | "config_path">>): void {
    for (const s of specs) {
      this.agents.set(s.agent_id, {
        spec: { agent_id: s.agent_id, harness: s.harness, config_path: s.config_path, transientKey: new Uint8Array(0) },
        child: null,
        base: "needs-unlock",
        restarts: 0,
        restartTimes: [],
        launchId: "",
        cancelTimer: null,
        generation: 0,
      });
    }
  }

  /** Stop everything (process shutdown). Zeroes all resident keys. */
  async shutdown(): Promise<void> {
    // R5-L1: mark shutting down + each entry stopping BEFORE stopping children
    // so an exit callback during teardown cannot schedule a restart spawn.
    this.shuttingDown = true;
    const ids = [...this.agents.keys()];
    for (const id of ids) {
      const entry = this.agents.get(id);
      if (!entry) continue;
      entry.base = "stopping";
      if (entry.cancelTimer) {
        entry.cancelTimer();
        entry.cancelTimer = null;
      }
      if (entry.child) await entry.child.stop();
      this.zero(entry.spec.transientKey);
    }
    this.agents.clear();
  }

  // ── internals ─────────────────────────────────────────────────────────

  /**
   * The ONLY path that spawns a child. EVERY launch (initial + crash-restart)
   * goes through here so the rotation guard cannot be bypassed (codex H2/H3):
   * re-check `isRotationInProgress` immediately before the spawn and refuse if
   * a rotation began since the request arrived. This narrows the TOCTOU window
   * to the spawn itself; the residual (a rotation journaled in the microseconds
   * between this check and `launcher.launch`) is the drain→re-establish
   * handshake the design defers to a follow-on (Supervised_Daemon_Lifecycle
   * §M3 (b)); for S1 the operator stops supervised agents before rotating, and
   * `rotateMaster`'s own preflight refuses while agents hold the master.
   */
  private async guardedLaunch(entry: SupervisedEntry, generation: number): Promise<void> {
    if (await this.deps.isRotationInProgress()) {
      throw new RotationRefusedError();
    }
    // Capture THIS attempt's spec/key before the await: if a re-protect swaps
    // entry.spec while this launch is in flight, a stale resolution must zero
    // only ITS OWN key, never the fresh re-protected one (codex R5-M1).
    const attemptSpec = entry.spec;
    const child = await this.deps.launcher.launch(attemptSpec);
    // Codex R3-H3 / R4: a launch that resolves AFTER its attempt was superseded
    // (protect timed out, unprotect/shutdown ran, a restart-timeout parked it,
    // or a new protect started a fresh attempt) must NOT attach an orphan child
    // that escapes status/unprotect/rotation handling and holds the key. The
    // generation token is authoritative: attach ONLY if this entry is still the
    // live registered one AND its generation is unchanged since this attempt
    // began. Any park/timeout/drop bumps the generation, so `crashed`/`needs-
    // unlock`/replaced entries all reject the late child here.
    if (
      this.agents.get(attemptSpec.agent_id) !== entry ||
      entry.generation !== generation
    ) {
      void child.stop();
      // Zero THIS attempt's key, not whatever entry.spec now points at.
      this.zero(attemptSpec.transientKey);
      this.deps.log("child.launched_after_supersede", { agent_id: attemptSpec.agent_id });
      return;
    }
    entry.child = child;
    entry.base = "running";
    child.onExit((info) => this.onChildExit(entry, info));
    this.deps.log("child.launched", { agent_id: entry.spec.agent_id, launch_id: entry.launchId });
  }

  /**
   * Race a launch against the configured bound. On timeout, reject with a
   * plain Error (NOT a RotationRefusedError) so runProtect drops the entry and
   * zeroes the key — a hung dependency can never pin the key in an unresolved
   * promise (codex R2-M1). The underlying launch promise is left to settle on
   * its own; the agent is already dropped so a late success has no entry to
   * attach to and is a harmless no-op.
   */
  private withTimeout<T>(promise: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      // Use a real timer (unref'd), NOT the injectable restart `schedule` — the
      // restart scheduler is stubbed in tests to fire synchronously, which is
      // correct for backoff but would make the timeout fire instantly. The
      // timeout is wall-clock by nature.
      const timer = setTimeout(() => {
        reject(new Error("supervised launch timed out"));
      }, this.deps.launchTimeoutMs);
      if (typeof timer.unref === "function") timer.unref();
      promise.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e instanceof Error ? e : new Error(String(e)));
        },
      );
    });
  }

  /** Zero the resident key and remove an agent from the registry. */
  private dropEntry(agentId: string): void {
    const entry = this.agents.get(agentId);
    if (!entry) return;
    if (entry.cancelTimer) {
      entry.cancelTimer();
      entry.cancelTimer = null;
    }
    this.zero(entry.spec.transientKey);
    this.agents.delete(agentId);
  }

  private onChildExit(
    entry: SupervisedEntry,
    info: { code: number | null; signal: string | null },
  ): void {
    // An exit during an operator-initiated stop or process shutdown is
    // expected — do not restart (R5-L1).
    if (this.shuttingDown || entry.base === "stopping" || entry.base === "stopped") return;
    entry.child = null;

    const now = this.deps.now();
    const policy = this.deps.restartPolicy;
    // Drop restart timestamps outside the burst window, then record this one.
    entry.restartTimes = entry.restartTimes.filter((t) => now - t <= policy.burstWindowMs);
    if (entry.restartTimes.length >= policy.maxRestartsInBurst) {
      // Codex R2-H1: parked crashed with no child running and no restart
      // pending ⇒ the transient key must NOT stay resident. Zero it; the entry
      // survives for status only. A later re-protect supplies a fresh key.
      // Bump the generation so any still-pending launch cannot attach (R4).
      entry.generation++;
      this.zero(entry.spec.transientKey);
      entry.base = "crashed";
      this.deps.log("child.crashed.burst", {
        agent_id: entry.spec.agent_id,
        restarts: entry.restarts,
        code: info.code,
        signal: info.signal,
      });
      return;
    }
    entry.restartTimes.push(now);
    entry.restarts++;

    const attempt = entry.restartTimes.length;
    const delay = Math.min(
      policy.baseDelayMs * 2 ** (attempt - 1),
      policy.maxDelayMs,
    );
    entry.base = "protecting"; // restarting → coming back up
    this.deps.log("child.restarting", {
      agent_id: entry.spec.agent_id,
      attempt,
      delay_ms: delay,
    });
    entry.cancelTimer = this.deps.schedule(() => {
      entry.cancelTimer = null;
      // New launch attempt ⇒ a fresh generation. guardedLaunch attaches only if
      // the generation is still this one; if a timeout/park below bumps it, the
      // late launch rejects + stops its orphan child (R4).
      const generation = ++entry.generation;
      // Codex H2: the restart path goes through guardedLaunch, so a crash that
      // happens AFTER a rotation started parks the agent needs-unlock instead
      // of relaunching under a retired master (split-state). Codex R3-H2: the
      // restart launch is bounded by the SAME timeout as the initial launch,
      // so a hung dependency on the restart path cannot leave the key resident
      // in `protecting` forever — it parks crashed (key zeroed) on timeout.
      void this.withTimeout(this.guardedLaunch(entry, generation)).catch((err) => {
        // Park: bump the generation so the (possibly still-pending) launch this
        // attempt started cannot attach a late orphan child after we parked.
        entry.generation++;
        if (err instanceof RotationRefusedError) {
          entry.base = "needs-unlock";
          this.zero(entry.spec.transientKey);
          this.deps.log("child.restart_parked.rotation", { agent_id: entry.spec.agent_id });
          return;
        }
        // Codex R2-H1 / R3-H2: restart failed or timed out, no child running ⇒
        // zero the resident key (no extended heap residency); the entry stays
        // for status only.
        this.zero(entry.spec.transientKey);
        entry.base = "crashed";
        this.deps.log("child.restart_failed", {
          agent_id: entry.spec.agent_id,
          error: err instanceof Error ? err.message : String(err),
        });
      });
    }, delay);
  }

  private statusOf(entry: SupervisedEntry): SupervisedAgentStatus {
    const lastEnf = this.deps.latestEnforcementAt(entry.spec.agent_id);
    const state = this.deriveState(entry, lastEnf);
    return {
      agent_id: entry.spec.agent_id,
      harness: entry.spec.harness,
      state,
      restarts: entry.restarts,
      last_enforcement_at: lastEnf,
    };
  }

  /**
   * Derive the wire-level state. The H3 rule lives here: a `running` child is
   * `protected` (green) ONLY when there is fresh enforcement evidence;
   * otherwise it is `degraded` (process alive but unverified). The supervisor
   * never reports `protected` on pid-liveness alone.
   */
  private deriveState(entry: SupervisedEntry, lastEnforcementAt: string | null): SupervisedAgentState {
    switch (entry.base) {
      case "running": {
        if (lastEnforcementAt === null) return "degraded";
        const age = this.deps.now() - Date.parse(lastEnforcementAt);
        if (!Number.isFinite(age) || age > this.deps.enforcementFreshnessMs) return "degraded";
        return "protected";
      }
      case "protecting":
        return "protecting";
      case "crashed":
        return "crashed";
      case "needs-unlock":
        return "needs-unlock";
      case "stopping":
        return "stopping";
      case "stopped":
        return "stopped";
    }
  }

  private zero(buf: Uint8Array): void {
    buf.fill(0);
  }
}
