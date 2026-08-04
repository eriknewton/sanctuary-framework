/**
 * Memory Checkpoint -- optional periodic checkpoint scheduler.
 *
 * The scheduler is local-only. It creates a scheduled checkpoint, prunes
 * expired local checkpoints, routes tick failures to onError, and never lets
 * onError crash the host process.
 */

import {
  createCheckpoint,
  type CreateCheckpointDeps,
} from "./create.js";
import {
  pruneExpiredCheckpoints,
} from "./retention.js";
import {
  MemoryCheckpointSchedulerError,
  type MemoryCheckpointRecord,
} from "./types.js";
import type { MemoryCheckpointClock } from "./store.js";

export const CHECKPOINT_INTERVAL_ENV = "SANCTUARY_CHECKPOINT_INTERVAL";
export const DEFAULT_CHECKPOINT_INTERVAL_MS = 6 * 60 * 60 * 1000;
export const MIN_CHECKPOINT_INTERVAL_MS = 60_000;

export function parseCheckpointInterval(
  value: string | undefined,
): number | null {
  if (value === undefined || value.trim() === "") {
    return DEFAULT_CHECKPOINT_INTERVAL_MS;
  }
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "off" || trimmed === "0" || trimmed === "disabled") {
    return null;
  }
  const match = /^(\d+)(ms|s|m|h|d)?$/.exec(trimmed);
  if (!match) {
    throw new MemoryCheckpointSchedulerError(
      `invalid ${CHECKPOINT_INTERVAL_ENV} value "${value}": use "off", milliseconds, or <n>s|m|h|d`,
      "invalid_interval",
    );
  }
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  const multiplier =
    unit === "ms" ? 1 :
    unit === "s" ? 1_000 :
    unit === "m" ? 60_000 :
    unit === "h" ? 3_600_000 :
    86_400_000;
  const ms = amount * multiplier;
  if (!Number.isSafeInteger(ms) || ms < MIN_CHECKPOINT_INTERVAL_MS) {
    throw new MemoryCheckpointSchedulerError(
      `invalid ${CHECKPOINT_INTERVAL_ENV} value "${value}": minimum interval is ${MIN_CHECKPOINT_INTERVAL_MS}ms (use "off" to disable)`,
      "invalid_interval",
    );
  }
  return ms;
}

export interface MemoryCheckpointSchedulerOptions {
  intervalMs: number;
  emit: () => Promise<unknown>;
  onError: (err: unknown) => void;
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}

export interface MemoryCheckpointSchedulerHandle {
  stop(): void;
}

export function startMemoryCheckpointScheduler(
  options: MemoryCheckpointSchedulerOptions,
): MemoryCheckpointSchedulerHandle {
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  let inFlight = false;
  let stopped = false;
  const timer = setIntervalFn(() => {
    if (inFlight || stopped) return;
    inFlight = true;
    void options
      .emit()
      .catch((err) => {
        try {
          options.onError(err);
        } catch {
          // onError must not take the scheduler down.
        }
      })
      .finally(() => {
        inFlight = false;
      });
  }, options.intervalMs);
  if (typeof (timer as NodeJS.Timeout).unref === "function") {
    (timer as NodeJS.Timeout).unref();
  }
  return {
    stop() {
      stopped = true;
      clearIntervalFn(timer);
    },
  };
}

export interface ScheduledCheckpointEmitterDeps
  extends Omit<CreateCheckpointDeps, "source" | "now"> {
  clock?: MemoryCheckpointClock;
}

export function buildScheduledCheckpointEmitter(
  deps: ScheduledCheckpointEmitterDeps,
): () => Promise<MemoryCheckpointRecord> {
  return async () => {
    let created: MemoryCheckpointRecord | null = null;
    try {
      const now = deps.clock?.now() ?? deps.store.now();
      created = await createCheckpoint({
        ...deps,
        source: "scheduled",
        now,
      });
      await pruneExpiredCheckpoints({
        store: deps.store,
        auditLog: deps.auditLog,
        identityId: deps.identityId,
        now: deps.clock?.now() ?? deps.store.now(),
      });
      return created;
    } catch (err) {
      if (created !== null) {
        try {
          await deps.store.delete(created.id);
        } catch (rollbackErr) {
          throw new MemoryCheckpointSchedulerError(
            `memory checkpoint scheduled tick failed and rollback delete also failed: ${
              rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)
            }`,
            "scheduled_tick_rollback_failed",
            err,
          );
        }
      }
      throw err;
    }
  };
}

export interface StartMemoryCheckpointSchedulerFromEnvDeps
  extends ScheduledCheckpointEmitterDeps {
  env?: NodeJS.ProcessEnv;
  onError: (err: unknown) => void;
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}

export function startMemoryCheckpointSchedulerFromEnv(
  deps: StartMemoryCheckpointSchedulerFromEnvDeps,
): MemoryCheckpointSchedulerHandle | null {
  const env = deps.env ?? process.env;
  const intervalMs = parseCheckpointInterval(env[CHECKPOINT_INTERVAL_ENV]);
  if (intervalMs === null) return null;
  return startMemoryCheckpointScheduler({
    intervalMs,
    emit: buildScheduledCheckpointEmitter(deps),
    onError: deps.onError,
    ...(deps.setIntervalFn !== undefined ? { setIntervalFn: deps.setIntervalFn } : {}),
    ...(deps.clearIntervalFn !== undefined ? { clearIntervalFn: deps.clearIntervalFn } : {}),
  });
}
