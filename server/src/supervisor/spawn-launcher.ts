/**
 * Phase S1 - Default {@link AgentLauncher}: spawns `sanctuary wrap`.
 *
 * The supervisor's production launcher. It starts the same enforcement chain
 * `sanctuary wrap` builds today (config rewrite + IPC enforcement daemon +
 * harness child), launched and OWNED by the supervisor instead of a foreground
 * CLI.
 *
 * Transient-key handoff (codex R2-H2): the key is handed to the child over a
 * ONE-SHOT inherited pipe (an extra stdio fd), NOT the environment and NOT
 * argv. Passing it in env would leave master-equivalent material readable by
 * any same-uid process via `/proc/<pid>/environ` or `ps e`, bypassing the
 * authenticated socket entirely; argv is world-readable via `ps`. The pipe is
 * written once and closed immediately. The child reads its single fd, scrubs
 * the buffer, and closes.
 *
 * Residency, stated honestly (do NOT over-claim, codex S1): this launcher does
 * NOT zero key material after spawn. The base64url copy it writes to the pipe
 * is an immutable JS string that cannot be wiped (it lingers until GC), and the
 * raw `spec.transientKey` is RETAINED by the supervisor for the agent lifetime
 * (Tier A crash-restart re-launches from the same spec). The supervisor zeroes
 * that raw key only on a failed/refused launch or on unprotect/shutdown, not
 * "after spawn." See supervisor.ts for the exact zeroing points.
 *
 * This module is the only one in the supervisor that touches real process
 * spawning, so the Supervisor state machine stays unit-testable against a mock
 * launcher. The wire-up here is deliberately thin: the heavy lifting lives in
 * `sanctuary wrap` already.
 *
 * NOTE: the actual `sanctuary wrap` end-to-end launch is exercised by the
 * Tier-A Protect acceptance drill (N>=3, Erik-present, on the signing host):
 * headless arming is broken on Tahoe, so a real launch cannot be asserted in
 * CI. The automated tests cover the spawn CONTRACT (fd key handoff, key never
 * in env/argv, exit wiring) against a stub binary, not a live wrap.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync, closeSync } from "node:fs";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import type { AgentLauncher, LaunchedChild, SupervisionSpec } from "./supervisor.js";

export interface SpawnLauncherOptions {
  /** Absolute path to the sanctuary CLI entrypoint (the `wrap` host). */
  cliPath: string;
  /** Node executable to run the CLI with. Defaults to process.execPath. */
  nodePath?: string;
  /**
   * Stdio fd index the child reads its transient key from. The supervisor
   * writes the base64url key to this inherited pipe once and closes it.
   * Defaults to 3 (the first fd after stdin/stdout/stderr). Surfaced to the
   * child via the `SANCTUARY_SUPERVISOR_KEY_FD` env var (the FD NUMBER is not
   * secret; the key bytes never touch env).
   */
  transientKeyFd?: number;
  /** Grace period (ms) between SIGTERM and SIGKILL on stop. Defaults to 5s. */
  stopGraceMs?: number;
  /** Injectable spawn (test seam). Defaults to node:child_process spawn. */
  spawnFn?: typeof spawn;
}

/** Env var naming the fd the child reads its key from (the fd #, not the key). */
export const SUPERVISOR_KEY_FD_ENV = "SANCTUARY_SUPERVISOR_KEY_FD";
const DEFAULT_KEY_FD = 3;

export class SpawnAgentLauncher implements AgentLauncher {
  private readonly opts: Required<Omit<SpawnLauncherOptions, "nodePath">> & {
    nodePath: string;
  };

  constructor(opts: SpawnLauncherOptions) {
    this.opts = {
      cliPath: opts.cliPath,
      nodePath: opts.nodePath ?? process.execPath,
      transientKeyFd: opts.transientKeyFd ?? DEFAULT_KEY_FD,
      stopGraceMs: opts.stopGraceMs ?? 5_000,
      spawnFn: opts.spawnFn ?? spawn,
    };
  }

  async launch(spec: SupervisionSpec): Promise<LaunchedChild> {
    const fd = this.opts.transientKeyFd;
    // Build the stdio array with a pipe at the chosen fd. stdin ignored,
    // stdout/stderr piped for supervision; fd N is the one-shot key pipe.
    const stdio: Array<"ignore" | "pipe"> = ["ignore", "pipe", "pipe"];
    while (stdio.length <= fd) stdio.push("pipe");
    stdio[fd] = "pipe";

    // Child env (honest, codex S1): the child INHERITS the supervisor's
    // process env (it spreads `process.env`) because `sanctuary wrap` needs the
    // normal environment (PATH, HOME, locale, etc.) to run; this is NOT a
    // "minimal env." What matters for custody is the invariant that holds: the
    // transient KEY never goes in env or argv (codex R2-H2); only the fd NUMBER
    // is advertised here so the wrap child knows where to read the key from. The
    // key bytes travel ONLY over the inherited one-shot fd pipe.
    //
    // Hardening note: the auth secret reaching the supervisor is passed
    // in-process (constructor deps), NOT via any env var, so it is not present
    // in `process.env` to be inherited here. If a future production spawn path
    // ever places sensitive material in the supervisor's env, this spread must
    // be narrowed to an allowlist before that lands.
    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      [SUPERVISOR_KEY_FD_ENV]: String(fd),
    };

    const child = this.opts.spawnFn(
      this.opts.nodePath,
      [this.opts.cliPath, "wrap", "--config", spec.config_path, "--harness", spec.harness],
      {
        env: childEnv,
        stdio,
        detached: false,
      },
    );

    // Codex S1 R4-H1: spawn FAILURE (ENOENT on a bad node/cli path, EACCES,
    // fork limits) is delivered ASYNCHRONOUSLY via an `error` event, NOT a
    // throw from `spawn()`. Returning a SpawnedChild synchronously would (a)
    // leave the child `error` event unhandled (an EventEmitter `error` with no
    // listener THROWS and can crash the supervisor), and (b) let the Supervisor
    // mark the entry `running` and RETAIN the transient key for a process that
    // never started. So await the spawn outcome here: resolve only once the
    // child confirms `spawn`, reject on `error` (or a pre-spawn `exit`). On
    // rejection `guardedLaunch`/`runProtect` zero the key and drop the entry:
    // honest fail-closed residency (claim #7), no key left resident on a failed
    // launch. The key is written to the pipe only AFTER spawn confirms, so a
    // failed spawn never even marshals the key onto a dead pipe.
    // Exit latch armed at spawn-confirmation (codex S1 R6-H1 + R11): the
    // supervised child can exit at ANY point after `spawn`, including in the
    // gap between spawn-confirmation and `new SpawnedChild(...)` below (very live
    // today: supervised `wrap` reads its key and exits 2 almost immediately).
    // A `once("exit")` installed only in the SpawnedChild constructor would MISS
    // an exit that lands in that gap, wedging the entry `running` with the key
    // resident. So install a PERSISTENT exit listener the instant `spawn` fires
    // (inside onSpawn, before resolving) that records into `exitState`; the
    // SpawnedChild then reads that pre-armed state. There is no gap: from the
    // moment spawn is confirmed, every exit is captured.
    const exitState: ChildExitState = { exited: null, cb: null };
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const onSpawn = (): void => {
        if (settled) return;
        settled = true;
        child.removeListener("error", onError);
        child.removeListener("exit", onEarlyExit);
        // Arm the persistent latch NOW, atomically with spawn-confirmation.
        child.on("exit", (code, signal) => {
          exitState.exited = { code, signal };
          if (exitState.cb) {
            const cb = exitState.cb;
            exitState.cb = null;
            cb({ code, signal });
          }
        });
        resolve();
      };
      const onError = (err: Error): void => {
        if (settled) return;
        settled = true;
        child.removeListener("spawn", onSpawn);
        child.removeListener("exit", onEarlyExit);
        reject(new Error(`supervised child failed to spawn: ${err.message}`));
      };
      const onEarlyExit = (code: number | null, signal: string | null): void => {
        // An exit BEFORE the spawn event means the process never came up.
        if (settled) return;
        settled = true;
        child.removeListener("spawn", onSpawn);
        child.removeListener("error", onError);
        reject(new Error(`supervised child exited before spawn (code=${code}, signal=${signal})`));
      };
      child.once("spawn", onSpawn);
      child.once("error", onError);
      child.once("exit", onEarlyExit);
    });

    // Spawn confirmed. Write the key to the pipe once, then close it
    // immediately. The encoded base64url string is the only copy the launcher
    // makes, and it is an immutable JS string that cannot be wiped (it lingers
    // until GC). The raw `spec.transientKey` is NOT zeroed here: the supervisor
    // retains it for the agent lifetime to support Tier-A crash-restart, and
    // zeroes it only on a failed/refused launch or on unprotect/shutdown (see
    // supervisor.ts).
    //
    // Codex S1 R9: a MISSING/non-writable key pipe means the child can never
    // receive its key and cannot establish custody; treat it as a launch
    // FAILURE here (kill the child + reject) rather than returning a SpawnedChild
    // the supervisor would mark `running` (retaining the key for a child that
    // can't use it). Rejecting routes through runProtect's catch → key zeroed +
    // entry dropped, honest fail-closed residency (#7).
    const keyPipe = child.stdio[fd];
    if (!keyPipe || typeof (keyPipe as { write?: unknown }).write !== "function") {
      try {
        child.kill("SIGKILL");
      } catch {
        /* best-effort: the child may already be gone */
      }
      throw new Error(`supervised child key pipe (fd ${fd}) is not writable; refusing launch`);
    }
    // Codex S1 R10: AWAIT the key-pipe write to completion and REJECT on an
    // async stream error (EPIPE/ECONNRESET if the child closed its read fd
    // before the key landed). Fire-and-forget `write()`/`end()` would let a
    // failed key delivery resolve as a successful launch; the child never got
    // its key but the supervisor marks `running` and retains it. Awaiting
    // `finish` vs `error` makes a post-spawn handoff failure a launch FAILURE
    // (→ kill child + throw → runProtect catch zeroes the key + drops the
    // entry). The `write` itself can also report a sync error via its callback.
    const writable = keyPipe as NodeJS.WritableStream;
    try {
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const onError = (err: Error): void => {
          if (settled) return;
          settled = true;
          reject(err);
        };
        const onFinish = (): void => {
          if (settled) return;
          settled = true;
          resolve();
        };
        writable.once("error", onError);
        writable.once("finish", onFinish);
        writable.write(`${toBase64url(spec.transientKey)}\n`, (err) => {
          if (err) onError(err);
        });
        writable.end();
      });
    } catch (err) {
      try {
        child.kill("SIGKILL");
      } catch {
        /* best-effort */
      }
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(`supervised child key handoff failed on fd ${fd}: ${detail}`, { cause: err });
    }
    // After a successful handoff a LATE pipe error (child gone) must not become
    // an unhandled error event; the child's exit drives teardown from here.
    writable.on("error", () => {});

    return new SpawnedChild(child, this.opts.stopGraceMs, exitState);
  }
}

/**
 * Shared exit-latch state armed in `launch()` at spawn-confirmation and read by
 * {@link SpawnedChild}. `exited` is set the instant the child exits (captured by
 * the persistent listener `launch()` installs on `spawn`); `cb` holds a
 * supervisor callback registered before the exit happened. This eliminates the
 * gap between spawn-confirmation and SpawnedChild construction (codex S1 R11).
 */
export interface ChildExitState {
  exited: { code: number | null; signal: string | null } | null;
  cb: ((info: { code: number | null; signal: string | null }) => void) | null;
}

/** Wraps a spawned wrap process behind the {@link LaunchedChild} contract. */
export class SpawnedChild implements LaunchedChild {
  private readonly child: ChildProcess;
  private readonly stopGraceMs: number;
  private stopped = false;
  /**
   * Pre-armed exit latch (codex S1 R6-H1 + R11). The supervisor registers its
   * exit callback AFTER `launch()` resolves, and a child can exit at ANY point
   * after `spawn`, including in the gap BEFORE this wrapper is even constructed
   * (very live today: supervised `wrap` reads its key and exits 2 almost
   * immediately). So the latch is armed by `launch()` AT spawn-confirmation and
   * passed in here as `state`; if the exit already landed before construction,
   * `state.exited` is already set and a late `onExit` replays it. There is no
   * gap in which an exit can be missed.
   */
  private readonly state: ChildExitState;

  constructor(child: ChildProcess, stopGraceMs: number, state: ChildExitState) {
    this.child = child;
    this.stopGraceMs = stopGraceMs;
    this.state = state;
  }

  onExit(cb: (info: { code: number | null; signal: string | null }) => void): void {
    // Already exited before the supervisor wired its callback (possibly before
    // this wrapper existed) ⇒ fire now (async to preserve callback ordering /
    // avoid re-entrancy into runProtect).
    if (this.state.exited) {
      const info = this.state.exited;
      queueMicrotask(() => cb(info));
      return;
    }
    this.state.cb = cb;
  }

  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    // Already exited (latched at spawn-confirmation, or reflected on the child)
    // ⇒ nothing to stop.
    if (this.state.exited !== null || this.child.exitCode !== null || this.child.signalCode !== null) {
      return;
    }

    this.child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const grace = setTimeout(() => {
        if (this.child.exitCode === null && this.child.signalCode === null) {
          this.child.kill("SIGKILL");
        }
        resolve();
      }, this.stopGraceMs);
      if (typeof grace.unref === "function") grace.unref();
      this.child.once("exit", () => {
        clearTimeout(grace);
        resolve();
      });
    });
  }
}

/** Thrown when supervisor mode is indicated but the fd handoff is malformed. */
export class SupervisorKeyHandoffError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SupervisorKeyHandoffError";
  }
}

/**
 * Child-side reader (codex R2-H2, R3-M1): read the transient key from the
 * inherited one-shot pipe the supervisor wrote, then return the raw bytes. The
 * `sanctuary wrap` host calls this when `SANCTUARY_SUPERVISOR_KEY_FD` is set:
 * the key NEVER arrives via env or argv, only this fd.
 *
 * FAIL-CLOSED (R3-M1): returns null ONLY when the env var is absent (the wrap
 * was launched interactively, not by the supervisor). When the env var IS
 * present, supervisor mode is indicated and the handoff MUST succeed; any
 * malformed fd, read failure, or malformed key THROWS {@link
 * SupervisorKeyHandoffError} rather than silently falling back to the
 * passphrase/keychain path (which would leave the key unread in the pipe for a
 * `/proc/<pid>/fd/3` race). The fd is ALWAYS closed in `finally`.
 *
 * Reads synchronously from the fd, which the supervisor has already fully
 * written and closed, so there is no partial-read race. The caller MUST zero
 * the returned bytes once the master is established.
 */
export function readSupervisorTransientKey(env: NodeJS.ProcessEnv = process.env): Uint8Array | null {
  const raw = env[SUPERVISOR_KEY_FD_ENV];
  if (raw === undefined || raw.length === 0) return null; // not supervisor mode
  // Strict fd: digits only, >= 3. parseInt's lenient prefix parse is rejected.
  if (!/^[0-9]+$/.test(raw)) {
    throw new SupervisorKeyHandoffError(`malformed ${SUPERVISOR_KEY_FD_ENV}: ${raw}`);
  }
  const fd = Number.parseInt(raw, 10);
  if (fd < 3) {
    throw new SupervisorKeyHandoffError(`${SUPERVISOR_KEY_FD_ENV} must be >= 3, got ${fd}`);
  }
  let b64: string;
  try {
    b64 = readFileSync(fd, "utf-8").trim();
  } catch (err) {
    throw new SupervisorKeyHandoffError(
      `cannot read supervisor key fd ${fd}: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    // Close the one-shot pipe immediately so the key cannot linger in an fd a
    // same-uid process could re-read.
    try {
      closeSync(fd);
    } catch {
      /* already closed by the reader / EOF; fine */
    }
  }
  if (b64.length === 0) {
    throw new SupervisorKeyHandoffError("supervisor key fd was empty");
  }
  let key: Uint8Array;
  try {
    key = fromBase64url(b64);
  } catch {
    throw new SupervisorKeyHandoffError("supervisor key is not valid base64url");
  }
  // Strict round-trip: Buffer's base64 decode is lenient, so require the bytes
  // to re-encode to exactly the input (rejects a silently-mangled key).
  if (key.length === 0 || toBase64url(key) !== b64) {
    // Codex S1 R8: a malformed-but-decodable body already materialized real key
    // bytes; zero them before throwing so a rejected handoff leaves none
    // resident (honest custody, same hygiene as the request-handler path).
    key.fill(0);
    throw new SupervisorKeyHandoffError("supervisor key failed strict base64url round-trip");
  }
  return key;
}
