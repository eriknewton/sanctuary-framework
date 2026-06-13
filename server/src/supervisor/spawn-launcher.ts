/**
 * Phase S1 — Default {@link AgentLauncher}: spawns `sanctuary wrap`.
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
 * written once and closed immediately; the supervisor zeroes its own copy
 * after spawn. The child reads its single fd, scrubs the buffer, and closes.
 *
 * This module is the only one in the supervisor that touches real process
 * spawning, so the Supervisor state machine stays unit-testable against a mock
 * launcher. The wire-up here is deliberately thin: the heavy lifting lives in
 * `sanctuary wrap` already.
 *
 * NOTE: the actual `sanctuary wrap` end-to-end launch is exercised by the
 * Tier-A Protect acceptance drill (N>=3, Erik-present, on the signing host) —
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

    // Minimal env: the key NEVER goes in env or argv (codex R2-H2). Only the
    // fd NUMBER is advertised so the wrap child knows where to read.
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

    // Write the key to the pipe once, then close it immediately. The encoded
    // string is the only copy the launcher makes; the supervisor zeroes the
    // raw spec key after launch returns.
    const keyPipe = child.stdio[fd];
    if (keyPipe && typeof (keyPipe as { write?: unknown }).write === "function") {
      const writable = keyPipe as NodeJS.WritableStream;
      writable.write(`${toBase64url(spec.transientKey)}\n`);
      writable.end();
    }

    return new SpawnedChild(child, this.opts.stopGraceMs);
  }
}

/** Wraps a spawned wrap process behind the {@link LaunchedChild} contract. */
export class SpawnedChild implements LaunchedChild {
  private readonly child: ChildProcess;
  private readonly stopGraceMs: number;
  private stopped = false;

  constructor(child: ChildProcess, stopGraceMs: number) {
    this.child = child;
    this.stopGraceMs = stopGraceMs;
  }

  onExit(cb: (info: { code: number | null; signal: string | null }) => void): void {
    this.child.once("exit", (code, signal) => cb({ code, signal }));
  }

  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;

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
 * `sanctuary wrap` host calls this when `SANCTUARY_SUPERVISOR_KEY_FD` is set —
 * the key NEVER arrives via env or argv, only this fd.
 *
 * FAIL-CLOSED (R3-M1): returns null ONLY when the env var is absent (the wrap
 * was launched interactively, not by the supervisor). When the env var IS
 * present, supervisor mode is indicated and the handoff MUST succeed — any
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
      /* already closed by the reader / EOF — fine */
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
    throw new SupervisorKeyHandoffError("supervisor key failed strict base64url round-trip");
  }
  return key;
}
