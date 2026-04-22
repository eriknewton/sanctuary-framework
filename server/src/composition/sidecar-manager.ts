/**
 * Sanctuary Composition v1.0 -- Sidecar Manager
 *
 * Spawns, supervises, and restarts the Concordia Python sidecar.
 * Exponential backoff on repeated crashes. Sidecar crash is NEVER
 * a fortress-halt condition.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { SIDECAR_RPC_METHODS } from "./constants.js";
import {
  SidecarMessageSizeCapExceededError,
  SidecarSpawnError,
} from "./errors.js";
import { SidecarRpcClient } from "./sidecar-rpc.js";
import type { CompositionConfig, SidecarResponse } from "./types.js";

export type SidecarState = "stopped" | "starting" | "running" | "crashed" | "restarting";

/**
 * Audit record emitted when a sidecar JSON-RPC frame exceeds the per-message
 * size cap. The SidecarManager fires this on the event listener so the
 * composition service layer can push the record into the audit log. Fields
 * are structured (not a free-form string) so a principal-id field can be
 * added at v1.x per the attestation-UX invariant without a schema break.
 */
export interface SidecarSizeCapAuditRecord {
  buffered_bytes: number;
  cap_bytes: number;
  consecutive_crashes: number;
  at: string;
}

/**
 * Event listener for sidecar lifecycle events.
 */
export interface SidecarEventListener {
  onStateChange?: (state: SidecarState) => void;
  onCrash?: (exitCode: number | null, signal: string | null) => void;
  onReady?: () => void;
  /**
   * Fired when the per-message size cap trips. The manager has already
   * killed the sidecar process by the time this callback runs. Wire this
   * to the audit log.
   */
  onMessageSizeCapExceeded?: (record: SidecarSizeCapAuditRecord) => void;
}

/**
 * Manages the lifecycle of the Concordia Python sidecar process.
 */
export class SidecarManager {
  private process: ChildProcess | null = null;
  private rpcClient: SidecarRpcClient | null = null;
  private state: SidecarState = "stopped";
  private consecutiveCrashes = 0;
  private lastCrashAt: string | null = null;
  private lastSuccessAt: string | null = null;
  private restartTimer: ReturnType<typeof setTimeout> | null = null;
  private isShuttingDown = false;

  constructor(
    private config: CompositionConfig,
    private listener?: SidecarEventListener
  ) {}

  /**
   * Spawn the sidecar process and wait for it to be ready.
   * @throws SidecarSpawnError if the sidecar fails to start
   */
  async start(): Promise<void> {
    if (this.state === "running") return;
    this.isShuttingDown = false;

    this.setState("starting");

    try {
      this.process = spawn(
        this.config.python_path,
        [this.config.sidecar_script_path],
        {
          stdio: ["pipe", "pipe", "pipe"],
          env: {
            ...process.env,
            PYTHONUNBUFFERED: "1",
          },
        }
      );

      // Handle process exit
      this.process.on("exit", (code, signal) => {
        this.handleExit(code, signal);
      });

      this.process.on("error", (err) => {
        this.handleSpawnError(err);
      });

      // Collect stderr for diagnostics (but don't block on it)
      if (this.process.stderr) {
        this.process.stderr.on("data", () => {
          // Sidecar stderr is diagnostic only; not parsed.
        });
      }

      this.rpcClient = new SidecarRpcClient(
        this.process,
        this.config.sidecar_rpc_timeout_ms,
        (err) => this.handleSizeCapExceeded(err)
      );

      // Wait for the sidecar to respond to a ping
      await this.waitForReady();

      this.setState("running");
      this.consecutiveCrashes = 0;
      this.lastSuccessAt = new Date().toISOString();
      this.listener?.onReady?.();
    } catch (err) {
      this.setState("crashed");
      this.kill();
      throw err instanceof SidecarSpawnError
        ? err
        : new SidecarSpawnError(
            err instanceof Error ? err.message : "Unknown spawn error"
          );
    }
  }

  private async waitForReady(): Promise<void> {
    if (!this.rpcClient) {
      throw new SidecarSpawnError("RPC client not initialized");
    }

    const response = await this.rpcClient.call(
      SIDECAR_RPC_METHODS.PING,
      {},
      this.config.sidecar_spawn_timeout_ms
    );

    if (response.error) {
      throw new SidecarSpawnError(
        `Sidecar ping failed: ${response.error.message}`
      );
    }
  }

  /**
   * Gracefully shut down the sidecar.
   */
  async stop(): Promise<void> {
    this.isShuttingDown = true;
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }

    if (this.rpcClient && this.state === "running") {
      try {
        await this.rpcClient.call(SIDECAR_RPC_METHODS.SHUTDOWN, {}, 2000);
      } catch {
        // Timeout or error on shutdown is acceptable.
      }
    }

    this.kill();
    this.setState("stopped");
  }

  /**
   * Get the RPC client for making calls to the sidecar.
   * Returns null if the sidecar is not running.
   */
  getRpcClient(): SidecarRpcClient | null {
    if (this.state !== "running") return null;
    return this.rpcClient;
  }

  /**
   * Get the current sidecar state.
   */
  getState(): SidecarState {
    return this.state;
  }

  /**
   * Get the number of consecutive crashes.
   */
  getConsecutiveCrashes(): number {
    return this.consecutiveCrashes;
  }

  /**
   * Get the last crash timestamp.
   */
  getLastCrashAt(): string | null {
    return this.lastCrashAt;
  }

  /**
   * Get the last successful operation timestamp.
   */
  getLastSuccessAt(): string | null {
    return this.lastSuccessAt;
  }

  /**
   * Record a successful operation (resets crash counter watchdog).
   */
  recordSuccess(): void {
    this.lastSuccessAt = new Date().toISOString();
  }

  /**
   * Send a version request to the sidecar.
   */
  async getVersion(): Promise<SidecarResponse | null> {
    const client = this.getRpcClient();
    if (!client) return null;
    return client.call(SIDECAR_RPC_METHODS.VERSION);
  }

  /**
   * Fired by the RPC client when a buffered JSON-RPC frame exceeds the
   * size cap. The manager must kill the sidecar (this is treated as a
   * crash for the restart-backoff loop) and surface an audit record to
   * the listener. The fortress does NOT halt.
   */
  private handleSizeCapExceeded(
    err: SidecarMessageSizeCapExceededError
  ): void {
    // Capture the consecutive-crash count BEFORE handleExit increments it,
    // so the audit record reflects the pre-trip count. The +1 happens in
    // handleExit when the sidecar process emits its "exit" event after
    // kill().
    const record = {
      buffered_bytes: err.bufferedBytes,
      cap_bytes: err.capBytes,
      consecutive_crashes: this.consecutiveCrashes,
      at: new Date().toISOString(),
    };
    try {
      this.listener?.onMessageSizeCapExceeded?.(record);
    } catch {
      // Listener errors must not propagate.
    }
    // Treat as a crash: kill + scheduleRestart via the exit handler.
    this.kill();
  }

  private handleExit(code: number | null, signal: string | null): void {
    if (this.isShuttingDown) {
      this.setState("stopped");
      return;
    }

    this.consecutiveCrashes++;
    this.lastCrashAt = new Date().toISOString();
    this.setState("crashed");
    this.listener?.onCrash?.(code, signal);

    // Cancel pending RPCs
    this.rpcClient?.cancelAll("sidecar process exited");
    this.rpcClient = null;
    this.process = null;

    // Schedule restart with exponential backoff
    if (this.consecutiveCrashes <= this.config.sidecar_max_consecutive_crashes) {
      this.scheduleRestart();
    }
  }

  private handleSpawnError(err: Error): void {
    if (this.isShuttingDown) return;

    this.consecutiveCrashes++;
    this.lastCrashAt = new Date().toISOString();
    this.setState("crashed");
    this.listener?.onCrash?.(null, null);

    this.rpcClient?.cancelAll(`spawn error: ${err.message}`);
    this.rpcClient = null;
    this.process = null;

    if (this.consecutiveCrashes <= this.config.sidecar_max_consecutive_crashes) {
      this.scheduleRestart();
    }
  }

  private scheduleRestart(): void {
    const delay = Math.min(
      this.config.sidecar_restart_initial_delay_ms *
        Math.pow(
          this.config.sidecar_restart_backoff_multiplier,
          this.consecutiveCrashes - 1
        ),
      this.config.sidecar_restart_max_delay_ms
    );

    this.setState("restarting");
    this.restartTimer = setTimeout(async () => {
      try {
        await this.start();
      } catch {
        // start() handles its own error state. The backoff loop
        // continues via handleExit/handleSpawnError.
      }
    }, delay);
  }

  private kill(): void {
    if (this.process) {
      this.rpcClient?.cancelAll("sidecar killed");
      this.rpcClient = null;
      try {
        this.process.kill("SIGTERM");
      } catch {
        // Already dead.
      }
      this.process = null;
    }
  }

  private setState(state: SidecarState): void {
    this.state = state;
    this.listener?.onStateChange?.(state);
  }
}
