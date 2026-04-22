/**
 * Sanctuary Composition v1.0 -- Composition Service
 *
 * Public API: isEnabled, packConcordiaReceipt, verifyMandate,
 * publishVerascoreSignal, getDegradeState.
 *
 * Orchestrates sidecar lifecycle, degrade monitor, and composition hooks.
 * All operations are gated on composition_enabled. Sidecar crash is NEVER
 * a fortress-halt condition.
 */

import { resolveCompositionConfig, isCompositionDisabled, type CompositionConfigInput } from "./composition-config.js";
import { SidecarManager, type SidecarEventListener } from "./sidecar-manager.js";
import { DegradeMonitor } from "./degrade-monitor.js";
import {
  packConcordiaReceipt as adapterPackReceipt,
  verifyConcordiaReceipt as adapterVerifyReceipt,
  verifyMandate as adapterVerifyMandate,
} from "./concordia-adapter.js";
import {
  publishVerascoreSignal as hookPublishSignal,
  clearPublishedSignals,
} from "./verascore-hook.js";
import { CompositionDisabledError, DegradeStateError } from "./errors.js";
import type {
  CompositionConfig,
  CompositionDegradeState,
  CommitmentEvent,
  ConcordiaReceipt,
  MandateVerificationResult,
  VerascoreSignal,
} from "./types.js";
import type { VerascoreScope } from "./constants.js";

/**
 * The composition service. Entry point for all composition operations.
 */
export class CompositionService {
  private config: CompositionConfig;
  private sidecarManager: SidecarManager | null = null;
  private degradeMonitor: DegradeMonitor;
  private started = false;

  constructor(configInput?: CompositionConfigInput, basePath?: string) {
    this.config = resolveCompositionConfig(configInput, basePath);
    this.degradeMonitor = new DegradeMonitor(
      this.config.replay_queue_max_depth
    );
  }

  /**
   * Check if composition is enabled.
   */
  isEnabled(): boolean {
    return this.config.composition_enabled;
  }

  /**
   * Start the composition service. Spawns the sidecar if composition
   * is enabled. No-op if disabled.
   */
  async start(): Promise<void> {
    if (isCompositionDisabled(this.config)) return;
    if (this.started) return;

    const listener: SidecarEventListener = {
      onStateChange: (state) => {
        this.degradeMonitor.reportSidecarState(state);
      },
      onCrash: () => {
        this.degradeMonitor.reportCrash(
          this.sidecarManager?.getConsecutiveCrashes() ?? 0,
          this.sidecarManager?.getLastCrashAt() ?? new Date().toISOString()
        );
      },
      onReady: () => {
        this.degradeMonitor.reportSuccess();
        // Replay queued events
        this.replayQueuedEvents();
      },
    };

    this.sidecarManager = new SidecarManager(this.config, listener);
    await this.sidecarManager.start();
    this.started = true;
  }

  /**
   * Stop the composition service. Gracefully shuts down the sidecar.
   */
  async stop(): Promise<void> {
    if (this.sidecarManager) {
      await this.sidecarManager.stop();
      this.sidecarManager = null;
    }
    this.started = false;
  }

  /**
   * Pack a Concordia receipt from a Sanctuary commitment event.
   *
   * @throws CompositionDisabledError if composition is off
   * @throws DegradeStateError if sidecar is degraded
   */
  async packReceipt(event: CommitmentEvent): Promise<ConcordiaReceipt> {
    this.assertEnabled();

    const rpc = this.sidecarManager?.getRpcClient();
    if (!rpc) {
      // Sidecar not running; queue for replay and throw degrade error
      this.degradeMonitor.queueForReplay(event);
      const state = this.degradeMonitor.getState();
      throw new DegradeStateError(
        "Sidecar not running",
        state.consecutive_crashes,
        state.replay_queue_depth
      );
    }

    try {
      const receipt = await adapterPackReceipt(rpc, event);
      this.sidecarManager?.recordSuccess();
      this.degradeMonitor.reportSuccess();
      return receipt;
    } catch (err) {
      // On failure, queue for replay; do NOT halt the fortress
      this.degradeMonitor.queueForReplay(event);
      const state = this.degradeMonitor.getState();
      throw new DegradeStateError(
        err instanceof Error ? err.message : "pack_receipt failed",
        state.consecutive_crashes,
        state.replay_queue_depth
      );
    }
  }

  /**
   * Verify a Concordia receipt.
   *
   * @throws CompositionDisabledError if composition is off
   * @throws DegradeStateError if sidecar is degraded
   */
  async verifyReceipt(receipt: ConcordiaReceipt): Promise<boolean> {
    this.assertEnabled();
    const rpc = this.requireRpc();

    try {
      const valid = await adapterVerifyReceipt(rpc, receipt);
      this.sidecarManager?.recordSuccess();
      this.degradeMonitor.reportSuccess();
      return valid;
    } catch (err) {
      const state = this.degradeMonitor.getState();
      throw new DegradeStateError(
        err instanceof Error ? err.message : "verify_receipt failed",
        state.consecutive_crashes,
        state.replay_queue_depth
      );
    }
  }

  /**
   * Verify a Concordia mandate (delegation chain).
   *
   * @throws CompositionDisabledError if composition is off
   * @throws DegradeStateError if sidecar is degraded
   * @throws MandateVerificationError on mandate-specific failure
   */
  async verifyMandate(
    mandateData: Record<string, unknown>
  ): Promise<MandateVerificationResult> {
    this.assertEnabled();
    const rpc = this.requireRpc();

    const result = await adapterVerifyMandate(rpc, mandateData);
    this.sidecarManager?.recordSuccess();
    this.degradeMonitor.reportSuccess();
    return result;
  }

  /**
   * Publish a Verascore reputation signal for a commitment close.
   *
   * @param receipt The Concordia receipt
   * @param fortressId Fortress ID
   * @param signingKey Ed25519 private key
   * @param options Optional scope override and public opt-in
   * @throws CompositionDisabledError if composition is off
   * @throws ScopeViolationError if public without opt-in
   */
  publishVerascoreSignal(
    receipt: ConcordiaReceipt,
    fortressId: string,
    signingKey: Uint8Array,
    options?: { scope?: VerascoreScope; explicitPublicOptIn?: boolean }
  ): VerascoreSignal {
    this.assertEnabled();

    return hookPublishSignal(this.config, {
      receipt,
      fortressId,
      signingKey,
      requestedScope: options?.scope,
      explicitPublicOptIn: options?.explicitPublicOptIn,
    });
  }

  /**
   * Get the current composition degrade state.
   */
  getDegradeState(): CompositionDegradeState {
    return this.degradeMonitor.getState();
  }

  /**
   * Register a listener for degrade state changes.
   * Used by the attestation service to update badges.
   */
  onDegradeStateChange(
    listener: (event: import("./degrade-monitor.js").DegradeStateChangeEvent) => void
  ): void {
    this.degradeMonitor.onStateChange(listener);
  }

  /**
   * Get the sidecar version info.
   */
  async getSidecarVersion(): Promise<Record<string, unknown> | null> {
    if (!this.sidecarManager) return null;
    const response = await this.sidecarManager.getVersion();
    if (!response || response.error) return null;
    return response.result as Record<string, unknown>;
  }

  /**
   * Get the composition config (read-only).
   */
  getConfig(): Readonly<CompositionConfig> {
    return this.config;
  }

  /**
   * Clear all composition state. Test-only.
   */
  clearAll(): void {
    this.degradeMonitor.clear();
    clearPublishedSignals();
  }

  private assertEnabled(): void {
    if (isCompositionDisabled(this.config)) {
      throw new CompositionDisabledError();
    }
  }

  private requireRpc() {
    const rpc = this.sidecarManager?.getRpcClient();
    if (!rpc) {
      const state = this.degradeMonitor.getState();
      throw new DegradeStateError(
        "Sidecar not running",
        state.consecutive_crashes,
        state.replay_queue_depth
      );
    }
    return rpc;
  }

  private async replayQueuedEvents(): Promise<void> {
    const events = this.degradeMonitor.drainReplayQueue();
    for (const event of events) {
      try {
        await this.packReceipt(event);
      } catch {
        // If replay fails, the event goes back into the queue via packReceipt.
        // Don't block recovery of subsequent events.
      }
    }
  }
}
