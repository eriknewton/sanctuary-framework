/**
 * Sanctuary Composition v1.0 -- Composition Service
 *
 * Public API: isEnabled, packConcordiaReceipt, verifyMandate,
 * emitForCommitment (canonical), publishVerascoreSignal, getDegradeState.
 *
 * Orchestrates sidecar lifecycle, degrade monitor, and composition hooks.
 * All operations are gated on composition_enabled. Sidecar crash is NEVER
 * a fortress-halt condition.
 */

import { resolveCompositionConfig, isCompositionDisabled, type CompositionConfigInput } from "./composition-config.js";
import {
  SidecarManager,
  type SidecarEventListener,
  type SidecarSizeCapAuditRecord,
} from "./sidecar-manager.js";
import {
  deriveSidecarSigningKey,
  type SidecarSigningKeypair,
} from "./sidecar-signing-key.js";
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
import {
  CompositionDisabledError,
  DegradeStateError,
  MissingSidecarSigningKeyError,
} from "./errors.js";
import { isPlainObject } from "./assert-shape.js";
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
 * Historical sidecar public key preserved across a master rotation. Kept so
 * composition events signed under a pre-rotation key remain verifiable after
 * the master has rotated (Federation Protocol v0.1 §9.5 audit-continuity at
 * the composition layer).
 */
export interface HistoricalSidecarPubkey {
  /** Base64url-encoded sidecar public key. */
  publicKey: Uint8Array;
  /** Fortress master public key that anchored this sidecar key. */
  anchoringMasterFingerprint: string;
  /** ISO 8601 timestamp when this key was superseded by a rotation. */
  retiredAt: string;
}

/**
 * Optional fortress context for the composition service. When supplied, the
 * service HKDF-derives the sidecar signing keypair from the fortress master
 * secret and manages the rotation cascade automatically.
 *
 * If omitted (test-only ergonomic path), callers must pass an explicit
 * signingKey into publishVerascoreSignal. Production call sites should
 * always construct with fortress context.
 */
export interface FortressContextInput {
  fortress_master_secret: Uint8Array;
  fortress_id: string;
}

/**
 * Input to CompositionService.emitForCommitment(), the canonical production
 * entry point for emitting a reputation signal on a closed commitment.
 *
 * The principal_id field is reserved for v1.x multi-principal-data-model
 * support. It is accepted at v1.0 so v1.x call sites can populate it without
 * a schema break; the v1.0 emitter ignores it.
 */
export interface EmitForCommitmentInput {
  receipt: ConcordiaReceipt;
  fortressId: string;
  /**
   * Reserved for v1.x per the Public Pool Federation Mode invariant holdout
   * check: multi-principal data model. Accepted but unused at v1.0.
   */
  principal_id?: string;
  /** Optional publish scope override. Defaults to config default (private). */
  scope?: VerascoreScope;
  /** Explicit public opt-in. REQUIRED for public scope. */
  explicitPublicOptIn?: boolean;
}

/**
 * Result of CompositionService.emitForCommitment(). The audit_event_ids
 * field is reserved for Follow-up #2b's broker wire-up, which will emit
 * composition_* signed-event envelope ids alongside the verascore signal.
 * At v1.0 this thread ships the signal emission only, so the field is
 * always the empty list.
 */
export interface EmitForCommitmentResult {
  signal: VerascoreSignal;
  /** Reserved for Follow-up #2b. Empty at v1.0. */
  audit_event_ids: readonly string[];
}

/**
 * The composition service. Entry point for all composition operations.
 */
export class CompositionService {
  private config: CompositionConfig;
  private sidecarManager: SidecarManager | null = null;
  private degradeMonitor: DegradeMonitor;
  private started = false;
  private sizeCapAuditListeners: Array<(record: SidecarSizeCapAuditRecord) => void> = [];
  private sizeCapAuditRecords: SidecarSizeCapAuditRecord[] = [];
  private fortressMasterSecret: Uint8Array | null = null;
  private fortressId: string | null = null;
  private sidecarKeypairCache: SidecarSigningKeypair | null = null;
  private historicalSidecarPubkeys: HistoricalSidecarPubkey[] = [];

  constructor(
    configInput?: CompositionConfigInput,
    basePath?: string,
    fortressContext?: FortressContextInput
  ) {
    this.config = resolveCompositionConfig(configInput, basePath);
    this.degradeMonitor = new DegradeMonitor(
      this.config.replay_queue_max_depth
    );
    if (fortressContext) {
      this.setFortressContext(fortressContext);
    }
  }

  /**
   * Install fortress master secret + fortress_id. Calling this (including
   * re-calling to set a new master) invalidates the cached sidecar keypair
   * so the next getSidecarSigningKey() call re-derives under the new master.
   *
   * Called by bootstrap code that constructs the service before the master
   * is available, and by the master-rotation ceremony to re-anchor.
   */
  setFortressContext(fortressContext: FortressContextInput): void {
    this.fortressMasterSecret = fortressContext.fortress_master_secret;
    this.fortressId = fortressContext.fortress_id;
    this.sidecarKeypairCache = null;
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
      onMessageSizeCapExceeded: (record) => {
        this.sizeCapAuditRecords.push(record);
        for (const l of this.sizeCapAuditListeners) {
          try {
            l(record);
          } catch {
            // Listener errors must not propagate.
          }
        }
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
   * When signingKey is omitted, the HKDF-derived sidecar signing key is used
   * (via getSidecarSigningKey()). This makes the production call shape
   * ergonomic by default: fortress context installed at construction is
   * enough, and no caller needs to carry the signing key around. If signingKey
   * is omitted AND no fortress context was installed, throws
   * MissingSidecarSigningKeyError.
   *
   * Explicit signingKey remains supported for test fixtures and migration
   * paths. Production call sites should prefer omitting it, OR prefer the
   * canonical entry point emitForCommitment().
   *
   * @param receipt The Concordia receipt
   * @param fortressId Fortress ID
   * @param signingKey Ed25519 private key. Optional; defaults to the
   *                   HKDF-derived sidecar signing key when omitted.
   * @param options Optional scope override and public opt-in
   * @throws CompositionDisabledError if composition is off
   * @throws MissingSidecarSigningKeyError if signingKey omitted and no
   *         fortress context installed
   * @throws ScopeViolationError if public without opt-in
   */
  publishVerascoreSignal(
    receipt: ConcordiaReceipt,
    fortressId: string,
    signingKey?: Uint8Array,
    options?: { scope?: VerascoreScope; explicitPublicOptIn?: boolean }
  ): VerascoreSignal {
    this.assertEnabled();

    const effectiveSigningKey = this.resolveSigningKey(
      signingKey,
      "publishVerascoreSignal"
    );

    return hookPublishSignal(this.config, {
      receipt,
      fortressId,
      signingKey: effectiveSigningKey,
      requestedScope: options?.scope,
      explicitPublicOptIn: options?.explicitPublicOptIn,
    });
  }

  /**
   * Canonical production entry point for emitting a reputation signal on a
   * closed commitment. The broker / commitment-boundary pipeline that lands
   * in Follow-up #2b calls this method.
   *
   * Always uses the HKDF-derived sidecar signing key. There is no signingKey
   * parameter; callers that want to pass an explicit key are in a test or
   * migration path and should use publishVerascoreSignal() instead.
   *
   * @throws CompositionDisabledError if composition is off
   * @throws MissingSidecarSigningKeyError if no fortress context installed
   * @throws ScopeViolationError if public without opt-in
   */
  emitForCommitment(input: EmitForCommitmentInput): EmitForCommitmentResult {
    this.assertEnabled();

    const signingKey = this.resolveSigningKey(undefined, "emitForCommitment");

    const signal = hookPublishSignal(this.config, {
      receipt: input.receipt,
      fortressId: input.fortressId,
      signingKey,
      requestedScope: input.scope,
      explicitPublicOptIn: input.explicitPublicOptIn,
    });

    return {
      signal,
      audit_event_ids: [],
    };
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
   * Register a listener for sidecar size-cap audit records. The SanctuaryAuditLog
   * wires through this subscription to append a composition-layer audit entry
   * on every cap-triggered rejection. The fortress continues operating; the
   * sidecar is terminated and restarted via the backoff loop.
   */
  onSidecarSizeCapAudit(
    listener: (record: SidecarSizeCapAuditRecord) => void
  ): void {
    this.sizeCapAuditListeners.push(listener);
  }

  /**
   * HKDF-derived sidecar signing keypair, anchored in the fortress master
   * installed via setFortressContext / the constructor. Returns null if no
   * fortress context has been installed.
   *
   * Deterministic: same (master, fortress_id) always yields the same keypair.
   * A rotateFortressMaster call retires the previous keypair and installs a
   * new one derived from the new master.
   *
   * This is the canonical production-path key for signing composition_*
   * signed-event envelopes and verascore signals. Tests that use
   * publishVerascoreSignal with an explicit signingKey argument are using
   * the v1.0 ergonomic escape hatch; production callers should route through
   * this method.
   */
  getSidecarSigningKey(): SidecarSigningKeypair | null {
    if (!this.fortressMasterSecret || !this.fortressId) return null;
    if (this.sidecarKeypairCache) return this.sidecarKeypairCache;
    this.sidecarKeypairCache = deriveSidecarSigningKey({
      fortress_master_secret: this.fortressMasterSecret,
      fortress_id: this.fortressId,
    });
    return this.sidecarKeypairCache;
  }

  /**
   * Rotate the fortress master secret. The current sidecar signing keypair is
   * preserved as a historical pubkey (so old signatures still verify) and the
   * new master is HKDF-anchored to derive a new sidecar keypair on the next
   * getSidecarSigningKey() call.
   *
   * @param newFortressMasterSecret The new fortress master secret (32-byte
   *                                private key material). Callers MUST zero
   *                                the old secret after this call returns.
   * @param anchoringMasterFingerprint Caller-supplied fingerprint (e.g.
   *                                  base64url of the OLD master pubkey) so
   *                                  historical-pubkey records can correlate
   *                                  to a specific rotation.
   */
  rotateFortressMaster(
    newFortressMasterSecret: Uint8Array,
    anchoringMasterFingerprint: string
  ): void {
    // Retire the current keypair, if we had one.
    const current = this.getSidecarSigningKey();
    if (current) {
      this.historicalSidecarPubkeys.push({
        publicKey: current.publicKey,
        anchoringMasterFingerprint,
        retiredAt: new Date().toISOString(),
      });
    }
    this.fortressMasterSecret = newFortressMasterSecret;
    this.sidecarKeypairCache = null;
  }

  /**
   * Historical sidecar public keys preserved across master rotations. Verifiers
   * consult this list to validate signatures emitted pre-rotation.
   */
  getHistoricalSidecarPubkeys(): readonly HistoricalSidecarPubkey[] {
    return this.historicalSidecarPubkeys;
  }

  /**
   * Snapshot of every sidecar size-cap audit record captured since start()
   * (or since the last clearAll() in tests). Read-only.
   */
  getSidecarSizeCapAuditRecords(): readonly SidecarSizeCapAuditRecord[] {
    return this.sizeCapAuditRecords;
  }

  /**
   * Get the sidecar version info.
   */
  async getSidecarVersion(): Promise<Record<string, unknown> | null> {
    if (!this.sidecarManager) return null;
    const response = await this.sidecarManager.getVersion();
    if (!response || response.error) return null;
    return isPlainObject(response.result) ? response.result : null;
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
    this.sizeCapAuditRecords = [];
    this.sizeCapAuditListeners = [];
    this.sidecarKeypairCache = null;
    this.historicalSidecarPubkeys = [];
    clearPublishedSignals();
  }

  private assertEnabled(): void {
    if (isCompositionDisabled(this.config)) {
      throw new CompositionDisabledError();
    }
  }

  /**
   * Resolve the Ed25519 signing key to use for a composition-layer emit.
   * If the caller passed one explicitly, it wins (test fixture / migration
   * path). Otherwise the HKDF-derived sidecar key is used. If neither is
   * available, throws MissingSidecarSigningKeyError.
   */
  private resolveSigningKey(
    explicitSigningKey: Uint8Array | undefined,
    callSite: "publishVerascoreSignal" | "emitForCommitment"
  ): Uint8Array {
    if (explicitSigningKey) return explicitSigningKey;
    const derived = this.getSidecarSigningKey();
    if (derived) return derived.privateKey;
    if (callSite === "publishVerascoreSignal") {
      throw new MissingSidecarSigningKeyError(
        "publishVerascoreSignal called without a signingKey, and no fortress context was provided to CompositionService. Pass a signingKey explicitly OR construct CompositionService with FortressContextInput so that getSidecarSigningKey() can derive one.",
        "publishVerascoreSignal"
      );
    }
    throw new MissingSidecarSigningKeyError(
      "emitForCommitment requires fortress context; pass FortressContextInput to the CompositionService constructor.",
      "emitForCommitment"
    );
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
