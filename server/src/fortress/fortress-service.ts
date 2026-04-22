/**
 * Sanctuary Fortress Modes -- Fortress Service
 *
 * Public API: getCurrentMode, proposeTransition, executeTransition,
 * queryTierProfile, registerAdapter.
 *
 * Orchestrates the state machine, precondition checks, signed event
 * creation, config persistence, and history logging.
 */

import type { StorageBackend } from "../storage/interface.js";
import type { ModeTier } from "./constants.js";
import { TIER_CAPABILITY_DEFAULTS } from "./constants.js";
import type {
  FortressModeStatus,
  TransitionProposal,
  TransitionResult,
  PreconditionContext,
  TierProfile,
  ExternalAdapterRegistration,
  TransitionHistoryEntry,
} from "./types.js";
import {
  ModePreconditionsNotMetError,
  InvalidAdapterError,
} from "./errors.js";
import { validateTransition, checkPreconditions } from "./mode-state-machine.js";
import { packModeTransitionEvent } from "./mode-transition-event.js";
import { getTierProfile } from "./tier-profile.js";
import { isExternalAdapterBit } from "./tier-profile.js";
import { FortressModeStore } from "./config.js";

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface FortressServiceParams {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  nodeId: string;
  principalId: string;
  nodePrivateKey: Uint8Array;
  principalPrivateKey?: Uint8Array;
  /** Monotonic counter. Caller is responsible for persistence. */
  nextMonotonicSeq: () => number;
}

export class FortressService {
  private store: FortressModeStore;
  private fortressId: string;
  private nodeId: string;
  private principalId: string;
  private nodePrivateKey: Uint8Array;
  private principalPrivateKey?: Uint8Array;
  private nextMonotonicSeq: () => number;
  private adapters: Map<string, ExternalAdapterRegistration> = new Map();

  constructor(params: FortressServiceParams) {
    this.store = new FortressModeStore(params.storage, params.masterKey);
    this.fortressId = params.fortressId;
    this.nodeId = params.nodeId;
    this.principalId = params.principalId;
    this.nodePrivateKey = params.nodePrivateKey;
    this.principalPrivateKey = params.principalPrivateKey;
    this.nextMonotonicSeq = params.nextMonotonicSeq;
  }

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  /**
   * Initialize or load the fortress mode config.
   * Call this at server startup. Creates a default Tier 1 config
   * if no config exists.
   */
  async initialize(): Promise<void> {
    const existing = await this.store.load();
    if (!existing) {
      await this.store.initialize(this.fortressId);
    }
  }

  // -----------------------------------------------------------------------
  // Queries
  // -----------------------------------------------------------------------

  /**
   * Get the current fortress mode status.
   */
  async getCurrentMode(): Promise<FortressModeStatus> {
    const config = await this.store.load();
    if (!config) {
      throw new Error("Fortress mode not initialized. Call initialize() first.");
    }

    const profile = getTierProfile(config.current_tier);
    const history = await this.store.loadHistory();

    return {
      tier: config.current_tier,
      profile,
      capability_bits: config.capability_bits,
      transitions_history: history.entries,
      last_transition_at: config.last_transition_at,
    };
  }

  /**
   * Query the static profile for any tier.
   */
  queryTierProfile(tier: ModeTier): TierProfile {
    return getTierProfile(tier);
  }

  // -----------------------------------------------------------------------
  // External adapter registry (Tier 3 hooks-only at v1.0)
  // -----------------------------------------------------------------------

  /**
   * Register a stub external-protocol adapter.
   * At v1.0, this satisfies the Tier 3 precondition.
   * Real adapter implementations ship in v1.x.
   */
  registerAdapter(registration: ExternalAdapterRegistration): void {
    if (!isExternalAdapterBit(registration.capability_bit)) {
      throw new InvalidAdapterError(
        `Capability bit ${registration.capability_bit} is not in the external-adapter range (3-7). ` +
          `External adapters must claim bits 3-7 per Federation v0.1 SS10.2.`
      );
    }
    this.adapters.set(registration.adapter_id, registration);
  }

  /**
   * Deregister an external-protocol adapter.
   */
  deregisterAdapter(adapterId: string): boolean {
    return this.adapters.delete(adapterId);
  }

  /**
   * Get all registered adapters.
   */
  getRegisteredAdapters(): ExternalAdapterRegistration[] {
    return Array.from(this.adapters.values());
  }

  // -----------------------------------------------------------------------
  // Transitions
  // -----------------------------------------------------------------------

  /**
   * Execute a mode transition. Validates legality, checks preconditions,
   * creates a signed event, persists the config update, and logs the
   * transition to history.
   *
   * Returns the transition result with the signed event ID.
   */
  async executeTransition(
    proposal: TransitionProposal,
    /** Override precondition context for testing. */
    contextOverrides?: Partial<PreconditionContext>
  ): Promise<TransitionResult> {
    const config = await this.store.load();
    if (!config) {
      throw new Error("Fortress mode not initialized. Call initialize() first.");
    }

    const fromTier = config.current_tier;
    const toTier = proposal.target_tier;

    // 1. Validate the transition is legal (throws on illegal)
    validateTransition(fromTier, toTier);

    // 2. Build precondition context
    const ctx: PreconditionContext = {
      current_tier: fromTier,
      target_tier: toTier,
      has_node_identity_cert: true,
      has_reachable_peer: true,
      registered_adapter_count: this.adapters.size,
      fortress_id: this.fortressId,
      ...proposal.precondition_overrides,
      ...contextOverrides,
    };

    // 3. Check preconditions (no LLM, no network, pure logic)
    const failures = await checkPreconditions(ctx);
    if (failures.length > 0) {
      throw new ModePreconditionsNotMetError(failures);
    }

    // 4. Determine capability bits for target tier
    const capabilityBits = TIER_CAPABILITY_DEFAULTS[toTier];

    // 5. Create signed transition event
    const preconditionIds = failures.length === 0
      ? (await import("./mode-state-machine.js")).getPreconditions(fromTier, toTier).map(p => p.id)
      : [];

    const event = packModeTransitionEvent({
      from_tier: fromTier,
      to_tier: toTier,
      fortress_id: this.fortressId,
      reason: proposal.reason,
      preconditions_checked: preconditionIds,
      emitter_node: this.nodeId,
      emitter_principal: this.principalId,
      monotonic_seq: this.nextMonotonicSeq(),
      node_private_key: this.nodePrivateKey,
      principal_private_key: this.principalPrivateKey,
    });

    // 6. Persist config update
    await this.store.applyTransition(toTier, event.event_id, capabilityBits);

    // 7. Append to history
    const historyEntry: TransitionHistoryEntry = {
      event_id: event.event_id,
      from_tier: fromTier,
      to_tier: toTier,
      reason: proposal.reason,
      transitioned_at: event.payload.transitioned_at,
    };
    await this.store.appendHistory(historyEntry);

    return {
      event_id: event.event_id,
      from_tier: fromTier,
      to_tier: toTier,
      capability_bits: capabilityBits,
      transitioned_at: event.payload.transitioned_at,
    };
  }
}
