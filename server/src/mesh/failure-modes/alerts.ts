/**
 * Failure-mode alert emission.
 *
 * Every detection / decision in the failure-mode + recovery surface emits a
 * signed `agent_usage_event` per Agent Contract v0.1 §6, with `event_class`
 * drawn from {sentinel_alert, gate_approved, gate_denied, policy_pinned}.
 *
 * The alerts module is the single seam between the failure-mode detector and
 * the Agent Contract emission path. Tests verify that every detection path
 * routes through here with the correct event_class.
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url, stringToBytes } from "../../core/encoding.js";
import { emitUsageEvent } from "../../agent-contract/usage-event.js";
import type { UsageEvent } from "../../agent-contract/types.js";
import type { SignedEvent } from "../types.js";
import type { CounterStore } from "../lifecycle/types.js";
import {
  failureModeCapabilityTarget,
  meshSystemAgentId,
  recoveryCapabilityTarget,
  type FailureMode,
} from "./constants.js";

/**
 * Per-emitter context the alerts module needs. Caller provides this once at
 * detector construction; the module uses it for every emission.
 */
export interface AlertEmitContext {
  /** Emitter node id — `mesh:<this>` becomes the agent_id. */
  emitter_node: string;
  /** Principal id under which alerts are signed (typically the system principal). */
  emitter_principal: string;
  /** Fortress id for this mesh. */
  fortress_id: string;
  /** Per-node Ed25519 private key for envelope signing. */
  node_private_key: Uint8Array;
  /**
   * Optional principal private key for envelope principal-signature. Most
   * mesh-system alerts are unsigned at the principal layer (system events),
   * but operator-decision alerts (gate_approved / gate_denied / policy_pinned)
   * SHOULD carry a principal signature where the operator authored.
   */
  principal_private_key?: Uint8Array;
  /** Monotonic counter store (envelope_monotonic_seq is consumed). */
  counters: CounterStore;
  /**
   * Static policy_version + policy_version_hash placeholder for mesh-system
   * emissions. The mesh-system pseudo-agent has no real policy; we emit a
   * zero-version hash that downstream consumers recognize.
   */
  mesh_system_policy_version?: number;
  mesh_system_policy_version_hash?: string;
}

/** Default mesh-system policy hash — SHA-256("mesh-system-v1"). */
export const MESH_SYSTEM_POLICY_VERSION_HASH = toBase64url(
  sha256(stringToBytes("mesh-system-v1"))
);

export interface EmittedAlert {
  signed_event: SignedEvent<UsageEvent>;
  event: UsageEvent;
}

function emit(
  ctx: AlertEmitContext,
  params: {
    event_class: UsageEvent["event_class"];
    capability_target: string;
    detail: Record<string, unknown>;
  }
): EmittedAlert {
  return emitUsageEvent({
    agent_id: meshSystemAgentId(ctx.emitter_node),
    fortress_id: ctx.fortress_id,
    event_class: params.event_class,
    capability_target: params.capability_target,
    input: { detail: params.detail },
    output: { acknowledged: true },
    policy_version: ctx.mesh_system_policy_version ?? 0,
    policy_version_hash:
      ctx.mesh_system_policy_version_hash ?? MESH_SYSTEM_POLICY_VERSION_HASH,
    attestation_state: "present",
    emitter_node: ctx.emitter_node,
    emitter_principal: ctx.emitter_principal,
    node_private_key: ctx.node_private_key,
    principal_private_key: ctx.principal_private_key,
    monotonic_seq: ctx.counters.next("envelope_monotonic_seq"),
  });
}

/**
 * Emit a sentinel_alert for a detected failure-mode condition. This is the
 * default detection-side emission for every failure mode (offline,
 * compromised, rollback, split-brain detection, canonical-audit-loss trigger,
 * dmswitch propagation receipt).
 */
export function emitSentinelAlert(
  ctx: AlertEmitContext,
  params: {
    failure_mode: FailureMode | "dmswitch" | "guardian_roster";
    target: string;
    detail: Record<string, unknown>;
  }
): EmittedAlert {
  const target =
    params.failure_mode === "dmswitch"
      ? recoveryCapabilityTarget("dmswitch", params.target)
      : params.failure_mode === "guardian_roster"
        ? recoveryCapabilityTarget("guardian_quorum", params.target)
        : failureModeCapabilityTarget(
            params.failure_mode as FailureMode,
            params.target
          );
  return emit(ctx, {
    event_class: "sentinel_alert",
    capability_target: target,
    detail: { failure_mode: params.failure_mode, ...params.detail },
  });
}

/**
 * Emit a gate_approved usage event for an operator-acted decision (rollback
 * accept, canonical-audit-promotion, etc.).
 */
export function emitGateApproved(
  ctx: AlertEmitContext,
  params: {
    failure_mode: FailureMode | "master_rotation" | "canonical_audit_loss";
    target: string;
    decision: string;
    detail: Record<string, unknown>;
  }
): EmittedAlert {
  const target =
    params.failure_mode === "master_rotation"
      ? recoveryCapabilityTarget("master_rotation", params.target)
      : failureModeCapabilityTarget(
          params.failure_mode as FailureMode,
          params.target
        );
  return emit(ctx, {
    event_class: "gate_approved",
    capability_target: target,
    detail: {
      failure_mode: params.failure_mode,
      decision: params.decision,
      ...params.detail,
    },
  });
}

/** Emit a gate_denied usage event for an operator-rejected decision. */
export function emitGateDenied(
  ctx: AlertEmitContext,
  params: {
    failure_mode: FailureMode;
    target: string;
    decision: string;
    detail: Record<string, unknown>;
  }
): EmittedAlert {
  return emit(ctx, {
    event_class: "gate_denied",
    capability_target: failureModeCapabilityTarget(
      params.failure_mode,
      params.target
    ),
    detail: {
      failure_mode: params.failure_mode,
      decision: params.decision,
      ...params.detail,
    },
  });
}

/**
 * Emit a policy_pinned usage event when an operator chooses one branch of a
 * split-brain conflict OR promotes a replica to canonical audit.
 */
export function emitPolicyPinned(
  ctx: AlertEmitContext,
  params: {
    /** Subject of the pin: agent_id for a policy choice, "canonical_audit_node" for a promotion. */
    subject: string;
    /** Chosen value: event_id of the kept branch, or new canonical node id. */
    pinned_to: string;
    detail: Record<string, unknown>;
  }
): EmittedAlert {
  return emit(ctx, {
    event_class: "policy_pinned",
    capability_target: `mesh.policy_pin:${params.subject}`,
    detail: { pinned_to: params.pinned_to, ...params.detail },
  });
}
