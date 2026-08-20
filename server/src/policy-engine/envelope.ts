/**
 * Sanctuary Policy Engine - SignedEvent<PolicyUpdatePayload> packaging.
 *
 * WP-MVP-3 owns the mesh surface. This module calls into the mesh only via
 * its public API (packSignedEvent / verifySignedEvent / verifyCertChain) -
 * it never touches `server/src/mesh/` internals.
 *
 * Pack flow:
 *   1. Validate CompiledPolicy shape.
 *   2. Encode blob: base64url(canonicalJSON(policy)).
 *   3. Build PolicyUpdatePayload { agent_id, policy_version, validity window,
 *      policy_blob, parent_version? }.
 *   4. Hand to mesh packSignedEvent with event_type = "policy_update".
 *
 * Unpack flow (receiver):
 *   1. mesh verifySignedEvent - validates chain + signatures + payload_hash.
 *   2. Decode policy_blob; validateCompiledPolicyShape.
 *   3. Cross-check payload.agent_id === compiled.agent_id,
 *      payload.policy_version === compiled.policy_version,
 *      payload.parent_version === compiled.parent_version.
 *   4. Version-monotonicity check against any pinned prior version.
 *
 * Step 3 is the load-bearing cross-check against a tampered blob: a sender
 * can't declare one version in the payload header and ship a different blob
 * inside, because both-sides verification compares the two.
 */

import { POLICY_UPDATE_EVENT_TYPE } from "./constants.js";
import {
  decodePolicyBlob,
  encodePolicyBlob,
  validateCompiledPolicyShape,
} from "./canonical-policy.js";
import {
  CompiledPolicyShapeError,
  PolicyVersionForkError,
  PolicyVersionRollbackError,
} from "./errors.js";
import type { CompiledPolicy } from "./types.js";
import { packSignedEvent, verifySignedEvent } from "../mesh/envelope.js";
import type { VerifyContext, VerifyResult } from "../mesh/envelope.js";
import type {
  PolicyUpdatePayload,
  SignedEvent,
} from "../mesh/types.js";
import { MeshSignatureError } from "../mesh/errors.js";
// the envelope header is parsed from an untrusted policy blob, so its fields
// carry no shape; diagnostics go through the untrusted-diagnostic chokepoint
// (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

/** Parameters for packing a policy_update event. */
export interface PackPolicyUpdateParams {
  policy: CompiledPolicy;
  emitter_node: string;
  /** Principal authoring the policy. Typically the Root principal. */
  emitter_principal: string;
  /** Per-emitter monotonic envelope sequence. */
  monotonic_seq: number;
  /** Node signing key - Ed25519 private key bytes. */
  node_private_key: Uint8Array;
  /** Principal signing key - Ed25519 private key bytes. Recommended. */
  principal_private_key?: Uint8Array;
  /** Optional causal parents (prior policy_update event_ids). */
  causal_parents?: string[];
  /** Optional start of the signed validity window. Defaults to now. */
  valid_from?: string;
  /** Optional end of the signed validity window. Defaults to valid_from + 24h. */
  valid_until?: string;
}

/**
 * Pack a CompiledPolicy into a signed mesh event ready for transport.
 *
 * Intentionally does NOT transport - the caller hands the returned event to
 * whatever mesh transport is active (WP-MVP-3's in-memory transport at v0.1,
 * a libp2p wire adapter at a later phase).
 */
export function packPolicyUpdate(
  params: PackPolicyUpdateParams
): SignedEvent<PolicyUpdatePayload> {
  validateCompiledPolicyShape(params.policy);
  const blob = encodePolicyBlob(params.policy);
  const validFrom = params.valid_from ?? new Date().toISOString();
  const validUntil =
    params.valid_until ??
    new Date(Date.parse(validFrom) + 24 * 60 * 60 * 1000).toISOString();
  const payload: PolicyUpdatePayload = {
    agent_id: params.policy.agent_id,
    policy_version: params.policy.policy_version,
    valid_from: validFrom,
    valid_until: validUntil,
    policy_blob: blob,
    ...(params.policy.parent_version !== undefined
      ? { parent_version: params.policy.parent_version }
      : {}),
  };
  return packSignedEvent<PolicyUpdatePayload>({
    event_type: POLICY_UPDATE_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.policy.fortress_id,
    causal_parents: params.causal_parents,
    payload,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
}

export interface UnpackPolicyUpdateResult {
  /** Passed-through mesh verify result (signatures, chain, fortress pinning). */
  meshVerify: VerifyResult;
  /** Decoded compiled policy. */
  compiled: CompiledPolicy;
  /** Raw payload. */
  payload: PolicyUpdatePayload;
}

export interface UnpackPolicyUpdateParams {
  event: SignedEvent<PolicyUpdatePayload>;
  meshVerifyContext: VerifyContext;
  /**
   * The pinned version this receiver believes is head for this agent.
   * Undefined ⇒ first policy ever received for this agent. Any non-negative
   * integer is compared to the incoming event's policy_version for
   * monotonicity + optional parent_version match.
   */
  pinnedVersionHead?: number;
}

/**
 * Verify a received policy_update envelope and decode it.
 *
 * Throws MeshSignatureError for mesh-surface failures (propagated from the
 * mesh verifier), CompiledPolicyShapeError for blob-shape failures,
 * PolicyVersionRollbackError / PolicyVersionForkError for version failures.
 *
 * Never silently degrades. A receiver that catches these errors MUST drop
 * the envelope and log; it MUST NOT fall back to the pinned prior version
 * as if the new one had landed.
 */
export function unpackPolicyUpdate(
  params: UnpackPolicyUpdateParams
): UnpackPolicyUpdateResult {
  const evt = params.event;
  if (evt.event_type !== POLICY_UPDATE_EVENT_TYPE) {
    throw new MeshSignatureError(
      `policy-engine unpack received event_type="${evt.event_type}"; expected "${POLICY_UPDATE_EVENT_TYPE}"`
    );
  }
  const meshVerify = verifySignedEvent(evt, params.meshVerifyContext);

  const payload = evt.payload;
  const compiled = decodePolicyBlob(payload.policy_blob);

  if (compiled.agent_id !== payload.agent_id) {
    throw new CompiledPolicyShapeError(
      `header/blob agent_id mismatch: envelope says ${describeUntrusted(payload.agent_id)}, blob says ${compiled.agent_id}`
    );
  }
  if (compiled.policy_version !== payload.policy_version) {
    throw new CompiledPolicyShapeError(
      `header/blob policy_version mismatch: envelope says ${describeUntrusted(payload.policy_version)}, blob says ${compiled.policy_version}`
    );
  }
  if (compiled.parent_version !== payload.parent_version) {
    throw new CompiledPolicyShapeError(
      `header/blob parent_version mismatch: envelope says ${describeUntrusted(payload.parent_version)}, blob says ${String(compiled.parent_version)}`
    );
  }
  if (compiled.fortress_id !== evt.fortress_id) {
    throw new CompiledPolicyShapeError(
      `envelope/blob fortress_id mismatch: envelope says ${describeUntrusted(evt.fortress_id)}, blob says ${compiled.fortress_id}`
    );
  }

  // Version-monotonicity + fork check.
  if (params.pinnedVersionHead !== undefined) {
    if (compiled.policy_version <= params.pinnedVersionHead) {
      throw new PolicyVersionRollbackError(
        `received policy_version ${compiled.policy_version} <= pinned head ${params.pinnedVersionHead} for ${compiled.agent_id}`
      );
    }
    if (
      compiled.parent_version !== undefined &&
      compiled.parent_version !== params.pinnedVersionHead
    ) {
      throw new PolicyVersionForkError(
        `received parent_version ${compiled.parent_version} does not match pinned head ${params.pinnedVersionHead} for ${compiled.agent_id}`
      );
    }
  }

  return { meshVerify, compiled, payload };
}
