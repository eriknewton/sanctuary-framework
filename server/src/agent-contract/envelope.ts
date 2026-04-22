/**
 * Sanctuary Agent Contract v0.1 — Harness I/O Envelope (§2.3).
 *
 * Every message flowing in or out of the harness is wrapped in this
 * envelope. Both sides authorize: the sender's claim asserts the envelope is
 * authorized; the receiver's policy check stamps an allow/deny decision
 * before the body is delivered to the harness or onwards to a downstream
 * tool.
 *
 * This envelope is distinct from the mesh SignedEvent envelope: the mesh
 * envelope covers cross-node federation; the harness envelope covers the
 * broker ↔ harness boundary on a single node. A harness envelope may be
 * downstream-packed into a mesh SignedEvent (e.g. when an agent's
 * harness_out flows to a cross-node tool) by the broker.
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  AGENT_CONTRACT_VERSION,
  SIGNATURE_SCHEME_V1,
  type CapabilityKind,
} from "./constants.js";
import { AgentContractError } from "./errors.js";
import { validateHarnessEnvelope } from "./schema.js";
import type { HarnessEnvelope } from "./types.js";

export interface WrapEnvelopeParams<Body> {
  direction: "harness_in" | "harness_out";
  agent_id: string;
  fortress_id: string;
  capability_kind: CapabilityKind;
  capability_target: string;
  body: Body;
  policy_version: number;
  /** Principal / agent making the sender's claim. */
  claimant: string;
  wrapped_at?: string;
  asserted_at?: string;
}

/**
 * Wrap a harness-bound or harness-emitted body in a validated envelope with
 * sender's claim stamped. The receiver MUST populate `receiver_check` before
 * delivering the body.
 */
export function wrapHarnessEnvelope<Body>(
  params: WrapEnvelopeParams<Body>
): HarnessEnvelope<Body> {
  const wrapped_at = params.wrapped_at ?? new Date().toISOString();
  const asserted_at = params.asserted_at ?? wrapped_at;
  const body_hash = toBase64url(sha256(canonicalizeToBytes(params.body)));
  const envelope_id = generateEnvelopeId();
  const env: HarnessEnvelope<Body> = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    envelope_id,
    direction: params.direction,
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    capability_kind: params.capability_kind,
    capability_target: params.capability_target,
    body: params.body,
    body_hash,
    policy_version: params.policy_version,
    sender_claim: {
      claimant: params.claimant,
      asserted_at,
    },
    wrapped_at,
  };
  validateHarnessEnvelope(env);
  return env;
}

/**
 * Record the receiver's policy-check decision on an envelope. Returns a new
 * envelope; the input is not mutated. Emits at broker receipt time,
 * immediately before the body is delivered to the harness (on
 * `harness_in`) or to the downstream tool (on `harness_out`).
 */
export function stampReceiverCheck<Body>(
  env: HarnessEnvelope<Body>,
  check: { decision: "allow" | "deny"; reason_code: string; gate_receipt_id?: string }
): HarnessEnvelope<Body> {
  const next: HarnessEnvelope<Body> = {
    ...env,
    receiver_check: {
      decision: check.decision,
      reason_code: check.reason_code,
      ...(check.gate_receipt_id ? { gate_receipt_id: check.gate_receipt_id } : {}),
    },
  };
  validateHarnessEnvelope(next);
  return next;
}

/**
 * Verify body integrity — useful when an envelope flows through a
 * cross-process boundary (broker → audit log) and the caller wants to
 * confirm the body matches its declared hash.
 */
export function verifyEnvelopeBodyHash<Body>(env: HarnessEnvelope<Body>): void {
  const fresh = toBase64url(sha256(canonicalizeToBytes(env.body)));
  if (fresh !== env.body_hash) {
    throw new AgentContractError(
      `harness envelope body_hash mismatch for envelope_id=${env.envelope_id}`
    );
  }
}

function generateEnvelopeId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
