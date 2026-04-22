/**
 * Sanctuary Policy Engine — Signed gate receipts.
 *
 * Every gate decision emits a receipt. The receipt is Ed25519-signed by the
 * evaluating node's per-node key so an operator auditing the log can
 * verify: "this decision was made by the node I expect, against the
 * policy_version I expect, with this reason_code, at this timestamp."
 *
 * This receipt is NOT a Concordia commitment receipt. Concordia commitments
 * travel a separate path through the commitment engine (Python sidecar per
 * WP-MVP-10). Gate receipts record "gate fired" — the commitment itself, if
 * any, is signed separately.
 *
 * The signature surface is canonicalize(receipt minus `signature`). Any
 * verifier reconstitutes that form, drops signature, re-canonicalizes, and
 * checks against the evaluating node's pinned public key.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import type { AutoTriggerTier, PolicySlot } from "./constants.js";
import type { GateReceipt } from "./types.js";

export interface IssueReceiptParams {
  decision: "allow" | "deny" | "operator_approval_required";
  slot: PolicySlot | "commitment_boundary";
  agent_id: string;
  counterparty?: string;
  action: string;
  invoked_skill_id?: string;
  policy_version: number | null;
  reason_code: string;
  fortress_id: string;
  evaluating_node_id: string;
  ladder_tier_fired?: AutoTriggerTier;
  /** Ed25519 private key of the evaluating node. */
  node_signing_key: Uint8Array;
  /** Injectable clock for deterministic tests. Defaults to Date.now(). */
  now?: () => Date;
}

/** 128-bit hex receipt id — same generator pattern as mesh event_id. */
function generateReceiptId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Build and sign a gate receipt.
 *
 * Optional fields are omitted from the body (not set to undefined) so the
 * canonical-JSON form is stable regardless of whether `counterparty` or
 * `invoked_skill_id` were present.
 */
export function issueGateReceipt(params: IssueReceiptParams): GateReceipt {
  const nowIso = (params.now ? params.now() : new Date()).toISOString();
  const body: Omit<GateReceipt, "signature"> = {
    receipt_id: generateReceiptId(),
    decision: params.decision,
    slot: params.slot,
    agent_id: params.agent_id,
    action: params.action,
    policy_version: params.policy_version,
    reason_code: params.reason_code,
    fortress_id: params.fortress_id,
    evaluating_node_id: params.evaluating_node_id,
    timestamp: nowIso,
  };
  if (params.counterparty !== undefined) body.counterparty = params.counterparty;
  if (params.invoked_skill_id !== undefined)
    body.invoked_skill_id = params.invoked_skill_id;
  if (params.ladder_tier_fired !== undefined)
    body.ladder_tier_fired = params.ladder_tier_fired;

  const sig = ed25519.sign(canonicalizeToBytes(body), params.node_signing_key);
  return { ...body, signature: toBase64url(sig) };
}

/**
 * Verify a gate receipt's signature against the evaluating node's public key.
 *
 * Returns true on success, false on any verification failure. Does NOT
 * throw — callers typically want to filter a stream of receipts without
 * unwinding the stack for each invalid one.
 */
export function verifyGateReceipt(
  receipt: GateReceipt,
  nodePublicKey: Uint8Array
): boolean {
  const { signature, ...body } = receipt;
  try {
    return ed25519.verify(
      fromBase64url(signature),
      canonicalizeToBytes(body),
      nodePublicKey
    );
  } catch {
    return false;
  }
}
