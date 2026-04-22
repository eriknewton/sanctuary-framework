/**
 * Recovery Cascade -- Guardian roster management.
 *
 * Wraps the mesh guardian primitives (issueGuardianRoster, verifyGuardianRoster)
 * with enroll/revoke operations that produce signed recovery events.
 *
 * Acceptance criterion 2: each operation produces a signed roster-update event
 * with `signature_scheme = 'ed25519-v1'`. Revoke does not leak guardian
 * identity beyond what was already published on the mesh.
 *
 * Key 13 LOCKED: 3-of-5 default, configurable. Human guardians only at v1.0.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import {
  issueGuardianRoster,
  verifyGuardianRoster,
} from "../mesh/guardian/guardian-roster.js";
import type {
  GuardianIdentity,
  GuardianRoster,
} from "../mesh/guardian/types.js";
import type { FortressMasterPublicKey } from "../mesh/types.js";
import { RECOVERY_EVENT_TYPES, RECOVERY_SIGNATURE_SCHEME } from "./constants.js";
import { GuardianNotFoundError, RecoveryConfigError } from "./errors.js";
import type { RecoveryEvent } from "./types.js";

/**
 * Generate a 128-bit hex event identifier.
 */
function generateEventId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Build a signed RecoveryEvent.
 */
function buildRecoveryEvent(params: {
  event_type: (typeof RECOVERY_EVENT_TYPES)[keyof typeof RECOVERY_EVENT_TYPES];
  fortress_id: string;
  emitter_node: string;
  emitter_principal: string;
  payload: Record<string, unknown>;
  signing_key: Uint8Array;
}): RecoveryEvent {
  const event_id = generateEventId();
  const created_at = new Date().toISOString();
  const payloadBytes = canonicalizeToBytes(params.payload);
  const payload_hash = toBase64url(sha256(payloadBytes));

  const body = {
    event_id,
    event_type: params.event_type,
    created_at,
    fortress_id: params.fortress_id,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    payload: params.payload,
    payload_hash,
    signature_scheme: RECOVERY_SIGNATURE_SCHEME,
  };

  const sig = ed25519.sign(canonicalizeToBytes(body), params.signing_key);

  return {
    ...body,
    signature: toBase64url(sig),
  };
}

/**
 * Enroll a new guardian on the roster. Returns the updated roster and a
 * signed recovery event recording the enrollment.
 *
 * Validation:
 *   - Guardian ID must not already exist in the roster.
 *   - Adding this guardian must not exceed the roster's N.
 *   - The new roster is re-signed by the fortress master.
 */
export function enrollGuardian(params: {
  current_roster: GuardianRoster;
  new_guardian: GuardianIdentity;
  fortress_master_public: FortressMasterPublicKey;
  fortress_master_private_key: Uint8Array;
  emitter_node: string;
  emitter_principal: string;
  node_signing_key: Uint8Array;
}): { roster: GuardianRoster; event: RecoveryEvent } {
  const { current_roster, new_guardian } = params;

  // Check for duplicate guardian_id.
  if (current_roster.guardians.some((g) => g.guardian_id === new_guardian.guardian_id)) {
    throw new RecoveryConfigError(
      `guardian ${new_guardian.guardian_id} already exists in the roster`
    );
  }

  const updatedGuardians = [...current_roster.guardians, new_guardian];
  const newN = updatedGuardians.length;

  // M cannot exceed N.
  if (current_roster.m > newN) {
    throw new RecoveryConfigError(
      `adding guardian would result in n=${newN} which is less than m=${current_roster.m}`
    );
  }

  // Issue new roster with incremented version.
  const newRoster = issueGuardianRoster({
    m: current_roster.m,
    n: newN,
    guardians: updatedGuardians,
    fortress_id: current_roster.fortress_id,
    version: current_roster.version + 1,
    master_private_key: params.fortress_master_private_key,
  });

  // Verify round-trip integrity.
  verifyGuardianRoster(newRoster, params.fortress_master_public);

  // Emit signed recovery event.
  const event = buildRecoveryEvent({
    event_type: RECOVERY_EVENT_TYPES.GUARDIAN_ENROLL,
    fortress_id: current_roster.fortress_id,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    payload: {
      guardian_id: new_guardian.guardian_id,
      guardian_kind: new_guardian.kind,
      roster_version: newRoster.version,
      previous_roster_version: current_roster.version,
      new_n: newN,
      m: current_roster.m,
    },
    signing_key: params.node_signing_key,
  });

  return { roster: newRoster, event };
}

/**
 * Revoke a guardian from the roster. Returns the updated roster and a
 * signed recovery event recording the revocation.
 *
 * Per acceptance criterion 2: revoke does not leak guardian identity
 * beyond what was already published on the mesh. The event payload
 * contains only the guardian_id (already public on the roster) and
 * roster version metadata.
 */
export function revokeGuardian(params: {
  current_roster: GuardianRoster;
  guardian_id: string;
  fortress_master_public: FortressMasterPublicKey;
  fortress_master_private_key: Uint8Array;
  emitter_node: string;
  emitter_principal: string;
  node_signing_key: Uint8Array;
}): { roster: GuardianRoster; event: RecoveryEvent } {
  const { current_roster, guardian_id } = params;

  // Find the guardian.
  const idx = current_roster.guardians.findIndex(
    (g) => g.guardian_id === guardian_id
  );
  if (idx === -1) {
    throw new GuardianNotFoundError(guardian_id);
  }

  const updatedGuardians = current_roster.guardians.filter(
    (g) => g.guardian_id !== guardian_id
  );
  const newN = updatedGuardians.length;

  // Threshold constraint: m must not exceed new n.
  const newM = Math.min(current_roster.m, newN);
  if (newN < 1) {
    throw new RecoveryConfigError(
      `revoking guardian ${guardian_id} would leave the roster empty`
    );
  }

  // Issue new roster.
  const newRoster = issueGuardianRoster({
    m: newM,
    n: newN,
    guardians: updatedGuardians,
    fortress_id: current_roster.fortress_id,
    version: current_roster.version + 1,
    master_private_key: params.fortress_master_private_key,
  });

  // Verify round-trip integrity.
  verifyGuardianRoster(newRoster, params.fortress_master_public);

  // Emit signed recovery event. Only guardian_id (already public).
  const event = buildRecoveryEvent({
    event_type: RECOVERY_EVENT_TYPES.GUARDIAN_REVOKE,
    fortress_id: current_roster.fortress_id,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    payload: {
      guardian_id,
      roster_version: newRoster.version,
      previous_roster_version: current_roster.version,
      new_n: newN,
      new_m: newM,
    },
    signing_key: params.node_signing_key,
  });

  return { roster: newRoster, event };
}

/**
 * Verify a RecoveryEvent's signature against a node's public key.
 */
export function verifyRecoveryEventSignature(
  event: RecoveryEvent,
  nodePublicKey: Uint8Array
): boolean {
  if (event.signature_scheme !== SIGNATURE_SCHEME_V1) {
    return false;
  }
  const { signature, ...body } = event;
  try {
    return ed25519.verify(
      new Uint8Array(Buffer.from(
        signature.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (signature.length % 4)) % 4),
        "base64"
      )),
      canonicalizeToBytes(body),
      nodePublicKey
    );
  } catch {
    return false;
  }
}
