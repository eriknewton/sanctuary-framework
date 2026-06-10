/**
 * /v1 session ceremony — shared message canonicalization (PR-A1).
 *
 * Both sides of the RFC v7 challenge-response ceremony (daemon verifier in
 * `session-service.ts`, CLI client in `cli/v1-session.ts`) MUST build the
 * byte string the client signs from this one function. Any drift between
 * what the client signs and what the daemon verifies is an auth bypass or
 * a permanent ceremony failure, so the encoding lives here and nowhere
 * else.
 *
 * Encoding: a fixed domain-separation prefix followed by length-prefixed
 * fields. Length prefixes (4-byte big-endian) make the encoding injective:
 * no two distinct (client_pubkey, challenge, attestation_ref) triples can
 * produce the same byte string, which kills cross-field splice attacks.
 */

/**
 * Domain separator for challenge signatures. Versioned under the v1
 * namespace; a future ceremony revision MUST use a different string.
 */
export const V1_CHALLENGE_SIGNATURE_DOMAIN = "sanctuary.v1.session.challenge";

/**
 * Attestation references recorded into a session's claims and bound into the
 * challenge message. PR-A3 REPLACED the PR-A1 temporary `local-operator`
 * (dashboard-token-possession) reference with the durable references below;
 * the token-possession path is gone, not stacked (see
 * `session-service.ts` → `validateAttestation`).
 *
 * - {@link OPERATOR_ED25519_ATTESTATION_REF}: the caller presented a durable
 *   Ed25519 operator attestation — an operator-identity signature binding the
 *   ephemeral session client key. This is the SAME operator key custody that
 *   backs the OPERATOR_SIGNED write path (PR-A2 agents protect/unprotect), so
 *   opening a session and authorizing a write now trace to one operator key.
 * - {@link LOOPBACK_OPERATOR_ATTESTATION_REF}: a same-box caller on a daemon
 *   that enabled post-unlock loopback auto-auth. This is a network-POSITION
 *   signal, never a credential a remote caller can present — it is not the
 *   downgrade surface the token path was, because a same-box post-unlock
 *   attacker already holds strictly more than a session token grants.
 * - {@link AUTH_DISABLED_ATTESTATION_REF}: a same-box caller on a daemon with
 *   NO operator identity configured at all (legacy auth-disabled dev mode);
 *   loopback only, never a network caller.
 *
 * The init response echoes the recorded ref so the client signs the challenge
 * over the exact ref the daemon bound — no client-side guessing across paths.
 */
export const OPERATOR_ED25519_ATTESTATION_REF = "operator-ed25519";
export const LOOPBACK_OPERATOR_ATTESTATION_REF = "loopback-operator";
export const AUTH_DISABLED_ATTESTATION_REF = "auth-disabled-loopback";

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

/**
 * Build the exact byte string the client signs in `/v1/session/complete`
 * (RFC v7 §5.2 step 3: canonical(client_pubkey || challenge ||
 * attestation_ref) under a domain separator).
 */
export function buildChallengeMessage(
  clientPubkey: Uint8Array,
  challenge: Uint8Array,
  attestationRef: string,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_CHALLENGE_SIGNATURE_DOMAIN),
    lengthPrefixed(clientPubkey),
    lengthPrefixed(challenge),
    lengthPrefixed(encoder.encode(attestationRef)),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}
