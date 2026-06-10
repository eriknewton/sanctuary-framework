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
 * Attestation reference recorded for the PR-A1 local-operator bridge
 * attestation (the caller proved possession of the dashboard operator
 * credential rather than presenting a durable Ed25519 operator
 * attestation — those arrive with the federation authorize ceremony in
 * PR-A3 and will carry real attestation ids here).
 */
export const LOCAL_OPERATOR_ATTESTATION_REF = "local-operator";

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
