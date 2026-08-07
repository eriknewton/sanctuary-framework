/**
 * Sanctuary MCP Server — Sovereignty Handshake Protocol
 *
 * Core handshake logic: initiate, respond, complete.
 * Nonce-based challenge-response prevents replay attacks.
 * SHR signatures are verified at each step.
 */

import type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
  HandshakeResult,
  HandshakeSession,
  SovereigntyLevel,
  TrustTier,
} from "./types.js";
import type { SignedSHR } from "../shr/types.js";
import { verifySHR } from "../shr/verifier.js";
import { sign, verify } from "../core/identity.js";
import { toBase64url, fromBase64url, stringToBytes } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { IdentityManager } from "../cognitive/tools.js";

/**
 * Handshake session time-to-live, in milliseconds.
 *
 * HS-2 (replay) defense: a handshake nonce is only valid for a short window.
 * The window is anchored to the SERVER's own receipt/respond time
 * (`new Date()` when the session is created), NOT to any counterparty-supplied
 * timestamp such as `challenge.initiated_at` — a malicious initiator could set
 * `initiated_at` in the future to defeat the TTL. The handshake is an
 * interactive / relayed exchange, not human-paced, so 120 s is generous.
 */
export const HANDSHAKE_SESSION_TTL_MS = 120_000;

/** Terminal session states — a session in any of these is single-use-spent. */
export const TERMINAL_SESSION_STATES: ReadonlySet<HandshakeSession["state"]> =
  new Set(["completed", "failed", "expired"]);

/**
 * Compute the server-anchored expiry for a session created/advanced now.
 * @param now - current server time (defaults to new Date())
 */
export function sessionExpiry(now: Date = new Date()): string {
  return new Date(now.getTime() + HANDSHAKE_SESSION_TTL_MS).toISOString();
}

/**
 * Is the session past its server-anchored TTL?
 *
 * Fails closed (LOW#6): a session with a missing or unparseable expires_at is
 * treated as EXPIRED, not permissive. All sessions created by the current code
 * set a valid expires_at, so this is unreachable today — but any future session
 * persistence/migration that drops the field must not silently disable the TTL.
 */
export function isSessionExpired(
  session: HandshakeSession,
  now: Date = new Date()
): boolean {
  if (!session.expires_at) return true;
  const exp = new Date(session.expires_at);
  if (isNaN(exp.getTime())) return true;
  return now.getTime() > exp.getTime();
}

/** Generate a cryptographic nonce for handshake */
function generateNonce(): string {
  // 32 = 256 random bits. A handshake nonce is anti-replay material, not a key;
  // the width is chosen so collisions are infeasible, and it is unrelated to the
  // 32-byte Ed25519 key size it happens to share.
  const nonce = randomBytes(32);
  if (!nonce || nonce.length !== 32) {
    throw new Error("Nonce generation failed: randomBytes returned unexpected length");
  }
  return toBase64url(nonce);
}

/**
 * Step 1: Initiate a handshake.
 * Generates a challenge containing our SHR and a nonce.
 */
export function initiateHandshake(
  ourSHR: SignedSHR
): { challenge: HandshakeChallenge; session: HandshakeSession } {
  const nonce = generateNonce();
  const sessionId = toBase64url(randomBytes(16));
  const now = new Date();

  const challenge: HandshakeChallenge = {
    protocol_version: "1.0",
    shr: ourSHR,
    nonce,
    initiated_at: now.toISOString(),
  };

  const session: HandshakeSession = {
    session_id: sessionId,
    role: "initiator",
    state: "initiated",
    our_nonce: nonce,
    our_shr: ourSHR,
    initiated_at: challenge.initiated_at,
    // HS-2: expiry anchored to OUR server clock, never to a peer-supplied value.
    expires_at: sessionExpiry(now),
  };

  return { challenge, session };
}

/**
 * Step 2: Respond to a handshake challenge.
 * Verifies the initiator's SHR, signs their nonce, generates our nonce.
 */
export function respondToHandshake(
  challenge: HandshakeChallenge,
  ourSHR: SignedSHR,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  identityId?: string
): { response: HandshakeResponse; session: HandshakeSession } | { error: string } {
  // Validate protocol version
  if (challenge.protocol_version !== "1.0") {
    return { error: `Unsupported protocol version: ${challenge.protocol_version}` };
  }

  // Verify the initiator's SHR
  const shrResult = verifySHR(challenge.shr);
  if (!shrResult.valid) {
    return { error: `Initiator SHR verification failed: ${shrResult.errors.join(", ")}` };
  }

  // Resolve signing identity
  const identity = identityId
    ? identityManager.get(identityId)
    : identityManager.getDefault();

  if (!identity) {
    return { error: "No identity available for signing" };
  }

  // Sign the initiator's nonce (proves we received it, prevents replay)
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const nonceBytes = stringToBytes(challenge.nonce);
  const nonceSignature = sign(
    nonceBytes,
    identity.encrypted_private_key,
    encryptionKey
  );

  const responderNonce = generateNonce();
  const now = new Date();

  const response: HandshakeResponse = {
    protocol_version: "1.0",
    shr: ourSHR,
    responder_nonce: responderNonce,
    initiator_nonce_signature: toBase64url(nonceSignature),
    responded_at: now.toISOString(),
  };

  const session: HandshakeSession = {
    session_id: toBase64url(randomBytes(16)),
    role: "responder",
    state: "responded",
    our_nonce: responderNonce,
    their_nonce: challenge.nonce,
    our_shr: ourSHR,
    their_shr: challenge.shr,
    initiated_at: challenge.initiated_at,
    // HS-2: expiry anchored to OUR receipt time, NOT challenge.initiated_at
    // (which the initiator controls and could set in the future).
    expires_at: sessionExpiry(now),
  };

  return { response, session };
}

/**
 * Step 3: Complete the handshake (initiator side).
 * Verifies the responder's SHR and nonce signature, signs responder's nonce.
 */
export function completeHandshake(
  response: HandshakeResponse,
  session: HandshakeSession,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  identityId?: string
): { completion: HandshakeCompletion; result: HandshakeResult } | { error: string } {
  // Validate protocol version
  if (response.protocol_version !== "1.0") {
    return { error: `Unsupported protocol version: ${response.protocol_version}` };
  }

  // Verify the responder's SHR
  const shrResult = verifySHR(response.shr);
  if (!shrResult.valid) {
    return { error: `Responder SHR verification failed: ${shrResult.errors.join(", ")}` };
  }

  // HS-3 liveness gate: this is the initiator-side trust-upgrade boundary.
  // SHR validity alone proves only that the SHR is well signed; the responder
  // earns verified:true / liveness_proven:true only after signing OUR session
  // nonce with the key named by response.shr.signed_by. Do not move either
  // trust flag above this check.
  const responderPublicKey = fromBase64url(response.shr.signed_by);
  const ourNonceBytes = stringToBytes(session.our_nonce);
  const nonceSignatureBytes = fromBase64url(response.initiator_nonce_signature);

  const nonceSignatureValid = verify(
    ourNonceBytes,
    nonceSignatureBytes,
    responderPublicKey
  );
  if (!nonceSignatureValid) {
    return { error: "Responder's nonce signature is invalid — possible replay or MITM" };
  }

  // Resolve our signing identity
  const identity = identityId
    ? identityManager.get(identityId)
    : identityManager.getDefault();

  if (!identity) {
    return { error: "No identity available for signing" };
  }

  // Sign the responder's nonce
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const responderNonceBytes = stringToBytes(response.responder_nonce);
  const responderNonceSignature = sign(
    responderNonceBytes,
    identity.encrypted_private_key,
    encryptionKey
  );

  const now = new Date().toISOString();

  const completion: HandshakeCompletion = {
    protocol_version: "1.0",
    responder_nonce_signature: toBase64url(responderNonceSignature),
    completed_at: now,
  };

  // Determine sovereignty level and trust tier
  const sovereigntyLevel = shrResult.sovereignty_level as SovereigntyLevel;
  const trustTier = deriveTrustTier(sovereigntyLevel);

  const result: HandshakeResult = {
    counterparty_id: shrResult.counterparty_id,
    counterparty_shr: response.shr,
    verified: true,
    sovereignty_level: sovereigntyLevel,
    trust_tier: trustTier,
    completed_at: now,
    expires_at: shrResult.expires_at,
    errors: [],
    // 4-step path: reached only after the responder's nonce signature
    // verified against signed_by — key-control + liveness are proven.
    liveness_proven: true,
  };

  return { completion, result };
}

/**
 * Step 4: Verify completion (responder side).
 * Verifies the initiator signed our nonce correctly.
 */
export function verifyCompletion(
  completion: HandshakeCompletion,
  session: HandshakeSession
): HandshakeResult {
  // Validate protocol version (runtime guard for untrusted input)
  if ((completion as { protocol_version: string }).protocol_version !== "1.0") {
    return {
      counterparty_id: "unknown",
      counterparty_shr: session.our_shr,
      verified: false,
      sovereignty_level: "unverified",
      trust_tier: "unverified",
      completed_at: completion.completed_at,
      expires_at: new Date().toISOString(),
      errors: [`Unsupported protocol version: ${(completion as { protocol_version: string }).protocol_version}`],
      liveness_proven: false,
    };
  }

  const errors: string[] = [];

  if (!session.their_shr) {
    return {
      counterparty_id: "unknown",
      counterparty_shr: session.our_shr, // placeholder
      verified: false,
      sovereignty_level: "unverified",
      trust_tier: "unverified",
      completed_at: completion.completed_at,
      expires_at: new Date().toISOString(),
      errors: ["No initiator SHR in session state"],
      liveness_proven: false,
    };
  }

  // HS-3 responder-side mirror: the responder marks the handshake verified
  // only if the initiator signs OUR responder nonce. Do not derive `verified`,
  // trust_tier, or liveness_proven from SHR validity alone.
  const initiatorPublicKey = fromBase64url(session.their_shr.signed_by);
  const ourNonceBytes = stringToBytes(session.our_nonce);
  const nonceSignatureBytes = fromBase64url(completion.responder_nonce_signature);

  const nonceSignatureValid = verify(
    ourNonceBytes,
    nonceSignatureBytes,
    initiatorPublicKey
  );

  if (!nonceSignatureValid) {
    errors.push("Initiator's nonce signature is invalid — possible replay or MITM");
  }

  // Verify the initiator's SHR (may have been verified earlier, but check expiry)
  const shrResult = verifySHR(session.their_shr);
  if (!shrResult.valid) {
    errors.push(...shrResult.errors);
  }

  const verified = errors.length === 0;
  const sovereigntyLevel: SovereigntyLevel = verified
    ? (shrResult.sovereignty_level as SovereigntyLevel)
    : "unverified";

  return {
    counterparty_id: session.their_shr.body.instance_id,
    counterparty_shr: session.their_shr,
    verified,
    sovereignty_level: sovereigntyLevel,
    trust_tier: deriveTrustTier(sovereigntyLevel),
    completed_at: completion.completed_at,
    expires_at: session.their_shr.body.expires_at,
    errors,
    // Responder side: reached only after the initiator's nonce signature over
    // OUR nonce verified — liveness is proven exactly when verified.
    liveness_proven: verified,
  };
}

/**
 * Derive trust tier from sovereignty level.
 */
function deriveTrustTier(level: SovereigntyLevel): TrustTier {
  switch (level) {
    case "full":
      return "verified-sovereign";
    case "degraded":
      return "verified-degraded";
    default:
      return "unverified";
  }
}
