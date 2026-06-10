/**
 * /v1 session ceremony service (PR-A1).
 *
 * Implements the RFC v7 §5.2 challenge-response session-open ceremony and
 * the §5.3 opaque session-token format for the new `/v1` API surface:
 *
 *   POST /v1/session/init      → validate attestation, issue challenge
 *   POST /v1/session/complete  → verify client signature, mint token
 *
 * Security properties enforced here (each has a test that fails without
 * it in test/v1/session-ceremony.test.ts):
 *
 * - Challenges are single-use. A challenge id is consumed by the FIRST
 *   `complete` attempt against it, success or failure — replaying a
 *   completed ceremony or brute-forcing signatures against one challenge
 *   is impossible.
 * - Challenges expire (60s default). The challenge is the freshness
 *   anchor; the client needs no synchronized clock.
 * - Tokens are AES-256-GCM-encrypted claims under a daemon-process-local
 *   key (key_id || nonce || ciphertext, per RFC v7 §5.3). Tampering fails
 *   GCM authentication; tokens expire (30min default, no sliding renewal);
 *   tokens from a previous session generation are rejected after
 *   `rotateSessions()`.
 * - Every failure path returns the same generic denial to the caller.
 *   Nothing in a response or thrown error reveals WHICH check failed
 *   (CLAUDE.md constraint 7) and no private key material ever enters this
 *   module — only public keys and signatures (constraint 6).
 *
 * PR-A3 attestation: the credentialed path is a DURABLE Ed25519 operator
 * attestation — an operator-identity signature binding the caller's
 * ephemeral session client key, verified against the same operator public
 * key that gates OPERATOR_SIGNED writes (see `operator-attestation.ts`).
 * This REPLACED PR-A1's temporary `local_operator` bearer-token validator;
 * the token path is gone, not stacked, so a leaked bearer token can no
 * longer open a /v1 session (the replace-not-extend invariant). Two
 * non-credentialed paths remain, both network-POSITION gated, never a
 * secret a remote caller can present: a same-box caller on a daemon with
 * post-unlock loopback auto-auth, and a same-box caller on a daemon with no
 * operator identity configured at all (legacy auth-disabled dev mode). A
 * network caller that presents no valid operator attestation never gets a
 * challenge.
 */

import { randomBytes, randomUUID } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  buildChallengeMessage,
  OPERATOR_ED25519_ATTESTATION_REF,
  LOOPBACK_OPERATOR_ATTESTATION_REF,
  AUTH_DISABLED_ATTESTATION_REF,
} from "./ceremony.js";
import { verifyOperatorAttestation } from "./operator-attestation.js";

/** Challenge TTL (RFC v7 §5.2: 60 seconds). */
export const V1_CHALLENGE_TTL_MS = 60_000;
/** Session-token TTL (RFC v7 §5.4: 30 minutes hard, no sliding renewal). */
export const V1_SESSION_TOKEN_TTL_MS = 30 * 60_000;
/** Bound on outstanding unconsumed challenges (memory-exhaustion guard). */
const MAX_PENDING_CHALLENGES = 256;
/** AAD binding token ciphertexts to their purpose. */
const TOKEN_AAD = new TextEncoder().encode("sanctuary.v1.session-token");

/**
 * PR-A1 capability vocabulary. The canonical Wave 1 capability set is
 * catalog open question Q2 (pending Erik); until it is ratified, sessions
 * carry the single least-privilege capability the PR-A1 surface needs.
 */
export const V1_CAPABILITY_STATUS_READ = "status_read";

export interface V1SessionClaims {
  client_pubkey: string;
  attestation_ref: string;
  session_generation: number;
  issued_at: number;
  expires_at: number;
  capabilities: string[];
}

interface ChallengeRecord {
  challenge: Uint8Array;
  clientPubkey: Uint8Array;
  attestationRef: string;
  expiresAtMs: number;
}

export interface V1SessionAuthBridge {
  /**
   * The daemon operator identity's Ed25519 public key (32 bytes), or null
   * when no operator identity is configured. This is the SAME key the
   * OPERATOR_SIGNED write path resolves (PR-A2), so a durable operator
   * attestation and a signed write trace to one operator key. Null forces
   * the credentialed path closed (only the loopback dev path remains).
   */
  resolveOperatorPublicKey(): Uint8Array | null;
  /** Whether the boot path enabled loopback auto-auth (post-unlock). */
  isLoopbackAutoAuthEnabled(): boolean;
}

export interface V1SessionServiceOptions {
  auth: V1SessionAuthBridge;
  /** Injectable clock for expiry tests. */
  now?: () => number;
  challengeTtlMs?: number;
  tokenTtlMs?: number;
  /** Override the durable-attestation freshness window (tests). */
  attestationMaxAgeMs?: number;
}

export type V1InitResult =
  | {
      ok: true;
      challenge: string;
      challenge_id: string;
      expires_at: number;
      /** The attestation ref the daemon bound; the client signs over it. */
      attestation_ref: string;
    }
  | { ok: false };

export type V1CompleteResult =
  | { ok: true; session_token: string; expires_at: number; capabilities: string[] }
  | { ok: false };

export class V1SessionService {
  private readonly auth: V1SessionAuthBridge;
  private readonly now: () => number;
  private readonly challengeTtlMs: number;
  private readonly tokenTtlMs: number;
  private readonly attestationMaxAgeMs?: number;
  private readonly challenges = new Map<string, ChallengeRecord>();
  /** Daemon-process-local token keys, indexed by key_id (RFC v7 §5.3). */
  private readonly tokenKeys = new Map<number, Uint8Array>();
  private currentKeyId = 1;
  private sessionGeneration = 1;

  constructor(options: V1SessionServiceOptions) {
    this.auth = options.auth;
    this.now = options.now ?? Date.now;
    this.challengeTtlMs = options.challengeTtlMs ?? V1_CHALLENGE_TTL_MS;
    this.tokenTtlMs = options.tokenTtlMs ?? V1_SESSION_TOKEN_TTL_MS;
    this.attestationMaxAgeMs = options.attestationMaxAgeMs;
    // Process-local key; sessions intentionally do not survive a daemon
    // restart (clients re-run the ceremony — fail closed, never open).
    this.tokenKeys.set(this.currentKeyId, randomBytes(32));
  }

  /**
   * POST /v1/session/init. Returns a challenge only when the request
   * carries a valid client public key AND a valid operator attestation.
   * Every failure collapses to `{ ok: false }` — the router maps that to
   * one generic 401.
   */
  init(body: unknown, requestIsLoopback: boolean): V1InitResult {
    if (typeof body !== "object" || body === null) return { ok: false };
    const { client_pubkey, operator_attestation } = body as {
      client_pubkey?: unknown;
      operator_attestation?: unknown;
    };

    if (typeof client_pubkey !== "string") return { ok: false };
    let clientPubkey: Uint8Array;
    try {
      clientPubkey = fromBase64url(client_pubkey);
    } catch {
      return { ok: false };
    }
    if (clientPubkey.length !== 32) return { ok: false };

    // Attestation is validated AGAINST this client key: a durable operator
    // attestation binds the operator's signature to exactly this ephemeral
    // session key, so it cannot be replayed to authorize a different one.
    const attestationRef = this.validateAttestation(
      operator_attestation,
      clientPubkey,
      requestIsLoopback,
    );
    if (attestationRef === null) return { ok: false };

    this.evictExpiredChallenges();
    if (this.challenges.size >= MAX_PENDING_CHALLENGES) {
      // Refuse new ceremonies rather than evicting live ones an operator
      // may be mid-flight on (fail closed under pressure).
      return { ok: false };
    }

    const challenge = randomBytes(32);
    const challengeId = randomUUID();
    const expiresAtMs = this.now() + this.challengeTtlMs;
    this.challenges.set(challengeId, {
      challenge,
      clientPubkey,
      attestationRef,
      expiresAtMs,
    });

    return {
      ok: true,
      challenge: toBase64url(challenge),
      challenge_id: challengeId,
      expires_at: Math.floor(expiresAtMs / 1000),
      attestation_ref: attestationRef,
    };
  }

  /**
   * POST /v1/session/complete. The challenge record is consumed by this
   * attempt no matter the outcome (single-use). On Ed25519 verification
   * of the client's signature over the canonical ceremony message, mints
   * an opaque session token bound to the client key.
   */
  complete(body: unknown): V1CompleteResult {
    if (typeof body !== "object" || body === null) return { ok: false };
    const { challenge_id, client_signature } = body as {
      challenge_id?: unknown;
      client_signature?: unknown;
    };
    if (typeof challenge_id !== "string" || typeof client_signature !== "string") {
      return { ok: false };
    }

    const record = this.challenges.get(challenge_id);
    // Single-use: consume BEFORE verification so a failed attempt cannot
    // retry against the same challenge, and a success cannot be replayed.
    this.challenges.delete(challenge_id);
    if (!record) return { ok: false };
    if (this.now() > record.expiresAtMs) return { ok: false };

    let signature: Uint8Array;
    try {
      signature = fromBase64url(client_signature);
    } catch {
      return { ok: false };
    }
    if (signature.length !== 64) return { ok: false };

    const message = buildChallengeMessage(
      record.clientPubkey,
      record.challenge,
      record.attestationRef,
    );
    if (!verify(message, signature, record.clientPubkey)) {
      return { ok: false };
    }

    const issuedAtMs = this.now();
    const expiresAtMs = issuedAtMs + this.tokenTtlMs;
    const claims: V1SessionClaims = {
      client_pubkey: toBase64url(record.clientPubkey),
      attestation_ref: record.attestationRef,
      session_generation: this.sessionGeneration,
      issued_at: Math.floor(issuedAtMs / 1000),
      expires_at: Math.floor(expiresAtMs / 1000),
      capabilities: [V1_CAPABILITY_STATUS_READ],
    };

    return {
      ok: true,
      session_token: this.encryptToken(claims),
      expires_at: claims.expires_at,
      capabilities: [...claims.capabilities],
    };
  }

  /**
   * Validate a bearer session token. Returns the decrypted claims, or
   * null on ANY failure (malformed, unknown key id, tampered, expired,
   * stale session generation) — uniform by design (RFC v7 §5.3).
   */
  validateToken(token: string): V1SessionClaims | null {
    let raw: Uint8Array;
    try {
      raw = fromBase64url(token);
    } catch {
      return null;
    }
    // key_id (4) || nonce (12) || GCM ciphertext (>= 16-byte tag).
    if (raw.length < 4 + 12 + 16) return null;
    const keyId = new DataView(raw.buffer, raw.byteOffset).getUint32(0, false);
    const key = this.tokenKeys.get(keyId);
    if (!key) return null;
    const nonce = raw.slice(4, 16);
    const ciphertext = raw.slice(16);

    let claims: V1SessionClaims;
    try {
      const plaintext = gcm(key, nonce, TOKEN_AAD).decrypt(ciphertext);
      claims = JSON.parse(new TextDecoder().decode(plaintext)) as V1SessionClaims;
    } catch {
      return null;
    }

    if (typeof claims.expires_at !== "number") return null;
    if (Math.floor(this.now() / 1000) >= claims.expires_at) return null;
    if (claims.session_generation !== this.sessionGeneration) return null;
    if (!Array.isArray(claims.capabilities)) return null;
    return claims;
  }

  /**
   * Invalidate every outstanding session token by bumping the session
   * generation (RFC v7 §5.4 revocation primitive; the Tier 1
   * `/v1/federation/rotate-sessions` endpoint lands later in the stack).
   * Returns the new generation.
   */
  rotateSessions(): number {
    this.sessionGeneration += 1;
    return this.sessionGeneration;
  }

  // ── internals ──────────────────────────────────────────────────────

  /**
   * PR-A3 attestation validator — see module docblock. Returns the
   * attestation ref to bind into the ceremony, or null to deny. The order is
   * deliberate: the durable credentialed path is tried first and is the ONLY
   * path open to a network caller; the loopback paths are network-POSITION
   * gates that never inspect a caller-presented secret.
   */
  private validateAttestation(
    attestation: unknown,
    clientPubkey: Uint8Array,
    requestIsLoopback: boolean,
  ): string | null {
    const operatorKey = this.auth.resolveOperatorPublicKey();

    // 1. Durable Ed25519 operator attestation (the credentialed path that
    //    REPLACED the PR-A1 bearer-token validator). Open to any caller,
    //    loopback or network, that can present a fresh operator signature
    //    bound to this client key.
    if (
      operatorKey &&
      verifyOperatorAttestation({
        attestation,
        clientPubkey,
        resolvedOperatorPubkey: operatorKey,
        now: this.now(),
        maxAgeMs: this.attestationMaxAgeMs,
      })
    ) {
      return OPERATOR_ED25519_ATTESTATION_REF;
    }

    // 2. Same-box caller on a daemon with post-unlock loopback auto-auth.
    //    Network position, not a credential — a remote caller can never reach
    //    this, and a same-box post-unlock attacker already holds more than a
    //    session grants, so this is not the downgrade surface the token was.
    if (requestIsLoopback && this.auth.isLoopbackAutoAuthEnabled()) {
      return LOOPBACK_OPERATOR_ATTESTATION_REF;
    }

    // 3. Legacy auth-disabled dev mode: no operator identity configured at
    //    all. Loopback callers only; a network caller presenting nothing
    //    never gets a challenge.
    if (requestIsLoopback && operatorKey === null) {
      return AUTH_DISABLED_ATTESTATION_REF;
    }

    return null;
  }

  private encryptToken(claims: V1SessionClaims): string {
    const key = this.tokenKeys.get(this.currentKeyId)!;
    const nonce = randomBytes(12);
    const plaintext = new TextEncoder().encode(JSON.stringify(claims));
    const ciphertext = gcm(key, nonce, TOKEN_AAD).encrypt(plaintext);
    const out = new Uint8Array(4 + 12 + ciphertext.length);
    new DataView(out.buffer).setUint32(0, this.currentKeyId, false);
    out.set(nonce, 4);
    out.set(ciphertext, 16);
    return toBase64url(out);
  }

  private evictExpiredChallenges(): void {
    const now = this.now();
    for (const [id, record] of this.challenges) {
      if (now > record.expiresAtMs) this.challenges.delete(id);
    }
  }
}
