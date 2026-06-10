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
 * PR-A1 attestation bridge: durable Ed25519 operator attestations are
 * issued by the federation authorize ceremony (PR-A3). Until then the
 * only accepted attestation type is `local_operator`: proof of possession
 * of the dashboard operator credential (the bearer auth token), or a
 * loopback call when the boot path enabled loopback auto-auth after a
 * successful master-key unlock. This is the SAME trust decision the
 * existing `/api/*` surface makes; the ceremony adds key binding,
 * single-use freshness, and short-lived capability-scoped tokens on top.
 * When no operator credential is configured at all, only loopback callers
 * may open sessions — the /v1 surface never serves a network caller that
 * presented nothing.
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { gcm } from "@noble/ciphers/aes.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  buildChallengeMessage,
  LOCAL_OPERATOR_ATTESTATION_REF,
} from "./ceremony.js";

/** Challenge TTL (RFC v7 §5.2: 60 seconds). */
export const V1_CHALLENGE_TTL_MS = 60_000;
/** Session-token TTL (RFC v7 §5.4: 30 minutes hard, no sliding renewal). */
export const V1_SESSION_TOKEN_TTL_MS = 30 * 60_000;
/** Bound on outstanding unconsumed challenges (memory-exhaustion guard). */
const MAX_PENDING_CHALLENGES = 256;
/** AAD binding token ciphertexts to their purpose. */
const TOKEN_AAD = new TextEncoder().encode("sanctuary.v1.session-token");
/**
 * Per-process random key for constant-shape operator-token comparison.
 * Never persisted, never exported — it exists only so the two HMAC
 * digests below are unpredictable to a caller while remaining
 * comparable to each other within this process.
 */
const TOKEN_COMPARE_KEY = randomBytes(32);

/**
 * Constant-shape secret comparison (codex review finding 1).
 *
 * A naive `length === length && timingSafeEqual(...)` gate only performs
 * the constant-time comparison for same-length candidates, which leaks
 * the configured token's byte length as a timing oracle. Instead, both
 * sides are compressed to fixed-size 32-byte HMAC-SHA256 digests under a
 * per-process random key, then compared with `timingSafeEqual`. Every
 * candidate — any length, any content — executes the identical
 * comparison work, so neither length nor prefix information is
 * observable through timing.
 */
export function constantShapeTokenEqual(presented: string, configured: string): boolean {
  const a = createHmac("sha256", TOKEN_COMPARE_KEY).update(presented, "utf-8").digest();
  const b = createHmac("sha256", TOKEN_COMPARE_KEY).update(configured, "utf-8").digest();
  return timingSafeEqual(a, b);
}

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
  /** The dashboard operator bearer token, when one is configured. */
  getAuthToken(): string | undefined;
  /** Whether the boot path enabled loopback auto-auth (post-unlock). */
  isLoopbackAutoAuthEnabled(): boolean;
}

export interface V1SessionServiceOptions {
  auth: V1SessionAuthBridge;
  /** Injectable clock for expiry tests. */
  now?: () => number;
  challengeTtlMs?: number;
  tokenTtlMs?: number;
}

export type V1InitResult =
  | { ok: true; challenge: string; challenge_id: string; expires_at: number }
  | { ok: false };

export type V1CompleteResult =
  | { ok: true; session_token: string; expires_at: number; capabilities: string[] }
  | { ok: false };

export class V1SessionService {
  private readonly auth: V1SessionAuthBridge;
  private readonly now: () => number;
  private readonly challengeTtlMs: number;
  private readonly tokenTtlMs: number;
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

    const attestationRef = this.validateAttestation(
      operator_attestation,
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
   * PR-A1 attestation bridge — see module docblock. Returns the
   * attestation ref to bind into the ceremony, or null to deny.
   */
  private validateAttestation(
    attestation: unknown,
    requestIsLoopback: boolean,
  ): string | null {
    if (typeof attestation !== "object" || attestation === null) return null;
    const { type, token } = attestation as { type?: unknown; token?: unknown };
    if (type !== "local_operator") return null;

    const configured = this.auth.getAuthToken();
    if (configured !== undefined && configured !== "" && typeof token === "string") {
      // Constant-shape comparison: identical work for every candidate
      // regardless of length (no configured-token-length timing oracle).
      if (constantShapeTokenEqual(token, configured)) {
        return LOCAL_OPERATOR_ATTESTATION_REF;
      }
    }
    if (requestIsLoopback && this.auth.isLoopbackAutoAuthEnabled()) {
      return LOCAL_OPERATOR_ATTESTATION_REF;
    }
    // No operator credential configured at all (legacy auth-disabled
    // mode): loopback callers only. A network caller with nothing to
    // present never gets a challenge.
    if (
      requestIsLoopback &&
      (configured === undefined || configured === "")
    ) {
      return LOCAL_OPERATOR_ATTESTATION_REF;
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
