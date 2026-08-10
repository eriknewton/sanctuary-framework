/**
 * Sanctuary MCP Server — Handshake MCP Tools
 *
 * MCP tool definitions for the sovereignty handshake protocol.
 * Four tools map to the four protocol steps:
 *   1. handshake_initiate — Start a handshake
 *   2. handshake_respond — Respond to an incoming challenge
 *   3. handshake_complete — Complete a handshake (initiator side)
 *   4. handshake_status — Check status of handshake sessions
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { SanctuaryConfig } from "../config.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { AuditLog } from "../operational/audit-log.js";
import { BoundedMap } from "../core/bounded-map.js";
import { generateSHR, type SHRGeneratorOptions } from "../shr/generator.js";
import {
  sign as identitySign,
  publicKeyToDid,
  isLocallyHeldPublicKey,
} from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
  verifyCompletion,
  isSessionExpired,
  TERMINAL_SESSION_STATES,
} from "./protocol.js";
import {
  generateAttestation,
  verifyAttestation,
  type SignedAttestation,
} from "./attestation.js";
import {
  auditHandshakeAborted,
  auditHandshakeCompleted,
  auditHandshakeFailed,
  auditHandshakeInitiated,
  HANDSHAKE_LIFECYCLE_OPS,
  type HandshakeAbortReason,
  type HandshakeFailureReason,
} from "./audit.js";
import { verifySHR } from "../shr/verifier.js";
import type { SignedSHR } from "../shr/types.js";
import type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
  HandshakeResult,
  HandshakeSession,
} from "./types.js";

/**
 * In-memory session store cap. BOUNDED (register LD2-03): `handshake_initiate`
 * mints a session per call with zero counterparty input, and a session is
 * otherwise deleted only by `handshake_abort` — an agent that never aborts
 * grows the store without limit. Every 4-step handler sweeps expired/terminal
 * sessions off the top (mirrors #1190's pruneExpiredActivations placement,
 * see the sweep calls in createHandshakeTools) so the map is bounded to LIVE
 * sessions on the request path; this cap is the backstop for a burst that
 * outpaces the 120s TTL between sweeps.
 *
 * 500 = generous headroom over any realistic single-fortress concurrent
 * in-flight handshake count (a human-triggered, interactive protocol, not a
 * hot loop) while still bounding worst-case memory to ~500 session records.
 * Exported so the class-level bounded-collection inventory test can drive
 * the real production path to this exact cap without hardcoding it twice.
 */
export const MAX_HANDSHAKE_SESSIONS = 500;

/**
 * `handshakeResults` cap — shared with L4 tier resolution, federation
 * registration, and the dashboard. BOUNDED (register LD2-03): every
 * `handshake_exchange` call from an externally minted keypair adds a
 * permanent preview entry (verified:false), and src never deletes an entry,
 * so an unbounded stream of minted keys grows this map without limit.
 *
 * 1000 = headroom for a real fortress's peer + preview count (an order of
 * magnitude above a realistic federation peer list) while keeping the
 * capacity-refusal path reachable in an adversarial test without an
 * impractically long loop. Exported for the same reason as
 * MAX_HANDSHAKE_SESSIONS above.
 */
export const MAX_HANDSHAKE_RESULTS = 1000;

export interface HandshakeToolsOptions {
  /** If true, auto-publishes handshake attestations to Verascore after handshake_respond. */
  autoPublishHandshakes?: boolean;
  /** Verascore base URL to publish to. */
  verascoreUrl?: string;
}

export function createHandshakeTools(
  config: SanctuaryConfig,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog,
  options?: HandshakeToolsOptions
): {
  tools: ToolDefinition[];
  // Exposed to every consumer (federation, dashboard, reputation, bridge) as
  // a ReadonlyMap: recordHandshakeResult below is the ONLY writer, and MUST
  // stay the only writer, since it is the producer chokepoint the whole
  // self-vouch class is closed at (register §Z RECHECK). The type system
  // enforces this at every consumer call site; a consumer that needs to
  // mutate the map is a design error, not a cast to work around.
  handshakeResults: ReadonlyMap<string, HandshakeResult>;
} {
  const autoPublishHandshakes = options?.autoPublishHandshakes ?? false;
  const verascoreUrl = options?.verascoreUrl ?? "https://verascore.ai";
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");

  // In-memory session store (per server instance lifetime). Eviction policy:
  // drop the OLDEST session (first in Map insertion order — sessions are
  // only ever newly inserted, never re-inserted under the same key, so
  // insertion order tracks creation order) to admit a new one. This is safe
  // to do unconditionally: an evicted in-flight session simply fails its
  // next step with "No handshake session found," identical to what already
  // happens once its TTL expires — no trust state is lost, because a session
  // carries no trust until `recordHandshakeResult` writes it into
  // `handshakeResults`. See MAX_HANDSHAKE_SESSIONS above for the cap.
  const sessions = new BoundedMap<string, HandshakeSession>({
    maxSize: MAX_HANDSHAKE_SESSIONS,
    selectEviction: (entries) => {
      const oldest = entries.keys().next();
      // entries is non-empty whenever selectEviction runs (set() only
      // calls it when size >= maxSize > 0), so oldest.done is unreachable;
      // refuse defensively rather than evict a key that doesn't exist.
      if (oldest.done) return { refuse: true };
      return { evict: oldest.value };
    },
    onEvict: (evictedSessionId) => {
      void auditLog.append("l4", "handshake_session_evicted", "system", {
        session_id: evictedSessionId,
        reason: "capacity",
      });
    },
  });

  // Completed handshake results indexed by counterparty ID — shared with L4
  // tier resolution, federation registration, and the dashboard. Kept as a
  // mutable BoundedMap INTERNALLY (recordHandshakeResult is the only
  // function in this closure that calls .set on it); the return type above
  // widens it to ReadonlyMap for every external consumer. See
  // MAX_HANDSHAKE_RESULTS above for the cap.
  //
  // Eviction policy: evict the oldest entry that is NOT both verified AND
  // liveness_proven (a preview, or a failed/expired-tier entry) to admit a
  // new one; a genuinely verified && liveness_proven entry is NEVER evicted
  // — see recordHandshakeResult, which refuses the insert instead when no
  // unverified entry exists to make room. A full 4-step handshake IS
  // attacker-reachable too (the counterparty side is whatever process holds
  // the minted key, which the attacker controls end-to-end), so "only evict
  // previews" is not a loophole an attacker can route around by completing
  // the liveness proof; it just costs them a real round trip, and once the
  // map is saturated with verified entries the fortress fails closed
  // (refuses new entries) rather than flushing an established peer's trust
  // state — the same fail-closed trade-off federation/registry.ts makes for
  // active peers.
  const HANDSHAKE_RESULTS_SATURATED_ERROR =
    "Handshake result store is at capacity and every entry is a verified, " +
    "live peer; cannot record a new handshake result until one expires or " +
    "is superseded.";
  const handshakeResults = new BoundedMap<string, HandshakeResult>({
    maxSize: MAX_HANDSHAKE_RESULTS,
    selectEviction: (entries) => {
      for (const [key, value] of entries) {
        if (!value.verified || !value.liveness_proven) {
          return { evict: key };
        }
      }
      return { refuse: true };
    },
    onEvict: (evictedCounterpartyId, evictedResult) => {
      void auditLog.append("l4", "handshake_result_evicted", "system", {
        counterparty_id: evictedCounterpartyId,
        verified: evictedResult.verified,
        liveness_proven: evictedResult.liveness_proven,
        reason: "capacity",
      });
    },
  });

  const shrOpts: SHRGeneratorOptions = {
    config,
    identityManager,
    masterKey,
  };

  const SELF_VOUCH_ERROR =
    "Self-handshake rejected: an identity cannot verify another identity held by the same fortress";

  /**
   * Decode a base64url-encoded Ed25519 public key to raw bytes, or undefined
   * if it cannot be decoded. Every caller below uses the result ONLY to
   * REFUSE (never to grant trust), so a decode failure just skips the
   * refusal; a genuinely malformed key is already rejected elsewhere by SHR/
   * signature verification.
   */
  function tryDecodeSignerKey(signedByBase64url: string | undefined): Uint8Array | undefined {
    if (!signedByBase64url) return undefined;
    try {
      return fromBase64url(signedByBase64url);
    } catch {
      return undefined;
    }
  }

  /**
   * Derive the DID for a base64url-encoded Ed25519 public key, or undefined
   * if it cannot be decoded. INFORMATIONAL ONLY (audit-log readability) —
   * never use this for the local-identity TRUST decision; see
   * isLocallyHeldSignerKey / isLocallyHeldPublicKey below for why a DID
   * string is not safe to compare against a persisted identity's `.did`.
   */
  function tryDeriveDid(signedByBase64url: string | undefined): string | undefined {
    if (!signedByBase64url) return undefined;
    try {
      return publicKeyToDid(fromBase64url(signedByBase64url));
    } catch {
      return undefined;
    }
  }

  /**
   * Is `signerPublicKey` the raw signing key of an identity THIS fortress
   * currently holds? Computed FRESH via identityManager.list() on every call
   * (never cached at module-load or server-boot time), so an identity
   * created after startup is covered. Delegates to the shared
   * isLocallyHeldPublicKey predicate (core/identity.ts) — comparing DECODED
   * KEY BYTES, never a DID string, because a persisted identity's `.did` can
   * be in the legacy base64url encoding (see legacyPublicKeyToDid) while a
   * freshly-derived DID uses the canonical base58btc encoding; DID-string
   * equality silently fails to recognize a legacy-encoded local identity as
   * local (the #1194-class defect this guard exists to close).
   */
  function isLocallyHeldSignerKey(signerPublicKey: Uint8Array | undefined): boolean {
    return isLocallyHeldPublicKey(signerPublicKey, identityManager.list());
  }

  /**
   * CLASS-LEVEL SELF-VOUCH CHOKEPOINT (register §Z RECHECK / LD2-02, LD2-02b).
   *
   * `handshakeResults` is a SHARED SUBSTRATE: federation (peer registration),
   * the operator dashboard (handshake panel), and reputation/bridge tier
   * resolution all read from this ONE map. A poisoned entry that slips in
   * here is inherited as "verified" by every one of those consumers,
   * regardless of whether that consumer holds its own local-custody check
   * (neither federation nor the dashboard did — that was LD2-02 / LD2-02b).
   * Refusing the WRITE at the producer, rather than gating each consumer
   * separately, closes the whole class at once: no future consumer of this
   * map can be tricked by an entry that never exists.
   *
   * Every `handshakeResults.set(...)` in this file funnels through this one
   * function. A counterparty is "locally held" when its signing KEY BYTES
   * equal the key bytes of an identity THIS fortress currently holds
   * (isLocallyHeldSignerKey — compares decoded key material, never a DID
   * string; see that function's doc for the legacy-DID-encoding defect this
   * closes). The protocol-level `sameSigningKey()` guard (protocol.ts) only
   * rejects the degenerate case of an IDENTICAL key signing both sides of a
   * handshake; two DISTINCT locally-held keys (identity A handshaking
   * identity B, both created by the same operator) pass every
   * sameSigningKey check and are exactly the case this chokepoint closes.
   *
   * Also the SOLE writer for the bounded-collection guard (register
   * LD2-03): a refused insert (map at capacity, every existing entry
   * verified && liveness_proven) fails closed the same way a self-vouch
   * does — the caller gets an explicit refusal, never a silently-dropped
   * "success". `reason` on the failure branch lets callers audit the two
   * cases distinctly instead of collapsing them to one hardcoded label.
   */
  function recordHandshakeResult(
    result: HandshakeResult,
    auditIdentityId: string
  ): { ok: true } | { ok: false; error: string; reason: HandshakeFailureReason } {
    const counterpartyKey = tryDecodeSignerKey(result.counterparty_shr.signed_by);
    if (isLocallyHeldSignerKey(counterpartyKey)) {
      // counterparty_did here is derived ONLY for the audit trail's
      // readability; the trust decision above already ran on decoded key
      // bytes, never this string.
      const counterpartyDid = tryDeriveDid(result.counterparty_shr.signed_by);
      void auditLog.append(
        "l4",
        "handshake_self_vouch_blocked",
        auditIdentityId,
        {
          counterparty_id: result.counterparty_id,
          ...(counterpartyDid ? { counterparty_did: counterpartyDid } : {}),
        },
        "failure"
      );
      return { ok: false, error: SELF_VOUCH_ERROR, reason: "self_vouch_local_did" };
    }
    const inserted = handshakeResults.set(result.counterparty_id, result);
    if (!inserted) {
      void auditLog.append(
        "l4",
        "handshake_results_saturated",
        auditIdentityId,
        { counterparty_id: result.counterparty_id },
        "failure"
      );
      return {
        ok: false,
        error: HANDSHAKE_RESULTS_SATURATED_ERROR,
        reason: "handshake_results_saturated",
      };
    }
    return { ok: true };
  }

  /**
   * CLASS-LEVEL bounded-collection sweep (register LD2-03): run at the top
   * of every handler that touches `sessions`, mirroring #1190's
   * pruneExpiredActivations placement, so the map is bounded to LIVE
   * sessions on the request path, not only by the capacity cap.
   * `excludeSessionId` protects THIS call's own target session from being
   * swept before its expired/terminal state is classified and audited
   * below — sweeping it away here first would collapse a precise
   * "Handshake session expired" error into a generic "No handshake session
   * found," losing forensic signal for no bounding benefit (the session is
   * about to be read, and likely deleted, by this call either way).
   */
  function sweepExpiredSessions(excludeSessionId?: string): void {
    sessions.sweep(
      (session, sessionId) =>
        sessionId !== excludeSessionId &&
        (TERMINAL_SESSION_STATES.has(session.state) || isSessionExpired(session))
    );
  }

  const tools: ToolDefinition[] = [
    {
      name: "handshake_initiate",
      description:
        "Initiate a sovereignty handshake with a counterparty. " +
        "Generates a challenge containing this instance's signed SHR and a cryptographic nonce. " +
        "Send the returned challenge to the counterparty.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description:
              "Identity to use for the handshake. Defaults to primary identity.",
          },
        },
      },
      handler: async (args) => {
        sweepExpiredSessions();

        // Generate our SHR
        const shr = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }

        const { challenge, session } = initiateHandshake(shr);
        sessions.set(session.session_id, session);

        void auditLog.append("l4", "handshake_initiate", shr.body.instance_id);
        auditHandshakeInitiated(auditLog, {
          session_id: session.session_id,
          role: "initiator",
          identity_id: shr.body.instance_id,
        });

        return toolResult({
          session_id: session.session_id,
          challenge,
          instructions:
            "Send the 'challenge' object to the counterparty's sanctuary/handshake_respond tool. " +
            "When you receive their response, pass it to sanctuary/handshake_complete with this session_id.",
        });
      },
    },

    {
      name: "handshake_respond",
      description:
        "Respond to an incoming sovereignty handshake challenge. " +
        "Verifies the initiator's SHR, signs their nonce, and returns our SHR with a counter-nonce.",
      inputSchema: {
        type: "object",
        properties: {
          challenge: {
            type: "object",
            description: "The HandshakeChallenge received from the initiator.",
          },
          identity_id: {
            type: "string",
            description:
              "Identity to use for the response. Defaults to primary identity.",
          },
        },
        required: ["challenge"],
      },
      handler: async (args) => {
        sweepExpiredSessions();

        const challenge = args.challenge as unknown as HandshakeChallenge;

        // Generate our SHR
        const shr = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }

        // Class-level self-vouch chokepoint (see recordHandshakeResult):
        // refuse a challenge from a counterparty this fortress already holds
        // keys for, before ever generating a response or advancing any
        // session state. sameSigningKey() inside respondToHandshake only
        // rejects an IDENTICAL key on both sides; this is the earliest point
        // that can catch the case it cannot — two DISTINCT locally-held keys.
        // Compares decoded key bytes (isLocallyHeldSignerKey), never a DID
        // string — see that function's doc.
        if (isLocallyHeldSignerKey(tryDecodeSignerKey(challenge.shr?.signed_by))) {
          void auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: "unknown",
            role: "responder",
            identity_id: shr.body.instance_id,
            reason: "self_vouch_local_did",
            error: SELF_VOUCH_ERROR,
          });
          return toolResult({ error: SELF_VOUCH_ERROR });
        }

        const result = respondToHandshake(
          challenge,
          shr,
          identityManager,
          masterKey,
          args.identity_id as string | undefined
        );

        if ("error" in result) {
          void auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: "unknown",
            role: "responder",
            identity_id: shr.body.instance_id,
            reason: classifyRespondFailure(result.error),
            error: result.error,
          });
          return toolResult({ error: result.error });
        }

        sessions.set(result.session.session_id, result.session);

        void auditLog.append("l4", "handshake_respond", shr.body.instance_id);
        auditHandshakeInitiated(auditLog, {
          session_id: result.session.session_id,
          role: "responder",
          identity_id: shr.body.instance_id,
          counterparty_id: challenge.shr.body.instance_id,
        });

        // Auto-publish handshake attestation to Verascore (configurable).
        // This is a best-effort, non-blocking surface: failures are audit-logged
        // but do not break the handshake response.
        let autoPublishResult:
          | { attempted: boolean; ok?: boolean; status?: number; error?: string }
          | undefined;
        if (autoPublishHandshakes) {
          autoPublishResult = { attempted: true };
          try {
            // Only publish against https verascore hosts.
            const parsed = new URL(verascoreUrl);
            if (parsed.protocol !== "https:") {
              autoPublishResult.error = `verascore URL must use HTTPS (got ${parsed.protocol})`;
            } else {
              // DELTA-04: privacy. Without mutual explicit consent, strip
              // initiator-identifying fields from the published envelope.
              // We publish only the responder's own identity + opaque session id.
              const attestationPayload = {
                type: "handshake" as const,
                our_shr_signed_by: shr.signed_by,
                counterparty_signed_by: "redacted" as const,
                session_id: result.session.session_id,
                responded_at: new Date().toISOString(),
              };

              // DELTA-05: sign the publish payload with the responder's Ed25519
              // identity key so Verascore can verify it end-to-end.
              const responderIdentity = identityManager.get(shr.body.instance_id);
              if (!responderIdentity) {
                autoPublishResult.error =
                  `responder identity ${shr.body.instance_id} not found; skipping auto-publish`;
                void auditLog.append(
                  "l4",
                  "handshake_auto_publish",
                  shr.body.instance_id,
                  { error: autoPublishResult.error },
                  "failure"
                );
              } else {
                const payloadBytes = new TextEncoder().encode(
                  JSON.stringify(attestationPayload)
                );
                const sigBytes = identitySign(
                  payloadBytes,
                  responderIdentity.encrypted_private_key,
                  identityEncKey
                );
                const signatureB64 = toBase64url(sigBytes);

                const resp = await fetch(
                  `${verascoreUrl.replace(/\/$/, "")}/api/publish`,
                  {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      agentId: shr.body.instance_id,
                      publicKey: shr.signed_by,
                      signature: signatureB64,
                      type: "handshake",
                      data: attestationPayload,
                    }),
                  }
                );
                autoPublishResult.ok = resp.ok;
                autoPublishResult.status = resp.status;
                void auditLog.append(
                  "l4",
                  "handshake_auto_publish",
                  shr.body.instance_id,
                  {
                    verascore_url: verascoreUrl,
                    status: resp.status,
                    ok: resp.ok,
                  },
                  resp.ok ? "success" : "failure"
                );
              }
            }
          } catch (err) {
            autoPublishResult.error =
              err instanceof Error ? err.message : String(err);
            void auditLog.append(
              "l4",
              "handshake_auto_publish",
              shr.body.instance_id,
              { verascore_url: verascoreUrl, error: autoPublishResult.error },
              "failure"
            );
          }
        }

        return toolResult({
          session_id: result.session.session_id,
          response: result.response,
          instructions:
            "Send the 'response' object back to the initiator. " +
            "When you receive their completion, pass it to sanctuary/handshake_status with this session_id.",
          auto_publish: autoPublishResult,
          // SEC-ADD-03: Tag response — contains SHR data that will be sent to counterparty
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_complete",
      description:
        "Complete a sovereignty handshake (initiator side). " +
        "Verifies the responder's SHR and nonce signature, signs their nonce, and produces the final result.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID from handshake_initiate.",
          },
          response: {
            type: "object",
            description: "The HandshakeResponse received from the responder.",
          },
        },
        required: ["session_id", "response"],
      },
      handler: async (args) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const response = args.response as unknown as HandshakeResponse;

        const session = sessions.get(sessionId);
        if (!session) {
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: "unknown",
            reason: "session_unknown",
            error: `No handshake session found: ${sessionId}`,
          });
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        // HS-2: reject a session past its server-anchored TTL. Mark it
        // `expired` (single-use terminal) so the nonce can never be reused.
        if (isSessionExpired(session)) {
          session.state = "expired";
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_expired",
            error: "Handshake session expired",
          });
          return toolResult({ error: "Handshake session expired" });
        }
        // HS-2: single-use. Only a fresh `initiated` session can be completed;
        // any terminal/advanced state is spent and must not be reusable.
        if (session.state !== "initiated") {
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_state_mismatch",
            error: `Session is in state '${session.state}', expected 'initiated'`,
          });
          return toolResult({
            error: `Session is in state '${session.state}', expected 'initiated'`,
          });
        }

        const result = completeHandshake(
          response,
          session,
          identityManager,
          masterKey
        );

        if ("error" in result) {
          session.state = "failed";
          void auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id, undefined, "failure");
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            reason: classifyCompleteFailure(result.error),
            error: result.error,
          });
          return toolResult({ error: result.error });
        }

        // Class-level self-vouch chokepoint: refuse to RECORD (and therefore
        // to complete) when the responder's signing key belongs to an
        // identity this fortress already holds — the case sameSigningKey()
        // above cannot catch (two distinct locally-held keys). Reject before
        // the session is marked completed so the caller gets an explicit
        // refusal instead of a silently-unrecorded "success".
        const recorded = recordHandshakeResult(
          result.result,
          session.our_shr.body.instance_id
        );
        if (!recorded.ok) {
          session.state = "failed";
          void auditLog.append(
            "l4",
            "handshake_complete",
            session.our_shr.body.instance_id,
            undefined,
            "failure"
          );
          auditHandshakeFailed(auditLog, {
            session_id: sessionId,
            role: "initiator",
            identity_id: session.our_shr.body.instance_id,
            counterparty_id: result.result.counterparty_id,
            reason: recorded.reason,
            error: recorded.error,
          });
          return toolResult({ error: recorded.error });
        }

        session.state = "completed";
        session.their_shr = response.shr;
        session.their_nonce = response.responder_nonce;
        session.result = result.result;

        void auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id);
        auditHandshakeCompleted(auditLog, {
          session_id: sessionId,
          role: "initiator",
          identity_id: session.our_shr.body.instance_id,
          counterparty_id: result.result.counterparty_id,
          trust_tier: result.result.trust_tier,
        });

        return toolResult({
          completion: result.completion,
          result: result.result,
          instructions:
            "Send the 'completion' object to the responder so they can verify the handshake. " +
            "The 'result' object contains the verified counterparty status and trust tier.",
          // SEC-ADD-03: Tag response as containing counterparty-controlled SHR data
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_status",
      description:
        "Check the state of an in-flight handshake session by id, or (responder side) verify an initiator's completion message. Read-only; returns session phase and, for verification, the validated counterparty SHR result.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID to check.",
          },
          completion: {
            type: "object",
            description:
              "Optional: HandshakeCompletion from the initiator (responder-side verification).",
          },
        },
        required: ["session_id"],
      },
      handler: async (args) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const completion = args.completion as unknown as HandshakeCompletion | undefined;

        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }

        // HS-2: a completion against an expired session is rejected. Mark the
        // session `expired` (single-use terminal) before any verification so a
        // stale nonce cannot be reused. Only applies when actually verifying a
        // completion; bare status reads on an expired session still surface the
        // expired state below.
        if (
          completion &&
          session.role === "responder" &&
          !TERMINAL_SESSION_STATES.has(session.state) &&
          isSessionExpired(session)
        ) {
          session.state = "expired";
          auditHandshakeFailed(auditLog, {
            session_id: session.session_id,
            role: "responder",
            identity_id: session.our_shr.body.instance_id,
            reason: "session_expired",
            error: "Handshake session expired",
          });
          return toolResult({ error: "Handshake session expired" });
        }

        // If completion is provided, verify it (responder side).
        // The `state === "responded"` guard enforces single-use: once the
        // completion is verified the session advances to completed/failed and
        // can never be re-verified (replay of the completion message).
        if (completion && session.role === "responder" && session.state === "responded") {
          let result = verifyCompletion(completion, session);
          let recordFailure: { error: string; reason: HandshakeFailureReason } | undefined;

          // Class-level self-vouch / bounded-collection chokepoint: a
          // verified completion still must not be RECORDED when the
          // initiator's signing key belongs to an identity this fortress
          // already holds (reached only when sameSigningKey() in
          // protocol.ts already passed — the two distinct-local-keys case),
          // or when the shared results map is at capacity and every slot
          // already holds a verified peer (register LD2-03). Either way,
          // downgrade the returned result to unverified exactly as an
          // invalid nonce signature would, rather than silently reporting
          // verified:true for an entry that was never written.
          if (result.verified) {
            const recorded = recordHandshakeResult(
              result,
              session.our_shr.body.instance_id
            );
            if (!recorded.ok) {
              recordFailure = { error: recorded.error, reason: recorded.reason };
              result = {
                ...result,
                verified: false,
                trust_tier: "unverified",
                liveness_proven: false,
                errors: [...result.errors, recorded.error],
              };
            }
          }

          session.state = result.verified ? "completed" : "failed";
          session.result = result;

          void auditLog.append(
            "l4",
            "handshake_verify_completion",
            session.our_shr.body.instance_id,
            undefined,
            result.verified ? "success" : "failure"
          );
          if (result.verified) {
            auditHandshakeCompleted(auditLog, {
              session_id: session.session_id,
              role: "responder",
              identity_id: session.our_shr.body.instance_id,
              counterparty_id: result.counterparty_id,
              trust_tier: result.trust_tier,
            });
          } else {
            auditHandshakeFailed(auditLog, {
              session_id: session.session_id,
              role: "responder",
              identity_id: session.our_shr.body.instance_id,
              counterparty_id: result.counterparty_id,
              reason:
                recordFailure?.reason ??
                classifyCompleteFailure(result.errors.join("; ")),
              error: recordFailure?.error ?? result.errors.join("; "),
            });
          }

          return toolResult({ result });
        }

        // Otherwise just return session status
        return toolResult({
          session_id: session.session_id,
          role: session.role,
          state: session.state,
          initiated_at: session.initiated_at,
          result: session.result ?? null,
        });
      },
    },

    // ─── Streamlined Exchange ─────────────────────────────────────────

    {
      name: "handshake_exchange",
      description:
        "One-shot sovereignty exchange. Accepts a counterparty's signed SHR, verifies it, " +
        "generates our SHR, and produces a signed attestation artifact — all in a single call. " +
        "Returns a shareable attestation with human-readable summary. " +
        "Use this instead of the 4-step handshake protocol when you want a quick, " +
        "portable sovereignty verification (e.g., for social posting or async exchanges).",
      inputSchema: {
        type: "object",
        properties: {
          counterparty_shr: {
            type: "object",
            description:
              "The counterparty's signed SHR (SignedSHR object with body, signed_by, signature).",
          },
          identity_id: {
            type: "string",
            description:
              "Identity to use for the exchange. Defaults to primary identity.",
          },
        },
        required: ["counterparty_shr"],
      },
      handler: async (args) => {
        const counterpartySHR = args.counterparty_shr as unknown as SignedSHR;

        // 1. Generate our SHR
        const ourSHR = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof ourSHR === "string") {
          return toolResult({ error: ourSHR });
        }

        // 2. Verify counterparty's SHR
        const verificationResult = verifySHR(counterpartySHR);

        // 3. Generate signed attestation artifact
        const attestation = generateAttestation({
          attesterSHR: ourSHR,
          subjectSHR: counterpartySHR,
          verificationResult,
          mutual: false,
          identityManager,
          masterKey,
          identityId: args.identity_id as string | undefined,
        });

        if ("error" in attestation) {
          void auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id, undefined, "failure");
          return toolResult({ error: attestation.error });
        }

        // 4. Store as a handshake result for tier resolution.
        //
        // HS-1 / HS-2 fix: handshake_exchange is a STRUCTURAL PREVIEW ONLY.
        // It performs no nonce challenge-response, so it proves neither
        // counterparty key-control nor liveness — a captured SHR replays
        // directly. Therefore it must NEVER write a `verified:true` result or
        // a verified-sovereign / verified-degraded trust tier. It is barred
        // from producing any trust label above `unverified`. Trust-establishing
        // handshakes MUST go through the nonce-bearing 4-step protocol
        // (handshake_initiate → respond → complete), which is the only path
        // that can set liveness_proven:true.
        if (verificationResult.valid) {
          const sovereigntyLevel = verificationResult.sovereignty_level as
            | "full"
            | "degraded"
            | "minimal"
            | "unverified";

          // MEDIUM#3: a structural preview must never DOWNGRADE an already
          // established peer. If a verified / liveness-proven result already
          // exists for this counterparty (from the 4-step protocol), leave it
          // intact — otherwise a captured SHR replayed through the preview path
          // would silently demote a live peer (downgrade DoS).
          const existing = handshakeResults.get(
            verificationResult.counterparty_id
          );
          if (!existing || (!existing.verified && !existing.liveness_proven)) {
            // Class-level self-vouch chokepoint: even an unverified preview
            // entry is refused when it describes a counterparty this fortress
            // already holds keys for — funneled through the SAME shared
            // recordHandshakeResult() every other write site uses, so a
            // future consumer of this map never has to special-case
            // "preview" entries differently from "completed" ones.
            recordHandshakeResult(
              {
                counterparty_id: verificationResult.counterparty_id,
                counterparty_shr: counterpartySHR,
                verified: false,
                sovereignty_level: sovereigntyLevel,
                trust_tier: "unverified",
                completed_at: new Date().toISOString(),
                expires_at: verificationResult.expires_at,
                errors: [],
                liveness_proven: false,
              },
              ourSHR.body.instance_id
            );
          }
        }

        void auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id);

        return toolResult({
          attestation,
          our_shr: ourSHR,
          verification: {
            counterparty_valid: verificationResult.valid,
            counterparty_sovereignty: verificationResult.sovereignty_level,
            counterparty_id: verificationResult.counterparty_id,
            liveness_proven: false,
            trust_tier: "unverified",
            errors: verificationResult.errors,
            warnings: verificationResult.warnings,
          },
          instructions:
            "STRUCTURAL CHECK ONLY — counterparty liveness is NOT proven, so this " +
            "is not a verified peer and cannot be used for federation. " +
            "The 'attestation' object is a signed, portable sovereignty verification artifact. " +
            "Share it with the counterparty or post attestation.summary publicly. " +
            "The counterparty can verify the attestation signature using your public key. " +
            "Our SHR is included so the counterparty can perform their own verification of us. " +
            "To establish a trusted peer, use the 4-step handshake_initiate / handshake_respond / " +
            "handshake_complete protocol, which proves liveness via a nonce challenge.",
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_verify_attestation",
      description:
        "Verify a signed attestation artifact from another agent. " +
        "Checks the Ed25519 signature, temporal validity, and structural integrity.",
      inputSchema: {
        type: "object",
        properties: {
          attestation: {
            type: "object",
            description:
              "The SignedAttestation object to verify (body, signed_by, signature, summary).",
          },
        },
        required: ["attestation"],
      },
      handler: async (args) => {
        const attestation = args.attestation as unknown as SignedAttestation;

        const result = verifyAttestation(attestation);

        void auditLog.append(
          "l4",
          "handshake_verify_attestation",
          result.attester_id,
          undefined,
          result.valid ? "success" : "failure"
        );

        return toolResult({
          ...result,
          _content_trust: "external",
        });
      },
    },

    {
      name: "handshake_abort",
      description:
        "Abort an in-flight handshake session. Drops the session record and " +
        "appends a session-lifecycle audit entry (handshake_aborted) so the " +
        "operator can distinguish operator-cancelled, timed-out, and dropped " +
        "sessions from sessions that simply fell off the protocol path.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID returned from handshake_initiate / handshake_respond.",
          },
          reason: {
            type: "string",
            enum: [
              "operator_cancelled",
              "session_timeout",
              "transport_dropped",
              "shutdown",
              "other",
            ],
            description:
              "Why the session is being aborted. Defaults to 'operator_cancelled'.",
          },
        },
        required: ["session_id"],
      },
      handler: async (args) => {
        const sessionId = args.session_id as string;
        sweepExpiredSessions(sessionId);
        const reason = (args.reason as HandshakeAbortReason | undefined) ??
          "operator_cancelled";
        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        if (session.state === "completed") {
          return toolResult({
            error: `Session ${sessionId} already completed; abort is only valid for in-flight sessions`,
          });
        }
        sessions.delete(sessionId);
        auditHandshakeAborted(auditLog, {
          session_id: sessionId,
          role: session.role,
          identity_id: session.our_shr.body.instance_id,
          ...(session.their_shr
            ? { counterparty_id: session.their_shr.body.instance_id }
            : {}),
          reason,
        });
        return toolResult({
          aborted: true,
          session_id: sessionId,
          reason,
        });
      },
    },
  ];

  return { tools, handshakeResults: handshakeResults.asReadonlyMap() };
}

/**
 * Map a respondToHandshake error string onto the lifecycle-audit reason
 * enum. Errors are short, well-known strings produced by protocol.ts.
 */
function classifyRespondFailure(error: string): HandshakeFailureReason {
  if (error.includes("Unsupported protocol version")) return "protocol_version_unsupported";
  if (error.includes("SHR verification failed")) return "shr_invalid";
  if (error.includes("No identity available")) return "no_signing_identity";
  return "other";
}

/** Same shape as classifyRespondFailure for completeHandshake / verifyCompletion errors. */
function classifyCompleteFailure(error: string): HandshakeFailureReason {
  if (error.includes("Unsupported protocol version")) return "protocol_version_unsupported";
  if (error.includes("SHR verification failed") || error.includes("SHR")) return "shr_invalid";
  if (error.includes("nonce signature is invalid")) return "nonce_signature_invalid";
  if (error.includes("No identity available")) return "no_signing_identity";
  return "other";
}

// Re-export the lifecycle ops for downstream consumers (audit-query callers).
export { HANDSHAKE_LIFECYCLE_OPS };
