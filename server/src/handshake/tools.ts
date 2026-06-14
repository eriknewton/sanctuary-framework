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
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { generateSHR, type SHRGeneratorOptions } from "../shr/generator.js";
import { sign as identitySign } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { toBase64url } from "../core/encoding.js";
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
): { tools: ToolDefinition[]; handshakeResults: Map<string, HandshakeResult> } {
  const autoPublishHandshakes = options?.autoPublishHandshakes ?? false;
  const verascoreUrl = options?.verascoreUrl ?? "https://verascore.ai";
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  // In-memory session store (per server instance lifetime)
  const sessions = new Map<string, HandshakeSession>();
  // Completed handshake results indexed by counterparty ID — shared with L4 tier resolution
  const handshakeResults = new Map<string, HandshakeResult>();

  const shrOpts: SHRGeneratorOptions = {
    config,
    identityManager,
    masterKey,
  };

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
        const challenge = args.challenge as unknown as HandshakeChallenge;

        // Generate our SHR
        const shr = generateSHR(args.identity_id as string | undefined, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
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

        session.state = "completed";
        session.their_shr = response.shr;
        session.their_nonce = response.responder_nonce;
        session.result = result.result;

        // Store completed result for tier resolution
        handshakeResults.set(result.result.counterparty_id, result.result);

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
          const result = verifyCompletion(completion, session);
          session.state = result.verified ? "completed" : "failed";
          session.result = result;

          // Store completed result for tier resolution
          if (result.verified) {
            handshakeResults.set(result.counterparty_id, result);
          }

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
              reason: classifyCompleteFailure(result.errors.join("; ")),
              error: result.errors.join("; "),
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
            handshakeResults.set(verificationResult.counterparty_id, {
              counterparty_id: verificationResult.counterparty_id,
              counterparty_shr: counterpartySHR,
              verified: false,
              sovereignty_level: sovereigntyLevel,
              trust_tier: "unverified",
              completed_at: new Date().toISOString(),
              expires_at: verificationResult.expires_at,
              errors: [],
              liveness_proven: false,
            });
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

  return { tools, handshakeResults };
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
