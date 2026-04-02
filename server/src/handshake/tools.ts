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
import {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
  verifyCompletion,
} from "./protocol.js";
import {
  generateAttestation,
  verifyAttestation,
  type SignedAttestation,
} from "./attestation.js";
import { verifySHR } from "../shr/verifier.js";
import type { SignedSHR } from "../shr/types.js";
import type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
  HandshakeResult,
  HandshakeSession,
} from "./types.js";

export function createHandshakeTools(
  config: SanctuaryConfig,
  identityManager: IdentityManager,
  masterKey: Uint8Array,
  auditLog: AuditLog
): { tools: ToolDefinition[]; handshakeResults: Map<string, HandshakeResult> } {
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
      name: "sanctuary/handshake_initiate",
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

        auditLog.append("l4", "handshake_initiate", shr.body.instance_id);

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
      name: "sanctuary/handshake_respond",
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
          auditLog.append("l4", "handshake_respond", shr.body.instance_id, undefined, "failure");
          return toolResult({ error: result.error });
        }

        sessions.set(result.session.session_id, result.session);

        auditLog.append("l4", "handshake_respond", shr.body.instance_id);

        return toolResult({
          session_id: result.session.session_id,
          response: result.response,
          instructions:
            "Send the 'response' object back to the initiator. " +
            "When you receive their completion, pass it to sanctuary/handshake_status with this session_id.",
          // SEC-ADD-03: Tag response — contains SHR data that will be sent to counterparty
          _content_trust: "external",
        });
      },
    },

    {
      name: "sanctuary/handshake_complete",
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
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        if (session.state !== "initiated") {
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
          auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id, undefined, "failure");
          return toolResult({ error: result.error });
        }

        session.state = "completed";
        session.their_shr = response.shr;
        session.their_nonce = response.responder_nonce;
        session.result = result.result;

        // Store completed result for tier resolution
        handshakeResults.set(result.result.counterparty_id, result.result);

        auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id);

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
      name: "sanctuary/handshake_status",
      description:
        "Check the status of a handshake session, or verify a completion message (responder side).",
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

        // If completion is provided, verify it (responder side)
        if (completion && session.role === "responder" && session.state === "responded") {
          const result = verifyCompletion(completion, session);
          session.state = result.verified ? "completed" : "failed";
          session.result = result;

          // Store completed result for tier resolution
          if (result.verified) {
            handshakeResults.set(result.counterparty_id, result);
          }

          auditLog.append(
            "l4",
            "handshake_verify_completion",
            session.our_shr.body.instance_id,
            undefined,
            result.verified ? "success" : "failure"
          );

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
      name: "sanctuary/handshake_exchange",
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
          auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id, undefined, "failure");
          return toolResult({ error: attestation.error });
        }

        // 4. Store as a handshake result for tier resolution
        if (verificationResult.valid) {
          const sovereigntyLevel = verificationResult.sovereignty_level as
            | "full"
            | "degraded"
            | "minimal"
            | "unverified";
          const trustTier =
            sovereigntyLevel === "full"
              ? "verified-sovereign"
              : sovereigntyLevel === "degraded"
                ? "verified-degraded"
                : "unverified";

          handshakeResults.set(verificationResult.counterparty_id, {
            counterparty_id: verificationResult.counterparty_id,
            counterparty_shr: counterpartySHR,
            verified: true,
            sovereignty_level: sovereigntyLevel,
            trust_tier: trustTier as "verified-sovereign" | "verified-degraded" | "unverified",
            completed_at: new Date().toISOString(),
            expires_at: verificationResult.expires_at,
            errors: [],
          });
        }

        auditLog.append("l4", "handshake_exchange", ourSHR.body.instance_id);

        return toolResult({
          attestation,
          our_shr: ourSHR,
          verification: {
            counterparty_valid: verificationResult.valid,
            counterparty_sovereignty: verificationResult.sovereignty_level,
            counterparty_id: verificationResult.counterparty_id,
            errors: verificationResult.errors,
            warnings: verificationResult.warnings,
          },
          instructions:
            "The 'attestation' object is a signed, portable sovereignty verification artifact. " +
            "Share it with the counterparty or post attestation.summary publicly. " +
            "The counterparty can verify the attestation signature using your public key. " +
            "Our SHR is included so the counterparty can perform their own verification of us.",
          _content_trust: "external",
        });
      },
    },

    {
      name: "sanctuary/handshake_verify_attestation",
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

        auditLog.append(
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
  ];

  return { tools, handshakeResults };
}
