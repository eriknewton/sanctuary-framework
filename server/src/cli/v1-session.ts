/**
 * CLI-side /v1 session ceremony client (Federation PR-A1).
 *
 * Runs the RFC v7 §5.2 challenge-response ceremony against a Sanctuary
 * daemon through the dashboard-request seam (#432) and returns a
 * short-lived session token for subsequent /v1 calls.
 *
 * Key handling: the client keypair is EPHEMERAL — generated per
 * invocation, used to sign exactly one challenge, and the private key is
 * zeroed before this function returns (CLAUDE.md constraint 6: private
 * keys exist only transiently in memory for signing).
 *
 * PR-A3 attestation: the bearer-token attestation is gone. On a same-box
 * loopback daemon the ceremony needs no credential body (the daemon
 * vouches via post-unlock loopback auto-auth). A caller authorizing over
 * the network passes a durable Ed25519 operator attestation
 * (`operator_attestation`) built from the operator identity key. The daemon
 * echoes the attestation ref it bound; the client signs the challenge over
 * THAT exact ref (it now varies by auth path).
 */

import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../core/identity.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { buildChallengeMessage } from "../v1/ceremony.js";
import type { OperatorEd25519Attestation } from "../v1/operator-attestation.js";
import {
  dashboardRequest,
  DashboardRequestError,
  type DashboardRequestContext,
} from "./dashboard-request.js";

export interface V1Session {
  token: string;
  /** UNIX seconds. */
  expiresAt: number;
  capabilities: string[];
}

export interface OpenV1SessionOptions {
  /**
   * Durable Ed25519 operator attestation for an authenticated/remote call.
   * Omit on a same-box loopback daemon (auto-auth covers it). The attestation
   * MUST be bound to the client key this call generates, which the caller
   * cannot know in advance — so callers that need it pass a factory instead
   * (see {@link buildAttestation}).
   */
  buildAttestation?: (clientPubkey: Uint8Array) => OperatorEd25519Attestation;
}

/**
 * Open a /v1 session: init → sign challenge → complete.
 *
 * Throws DashboardRequestError (kind "network" when the daemon is
 * unreachable, "auth" when any ceremony step is denied) so callers map
 * directly onto the catalog CLI exit codes.
 */
export async function openV1Session(
  ctx?: DashboardRequestContext,
  options?: OpenV1SessionOptions,
): Promise<V1Session> {
  const { publicKey, privateKey } = generateKeypair();
  try {
    // authToken: "" — /v1 ceremony endpoints never take a bearer header.
    const ceremonyCtx: DashboardRequestContext = { ...ctx, authToken: "" };
    const attestation = options?.buildAttestation?.(publicKey);

    const init = (await dashboardRequest(
      "/v1/session/init",
      {
        method: "POST",
        body: JSON.stringify({
          client_pubkey: toBase64url(publicKey),
          ...(attestation ? { operator_attestation: attestation } : {}),
        }),
      },
      ceremonyCtx,
    )) as { challenge?: unknown; challenge_id?: unknown; attestation_ref?: unknown };

    if (
      typeof init.challenge !== "string" ||
      typeof init.challenge_id !== "string" ||
      typeof init.attestation_ref !== "string"
    ) {
      throw new DashboardRequestError(
        "session ceremony failed: daemon returned a malformed challenge",
        "auth",
      );
    }

    const message = buildChallengeMessage(
      publicKey,
      fromBase64url(init.challenge),
      init.attestation_ref,
    );
    const signature = ed25519.sign(message, privateKey);

    const complete = (await dashboardRequest(
      "/v1/session/complete",
      {
        method: "POST",
        body: JSON.stringify({
          challenge_id: init.challenge_id,
          client_signature: toBase64url(signature),
        }),
      },
      ceremonyCtx,
    )) as {
      session_token?: unknown;
      expires_at?: unknown;
      capabilities?: unknown;
    };

    if (typeof complete.session_token !== "string") {
      throw new DashboardRequestError(
        "session ceremony failed: daemon returned no session token",
        "auth",
      );
    }

    return {
      token: complete.session_token,
      expiresAt: typeof complete.expires_at === "number" ? complete.expires_at : 0,
      capabilities: Array.isArray(complete.capabilities)
        ? complete.capabilities.filter((c): c is string => typeof c === "string")
        : [],
    };
  } finally {
    privateKey.fill(0);
  }
}
