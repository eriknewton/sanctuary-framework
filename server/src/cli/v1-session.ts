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
 * keys exist only transiently in memory for signing). The long-lived
 * dashboard operator token rides INSIDE the ceremony's attestation body
 * exactly once; it is never sent as a bearer header to /v1 routes.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../core/identity.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import {
  buildChallengeMessage,
  LOCAL_OPERATOR_ATTESTATION_REF,
} from "../v1/ceremony.js";
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

/**
 * Open a /v1 session: init → sign challenge → complete.
 *
 * Throws DashboardRequestError (kind "network" when the daemon is
 * unreachable, "auth" when any ceremony step is denied) so callers map
 * directly onto the catalog CLI exit codes.
 */
export async function openV1Session(
  ctx?: DashboardRequestContext,
): Promise<V1Session> {
  const { publicKey, privateKey } = generateKeypair();
  try {
    const operatorToken = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
    // authToken: "" — the ceremony endpoints take the operator credential
    // in the attestation body, not as a bearer header.
    const ceremonyCtx: DashboardRequestContext = { ...ctx, authToken: "" };

    const init = (await dashboardRequest(
      "/v1/session/init",
      {
        method: "POST",
        body: JSON.stringify({
          client_pubkey: toBase64url(publicKey),
          operator_attestation: {
            type: "local_operator",
            ...(operatorToken ? { token: operatorToken } : {}),
          },
        }),
      },
      ceremonyCtx,
    )) as { challenge?: unknown; challenge_id?: unknown };

    if (
      typeof init.challenge !== "string" ||
      typeof init.challenge_id !== "string"
    ) {
      throw new DashboardRequestError(
        "session ceremony failed: daemon returned a malformed challenge",
        "auth",
      );
    }

    const message = buildChallengeMessage(
      publicKey,
      fromBase64url(init.challenge),
      LOCAL_OPERATOR_ATTESTATION_REF,
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
