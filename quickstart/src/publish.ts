/**
 * Publish a quickstart profile to Verascore.
 *
 * Envelope format matches server/src/l4-reputation/tools.ts reputation_publish:
 *   {
 *     agentId: string,
 *     signature: string (base64url over JSON.stringify(data)),
 *     publicKey: string (base64url),
 *     type: string,
 *     data: object
 *   }
 *
 * Signature is computed over the UTF-8 bytes of JSON.stringify(data).
 */

import { signBytes, type QuickstartIdentity } from "./identity.js";

export interface PublishPayload {
  did: string;
  name: string;
  sanctuary_version: string;
  layers: {
    l1: string;
    l2: string;
    l3: string;
    l4: string;
  };
  timestamp: string;
}

export interface PublishResult {
  ok: boolean;
  status: number;
  body: unknown;
  profileUrl: string;
}

/**
 * Build the SHR-shaped payload for the quickstart profile.
 */
export function buildPayload(
  identity: QuickstartIdentity,
  agentName: string,
): PublishPayload {
  return {
    did: identity.did,
    name: agentName,
    sanctuary_version: "quickstart-0.1.0",
    layers: {
      l1: "partial",
      l2: "none",
      l3: "none",
      l4: "self-attested",
    },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Derive a Verascore-safe agentId from a DID. Matches the sanitization
 * logic in reputation_publish (replaces non-[a-zA-Z0-9-] with '-', lowercased).
 */
export function didToAgentId(did: string): string {
  return did.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
}

/**
 * Sign the payload and POST it to Verascore's /api/publish.
 */
export async function publishProfile(
  identity: QuickstartIdentity,
  agentName: string,
  verascoreUrl: string,
): Promise<PublishResult> {
  const payload = buildPayload(identity, agentName);
  const agentId = didToAgentId(identity.did);

  // Sign canonical JSON of the payload (JSON.stringify matches server behavior).
  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const signature = signBytes(payloadBytes, identity.privateKey);

  const requestBody = {
    agentId,
    signature,
    publicKey: identity.publicKey,
    type: "shr",
    data: payload,
  };

  const profileUrl = `${verascoreUrl.replace(/\/+$/, "")}/agent/${encodeURIComponent(identity.did)}`;

  const response = await fetch(`${verascoreUrl.replace(/\/+$/, "")}/api/publish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    body,
    profileUrl,
  };
}
