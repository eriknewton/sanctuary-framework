/**
 * Publish a quickstart profile to Verascore.
 *
 * Envelope format matches server/src/reputation/tools.ts reputation_publish:
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

import { createRequire } from "node:module";

import { signBytes, type QuickstartIdentity } from "./identity.js";

/**
 * The package version, read from the shipped package.json (one directory up
 * from both `src/` and `dist/`) so the payload's `sanctuary_version` can never
 * drift from the published version. npm always includes package.json in the
 * tarball, so this read cannot miss in an installed copy.
 */
export const QUICKSTART_VERSION: string = (
  createRequire(import.meta.url)("../package.json") as { version: string }
).version;

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
    sanctuary_version: `quickstart-${QUICKSTART_VERSION}`,
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

/** The exact HTTP request quickstart would send, built before anything is sent. */
export interface PublishRequest {
  /** Absolute URL of Verascore's publish endpoint. */
  endpoint: string;
  /** Profile URL Verascore serves for this DID once published. */
  profileUrl: string;
  /** The JSON request body, byte-for-byte what `sendPublishRequest` POSTs. */
  body: {
    agentId: string;
    signature: string;
    publicKey: string;
    type: "shr";
    data: PublishPayload;
  };
}

/**
 * Build and sign the publish request without sending it.
 *
 * Built once and reused: the consent prompt shows this object and
 * `sendPublishRequest` sends the same object, so what the operator approved
 * is exactly what leaves the machine (the payload timestamp is fixed here,
 * not re-read at send time). The private key is used to sign and is not
 * part of the request.
 */
export function buildPublishRequest(
  identity: QuickstartIdentity,
  agentName: string,
  verascoreUrl: string,
): PublishRequest {
  const payload = buildPayload(identity, agentName);
  const agentId = didToAgentId(identity.did);

  // Sign canonical JSON of the payload (JSON.stringify matches server behavior).
  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const signature = signBytes(payloadBytes, identity.privateKey);

  const base = verascoreUrl.replace(/\/+$/, "");
  return {
    endpoint: `${base}/api/publish`,
    profileUrl: `${base}/agent/${encodeURIComponent(identity.did)}`,
    body: {
      agentId,
      signature,
      publicKey: identity.publicKey,
      type: "shr",
      data: payload,
    },
  };
}

/** POST a request built by `buildPublishRequest` to Verascore. */
export async function sendPublishRequest(
  request: PublishRequest,
): Promise<PublishResult> {
  const response = await fetch(request.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request.body),
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
    profileUrl: request.profileUrl,
  };
}

/**
 * Sign the payload and POST it to Verascore's /api/publish in one step.
 * Callers that need operator consent first use `buildPublishRequest`, show
 * the result, then `sendPublishRequest`.
 */
export async function publishProfile(
  identity: QuickstartIdentity,
  agentName: string,
  verascoreUrl: string,
): Promise<PublishResult> {
  return sendPublishRequest(
    buildPublishRequest(identity, agentName, verascoreUrl),
  );
}
