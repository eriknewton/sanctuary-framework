/**
 * Sanctuary WP-V1.x-RECOGNITION-LAYER Path C hosted-alternative route.
 *
 * HTTP handler that serves `GET /:operator_handle/.well-known/did.json`
 * from the Sanctuary endpoint at `identity.sanctuaryprotocol.ai/<handle>/`.
 *
 * Operators without their own domain register their handle via the CLI
 * (`sanctuary did-web register-hosted <handle>`); this route serves the
 * DID Document they published at registration time.
 *
 * Castle-walking: read-only. Serves only operator-signed content. No
 * mutation surface for unauthorized parties. Operator signing key never
 * leaves the castle.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { StorageBackend } from "../storage/interface.js";
import { DID_WEB_AUDIT_OPS } from "./did-web.js";
import { DidWebHostedRegistry } from "./did-web-hosted-registry.js";

/**
 * Extended audit ops for hosted did:web resolution. Adds the
 * HOSTED_DID_RESOLVED op alongside the existing DID_WEB_AUDIT_OPS.
 */
export const HOSTED_DID_WEB_AUDIT_OPS = {
  ...DID_WEB_AUDIT_OPS,
  HOSTED_DID_RESOLVED: "did_web_hosted_resolved",
} as const;

export type HostedDidWebAuditOp =
  (typeof HOSTED_DID_WEB_AUDIT_OPS)[keyof typeof HOSTED_DID_WEB_AUDIT_OPS];

export interface HostedDidWebRouteOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
  now?: () => Date;
  onAudit?: (op: string, detail: Record<string, unknown>) => void;
}

/**
 * Pattern: `/<handle>/.well-known/did.json`
 * Captures the operator handle from the URL path.
 */
const HOSTED_DID_PATH_RE = /^\/([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)\/.well-known\/did\.json$/;

/**
 * Handle a hosted did:web resolution request. Returns true if the
 * request was handled (even if 404), false if the URL does not match
 * the hosted did:web pattern and should be passed to other handlers.
 */
export async function handleHostedDidWebRoute(
  opts: HostedDidWebRouteOptions,
  _req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  if (method !== "GET") return false;

  const match = HOSTED_DID_PATH_RE.exec(url.pathname);
  if (!match) return false;

  const handle = match[1]!;
  const registry = new DidWebHostedRegistry({
    storage: opts.storage,
    masterKey: opts.masterKey,
    fortressId: opts.fortressId,
    now: opts.now,
  });

  const entry = await registry.get(handle);
  if (!entry) {
    // Registry miss, corruption, or wrong-fortress ciphertext all return 404, so the route never serves unverified fallback data.
    res.writeHead(404, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    res.end(JSON.stringify({ error: "not_found", handle }));
    return true;
  }

  if (opts.onAudit) {
    // The audit event is emitted only after registry validation returns an entry, so resolution provenance names served content.
    opts.onAudit(HOSTED_DID_WEB_AUDIT_OPS.HOSTED_DID_RESOLVED, {
      operator_handle: handle,
      did: entry.did_document.id,
    });
  }

  const body = JSON.stringify(entry.did_document);
  res.writeHead(200, {
    "Content-Type": "application/did+json; charset=utf-8",
    "Cache-Control": "public, max-age=300, must-revalidate",
    "Content-Length": Buffer.byteLength(body, "utf-8").toString(),
  });
  res.end(body);
  return true;
}
