/**
 * /v1 shared HTTP primitives (PR-A2).
 *
 * Extracted so every /v1 module — the router skeleton (PR-A1) and the
 * agents handler (PR-A2) — emits byte-identical denial bodies from ONE
 * source of truth. The uniform, constant-shape denial is a security
 * invariant (CLAUDE.md constraint 7; PR-A1 codex finding 3): a caller must
 * not be able to tell WHICH check failed from the response body, so the
 * denial helpers live here and nowhere else.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

/** Request bodies above this size are rejected before parsing. */
export const MAX_BODY_BYTES = 16 * 1024;

export function writeJson(
  res: ServerResponse,
  status: number,
  payload: unknown,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

/** One generic denial for every authentication failure. */
export function denyUnauthorized(res: ServerResponse): void {
  writeJson(res, 401, { error: "unauthorized" });
}

/**
 * One generic denial for every authorization failure — a valid session
 * that lacks the required capability OR fails operator-signature
 * verification. Every failure reason collapses to this same body so that
 * "missing signature", "bad signature", and "no operator identity
 * configured" are indistinguishable to the caller.
 */
export function denyForbidden(res: ServerResponse): void {
  writeJson(res, 403, { error: "forbidden" });
}

/** Generic not-found, only reachable by an authenticated caller. */
export function denyNotFound(res: ServerResponse): void {
  writeJson(res, 404, { error: "not found" });
}

/**
 * Read and JSON-parse a bounded request body. Returns `undefined` on an
 * empty body, a body over the supplied cap, or invalid JSON — the
 * caller decides how to map `undefined` (the ceremony endpoints collapse
 * it into the generic 401; the agent write endpoints treat it as a 400
 * bad-request because the caller is already authenticated).
 */
export async function readJsonBody(
  req: IncomingMessage,
  maxBodyBytes = MAX_BODY_BYTES,
): Promise<unknown | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBodyBytes) return undefined;
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf-8");
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}
