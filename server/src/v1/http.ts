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

/**
 * The generic 403, plus an opaque per-request correlation id.
 *
 * OPERATOR DIAGNOSABILITY, WITHOUT AN ORACLE (F-FED-OPAQUEDENY, 2026-07-31).
 * On a pre-session route the caller is an operator's own machine that gets one
 * undifferentiated "forbidden" while the server audits the precise cause. That
 * is correct for security and terrible for the operator: a two-machine drill
 * burned ~an hour on it, twice. This helper hands back a correlation id the
 * operator can look up in the SERVER's audit log (`sanctuary audit search
 * --request-id <id>`), so the reason is retrievable BY SOMEONE WHO CAN ALREADY
 * READ THE FORTRESS, and by nobody else.
 *
 * The constant-shape invariant (CLAUDE.md constraint 7) is PRESERVED, and the
 * preservation is structural, not incidental:
 *
 *   - `requestId` MUST be a value the caller cannot influence and that does NOT
 *     depend on which check failed: a fresh `randomUUID()` minted once per
 *     request, BEFORE any check runs.
 *   - Every response the route's HANDLER emits — success, denial, and any
 *     same-shaped decoy — MUST carry the id. If only denials carried it, its
 *     presence would itself be the oracle.
 *
 * Under those two rules the body is one fixed shape whose only varying field is
 * uniform random noise: it distinguishes nothing. Callers that cannot honor both
 * rules must use {@link denyForbidden} instead.
 *
 * SCOPE, stated precisely: the second rule covers what the handler emits. A
 * request rejected by a layer IN FRONT of the handler — today the shared /v1
 * rate limiter, which answers 429 — carries no id. That is not an oracle: the
 * rate limiter keys on the CALLER's own request rate, never on fortress state,
 * and it already announces itself with a different status code. Do not read the
 * rule as "every byte this port ever emits".
 */
export function denyForbiddenWithRequestId(
  res: ServerResponse,
  requestId: string,
): void {
  writeJson(res, 403, { error: "forbidden", request_id: requestId });
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
