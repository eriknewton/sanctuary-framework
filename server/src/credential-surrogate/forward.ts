/** Pure forward-request validation and framing for credential surrogacy. */
import type { IncomingHttpHeaders, OutgoingHttpHeaders } from "node:http";
import { isIP } from "node:net";
import { validateSurrogateHost, SURROGATE_BOUND_PORT } from "./binding.js";
import { MAX_PLACEHOLDERS_PER_REQUEST } from "./constants.js";
import { surrogatePlaceholderScanRe } from "./placeholder.js";
import { isSurrogateCorrelationId } from "./wire.js";
import type { SurrogateDenyReason } from "./query-codec.js";

/** A validated join key, never arbitrary log text. */
export type SurrogateCorrelationId = string & { readonly __surrogateCorrelation: unique symbol };
export function surrogateCorrelationId(value: unknown): SurrogateCorrelationId | undefined {
  return isSurrogateCorrelationId(value) ? value as SurrogateCorrelationId : undefined;
}

export type SurrogateFailureCode =
  | "header_write_failed" | "upstream_tls_failed" | "upstream_reset"
  | "helper_connect_failed" | "helper_timeout" | "helper_malformed"
  | "helper_id_mismatch" | "body_length_mismatch" | "socket_error";
export type SurrogateRefusal = SurrogateDenyReason | SurrogateFailureCode | "limit"
  | "invalid_target" | "duplicate_header" | "transfer_encoding" | "host_mismatch"
  | "upgrade" | "client_denied" | "not_live" | "policy_denied";

// Coordinator clarification, 2026-10-01: request refusals are 403; helper state
// is 503, superseding design 3.6 step 5 with design 3.4.5. This is the sole table.
export const SURROGATE_STATUS = {
  unknown: [403, "surrogate-unknown"], misroute: [403, "surrogate-misroute"],
  wrong_location: [403, "surrogate-wrong-location"], limit: [403, "surrogate-limit"],
  locked: [503, "surrogate-locked"], expired: [503, "surrogate-locked"],
  rate_limited: [503, "rate_limited"], malformed: [503, "surrogate-helper-unavailable"],
  helper_connect_failed: [503, "surrogate-helper-unavailable"],
  helper_timeout: [503, "surrogate-helper-unavailable"],
  helper_malformed: [503, "surrogate-helper-unavailable"],
  helper_id_mismatch: [503, "surrogate-helper-unavailable"],
  header_write_failed: [502, "header_write_failed"], upstream_tls_failed: [502, "upstream_tls_failed"],
  upstream_reset: [502, "upstream_reset"], body_length_mismatch: [502, "body_length_mismatch"],
  socket_error: [502, "socket_error"], invalid_target: [400, "surrogate-invalid-target"],
  duplicate_header: [400, "surrogate-duplicate-header"], transfer_encoding: [411, "surrogate-transfer-encoding"],
  host_mismatch: [400, "surrogate-host-mismatch"], upgrade: [501, "surrogate-upgrade"],
  client_denied: [403, "client-denied"], not_live: [503, "surrogate-not-live"],
  policy_denied: [403, "denied-by-policy"],
} as const satisfies Record<SurrogateRefusal, readonly [number, string]>;

export interface SurrogateForwardTarget { host: string; authority: string; path: string }
/** Parse before URL normalization so userinfo, fragments and port spelling cannot disappear. */
export function parseSurrogateForwardTarget(raw: string): SurrogateForwardTarget | null {
  const match = /^http:\/\/([^/?#]+)([^#]*)$/i.exec(raw);
  if (!match || /[\s\\\x00-\x1f\x7f]/.test(raw)) return null;
  const authority = match[1]!;
  const hostMatch = /^([^:@\[\]]+)(?::80)?$/.exec(authority);
  if (!hostMatch) return null;
  const host = hostMatch[1]!.toLowerCase();
  if (validateSurrogateHost(host) !== null || isIP(host)) return null;
  // WHATWG also recognizes numeric IPv4 aliases; reject them before any resolver.
  try { if (isIP(new URL(`http://${host}`).hostname)) return null; } catch { return null; }
  const suffix = match[2]!;
  return { host, authority: `${host}:${SURROGATE_BOUND_PORT}`, path: suffix.startsWith("/") ? suffix : `/${suffix}` };
}

/** Host is only a consistency check; the target alone supplies upstream identity. */
export function reconcileSurrogateHost(host: string, supplied: string | string[] | undefined): boolean {
  return supplied === undefined || (typeof supplied === "string" && supplied.toLowerCase().replace(/:80$/, "") === host);
}

/** Refuse duplicate names conservatively: the gate never knows which names root bound. */
export function checkSurrogateRawHeaders(raw: readonly string[]): SurrogateRefusal | null {
  const names = new Set<string>();
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i]!.toLowerCase();
    if (names.has(name)) return "duplicate_header";
    names.add(name);
  }
  if (names.has("transfer-encoding")) return "transfer_encoding";
  if (names.has("upgrade")) return "upgrade";
  return null;
}

export interface SurrogateOccurrence { placeholder: string; location: string; start: number; header?: string }
/** Retain at most the cap; null means over-cap and must precede every helper query. */
export function scanSurrogateRequest(target: string, headers: IncomingHttpHeaders): SurrogateOccurrence[] | null {
  const found: SurrogateOccurrence[] = [];
  const scan = (value: string, location: string, header?: string): boolean => {
    for (const match of value.matchAll(surrogatePlaceholderScanRe())) {
      if (found.length === MAX_PLACEHOLDERS_PER_REQUEST) return false;
      found.push({ placeholder: match[0], location, start: match.index!, ...(header ? { header } : {}) });
    }
    return true;
  };
  if (!scan(target, "target")) return null;
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    for (const part of Array.isArray(value) ? value : [value]) {
      if (!scan(part, `header:${name.toLowerCase()}`, name.toLowerCase())) return null;
    }
  }
  return found;
}

/** Body octets only, from the parser's accepted length, never from a swapped field. */
export function surrogateContentLength(headers: IncomingHttpHeaders): number | null {
  const raw = headers["content-length"];
  if (raw === undefined) return 0;
  if (typeof raw !== "string" || !/^\d+$/.test(raw)) return null;
  const size = Number(raw);
  return Number.isSafeInteger(size) ? size : null;
}

/** Strip hop-by-hop and client framing fields before constructing the TLS request. */
export function buildSurrogateUpstreamHeaders(headers: IncomingHttpHeaders, host: string, length: number, swapped: boolean): OutgoingHttpHeaders {
  const omitted = new Set(["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "proxy-authorization", "proxy-connection", "expect", "host", "content-length"]);
  for (const name of (headers.connection ?? "").split(",")) omitted.add(name.trim().toLowerCase());
  const result: OutgoingHttpHeaders = Object.create(null) as OutgoingHttpHeaders;
  for (const [name, value] of Object.entries(headers)) if (!omitted.has(name.toLowerCase())) result[name] = value;
  result.host = host;
  result.connection = "close";
  if (headers["content-length"] !== undefined) result["content-length"] = length;
  if (swapped) result["accept-encoding"] = "identity";
  return result;
}
