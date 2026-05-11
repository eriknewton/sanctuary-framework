/**
 * Sanctuary WP-V1.x-QUERY-LAYER-ANONYMITY Rho-1 Tier A header strip.
 *
 * **Opens WP-V1.x-QUERY-LAYER-ANONYMITY.** Closes Principle 4 (Opacity
 * at the query layer) at the foundation level. Genuinely novel claim
 * per the Sovereignty Stack Assessment 2026-05-10: no comparator
 * surveyed (SSI stacks, personal data stores, decentralized social,
 * confidential computing) ships query-layer anonymity at strength.
 *
 * Tier A scope (this module): strip fingerprintable HTTP headers from
 * every outbound substrate-selector call. Default-on, structurally
 * unconditional — no operator-side opt-out at v1.x. Operators who need
 * the headers for some reason must change code.
 *
 * Tier B (PII rewrite opt-in) lives in a Rho-2 dispatch, gated on
 * Erik morning read of the privacy-vs-functionality trade-off.
 * Tier C (mix network / ZK) is research-grade, out of v1.x.
 *
 * Castle-walking discipline:
 *   - This module introduces NO new outbound surface; it is a
 *     reduction of metadata on EXISTING outbound calls. The substrate
 *     selector remains the only outbound LLM channel; Castle Wall
 *     egress filter still binds; Rho-1 makes that channel measurably
 *     more anonymous.
 *   - The strip happens at the operator-substrate boundary
 *     (application layer), structurally similar to Apple Private
 *     Relay or Tor's HTTP-stripping logic but bound to a different
 *     trust boundary.
 *
 * Audit emission:
 *   - `query_anonymity_headers_stripped` fires on every wrapped fetch
 *     call with stripped header count + names + reasons. Cumulative
 *     count per fortress is operator-visible via the dashboard.
 */

// ── Public types ─────────────────────────────────────────────────────

export type StripReason =
  | "user-agent"
  | "fingerprintable-extension"
  | "unnecessary-metadata"
  | "leaking-network-info"
  | "locale-fingerprint";

export interface StrippableHeader {
  /** Header name. Matched case-insensitively. */
  name: string;
  /** Why this header is stripped. Surfaced in audit + dashboard. */
  reason: StripReason;
}

export interface StripResult {
  /**
   * The cleaned header set. Keys removed entirely (no empty-string
   * placeholders here — let the caller decide whether to also add
   * undici-defeat overrides via `defeatUndiciDefaultsInto`).
   */
  stripped: Record<string, string>;
  /**
   * The headers that were removed, in the order they were
   * encountered. Names are returned as they appeared in the input
   * (case preserved) so downstream audit emission can quote them
   * faithfully.
   */
  removed: { name: string; reason: StripReason }[];
}

/** Audit-op constants. Stable shape for downstream emitters. */
export const QUERY_ANONYMITY_AUDIT_OPS = {
  HEADERS_STRIPPED: "query_anonymity_headers_stripped",
} as const;

export type QueryAnonymityAuditOp =
  (typeof QUERY_ANONYMITY_AUDIT_OPS)[keyof typeof QUERY_ANONYMITY_AUDIT_OPS];

// ── Canonical strip list ─────────────────────────────────────────────

/**
 * The canonical Tier A strip list. Headers here are removed from every
 * outbound substrate-selector call.
 *
 * Each entry carries a `name` (case-insensitive match) and a `reason`
 * surfaced in the audit log so the operator can understand WHY a
 * given header was stripped.
 *
 * If you add to this list, add a corresponding zero-PII regression
 * test that covers the new class.
 */
const CANONICAL_STRIP_LIST: readonly StrippableHeader[] = [
  // Browser / runtime fingerprinting.
  { name: "user-agent", reason: "user-agent" },
  { name: "sec-ch-ua", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-mobile", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-platform", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-platform-version", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-arch", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-bitness", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-model", reason: "fingerprintable-extension" },
  { name: "sec-ch-ua-full-version-list", reason: "fingerprintable-extension" },

  // Locale fingerprint.
  { name: "accept-language", reason: "locale-fingerprint" },

  // Request-origin leak.
  { name: "referer", reason: "leaking-network-info" },
  { name: "referrer-policy", reason: "leaking-network-info" },
  { name: "origin", reason: "leaking-network-info" },

  // Forwarded-by / IP-derived network info.
  { name: "via", reason: "leaking-network-info" },
  { name: "forwarded", reason: "leaking-network-info" },
  { name: "x-forwarded-for", reason: "leaking-network-info" },
  { name: "x-real-ip", reason: "leaking-network-info" },
  { name: "x-client-ip", reason: "leaking-network-info" },

  // DNT / GPC are technically anti-tracking signals but they
  // themselves form a fingerprint (operators who set DNT=1 are a
  // smaller subset). Strip to keep the substrate ignorant of
  // operator preferences.
  { name: "dnt", reason: "unnecessary-metadata" },
  { name: "sec-gpc", reason: "unnecessary-metadata" },
] as const;

/**
 * Required-header allowlist. Headers in this set are NEVER stripped,
 * regardless of any future strip-list expansion. Bound at the
 * provider-protocol contract level.
 *
 * If you add a provider that needs a new required header, add it
 * here AND in the provider's substrate client.
 */
const REQUIRED_HEADERS: readonly string[] = [
  "authorization",
  "content-type",
  "content-length",
  "host",
  "accept",
  "x-api-key",                  // Anthropic API auth
  "anthropic-version",          // Anthropic API contract version
  "anthropic-beta",             // optional Anthropic beta opt-in
  "openai-organization",        // optional OpenAI org id
  "x-stainless-package-version",// allowed for Anthropic + OpenAI SDK contract compat
  "x-goog-api-key",             // Google AI Studio
  "x-goog-user-project",        // Google AI Studio
] as const;

const REQUIRED_HEADER_SET = new Set(
  REQUIRED_HEADERS.map((h) => h.toLowerCase()),
);

const STRIP_REASON_BY_NAME = new Map<string, StripReason>(
  CANONICAL_STRIP_LIST.map((h) => [h.name.toLowerCase(), h.reason]),
);

// ── Pure API ─────────────────────────────────────────────────────────

/**
 * Canonical strip list view. Exposed so the documentation site and
 * the operator dashboard can render it without duplicating literals.
 */
export function getStripList(): StrippableHeader[] {
  return CANONICAL_STRIP_LIST.map((h) => ({ ...h }));
}

/**
 * Required-header allowlist view. Exposed for tests + dashboard.
 */
export function getRequiredHeaders(): string[] {
  return [...REQUIRED_HEADERS];
}

/**
 * Strip fingerprintable headers from a headers record.
 *
 * Behavior:
 *   - Matches headers case-insensitively against the canonical
 *     strip list.
 *   - Required headers (Authorization, Content-Type, provider-
 *     specific auth) are preserved even if a future strip-list
 *     expansion would otherwise remove them.
 *   - Custom `X-*` headers are preserved unless they appear in the
 *     strip list (currently the network-info `X-*` family).
 *
 * Returns the cleaned headers plus the audit-quality `removed` list.
 */
export function stripHeaders(
  headers: Record<string, string>,
): StripResult {
  const stripped: Record<string, string> = {};
  const removed: { name: string; reason: StripReason }[] = [];
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (REQUIRED_HEADER_SET.has(lower)) {
      stripped[name] = value;
      continue;
    }
    const reason = STRIP_REASON_BY_NAME.get(lower);
    if (reason !== undefined) {
      removed.push({ name, reason });
      continue;
    }
    // Unknown header: preserve (operator may have configured a custom
    // required header for a provider; the substrate client is the
    // authority on which headers a given API call needs). Future
    // tightening could move this to deny-by-default with an explicit
    // allowlist.
    stripped[name] = value;
  }
  return { stripped, removed };
}

/**
 * Mutate the supplied headers object to neutralize Node `fetch` /
 * undici defaults. Adds empty-string overrides for headers the
 * underlying HTTP client would otherwise insert (User-Agent in
 * particular). Returns the same record for fluent chaining.
 *
 * Undici discipline: an explicit `User-Agent: ""` is sent verbatim,
 * which is strictly more anonymous than letting undici insert its
 * `node` default. If a future Node version rejects empty-string
 * headers, fall back to a stable string like `sanctuary-substrate`
 * that does not carry version info.
 */
export function defeatUndiciDefaultsInto(
  headers: Record<string, string>,
): Record<string, string> {
  if (headers["user-agent"] === undefined && headers["User-Agent"] === undefined) {
    headers["User-Agent"] = "";
  }
  if (
    headers["accept-language"] === undefined &&
    headers["Accept-Language"] === undefined
  ) {
    headers["Accept-Language"] = "";
  }
  return headers;
}

// ── Audit-emitting fetch wrapper ─────────────────────────────────────

export interface AnonymizedFetchAuditEvent {
  url: string;
  method: string;
  stripped_count: number;
  removed: { name: string; reason: StripReason }[];
  required_preserved: string[];
}

export type AnonymizedFetchAuditCallback = (
  event: AnonymizedFetchAuditEvent,
) => void;

/**
 * Wrap a `fetch`-compatible function so every call has its headers
 * stripped + undici defaults defeated + the operation audited.
 *
 * Substrate selector wires this in once at construction; substrate
 * clients receive the wrapped fetch and use it without knowing
 * anonymization happened. Bypass requires a code change to the
 * selector — there is no runtime configuration knob that turns
 * the strip off.
 */
export function createAnonymizedFetch(
  baseFetch: typeof fetch,
  onAudit?: AnonymizedFetchAuditCallback,
): typeof fetch {
  const wrapped: typeof fetch = async (input, init) => {
    const headers = normalizeHeadersInit(init?.headers as HeadersInitLike);
    const result = stripHeaders(headers);
    defeatUndiciDefaultsInto(result.stripped);
    const preservedRequired = Object.keys(result.stripped).filter((k) =>
      REQUIRED_HEADER_SET.has(k.toLowerCase()),
    );
    const url = typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : (input as Request).url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    if (onAudit) {
      onAudit({
        url,
        method,
        stripped_count: result.removed.length,
        removed: result.removed,
        required_preserved: preservedRequired,
      });
    }
    return baseFetch(input, { ...init, headers: result.stripped });
  };
  return wrapped;
}

// ── PII ship-gate helpers ────────────────────────────────────────────

/**
 * Returns true if the given headers map contains a substring matching
 * one of the four PII classes the Rho-1 ship gate forbids. Designed
 * for test assertions: a passing call's headers must produce
 * `containsPiiSignal(...) === false`.
 *
 * The four PII classes:
 *   - Email address (any `@`-containing token).
 *   - IPv4 / IPv6 address (regex).
 *   - System hostname (the operator's machine hostname appearing as
 *     a value).
 *   - System / locale identifiers (User-Agent, Accept-Language —
 *     these are also in the strip list, so this gate is a
 *     belt-and-suspenders catch).
 */
export interface PiiSignalMatch {
  piiClass: "email" | "ip-address" | "hostname" | "system-locale";
  header: string;
  value: string;
}

export function detectPiiInHeaders(
  headers: Record<string, string>,
  opts: { hostname?: string } = {},
): PiiSignalMatch[] {
  const matches: PiiSignalMatch[] = [];
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (EMAIL_RE.test(value)) {
      matches.push({ piiClass: "email", header: name, value });
    }
    if (IPV4_RE.test(value) || IPV6_RE.test(value)) {
      matches.push({ piiClass: "ip-address", header: name, value });
    }
    if (opts.hostname && value.includes(opts.hostname)) {
      matches.push({ piiClass: "hostname", header: name, value });
    }
    if (
      (lower === "user-agent" || lower === "accept-language") &&
      value.length > 0
    ) {
      matches.push({ piiClass: "system-locale", header: name, value });
    }
  }
  return matches;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const IPV6_RE = /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/;

// ── helpers ──────────────────────────────────────────────────────────

type HeadersInitLike =
  | Record<string, string>
  | Array<[string, string]>
  | Headers
  | undefined;

function normalizeHeadersInit(
  raw: HeadersInitLike,
): Record<string, string> {
  if (raw === undefined) return {};
  if (typeof Headers !== "undefined" && raw instanceof Headers) {
    const out: Record<string, string> = {};
    raw.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  if (Array.isArray(raw)) {
    const out: Record<string, string> = {};
    for (const [k, v] of raw) {
      if (k !== undefined && v !== undefined) out[k] = v;
    }
    return out;
  }
  return { ...(raw as Record<string, string>) };
}
