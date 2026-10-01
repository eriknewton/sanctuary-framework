/**
 * Credential surrogacy: the binding shape and the element-level validators
 * every stage shares (AGENTS.md rule 11).
 *
 * THREE STAGES READ A BINDING and they must agree element by element, or a
 * value ends up on a destination one of them would have refused:
 *   1. the operator CLI and the broker, through `parseSurrogatePolicyDocument`
 *      in `disclosure/broker/policy.ts`, over `<fortress>/surrogate-policy.json`;
 *   2. root arming, through the same parser, writing `gate-surrogate/<uid>.bindings`;
 *   3. the root helper daemon, loading that file back at start.
 * So the grammar lives HERE, once, as functions all three call. None of them
 * re-implements a character class.
 *
 * The validators return a fixed reason code, never a message built from the
 * input. A parser message that echoed the offending bytes would put policy
 * content (and, on the unlock path, value bytes) into a log line.
 */

/**
 * Env names that must never be written into a world-readable plist or exported
 * by the release wrapper.
 *
 * MUST MATCH `HARNESS_FORBIDDEN_PLIST_ENV` in `egress-gate/harness-daemon.ts`.
 * Duplicated rather than imported for the same reason that list is duplicated
 * from `cli/castle-wall-boot.ts`: this module is loaded by the root helper, by
 * root arming and by the broker, and none of them should pull the launchd
 * harness machinery in to read six strings. The two lists are pinned equal by
 * `server/test/credential-surrogate/binding.test.ts`, so a drift on either side
 * fails a test instead of silently letting a binding name `HTTP_PROXY`.
 */
export const SURROGATE_RESERVED_ENV_NAMES: readonly string[] = [
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_KEY",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "https_proxy",
  "http_proxy",
];

/**
 * The only port slice 1 binds.
 *
 * Reason it is a constant and not an option: the gate writes the value only
 * inside a TLS session whose certificate verified for the bound hostname, and
 * that is the whole confidentiality argument. A plaintext port would put the
 * credential on the wire in the clear.
 */
export const SURROGATE_BOUND_PORT = 443;

/** One destination a binding authorizes. */
export interface SurrogateDestination {
  /** Lowercase DNS name. No wildcard, no IP literal, no port suffix. */
  host: string;
  /** Always {@link SURROGATE_BOUND_PORT} in slice 1. */
  port: number;
}

/** One binding as the operator writes it and as every stage reads it. */
export interface SurrogateBinding {
  /** Secret name as stored under the surrogate keychain label. */
  secret: string;
  /** Agent id whose gate may spend this value. */
  agent: string;
  /** Env name the release wrapper exports the placeholder under. */
  env: string;
  /** Destinations this value may be written to, 1 to `MAX_SURROGATE_DESTINATIONS_PER_BINDING`. */
  destinations: readonly SurrogateDestination[];
  /** The one request header the gate writes the value into. Canonical spelling as the operator wrote it. */
  header: string;
}

/**
 * A binding plus what root assigned it for one generation. This is the shape in
 * `gate-surrogate/<uid>.bindings` and in the helper's table.
 */
export interface MintedSurrogateBinding extends SurrogateBinding {
  /** The placeholder root minted for this binding in this generation. */
  placeholder: string;
  /** Root-assigned ordinal, stable within one generation. Gate events carry this instead of any name. */
  ordinal: number;
}

/**
 * Fixed reason codes. A caller may log one of these; it may never log the input
 * that produced it.
 */
export type SurrogateValidationReason =
  | "not_a_string"
  | "empty"
  | "too_long"
  | "bad_charset"
  | "reserved_name"
  | "hop_by_hop_header"
  | "forbidden_header"
  | "wildcard_host"
  | "ip_literal_host"
  | "bad_port"
  | "illegal_value_byte";

/**
 * Env-name grammar.
 *
 * MUST MATCH the wrapper's own check in `egress-gate/release-barrier.ts`, which
 * exports a surrogates-file line only when it matches
 * `^[A-Z_][A-Z0-9_]{0,63}=sanctuary_surrogate_[0-9a-f]{32}$`. A name this
 * parser accepted but the wrapper refused would park the harness at exit 78
 * after arming had already reported success.
 */
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;

/** RFC 7230 token charset, the legal spelling of a header field name. */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** Longest header name accepted. Derivation: the wire envelope budget carries `header:` plus a token of at most 64 bytes. */
export const MAX_SURROGATE_HEADER_NAME_LENGTH = 64;

/** Longest DNS name. Derivation: 253 is the maximum length of a presentation-format domain name. */
export const MAX_SURROGATE_HOST_LENGTH = 253;

/**
 * Headers a binding may never name.
 *
 * `Host` because the gate reconciles it against the request target and a bound
 * Host would let a swap retarget the request; `Content-Length` and
 * `Transfer-Encoding` because Node owns request framing and writing into either
 * is a request-smuggling primitive; `Expect` and `Upgrade` because they change
 * the protocol rather than carry a credential; hop-by-hop headers and `Proxy-*`
 * because they address the gate itself, not the destination.
 */
const HOP_BY_HOP_HEADERS: readonly string[] = [
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

const FORBIDDEN_BOUND_HEADERS: readonly string[] = [
  "host",
  "content-length",
  "expect",
];

/** Validate an env name. Returns `null` when it is acceptable. */
export function validateSurrogateEnvName(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "string") return "not_a_string";
  if (value.length === 0) return "empty";
  // Reserved-name refusal runs BEFORE the charset check, and case-insensitively,
  // so every reserved spelling reports `reserved_name`. Two of the reserved names
  // are lowercase (`http_proxy`, `https_proxy`) and would otherwise be refused
  // only incidentally, as `bad_charset`, which tells an operator the wrong thing
  // and would silently stop being a refusal if the charset ever widened.
  //
  // Why these names are refused at all: a binding that named a proxy variable
  // would have the release wrapper export a placeholder OVER the gate's own proxy
  // setting and route the agent past the gate entirely.
  const upper = value.toUpperCase();
  for (const reserved of SURROGATE_RESERVED_ENV_NAMES) {
    if (reserved.toUpperCase() === upper) return "reserved_name";
  }
  if (!ENV_NAME_RE.test(value)) return "bad_charset";
  return null;
}

/** Validate the bound header name. Returns `null` when it is acceptable. */
export function validateSurrogateHeaderName(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "string") return "not_a_string";
  if (value.length === 0) return "empty";
  if (value.length > MAX_SURROGATE_HEADER_NAME_LENGTH) return "too_long";
  if (!HEADER_NAME_RE.test(value)) return "bad_charset";
  const lower = value.toLowerCase();
  if (HOP_BY_HOP_HEADERS.includes(lower)) return "hop_by_hop_header";
  if (FORBIDDEN_BOUND_HEADERS.includes(lower)) return "forbidden_header";
  if (lower.startsWith("proxy-")) return "forbidden_header";
  return null;
}

/** DNS label grammar, lowercase only: a mixed-case host would not compare equal to the gate's parsed authority. */
const DNS_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Validate a destination host. Returns `null` when it is acceptable. */
export function validateSurrogateHost(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "string") return "not_a_string";
  if (value.length === 0) return "empty";
  if (value.length > MAX_SURROGATE_HOST_LENGTH) return "too_long";
  if (value.includes("*")) return "wildcard_host";
  // An IP literal is refused because the confidentiality argument is a
  // certificate that verified for the bound HOSTNAME; there is no hostname to
  // verify against for a literal, and an address can be re-pointed by whoever
  // controls the route without the binding changing.
  if (/^[0-9.]+$/.test(value) || value.includes(":")) return "ip_literal_host";
  if (!DNS_NAME_RE.test(value)) return "bad_charset";
  return null;
}

/** Validate a destination port. Slice 1 accepts only {@link SURROGATE_BOUND_PORT}. */
export function validateSurrogatePort(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "number" || !Number.isInteger(value)) return "bad_port";
  if (value !== SURROGATE_BOUND_PORT) return "bad_port";
  return null;
}

/** Agent-id charset: the same conservative set the gate service account is derived from. */
const AGENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/** Validate an agent id. Returns `null` when it is acceptable. */
export function validateSurrogateAgentId(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "string") return "not_a_string";
  if (value.length === 0) return "empty";
  if (!AGENT_ID_RE.test(value)) return "bad_charset";
  return null;
}

/** Secret-name charset. Must match the broker backend's own `validateSecretName` grammar in `keychain-backend.ts`. */
const SECRET_NAME_RE = /^[A-Za-z0-9._\-:/]+$/;

/** Validate a secret name. Returns `null` when it is acceptable. */
export function validateSurrogateSecretName(value: unknown): SurrogateValidationReason | null {
  if (typeof value !== "string") return "not_a_string";
  if (value.length === 0) return "empty";
  if (!SECRET_NAME_RE.test(value)) return "bad_charset";
  return null;
}

/**
 * True only if every byte of `value` is legal in an HTTP field value: visible
 * ASCII (0x21 to 0x7e), space or tab. No CR, no LF, no NUL, no control byte.
 *
 * THIS IS THE HEADER-SPLITTING GUARD. The helper checks it before accepting an
 * unlock, so a value the gate later writes into a request header cannot end the
 * header, start a second one, or smuggle a whole request. Checked on the
 * RELYING side (the helper), never trusted from the client.
 */
export function isLegalHttpFieldValue(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x09 || code === 0x20) continue;
    if (code >= 0x21 && code <= 0x7e) continue;
    return false;
  }
  return true;
}
