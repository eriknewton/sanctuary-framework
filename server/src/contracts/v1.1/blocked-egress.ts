import { isIP } from "node:net";

/** DNS presentation-format name limit without the final dot; any final dot uses this same budget. */
export const BLOCKED_EGRESS_HOST_MAX_CHARS = 253;
/** DNS label limit. */
export const BLOCKED_EGRESS_LABEL_MAX_CHARS = 63;
/** Longest IPv6 text form with embedded IPv4. */
export const BLOCKED_EGRESS_IP_MAX_CHARS = 45;
/** 2048 bytes = the design's 2 KiB encoded metadata budget. */
export const BLOCKED_EGRESS_METADATA_MAX_BYTES = 2048;

/** Closed diagnostics never include rejected destination text. */
export type BlockedEgressParseReason =
  | "type" | "too_long" | "invalid_host" | "literal_ip" | "invalid_ip"
  | "too_large" | "malformed" | "unknown_field" | "invalid_attribution" | "invalid_subject";
/** Consumers use the parsed value only on the successful arm. */
export type BlockedEgressParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: BlockedEgressParseReason };

/** Validate a DNS presentation name without normalization or resolution. */
export function parseBlockedEgressHost(raw: unknown): BlockedEgressParseResult<string> {
  if (typeof raw !== "string") return { ok: false, reason: "type" };
  // Bound work before scanning attacker-selected text.
  if (raw.length > BLOCKED_EGRESS_HOST_MAX_CHARS) return { ok: false, reason: "too_long" };
  if (raw.length === 0 || /[^A-Za-z0-9.-]/.test(raw)) return { ok: false, reason: "invalid_host" };
  const name = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  if (isIP(name)) return { ok: false, reason: "literal_ip" };
  if (name.split(".").some((label) =>
    label.length === 0 || label.length > BLOCKED_EGRESS_LABEL_MAX_CHARS ||
    label.startsWith("-") || label.endsWith("-"))) {
    return { ok: false, reason: "invalid_host" };
  }
  return { ok: true, value: raw };
}

/** Validate only an IPv4 or IPv6 literal, without a zone, endpoint or network suffix. */
export function parseBlockedEgressIp(raw: unknown): BlockedEgressParseResult<string> {
  if (typeof raw !== "string") return { ok: false, reason: "type" };
  if (raw.length > BLOCKED_EGRESS_IP_MAX_CHARS) return { ok: false, reason: "too_long" };
  if (!/^[A-Fa-f0-9:.]+$/.test(raw) || !isIP(raw)) return { ok: false, reason: "invalid_ip" };
  return { ok: true, value: raw };
}

/** Producer verification is separate from operation success and enrolled-agent binding. */
// Must match the attribution field in hub-events.ts; both use this shared type.
export interface BlockedEgressAttribution {
  subject: "castle_wall_producer";
  evidence_source: "producer_signature";
  verifier: "castle_wall_audit_consumer";
  state: "verified" | "unverified";
}

/** Dormant structured evidence; stored verification state alone is not a read-side proof. */
export interface BlockedEgressMetadata {
  destination_host?: string;
  destination_ip?: string;
  attribution: BlockedEgressAttribution;
  /** OS subject established from the signed body by the consumer's subject-binding check. */
  subject?: string;
}

function record(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === "object" && !Array.isArray(raw);
}

/** Validate either encoded JSON or an object, returning a detached, complete metadata value. */
export function parseBlockedEgressMetadata(raw: unknown): BlockedEgressParseResult<BlockedEgressMetadata> {
  let value: unknown = raw;
  try {
    const encoded = typeof raw === "string" ? raw : JSON.stringify(raw);
    if (encoded === undefined) return { ok: false, reason: "type" };
    // Reject oversized encodings before JSON parsing or field validation.
    if (encoded.length > BLOCKED_EGRESS_METADATA_MAX_BYTES ||
        Buffer.byteLength(encoded, "utf8") > BLOCKED_EGRESS_METADATA_MAX_BYTES) {
      return { ok: false, reason: "too_large" };
    }
    if (typeof raw === "string") value = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!record(value)) return { ok: false, reason: "type" };
  if (Object.keys(value).some((key) => !["destination_host", "destination_ip", "attribution", "subject"].includes(key))) {
    return { ok: false, reason: "unknown_field" };
  }
  const attribution = value.attribution;
  if (!record(attribution)) return { ok: false, reason: "invalid_attribution" };
  if (Object.keys(attribution).some((key) => !["subject", "evidence_source", "verifier", "state"].includes(key))) {
    return { ok: false, reason: "unknown_field" };
  }
  // An unverified event never renders as verified, and the host string is displayed as bounded escaped data, never dereferenced.
  if (attribution.subject !== "castle_wall_producer" || attribution.evidence_source !== "producer_signature" ||
      attribution.verifier !== "castle_wall_audit_consumer" ||
      (attribution.state !== "verified" && attribution.state !== "unverified")) {
    return { ok: false, reason: "invalid_attribution" };
  }
  const out: BlockedEgressMetadata = { attribution: {
    subject: attribution.subject, evidence_source: attribution.evidence_source,
    verifier: attribution.verifier, state: attribution.state,
  } };
  if ("destination_host" in value) {
    const host = parseBlockedEgressHost(value.destination_host);
    if (!host.ok) return host;
    out.destination_host = host.value;
  }
  if ("destination_ip" in value) {
    const ip = parseBlockedEgressIp(value.destination_ip);
    if (!ip.ok) return ip;
    out.destination_ip = ip.value;
  }
  if ("subject" in value) {
    // Only authenticated subject bindings may survive into structured metadata.
    if (attribution.state !== "verified" || typeof value.subject !== "string" || value.subject.length === 0) {
      return { ok: false, reason: "invalid_subject" };
    }
    out.subject = value.subject;
  }
  return { ok: true, value: out };
}

/** Map an already verified consumer outcome; this function does not verify signatures itself. */
export function blockedEgressReasonClass(signedEvent: unknown): "egress_policy_deny" | "other" {
  // Must match SignatureOutcome in castle-wall/runtime/audit-consumer.ts; only its verified arm carries signedBody.
  if (!record(signedEvent) || signedEvent.kind !== "verified" || !record(signedEvent.signedBody)) return "other";
  const body = signedEvent.signedBody;
  if (body.operation !== "egress_blocked" || (body.result !== "failure" && body.result !== "blocked") || !record(body.details)) return "other";
  return body.details.decision_provenance === "default_deny" || body.details.decision_provenance === "static_rule"
    ? "egress_policy_deny" : "other";
}
