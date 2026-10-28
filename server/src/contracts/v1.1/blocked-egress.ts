import { isIP } from "node:net";

/** DNS presentation-format name limit without the final dot; any final dot uses this same budget. */
export const BLOCKED_EGRESS_HOST_MAX_CHARS = 253;
/** DNS label limit. */
export const BLOCKED_EGRESS_LABEL_MAX_CHARS = 63;
/** Longest IPv6 text form with embedded IPv4. */
export const BLOCKED_EGRESS_IP_MAX_CHARS = 45;
/** 2048 bytes = the design's 2 KiB encoded metadata budget. */
export const BLOCKED_EGRESS_METADATA_MAX_BYTES = 2048;

/** 64 = a 32-byte audit token in hex; also fits the minted identity hex + /uid- + uint32 (32 + 5 + 10; core/identity.ts). */
export const BLOCKED_EGRESS_SUBJECT_MAX_CHARS = 64;

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
  const labels = name.split(".");
  // Numeric final labels and hex-prefixed labels can be interpreted as inet_aton IPv4, never DNS names.
  if (/^[0-9]+$/.test(labels[labels.length - 1]!) || labels.some((label) => /^0x/i.test(label))) {
    return { ok: false, reason: "literal_ip" };
  }
  if (isIP(name)) return { ok: false, reason: "literal_ip" };
  if (labels.some((label) =>
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

/**
 * Verified carries the pinned Castle Wall producer's credibility only for signed
 * destination host/IP, signed string agent_id and timestamp, signature-bound seq, and
 * the consumer subject derived from signed agent_id (local fortress scope) or
 * signed identity_id. It does not vouch for reason, reason class, severity, or
 * any other envelope field, nor does it prove operation success or enrollment.
 * Missing/non-string signed agent_id is unverified with no subject; a contradicting
 * envelope destination suppresses projection entirely.
 * Must match blockedEgressMetadataFor in castle-wall/runtime/audit-consumer.ts.
 */
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
  let value: unknown;
  try {
    if (typeof raw === "string") {
      // Bound the encoding before parsing attacker-selected text.
      if (raw.length > BLOCKED_EGRESS_METADATA_MAX_BYTES || Buffer.byteLength(raw, "utf8") > BLOCKED_EGRESS_METADATA_MAX_BYTES) {
        return { ok: false, reason: "too_large" };
      }
      value = JSON.parse(raw);
    } else {
      // Copy only bounded plain data before serialization; getters and toJSON never execute.
      const copied = boundedMetadataCopy(raw);
      if (!copied.ok) return copied;
      value = copied.value;
      if (Buffer.byteLength(JSON.stringify(value), "utf8") > BLOCKED_EGRESS_METADATA_MAX_BYTES) {
        return { ok: false, reason: "too_large" };
      }
    }
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
    if (attribution.state !== "verified" || !isBlockedEgressSubject(value.subject)) {
      return { ok: false, reason: "invalid_subject" };
    }
    out.subject = value.subject;
  }
  return { ok: true, value: out };
}

/** Bound display subjects independently of the whole metadata budget. */
export function isBlockedEgressSubject(raw: unknown): raw is string {
  // Signed text is still untrusted display data; reject controls and markup before projection.
  return typeof raw === "string" && raw.length > 0 && raw.length <= BLOCKED_EGRESS_SUBJECT_MAX_CHARS &&
    !/[^\x20-\x7e]|[<>]/.test(raw);
}

function boundedMetadataCopy(raw: unknown): BlockedEgressParseResult<unknown> {
  // Metadata and attribution each have four fields and at most two object levels.
  const MAX_FIELDS = 4;
  const MAX_OBJECT_DEPTH = 2;
  let remaining = BLOCKED_EGRESS_METADATA_MAX_BYTES;
  function copy(value: unknown, depth: number): BlockedEgressParseResult<unknown> {
    if (!record(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
      return { ok: false, reason: "type" };
    }
    if (depth > MAX_OBJECT_DEPTH) return { ok: false, reason: "malformed" };
    const out: Record<string, unknown> = Object.create(null);
    let count = 0;
    for (const key in value) {
      if (!Object.hasOwn(value, key)) continue;
      if (++count > MAX_FIELDS) return { ok: false, reason: "unknown_field" };
      remaining -= key.length;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) return { ok: false, reason: "malformed" };
      const item: unknown = descriptor.value;
      if (typeof item === "string") remaining -= item.length;
      if (remaining < 0) return { ok: false, reason: "too_large" };
      if (record(item)) {
        const nested = copy(item, depth + 1);
        if (!nested.ok) return nested;
        out[key] = nested.value;
      } else if (item === null || item === undefined || ["string", "number", "boolean"].includes(typeof item)) {
        out[key] = item;
      } else {
        return { ok: false, reason: key === "attribution" ? "invalid_attribution" : "malformed" };
      }
    }
    return { ok: true, value: out };
  }
  return copy(raw, 1);
}
