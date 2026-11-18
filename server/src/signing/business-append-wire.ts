// Must match business_profile/append_contract.rs; shapes and bounds carry no authority.
import {createHash} from "node:crypto";
import data from "./business-append-contract.json";
import {canonicalBytes, decodeCanonical, LINUX_FIELDS, SIGNER_FRAME_MAX_BYTES} from "./contract.js";
import {BUSINESS_BOUNDS, validateBusinessRecord} from "./linux-business-records.js";
import {joinCommitment, type JoinRecord, type Json} from "./record-joins.js";
// Must match activation-anchor.ts scalar widths; no anchor codec belongs in the wire graph.
const HEX_CHARACTERS_PER_BYTE = 2;
/** Wire consumers require this many lowercase hexadecimal identifier characters. */
// Must match the ID_HEX_LENGTH compatibility re-export in business-append-contract.ts.
export const ID_HEX_LENGTH = 16 * HEX_CHARACTERS_PER_BYTE; // The protocol uses 128-bit identifiers.
/** Wire consumers require this many hexadecimal characters after a SHA-256 prefix. */
// Must match the DIGEST_HEX_LENGTH compatibility re-export in business-append-contract.ts.
export const DIGEST_HEX_LENGTH = 32 * HEX_CHARACTERS_PER_BYTE; // SHA-256 has 32 bytes.
/** Wire consumers reject integers above this shared exact JavaScript bound. */
// Must match the SAFE_INTEGER compatibility re-export in business-append-contract.ts.
export const SAFE_INTEGER = BUSINESS_BOUNDS.safe_integer;
import {parseStrict} from "../smb/parse-strict.js";

import {ED25519_SIGNATURE_BYTES} from "../core/crypto-suite-registry.js";
// Must match writer_protocol.rs SIGNATURE_BYTES and SIGNATURE_TEXT_BYTES.
// Must match the BUSINESS_SIGNATURE_TEXT_BYTES compatibility re-export in business-append-contract.ts.
export const BUSINESS_SIGNATURE_TEXT_BYTES = Math.ceil(ED25519_SIGNATURE_BYTES * 8 / 6);
// These ASCII widths derive from the primitive definitions used by the schema.
// Must match the BUSINESS_ENCODING_WIDTHS compatibility re-export in business-append-contract.ts.
export const BUSINESS_ENCODING_WIDTHS = Object.freeze({
  id: ID_HEX_LENGTH, digest: "sha256:".length + DIGEST_HEX_LENGTH,
  kid: "k1:sha256:".length + DIGEST_HEX_LENGTH, u64: BUSINESS_BOUNDS.u64_max.length,
  ipv4: 4 * String(255).length + 3, // Four octets and three dots.
  ipv6: 8 * 4 + 7, // Eight hexadecimal groups and seven colons.
});
// Must match SAFE_INTEGER in business_profile/append_contract.rs.
const BUSINESS_SAFE_INTEGER = SAFE_INTEGER;
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
// Must match the APPEND_CONTRACT compatibility re-export in business-append-contract.ts.
export const APPEND_CONTRACT = deepFreeze(data);
// Must match the PRODUCER_ENVELOPE_MAX_BYTES compatibility re-export in business-append-contract.ts.
export const PRODUCER_ENVELOPE_MAX_BYTES = data.envelope_max_bytes;
// Must match the ENVELOPE_BASE64_MAX compatibility re-export in business-append-contract.ts.
export const ENVELOPE_BASE64_MAX = Math.ceil(PRODUCER_ENVELOPE_MAX_BYTES * 8 / 6);
// Must match the BusinessDeliveryIdentity compatibility re-export in business-append-contract.ts.
export interface BusinessDeliveryIdentity {version: 1; sequence: number; commitment: string; envelope_sha256: string;}
// Must match business_wal.rs persist_ts_fact: W reads back the exact TS fact and delivered cursor before n+1 delivery.
// Must match the BusinessDeliveryAck compatibility re-export in business-append-contract.ts.
export interface BusinessDeliveryAck {version: 1; identity: BusinessDeliveryIdentity;}
// Must match the BusinessVerifiedRecord compatibility re-export in business-append-contract.ts.
export type BusinessVerifiedRecord = Record<keyof typeof data.projection, Json>;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
// Must match the envelopeSizeAdmitted compatibility re-export in business-append-contract.ts.
export const envelopeSizeAdmitted = (length: number): boolean => Number.isSafeInteger(length) && length >= 0 && length <= PRODUCER_ENVELOPE_MAX_BYTES;
const U64_DECIMAL_MAX_BYTES = BUSINESS_ENCODING_WIDTHS.u64;
const digest = (v: unknown) => typeof v === "string" && new RegExp(`^sha256:[a-f0-9]{${DIGEST_HEX_LENGTH}}$`).test(v);
/** Wire and checkpoint callers share scalar bounds without importing checkpoint codecs. */
// Must match the appendScalarShape compatibility re-export in business-append-contract.ts.
export function appendScalarShape(token: unknown, v: unknown): boolean {
    switch (token) {
      case "safe": case "positive": return typeof v === "number" && Number.isSafeInteger(v) && v <= BUSINESS_SAFE_INTEGER && v >= (token === "positive" ? 1 : 0);
      case "digest": return digest(v);
      case "nullable_hex": if (v === null) return true;
        return typeof v === "string" && new RegExp(`^[a-f0-9]{${DIGEST_HEX_LENGTH}}$`).test(v);
      case "hex": return typeof v === "string" && new RegExp(`^[a-f0-9]{${DIGEST_HEX_LENGTH}}$`).test(v);
      case "text": return typeof v === "string" && v.length <= PRODUCER_ENVELOPE_MAX_BYTES && Buffer.byteLength(v, "utf8") <= PRODUCER_ENVELOPE_MAX_BYTES;
      case "base64": return typeof v === "string" && v.length <= ENVELOPE_BASE64_MAX && /^[A-Za-z0-9_-]+$/.test(v);
      case "boolean": return typeof v === "boolean";
      case "id": return typeof v === "string" && new RegExp(`^[a-f0-9]{${ID_HEX_LENGTH}}$`).test(v);
      case "u64": return typeof v === "string" && v.length <= U64_DECIMAL_MAX_BYTES && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) <= BigInt(BUSINESS_BOUNDS.u64_max);
      case "commitment": return v === "GENESIS" || digest(v);
      case "nullable_digest": return v === null || digest(v);
      default: return v === token;
    }
}
/** Exact wire shapes confer correlation only, never acceptance authority. */
// Must match the appendWireShape compatibility re-export in business-append-contract.ts.
export function appendWireShape(name: "identity" | "ack" | "event", value: unknown): boolean {
  try {
    const fields: Record<string, unknown> = data[name];
    if (!fields || !object(value) || Object.keys(value).length !== Object.keys(fields).length) return false;
    return Object.entries(fields).every(([key, token]) => Object.hasOwn(value, key) &&
      (token === "identity" ? appendWireShape("identity", value[key]) : appendScalarShape(token, value[key])));
  } catch { return false; }
}
/** Decode exact E before using any unsigned wrapper field. G5 remains a caller obligation. */
// Must match the parseBusinessEnvelope compatibility re-export in business-append-contract.ts.
export function parseBusinessEnvelope(encoded: string): {bytes: Uint8Array; record: JoinRecord} {
  // Check encoded length before Buffer allocation, then canonical round trip.
  if (typeof encoded !== "string" || encoded.length > ENVELOPE_BASE64_MAX) throw Error("BUSINESS_ENVELOPE");
  const bytes = decodeCanonical(encoded);
  // The encoded cap already implies decoded bytes <= PRODUCER_ENVELOPE_MAX_BYTES; the strict parser shares that cap.
  const v = parseStrict(bytes, PRODUCER_ENVELOPE_MAX_BYTES);
  if (!object(v) || !same(Object.keys(v).sort(), ["body", "outer"]) || !validateBusinessRecord(v.body) || !object(v.outer) || !Buffer.from(canonicalBytes(v)).equals(Buffer.from(bytes))) throw Error("BUSINESS_ENVELOPE");
  const body = v.body as Record<string, Json>, outer = v.outer;
  const keys = [...LINUX_FIELDS.filter(k => !k.endsWith("_digest")), "machine_id"];
  if (!same(Object.keys(outer).sort(), [...keys, "signature"].sort()) || keys.some(k => !same(body[k], outer[k])) || typeof outer.signature !== "string") throw Error("BUSINESS_ENVELOPE");
  decodeCanonical(outer.signature, ED25519_SIGNATURE_BYTES);
  return {bytes, record: v as unknown as JoinRecord};
}
// Must match the deliveryIdentity compatibility re-export in business-append-contract.ts.
export function deliveryIdentity(bytes: Uint8Array, record: JoinRecord): BusinessDeliveryIdentity {
  return {version: 1, sequence: record.body.sequence as number, commitment: joinCommitment(record), envelope_sha256: "sha256:" + createHash("sha256").update(bytes).digest("hex")};
}
/** Projection reads only the verified body. Transport metadata never becomes authority. */
// Must match the projectBusinessRecord compatibility re-export in business-append-contract.ts.
export function projectBusinessRecord(record: JoinRecord): BusinessVerifiedRecord {
  return Object.fromEntries(Object.entries(data.projection).map(([key, source]) => [key, structuredClone(record.body[source])])) as BusinessVerifiedRecord;
}
/** Object callers already hold a parsed value; only parseBusinessEventBytes can detect duplicate keys. */
// Must match the parseBusinessEvent compatibility re-export in business-append-contract.ts.
export function parseBusinessEvent(value: unknown): {bytes: Uint8Array; record: JoinRecord; identity: BusinessDeliveryIdentity} {
  if (!appendWireShape("event", value)) throw Error("BUSINESS_EVENT");
  const event = value as Record<string, unknown>;
  const parsed = parseBusinessEnvelope(event.business_envelope as string);
  if (event.captured_at_unix_ms !== parsed.record.body.captured_at_unix_ms || event.event_canonical_json !== Buffer.from(canonicalBytes(parsed.record.body)).toString("utf8")) throw Error("BUSINESS_PROJECTION");
  return {...parsed, identity: deliveryIdentity(parsed.bytes, parsed.record)};
}

/** Preserve duplicate-key evidence at the serialized event boundary. */
// Must match the parseBusinessEventBytes compatibility re-export in business-append-contract.ts.
export function parseBusinessEventBytes(bytes: Uint8Array): ReturnType<typeof parseBusinessEvent> {
  const value = parseStrict(bytes, SIGNER_FRAME_MAX_BYTES);
  if (!Buffer.from(canonicalBytes(value)).equals(Buffer.from(bytes))) throw Error("BUSINESS_EVENT_CANONICAL");
  return parseBusinessEvent(value);
}
