import {createHash} from "node:crypto";
import data from "./business-append-contract.json";
import {canonicalBytes, decodeCanonical, LINUX_FIELDS, SIGNER_FRAME_MAX_BYTES} from "./contract.js";
import {validateBusinessRecord} from "./linux-business-records.js";
import {joinCommitment, joinStateValid, type JoinRecord, type Json} from "./record-joins.js";
import {anchorSchema, anchorDigest} from "../linux-business/activation-anchor.js";
import {parseStrict} from "../smb/parse-strict.js";

export const APPEND_CONTRACT = data;
export const PRODUCER_ENVELOPE_MAX_BYTES = data.envelope_max_bytes;
export const ENVELOPE_BASE64_MAX = Math.ceil(PRODUCER_ENVELOPE_MAX_BYTES * 8 / 6);
export interface BusinessDeliveryIdentity {version: 1; sequence: number; commitment: string; envelope_sha256: string;}
export interface BusinessDeliveryAck {version: 1; identity: BusinessDeliveryIdentity;}
export type BusinessVerifiedRecord = Record<keyof typeof data.projection, Json>;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
export const envelopeSizeAdmitted = (length: number): boolean => Number.isSafeInteger(length) && length >= 0 && length <= PRODUCER_ENVELOPE_MAX_BYTES;
const U64_DECIMAL_MAX_BYTES = 20; // Decimal width of 2^64 - 1.
const digest = (v: unknown) => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v);
/** Shared field tables own exact shapes; these checks confer no authority. */
export function appendShape(name: "identity" | "ack" | "event" | "checkpoint" | "observation" | "wal_checkpoint" | "retained_original", value: unknown): boolean {
  const fields: Record<string, unknown> = data[name];
  if (!object(value) || Object.keys(value).length !== Object.keys(fields).length) return false;
  const valid = Object.entries(fields).every(([key, token]) => {
    if (!Object.hasOwn(value, key)) return false;
    const v = value[key];
    switch (token) {
      case "safe": case "positive": return typeof v === "number" && Number.isSafeInteger(v) && v >= (token === "positive" ? 1 : 0);
      case "digest": return digest(v);
      case "nullable_hex": if (v === null) return true;
        return typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
      case "hex": return typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
      case "text": return typeof v === "string" && v.length <= PRODUCER_ENVELOPE_MAX_BYTES && Buffer.byteLength(v, "utf8") <= PRODUCER_ENVELOPE_MAX_BYTES;
      case "base64": return typeof v === "string" && v.length <= ENVELOPE_BASE64_MAX && /^[A-Za-z0-9_-]+$/.test(v);
      case "identity": case "observation": case "wal_checkpoint": return appendShape(token, v);
      case "boolean": return typeof v === "boolean";
      case "id": return typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
      case "u64": return typeof v === "string" && v.length <= U64_DECIMAL_MAX_BYTES && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) <= 18446744073709551615n;
      case "commitment": return v === "GENESIS" || digest(v);
      case "nullable_digest": return v === null || digest(v);
      case "nullable_anchor": return v === null || anchorSchema.safeParse(v).success;
      case "observation_state": return (data.observation_states as unknown[]).includes(v);
      case "join_state": return joinStateValid(v);
      // Must match the native owner through the executed whole-set limits pin.
      case "retained_originals": return Array.isArray(v) && v.length <= data.limits.d_undrained_max && v.every(row => appendShape("retained_original",row));
      default: return v === token;
    }
  });
  if (!valid || name !== "observation") return valid;
  // Must match drain_protocol READ_REPLY: shape does not confer mutation authority.
  if (value.state === "ABSENT") return value.anchor === null && value.anchor_digest === null && value.latched === false;
  const anchor=anchorSchema.safeParse(value.anchor);
  return anchor.success && value.anchor_digest === anchorDigest(anchor.data) && value.latched === anchor.data.recovery_required;
}
/** Decode exact E before using any unsigned wrapper field. G5 remains a caller obligation. */
export function parseBusinessEnvelope(encoded: string): {bytes: Uint8Array; record: JoinRecord} {
  // Check encoded length before Buffer allocation, then canonical round trip.
  if (typeof encoded !== "string" || encoded.length > ENVELOPE_BASE64_MAX) throw Error("BUSINESS_ENVELOPE");
  const bytes = decodeCanonical(encoded);
  if (!envelopeSizeAdmitted(bytes.byteLength)) throw Error("BUSINESS_ENVELOPE");
  const v = parseStrict(bytes, PRODUCER_ENVELOPE_MAX_BYTES);
  if (!object(v) || !same(Object.keys(v).sort(), ["body", "outer"]) || !validateBusinessRecord(v.body) || !object(v.outer) || !Buffer.from(canonicalBytes(v)).equals(Buffer.from(bytes))) throw Error("BUSINESS_ENVELOPE");
  const body = v.body as Record<string, Json>, outer = v.outer;
  const keys = [...LINUX_FIELDS.filter(k => !k.endsWith("_digest")), "machine_id"];
  if (!same(Object.keys(outer).sort(), [...keys, "signature"].sort()) || keys.some(k => !same(body[k], outer[k])) || typeof outer.signature !== "string") throw Error("BUSINESS_ENVELOPE");
  decodeCanonical(outer.signature, 64);
  return {bytes, record: v as unknown as JoinRecord};
}
export function deliveryIdentity(bytes: Uint8Array, record: JoinRecord): BusinessDeliveryIdentity {
  return {version: 1, sequence: record.body.sequence as number, commitment: joinCommitment(record), envelope_sha256: "sha256:" + createHash("sha256").update(bytes).digest("hex")};
}
/** Projection reads only the verified body. Transport metadata never becomes authority. */
export function projectBusinessRecord(record: JoinRecord): BusinessVerifiedRecord {
  return Object.fromEntries(Object.entries(data.projection).map(([key, source]) => [key, structuredClone(record.body[source])])) as BusinessVerifiedRecord;
}
export function parseBusinessEvent(value: unknown): {bytes: Uint8Array; record: JoinRecord; identity: BusinessDeliveryIdentity} {
  if (!appendShape("event", value)) throw Error("BUSINESS_EVENT");
  const event = value as Record<string, unknown>;
  const parsed = parseBusinessEnvelope(event.business_envelope as string);
  if (event.captured_at_unix_ms !== parsed.record.body.captured_at_unix_ms || event.event_canonical_json !== Buffer.from(canonicalBytes(parsed.record.body)).toString("utf8")) throw Error("BUSINESS_PROJECTION");
  return {...parsed, identity: deliveryIdentity(parsed.bytes, parsed.record)};
}

/** Preserve duplicate-key evidence at the serialized event boundary. */
export function parseBusinessEventBytes(bytes: Uint8Array): ReturnType<typeof parseBusinessEvent> {
  const value = parseStrict(bytes, SIGNER_FRAME_MAX_BYTES);
  if (!Buffer.from(canonicalBytes(value)).equals(Buffer.from(bytes))) throw Error("BUSINESS_EVENT_CANONICAL");
  return parseBusinessEvent(value);
}
