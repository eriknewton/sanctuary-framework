// Must match business_profile/append_contract.rs; checkpoint codecs remain outside live wire roots.
import data from "./business-append-contract.json";
import checkpointBounds from "./checkpoint-bounds.json";
import {canonicalBytes} from "./contract.js";
import {joinStateValid, parseJoinState} from "./record-joins.js";
import {anchorSchema, anchorDigest} from "../linux-business/activation-anchor.js";
import {parseStrict} from "../smb/parse-strict.js";
import {appendScalarShape, appendWireShape} from "./business-append-wire.js";
// Must match the ID_HEX_LENGTH definition in business-append-wire.ts.
export {ID_HEX_LENGTH} from "./business-append-wire.js";
// Must match the DIGEST_HEX_LENGTH definition in business-append-wire.ts.
export {DIGEST_HEX_LENGTH} from "./business-append-wire.js";
// Must match the SAFE_INTEGER definition in business-append-wire.ts.
export {SAFE_INTEGER} from "./business-append-wire.js";
// Must match the BUSINESS_SIGNATURE_TEXT_BYTES definition in business-append-wire.ts.
export {BUSINESS_SIGNATURE_TEXT_BYTES} from "./business-append-wire.js";
// Must match the BUSINESS_ENCODING_WIDTHS definition in business-append-wire.ts.
export {BUSINESS_ENCODING_WIDTHS} from "./business-append-wire.js";
// Must match the APPEND_CONTRACT definition in business-append-wire.ts.
export {APPEND_CONTRACT} from "./business-append-wire.js";
// Must match the PRODUCER_ENVELOPE_MAX_BYTES definition in business-append-wire.ts.
export {PRODUCER_ENVELOPE_MAX_BYTES} from "./business-append-wire.js";
// Must match the ENVELOPE_BASE64_MAX definition in business-append-wire.ts.
export {ENVELOPE_BASE64_MAX} from "./business-append-wire.js";
// Must match the BusinessDeliveryIdentity definition in business-append-wire.ts.
export {type BusinessDeliveryIdentity} from "./business-append-wire.js";
// Must match business_wal.rs persist_ts_fact: W reads back the exact TS fact and delivered cursor before n+1 delivery.
// Must match the BusinessDeliveryAck definition in business-append-wire.ts.
export {type BusinessDeliveryAck} from "./business-append-wire.js";
// Must match the BusinessVerifiedRecord definition in business-append-wire.ts.
export {type BusinessVerifiedRecord} from "./business-append-wire.js";
// Must match the envelopeSizeAdmitted definition in business-append-wire.ts.
export {envelopeSizeAdmitted} from "./business-append-wire.js";
// Must match the appendScalarShape definition in business-append-wire.ts.
export {appendScalarShape} from "./business-append-wire.js";
// Must match the appendWireShape definition in business-append-wire.ts.
export {appendWireShape} from "./business-append-wire.js";
// Must match the parseBusinessEnvelope definition in business-append-wire.ts.
export {parseBusinessEnvelope} from "./business-append-wire.js";
// Must match the deliveryIdentity definition in business-append-wire.ts.
export {deliveryIdentity} from "./business-append-wire.js";
// Must match the projectBusinessRecord definition in business-append-wire.ts.
export {projectBusinessRecord} from "./business-append-wire.js";
// Must match the parseBusinessEvent definition in business-append-wire.ts.
export {parseBusinessEvent} from "./business-append-wire.js";
// Must match the parseBusinessEventBytes definition in business-append-wire.ts.
export {parseBusinessEventBytes} from "./business-append-wire.js";
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a: unknown, b: unknown) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
/** Shared field tables own exact shapes; these checks confer no authority. */
export function appendShape(name: "identity" | "ack" | "event" | "checkpoint" | "observation" | "wal_checkpoint" | "retained_original", value: unknown): boolean {
  try {
  if (name === "identity" || name === "ack" || name === "event") return appendWireShape(name, value);
  if (!Object.hasOwn(data,name)) return false;
  const fields: Record<string, unknown> = data[name];
  if (!object(value) || Object.keys(value).length !== Object.keys(fields).length) return false;
  const valid = Object.entries(fields).every(([key, token]) => {
    if (!Object.hasOwn(value, key)) return false;
    const v = value[key];
    switch (token) {
      case "identity": case "observation": case "wal_checkpoint": return appendShape(token, v);
      case "nullable_anchor": return v === null || anchorSchema.safeParse(v).success;
      case "observation_state": return (data.observation_states as unknown[]).includes(v);
      case "join_state": return joinStateValid(v);
      // Must match the native owner through the executed whole-set limits pin.
      case "retained_originals": return Array.isArray(v) && v.length <= data.limits.d_undrained_max && v.every(row => appendShape("retained_original",row));
      default: return appendScalarShape(token, v);
    }
  });
  if (!valid || name !== "observation") return valid;
  // Must match drain_protocol READ_REPLY: shape does not confer mutation authority.
  if (value.state === "ABSENT") return value.anchor === null && value.anchor_digest === null && value.latched === false;
  const anchor=anchorSchema.safeParse(value.anchor);
  return anchor.success && value.anchor_digest === anchorDigest(anchor.data) && value.latched === anchor.data.recovery_required;
  } catch { return false; }
}
/** Must match append_checkpoint::Candidate::parse; raw join bytes retain numeric spelling. */
export function parseBusinessCheckpoint(bytes: Uint8Array): Record<string, unknown> {
  const maximum = Math.ceil(checkpointBounds.honest_max_bytes / checkpointBounds.part_bytes) * checkpointBounds.part_bytes;
  const value = parseStrict(bytes, maximum);
  if (!Buffer.from(canonicalBytes(value)).equals(Buffer.from(bytes))) throw Error("BUSINESS_CHECKPOINT_CANONICAL");
  const originalObject = (input: Uint8Array, marker: string): Uint8Array => {
    const source = Buffer.from(input), token = Buffer.from(marker);
    const at = source.indexOf(token);
    if (at < 0) throw Error("BUSINESS_CHECKPOINT");
    const start = at + token.length - 1;
    let depth = 0, string = false, escaped = false;
    for (let i = start; i < source.length; i++) {
      const b = source[i];
      if (string) { if (b === 34 && !escaped) string = false; escaped = b === 92 && !escaped; }
      else if (b === 34) string = true;
      else if (b === 123) depth++;
      else if (b === 125 && --depth === 0) return source.subarray(start, i + 1);
    }
    throw Error("BUSINESS_CHECKPOINT");
  };
  const wal = originalObject(bytes, '"wal_checkpoint":{');
  const join = parseJoinState(originalObject(wal, '"join_state":{'));
  if (!appendShape("checkpoint", value) || !object(value) || !object(value.wal_checkpoint)
      || !same(value.wal_checkpoint.join_state, join)) throw Error("BUSINESS_CHECKPOINT");
  return value;
}
