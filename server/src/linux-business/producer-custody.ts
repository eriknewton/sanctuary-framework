import { z } from "zod";
import { canonicalBytes, parseRecord, refuse, SIGNER_FRAME_MAX_BYTES, SIGNER_HEADER_MAX_BYTES, SIGNER_PREIMAGE_MAX_BYTES, SIGNER_PROTOCOL, ROLE_REGISTRY, type SigningRole } from "../signing/contract.js";
import { parseStrict } from "../smb/parse-strict.js";
import { verifyRecord, type RolePin } from "../signing/strict-verifier.js";

const id = z.string().regex(/^[a-f0-9]{32}$/);
const integer = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const headerSchema = z.object({v: z.literal(1), protocol: z.literal(SIGNER_PROTOCOL), request_id: id, activation_id: id, lease_id: id,
  generation: integer, epoch: integer.min(1), role: z.enum(ROLE_REGISTRY.map(row => row.role) as [SigningRole, ...SigningRole[]]), deadline_boottime_ns: z.string().regex(/^(0|[1-9][0-9]*)$/).refine(value => BigInt(value) <= 18446744073709551615n),
  preimage_length: integer.max(SIGNER_PREIMAGE_MAX_BYTES),
}).strict();
export type SignerHeader = z.infer<typeof headerSchema>;
/** Pure bounded framing only; this module opens no sockets or stores. */
export function encodeSignerFrame(header: SignerHeader, preimage: Uint8Array): Uint8Array {
  try {
    const checked = headerSchema.parse(header);
    const encoded = canonicalBytes(checked);
    if (encoded.length > SIGNER_HEADER_MAX_BYTES || checked.preimage_length !== preimage.length) return refuse();
    const size = Buffer.alloc(4); size.writeUInt32BE(encoded.length);
    return Buffer.concat([size, encoded, preimage]);
  } catch { return refuse(); }
}
export function decodeSignerFrame(frame: Uint8Array): {header: SignerHeader; preimage: Uint8Array} {
  try {
    if (frame.length < 4 || frame.length > SIGNER_FRAME_MAX_BYTES) return refuse();
    const length = Buffer.from(frame.buffer, frame.byteOffset, 4).readUInt32BE();
    if (length > SIGNER_HEADER_MAX_BYTES || 4 + length > frame.length) return refuse();
    const bytes = frame.subarray(4, 4 + length);
    const header = headerSchema.parse(parseStrict(bytes, SIGNER_HEADER_MAX_BYTES));
    if (!Buffer.from(canonicalBytes(header)).equals(Buffer.from(bytes)) || frame.length !== 4 + length + header.preimage_length) return refuse();
    return {header, preimage: frame.slice(4 + length)};
  } catch { return refuse(); }
}
export interface OuterRecordIndex {
  sequence: number; prior_commitment: string; captured_at_unix_ms: number; captured_at_boottime_ns: string;
  machine_id: string; boot_id: string; activation_id: string; lease_id: string; generation: number;
}
export function verifyIndexedRecord(preimage: Uint8Array, signature: string, pin: RolePin, outer: OuterRecordIndex, payloadSchema: z.ZodType): boolean {
  try {
    if (pin.role !== "extension:linux-business-producer-v0") return false;
    const body = parseRecord(preimage, pin.role as SigningRole, payloadSchema);
    for (const key of ["sequence", "prior_commitment", "captured_at_unix_ms", "captured_at_boottime_ns", "machine_id", "boot_id", "activation_id", "lease_id", "generation"] as const) {
      if (body[key] !== outer[key]) return false;
    }
    return verifyRecord(preimage, signature, pin, payloadSchema);
  } catch { return false; }
}
