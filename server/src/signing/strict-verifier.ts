import type { z } from "zod";
import { verify, isStrictEd25519PointEncoding } from "../core/identity.js";
import { checkEnvelopeSize, decodeCanonical, parseRecord, recordMessage, roleKid, ROLE_SIGNATURE_SCHEME, type SigningRole } from "./contract.js";

export interface RolePin { readonly role: SigningRole; readonly epoch: number; readonly public_key: string; readonly kid: string; readonly identity_id: string; readonly machine_id: string; }
/** Encoding admission is independently testable even where the equation would also reject a point. */
export function strictEncodingProfile(signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (!isStrictEd25519PointEncoding(publicKey) || signature.length !== 64 ||
      !isStrictEd25519PointEncoding(signature.subarray(0, 32))) return false;
  const scalar = BigInt("0x" + Buffer.from(signature.subarray(32)).reverse().toString("hex"));
  // Ed25519 subgroup order L = 2^252 + 27742317777372353535851937790883648493.
  return scalar < 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
}
/** Both point gates are part of the public strict profile, including the self-check. */
export function strictVerify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  return strictEncodingProfile(signature, publicKey) && verify(message, signature, publicKey);
}
export function verifyRecord(preimage: Uint8Array, signature: string, pin: RolePin, payloadSchema: z.ZodType, recordKind: string): boolean {
  try {
    // Must match the trusted record_kind selection in record-signer.ts and contract.ts.
    const body = parseRecord(preimage, pin.role, payloadSchema, recordKind);
    checkEnvelopeSize(pin.role, body, preimage);
    // A valid legacy signature cannot convey role authority because its scheme and key binding name another protocol.
    if (body.signature_scheme !== ROLE_SIGNATURE_SCHEME || body.kid !== roleKid(pin.role, pin.epoch, pin.public_key) ||
        body.kid !== pin.kid || body.epoch !== pin.epoch || body.identity_id !== pin.identity_id || body.machine_id !== pin.machine_id) return false;
    return strictVerify(recordMessage(pin.role, preimage), decodeCanonical(signature, 64), decodeCanonical(pin.public_key, 32));
  } catch { return false; }
}
