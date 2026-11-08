import { z } from "zod";
import { canonicalBytes, decodeCanonical, PRODUCER_ROTATION_DOMAIN, CUSTODY_SIGNATURE_SCHEME, refuse, safeInteger, roleKid } from "./contract.js";
import { strictVerify, type RolePin } from "./strict-verifier.js";
import type { ExactMessageProvider } from "./record-signer.js";

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const rotationSchema = z.object({
  v: z.literal(1), signature_scheme: z.literal(CUSTODY_SIGNATURE_SCHEME), role: z.string(), machine_id: z.string().regex(/^[a-f0-9]{32}$/),
  old_epoch: safeInteger.min(1), new_epoch: safeInteger.min(1), old_kid: z.string(), new_kid: z.string(),
  old_descriptor_digest: digest, new_descriptor_digest: digest, old_terminal_sequence: safeInteger,
  old_terminal_commitment: z.union([digest, z.literal("GENESIS")]), transaction_id: z.string().regex(/^[a-f0-9]{32}$/), reason: z.string().min(1).max(256),
}).strict();
export type RotationBody = z.infer<typeof rotationSchema>;
function rotationMessage(body: RotationBody, oldPin: RolePin, newPin: RolePin): Uint8Array {
  const parsed = rotationSchema.parse(body);
  if (parsed.role !== oldPin.role || parsed.role !== newPin.role || oldPin.machine_id !== newPin.machine_id || parsed.machine_id !== oldPin.machine_id ||
      parsed.old_epoch !== oldPin.epoch || parsed.new_epoch !== newPin.epoch || newPin.epoch !== oldPin.epoch + 1 ||
      parsed.old_kid !== oldPin.kid || parsed.new_kid !== newPin.kid || oldPin.public_key === newPin.public_key ||
      oldPin.kid !== roleKid(oldPin.role, oldPin.epoch, oldPin.public_key) || newPin.kid !== roleKid(newPin.role, newPin.epoch, newPin.public_key)) return refuse();
  return Buffer.concat([Buffer.from(PRODUCER_ROTATION_DOMAIN), canonicalBytes(parsed)]);
}
/** Candidate proof only; a future journal must commit both signatures before changing any binding. */
export function prepareRotation(body: RotationBody, oldPin: RolePin, newPin: RolePin, oldProvider: ExactMessageProvider, newProvider: ExactMessageProvider) {
  try {
    const message = rotationMessage(body, oldPin, newPin);
    const result = {old_signature: Buffer.from(oldProvider.sign(message)).toString("base64url"), new_signature: Buffer.from(newProvider.sign(message)).toString("base64url")};
    if (!verifyRotation(body, oldPin, newPin, result)) return refuse();
    return result;
  } catch { return refuse(); }
}
export function verifyRotation(body: RotationBody, oldPin: RolePin, newPin: RolePin, signatures: {old_signature: string; new_signature: string}): boolean {
  try {
    const message = rotationMessage(body, oldPin, newPin);
    return strictVerify(message, decodeCanonical(signatures.old_signature, 64), decodeCanonical(oldPin.public_key, 32)) &&
      strictVerify(message, decodeCanonical(signatures.new_signature, 64), decodeCanonical(newPin.public_key, 32));
  } catch { return false; }
}
