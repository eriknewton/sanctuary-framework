import { z } from "zod";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { parseStrict } from "../smb/parse-strict.js";
import { canonicalBytes, decodeCanonical, refuse, safeInteger, ROLE_REGISTRY, PRODUCER_CUSTODY_BINDING_AAD, PRODUCER_CUSTODY_BINDING_PURPOSE, type SigningRole } from "./contract.js";

// Must match provision.ts: role identity comes from the authenticated binding fields, never an identity label.
export interface BindingContext { fortress_id: string; machine_id: string; role: SigningRole; }
const bindingSchema = z.object({
  identity_id: z.string().regex(/^[a-f0-9]{32}$/), role: z.enum(ROLE_REGISTRY.map(row => row.role) as [SigningRole, ...SigningRole[]]),
  machine_id: z.string().regex(/^[a-f0-9]{32}$/), epoch: safeInteger.min(1), kid: z.string().regex(/^k1:sha256:[a-f0-9]{64}$/),
  roster_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/), high_water: safeInteger,
  transaction_state: z.enum(["LOCKED", "PROVISIONING", "ROTATING", "RECOVERING", "RECOVERY_REQUIRED", "RETIRED"]),
}).strict();
export type CustodyBinding = z.infer<typeof bindingSchema>;
export function validateEncryptedPayload(payload: EncryptedPayload): void {
  if (canonicalBytes(payload).length > 65536) return refuse();
  if (Object.keys(payload).sort().join(",") !== "alg,ct,iv,ts,v" || payload.v !== 1 || payload.alg !== "aes-256-gcm" || typeof payload.ts !== "string" ||
      decodeCanonical(payload.iv).length !== 12 || decodeCanonical(payload.ct).length < 16) refuse();
}
function aad(context: BindingContext): Uint8Array {
  if (!/^[a-f0-9]{32}$/.test(context.fortress_id) || !/^[a-f0-9]{32}$/.test(context.machine_id)) return refuse();
  return Buffer.concat([Buffer.from(PRODUCER_CUSTODY_BINDING_AAD), canonicalBytes({fortress_id: context.fortress_id, machine_id: context.machine_id, role: context.role})]);
}
/** Codec only: the future held-directory store must supply atomic durability and independent high-water evidence. */
export function encryptBinding(binding: CustodyBinding, master: Uint8Array, context: BindingContext): EncryptedPayload {
  const key = derivePurposeKey(master, PRODUCER_CUSTODY_BINDING_PURPOSE);
  let plain: Uint8Array | undefined;
  try {
    const parsed = bindingSchema.parse(binding);
    if (parsed.role !== context.role || parsed.machine_id !== context.machine_id) return refuse();
    plain = canonicalBytes(parsed);
    return encrypt(plain, key, aad(context));
  } catch { return refuse(); }
  finally { key.fill(0); plain?.fill(0); }
}
export function decryptBinding(payload: EncryptedPayload, master: Uint8Array, context: BindingContext): CustodyBinding {
  const key = derivePurposeKey(master, PRODUCER_CUSTODY_BINDING_PURPOSE);
  let plain: Uint8Array | undefined;
  try {
    if (canonicalBytes(payload).length > 65536) return refuse();
    validateEncryptedPayload(payload);
    plain = decrypt(payload, key, aad(context));
    const parsed = bindingSchema.parse(parseStrict(plain, 65536));
    if (parsed.role !== context.role || parsed.machine_id !== context.machine_id || !Buffer.from(canonicalBytes(parsed)).equals(Buffer.from(plain))) return refuse();
    return parsed;
  } catch { return refuse(); }
  finally { key.fill(0); plain?.fill(0); }
}
