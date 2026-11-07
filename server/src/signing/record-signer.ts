import type { z } from "zod";
import { startsWithInternalSigningDomain } from "../core/signing-domains.js";
import { checkEnvelopeSize, parseRecord, recordMessage, refuse, type SigningRole } from "./contract.js";
import { verifyRecord, type RolePin } from "./strict-verifier.js";

/** Exact-message provider, never a digest or caller-selected domain service. */
export interface ExactMessageProvider { sign(message: Uint8Array): Uint8Array; }
export interface SigningGrant extends RolePin {
  readonly activation_id: string; readonly lease_id: string; readonly generation: number;
}
export interface RecordRequest { role: SigningRole; epoch: number; preimage_bytes: Uint8Array; }
export interface RecordSigner { signRecord(request: RecordRequest): {signature: string; kid: string}; }
/** Contract composition only; attendance, watchdog, storage and permit authority are external obligations. */
export function createRecordSigner(grant: SigningGrant, provider: ExactMessageProvider, payloadSchema: z.ZodType): RecordSigner {
  const pin = Object.freeze({...grant});
  return Object.freeze({
    signRecord(request: RecordRequest) {
      try {
        if (Object.keys(request).sort().join(",") !== "epoch,preimage_bytes,role" || request.role !== pin.role || request.epoch !== pin.epoch) return refuse();
        const preimage = new Uint8Array(request.preimage_bytes);
        if (startsWithInternalSigningDomain(preimage)) return refuse();
        const body = parseRecord(preimage, pin.role, payloadSchema);
        if (body.kid !== pin.kid || body.identity_id !== pin.identity_id || body.machine_id !== pin.machine_id || body.epoch !== pin.epoch) return refuse();
        if (pin.role.startsWith("extension:linux-business-") &&
            (body.activation_id !== pin.activation_id || body.lease_id !== pin.lease_id || body.generation !== pin.generation)) return refuse();
        checkEnvelopeSize(pin.role, body, preimage);
        // The signer adds the fixed role domain so a caller cannot substitute a digest or another protocol's message.
        const signature = Buffer.from(provider.sign(recordMessage(pin.role, preimage))).toString("base64url");
        if (!verifyRecord(preimage, signature, pin, payloadSchema)) return refuse();
        return {signature, kid: pin.kid};
      } catch { return refuse(); }
    },
  });
}
