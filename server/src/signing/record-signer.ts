import type { z } from "zod";
import { startsWithInternalSigningDomain } from "../core/signing-domains.js";
import { INERT_PAYLOAD_SCHEMA, ROLE_REGISTRY, checkEnvelopeSize, parseRecord, recordMessage, refuse, type SigningRole } from "./contract.js";
import { verifyRecord, type RolePin } from "./strict-verifier.js";

declare const installedBusiness: unique symbol;
/** A future custody admission owns this sealed type; this slice exports no constructor or decoder. */
export interface InstalledBusiness { readonly [installedBusiness]: never; }

/** Exact-message provider, never a digest or caller-selected domain service. */
export interface ExactMessageProvider { sign(message: Uint8Array): Uint8Array; }
// Must match records.rs verify and BusinessPin in linux-business/producer-custody.ts: the grant binds activation, lease and generation to the enrolled subject.
export interface SigningGrant extends RolePin {
  readonly activation_id: string; readonly lease_id: string; readonly generation: number;
}
export interface RecordRequest { role: SigningRole; epoch: number; preimage_bytes: Uint8Array; }
export interface RecordSigner { signRecord(request: RecordRequest): {signature: string; kid: string}; }
/** Contract composition only; attendance, watchdog, storage and permit authority are external obligations. */
export function createRecordSigner(grant: SigningGrant, provider: ExactMessageProvider, payloadSchema: z.ZodType, recordKind: string): RecordSigner {
  // Must match the registered record_kind schema in contract.ts and the verifier adapter selection.
  // Business kinds cannot construct a signer before installed custody can supply authority; append retains its separate legacy contract.
  if (grant.role === ROLE_REGISTRY[0].role && recordKind !== "counter" && recordKind !== "append") return refuse();
  const pin = Object.freeze({...grant});
  return Object.freeze({
    signRecord(request: RecordRequest) {
      try {
        if (Object.keys(request).sort().join(",") !== "epoch,preimage_bytes,role" || request.role !== pin.role || request.epoch !== pin.epoch) return refuse();
        // Caller-controlled shared memory must not change the bytes after admission.
        const preimage = new Uint8Array(new Uint8Array(request.preimage_bytes));
        if (startsWithInternalSigningDomain(preimage)) return refuse();
        // Must match service.ts INERT_SIGNABLE_ADAPTERS: caller schemas cannot widen the live producer adapter.
        const body = parseRecord(preimage, pin.role, pin.role === ROLE_REGISTRY[0].role && recordKind === "counter" ? INERT_PAYLOAD_SCHEMA : payloadSchema, recordKind);
        if (body.kid !== pin.kid || body.identity_id !== pin.identity_id || body.machine_id !== pin.machine_id || body.epoch !== pin.epoch) return refuse();
        if (pin.role.startsWith("extension:linux-business-") &&
            (body.activation_id !== pin.activation_id || body.lease_id !== pin.lease_id || body.generation !== pin.generation)) return refuse();
        checkEnvelopeSize(pin.role, body, preimage);
        // The signer adds the fixed role domain so a caller cannot substitute a digest or another protocol's message.
        const signature = Buffer.from(provider.sign(recordMessage(pin.role, preimage))).toString("base64url");
        if (!verifyRecord(preimage, signature, pin, pin.role === ROLE_REGISTRY[0].role && recordKind === "counter" ? INERT_PAYLOAD_SCHEMA : payloadSchema, recordKind)) return refuse();
        return {signature, kid: pin.kid};
      } catch { return refuse(); }
    },
  });
}
