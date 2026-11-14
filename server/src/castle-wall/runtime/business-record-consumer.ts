import {z} from "zod";
import {canonicalBytes} from "../../signing/contract.js";
import {BUSINESS_PIN_FIELDS, verifyIndexedRecord, type BusinessPin, type OuterRecordIndex} from "../../linux-business/producer-custody.js";
import {joinStateValid, verifyBusinessJoin, type JoinState, type JoinRecord} from "../../signing/record-joins.js";
import {envelopeSizeAdmitted, parseBusinessEvent, parseBusinessEventBytes, parseBusinessEnvelope, deliveryIdentity, projectBusinessRecord, type BusinessDeliveryAck, type BusinessDeliveryIdentity, type BusinessVerifiedRecord} from "../../signing/business-append-contract.js";

export interface DurableBusinessAcceptance {
  envelope: Uint8Array;
  projection: BusinessVerifiedRecord;
  checkpoint: JoinState;
  identity: BusinessDeliveryIdentity;
}
/** Trusted composition dependency. persist atomically stores all four fields,
 * reads them back, and resolves only when durable. Repeating exact bytes is
 * idempotent; a changed delivery at an owned sequence must refuse. */
export interface BusinessDurableSink {
  load(): Promise<DurableBusinessAcceptance | null>;
  persist(acceptance: DurableBusinessAcceptance): Promise<DurableBusinessAcceptance>;
}
export type ConsumerMode =
  | {kind: "Legacy"; consume: (event: unknown) => Promise<void>}
  | {kind: "Business"; pin: BusinessPin; committed_state: JoinState; durable_sink: BusinessDurableSink};
const equal = (a: unknown,b: unknown) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const sameEnvelope = (a: Uint8Array,b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const copy = (value: DurableBusinessAcceptance): DurableBusinessAcceptance => structuredClone(value);
const equalAcceptance = (a: DurableBusinessAcceptance,b: DurableBusinessAcceptance) => sameEnvelope(a.envelope,b.envelope) && equal(a.identity,b.identity) && equal(a.projection,b.projection) && equal(a.checkpoint,b.checkpoint);
/** Mode and pins are supplied by trusted composition, never selected by event fields. */
export async function createBusinessRecordConsumer(mode: ConsumerMode): Promise<{accept(event: unknown): Promise<BusinessDeliveryAck | void>; committedState(): JoinState | null; pendingDelivery(): BusinessDeliveryIdentity | null}> {
  if (mode.kind === "Legacy") {
    return {committedState:()=>null,pendingDelivery:()=>null,async accept(event) {
      if (event !== null && typeof event === "object" && "business_envelope" in event && event.business_envelope !== null && event.business_envelope !== undefined) throw Error("BUSINESS_IN_LEGACY");
      await mode.consume(event);
    }};
  }
  const pin=structuredClone(mode.pin), sink=mode.durable_sink;
  let committed=structuredClone(mode.committed_state);
  // The explicit enrollment pin and independent checkpoint must agree before
  // any candidate can be examined. Neither can fill a missing field in the other.
  if (!joinStateValid(committed) || BUSINESS_PIN_FIELDS.some(key => pin[key] !== ({...committed.pin,...committed.grant})[key]) || pin.public_key !== committed.pin.public_key) throw Error("BUSINESS_PIN");
  function authentic(record: JoinRecord): boolean {
    return verifyIndexedRecord(canonicalBytes(record.body),record.outer.signature as string,pin,record.outer as unknown as OuterRecordIndex,z.unknown(),record.body.record_kind as string);
  }
  function validateStored(stored: DurableBusinessAcceptance): void {
    if (!envelopeSizeAdmitted(stored.envelope.byteLength)) throw Error("BUSINESS_DURABLE_STATE");
    const {record,bytes}=parseBusinessEnvelope(Buffer.from(stored.envelope).toString("base64url"));
    if (!authentic(record) || !equal(deliveryIdentity(bytes,record),stored.identity) || !equal(projectBusinessRecord(record),stored.projection) || !joinStateValid(stored.checkpoint) || stored.checkpoint.anchor.sequence !== stored.identity.sequence || stored.checkpoint.anchor.commitment !== stored.identity.commitment) throw Error("BUSINESS_DURABLE_STATE");
  }
  let last=await sink.load();
  if(last) {
    validateStored(last);
    if(!equal(last.checkpoint,committed)) {
      // A lost ACK may leave the trusted starting checkpoint one delivery behind.
      const {record}=parseBusinessEnvelope(Buffer.from(last.envelope).toString("base64url"));
      const result=verifyBusinessJoin(committed,record);
      if(result.refusal_code || !equal(result.final_state,last.checkpoint)) throw Error("BUSINESS_DURABLE_STATE");
      committed=structuredClone(last.checkpoint);
    }
    last=copy(last);
  }
  let busy=false;
  let pending: DurableBusinessAcceptance | null=null;
  return {
    committedState:()=>structuredClone(committed),
    pendingDelivery:()=>pending ? structuredClone(pending.identity) : null,
    async accept(event) {
      // One owned operation includes sink completion, preventing overlapping state advances.
      if(busy) throw Error("BUSINESS_BUSY");
      busy=true;
      try {
        const {record,bytes,identity}=event instanceof Uint8Array ? parseBusinessEventBytes(event) : parseBusinessEvent(event);
        if(!authentic(record)) throw Error("BUSINESS_AUTH");
        if(last && equal(last.identity,identity)) {
          if(!sameEnvelope(last.envelope,bytes)) throw Error("BUSINESS_REPLAY");
          return {version:1,identity:structuredClone(last.identity)};
        }
        if(pending && (!equal(pending.identity,identity) || !sameEnvelope(pending.envelope,bytes))) throw Error("BUSINESS_HELD");
        const result=verifyBusinessJoin(committed,record);
        if(result.refusal_code) throw Error("BUSINESS_JOIN");
        const acceptance={envelope:bytes,projection:projectBusinessRecord(record),checkpoint:result.final_state,identity};
        pending=copy(acceptance);
        // The required trusted sink performs atomic persistence and readback.
        // A throw keeps the same pending E and the old committed state for retry.
        const durable=await sink.persist(copy(acceptance));
        validateStored(durable);
        if(!equalAcceptance(durable,acceptance)) throw Error("BUSINESS_PERSISTENCE");
        last=copy(durable);committed=structuredClone(durable.checkpoint);pending=null;
        return {version:1,identity:structuredClone(durable.identity)};
      } finally {busy=false;}
    },
  };
}
