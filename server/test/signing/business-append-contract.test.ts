// W-PROVENANCE
// W-ENVELOPE-CAP
// W-JOIN-LIFECYCLE
import {it, expect, vi} from "vitest";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
import {APPEND_CONTRACT, appendShape, envelopeSizeAdmitted, parseBusinessEnvelope, parseBusinessEvent, parseBusinessEventBytes, deliveryIdentity, projectBusinessRecord} from "../../src/signing/business-append-contract.js";
import {initialLifecycle, lifecycleStep} from "../../src/signing/business-join-lifecycle.js";
import * as signingContract from "../../src/signing/contract.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {BUSINESS_KINDS, validateBusinessRecord} from "../../src/signing/linux-business-records.js";
import type {JoinRecord} from "../../src/signing/record-joins.js";
const corpus = loadCheckedCorpus("record_join_vectors.json") as {cases: Array<{id:string;records:JoinRecord[]}>};
const record = corpus.cases[0].records[0];
const bytes = canonicalBytes(record);
const encoded = Buffer.from(bytes).toString("base64url");
it.each(APPEND_CONTRACT.identity_vectors)("delivery identity $id", row => {
  expect(appendShape("identity", row.value)).toBe(row.accepted);
  expect(appendShape("ack", {version:1,identity:row.value})).toBe(row.accepted);
});
it("exact envelope cap predicates admit 4096 and refuse 4097", () => {
  expect(envelopeSizeAdmitted(4096)).toBe(true);
  expect(envelopeSizeAdmitted(4097)).toBe(false);
  expect(()=>parseBusinessEnvelope(Buffer.alloc(4097,32).toString("base64url"))).toThrow();
});
it("exact canonical envelope and business event preserve every signed byte", () => {
  expect(parseBusinessEnvelope(encoded)).toEqual({bytes:Buffer.from(bytes),record});
  const event = {seq:50,captured_at_unix_ms:record.body.captured_at_unix_ms,prior_sha256_hex:"0".repeat(64),event_canonical_json:Buffer.from(canonicalBytes(record.body)).toString(),critical:true,business_envelope:encoded,producer_signature_b64url:null,producer_key_id:null};
  expect(parseBusinessEvent(event).identity).toEqual(deliveryIdentity(bytes,record));
  for(const changed of [{...event,critical:false},{...event,business_envelope:null},{...event,producer_key_id:"raw"},{...event,captured_at_unix_ms:99},{...event,event_canonical_json:"{}"}]) expect(()=>parseBusinessEvent(changed)).toThrow();
  expect(()=>parseBusinessEnvelope(encoded+"=")).toThrow();
  expect(()=>parseBusinessEnvelope(Buffer.from('{"body":null,"body":null,"outer":{}}').toString("base64url"))).toThrow();
});
it.each(corpus.cases.filter(row=>row.id.startsWith("provenance-")))("schema boundary $id", row => {
  expect(validateBusinessRecord(row.records.at(-1)!.body)).toBe(row.id.endsWith("-equal"));
});
it.each(APPEND_CONTRACT.lifecycle_vectors)("shared lifecycle $id", row => {
  let state=initialLifecycle();
  const events=APPEND_CONTRACT.lifecycle_events as Record<string,Record<string,unknown>>;
  const states=APPEND_CONTRACT.lifecycle_states as Record<string,unknown>;
  for(const [event,accepted,next] of row.steps) {
    const result=lifecycleStep(state,events[String(event)]);
    expect(result.accepted).toBe(accepted);
    expect(result.state).toEqual(states[String(next)]);
    state=result.state;
  }
});

it.each(APPEND_CONTRACT.ack_vectors)("shared ACK $id", row => {
  expect(appendShape("ack",row.value)).toBe(row.accepted);
});
it.each(APPEND_CONTRACT.event_vectors)("shared event $id", row => {
  if(row.accepted) expect(parseBusinessEvent(row.value).identity).toEqual(deliveryIdentity(bytes,record));
  else expect(()=>parseBusinessEvent(row.value)).toThrow();
});

it("serialized business events reject duplicate wrapper keys before normalization", () => {
  const event=APPEND_CONTRACT.event_vectors[0].value;
  const bytes=canonicalBytes(event);
  expect(parseBusinessEventBytes(bytes).identity).toEqual(deliveryIdentity(canonicalBytes(record),record));
  const duplicate=Buffer.from(Buffer.from(bytes).toString().replace('"critical":true','"critical":true,"critical":true'));
  expect(()=>parseBusinessEventBytes(duplicate)).toThrow();
});

it("checkpoint shapes share complete bounded nested tables without granting authority", () => {
  for(const row of APPEND_CONTRACT.checkpoint_vectors) expect(appendShape("checkpoint",row.value),row.id).toBe(row.accepted);
});

it.each(["constructor","__proto__","toString"])("lifecycle refuses inherited event name %s",type=>{
  const state=initialLifecycle();expect(lifecycleStep(state,{type})).toEqual({accepted:false,state});
});
it("lifecycle refuses a table entry with no implemented transition",async()=>{
  vi.resetModules();
  vi.doMock("../../src/signing/business-append-contract.js",async importOriginal=>{
    const original=await importOriginal<typeof import("../../src/signing/business-append-contract.js")>();
    const cloned=structuredClone(original.APPEND_CONTRACT);
    (cloned.lifecycle as Record<string,string[]>).Future=[];
    return {...original,APPEND_CONTRACT:cloned};
  });
  try {
    const mocked=await import("../../src/signing/business-append-contract.js");
    // The injected entry must be visible, or the first table guard would refuse before the default arm.
    expect(Object.hasOwn(mocked.APPEND_CONTRACT.lifecycle,"Future")).toBe(true);
    const {lifecycleStep:step}=await import("../../src/signing/business-join-lifecycle.js");
    const state=initialLifecycle();expect(step(state,{type:"Future"})).toEqual({accepted:false,state});
  } finally {vi.doUnmock("../../src/signing/business-append-contract.js");vi.resetModules();}
});
it("the exported append contract is frozen at every object and array",()=>{
  function check(value:unknown):void {
    if(value===null || typeof value!=="object") return;
    expect(Object.isFrozen(value)).toBe(true);
    for(const child of Object.values(value)) check(child);
  }
  check(APPEND_CONTRACT);
  expect(()=>{(APPEND_CONTRACT.lifecycle as Record<string,string[]>).Future=[];}).toThrow(TypeError);
  expect(()=>{APPEND_CONTRACT.lifecycle.SignAdmitted.push("authority");}).toThrow(TypeError);
});
it("the oversized lifecycle envelope keeps a full-width signature and exceeds the byte cap",()=>{
  const record=APPEND_CONTRACT.lifecycle_events["oversize-envelope"].record;
  expect(record.outer.signature).toHaveLength(86);
  expect(canonicalBytes(record)).toHaveLength(4097);
});

it("real envelope parser checks 4097 before decode and admits 4096 to decoding",()=>{
  const decode=vi.spyOn(signingContract,"decodeCanonical");
  try {
    for(const length of [4096,4097]) {
      const shaped=structuredClone(record);
      const payload=shaped.body.payload as Record<string,unknown>;
      payload.reason="a".repeat(length-bytes.length+String(payload.reason).length);
      const candidate=canonicalBytes(shaped);
      expect(candidate.length).toBe(length);
      decode.mockClear();
      let failure: unknown;
      try {parseBusinessEnvelope(Buffer.from(candidate).toString("base64url"));} catch(error) {failure=error;}
      expect(decode).toHaveBeenCalledTimes(length===4096?1:0);
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toBe("BUSINESS_ENVELOPE");
    }
  } finally {decode.mockRestore();}
});

it.each(APPEND_CONTRACT.projection_vectors)("shared projection $id",row=>{
  const candidate=row.record as unknown as JoinRecord;
  expect(validateBusinessRecord(candidate.body)).toBe(true);
  expect(projectBusinessRecord(candidate)).toEqual(row.expected);
});
it("projection vectors cover the entire schema kind set and permit unknown",()=>{
  expect([...new Set(APPEND_CONTRACT.projection_vectors.map(row=>row.record.body.record_kind))].sort()).toEqual([...BUSINESS_KINDS].sort());
  const unknown=APPEND_CONTRACT.projection_vectors.find(row=>row.id==="permit-unknown")!;
  expect(unknown.record.body.payload).toMatchObject({type:"permit",outcome:"unknown",effect:"EFFECT_UNKNOWN"});
});
