// fail-before-exempt: live Business-loop assertions use the complete pinned native record corpus.
// W-TS-CONSUMER
import {it, expect, vi} from "vitest";
import {startLinuxAuditDrainLoop} from "../../src/castle-wall/runtime/linux-audit-drain.js";
import type {IpcClient} from "../../src/castle-wall/runtime/ipc-client.js";
import type {BusinessPin} from "../../src/linux-business/producer-custody.js";
import {BUSINESS_KINDS} from "../../src/signing/linux-business-records.js";
import {ed25519} from "@noble/curves/ed25519";
import {ROLE_REGISTRY,canonicalBytes} from "../../src/signing/contract.js";
import {type JoinRecord, type JoinState} from "../../src/signing/record-joins.js";
import type {BusinessDurableSink, DurableBusinessAcceptance} from "../../src/castle-wall/runtime/business-record-consumer.js";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
const corpus = loadCheckedCorpus("record_join_vectors.json") as {cases:{id:string;initial:JoinState;records:JoinRecord[];expect:{refusal_code:string|null}}[]};
const first=corpus.cases[0];
const event=(record:JoinRecord)=>({seq:record.body.sequence,captured_at_unix_ms:record.body.captured_at_unix_ms,prior_sha256_hex:null,event_canonical_json:Buffer.from(canonicalBytes(record.body)).toString(),critical:true,business_envelope:Buffer.from(canonicalBytes(record)).toString("base64url"),producer_signature_b64url:null,producer_key_id:null});
class Sink implements BusinessDurableSink {
  value:DurableBusinessAcceptance|null=null;
  load=async()=>structuredClone(this.value);
  persist=vi.fn(async(value:DurableBusinessAcceptance)=>{this.value=structuredClone(value);return structuredClone(value);});
}
async function cycle(events:unknown[], initial=first.initial, sink=new Sink(), {waitForCompletion=true}={}) {
  const acks=vi.fn(async()=>{}), errors:Error[]=[];let timer:(()=>void)|null=null;
  let finish:()=>void=()=>{};let done=new Promise<void>(r=>{finish=r;});
  const handle=startLinuxAuditDrainLoop({businessDrainRequest:async()=>({event:events.shift()??null,error:null}),sendBusinessAck:acks} as unknown as IpcClient,null,{
    mode:{kind:"Business",pin:{...initial.pin,...initial.grant} as unknown as BusinessPin,committed_state:initial,durable_sink:sink},
    onDrainFault:error=>errors.push(error),setTimer:cb=>{timer=cb;finish();return 1;},clearTimer:()=>{},
  });
  if(waitForCompletion) await done;
  return {handle,acks,errors,sink,done,next:async()=>{done=new Promise<void>(r=>{finish=r;});timer!();await done;}};
}
it("delivers every shared positive record kind and projection through the live loop",async()=>{
  const seen=new Set<string>();
  for(const row of corpus.cases.filter(c=>c.expect.refusal_code===null && c.records.length)){
    const c=await cycle(row.records.map(event),row.initial);
    try {
      for(let i=0;i<row.records.length;i++){
        if(i) await c.next();
        expect(c.errors,row.id).toEqual([]);expect(c.acks).toHaveBeenCalledTimes(i+1);
        expect(c.sink.value!.projection.kind).toBe(row.records[i].body.record_kind);
        seen.add(row.records[i].body.record_kind as string);
      }
    } finally {await c.handle.stop();}
  }
  expect([...seen].sort()).toEqual([...BUSINESS_KINDS].sort());
});
it("rejects raw mixed stripped and malformed nested Business events without ACK",async()=>{
  const base=event(first.records[0]);
  const badRecord=structuredClone(first.records[0]);badRecord.body.payload=null;
  for(const candidate of [{...base,producer_signature_b64url:"A".repeat(86)},{...base,business_envelope:undefined},{...base,event_canonical_json:"{}"},{...base,critical:false},event(badRecord)]){
    const c=await cycle([candidate]);try {expect(c.acks).not.toHaveBeenCalled();expect(c.sink.persist).not.toHaveBeenCalled();expect(c.errors).toHaveLength(1);}finally{await c.handle.stop();}
  }
});
it("keeps a failed durable acceptance pending without ACK and then replays exactly",async()=>{
  const sink=new Sink();sink.persist.mockRejectedValueOnce(Error("held"));const record=event(first.records[0]);
  const c=await cycle([record,record,record],first.initial,sink);
  try {expect(c.acks).not.toHaveBeenCalled();await c.next();expect(c.acks).toHaveBeenCalledTimes(1);await c.next();expect(c.acks).toHaveBeenCalledTimes(2);expect(sink.persist).toHaveBeenCalledTimes(2);}finally{await c.handle.stop();}
});
it("keeps the ACK behind an unresolved durable sink operation",async()=>{
  const sink=new Sink();let release!:(v:DurableBusinessAcceptance)=>void;let entered!:(v:DurableBusinessAcceptance)=>void;
  const started=new Promise<DurableBusinessAcceptance>(r=>{entered=r;});
  sink.persist.mockImplementationOnce(value=>{entered(value);return new Promise(r=>{release=r;});});
  const c=await cycle([event(first.records[0])],first.initial,sink,{waitForCompletion:false});
  const value=await started;
  try {
    // A check-phase turn drains promise continuations while persistence stays unresolved.
    await new Promise<void>(resolve=>setImmediate(resolve));
    expect(c.acks).not.toHaveBeenCalled();
    expect(sink.value).toBeNull();
    release(value);await c.done;
    expect(c.acks).toHaveBeenCalledTimes(1); // One ACK for the single delivered record.
  } finally {release(value);await c.handle.stop();}
});
it("refuses wrong lease and impostor signatures with no acceptance change",async()=>{
  for(const change of ["signature","wrong-key","lease","sequence","body"]){
    const record=structuredClone(first.records[0]);
    if(change==="signature") record.outer.signature="A".repeat(86);
    else if(change==="wrong-key") record.outer.signature=Buffer.from(ed25519.sign(Buffer.concat([Buffer.from(ROLE_REGISTRY[0].domain),Buffer.from(canonicalBytes(record.body))]),new Uint8Array(32).fill(19))).toString("base64url");
    else if(change==="body") record.body.policy_digest="sha256:"+"0".repeat(64);
    else if(change==="lease") {record.body.lease_id="0".repeat(32);record.outer.lease_id=record.body.lease_id;}
    else {record.body.sequence=99;record.outer.sequence=99;}
    const c=await cycle([event(record)]);try {expect(c.acks).not.toHaveBeenCalled();expect(c.sink.persist).not.toHaveBeenCalled();}finally{await c.handle.stop();}
  }
});

import * as checkedAppend from "../../src/signing/business-append-wire.js";
it("the live consumer reaches the checked parser before accepting valid E",async()=>{
  const parser=vi.spyOn(checkedAppend,"parseBusinessEvent");
  try {const c=await cycle([event(first.records[0])]);try {expect(c.acks).toHaveBeenCalledTimes(1);expect(parser,"live acceptance uses checked event parser").toHaveBeenCalled();}finally{await c.handle.stop();}}
  finally{parser.mockRestore();}
});
it("changed bytes at the accepted sequence produce no second durable advance or ACK",async()=>{
  const firstEvent=event(first.records[0]);const changed=structuredClone(first.records[0]);changed.outer.signature="A".repeat(86);
  const c=await cycle([firstEvent,event(changed)]);
  try {expect(c.acks).toHaveBeenCalledTimes(1);await c.next();expect(c.acks).toHaveBeenCalledTimes(1);expect(c.sink.persist).toHaveBeenCalledTimes(1);}finally{await c.handle.stop();}
});

import {producerSigningBytes,verifyProducerSignature} from "../../src/castle-wall/runtime/producer-signature.js";
import {CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1} from "../../src/castle-wall/constants.js";
it("a valid Legacy signature and wrapper cannot select Business raw fallback",async()=>{
  const seed=new Uint8Array(32).fill(23),canonical=JSON.stringify({operation:"egress_blocked",layer:"l1",identity_id:"agent",result:"blocked",details:{agent_id:"agent"}});
  const signature=Buffer.from(ed25519.sign(producerSigningBytes(canonical,1,1),seed)).toString("base64url");
  const raw={seq:1,captured_at_unix_ms:1,prior_sha256_hex:null,event_canonical_json:canonical,critical:true,producer_signature_b64url:signature,producer_key_id:CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1};
  expect(verifyProducerSignature({eventCanonicalJson:canonical,capturedAtUnixMs:1,seq:1,signatureB64url:signature,keyId:CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1},Buffer.from(ed25519.getPublicKey(seed)).toString("base64url"))).toEqual({ok:true});
  const c=await cycle([raw]);try {expect(c.acks,"valid Legacy wrapper has no Business ACK").not.toHaveBeenCalled();expect(c.sink.persist).not.toHaveBeenCalled();}finally{await c.handle.stop();}
  const positive=await cycle([event(first.records[0])]);try {expect(positive.acks).toHaveBeenCalledTimes(1);}finally{await positive.handle.stop();}
});
