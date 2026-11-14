// fail-before-exempt: shared native records and an isolated durable sink exercise the new business consumer.
import {it, expect, vi} from "vitest";
import {mkdtempSync, writeFileSync, openSync, fsyncSync, closeSync, renameSync, readFileSync, unlinkSync, rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createBusinessRecordConsumer, type BusinessDurableSink, type DurableBusinessAcceptance} from "../../src/castle-wall/runtime/business-record-consumer.js";
import {BUSINESS_PIN_FIELDS, type BusinessPin} from "../../src/linux-business/producer-custody.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {type JoinRecord, type JoinState} from "../../src/signing/record-joins.js";
import * as append from "../../src/signing/business-append-contract.js";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
const corpus=loadCheckedCorpus("record_join_vectors.json") as {cases:Array<{id:string;initial:JoinState;records:JoinRecord[];expect:{accepted_prefix:number;refusal_code:string|null;final_state:JoinState}}>};
const first=corpus.cases[0];
const pin=(state=first.initial)=>({...state.pin,...state.grant}) as unknown as BusinessPin;
const event=(record=first.records[0])=>({seq:100,captured_at_unix_ms:record.body.captured_at_unix_ms,prior_sha256_hex:null,event_canonical_json:Buffer.from(canonicalBytes(record.body)).toString(),critical:true,business_envelope:Buffer.from(canonicalBytes(record)).toString("base64url"),producer_signature_b64url:null,producer_key_id:null});
class MemorySink implements BusinessDurableSink {
  value:DurableBusinessAcceptance|null=null;
  async load(){return structuredClone(this.value);}
  async persist(v:DurableBusinessAcceptance){this.value=structuredClone(v);return structuredClone(v);}
}
const create=(sink:BusinessDurableSink=new MemorySink(),state=first.initial)=>createBusinessRecordConsumer({kind:"Business",pin:pin(state),committed_state:state,durable_sink:sink});
it.each([...BUSINESS_PIN_FIELDS,"public_key"] as const)("requires independent pin member %s before reading events",async key=>{
  const wrong={...pin(),[key]:typeof pin()[key]==="number" ? 99 : "wrong"};
  await expect(createBusinessRecordConsumer({kind:"Business",pin:wrong,committed_state:first.initial,durable_sink:new MemorySink()})).rejects.toThrow("BUSINESS_PIN");
});
it("whole positive corpus preserves signed projections, identities and join checkpoints",async()=>{
  for(const row of corpus.cases.filter(row=>row.expect.refusal_code===null)){
    const sink=new MemorySink(),consumer=await create(sink,row.initial);
    for(const record of row.records){
      const ack=await consumer.accept(event(record));
      expect(ack).toEqual({version:1,identity:append.deliveryIdentity(canonicalBytes(record),record)});
      expect(sink.value!.projection).toEqual(append.projectBusinessRecord(record));
      expect(Buffer.from(sink.value!.envelope)).toEqual(Buffer.from(canonicalBytes(record)));
    }
    expect(consumer.committedState(),row.id).toEqual(row.expect.final_state);
  }
});
it("whole invalid corpus refuses the first unaccepted record without advancing",async()=>{
  for(const row of corpus.cases.filter(row=>row.expect.refusal_code!==null)){
    let consumer;
    try{consumer=await create(new MemorySink(),row.initial);}catch{continue;}
    for(let i=0;i<row.expect.accepted_prefix;i++)await consumer.accept(event(row.records[i]));
    const before=consumer.committedState();
    let candidate:unknown;
    try{candidate=event(row.records[row.expect.accepted_prefix]);}catch{candidate=null;}
    await expect(consumer.accept(candidate),row.id).rejects.toThrow();
    expect(consumer.committedState(),row.id).toEqual(before);
  }
});
it.each([
  ["missing envelope",(v:Record<string,unknown>)=>{delete v.business_envelope;}],
  ["raw mixed",(v:Record<string,unknown>)=>{v.producer_signature_b64url="A".repeat(86);}],
  ["wrong capture",(v:Record<string,unknown>)=>{v.captured_at_unix_ms=99;}],
  ["unsigned projection",(v:Record<string,unknown>)=>{v.event_canonical_json="{}";}],
  ["extra key",(v:Record<string,unknown>)=>{v.authority=true;}],
  ["oversize",(v:Record<string,unknown>)=>{v.business_envelope=Buffer.alloc(4097).toString("base64url");}],
  ["unsafe storage sequence",(v:Record<string,unknown>)=>{v.seq=Number.MAX_SAFE_INTEGER+1;}],
  ["noncanonical base64",(v:Record<string,unknown>)=>{v.business_envelope+="=";}],
  ["noncritical",(v:Record<string,unknown>)=>{v.critical=false;}],
] as const)("refuses business representation %s",async(_name,change)=>{
  const consumer=await create(),v=event();change(v);
  await expect(consumer.accept(v)).rejects.toThrow();expect(consumer.committedState()).toEqual(first.initial);
});
it("the real consumer reaches the bounded parser before acceptance",async()=>{
  const spy=vi.spyOn(append,"parseBusinessEvent");
  try{await (await create()).accept(event());expect(spy).toHaveBeenCalledTimes(1);}finally{spy.mockRestore();}
});
it("trusted mode preserves legacy calls and never selects raw fallback from a business event",async()=>{
  let calls=0;
  const legacy=await createBusinessRecordConsumer({kind:"Legacy",async consume(){calls++;}});
  const raw={seq:1,critical:false,event_canonical_json:"{}",producer_signature_b64url:"raw",producer_key_id:"legacy"};
  await legacy.accept(raw);expect(calls).toBe(1);
  await expect(legacy.accept(event())).rejects.toThrow("BUSINESS_IN_LEGACY");expect(calls).toBe(1);
  await expect((await create()).accept(raw)).rejects.toThrow();expect(calls).toBe(1);
});
it("forty held sink completions preserve one delivery and do not advance early",async()=>{
  for(let wave=0;wave<40;wave++){
    let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});
    const sink=new MemorySink();const persist=sink.persist.bind(sink);
    sink.persist=async value=>{await gate;return persist(value);};
    const consumer=await create(sink),pending=consumer.accept(event());
    expect(consumer.committedState()).toEqual(first.initial);
    await expect(consumer.accept(event())).rejects.toThrow("BUSINESS_BUSY");
    release();await pending;expect(consumer.committedState()).toEqual(first.expect.final_state);
  }
});
it("lost acknowledgement retains exact pending bytes and permits identical replay after restart",async()=>{
  const sink=new MemorySink(),persist=sink.persist.bind(sink);let lost=true;
  sink.persist=async value=>{const durable=await persist(value);if(lost){lost=false;throw Error("lost");}return durable;};
  const consumer=await create(sink);
  await expect(consumer.accept(event())).rejects.toThrow("lost");expect(consumer.committedState()).toEqual(first.initial);
  expect(consumer.pendingDelivery()).toEqual(append.deliveryIdentity(canonicalBytes(first.records[0]),first.records[0]));
  const next=corpus.cases.find(row=>row.id==="ingress-accept")!.records[1];
  await expect(consumer.accept(event(next))).rejects.toThrow("BUSINESS_HELD");
  const restarted=await create(sink);expect(restarted.committedState()).toEqual(first.expect.final_state);
  const before=structuredClone(sink.value);await restarted.accept(event());expect(sink.value).toEqual(before);
});
it("a substituted sink result cannot advance state or acknowledge delivery",async()=>{
  const sink=new MemorySink();sink.persist=async value=>({...value,identity:{...value.identity,envelope_sha256:"sha256:"+"f".repeat(64)}});
  const consumer=await create(sink);await expect(consumer.accept(event())).rejects.toThrow();expect(consumer.committedState()).toEqual(first.initial);
});
it("isolated atomic disk sink reads exact bytes back and recovers the last delivery",async()=>{
  const root=mkdtempSync(join(tmpdir(),"business-sink-")),path=join(root,"acceptance.json"),stage=join(root,"staging.json");
  const load=async()=>{try{const v=JSON.parse(readFileSync(path,"utf8"));return {...v,envelope:Buffer.from(v.envelope,"base64url")};}catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return null;throw error;}};
  const sink:BusinessDurableSink={load,async persist(value){
    writeFileSync(stage,canonicalBytes({...value,envelope:Buffer.from(value.envelope).toString("base64url")}),{mode:0o600});
    let fd=openSync(stage,"r");try{fsyncSync(fd);}finally{closeSync(fd);}renameSync(stage,path);
    fd=openSync(root,"r");try{fsyncSync(fd);}finally{closeSync(fd);}return (await load())!;
  }};
  try{await (await create(sink)).accept(event());const bytes=readFileSync(path);const restarted=await create(sink);await restarted.accept(event());expect(readFileSync(path)).toEqual(bytes);expect(restarted.committedState()).toEqual(first.expect.final_state);}
  finally{for(const p of [stage,path]){try{unlinkSync(p);}catch{}}rmdirSync(root);}
});
