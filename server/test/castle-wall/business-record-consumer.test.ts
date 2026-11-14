// fail-before-exempt: same-anchor recovery, serialized input and exact-refusal assertions read the manifest-checked native corpus, outside server/src.
// W-TS-SCHEMA
// W-ENVELOPE-CAP
import {it, expect, vi} from "vitest";
import {ed25519} from "@noble/curves/ed25519";
import {producerSigningBytes, verifyProducerSignature} from "../../src/castle-wall/runtime/producer-signature.js";
import {buildCriticalEnvelopeFromDrainEvent} from "../../src/castle-wall/runtime/linux-audit-drain.js";
import {CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1} from "../../src/castle-wall/constants.js";
import type {AuditDrainEvent} from "../../src/castle-wall/ipc/messages.js";
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
const pin=(state=first.initial)=>({...state?.pin,...state?.grant}) as unknown as BusinessPin;
const event=(record=first.records[0])=>({seq:100,captured_at_unix_ms:record.body.captured_at_unix_ms,prior_sha256_hex:null,event_canonical_json:Buffer.from(canonicalBytes(record.body)).toString(),critical:true,business_envelope:Buffer.from(canonicalBytes(record)).toString("base64url"),producer_signature_b64url:null,producer_key_id:null});
class MemorySink implements BusinessDurableSink {
  value:DurableBusinessAcceptance|null=null;
  async load(){return structuredClone(this.value);}
  async persist(v:DurableBusinessAcceptance){this.value=structuredClone(v);return structuredClone(v);}
}
const create=(sink:BusinessDurableSink=new MemorySink(),state=first.initial)=>createBusinessRecordConsumer({kind:"Business",pin:pin(state),committed_state:state,durable_sink:sink});
it.each([...BUSINESS_PIN_FIELDS,"public_key"] as const)("requires independent pin member %s before reading events",async key=>{
  const wrong={...pin(),[key]:typeof pin()[key]==="number" ? 99 : "wrong"};
  await expect(createBusinessRecordConsumer({kind:"Business",pin:wrong,committed_state:first.initial,durable_sink:new MemorySink()})).rejects.toThrow(/^BUSINESS_PIN$/);
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
    if(row.expect.refusal_code==="INPUT") {
      await expect(create(new MemorySink(),row.initial),row.id).rejects.toThrow(/^BUSINESS_PIN$/);
      continue;
    }
    const consumer=await create(new MemorySink(),row.initial);
    for(let i=0;i<row.expect.accepted_prefix;i++)await consumer.accept(event(row.records[i]));
    const before=consumer.committedState();
    const record=row.records[row.expect.accepted_prefix];
    const candidate=record ? event(record) : null;
    const code=!record ? "BUSINESS_EVENT" : ["SCHEMA","OUTER"].includes(row.expect.refusal_code!) ? "BUSINESS_ENVELOPE" : ["subject-activation_id-refuse","subject-machine_id-refuse"].includes(row.id) ? "BUSINESS_AUTH" : "BUSINESS_JOIN";
    await expect(consumer.accept(candidate),row.id).rejects.toThrow(new RegExp(`^${code}$`));
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
  try{const consumer=await create();await consumer.accept(event());expect(spy).toHaveBeenCalledTimes(1);
    await expect(consumer.accept(canonicalBytes(event()))).resolves.toEqual({version:1,identity:append.deliveryIdentity(canonicalBytes(first.records[0]),first.records[0])});}finally{spy.mockRestore();}
});
it("trusted mode preserves legacy calls and never selects raw fallback from a business event",async()=>{
  let calls=0;
  const captured=Date.now();
  const seed=new Uint8Array(32).fill(8),publicKey=Buffer.from(ed25519.getPublicKey(seed)).toString("base64url");
  const canonical=Buffer.from(canonicalBytes({operation:"egress_blocked",layer:"l1",identity_id:"agent",result:"blocked",timestamp:new Date(captured).toISOString(),details:{agent_id:"agent"}})).toString();
  const raw:AuditDrainEvent={seq:1,captured_at_unix_ms:captured,prior_sha256_hex:null,critical:true,event_canonical_json:canonical,producer_signature_b64url:Buffer.from(ed25519.sign(producerSigningBytes(canonical,captured,1),seed)).toString("base64url"),producer_key_id:CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1};
  const legacy=await createBusinessRecordConsumer({kind:"Legacy",async consume(value){
    calls++;
    const built=buildCriticalEnvelopeFromDrainEvent(value as AuditDrainEvent,async()=>{});
    expect(built.kind).toBe("ok");
    if(built.kind!=="ok" || !built.envelope.producer) throw Error("LEGACY_WRAPPER");
    expect(verifyProducerSignature(built.envelope.producer,publicKey)).toEqual({ok:true});
  }});
  await legacy.accept(raw);expect(calls).toBe(1);
  await expect(legacy.accept({...raw,business_envelope:event().business_envelope})).rejects.toThrow(/^BUSINESS_IN_LEGACY$/);expect(calls).toBe(1);
  await expect((await create()).accept(raw)).rejects.toThrow();expect(calls).toBe(1);
});
it("forty held sink completions preserve one delivery and do not advance early",async()=>{
  for(let wave=0;wave<40;wave++){
    let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});
    const sink=new MemorySink();const persist=sink.persist.bind(sink);
    sink.persist=async value=>{await gate;return persist(value);};
    const consumer=await create(sink),pending=consumer.accept(event());
    expect(consumer.committedState()).toEqual(first.initial);
    await expect(consumer.accept(event())).rejects.toThrow(/^BUSINESS_BUSY$/);
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
  await expect(consumer.accept(event(next))).rejects.toThrow(/^BUSINESS_HELD$/);
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

it.each(["object","bytes","buffer","string"])("legacy refuses strict business event in %s form",async form=>{
  const consume=vi.fn(async()=>{}), consumer=await createBusinessRecordConsumer({kind:"Legacy",consume});
  const bytes=canonicalBytes(event());
  const value=form==="object"?event():form==="string"?Buffer.from(bytes).toString():form==="buffer"?Buffer.from(bytes):new Uint8Array(bytes);
  await expect(consumer.accept(value)).rejects.toThrow(/^BUSINESS_IN_LEGACY$/);
  expect(consume).not.toHaveBeenCalled();
});
it("pending delivery excludes the last recorded replay",async()=>{
  const sink=new MemorySink(),consumer=await create(sink);
  await consumer.accept(event());const committed=consumer.committedState();
  const next=corpus.cases.find(row=>row.id==="ingress-accept")!.records[1];
  const persist=sink.persist.bind(sink);sink.persist=async()=>{throw Error("held");};
  await expect(consumer.accept(event(next))).rejects.toThrow("held");
  const pending=consumer.pendingDelivery();
  await expect(consumer.accept(event())).rejects.toThrow(/^BUSINESS_HELD$/);
  expect(consumer.pendingDelivery()).toEqual(pending);expect(consumer.committedState()).toEqual(committed);
  sink.persist=persist;await consumer.accept(event(next));expect(consumer.pendingDelivery()).toBeNull();
});
it.each(["projection","identity","anchor","two ahead","unjoined"])("startup refuses inconsistent durable %s",async variant=>{
  const sink=new MemorySink(),consumer=await create(sink);await consumer.accept(event());
  let start=first.initial;
  if(variant==="projection") sink.value!.projection.sequence=99;
  if(variant==="identity") sink.value!.identity.envelope_sha256="sha256:"+"f".repeat(64);
  if(variant==="anchor") sink.value!.checkpoint.anchor.commitment="sha256:"+"f".repeat(64);
  if(variant==="two ahead") await consumer.accept(event(corpus.cases.find(row=>row.id==="ingress-accept")!.records[1]));
  if(variant==="unjoined") {start=structuredClone(first.initial);start.policy.policy_digest="sha256:"+"f".repeat(64);}
  await expect(create(sink,start)).rejects.toThrow(/^BUSINESS_DURABLE_STATE$/);
});
it("different authentic bytes at the accepted sequence never receive its recorded ACK",async()=>{
  const sink=new MemorySink(),consumer=await create(sink);await consumer.accept(event());
  const changed=corpus.cases.find(row=>row.id==="activation-start-accept")!.records[0];
  expect(changed.body.sequence).toBe(first.records[0].body.sequence);
  expect(canonicalBytes(changed)).not.toEqual(canonicalBytes(first.records[0]));
  await expect(consumer.accept(event(changed))).rejects.toThrow(/^BUSINESS_REPLAY$/);
  expect(consumer.committedState()).toEqual(first.expect.final_state);
});
it("self-consistent prior readback cannot acknowledge a new delivery",async()=>{
  const sink=new MemorySink(),consumer=await create(sink);await consumer.accept(event());
  const prior=structuredClone(sink.value!);sink.persist=async()=>structuredClone(prior);
  await expect(consumer.accept(event(corpus.cases.find(row=>row.id==="ingress-accept")!.records[1]))).rejects.toThrow(/^BUSINESS_PERSISTENCE$/);
  expect(consumer.committedState()).toEqual(prior.checkpoint);expect(consumer.pendingDelivery()!.sequence).toBe(2);
});
it("grant rollover recovers the acceptance pin and replays only recorded old bytes",async()=>{
  const prior=corpus.cases.find(row=>row.id==="allowance-origin-accept")!,rollover=corpus.cases.find(row=>row.id==="rollover-accept")!;
  const sink=new MemorySink(),consumer=await create(sink,prior.initial);
  for(const record of prior.records) await consumer.accept(event(record));
  const recorded=structuredClone(sink.value!),lastEvent=event(prior.records.at(-1)!);
  expect(recorded.checkpoint.anchor).toEqual(rollover.initial.anchor);
  const restarted=await create(sink,rollover.initial);
  expect(restarted.committedState()).toEqual(rollover.initial);
  await expect(restarted.accept(lastEvent)).resolves.toEqual({version:1,identity:recorded.identity});
  expect(sink.value).toEqual(recorded);
  await expect(restarted.accept(event(prior.records[0]))).rejects.toThrow(/^BUSINESS_AUTH$/);
  await expect(consumer.accept(event(rollover.records[0]))).rejects.toThrow(/^BUSINESS_AUTH$/);
  await restarted.accept(event(rollover.records[0]));expect(restarted.committedState()).toEqual(rollover.expect.final_state);
});

it.each(["policy","history","pin.kid"])("same-anchor startup refuses differing %s",async variant=>{
  const prior=corpus.cases.find(row=>row.id==="allowance-origin-accept")!,rollover=corpus.cases.find(row=>row.id==="rollover-accept")!;
  const sink=new MemorySink(),consumer=await create(sink,prior.initial);
  for(const record of prior.records) await consumer.accept(event(record));
  const stored=structuredClone(sink.value!),start=structuredClone(stored.checkpoint);
  start.grant=structuredClone(rollover.initial.grant);
  if(variant==="policy") start.policy.policy_digest="sha256:"+"f".repeat(64);
  if(variant==="history") start.flow_state.history=[];
  if(variant==="pin.kid") start.pin.kid="k1:sha256:"+"f".repeat(64);
  expect(start.anchor).toEqual(stored.checkpoint.anchor);
  expect(start).not.toEqual({...stored.checkpoint,grant:start.grant});
  await expect(create(sink,start)).rejects.toThrow(/^BUSINESS_DURABLE_STATE$/);
  expect(sink.value).toEqual(stored);
});
it.each(["malformed","noncanonical","duplicate-key"])("legacy refuses %s serialized business events",async variant=>{
  const consume=vi.fn(async()=>{}),consumer=await createBusinessRecordConsumer({kind:"Legacy",consume});
  const text=Buffer.from(canonicalBytes(event())).toString();
  const serialized=variant==="malformed" ? text.slice(0,-1) : variant==="noncanonical" ? JSON.stringify(event(),null,2) : text.replace('"critical":true','"critical":true,"critical":true');
  for(const input of [serialized,Buffer.from(serialized),new Uint8Array(Buffer.from(serialized))]) {
    await expect(consumer.accept(input)).rejects.toThrow(/^BUSINESS_IN_LEGACY$/);
    expect(consume).not.toHaveBeenCalled();
  }
});
it.each([null,undefined,1,true,[],new Date(0),Object.create({legacy:true})])("legacy refuses non-plain input %#",async input=>{
  const consume=vi.fn(async()=>{}),consumer=await createBusinessRecordConsumer({kind:"Legacy",consume});
  await expect(consumer.accept(input)).rejects.toThrow(/^BUSINESS_IN_LEGACY$/);
  expect(consume).not.toHaveBeenCalled();
});
it("legacy admits a plain object with a null prototype",async()=>{
  const consume=vi.fn(async()=>{}),consumer=await createBusinessRecordConsumer({kind:"Legacy",consume});
  const input=Object.assign(Object.create(null),{seq:1});
  await consumer.accept(input);expect(consume).toHaveBeenCalledWith(input);
});
it("business admits a canonical well-formed string with exact delivery identity",async()=>{
  const consumer=await create();
  await expect(consumer.accept(Buffer.from(canonicalBytes(event())).toString())).resolves.toEqual({version:1,identity:append.deliveryIdentity(canonicalBytes(first.records[0]),first.records[0])});
});
it.each(["\ud800","\udc00","\ud800x","x\udc00"])("business refuses unpaired UTF-16 before byte parsing %#",async surrogate=>{
  const consumer=await create(),spy=vi.spyOn(append,"parseBusinessEventBytes");
  try {
    await expect(consumer.accept('"'+surrogate+'"')).rejects.toThrow(/^BUSINESS_EVENT$/);
    expect(spy).not.toHaveBeenCalled();expect(consumer.committedState()).toEqual(first.initial);
  } finally {spy.mockRestore();}
});
it("business refuses both distinct strings merged by lossy UTF-8 conversion",async()=>{
  const text=Buffer.from(canonicalBytes({...event(),event_canonical_json:"REPLACE"})).toString();
  const strings=[text.replace("REPLACE","\ud800"),text.replace("REPLACE","\udc00")];
  expect(strings[0]).not.toBe(strings[1]);
  expect(Buffer.from(strings[0],"utf8")).toEqual(Buffer.from(strings[1],"utf8"));
  const consumer=await create(),spy=vi.spyOn(append,"parseBusinessEventBytes");
  try {
    for(const input of strings) await expect(consumer.accept(input)).rejects.toThrow(/^BUSINESS_EVENT$/);
    expect(spy).not.toHaveBeenCalled();expect(consumer.committedState()).toEqual(first.initial);
  } finally {spy.mockRestore();}
});
it("lost ACK followed by a grant change refuses startup without changing storage",async()=>{
  // 2e2 must reconcile lost-ACK evidence across grant rollover before startup can proceed.
  const sink=new MemorySink(),persist=sink.persist.bind(sink);
  sink.persist=async value=>{await persist(value);throw Error("lost");};
  const consumer=await create(sink);
  await expect(consumer.accept(event())).rejects.toThrow(/^lost$/);
  expect(consumer.committedState()).toEqual(first.initial);
  const stored=structuredClone(sink.value!),start=structuredClone(first.initial);
  start.grant=structuredClone(corpus.cases.find(row=>row.id==="rollover-accept")!.initial.grant);
  expect(start.anchor.sequence).toBe((stored.identity.sequence as number)-1);
  await expect(create(sink,start)).rejects.toThrow(/^BUSINESS_DURABLE_STATE$/);
  expect(sink.value).toEqual(stored);
});
