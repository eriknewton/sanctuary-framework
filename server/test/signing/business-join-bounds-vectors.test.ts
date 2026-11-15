// fail-before-exempt: shared native fixture vectors exercise both language validators and existing corpus compatibility.
// Bounded state admission and durable reload preserve the shared representation.
// W-JOIN-BOUNDS
import {readFileSync} from "node:fs";
import {it,expect} from "vitest";
import {APPEND_CONTRACT,appendShape,type BusinessDeliveryIdentity} from "../../src/signing/business-append-contract.js";
import {advance,joinStateValid,type JoinState,type JoinRecord} from "../../src/signing/record-joins.js";
import {initialLifecycle,lifecycleStep,type JoinLifecycleState} from "../../src/signing/business-join-lifecycle.js";
import {createBusinessRecordConsumer,type BusinessDurableSink,type DurableBusinessAcceptance} from "../../src/castle-wall/runtime/business-record-consumer.js";
import type {BusinessPin} from "../../src/linux-business/producer-custody.js";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
import {canonicalBytes} from "../../src/signing/contract.js";
const rows=JSON.parse(readFileSync(new URL("../../../castle-wall-daemon/tests/fixtures/join-bounds.json",import.meta.url),"utf8")) as Array<{id:string;path:string;value:unknown;valid:boolean}>;
const seed=()=>structuredClone(APPEND_CONTRACT.lifecycle_states.ready.committed) as unknown as JoinState;
const record=()=>structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record) as unknown as JoinRecord;
function replace(state:JoinState,path:string,value:unknown){const keys=path.split(".");let target:unknown=state;for(const k of keys.slice(0,-1))target=(target as Record<string,unknown>)[k];(target as Record<string,unknown>)[keys.at(-1)!]=structuredClone(value);}
const pin=(s:JoinState)=>({...s.pin,...s.grant}) as unknown as BusinessPin;
class Sink implements BusinessDurableSink{value:DurableBusinessAcceptance|null=null;async load(){return structuredClone(this.value);}async persist(v:DurableBusinessAcceptance){this.value=structuredClone(v);return structuredClone(v);}}
const create=(s:JoinState,sink:Sink=new Sink())=>createBusinessRecordConsumer({kind:"Business",pin:pin(s),committed_state:s,durable_sink:sink});
const event=(r:JoinRecord)=>({seq:1,captured_at_unix_ms:r.body.captured_at_unix_ms,prior_sha256_hex:null,event_canonical_json:Buffer.from(canonicalBytes(r.body)).toString(),critical:true,business_envelope:Buffer.from(canonicalBytes(r)).toString("base64url"),producer_signature_b64url:null,producer_key_id:null});
it.each(rows)("shared bounded join $id",async row=>{
  const state=seed();if(row.path.startsWith("flow_state"))state.flow_state.history=[record()];
  replace(state,row.path,row.value);
  expect(joinStateValid(state),row.id).toBe(row.valid);
  expect(lifecycleStep(initialLifecycle(),{type:"Checkpoint",checkpoint:state}).accepted,row.id).toBe(row.valid);
  expect(lifecycleStep({...initialLifecycle(),committed:state},{type:"NextGrant"}).accepted,row.id).toBe(row.valid);
  expect(lifecycleStep({...initialLifecycle(),provisional:{state,identity:structuredClone(APPEND_CONTRACT.lifecycle_states.pending.provisional.identity) as BusinessDeliveryIdentity,signed:false}},{type:"LostOrUnmatched"}).accepted,row.id).toBe(row.valid);
  expect(appendShape("wal_checkpoint",{committed_sequence:0,committed_digest:"GENESIS",drained_sequence:0,drained_digest:"GENESIS",retained_originals:[],join_state:state,unresolved_intent:false}),row.id).toBe(row.valid);
  if(row.valid){expect((await create(state)).committedState()).toEqual(state);}else{
    expect(advance(state,record()).refusal_code,row.id).toBe("INPUT");
    await expect(create(state),row.id).rejects.toThrow(/^BUSINESS_PIN$/);
    const disk=new Sink(),consumer=await create(seed(),disk);await consumer.accept(event(record()));
    replace(disk.value!.checkpoint,row.path,row.value);
    await expect(create(seed(),disk),row.id).rejects.toThrow(/^BUSINESS_DURABLE_STATE$/);
  }
});
it("all existing caller policies remain byte-identical after admission",async()=>{
  const corpus=loadCheckedCorpus("record_join_vectors.json") as {cases:Array<{initial:JoinState;expect:{refusal_code:string|null}}>};
  for(const row of corpus.cases){if(row.expect.refusal_code==="INPUT")continue;const before=canonicalBytes(row.initial);expect(joinStateValid(row.initial)).toBe(true);expect((await create(row.initial)).committedState()).toEqual(row.initial);expect(canonicalBytes(row.initial)).toEqual(before);}
  for(const v of Object.values(APPEND_CONTRACT.lifecycle_states)){for(const s of [v.committed,"provisional" in v && v.provisional ? v.provisional.state:null])if(s)expect(joinStateValid(s)).toBe(true);}
});

it("refuses original noncanonical join number bytes before value admission",async()=>{
  const joins=await import("../../src/signing/record-joins.js");
  const vectors=JSON.parse(readFileSync(new URL("../../../castle-wall-daemon/tests/fixtures/join-raw-numbers.json",import.meta.url),"utf8")) as Array<{id:string;raw:string;valid:boolean}>;
  for(const row of vectors) {
    // The base has only value admission; preserve its actual parse-then-predicate behavior for fail-before.
    const parser=(joins as Partial<typeof joins>).parseJoinState;
    const accepted=parser ? parser(Buffer.from(row.raw)) !== null : joins.joinStateValid(JSON.parse(row.raw));
    expect(accepted,row.id).toBe(row.valid);
  }
});

it("refuses every malformed lifecycle wrapper from the shared vectors",()=>{
  const vectors=JSON.parse(readFileSync(new URL("../../../castle-wall-daemon/tests/fixtures/join-lifecycle-bounds.json",import.meta.url),"utf8")) as Array<{id:string;seed:keyof typeof APPEND_CONTRACT.lifecycle_states;path:string;remove?:boolean;value?:unknown}>;
  for(const row of vectors) {
    const state=structuredClone(APPEND_CONTRACT.lifecycle_states[row.seed]) as unknown as JoinLifecycleState;
    const keys=row.path.split(".");let target:unknown=state;
    for(const key of keys.slice(0,-1))target=(target as Record<string,unknown>)[key];
    if(row.remove)delete (target as Record<string,unknown>)[keys.at(-1)!];
    else (target as Record<string,unknown>)[keys.at(-1)!]=row.value;
    let accepted: boolean | undefined;
    expect.soft(()=>{accepted=lifecycleStep(state,{type:"NextGrant"}).accepted;},row.id).not.toThrow();
    expect.soft(accepted,row.id).toBe(false);
  }
});
