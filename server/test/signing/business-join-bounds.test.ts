// fail-before-exempt: maximal raw-parser round trips consume the shared native size fixture.
// Bounded state admission preserves exact caller policies and retained envelopes.
// W-JOIN-BOUNDS
import {it, expect} from "vitest";
import {readFileSync} from "node:fs";
import {APPEND_CONTRACT, appendShape, type BusinessDeliveryIdentity} from "../../src/signing/business-append-contract.js";
import {advance, joinStateValid, parseJoinState, JOIN_STATE_BYTES_MAX, JOIN_STATE_SCHEMA, type JoinState, type JoinRecord} from "../../src/signing/record-joins.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {initialLifecycle, lifecycleStep} from "../../src/signing/business-join-lifecycle.js";
import {createBusinessRecordConsumer, type BusinessDurableSink} from "../../src/castle-wall/runtime/business-record-consumer.js";
import type {BusinessPin} from "../../src/linux-business/producer-custody.js";
// Positive-control sizes come from the shared maximal vectors, so fail-before never relies on new production exports.
const policyVectors=JSON.parse(readFileSync(new URL("../../../castle-wall-daemon/tests/fixtures/join-bounds.json",import.meta.url),"utf8")) as Array<{id:string;value:unknown[]}>;
const POLICY_AGENT_UIDS_MAX=policyVectors.find(row=>row.id==="uids-maximum")!.value.length;
const POLICY_VENDORS_MAX=policyVectors.find(row=>row.id==="vendors-maximum")!.value.length;
const seed = () => structuredClone(APPEND_CONTRACT.lifecycle_states.ready.committed) as unknown as JoinState;
const record = () => structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record) as unknown as JoinRecord;
const sink: BusinessDurableSink = {async load(){return null;},async persist(v){return v;}};
it("bounds caller state before consumer construction and lifecycle pass-through",async()=>{
  const valid=seed();
  const invalid=seed(); invalid.policy.agent_uids=Array.from({length:POLICY_AGENT_UIDS_MAX+1},(_,i)=>i); // One above the v0 policy cap.
  expect(joinStateValid(valid)).toBe(true);
  expect(joinStateValid(invalid)).toBe(false);
  expect(advance(invalid,record()).refusal_code).toBe("INPUT");
  expect(lifecycleStep(initialLifecycle(),{type:"Checkpoint",checkpoint:invalid}).accepted).toBe(false);
  expect(lifecycleStep({...initialLifecycle(),committed:invalid},{type:"NextGrant"}).accepted).toBe(false);
  await expect(createBusinessRecordConsumer({kind:"Business",pin:{...invalid.pin,...invalid.grant} as unknown as BusinessPin,committed_state:invalid,durable_sink:sink})).rejects.toThrow(/^BUSINESS_PIN$/);
  const consumer=await createBusinessRecordConsumer({kind:"Business",pin:{...valid.pin,...valid.grant} as unknown as BusinessPin,committed_state:valid,durable_sink:sink});
  expect(consumer.committedState()).toEqual(valid);
});
it("bounds newly advanced signatures as well as seeded history",()=>{
  const good=record(),bad=record();bad.outer.signature="A";
  expect(advance(seed(),good).refusal_code).toBeNull();
  expect(advance(seed(),bad).refusal_code).toBe("OUTER");
  const seeded=seed();seeded.flow_state.history=[bad];
  expect(joinStateValid(seeded)).toBe(false);
  expect(appendShape("wal_checkpoint",{committed_sequence:0,committed_digest:"GENESIS",drained_sequence:0,drained_digest:"GENESIS",retained_originals:[],join_state:seeded,unresolved_intent:false})).toBe(false);
});

it("accepts maximal canonical policies and every registered pin role unchanged (positive control)",async()=>{
  const {ROLE_REGISTRY}=await import("../../src/signing/contract.js");
  const {BUSINESS_SCHEMA_AST}=await import("../../src/signing/linux-business-records.js");
  const {JOIN_HISTORY_MAX}=await import("../../src/signing/record-joins.js");
  for(const {role} of ROLE_REGISTRY){
    const state=JSON.parse(readFileSync(new URL("../../../castle-wall-daemon/tests/fixtures/maximal-join-state.json",import.meta.url),"utf8")) as JoinState;state.pin.role=role;
    state.flow_state.history=Array.from({length:JOIN_HISTORY_MAX},()=>structuredClone(state.flow_state.history[0]));
    state.policy.agent_uids=Array.from({length:POLICY_AGENT_UIDS_MAX},(_,i)=>Number.MAX_SAFE_INTEGER-POLICY_AGENT_UIDS_MAX+1+i);
    state.policy.vendors=Array.from({length:POLICY_VENDORS_MAX},(_,i)=>({address:"255.255.255.255",port:BUSINESS_SCHEMA_AST.definitions.Port.max-POLICY_VENDORS_MAX+1+i})); // Maximal IPv4 octets and u16 port domain.
    const raw=canonicalBytes(state);
    expect(raw.length).toBeLessThanOrEqual(JOIN_STATE_BYTES_MAX);
    expect(raw.length).toBeGreaterThan(JOIN_STATE_BYTES_MAX - 6500); // 64 envelopes times 96 conservative bytes, plus registry role widths.
    expect(parseJoinState(raw)).toEqual(state);
    const before=structuredClone(state);
    expect(joinStateValid(state)).toBe(true);
    const consumer=await createBusinessRecordConsumer({kind:"Business",pin:{...state.pin,...state.grant} as unknown as BusinessPin,committed_state:state,durable_sink:sink});
    expect(consumer.committedState()).toEqual(before);
    expect(state).toEqual(before);
  }
});
it("refuses retained committed state on a lifecycle pass-through",()=>{
  const state=seed();state.pin.role="unregistered";
  expect(lifecycleStep({...initialLifecycle(),committed:state},{type:"NextGrant"}).accepted).toBe(false);
});
it("refuses retained provisional state before discarding it",()=>{
  const state=seed();state.pin.role="unregistered";
  expect(lifecycleStep({...initialLifecycle(),provisional:{state,identity:structuredClone(APPEND_CONTRACT.lifecycle_states.pending.provisional.identity) as BusinessDeliveryIdentity,signed:false}},{type:"LostOrUnmatched"}).accepted).toBe(false);
});

it("refuses unbounded top-level wrapper fields before retaining a new record",()=>{
  const extra={...record(),extra:"x".repeat(8194)}; // Survey growth input exceeds two envelope caps.
  expect(advance(seed(),extra).refusal_code).toBe("OUTER");
});

it("keeps every exported state field table immutable",()=>{
  expect(Object.isFrozen(JOIN_STATE_SCHEMA)).toBe(true);
  expect(Object.values(JOIN_STATE_SCHEMA).every(fields=>Object.isFrozen(fields))).toBe(true);
});

it("refuses negative zero in UID and port value admission",()=>{
  const uid=seed();uid.policy.agent_uids=[-0];
  const port=seed();port.policy.vendors=[{address:"1.2.3.4",port:-0}];
  expect(joinStateValid(uid),"negative-zero UID").toBe(false);
  expect(joinStateValid(port),"negative-zero port").toBe(false);
});

it("refuses holes, extra array properties and accessors without invoking them",async()=>{
  const malformed: JoinState[]=[];
  for(const key of ["agent_uids","vendors"]){
    const state=seed();const list=state.policy[key] as unknown[];list.length++;malformed.push(state);
    const extra=seed();Object.defineProperty(extra.policy[key],"extra",{value:"unretained",enumerable:true});malformed.push(extra);
  }
  const history=seed();history.flow_state.history.length=1;malformed.push(history);
  const hidden=seed();Object.defineProperty(hidden.policy.agent_uids,"hidden",{value:"unretained"});malformed.push(hidden);
  const symbol=seed();Object.defineProperty(symbol.pin,Symbol("hidden"),{value:"unretained"});malformed.push(symbol);
  const exotic=seed();Object.setPrototypeOf(exotic.pin,{unexpected:true});malformed.push(exotic);
  let calls=0;const getter=seed();const role=getter.pin.role;
  Object.defineProperty(getter.pin,"role",{enumerable:true,get(){calls++;return calls===1?role:"unregistered";}});malformed.push(getter);
  for(const [index,state] of malformed.entries()) {
    expect(joinStateValid(state),`plain JSON row ${index}`).toBe(false);
    expect(advance(state,record()).refusal_code,`advance row ${index}`).toBe("INPUT");
    expect(lifecycleStep(initialLifecycle(),{type:"Checkpoint",checkpoint:state}).accepted,`checkpoint row ${index}`).toBe(false);
    await expect(createBusinessRecordConsumer({kind:"Business",pin:{...seed().pin,...seed().grant} as unknown as BusinessPin,committed_state:state,durable_sink:sink})).rejects.toThrow(/^BUSINESS_PIN$/);
  }
  expect(calls,"validation must not invoke accessors").toBe(0);
});
