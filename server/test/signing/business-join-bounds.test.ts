// Bounded state admission preserves exact caller policies and retained envelopes.
// W-JOIN-BOUNDS
import {it, expect} from "vitest";
import {APPEND_CONTRACT, appendShape} from "../../src/signing/business-append-contract.js";
import {advance, joinStateValid, JOIN_STATE_SCHEMA, type JoinState, type JoinRecord} from "../../src/signing/record-joins.js";
import {initialLifecycle, lifecycleStep} from "../../src/signing/business-join-lifecycle.js";
import {createBusinessRecordConsumer, type BusinessDurableSink} from "../../src/castle-wall/runtime/business-record-consumer.js";
import type {BusinessPin} from "../../src/linux-business/producer-custody.js";
const seed = () => structuredClone(APPEND_CONTRACT.lifecycle_states.ready.committed) as unknown as JoinState;
const record = () => structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record) as unknown as JoinRecord;
const sink: BusinessDurableSink = {async load(){return null;},async persist(v){return v;}};
it("bounds caller state before consumer construction and lifecycle pass-through",async()=>{
  const valid=seed();
  const invalid=seed(); invalid.policy.agent_uids=Array.from({length:65},(_,i)=>i); // One above the v0 policy cap.
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

it("accepts maximal canonical policies and every registered pin role unchanged",async()=>{
  const {ROLE_REGISTRY}=await import("../../src/signing/contract.js");
  const {JOIN_HISTORY_MAX,POLICY_AGENT_UIDS_MAX,POLICY_VENDORS_MAX}=await import("../../src/signing/record-joins.js");
  for(const {role} of ROLE_REGISTRY){
    const state=seed();state.pin.role=role;
    state.flow_state.history=Array.from({length:JOIN_HISTORY_MAX},()=>record());
    state.policy.agent_uids=Array.from({length:POLICY_AGENT_UIDS_MAX},(_,i)=>Number.MAX_SAFE_INTEGER-POLICY_AGENT_UIDS_MAX+1+i);
    state.policy.vendors=Array.from({length:POLICY_VENDORS_MAX},(_,i)=>({address:"255.255.255.255",port:65535-POLICY_VENDORS_MAX+1+i})); // Maximal IPv4 octets and u16 port domain.
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
  expect(lifecycleStep({...initialLifecycle(),provisional:{state,identity:{version:1,sequence:1,commitment:"",envelope_sha256:""},signed:false}},{type:"LostOrUnmatched"}).accepted).toBe(false);
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
