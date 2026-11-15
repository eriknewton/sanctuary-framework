// In-memory state boundaries refuse deep trees and aliases before copying caller data.
// W-JOIN-BOUNDS
import {expect, it, vi} from "vitest";
import {APPEND_CONTRACT, appendShape} from "../../src/signing/business-append-contract.js";
import {joinStateValid, plainJoinJson, type JoinState} from "../../src/signing/record-joins.js";
import {initialLifecycle, lifecycleStep} from "../../src/signing/business-join-lifecycle.js";
import {bound} from "../../src/smb/constants.js";

const seed = () => structuredClone(APPEND_CONTRACT.lifecycle_states.ready.committed) as unknown as JoinState;
const wal = (state: unknown) => ({committed_sequence:0,committed_digest:"GENESIS",drained_sequence:0,drained_digest:"GENESIS",retained_originals:[],join_state:state,unresolved_intent:false});
const entries = {
  joinStateValid: (state: unknown) => joinStateValid(state),
  lifecycleStep: (state: unknown) => lifecycleStep(initialLifecycle(),{type:"Checkpoint",checkpoint:state}).accepted,
  appendShape: (state: unknown) => appendShape("wal_checkpoint",wal(state)),
};
const nested = (depth: number, shared: boolean): unknown => {
  let value: unknown = [];
  for(let i=0;i<depth;i++) value=shared ? [value,value] : [value];
  return value;
};
// A quarter-second ceiling allows instrumentation overhead while ruling out an exponential traversal.
const REFUSAL_BUDGET_MS = 250;
it("uses the strict parser depth boundary with an inclusive positive control",()=>{
  expect(plainJoinJson(nested(bound("JSON_MAX_DEPTH"),false))).toBe(true);
  expect(plainJoinJson(nested(bound("JSON_MAX_DEPTH")+1,false)),"one container beyond parser depth").toBe(false);
});
it("rejects a second reference even when the tree is shallow",()=>{
  const child={value:1};
  expect(plainJoinJson([{value:1},{value:1}])).toBe(true);
  expect(plainJoinJson([child,child]),"shared reference").toBe(false);
});
for(const [name,entry] of Object.entries(entries)) {
  it.each(["deep","shared"])(`${name} refuses %s input promptly without throwing`,kind=>{
    // Ten thousand levels exceeds the native stack; forty shared levels would imply a trillion visits.
    const invalid={...seed(),extra:nested(kind==="deep" ? 10_000 : 40,kind==="shared")};
    expect(entry(seed())).toBe(true);
    if (kind === "shared") {
      // Fail before exponential stress on an old traversal, using the same entry point.
      const aliased=seed(), record=structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record);
      aliased.flow_state.history=[record,record] as unknown as JoinState["flow_state"]["history"];
      expect(entry(aliased),"alias refusal before exponential stress").toBe(false);
    }
    const started=performance.now();
    let accepted: boolean | undefined;
    expect(()=>{accepted=entry(invalid);}).not.toThrow();
    expect(accepted,"typed refusal").toBe(false);
    expect(performance.now()-started,"bounded precheck work").toBeLessThan(REFUSAL_BUDGET_MS);
  });
  it(`${name} refuses aliases in otherwise admitted state`,()=>{
    const state=seed();
    const record=structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record);
    state.flow_state.history=[record,record] as unknown as JoinState["flow_state"]["history"];
    expect(entry(structuredClone({...state,flow_state:{history:[structuredClone(record),structuredClone(record)]}}))).toBe(true);
    expect(entry(state),"aliased retained history").toBe(false);
  });
}
it("joinStateValid converts a precheck exception into false",()=>{
  const state=seed();
  const spy=vi.spyOn(Object,"getOwnPropertyDescriptors").mockImplementation(()=>{throw new RangeError("fixture");});
  let result: boolean | undefined, error: unknown;
  try {result=joinStateValid(state);} catch (caught) {error=caught;} finally {spy.mockRestore();}
  expect(error,"join precheck must not throw").toBeUndefined();
  expect(result!,"join typed exception refusal").toBe(false);
});
it("lifecycleStep converts a precheck exception into rejected transition",()=>{
  const state=initialLifecycle();
  const spy=vi.spyOn(Object,"getOwnPropertyDescriptors").mockImplementation(()=>{throw new RangeError("fixture");});
  let result: ReturnType<typeof lifecycleStep> | undefined, error: unknown;
  try {result=lifecycleStep(state,{type:"NextGrant"});} catch (caught) {error=caught;} finally {spy.mockRestore();}
  expect(error,"lifecycle precheck must not throw").toBeUndefined();
  expect(result!.accepted,"lifecycle typed exception refusal").toBe(false);
  expect(result!.state).toBe(state);
});
it("appendShape converts a shape precheck exception into false",()=>{
  const state=wal(seed());
  const keys=Object.keys;
  const spy=vi.spyOn(Object,"keys").mockImplementation(value=>{if(value===state) throw new RangeError("fixture");return keys(value);});
  let result: boolean | undefined, error: unknown;
  try {result=appendShape("wal_checkpoint",state);} catch (caught) {error=caught;} finally {spy.mockRestore();}
  expect(error,"shape precheck must not throw").toBeUndefined();
  expect(result!,"shape typed exception refusal").toBe(false);
});
