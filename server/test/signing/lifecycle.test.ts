import {describe,it,expect} from "vitest";
import {ALLOWED_TRANSITIONS,CUSTODY_STATES,transition} from "../../src/signing/lifecycle.js";
describe("custody lifecycle relation",()=>{
  it.each(ALLOWED_TRANSITIONS)("$from -> $to: $event",row=>{expect(transition(row.from,row.event)).toBe(row.to);});
  it("default denies the complete unlisted state/event complement",()=>{
    const states=[...CUSTODY_STATES,"LOCKED at boot","UNKNOWN"];
    const events=[...ALLOWED_TRANSITIONS.map(row=>row.event),"UNLISTED"];
    let denied=0;
    for(const state of states)for(const event of events)if(!ALLOWED_TRANSITIONS.some(row=>row.from===state&&row.event===event)){
      expect(()=>transition(state,event)).toThrow("K1_REFUSED");denied++;
    }
    expect(denied).toBeGreaterThan(300);
  });
  it("retired has no signing exit and recovery never unlocks directly",()=>{
    expect(ALLOWED_TRANSITIONS.filter(row=>row.from==="RETIRED").map(row=>row.to)).toEqual(["RETIRED"]);
    expect(ALLOWED_TRANSITIONS.filter(row=>row.from==="RECOVERING").every(row=>!row.to.includes("directly UNLOCKED")||row.to==="LOCKED, never directly UNLOCKED")).toBe(true);
  });
});
