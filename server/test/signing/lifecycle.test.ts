import {describe,it,expect} from "vitest";
import {ALLOWED_TRANSITIONS,CUSTODY_STATES,transition} from "../../src/signing/lifecycle.js";
describe("custody lifecycle relation",()=>{
  it.each(ALLOWED_TRANSITIONS)("$from -> $to: $event",row=>{
    expect(transition(row.from,row.event,row.guard)).toEqual({to:row.to,cleanup_destination:("cleanup_destination" in row?row.cleanup_destination:null)});
  });
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
    expect(ALLOWED_TRANSITIONS.filter(row=>row.from==="RECOVERING").every(row=>row.to!==("UNLOCKED" as string))).toBe(true);
  });
});

it("returns only named states with explicit conditional guards", () => {
  for (const row of ALLOWED_TRANSITIONS) expect(CUSTODY_STATES).toContain(row.to);
  expect(ALLOWED_TRANSITIONS.filter(row => row.from === "WIPED")).toHaveLength(2);
});

it("returns the cleanup destination so settled and uncertain locks stay distinguishable", () => {
  const event = "Owner lock, margin reached after finalization, expiry, peer death, policy fault or shutdown";
  expect(transition("UNLOCKED", event, "SETTLED")).toEqual({to: "LOCKING", cleanup_destination: "LOCKED"});
  expect(transition("UNLOCKED", event, "UNCERTAIN")).toEqual({to: "LOCKING", cleanup_destination: "RECOVERY_REQUIRED"});
  expect(Object.isFrozen(transition("UNLOCKED", event, "SETTLED"))).toBe(true);
  for (const row of ALLOWED_TRANSITIONS) if (row.to === "LOCKING" && row.from !== "LOCKING") expect(transition(row.from, row.event, row.guard).cleanup_destination).not.toBeNull();
  expect(transition("LOCKING", "Cooperative owned-buffer cleanup AND worker reaped").cleanup_destination).toBeNull();
});
it("refuses every listed state/event pair under the default guard and every guard the table does not list for it", () => {
  // Kills a mutant that treats the default guard as a wildcard over guarded rows.
  expect(() => transition("WIPED", "Recorded destination intact")).toThrow("K1_REFUSED");
  expect(() => transition("LOCKED", "Durable retired epoch")).toThrow("K1_REFUSED");
  expect(() => transition("UNLOCKED", "Owner lock, margin reached after finalization, expiry, peer death, policy fault or shutdown")).toThrow("K1_REFUSED");
  const guards = [...new Set(ALLOWED_TRANSITIONS.map(row => row.guard as string)), "UNLISTED"];
  let denied = 0;
  for (const {from, event} of ALLOWED_TRANSITIONS) {
    const listed = ALLOWED_TRANSITIONS.filter(row => row.from === from && row.event === event).map(row => row.guard as string);
    if (!listed.includes("ALWAYS")) { expect(() => transition(from, event)).toThrow("K1_REFUSED"); denied++; }
    for (const guard of guards.filter(value => !listed.includes(value))) { expect(() => transition(from, event, guard)).toThrow("K1_REFUSED"); denied++; }
  }
  expect(denied).toBeGreaterThan(ALLOWED_TRANSITIONS.length);
});
