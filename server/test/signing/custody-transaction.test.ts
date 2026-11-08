import {it,expect} from "vitest";
import {canonicalBytes} from "../../src/signing/contract.js";
import {beginTransaction,advanceTransaction,transactionComplete,decodeTransaction,classifyCustodyOutcome,TRANSACTION_PHASES,type CustodyTransaction} from "../../src/signing/custody-transaction.js";
import {DURABILITY_STEPS} from "../../src/signing/durable-store.js";
const journal:CustodyTransaction={version:1,transaction_id:"a".repeat(32),operation:"ROTATE",old:{revision:1,digest:"sha256:"+"b".repeat(64)},next:{revision:2,digest:"sha256:"+"c".repeat(64)},phase:"PREPARED"};
it("transaction codec pins canonical consecutive changed revisions",()=>{
  expect(decodeTransaction(canonicalBytes(journal))).toEqual(journal);
  for(const bad of [{...journal,extra:true},{...journal,next:journal.old},{...journal,next:{...journal.next,revision:3}}])expect(()=>decodeTransaction(canonicalBytes(bad))).toThrow();
  expect(()=>decodeTransaction(Buffer.from(JSON.stringify(journal)))).toThrow();
});
it.each(TRANSACTION_PHASES)("every durability step gates phase %s independently",phase=>{
  let state=beginTransaction(journal);
  for(const target of TRANSACTION_PHASES){
    for(const step of DURABILITY_STEPS){
      if(target===phase){expect(()=>advanceTransaction(state,{op:"NEXT"})).toThrow("K1_REFUSED");expect(transactionComplete(state)).toBe(false);}
      state=advanceTransaction(state,step==="READBACK"?{op:step,bytes:canonicalBytes(state.journal)}:{op:step});
    }
    if(target!=="COMPLETE")state=advanceTransaction(state,{op:"NEXT"});
  }
  expect(transactionComplete(state)).toBe(true);
});
it.each(DURABILITY_STEPS)("cut before %s stays recovery-required",step=>{
  let state=beginTransaction(journal);
  for(const op of DURABILITY_STEPS){if(op===step)break;state=advanceTransaction(state,op==="READBACK"?{op,bytes:canonicalBytes(state.journal)}:{op});}
  state=advanceTransaction(state,{op:"CUT"});
  expect(transactionComplete(state)).toBe(false);expect(()=>advanceTransaction(state,step==="READBACK"?{op:step,bytes:canonicalBytes(state.journal)}:{op:step})).toThrow("K1_REFUSED");
});
it("readback must match the exact journal rather than merely acknowledge IO",()=>{
  let state=beginTransaction(journal);
  for(const op of ["WRITE","FILE_SYNC","DIRECTORY_SYNC"] as const)state=advanceTransaction(state,{op});
  expect(()=>advanceTransaction(state,{op:"READBACK",bytes:canonicalBytes({...journal,operation:"RECOVER"})})).toThrow("K1_REFUSED");
  expect(()=>advanceTransaction(beginTransaction(journal),{op:"DIRECTORY_SYNC"})).toThrow("K1_REFUSED");
});
it("integrity classification precedes factor outcome without latching state",()=>{
  expect(classifyCustodyOutcome(journal.old.digest,journal.next.digest,"REFUSED")).toBe("INTEGRITY_REFUSED");
  expect(classifyCustodyOutcome(journal.old.digest,journal.old.digest,"REFUSED")).toBe("FACTOR_REFUSED");
  expect(classifyCustodyOutcome(journal.old.digest,journal.old.digest,"ACCEPTED")).toBe("CLEAN");
});
