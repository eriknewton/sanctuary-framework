import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
import {anchorSchema, anchorDigest} from "../../src/linux-business/activation-anchor.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {beginTransaction,advanceTransaction,transactionComplete,decodeTransaction,classifyCustodyOutcome,TRANSACTION_PHASES,type CustodyTransaction} from "../../src/signing/custody-transaction.js";
import {DURABILITY_STEPS} from "../../src/signing/durable-store.js";
const journal:CustodyTransaction={version:2,cut:false,reconciliation:null,drain_ack:{prepare:null,commit:null},transaction_id:"a".repeat(32),operation:"ROTATE",old:{revision:1,digest:"sha256:"+"b".repeat(64)},next:{revision:2,digest:"sha256:"+"c".repeat(64)},phase:"PREPARED"};
// Must match closure_vectors.json: journal acknowledgments use the shared public anchor tuple.
const baseAnchor = anchorSchema.parse(JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/closure_vectors.json", "utf8")).anchor);
function acknowledge(state: ReturnType<typeof beginTransaction>) {
  if (state.journal.phase !== "D_PREPARE" && state.journal.phase !== "D_COMMIT") return state;
  return advanceTransaction(state, {op: "D_ACK", anchor: {...baseAnchor,
    enrollment_revision: state.journal.next.revision, custody_envelope_digest: state.journal.next.digest,
    transaction_id: state.journal.phase === "D_PREPARE" ? state.journal.transaction_id : null}});
}
it("transaction codec pins canonical consecutive changed revisions",()=>{
  expect(decodeTransaction(canonicalBytes(journal))).toEqual(journal);
  for(const bad of [{...journal,extra:true},{...journal,next:journal.old},{...journal,next:{...journal.next,revision:3}}])expect(()=>decodeTransaction(canonicalBytes(bad))).toThrow();
  expect(()=>decodeTransaction(Buffer.from(JSON.stringify(journal)))).toThrow();
});
it.each(TRANSACTION_PHASES)("every durability step gates phase %s independently",phase=>{
  let state=beginTransaction(journal);
  for(const target of TRANSACTION_PHASES){
    state=acknowledge(state);
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

it("closure cut survives journal replay", () => {
  const cut = advanceTransaction(beginTransaction(journal), {op: "CUT"});
  expect(() => beginTransaction(decodeTransaction(canonicalBytes(cut.journal)))).toThrow("K1_REFUSED");
});
it("closure recovery requires recorded reconciliation", () => {
  let state = beginTransaction({...journal, operation: "RECOVER"});
  for (const phase of TRANSACTION_PHASES) {
    state=acknowledge(state);
    for (const op of DURABILITY_STEPS) state = advanceTransaction(state, op === "READBACK" ? {op, bytes: canonicalBytes(state.journal)} : {op});
    if (phase !== "COMPLETE") state = advanceTransaction(state, {op: "NEXT"});
  }
  expect(transactionComplete(state)).toBe(false);
});

it("recorded same-epoch recovery and drain acknowledgments permit completion", () => {
  let state = beginTransaction({...journal, operation: "RECOVER"});
  const custody = {...baseAnchor, custody_envelope_digest: journal.old.digest};
  state = advanceTransaction(state, {op: "RECONCILE", input: {custody, drain: custody,
    outside_receipt_digest: anchorDigest(custody), original_tail_digest: custody.committed_digest}});
  for (const phase of TRANSACTION_PHASES) {
    state = acknowledge(state);
    for (const op of DURABILITY_STEPS) state = advanceTransaction(state, op === "READBACK" ? {op, bytes: canonicalBytes(state.journal)} : {op});
    if (phase !== "COMPLETE") state = advanceTransaction(state, {op: "NEXT"});
  }
  expect(transactionComplete(state)).toBe(true);
  expect(decodeTransaction(canonicalBytes(state.journal)).drain_ack.commit).not.toBeNull();
});

it("drain acknowledgment remains required after local completion", () => {
  let state = beginTransaction(journal);
  for (const phase of TRANSACTION_PHASES) {
    for (const op of DURABILITY_STEPS) state = advanceTransaction(state, op === "READBACK" ? {op, bytes: canonicalBytes(state.journal)} : {op});
    if (phase !== "COMPLETE") state = advanceTransaction(state, {op: "NEXT"});
  }
  expect(transactionComplete(state)).toBe(false);
});
it("reconciliation refuses a foreign outside receipt before journaling it", () => {
  const custody = {...baseAnchor, custody_envelope_digest: journal.old.digest};
  expect(() => advanceTransaction(beginTransaction({...journal, operation: "RECOVER"}), {op: "RECONCILE",
    input: {custody, drain: custody, outside_receipt_digest: "sha256:" + "e".repeat(64), original_tail_digest: custody.committed_digest}})).toThrow("K1_REFUSED");
});
it("a foreign drain transaction cannot acknowledge preparation", () => {
  let state = beginTransaction(journal);
  while (state.journal.phase !== "D_PREPARE") {
    for (const op of DURABILITY_STEPS) state = advanceTransaction(state, op === "READBACK" ? {op, bytes: canonicalBytes(state.journal)} : {op});
    state = advanceTransaction(state, {op: "NEXT"});
  }
  expect(() => advanceTransaction(state, {op: "D_ACK", anchor: {...baseAnchor, enrollment_revision: journal.next.revision,
    custody_envelope_digest: journal.next.digest, transaction_id: "d".repeat(32)}})).toThrow("K1_REFUSED");
});
