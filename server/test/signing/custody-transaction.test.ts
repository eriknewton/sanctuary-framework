import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
import {anchorSchema, anchorDigest} from "../../src/linux-business/activation-anchor.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import * as custody from "../../src/signing/custody-transaction.js";
import {advanceTransaction,transactionComplete,decodeTransaction,classifyCustodyOutcome,TRANSACTION_PHASES,type CustodyTransaction} from "../../src/signing/custody-transaction.js";
import {DURABILITY_STEPS,preparePersistence} from "../../src/signing/durable-store.js";
const journal:CustodyTransaction={version:2,cut:false,reconciliation:null,drain_ack:{prepare:null,commit:null},transaction_id:"a".repeat(32),operation:"ROTATE",old:{revision:1,digest:"sha256:"+"b".repeat(64)},next:{revision:2,digest:"sha256:"+"c".repeat(64)},phase:"PREPARED"};
// Must match closure_vectors.json: journal acknowledgments use the shared public anchor tuple.
const baseAnchor = anchorSchema.parse(JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/closure_vectors.json", "utf8")).anchor);
// The pre-transaction anchor names the journal's old custody revision and envelope digest.
const prior = {...baseAnchor, enrollment_revision: journal.old.revision, custody_envelope_digest: journal.old.digest};
const beginTransaction = (j: CustodyTransaction, before = prior) => custody.beginTransaction(j, before);
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
  expect(transactionComplete(state)).toBe(false);
  // The cut journal restarts its own persistence at WRITE, so the interrupted step only continues when it is WRITE.
  const resume=()=>advanceTransaction(state,step==="READBACK"?{op:step,bytes:canonicalBytes(state.journal)}:{op:step});
  if(step==="WRITE")expect(transactionComplete(resume())).toBe(false);else expect(resume).toThrow("K1_REFUSED");
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
    // Without a recorded reconciliation there is no drained tuple for the acknowledgment to name, so D_ACK refuses.
    if (phase === "D_PREPARE") expect(() => acknowledge(state)).toThrow("K1_REFUSED");
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

// Closure round two: drain acknowledgments, write-once preparation, durable cuts and the readback binding.
type State = ReturnType<typeof beginTransaction>;
const step = (state: State, op: typeof DURABILITY_STEPS[number]) => advanceTransaction(state, op === "READBACK" ? {op, bytes: canonicalBytes(state.journal)} : {op});
const persist = (state: State) => DURABILITY_STEPS.reduce(step, state);
/** Walk every phase to COMPLETE, acknowledging D only when asked. */
function walk(state: State, ack = true): State {
  for (const phase of TRANSACTION_PHASES) {
    if (ack) state = acknowledge(state);
    state = persist(state);
    if (phase !== "COMPLETE") state = advanceTransaction(state, {op: "NEXT"});
  }
  return state;
}
function toPhase(state: State, target: typeof TRANSACTION_PHASES[number]): State {
  while (state.journal.phase !== target) state = advanceTransaction(persist(state), {op: "NEXT"});
  return state;
}
const preparedAck = {...prior, enrollment_revision: journal.next.revision, custody_envelope_digest: journal.next.digest, transaction_id: journal.transaction_id};
const committedAck = {...preparedAck, transaction_id: null};
const stuffed = {...prior, enrollment_revision: 99, retired: true, recovery_required: true, recovery_reason: "integrity" as const, recovery_revision: 1};
const recovered = {custody: prior, drain: prior, outside_receipt_digest: anchorDigest(prior), original_tail_digest: prior.committed_digest};
const otherDigest = "sha256:" + "e".repeat(64);
it("closure seeded drain acknowledgments or reconciliation refuse at begin", () => {
  expect(() => beginTransaction({...journal, drain_ack: {prepare: stuffed, commit: stuffed}})).toThrow("K1_REFUSED");
  expect(() => beginTransaction({...journal, drain_ack: {prepare: preparedAck, commit: null}})).toThrow("K1_REFUSED");
  expect(() => beginTransaction({...journal, drain_ack: {prepare: null, commit: committedAck}})).toThrow("K1_REFUSED");
  expect(() => beginTransaction({...journal, operation: "RECOVER", reconciliation: {result: "CONSISTENT", input: recovered}})).toThrow("K1_REFUSED");
  expect(beginTransaction(journal).journal).toEqual(journal);
});
it("closure begin binds the pre-transaction anchor to the old custody revision", () => {
  expect(() => beginTransaction(journal, {...prior, enrollment_revision: 3})).toThrow("K1_REFUSED");
  expect(() => beginTransaction(journal, {...prior, custody_envelope_digest: otherDigest})).toThrow("K1_REFUSED");
});
it("closure a journal mutated after begin cannot complete on unchecked acknowledgments", () => {
  const seed = (prepare: typeof preparedAck | typeof stuffed, commit: typeof committedAck | typeof stuffed) => {
    const state = beginTransaction(journal), mutated = {...state.journal, drain_ack: {prepare, commit}};
    return walk({...state, journal: mutated, persistence: preparePersistence(mutated)}, false);
  };
  expect(transactionComplete(seed(stuffed, stuffed))).toBe(false);
  expect(transactionComplete(seed(preparedAck, {...committedAck, activation_id: "d".repeat(32)}))).toBe(false);
  expect(transactionComplete(seed({...preparedAck, committed_sequence: 1, reserved_sequence: 1, committed_digest: otherDigest}, {...committedAck, committed_sequence: 1, reserved_sequence: 1, committed_digest: otherDigest}))).toBe(false);
  // The same walk with the acknowledgments D_ACK would have accepted still completes, so only the re-check refuses.
  expect(transactionComplete(seed(preparedAck, committedAck))).toBe(true);
});
it("closure completion is bound to the exact journal that was read back", () => {
  const state = walk(beginTransaction(journal));
  expect(transactionComplete(state)).toBe(true);
  expect(transactionComplete({...state, journal: {...state.journal, operation: "PROVISION"}})).toBe(false);
});
it("closure the prepare acknowledgment is write-once", () => {
  const prepared = advanceTransaction(toPhase(beginTransaction(journal), "D_PREPARE"), {op: "D_ACK", anchor: preparedAck});
  expect(() => advanceTransaction(prepared, {op: "D_ACK", anchor: preparedAck})).toThrow("K1_REFUSED");
  expect(() => advanceTransaction(prepared, {op: "D_ACK", anchor: {...preparedAck, drained_sequence: 0, committed_sequence: 0}})).toThrow("K1_REFUSED");
  const committed = advanceTransaction(toPhase(prepared, "D_COMMIT"), {op: "D_ACK", anchor: committedAck});
  expect(() => advanceTransaction(committed, {op: "D_ACK", anchor: committedAck})).toThrow("K1_REFUSED");
});
it.each([
  ["committed tail", {reserved_sequence: 1, committed_sequence: 1, committed_digest: otherDigest}],
  ["drained tail", {reserved_sequence: 1, committed_sequence: 1, committed_digest: otherDigest, drained_sequence: 1, drained_digest: otherDigest}],
  ["generation high water", {generation_high_water: 1}],
  ["fortress", {fortress_id: "d".repeat(32)}],
  ["machine", {machine_id: "d".repeat(32)}],
  ["activation", {activation_id: "d".repeat(32)}],
  ["boot", {boot_id: "d".repeat(32)}],
  ["recovery revision", {recovery_revision: 1}],
])("closure the prepare acknowledgment refuses a changed %s outside the PREPARE field set", (_name, change) => {
  const state = toPhase(beginTransaction(journal), "D_PREPARE");
  expect(() => advanceTransaction(state, {op: "D_ACK", anchor: {...preparedAck, ...change}})).toThrow("K1_REFUSED");
  expect(advanceTransaction(state, {op: "D_ACK", anchor: preparedAck}).journal.drain_ack.prepare).toEqual(preparedAck);
});
it("closure a recovery acknowledgment names the reconciled drain tuple", () => {
  // The transaction began against a later generation than the anchor it reconciled, so only the reconciliation binding refuses.
  const later = {...prior, generation_high_water: 1};
  let state = beginTransaction({...journal, operation: "RECOVER"}, later);
  state = advanceTransaction(state, {op: "RECONCILE", input: recovered});
  state = toPhase(state, "D_PREPARE");
  expect(() => advanceTransaction(state, {op: "D_ACK", anchor: {...preparedAck, generation_high_water: 1}})).toThrow("K1_REFUSED");
  let aligned = advanceTransaction(beginTransaction({...journal, operation: "RECOVER"}), {op: "RECONCILE", input: recovered});
  aligned = toPhase(aligned, "D_PREPARE");
  expect(advanceTransaction(aligned, {op: "D_ACK", anchor: preparedAck}).journal.drain_ack.prepare).toEqual(preparedAck);
});
it("closure a second reconciliation refuses", () => {
  const once = advanceTransaction(beginTransaction({...journal, operation: "RECOVER"}), {op: "RECONCILE", input: recovered});
  expect(() => advanceTransaction(once, {op: "RECONCILE", input: recovered})).toThrow("K1_REFUSED");
});
it("closure a cut persists through write and readback and then refuses replay", () => {
  let state = advanceTransaction(beginTransaction(journal), {op: "CUT"});
  for (const op of ["WRITE", "FILE_SYNC", "DIRECTORY_SYNC"] as const) { state = advanceTransaction(state, {op}); expect(custody.cutDurable(state)).toBe(false); }
  const bytes = canonicalBytes(state.journal);
  state = advanceTransaction(state, {op: "READBACK", bytes});
  expect(custody.cutDurable(state)).toBe(true);
  expect(decodeTransaction(bytes).cut).toBe(true);
  expect(() => beginTransaction(decodeTransaction(bytes))).toThrow("K1_REFUSED");
  for (const event of [{op: "NEXT"}, {op: "RECONCILE", input: recovered}, {op: "D_ACK", anchor: preparedAck}] as const)
    expect(() => advanceTransaction(state, event)).toThrow("K1_REFUSED");
  expect(transactionComplete(state)).toBe(false);
});
