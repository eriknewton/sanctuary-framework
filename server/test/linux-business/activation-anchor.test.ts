import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
const checkedClosureVectors = loadCheckedCorpus("closure_vectors.json") as Record<string, unknown>;
import {it,expect} from "vitest";
import {anchorSchema,anchorDigest,decodeAnchorMessage,proposeAnchor,reconcile,ANCHOR_OPS,type ActivationAnchor,type AnchorMessage} from "../../src/linux-business/activation-anchor.js";
import {canonicalBytes} from "../../src/signing/contract.js";
// Must match the anchor field in closure_vectors.json and linux_business_schema.rs.
export const anchor=anchorSchema.parse(checkedClosureVectors.anchor);
const request="c".repeat(32),digest="sha256:"+"d".repeat(64);
function message(op:AnchorMessage["op"],expected=anchor,next:ActivationAnchor|null=null):AnchorMessage{return {version:1,op,request_id:request,expected,next};}
it("canonical anchor messages preserve exact complete tuples",()=>{
  for(const op of ANCHOR_OPS){const m=message(op,anchor,op==="READ"?null:anchor);expect(decodeAnchorMessage(canonicalBytes(m))).toEqual(m);expect(()=>decodeAnchorMessage(Buffer.from(JSON.stringify(m)))).toThrow();}
  for(const key of Object.keys(anchor)){const bad={...anchor};delete bad[key as keyof typeof bad];expect(anchorSchema.safeParse(bad).success).toBe(false);}
  expect(anchorSchema.safeParse({...anchor,extra:true}).success).toBe(false);
});
it("whole tuple CAS refuses stale generation and reserve continues through commit and drain",()=>{
  const reserved={...anchor,reserved_sequence:1};
  expect(proposeAnchor(anchor,message("RESERVE",anchor,reserved))).toEqual(reserved);
  expect(()=>proposeAnchor({...anchor,generation_high_water:1},message("RESERVE",anchor,{...reserved,generation_high_water:1}))).toThrow("K1_REFUSED");
  const committed={...reserved,committed_sequence:1,committed_digest:digest};
  expect(proposeAnchor(reserved,message("COMMIT",reserved,committed))).toEqual(committed);
  const drained={...committed,drained_sequence:1,drained_digest:digest};
  expect(proposeAnchor(committed,message("DRAIN",committed,drained))).toEqual(drained);
  expect(()=>proposeAnchor(anchor,message("RESERVE",anchor,{...reserved,boot_id:request}))).toThrow("K1_REFUSED");
});
it("prepared custody proposals require consecutive revisions and matching transaction ids",()=>{
  const prepared={...anchor,enrollment_revision:2,transaction_id:request,custody_envelope_digest:digest};
  expect(proposeAnchor(anchor,message("PREPARE",anchor,prepared))).toEqual(prepared);
  expect(()=>proposeAnchor(anchor,message("PREPARE",anchor,{...prepared,enrollment_revision:3}))).toThrow("K1_REFUSED");
  expect(proposeAnchor(prepared,message("COMMIT",prepared,{...prepared,transaction_id:null})).transaction_id).toBeNull();
});
it("latch proposals remain pure and have no recovery clearing constructor",()=>{
  const latched={...anchor,recovery_required:true,recovery_reason:"integrity" as const,recovery_revision:1};
  expect(proposeAnchor(anchor,message("LATCH",anchor,latched))).toEqual(latched);
  expect(()=>proposeAnchor(latched,message("RECOVERY_COMMIT",latched,anchor))).toThrow("K1_REFUSED");
  expect(anchor.recovery_required).toBe(false);
});
it("outside receipt and original tail are independently required for same-epoch classification",()=>{
  const input={custody:anchor,drain:anchor,outside_receipt_digest:anchorDigest(anchor),original_tail_digest:anchor.committed_digest};
  expect(reconcile(input)).toBe("CONSISTENT");
  expect(reconcile({...input,outside_receipt_digest:null})).toBe("RECOVERY_REQUIRED");
  expect(reconcile({...input,original_tail_digest:null})).toBe("RECOVERY_REQUIRED");
  expect(reconcile({...input,custody:{...anchor,enrollment_revision:2}})).toBe("RECOVERY_REQUIRED");
});

// Must match closure_vectors.json and linux_business_schema.rs: every proposal and reconciliation id executes.
const closure = checkedClosureVectors as {
  anchors: Array<{id: string; op: string; request_id: string; old: ActivationAnchor; next: ActivationAnchor | null; accept: boolean}>;
  reconcile: Array<{id: string; anchor: ActivationAnchor; accept: boolean}>;
};
it("shared anchor corpus has complete unique ids", () => {
  for (const group of [closure.anchors, closure.reconcile]) expect([...new Set(group.map((c: {id: string}) => c.id))].sort()).toEqual(group.map((c: {id: string}) => c.id).sort());
});
it.each(closure.anchors)("closure anchor $id", c => {
  const input = {version: 1, op: c.op, request_id: c.request_id, expected: c.old, next: c.next} as AnchorMessage;
  if (c.accept) expect(proposeAnchor(c.old, input)).toEqual(c.next ?? c.old);
  else expect(() => proposeAnchor(c.old, input)).toThrow();
});
it.each(closure.reconcile)("closure reconciliation $id", c => {
  expect(reconcile({custody: c.anchor, drain: c.anchor, outside_receipt_digest: anchorDigest(c.anchor), original_tail_digest: c.anchor.committed_digest})).toBe(c.accept ? "CONSISTENT" : "RECOVERY_REQUIRED");
});

it("closure reserve-latch-commit sequence", () => {
  const cases = new Map(closure.anchors.map(c => [c.id, c]));
  const reserve = cases.get("reserve")!, latch = cases.get("latch")!, commit = cases.get("latched-commit")!;
  let state = reserve.old;
  for (const c of [reserve, latch]) state = proposeAnchor(state, {version: 1, op: c.op, request_id: c.request_id, expected: state, next: c.next});
  expect(() => proposeAnchor(state, {version: 1, op: commit.op, request_id: commit.request_id, expected: state, next: commit.next})).toThrow("K1_REFUSED");
  expect(state).toEqual(latch.next);
});

it("closure activation identities never return: A to B to A refuses", () => {
  const cases = new Map(closure.anchors.map(c => [c.id, c]));
  const forward = cases.get("advance_activation")!, back = cases.get("advance-activation-return")!, onward = cases.get("advance-activation-forward")!;
  const state = proposeAnchor(forward.old, {version: 1, op: forward.op, request_id: forward.request_id, expected: forward.old, next: forward.next} as AnchorMessage);
  expect(state).toEqual(back.old);
  expect(back.next!.activation_id).toBe(forward.old.activation_id);
  expect(() => proposeAnchor(state, {version: 1, op: back.op, request_id: back.request_id, expected: state, next: back.next} as AnchorMessage)).toThrow("K1_REFUSED");
  expect(proposeAnchor(state, {version: 1, op: onward.op, request_id: onward.request_id, expected: state, next: onward.next} as AnchorMessage)).toEqual(onward.next);
});

import * as anchorModule from "../../src/linux-business/activation-anchor.js";
it("closure PREPARE field set is the shared corpus set", () => {
  const value = checkedClosureVectors;
  expect([...anchorModule.PREPARE_CHANGED_FIELDS]).toEqual(value.prepare_changed_fields);
});
it("closure drained tuple field set is the shared corpus set", () => {
  const value = checkedClosureVectors;
  expect([...anchorModule.DRAIN_TUPLE_FIELDS]).toEqual(value.drain_tuple_fields);
});
// Must match recoveryPrepareBase in activation-anchor.ts and recovery_prepare_base in activation_anchor.rs: the base is the prior anchor carrying the drain's drained tuple, or null.
it("closure recovery prepare bases match the shared recover group as a full id set", () => {
  const value = checkedClosureVectors as {recover: Array<{id: string; prior: ActivationAnchor; drain: ActivationAnchor; refused_at: string | null}>};
  const base = (c: {prior: ActivationAnchor; drain: ActivationAnchor}) => anchorModule.recoveryPrepareBase(c.prior, c.drain);
  expect(value.recover.map(c => [c.id, base(c)])).toEqual(value.recover.map(c => [c.id, c.refused_at === "RECONCILE" ? null : c.drain]));
});
