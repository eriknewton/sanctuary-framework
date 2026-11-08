import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
import {anchorSchema,anchorDigest,decodeAnchorMessage,proposeAnchor,reconcile,ANCHOR_OPS,type ActivationAnchor,type AnchorMessage} from "../../src/linux-business/activation-anchor.js";
import {canonicalBytes} from "../../src/signing/contract.js";
// Must match ANCHOR_FIXTURE in linux_business_schema.rs, executed by the native codec as well.
export const anchor=anchorSchema.parse(JSON.parse(readFileSync("../castle-wall-daemon/tests/linux_business_schema.rs","utf8").match(/const ANCHOR_FIXTURE: &str = r#"([^\n]+)"#;/)![1]));
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
