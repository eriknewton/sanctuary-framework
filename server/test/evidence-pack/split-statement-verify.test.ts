// Candidate-only nested checks; the static entry witness supplies semantic base evidence.
import { describe,expect,it } from "vitest";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { verifySplitNested } from "../../src/evidence-pack/split-statement-nested.js";
import { splitFixture,refreshSplit,signSplit,type SplitFixture } from "./split-statement-fixtures.js";
import { checkpointSigningBytes } from "../../src/audit/chain.js";
import { jsonBytes,signBytes } from "./snapshot-fixtures.js";
const parse=(s:SplitFixture)=>{const r=B.parseSplitStatement(s.manifest,s.trust,s.files);if(r.kind!=="parsed")throw new Error(r.code);return r.value;};
const inspect=(s:SplitFixture)=>verifySplitNested(parse(s));
function changeCheckpoint(s:SplitFixture,id:B.ChainId,edit:(cp:any)=>void){const row=s.chains[id].find(r=>r.type === "checkpoint")!;const cp=JSON.parse(Buffer.from(row.persisted_base64url as string,"base64url").toString());edit(cp);row.persisted_base64url=Buffer.from(JSON.stringify(cp)).toString("base64url");refreshSplit(s);}
function updateCensus(s:SplitFixture){s.files.set(B.FIXED_FILES.census[0],jsonBytes(s.census));signSplit(s);}
describe("separate chain ordinary evidence",()=>{
 it("verifies both sequence spaces and preserves unsigned daemon basis",()=>{const r=inspect(splitFixture());expect(r.hard).toEqual([]);expect(r.partial).toEqual([]);expect(r.chains.map(c=>c.historical_signatures)).toEqual(["all_pinned","unsigned_present"]);expect(r.chains[1].signatures_verified).toBe(0);});
 it.each(B.CHAIN_IDS)("keeps delivered %s tails incomplete",id=>{const s=splitFixture();s.chains[id]=s.chains[id].filter(r=>r.type!=="checkpoint");refreshSplit(s);const r=inspect(s);expect(r.partial).toContain("audit_tail_unanchored");expect(r.chains[B.CHAIN_IDS.indexOf(id)].tail_entries).toBeGreaterThan(0);});
 it("does not promote an unsigned operator",()=>{const s=splitFixture();changeCheckpoint(s,"operator",cp=>{Object.assign(cp,{unsigned:true,signature:null,signer_kid:null,signature_algorithm:null});delete cp.public_key;});expect(inspect(s).partial).toContain("checkpoint_unsigned");});
 it("requires the daemon basis allowed by this contract",()=>{const s=splitFixture();changeCheckpoint(s,"daemon",cp=>{Object.assign(cp,{unsigned:false,signer_kid:s.f.audit.identity_id,signature_algorithm:C.ALGORITHM,public_key:s.f.audit.public_key});delete cp.unsigned_reason;cp.signature=signBytes(checkpointSigningBytes({checkpoint_kind:cp.checkpoint_kind,checkpoint_sequence:cp.checkpoint_sequence,from_sequence:cp.from_sequence,root_hash:cp.root_hash,previous_checkpoint_sequence:cp.previous_checkpoint_sequence,signed_at:cp.signed_at}),s.f.audit);});const trust=JSON.parse(Buffer.from(s.trust).toString());trust.keys.push({...trust.keys.find((k:any)=>k.role===B.PIN_ROLE.operator),role:B.PIN_ROLE.daemon});trust.keys.sort((a:any,b:any)=>(a.role+":"+a.key_id)<(b.role+":"+b.key_id)?-1:1);s.trust=jsonBytes(trust);s.files.set(C.TRUST_FILENAME,s.trust);signSplit(s);expect(inspect(s).hard).toContain("daemon_basis_unsupported");});
 it("refuses a claimed empty daemon",()=>{const s=splitFixture();s.chains.daemon=[];refreshSplit(s);expect(inspect(s).hard).toContain("migration_invalid");});
 it("admits the locally checked zero-prefix empty operator",()=>{const s=splitFixture();s.chains.operator=[];Object.assign(s.census.migration,{sealed_base_sequence:0,sealed_tip_sequence:0,sealed_tip_entry_hash:"GENESIS"});refreshSplit(s);const r=inspect(s);expect(r.hard).toEqual([]);expect(r.chains[0]).toMatchObject({state:"empty",historical_signatures:"all_pinned",signatures_verified:0,coverage:{checkpointed:null,tail:null}});});
 it("keeps unreadable evidence unevaluated",()=>{const s=splitFixture();s.chains.operator=[];refreshSplit(s);s.manifest.components.operator={state:"read_failed",reason:"source_unreadable"};Object.assign(s.census.chains[0],{census_state:"unavailable",source_entries:null,source_checkpoints:null,exported_entries:null,exported_checkpoints:null,skipped:null,controls_state:"unavailable"});s.census.state="incomplete";updateCensus(s);const r=inspect(s);expect(r.chains[0].historical_signatures).toBeNull();expect(r.partial).toContain("source_unreadable");});
 it("rejects a false empty source census",()=>{const s=splitFixture();s.chains.operator=[];refreshSplit(s);s.census.chains[0].source_entries=1;updateCensus(s);expect(inspect(s).hard).toContain("census_mismatch");});
 it.each(["sealed_tip_entry_hash","daemon_genesis_entry_hash"])("binds migration field %s to public bytes",field=>{const s=splitFixture();s.census.migration[field]="0".repeat(64);updateCensus(s);expect(inspect(s).hard).toContain("migration_invalid");});
 it("never calls unavailable migration publicly verified",()=>{const s=splitFixture();s.census.migration={state:"unavailable",reason:"migration_unavailable"};updateCensus(s);expect(inspect(s).partial).toContain("migration_unavailable");});
 it("does not erase an evaluated signing error with incompleteness",()=>{const s=splitFixture();changeCheckpoint(s,"operator",cp=>{cp.signature=Buffer.alloc(C.SIGNATURE_BYTES).toString("base64url");});s.census.state="incomplete";s.census.issues=["source_incomplete"];updateCensus(s);const r=inspect(s);expect(r.hard).toContain("checkpoint_invalid");expect(r.chains[0].historical_signatures).toBe("signed_with_errors");});
 it("keeps absent ordinary coverage null with the whole range in tail",()=>{const s=splitFixture();s.chains.operator=s.chains.operator.filter(r=>r.type==="entry");refreshSplit(s);expect(inspect(s).chains[0]).toMatchObject({historical_signatures:null,signatures_unevaluated_reason:"no_checkpoints",coverage:{checkpointed:null,tail:{first:1,last:2}}});});
 it("detects a changed ciphertext hash",()=>{const s=splitFixture();s.chains.daemon[0].encrypted_payload_bytes="AQ";refreshSplit(s);expect(inspect(s).hard).toContain("chain_invalid");});
 it("detects duplicate entry sequences",()=>{const s=splitFixture();s.chains.operator.splice(1,0,{...s.chains.operator[0]});refreshSplit(s);expect(inspect(s).hard).toContain("chain_invalid");});
 it("detects a wrong genesis predecessor",()=>{const s=splitFixture();s.chains.daemon[0].prev_hash="a".repeat(64);refreshSplit(s);expect(inspect(s).hard).toContain("chain_invalid");});
 it("retains the pruned-history diagnostic",()=>{const s=splitFixture();s.chains.operator=s.chains.operator.slice(1);refreshSplit(s);expect(inspect(s).partial).toContain("pruned_history");});
 it("detects wrong ordinary checkpoint roots",()=>{const s=splitFixture();changeCheckpoint(s,"daemon",cp=>{cp.root_hash="0".repeat(64);});expect(inspect(s).hard).toContain("checkpoint_invalid");});
 it("detects inconsistent source counts",()=>{const s=splitFixture();s.census.chains[0].source_entries++;updateCensus(s);expect(inspect(s).hard).toContain("census_mismatch");});
 it("detects an omitted delivered-record mapping",()=>{const s=splitFixture();s.census.objects.pop();updateCensus(s);expect(inspect(s).hard).toContain("census_mismatch");});
 it("detects duplicate mapping targets",()=>{const s=splitFixture();s.census.objects[1].output=s.census.objects[0].output;updateCensus(s);expect(inspect(s).hard).toContain("census_mismatch");});
 it("detects swapped subject files",()=>{const s=splitFixture();const a=s.files.get(B.FIXED_FILES["audit-operator"][0])!;s.files.set(B.FIXED_FILES["audit-operator"][0],s.files.get(B.FIXED_FILES["audit-daemon"][0])!);s.files.set(B.FIXED_FILES["audit-daemon"][0],a);signSplit(s);expect(inspect(s).hard).toContain("census_mismatch");});
 it("treats local control invalidity as hard failure",()=>{const s=splitFixture();s.census.state="incomplete";s.census.chains[0].census_state="incomplete";s.census.chains[0].controls_state="invalid";updateCensus(s);expect(inspect(s).hard).toContain("source_control_invalid");});
});

import {verifySplitStatement,validateSplitPins} from "../../src/evidence-pack/split-statement-verify.js";
import {verifySplitTransparency} from "../../src/evidence-pack/split-statement-nested.js";
import {verifyTransparencyCheckpoints} from "../../src/transparency/verify.js";
import {computeAuditRoot} from "../../src/audit/chain.js";
import {checkpointPayloadOf,computeCheckpointHash} from "../../src/transparency/checkpoint.js";
import {SOURCE,resignTransparency} from "./snapshot-fixtures.js";
function syncWindows(s:SplitFixture){let previous="GENESIS";for(const [i,cp]of s.bundle.checkpoints.entries()){cp.counter=i+1;cp.previous_checkpoint_hash=previous;resignTransparency(cp,s.f.transparency);previous=computeCheckpointHash(checkpointPayloadOf(cp));}s.census.transparency_floor.highest_counter=s.bundle.checkpoints.length;refreshSplit(s);}
const verified=(s:SplitFixture)=>verifySplitStatement(s.capture,s.pins,SOURCE);
describe("split transparency and bounded recipient",()=>{
 it("assigns an operator-to-daemon head reset uniquely",()=>{const s=splitFixture(),r=verified(s);expect(r.status).toBe("PASS");expect(r.result.transparency_assignments).toEqual([{counter:1,chain_id:"operator"},{counter:2,chain_id:"daemon"}]);});
 it("preserves V0's global audit head rollback rule",()=>{const s=splitFixture();expect(verifyTransparencyCheckpoints(s.bundle,{publicKey:s.f.transparency.public_key}).findings.map(f=>f.kind)).toContain("counter_rollback");});
 it("refuses a within-chain head rollback",()=>{const s=splitFixture();const e=s.chains.operator[0] as any;s.bundle.checkpoints[1].audit={entry_count:1,lowest_sequence:1,highest_sequence:1,head_hash:e.entry_hash,merkle_root:computeAuditRoot([e.entry_hash])};syncWindows(s);expect(verified(s).result.findings.map(f=>f.code)).toContain("transparency_subject_mismatch");});
 it("keeps an empty window partial without an assignment",()=>{const s=splitFixture();s.bundle.checkpoints[1].audit={entry_count:0,lowest_sequence:0,highest_sequence:0,head_hash:"GENESIS",merkle_root:computeAuditRoot([])};syncWindows(s);const r=verified(s);expect(r.status).toBe("PARTIAL");expect(r.result.transparency_assignments).toHaveLength(1);expect(r.result.partial_reasons).toContain("transparency_window_unavailable");});
 it("refuses a recomputed root mismatch",()=>{const s=splitFixture();s.bundle.checkpoints[1].audit.merkle_root="0".repeat(64);syncWindows(s);expect(verified(s).status).toBe("FAIL");});
 it("refuses two matching public subjects",()=>{const s=splitFixture();s.chains.daemon[0]={...s.chains.operator[0]};changeCheckpoint(s,"daemon",cp=>{cp.root_hash=computeAuditRoot([s.chains.daemon[0].entry_hash as string]);});s.census.migration.daemon_genesis_entry_hash=s.chains.daemon[0].entry_hash;s.bundle.checkpoints[1].audit={entry_count:1,lowest_sequence:1,highest_sequence:1,head_hash:s.chains.daemon[0].entry_hash as string,merkle_root:computeAuditRoot([s.chains.daemon[0].entry_hash as string])};syncWindows(s);expect(verified(s).result.findings.map(f=>f.code)).toContain("transparency_subject_mismatch");});
 it("preserves prefix incompleteness under the shared counter primitive",()=>{const s=splitFixture();s.bundle.checkpoints.shift();refreshSplit(s);const r=verified(s);expect(r.status).toBe("PARTIAL");expect(r.result.partial_reasons).toContain("transparency_prefix_unverified");});
 it("refuses duplicate global counters",()=>{const s=splitFixture();s.bundle.checkpoints[1].counter=1;resignTransparency(s.bundle.checkpoints[1],s.f.transparency);refreshSplit(s);expect(verified(s).status).toBe("FAIL");});
 it("refuses a global predecessor mismatch",()=>{const s=splitFixture();s.bundle.checkpoints[1].previous_checkpoint_hash="0".repeat(64);resignTransparency(s.bundle.checkpoints[1],s.f.transparency);refreshSplit(s);expect(verified(s).status).toBe("FAIL");});
 it("refuses a different fortress subject",()=>{const s=splitFixture();s.bundle.checkpoints[1].fortress_id="fortress-0000000000000000";resignTransparency(s.bundle.checkpoints[1],s.f.transparency);refreshSplit(s);expect(verified(s).status).toBe("FAIL");});
 it("refuses signature failure before accepting a subject",()=>{const s=splitFixture();s.bundle.checkpoints[1].signature=Buffer.alloc(C.SIGNATURE_BYTES).toString("base64url");refreshSplit(s);expect(verified(s).status).toBe("FAIL");});
 it("keeps unused extension pins incomplete",()=>{const s=splitFixture();const trust=JSON.parse(Buffer.from(s.trust).toString());trust.keys.push({...trust.keys.find((k:any)=>k.role===B.PIN_ROLE.pack),role:"extension:synthetic"});trust.keys.sort((a:any,b:any)=>(a.role+":"+a.key_id)<(b.role+":"+b.key_id)?-1:1);s.trust=jsonBytes(trust);s.pins.descriptorBytes=s.trust;s.files.set(C.TRUST_FILENAME,s.trust);signSplit(s);expect(verified(s).result.partial_reasons).toContain("extension_unverified");});
 it("requires the exact independent descriptor bytes",()=>{const s=splitFixture();s.pins.descriptorBytes=C.utf8(Buffer.from(s.trust).toString()+"\n");expect(verified(s).status).toBe("FAIL");});
 it("requires the expected raw manifest digest",()=>{const s=splitFixture();s.pins.expectedManifestDigest="sha256:"+"0".repeat(64);expect(verified(s).result.findings[0].code).toBe("manifest_digest_mismatch");});
 it("does not deserialize a verified capability from a result",()=>{const r=verified(splitFixture());expect(r.status).toBe("PASS");expect(Object.keys(B.parseResult(JSON.parse(JSON.stringify(r.result))))).not.toContain("evidence");expect(()=>B.parseResult({...r.result,evidence:{}})).toThrow();});
 it("meters repeated common-lowest windows linearly",()=>{const s=splitFixture();s.bundle.checkpoints=Array.from({length:100},()=>structuredClone(s.bundle.checkpoints[0]));syncWindows(s);const p=parse(s),n=verifySplitNested(p);const before=p.budget.leaves;const t=verifySplitTransparency(p,n);expect(t.hard).toEqual([]);expect(t.assignments).toHaveLength(100);expect(p.budget.leaves-before).toBe(2);});
 it("allows exact aggregate work equality",()=>{const p=parse(splitFixture());p.budget.charge("leaves",B.MAX_LEAF_VISITS-6);const n=verifySplitNested(p);expect(verifySplitTransparency(p,n).hard).toEqual([]);expect(p.budget.leaves).toBe(B.MAX_LEAF_VISITS);});
 it("refuses the first work unit over the aggregate cap",()=>{const p=parse(splitFixture());p.budget.charge("leaves",B.MAX_LEAF_VISITS-5);const n=verifySplitNested(p);expect(()=>verifySplitTransparency(p,n)).toThrow();expect(p.budget.leaves).toBe(B.MAX_LEAF_VISITS);});
 it("refuses malformed nested elements before all consumers",()=>{const s=splitFixture();s.bundle.checkpoints[0].audit=null as any;s.files.set(C.TRANSPARENCY_FILENAME,jsonBytes(s.bundle));signSplit(s);expect(verified(s).status).toBe("FAIL");});
 it("requires stable held-file observations at final verification",()=>{const s=splitFixture();s.capture.files[0].after={...s.capture.files[0].after,size:s.capture.files[0].after.size+1};expect(verified(s).result.findings[0].code).toBe("snapshot_changed");});
});

import {rotateKeys} from "../../src/core/identity.js";
import {encryptionKey} from "./snapshot-fixtures.js";
import {projectIdentity} from "../../src/evidence-pack/snapshot-generate.js";
describe("aggregate authentication admission",()=>{
 it("charges outer and nested signatures to the same budget",()=>{const s=splitFixture(),budget=new B.Budget();expect(verifySplitStatement(s.capture,s.pins,SOURCE,budget).status).toBe("PASS");expect(budget.signatures).toBe(4);});
 it("refuses a manifest attempt beyond the aggregate signature cap",()=>{const s=splitFixture(),budget=new B.Budget();budget.charge("signatures",B.MAX_SIGNATURE_ATTEMPTS);const r=verifySplitStatement(s.capture,s.pins,SOURCE,budget);expect(r.status).toBe("FAIL");expect(r.result.findings[0].code).toBe("limit_exceeded");expect(budget.signatures).toBe(B.MAX_SIGNATURE_ATTEMPTS);});
 it("charges outer history before its verifier",()=>{const s=splitFixture(),current=rotateKeys(s.f.pack,encryptionKey,"scheduled").updatedIdentity,trust=JSON.parse(Buffer.from(s.pins.descriptorBytes).toString());trust.keys=trust.keys.map((k:any)=>k.role===B.PIN_ROLE.pack?projectIdentity(current,B.PIN_ROLE.pack):k);trust.keys.sort((a:any,b:any)=>(a.role+":"+a.key_id)<(b.role+":"+b.key_id)?-1:1);const pins={...s.pins,packKey:current.public_key,descriptorBytes:jsonBytes(trust)};expect(()=>validateSplitPins(pins)).not.toThrow();const budget=new B.Budget();budget.charge("signatures",B.MAX_SIGNATURE_ATTEMPTS);expect(()=>validateSplitPins(pins,budget)).toThrowError("limit_exceeded");});
 it("returns a failed result when the build revision is unavailable",()=>{const s=splitFixture(),r=verifySplitStatement(s.capture,s.pins,"");expect(r.status).toBe("FAIL");expect(r.result.verifier_source_revision).toBe("");expect(()=>B.parseResult(r.result)).not.toThrow();});
});


describe("retained checkpoint prefixes and knowable subjects",()=>{
 it.each(["omitted-predecessor","checkpoint-before-entries"])("keeps %s partial with valid original signatures",shape=>{
  const s=splitFixture(),first=s.chains.operator[0],last=s.chains.operator[1];
  s.chains.operator=s.chains.operator.slice(1);
  changeCheckpoint(s,"operator",cp=>{
   Object.assign(cp,shape==="omitted-predecessor"?{from_sequence:2,checkpoint_sequence:2,previous_checkpoint_sequence:1,root_hash:computeAuditRoot([last.entry_hash as string])}:{from_sequence:1,checkpoint_sequence:1,previous_checkpoint_sequence:0,root_hash:computeAuditRoot([first.entry_hash as string])});
   cp.signature=signBytes(checkpointSigningBytes({checkpoint_kind:cp.checkpoint_kind,checkpoint_sequence:cp.checkpoint_sequence,from_sequence:cp.from_sequence,root_hash:cp.root_hash,previous_checkpoint_sequence:cp.previous_checkpoint_sequence,signed_at:cp.signed_at}),s.f.audit);
  });
  const r=verified(s);expect(r.status).toBe("PARTIAL");expect(r.result.partial_reasons).toContain("pruned_history");
  expect(r.result.chains[0]).toMatchObject({historical_signatures:"all_pinned",signatures_verified:1,coverage:{checkpointed:null,tail:{first:2,last:2}}});
 });
 it("uses complete entry extents despite missing ordinary prefix coverage",()=>{
  const s=splitFixture();changeCheckpoint(s,"daemon",cp=>{cp.from_sequence=1;});
  changeCheckpoint(s,"operator",cp=>{cp.from_sequence=2;cp.root_hash=computeAuditRoot([s.chains.operator[1].entry_hash as string]);cp.signature=signBytes(checkpointSigningBytes({checkpoint_kind:cp.checkpoint_kind,checkpoint_sequence:cp.checkpoint_sequence,from_sequence:cp.from_sequence,root_hash:cp.root_hash,previous_checkpoint_sequence:cp.previous_checkpoint_sequence,signed_at:cp.signed_at}),s.f.audit);});
  s.bundle.checkpoints[1].audit={entry_count:1,lowest_sequence:3,highest_sequence:3,head_hash:"0".repeat(64),merkle_root:computeAuditRoot(["0".repeat(64)])};syncWindows(s);
  const r=verified(s);expect(r.status).toBe("FAIL");expect(r.result.findings.map(f=>f.code)).toContain("transparency_subject_mismatch");
 });
});

// The result preserves counter-specific diagnostics and the primitive's remaining scope limits.
it("reports bounded unavailable-window counters without losing totals",()=>{
 const s=splitFixture();s.bundle.checkpoints[1].audit={entry_count:0,lowest_sequence:0,highest_sequence:0,head_hash:"GENESIS",merkle_root:computeAuditRoot([])};syncWindows(s);const result=verified(s).result;
 expect(result.nested.transparency).toMatchObject({verdict:"PARTIAL",window_findings:[{code:"transparency_window_unavailable",counter:2}],window_findings_total:1,window_findings_truncated:false});
 const t=result.nested.transparency!;expect(()=>B.parseResult({...result,nested:{...result.nested,transparency:{...t,window_findings_total:2}}})).toThrow();
 expect(()=>B.parseResult({...result,nested:{...result.nested,transparency:{...t,window_findings:[{code:"transparency_window_unavailable",counter:0}]}}})).toThrow();
 for(const count of [B.MAX_FINDINGS,B.MAX_FINDINGS+1]){
  s.bundle.checkpoints=Array.from({length:count},()=>structuredClone(s.bundle.checkpoints[1]));syncWindows(s);let outcome:ReturnType<typeof verified>|undefined;expect(()=>{outcome=verified(s);}).not.toThrow();const bounded=outcome!.result;
  expect(bounded.status).toBe("PARTIAL");expect(bounded.nested.transparency).toMatchObject({window_findings_total:count,window_findings_truncated:count>B.MAX_FINDINGS});
  expect(bounded.nested.transparency?.window_findings).toHaveLength(B.MAX_FINDINGS);expect(bounded.nested.transparency?.window_findings.at(-1)?.counter).toBe(B.MAX_FINDINGS);
 }

});
it("retains transparency limits after recomputing delivered window roots",async()=>{
 const s=splitFixture(),result=verified(s).result;
 const {verifyTransparencyCounterChain,TRANSPARENCY_AUDIT_CONTENTS_NOT_CHECKED}=await import("../../src/transparency/verify.js");
 const primitive=verifyTransparencyCounterChain(s.bundle,{publicKey:s.bundle.public_key,trustEmbedded:false,allowPartial:true});
 expect(result.nested.transparency?.not_checked).toEqual(primitive.not_checked.filter(note=>note!==TRANSPARENCY_AUDIT_CONTENTS_NOT_CHECKED));
 expect(result.nested.transparency).toMatchObject({verdict:"PASS",window_findings:[],window_findings_total:0,window_findings_truncated:false});
});

import {computeAuditEntryHash} from "../../src/audit/chain.js";
it("keeps mixed daemon checkpoints PARTIAL and unaccepted",()=>{
 const s=splitFixture(),first=s.chains.daemon[0];
 const second:Record<string,unknown>={...first,seq:2,prev_hash:first.entry_hash,encrypted_payload_bytes:Buffer.from("daemon-second").toString("base64url")};
 second.entry_hash=computeAuditEntryHash({sequence:2,schema_version:second.schema_version as number,prev_hash:second.prev_hash as string,timestamp:second.timestamp as string,encrypted_payload_bytes:second.encrypted_payload_bytes as string});
 const cp=JSON.parse(Buffer.from(s.chains.daemon[1].persisted_base64url as string,"base64url").toString());
 Object.assign(cp,{from_sequence:2,checkpoint_sequence:2,previous_checkpoint_sequence:1,root_hash:computeAuditRoot([second.entry_hash as string]),unsigned:false,signer_kid:s.f.audit.identity_id,signature_algorithm:C.ALGORITHM,public_key:s.f.audit.public_key});delete cp.unsigned_reason;
 cp.signature=signBytes(checkpointSigningBytes({checkpoint_kind:cp.checkpoint_kind,checkpoint_sequence:cp.checkpoint_sequence,from_sequence:cp.from_sequence,root_hash:cp.root_hash,previous_checkpoint_sequence:cp.previous_checkpoint_sequence,signed_at:cp.signed_at}),s.f.audit);
 s.chains.daemon.push(second,{type:"checkpoint",persisted_base64url:Buffer.from(JSON.stringify(cp)).toString("base64url")});
 const trust=JSON.parse(Buffer.from(s.trust).toString());trust.keys.push({...trust.keys.find((k:any)=>k.role===B.PIN_ROLE.operator),role:B.PIN_ROLE.daemon});trust.keys.sort((a:any,b:any)=>(a.role+":"+a.key_id).localeCompare(b.role+":"+b.key_id));s.trust=jsonBytes(trust);s.pins.descriptorBytes=s.trust;s.files.set(C.TRUST_FILENAME,s.trust);refreshSplit(s);
 const r=verified(s);expect(r.result.findings).toEqual([]);expect(r.result.chains[1]).toMatchObject({unsigned_count:1,signatures_verified:1,tail_entries:0});
 expect(r.result.partial_reasons,"mixed daemon reason").toEqual(["checkpoint_mixed"]);
 expect([r.status,r.accepted],"mixed daemon acceptance").toEqual(["PARTIAL",false]);
});

it("keeps checkpointed coverage before a mid-span hole",()=>{
 const s=splitFixture(),first=s.chains.daemon[0],cp=JSON.parse(Buffer.from(s.chains.daemon[1].persisted_base64url as string,"base64url").toString());let previous=first;
 for(const seq of [2,3]){const entry:Record<string,unknown>={...first,seq,prev_hash:previous.entry_hash};entry.entry_hash=computeAuditEntryHash({sequence:seq,schema_version:entry.schema_version as number,prev_hash:entry.prev_hash as string,timestamp:entry.timestamp as string,encrypted_payload_bytes:entry.encrypted_payload_bytes as string});s.chains.daemon.push(entry);previous=entry;}
 Object.assign(cp,{from_sequence:3,checkpoint_sequence:3,previous_checkpoint_sequence:1,root_hash:computeAuditRoot([previous.entry_hash as string])});s.chains.daemon.push({type:"checkpoint",persisted_base64url:Buffer.from(JSON.stringify(cp)).toString("base64url")});refreshSplit(s);
 const r=verified(s);expect(r.status).toBe("PARTIAL");expect(r.result.partial_reasons).toContain("checkpoint_coverage_absent");
 expect(r.result.chains[1].coverage,"contiguous checkpointed prefix").toEqual({checkpointed:{first:1,last:1},tail:{first:2,last:3}});
});
