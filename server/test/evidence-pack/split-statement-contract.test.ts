// Candidate-only schema tests; semantic base evidence belongs to split-statement-failbefore-1.test.ts.
import { describe, expect, it } from "vitest";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { AUDIT_CHECKPOINT_REQUIRED_KEYS, AUDIT_CHECKPOINT_OPTIONAL_KEYS, isAuditCheckpointRecord } from "../../src/audit/checkpoint-shape.js";
import { checkpointSigningBytes } from "../../src/audit/chain.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { identity, master, signBytes, jsonBytes } from "./snapshot-fixtures.js";
import { splitFixture } from "./split-statement-fixtures.js";

function importer(value: B.ParsedSplitStatement) {
  return [...value.operator,...value.daemon].map(l=>l.record.type === "entry" ? l.record.entry_hash.length : l.record.checkpoint.root_hash.length).concat(value.transparency?.checkpoints.map(c=>c.audit.merkle_root.length)??[]);
}
describe("closed split-statement contract",()=>{
  it("parses complete synthetic structure through the importer boundary",()=>{const s=splitFixture();const r=B.parseSplitStatement(s.manifest,s.trust,s.files);expect(r.kind).toBe("parsed");if(r.kind === "parsed") expect(importer(r.value).every(n=>n===64)).toBe(true);});
  it.each(["signed","unsigned","error"] as const)("matches actual persisted producer keys: %s",async mode=>{
    const storage=new MemoryStorage(),who=identity();
    const signer=mode === "unsigned" ? undefined : async (payload:Parameters<typeof checkpointSigningBytes>[0])=>{if(mode === "error")throw new Error("synthetic signer error");return {signer_kid:who.identity_id,signature:signBytes(checkpointSigningBytes(payload),who),public_key:who.public_key};};
    const log=new AuditLog(storage,master,{checkpointInterval:1,checkpointSigner:signer});
    await log.appendCritical({layer:"l1",operation:"synthetic",identity_id:who.identity_id,result:"success",details:{}}).catch(error=>{if(mode!=="error")throw error;});
    await log.flush().catch(error=>{if(mode!=="error")throw error;});
    const rows=await storage.list("_audit_checkpoints");let found=0;
    for(const row of rows){const bytes=await storage.read("_audit_checkpoints",row.key);const object=bytes&&JSON.parse(Buffer.from(bytes).toString());if(!isAuditCheckpointRecord(object))continue;found++;expect(Object.keys(object).filter(k=>!(AUDIT_CHECKPOINT_OPTIONAL_KEYS as readonly string[]).includes(k)).sort()).toEqual([...AUDIT_CHECKPOINT_REQUIRED_KEYS].sort());expect(B.parsePersistedCheckpoint(bytes!)).toEqual(object);}
    expect(found).toBeGreaterThan(0);
  });
  it.each([
    ["entry_count",null],["entry_count",-1],["entry_count",1.5],["entry_count",Number.MAX_SAFE_INTEGER+1],["entry_count","1"],
    ["lowest_sequence",0],["lowest_sequence",null],["highest_sequence",-1],["highest_sequence",1.5],["highest_sequence","2"],
    ["head_hash","bad"],["merkle_root",null],["merkle_root","A".repeat(64)],["extra",0],
  ])("rejects malformed window scalar %s=%s before importer access",(field,value)=>{
    const s=splitFixture();(s.bundle.checkpoints[0].audit as any)[field as string]=value;s.files.set(C.TRANSPARENCY_FILENAME,jsonBytes(s.bundle));
    expect(B.parseSplitStatement(s.manifest,s.trust,s.files).kind).toBe("rejected");
  });
  it("rejects null elements and absent window fields",()=>{const s=splitFixture();for(const value of [null,{}, {...s.bundle.checkpoints[0],audit:{}}]){const b={...s.bundle,checkpoints:[value]};expect(()=>B.parseTransparency(jsonBytes(b),new B.Budget())).toThrow();}});
  it("rejects checkpoint missing and extra producer keys",()=>{const s=splitFixture(),cp=JSON.parse(Buffer.from(s.chains.daemon.at(-1)!.persisted_base64url as string,"base64url").toString());for(const field of AUDIT_CHECKPOINT_REQUIRED_KEYS){const r={...cp};delete r[field];expect(()=>B.parsePersistedCheckpoint(jsonBytes(r))).toThrow();}expect(()=>B.parsePersistedCheckpoint(jsonBytes({...cp,extra:true}))).toThrow();});
  it("rejects evaluated and null-basis disagreement",()=>{const c={chain_id:"daemon",state:"unavailable",historical_signatures:null,signatures_evaluated:false,signatures_unevaluated_reason:"unreadable",checkpoint_count:null,unsigned_count:null,signatures_verified:null,entries_verified:null,tail_entries:null,coverage:null,partial_reasons:["source_unreadable"]};expect(B.parseChainResult(c)).toEqual(c);for(const delta of [{signatures_evaluated:true},{historical_signatures:"all_pinned"},{signatures_unevaluated_reason:null},{signatures_unevaluated_reason:"invented"}])expect(()=>B.parseChainResult({...c,...delta})).toThrow();});
  it("keeps V0 and split formats and domains distinct",()=>{const s=splitFixture();expect(()=>C.parseManifest(s.manifest)).toThrow();expect(()=>B.parseManifest({...s.manifest,format:C.SNAPSHOT_FORMAT})).toThrow();expect(Buffer.from(B.manifestSigningBytes(s.manifest)).subarray(0,B.MANIFEST_DOMAIN.length).toString()).toBe("sanctuary.evidence-split-statement.v1\n");});
  it("requires every coverage and sentence field on human surfaces",()=>{const c=B.parseChainResult({chain_id:"daemon",state:"included",historical_signatures:"unsigned_present",signatures_evaluated:true,signatures_unevaluated_reason:null,checkpoint_count:1,unsigned_count:1,signatures_verified:0,entries_verified:3,tail_entries:2,coverage:{checkpointed:{first:1,last:1},tail:{first:2,last:3}},partial_reasons:["audit_tail_unanchored"]});const text=B.renderChains([c]);expect(text.sentences).toEqual([B.PRESENTATION,B.UNSIGNED_SENTENCE]);expect(text.coverage).toEqual(["COVERAGE=daemon:checkpointed=1-1,tail=2-3;unsigned=1,verified=0"]);});
  it("charges aggregate decoded and operation budgets before the excess unit",()=>{for(const [kind,cap] of [["records",B.MAX_EVIDENCE_RECORDS],["decoded",B.MAX_DECODED_CHECKPOINT_BYTES],["leaves",B.MAX_LEAF_VISITS],["signatures",B.MAX_SIGNATURE_ATTEMPTS]] as const){const b=new B.Budget();b.charge(kind,cap);expect(()=>b.charge(kind,1)).toThrow();expect(b[kind]).toBe(cap);}});
});

import {validatePins} from "../../src/evidence-pack/snapshot-dispatch.js";
import {validateSnapshotPins} from "../../src/evidence-pack/snapshot-trust.js";
it.each(["{bad","[]","null"])("preserves base pin_invalid for malformed V0 descriptor %s",descriptor=>{
 const pins={packKey:identity().public_key,descriptorBytes:Buffer.from(descriptor),expectedManifestDigest:"sha256:"+"0".repeat(64 /* SHA-256 hexadecimal width. */)};
 expect(()=>validateSnapshotPins(pins)).toThrowError("pin_invalid");
 expect(()=>validatePins(pins),"base-equal malformed descriptor").toThrowError("pin_invalid");
});

it.each(["entry","checkpoint","excluded","unsupported"])("requires census read-state parity for %s",kind=>{
 const s=splitFixture(),row=s.census.objects[0];Object.assign(row,{kind,read_state:kind==="entry"||kind==="checkpoint"?"absent":"unreadable",source_sha256:null,output:null});
 expect(()=>B.parseCensus(Buffer.from(JSON.stringify(s.census))),"element read-state parity").toThrowError("census_mismatch");
});
