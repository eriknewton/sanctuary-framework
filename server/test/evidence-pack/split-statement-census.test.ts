// fail-before-exempt: imports audit/split-evidence-source.js, which base lacks, so this candidate-only file cannot collect on base.
// Candidate-only bounded source checks; production writers and migration create every positive store.
import {describe,it,expect} from "vitest";
import {mkdir,writeFile,unlink,rmdir,symlink} from "node:fs/promises";
import {join} from "node:path";
import {physicalSplitFixture} from "./split-statement-fixtures.js";
import {readSplitSource,sourceIO,capturedStorage,type SourceIO} from "../../src/audit/split-evidence-source.js";
import {censusSplitSource,classifySplitSource} from "../../src/evidence-pack/split-statement-census.js";
import {sourceKind,SOURCE_NAMESPACES,CHAIN_NAMESPACES,BOUNDARY,META_CONTROLS,AUDIT_CHECKPOINT_REQUIRED_KEYS,AUDIT_CHECKPOINT_OPTIONAL_KEYS,excludedRawSourceName} from "../../src/audit/split-evidence-registry.js";
import * as A from "../../src/operational/audit-log.js";
import * as D from "../../src/operational/audit-store-split.js";
import {CUSTODY_WRITE_LOCK_NAMESPACE,CUSTODY_WRITE_LOCK_FILE} from "../../src/core/master-custody.js";
import * as T from "../../src/transparency/emitter.js";
import * as CP from "../../src/audit/checkpoint-shape.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
const signal=()=>new AbortController().signal;
async function withStore(run:(s:Awaited<ReturnType<typeof physicalSplitFixture>>)=>Promise<void>,split=true){const s=await physicalSplitFixture(split);try{await run(s);}finally{await s.cleanup();}}
describe("bounded source census",()=>{
 it("selects B from production migration and keeps the streams separate",()=>withStore(async s=>{const p=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));expect(p.topology).toBe("split");expect(p.records.operator.filter(r=>r.record.type==="entry")).toHaveLength(1);expect(p.records.daemon.filter(r=>r.record.type==="entry")).toHaveLength(1);}));
 it("selects V0 for a clean unsplit source",()=>withStore(async s=>expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("unsplit"),false));
 it.each(["_audit_integrity_alert","_audit_migration","_transparency_checkpoints","_meta"])("keeps applicable empty unsplit namespace %s in V0",namespace=>withStore(async s=>{await mkdir(join(s.state,namespace),{recursive:true});expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("unsplit");},false));
 it.each(Object.values(CHAIN_NAMESPACES.daemon))("selects B for raw daemon namespace %s",namespace=>withStore(async s=>{await mkdir(join(s.state,namespace));expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("split");},false));
 it("refuses an unknown audit namespace without split evidence",()=>withStore(async s=>{await mkdir(join(s.state,"_audit_unknown"));await expect(classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).rejects.toMatchObject({code:"topology_ambiguous"});},false));
 it("retains unknown objects as incomplete after positive split evidence",()=>withStore(async s=>{await s.storage.write("_audit_checkpoints","foreign",new Uint8Array([1]));const p=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));expect(p.topology).toBe("split");expect(p.issues).toContain("unknown_source_object");}));
 it("keeps raw boundary presence when its JSON lacks a marker",()=>withStore(async s=>{await mkdir(join(s.state,BOUNDARY.namespace),{recursive:true});await writeFile(join(s.state,BOUNDARY.namespace,BOUNDARY.name),"{}");expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("split");},false));
 it("keeps a missing daemon split when the marker remains",()=>withStore(async s=>{const read=await readSplitSource(s.state,sourceIO,signal());for(const o of read.objects.filter(o=>o.namespace===CHAIN_NAMESPACES.daemon.entries))await unlink(join(s.state,o.namespace,o.rawName));await rmdir(join(s.state,CHAIN_NAMESPACES.daemon.entries));expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("split");}));
 it("does not call a non-directory daemon path unsplit",()=>withStore(async s=>{await writeFile(join(s.state,CHAIN_NAMESPACES.daemon.entries),"synthetic");expect(await classifySplitSource(await readSplitSource(s.state,sourceIO,signal()))).toBe("split");},false));
 it("classifies daemon access failure as incomplete",()=>withStore(async s=>{const io={...sourceIO,open:async(...args:Parameters<typeof sourceIO.open>)=>{if(String(args[0]).includes("_audit-daemon"))throw Object.assign(new Error("synthetic"),{code:"EACCES"});return sourceIO.open(...args);}};const read=await readSplitSource(s.state,io,signal());expect(read.issues).toContain("source_unreadable");expect(await classifySplitSource(read)).toBe("split");}));
 it("rejects a linked chain file as a clean source",()=>withStore(async s=>{await symlink("missing",join(s.state,"_audit","entry-00000000000000000002-x.enc"));const read=await readSplitSource(s.state,sourceIO,signal());expect(read.hard).toContain("source_control_invalid");}));
 it("does not read excluded metadata values",()=>withStore(async s=>{await s.storage.write("_meta","unrelated-private",new Uint8Array([1]));const read=await readSplitSource(s.state,sourceIO,signal());const o=read.objects.find(o=>o.key==="unrelated-private")!;expect([o.kind,o.bytes,o.digest]).toEqual(["excluded",null,null]);}));
 it("preserves exact persisted checkpoint bytes",()=>withStore(async s=>{const p=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));for(const rows of Object.values(p.records))for(const row of rows)if(row.record.type==="checkpoint")expect(Buffer.from(row.record.persisted_base64url as string,"base64url")).toEqual(Buffer.from(row.source.bytes!));}));
 it("includes every raw name in the object budget",()=>withStore(async s=>{const r=await readSplitSource(s.state,sourceIO,signal());expect(r.objectsSeen).toBe(r.namespaces.reduce((n,ns)=>n+(ns.names?.length??0),0));expect(r.objects.length).toBe(r.objectsSeen);}));
 it("enforces the whole namespace registry",()=>{expect([...SOURCE_NAMESPACES].sort()).toEqual(["state","_audit","_audit_checkpoints","_audit_integrity_alert","_audit_migration","_audit-daemon","_audit-daemon_checkpoints","_audit-daemon_meta","_meta","_transparency_checkpoints"].sort());expect(sourceKind("_audit_checkpoints","unknown")).toBe("unsupported");
   expect(CHAIN_NAMESPACES).toEqual({operator:{entries:A.AUDIT_NAMESPACE,checkpoints:A.AUDIT_CHECKPOINT_NAMESPACE,meta:A.AUDIT_META_NAMESPACE},daemon:{entries:D.AUDIT_DAEMON_NAMESPACE,checkpoints:D.AUDIT_DAEMON_CHECKPOINT_NAMESPACE,meta:D.AUDIT_DAEMON_META_NAMESPACE}});
   expect([...SOURCE_NAMESPACES].sort()).toEqual(["state",A.AUDIT_NAMESPACE,A.AUDIT_CHECKPOINT_NAMESPACE,A.AUDIT_META_NAMESPACE,A.AUDIT_INTEGRITY_ALERT_NAMESPACE,A.AUDIT_SPLIT_BOUNDARY_DIRNAME,...Object.values(CHAIN_NAMESPACES.daemon),T.TRANSPARENCY_CHECKPOINT_NAMESPACE].sort());
   expect(excludedRawSourceName(CUSTODY_WRITE_LOCK_NAMESPACE,CUSTODY_WRITE_LOCK_FILE)).toBe(true);expect(excludedRawSourceName(CUSTODY_WRITE_LOCK_NAMESPACE,"unknown.lock")).toBe(false);
   expect(BOUNDARY).toEqual({namespace:A.AUDIT_SPLIT_BOUNDARY_DIRNAME,name:A.AUDIT_SPLIT_BOUNDARY_FILENAME});
   expect([...META_CONTROLS].sort()).toEqual([A.AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY,A.AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY,A.AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY,T.TRANSPARENCY_FLOOR_META_KEY].sort());
   expect(AUDIT_CHECKPOINT_REQUIRED_KEYS).toEqual(CP.AUDIT_CHECKPOINT_REQUIRED_KEYS);expect(AUDIT_CHECKPOINT_OPTIONAL_KEYS).toEqual(CP.AUDIT_CHECKPOINT_OPTIONAL_KEYS);
   for(const chain of Object.values(CHAIN_NAMESPACES)){for(const key of [...CP.AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS,A.AUDIT_ROTATION_ANCHOR_KEY])expect(sourceKind(chain.checkpoints,key)).toBe("control");for(const key of META_CONTROLS)expect(sourceKind(chain.meta,key)).toBe("control");}});
 it("refuses every mutation method on captured storage",()=>withStore(async s=>{const storage=capturedStorage(await readSplitSource(s.state,sourceIO,signal()));await expect(storage.write("_audit","x",new Uint8Array())).rejects.toThrow();await expect(storage.delete("_audit","x")).rejects.toThrow();}));
 it("returns independent byte buffers to source validators",()=>withStore(async s=>{const r=await readSplitSource(s.state,sourceIO,signal()),storage=capturedStorage(r),row=r.objects.find(o=>o.kind==="entry")!;const a=await storage.read(row.namespace,row.key!);a!.fill(0);expect(await storage.read(row.namespace,row.key!)).toEqual(row.bytes);}));
 it("checks cancellation before source admission",()=>withStore(async s=>{const controller=new AbortController();controller.abort();await expect(readSplitSource(s.state,sourceIO,controller.signal)).rejects.toThrow();}));
 it("keeps source and evidence caps independent",()=>{expect(B.MAX_SOURCE_OBJECTS).toBe(125000);expect(B.MAX_CENSUS_OBJECTS).toBe(125000);expect(B.MAX_EVIDENCE_RECORDS).toBe(100000);});
 it("retains pre-V2 history as incomplete",()=>withStore(async s=>{const r=await readSplitSource(s.state,sourceIO,signal()),row=r.objects.find(o=>o.kind==="entry"&&o.namespace==="_audit")!;await s.storage.write(row.namespace,row.key!,Buffer.from(JSON.stringify((await import("../../src/core/encryption.js")).encrypt(Buffer.from(JSON.stringify({timestamp:new Date().toISOString(),layer:"l1",operation:"synthetic",identity_id:"synthetic",result:"success"})),(await import("../../src/core/key-derivation.js")).derivePurposeKey(s.masterKey,"audit-log")))));expect((await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()))).issues).toContain("pre_v2_history");}));
 it.each([B.MAX_SOURCE_OBJECTS,B.MAX_SOURCE_OBJECTS+1])("bounds incremental admission at %s raw names",count=>withStore(async s=>{
   let visited=0;
   const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<typeof sourceIO.lstat>)=>{if(String(args[0]).startsWith(s.state+"/"))throw Object.assign(new Error("synthetic absent"),{code:"ENOENT"});return sourceIO.lstat(...args);}) as SourceIO["lstat"],opendir:(async()=>({async *[Symbol.asyncIterator](){for(let i=0;i<count;i++){visited++;yield {name:Buffer.from("_audit_synthetic-"+i)};}}})) as unknown as SourceIO["opendir"]};
   const r=await readSplitSource(s.state,io,signal());expect(r.objectsSeen).toBe(B.MAX_SOURCE_OBJECTS);expect(r.limited).toBe(count>B.MAX_SOURCE_OBJECTS);expect(visited).toBe(count);
 }));

});

import {gatherExportStatement,exportDependencies} from "../../src/evidence-pack/snapshot-export-cli.js";
import {gatherSnapshot} from "../../src/evidence-pack/snapshot-gather.js";
import {TRANSPARENCY_ANCHOR_CONFIG_META_KEY} from "../../src/transparency/anchoring.js";
import {encrypt} from "../../src/core/encryption.js";
import {derivePurposeKey} from "../../src/core/key-derivation.js";
import {sourceIO as productionIO} from "../../src/audit/split-evidence-source.js";
it.each(["legacy-anchor","pre-v2","anchor-config","audit-lock","emit-lock","claim","symlink-ancestor"])("preserves production V0 gather for %s",trigger=>withStore(async s=>{
 if(trigger==="legacy-anchor")await s.storage.write("_audit_checkpoints","legacy-anchor-00000000000000000001",Buffer.from("{}"));
 if(trigger==="pre-v2")await s.storage.write("_audit","entry-1234567890-0",Buffer.from(JSON.stringify(encrypt(Buffer.from("{}"),derivePurposeKey(s.masterKey,"audit-log")))));
 if(trigger==="anchor-config")await s.storage.write("_meta",TRANSPARENCY_ANCHOR_CONFIG_META_KEY,Buffer.from("{}"));
 if(trigger==="audit-lock")await writeFile(join(s.state,"_audit",A.AUDIT_WRITE_LOCK_FILE),"live synthetic lock");
 if(trigger==="emit-lock"){await mkdir(join(s.state,T.TRANSPARENCY_CHECKPOINT_NAMESPACE),{recursive:true});await writeFile(join(s.state,T.TRANSPARENCY_CHECKPOINT_NAMESPACE,T.TRANSPARENCY_EMIT_LOCK_FILE),"live synthetic lock");}
 if(trigger==="claim")await writeFile(join(s.state,"_audit",".entry-1.enc.123.0123456789abcdef.claim"),"synthetic claim");
 let fortress=s.root;
 if(trigger==="symlink-ancestor"){await symlink(s.root,join(s.root,"alias"));fortress=join(s.root,"alias");}
 const input={storage:s.storage,masterKey:s.masterKey,fortress,generatedAt:"2026-01-01T00:00:00.000Z",localSign:false};
 const expected=await gatherSnapshot(input);
 await expect(gatherExportStatement({...input,source:{...exportDependencies.source,io:productionIO},classify:exportDependencies.classify,resolvePin:exportDependencies.resolvePin,signal:signal(),identities:[],phase:async()=>{},quiesce:async()=>{throw new Error("V0 must retain its lifecycle");}}),"production V0 equals base gather").resolves.toEqual(expected);
},false));
it("projects legacy producer keys as pre_v2_history on split sources",()=>withStore(async s=>{
 const checkpoints=await s.storage.list("_audit_checkpoints","audit-checkpoint-");const anchor=JSON.parse(Buffer.from((await s.storage.read("_audit_checkpoints",checkpoints[0].key))!).toString());anchor.checkpoint_kind="legacy-anchor";await s.storage.write("_audit_checkpoints","legacy-anchor-00000000000000000001",Buffer.from(JSON.stringify(anchor)));
 await s.storage.write("_audit","entry-1234567890-0",Buffer.from(JSON.stringify(encrypt(Buffer.from("{}"),derivePurposeKey(s.masterKey,"audit-log")))));
 const p=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));expect(p.issues).toContain("pre_v2_history");
}));
it("matches the complete producer metadata and checkpoint key registry",async()=>{
 const anchoring=await import("../../src/transparency/anchoring.js");
 const meta=Object.entries({...A,...T,...anchoring}).filter(([name,value])=>name.endsWith("KEY")&&typeof value==="string"&&(/^(audit-|__audit|transparency-)/.test(value))&&!name.includes("CHECKPOINT"));
 expect(meta.map(([,value])=>value).sort()).toEqual([...META_CONTROLS,TRANSPARENCY_ANCHOR_CONFIG_META_KEY].sort());
 for(const [,key] of meta)expect(sourceKind("_meta",key as string)).toBe(key===TRANSPARENCY_ANCHOR_CONFIG_META_KEY?"excluded":"control");
 for(const prefix of Object.values(A.AUDIT_CHECKPOINT_KEY_PREFIXES))expect(sourceKind(A.AUDIT_CHECKPOINT_NAMESPACE,prefix+"00000000000000000001")).toBe("checkpoint");
});

it("keeps object diagnostics on the unsplit V0 route",()=>withStore(async s=>{
 await s.storage.write("_audit_checkpoints","unrecognized-object",Buffer.from("{}"));
 const input={storage:s.storage,masterKey:s.masterKey,fortress:s.root,generatedAt:"2026-01-01T00:00:00.000Z",localSign:false};
 await expect(gatherExportStatement({...input,source:exportDependencies.source,classify:exportDependencies.classify,resolvePin:exportDependencies.resolvePin,signal:signal(),identities:[],phase:async()=>{},quiesce:async()=>{throw new Error("V0 lifecycle");}})).resolves.toEqual(await gatherSnapshot(input));
},false));

import {FILESYSTEM_STORAGE_CLAIM_SUFFIX,FILESYSTEM_STORAGE_CLAIM_NONCE_BYTES} from "../../src/storage/filesystem.js";
it.each([
 ["audit-write",A.AUDIT_NAMESPACE,A.AUDIT_WRITE_LOCK_FILE],
 ["transparency-emit",T.TRANSPARENCY_CHECKPOINT_NAMESPACE,T.TRANSPARENCY_EMIT_LOCK_FILE],
 ["storage-claim",A.AUDIT_NAMESPACE,`.entry-1.enc.${process.pid}.${"ab".repeat(FILESYSTEM_STORAGE_CLAIM_NONCE_BYTES)}${FILESYSTEM_STORAGE_CLAIM_SUFFIX}`],
])("excludes producer raw name %s",(_label,namespace,rawName)=>withStore(async s=>{
 await mkdir(join(s.state,namespace),{recursive:true});await writeFile(join(s.state,namespace,rawName),"synthetic producer name");
 const projection=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));
 const object=projection.read.objects.find(o=>o.namespace===namespace&&o.rawName===rawName)!;
 expect(object.kind,"producer raw name excluded").toBe("excluded");
 expect(projection.issues,"producer raw name has no unknown issue").not.toContain("unknown_source_object");
 expect([object.read_state,object.bytes,object.digest],"producer raw name is never read").toEqual(["absent",null,null]);
}));

import * as FS from "../../src/storage/filesystem.js";
import * as CF from "../../src/storage/custody-fs.js";
import * as MC from "../../src/core/master-custody.js";
import {SOURCE_RAW_NAME_PRODUCERS,producerRawSourceName} from "../../src/audit/split-evidence-registry.js";
it("matches every producer staging and lock name",()=>{
 const producers={...A.AUDIT_RAW_NAME_GRAMMARS,...T.TRANSPARENCY_RAW_NAME_GRAMMARS,...FS.FILESYSTEM_RAW_NAME_GRAMMARS,...CF.CUSTODY_FS_RAW_NAME_GRAMMARS,...MC.MASTER_CUSTODY_RAW_NAME_GRAMMARS};
 expect(SOURCE_RAW_NAME_PRODUCERS,"complete raw producer registry").toEqual(producers);
 const rows=[
  [A.AUDIT_NAMESPACE,A.AUDIT_WRITE_LOCK_FILE],
  [T.TRANSPARENCY_CHECKPOINT_NAMESPACE,T.TRANSPARENCY_EMIT_LOCK_FILE],
  [MC.CUSTODY_WRITE_LOCK_NAMESPACE,MC.CUSTODY_WRITE_LOCK_FILE],
  [A.AUDIT_NAMESPACE,`.entry-1.enc.${process.pid}.${"ab".repeat(FS.FILESYSTEM_STORAGE_CLAIM_NONCE_BYTES)}${FS.FILESYSTEM_STORAGE_CLAIM_SUFFIX}`],
  [A.AUDIT_NAMESPACE,`.entry-1.enc${FS.FILESYSTEM_STORAGE_COMPARE_REPLACE_LOCK_SUFFIX}`],
  [A.AUDIT_NAMESPACE,`.entry-1.enc.${process.pid}.${"ab".repeat(CF.CUSTODY_ATOMIC_WRITE_NONCE_BYTES)}${CF.CUSTODY_ATOMIC_WRITE_STAGING_SUFFIX}`],
 ];
 expect(rows.map(([ns,name])=>excludedRawSourceName(ns,name)),"all producer names excluded").toEqual(rows.map(()=>true));
});
it.each([
 ["atomic-write",`.entry-1.enc.${process.pid}.${"ab".repeat(CF.CUSTODY_ATOMIC_WRITE_NONCE_BYTES)}${CF.CUSTODY_ATOMIC_WRITE_STAGING_SUFFIX}`],
 ["compare-replace",`.entry-1.enc${FS.FILESYSTEM_STORAGE_COMPARE_REPLACE_LOCK_SUFFIX}`],
])("excludes producer transient %s",(_label,rawName)=>withStore(async s=>{
 await writeFile(join(s.state,A.AUDIT_NAMESPACE,rawName),"synthetic transient");
 const projection=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));
 expect(projection.read.objects.find(o=>o.rawName===rawName)?.kind,"transient excluded").toBe("excluded");
 expect(projection.issues,"transient has no unknown issue").not.toContain("unknown_source_object");
}));

it.each([
 ["acquire",`.audit-write.lock.acquire.${process.pid}.0.${"ab".repeat(A.AUDIT_RAW_NAME_GRAMMARS.auditClaim.nonceBytes)}.tmp`,"excluded"],
 ["claim",`.audit-write.lock.claim.${process.pid}.${"ab".repeat(A.AUDIT_RAW_NAME_GRAMMARS.auditClaim.nonceBytes)}.tomb`,"excluded"],
 ["evidence",`.audit-write.lock.evidence.${process.pid}.${"ab".repeat(A.AUDIT_RAW_NAME_GRAMMARS.auditClaim.nonceBytes)}.tomb`,"incident"],
])("producer grammar %s",(_label,rawName,disposition)=>withStore(async s=>{
 await writeFile(join(s.state,A.AUDIT_NAMESPACE,rawName),"synthetic residue");
 expect(producerRawSourceName(A.AUDIT_NAMESPACE,rawName),"producer recognized").toBe(disposition);
 const projection=await censusSplitSource(await readSplitSource(s.state,sourceIO,signal()));
 const object=projection.read.objects.find(o=>o.rawName===rawName)!;
 expect(object.kind,"producer disposition").toBe(disposition==="excluded"?"excluded":"unsupported");
 expect([object.read_state,object.bytes,object.digest],"residue never read").toEqual(["absent",null,null]);
 if(disposition==="excluded")expect(projection.issues,"ordinary residue excluded").not.toContain("unknown_source_object");
 else expect(projection.issues,"incident remains visible").toContain("unknown_source_object");
}));
