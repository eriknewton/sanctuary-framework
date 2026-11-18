// fail-before-exempt: imports evidence-pack/split-statement-gather.js, which base lacks, so this candidate-only file cannot collect on base.
// Candidate-only local-control checks over production-migrated storage.
import {describe,it,expect} from "vitest";
import {writeFile,readFile} from "node:fs/promises";
import {join} from "node:path";
import {physicalSplitFixture} from "./split-statement-fixtures.js";
import {readSplitSource,recheckSplitSource,sourceIO} from "../../src/audit/split-evidence-source.js";
import {censusSplitSource} from "../../src/evidence-pack/split-statement-census.js";
import {validateSplitSource,gatherSplitSource,type SplitGatherDependencies} from "../../src/evidence-pack/split-statement-gather.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
const signal=()=>new AbortController().signal;
const deps:SplitGatherDependencies={io:sourceIO,read:readSplitSource,census:censusSplitSource,validate:validateSplitSource,recheck:recheckSplitSource,budget:()=>new B.Budget()};
async function withStore(run:(s:Awaited<ReturnType<typeof physicalSplitFixture>>)=>Promise<void>){const s=await physicalSplitFixture();try{await run(s);}finally{await s.cleanup();}}
async function validate(s:Awaited<ReturnType<typeof physicalSplitFixture>>){return validateSplitSource({projection:await censusSplitSource(await readSplitSource(s.state,sourceIO,signal())),masterKey:s.masterKey,resolveKey:()=>undefined,budget:new B.Budget(),signal:signal()});}
const boundary=(s:{state:string})=>join(s.state,"_audit_migration","boundary-v1.json");
describe("captured source validation",()=>{
 it("checks both chain controls and the decrypted migration genesis",()=>withStore(async s=>{const v=await validate(s);expect(v.controls.operator.state).toBe("operator_checked");expect(v.controls.daemon.state).toBe("operator_checked");expect(v.migration.state).toBe("operator_checked");}));
 it("leaves all source names and bytes unchanged",()=>withStore(async s=>{const before=await readSplitSource(s.state,sourceIO,signal());await validate(s);expect(await recheckSplitSource(before,signal())).toBe(true);}));
 it("refuses a present boundary whose parsed marker is absent",()=>withStore(async s=>{await writeFile(boundary(s),"{}");await expect(validate(s)).rejects.toMatchObject({code:"migration_invalid"});}));
 it("refuses an invalid boundary MAC",()=>withStore(async s=>{const read=await readSplitSource(s.state,sourceIO,signal()),row=read.objects.find(o=>o.namespace==="_audit_migration")!,value=JSON.parse(Buffer.from(row.bytes!).toString());value.mac="A".repeat(43);await writeFile(boundary(s),JSON.stringify(value));await expect(validate(s)).rejects.toMatchObject({code:"migration_invalid"});}));
 it("requires the established marker alongside the boundary",()=>withStore(async s=>{await s.storage.delete("_meta","audit-store-split-established-v1");await expect(validate(s)).rejects.toMatchObject({code:"migration_invalid"});}));
 it("keeps an unavailable daemon control unverified",()=>withStore(async s=>{const base=await readSplitSource(s.state,sourceIO,signal());const row=base.objects.find(o=>o.namespace==="_audit-daemon_checkpoints"&&o.kind==="control")!;const read={...base,objects:base.objects.map(o=>o===row?{...o,read_state:"unreadable" as const,bytes:null,digest:null}:o)};const p=await censusSplitSource(read);const v=await validateSplitSource({projection:p,masterKey:s.masterKey,resolveKey:()=>undefined,budget:new B.Budget(),signal:signal()});expect(v.controls.daemon.state).toBe("unavailable");expect(v.migration.state).toBe("unavailable");}));
 it("refuses malformed signing controls",()=>withStore(async s=>{await s.storage.write("_audit_checkpoints","__signing_head",Buffer.from("{}"));await expect(validate(s)).rejects.toMatchObject({code:"source_control_invalid"});const base=await readSplitSource(s.state,sourceIO,signal()),read={...base,namespaces:base.namespaces.map(n=>n.namespace==="_audit"?{...n,state:"unreadable" as const,names:null}:n)};await expect(validateSplitSource({projection:await censusSplitSource(read),masterKey:s.masterKey,resolveKey:()=>undefined,budget:new B.Budget(),signal:signal()})).rejects.toMatchObject({code:"source_control_invalid"});}));
 it("refuses malformed custody epoch controls",()=>withStore(async s=>{await s.storage.write("_audit_checkpoints","__custody_epoch_keys",Buffer.from("{}"));await expect(validate(s)).rejects.toMatchObject({code:"source_control_invalid"});}));
 it("refuses an invalid transparency floor",()=>withStore(async s=>{await s.storage.write("_meta","transparency-counter-floor-v1",Buffer.from("{}"));await expect(validate(s)).rejects.toMatchObject({code:"source_control_invalid"});}));
 it("does not infer zero from an unreadable required namespace",()=>withStore(async s=>{const base=await readSplitSource(s.state,sourceIO,signal()),read={...base,namespaces:base.namespaces.map(n=>n.namespace==="_audit-daemon"?{...n,state:"unreadable" as const,names:null}:n)};const v=await validateSplitSource({projection:await censusSplitSource(read),masterKey:s.masterKey,resolveKey:()=>undefined,budget:new B.Budget(),signal:signal()});expect(v.controls.daemon.state).toBe("unavailable");}));
 it("detects a name added after the captured interval",()=>withStore(async s=>{const before=await readSplitSource(s.state,sourceIO,signal());await s.storage.write("_meta","synthetic-new",Buffer.from("x"));expect(await recheckSplitSource(before,signal())).toBe(false);}));
 it("uses a fresh whole census after one changed attempt",()=>withStore(async s=>{let checks=0,reads=0;const result=await gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,read:async(...args)=>{reads++;return readSplitSource(...args);},recheck:async()=>++checks>1});expect([reads,checks,result.stable]).toEqual([2,2,true]);}));
 it("stops after the second changed attempt",()=>withStore(async s=>{let reads=0;const r=await gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,read:async(...args)=>{reads++;return readSplitSource(...args);},recheck:async()=>false});expect(reads).toBe(2);expect(r.stable).toBe(false);expect(r.validation.issues).toContain("source_changed");}));
 it("keeps a hard source finding ahead of a changed recheck",()=>withStore(async s=>{await writeFile(boundary(s),"{}");let checks=0;await expect(gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,recheck:async()=>{checks++;return false;}})).rejects.toMatchObject({code:"migration_invalid"});expect(checks).toBe(0);}));
 it("rejects a read that completes after cancellation",()=>withStore(async s=>{const controller=new AbortController();let release!:()=>void;const wait=new Promise<void>(resolve=>{release=resolve;});let admitted!:()=>void;const admission=new Promise<void>(resolve=>{admitted=resolve;});const run=gatherSplitSource(s.state,s.masterKey,()=>undefined,controller.signal,{...deps,read:async(...args)=>{const read=await readSplitSource(...args);admitted();await wait;return read;}});await admission;controller.abort();release();await expect(run).rejects.toThrow();}));
 it("requires source validation as a dependency",()=>withStore(async s=>{await expect(gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,validate:undefined} as unknown as SplitGatherDependencies)).rejects.toThrow();}));
 it("charges validator work before running its checkpoint walk",()=>withStore(async s=>{const budget=new B.Budget();budget.charge("leaves",B.MAX_LEAF_VISITS);await expect(validateSplitSource({projection:await censusSplitSource(await readSplitSource(s.state,sourceIO,signal())),masterKey:s.masterKey,resolveKey:()=>undefined,budget,signal:signal()})).rejects.toMatchObject({code:"limit_exceeded"});}));
 it("keeps unknown audit objects incomplete without reading their bytes",()=>withStore(async s=>{await s.storage.write("_audit_checkpoints","unknown-audit",Buffer.from("private synthetic"));const v=await validate(s);expect(v.issues).toContain("unknown_source_object");expect(v.controls.operator.state).toBe("unavailable");}));
});

import * as C from "../../src/evidence-pack/snapshot-contract.js";
import {MAX_SOURCE_HANDLES,type SourceIO} from "../../src/audit/split-evidence-source.js";
/** Native size/read observations exercise admission without manufacturing an over-sized disk allocation. */
async function sizedNativeRead(s:Awaited<ReturnType<typeof physicalSplitFixture>>,sizes:number[]) {
  const existing=await s.storage.list("_audit","entry-");for(const row of existing)await s.storage.delete("_audit",row.key);
  const sizesByPath=new Map<string,number>();
  for(let index=0;index<sizes.length;index++){const key="entry-"+String(index+1).padStart(20,"0")+"-synthetic";await s.storage.write("_audit",key,Buffer.from("x"));sizesByPath.set(join(s.state,"_audit",key+".enc"),sizes[index]);}
  let opened=0,closed=0,peak=0;
  const shape=(value:any,path:string)=>sizesByPath.has(path)?Object.assign(Object.create(Object.getPrototypeOf(value)),value,{size:BigInt(sizesByPath.get(path)!)}):value;
  const io:SourceIO={...sourceIO,lstat:(async(...args:any[])=>{const path=String(args[0]);if(path.startsWith(s.state+"/")&&!path.startsWith(join(s.state,"_audit")+"/")&&path!==join(s.state,"_audit"))throw Object.assign(new Error("synthetic absent"),{code:"ENOENT"});return shape(await (sourceIO.lstat as any)(...args),path);}) as SourceIO["lstat"],open:(async(...args:any[])=>{const path=String(args[0]),fd=await (sourceIO.open as any)(...args);opened++;peak=Math.max(peak,opened-closed);return new Proxy(fd,{get(target,key){if(key==="close")return async()=>{try{await target.close();}finally{closed++;}};if(key==="stat")return async(...options:any[])=>shape(await target.stat(...options),path);if(key==="read"&&sizesByPath.has(path))return async(buffer:Uint8Array,_offset:number,length:number)=>({bytesRead:length,buffer});const value=Reflect.get(target,key);return typeof value==="function"?value.bind(target):value;}});}) as SourceIO["open"]};
  const read=await readSplitSource(s.state,io,signal());expect(opened).toBe(closed);expect(peak).toBeLessThanOrEqual(MAX_SOURCE_HANDLES);return read;
}
it.each([C.MAX_FILE_BYTES,C.MAX_FILE_BYTES+1])("admits source file bytes before allocation at %s",size=>withStore(async s=>{const read=await sizedNativeRead(s,[size]);expect(read.limited).toBe(size>C.MAX_FILE_BYTES);expect(read.bytesRead).toBe(size>C.MAX_FILE_BYTES?0:size);}));
it.each([0,1])("enforces aggregate source bytes with %s extra byte",extra=>withStore(async s=>{const sizes=Array.from({length:C.MAX_PACK_BYTES/C.MAX_FILE_BYTES},()=>C.MAX_FILE_BYTES);if(extra)sizes.push(extra);const read=await sizedNativeRead(s,sizes);expect(read.bytesRead).toBe(C.MAX_PACK_BYTES);expect(read.limited).toBe(extra>0);}));
it("closes every admitted handle when a native read settles after cancellation",()=>withStore(async s=>{
  const controller=new AbortController();let release!:()=>void,admit!:()=>void,reads=0,opened=0,closed=0;
  const waiting=new Promise<void>(resolve=>{release=resolve;}),admitted=new Promise<void>(resolve=>{admit=resolve;});
  const io:SourceIO={...sourceIO,open:(async(...args:Parameters<typeof sourceIO.open>)=>{const fd=await sourceIO.open(...args);opened++;return new Proxy(fd,{get(target,key){if(key==="close")return async()=>{try{await target.close();}finally{closed++;}};if(key==="read")return async(...params:any[])=>{reads++;admit();await waiting;return (target.read as any)(...params);};const value=Reflect.get(target,key);return typeof value==="function"?value.bind(target):value;}});}) as SourceIO["open"]};
  const run=readSplitSource(s.state,io,controller.signal);await admitted;controller.abort();release();await expect(run).rejects.toThrow();expect(reads).toBe(1);expect(opened).toBe(closed);
}));
it("rechecks changed control bytes as well as entry names",()=>withStore(async s=>{const read=await readSplitSource(s.state,sourceIO,signal()),row=read.objects.find(o=>o.kind==="control"&&o.bytes)!;const changed=Buffer.from(row.bytes!);changed[changed.length-1]^=1;await s.storage.write(row.namespace,row.key!,changed);expect(await recheckSplitSource(read,signal())).toBe(false);}));

it("refuses a failed file-shape check during the whole source reread",()=>withStore(async s=>{
  const read=await readSplitSource(s.state,sourceIO,signal()),row=read.objects.find(o=>o.kind==="entry")!;let fresh=false;
  const io:SourceIO={...sourceIO,open:(async(...args:Parameters<typeof sourceIO.open>)=>{if(String(args[0])===s.state)fresh=true;return sourceIO.open(...args);}) as SourceIO["open"],lstat:(async(...args:Parameters<typeof sourceIO.lstat>)=>{const stat=await sourceIO.lstat(...args);return fresh&&String(args[0])===join(s.state,row.namespace,row.rawName)?new Proxy(stat,{get(target,key){if(key==="isFile")return ()=>false;const value=Reflect.get(target,key);return typeof value==="function"?value.bind(target):value;}}):stat;}) as SourceIO["lstat"]};
  await expect(recheckSplitSource({...read,io},signal())).rejects.toMatchObject({code:"source_control_invalid"});
}));

it.each(["read","recheck"] as const)("discards observations after repeated capture changes at %s",stage=>withStore(async s=>{
  let calls=0;const changed=async()=>{calls++;throw new B.SplitError("snapshot_changed");};
  const run=gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,[stage]:changed});
  await expect(run).resolves.toMatchObject({stable:false});const outcome=await run;
  expect(calls).toBe(2);expect(outcome.stable).toBe(false);expect(outcome.projection.read.objects).toEqual([]);expect(outcome.projection.records).toEqual({operator:[],daemon:[]});expect(outcome.validation.issues).toContain("source_changed");
}));

it.each(["boundary","floor","operator-head","daemon-head"])("keeps %s control refusal before exhausted leaf admission",kind=>withStore(async s=>{
 if(kind==="boundary")await writeFile(boundary(s),"{}");
 else if(kind==="floor")await s.storage.write("_meta","transparency-counter-floor-v1",Buffer.from("{}"));
 else await s.storage.write(kind==="operator-head"?"_audit_checkpoints":"_audit-daemon_checkpoints","__signing_head",Buffer.from("{}"));
 const exhausted=()=>{const budget=new B.Budget();budget.charge("leaves",B.MAX_LEAF_VISITS);return budget;};
 await expect(gatherSplitSource(s.state,s.masterKey,()=>undefined,signal(),{...deps,budget:exhausted}),"hard controls precede diagnostics").rejects.toMatchObject({code:kind==="boundary"?"migration_invalid":"source_control_invalid"});
}));


it("boundary decoding equals base",()=>withStore(async s=>{
 const {deriveAuditStoreSplitBoundaryMacKey,validateAuditStoreSplitBoundaryBytes,readAuditStoreSplitBoundary}=await import("../../src/operational/audit-log.js");
 const key=deriveAuditStoreSplitBoundaryMacKey(s.masterKey);
 try {
  const raw=await readFile(boundary(s));
  expect(validateAuditStoreSplitBoundaryBytes(raw,key).status,"ordinary boundary valid").toBe("valid");
  const bom=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),raw]); // UTF-8 encoding of U+FEFF.
  expect(()=>JSON.parse(bom.toString("utf8")),"base decoding rejects BOM").toThrow(SyntaxError);
  expect(validateAuditStoreSplitBoundaryBytes(bom,key),"captured boundary base equality").toEqual({status:"invalid"});
  await writeFile(boundary(s),bom);
  expect(await readAuditStoreSplitBoundary(s.state,key),"filesystem boundary base equality").toEqual({status:"invalid"});
 } finally {key.fill(0);}
}));
