// fail-before-exempt: imports audit/split-evidence-source.js and split-statement-census.js, which base lacks and cannot collect.
import {expect,it} from "vitest";
import {mkdir,writeFile,readFile,symlink,realpath,rename,cp} from "node:fs/promises";
import {join,basename} from "node:path";
import {physicalSplitFixture,splitFixtureByteInventory} from "./split-statement-fixtures.js";
import {seedExportFortress,identity,SOURCE} from "./snapshot-fixtures.js";
import {sourceIO,SOURCE_ATTEMPTS,type SourceIO} from "../../src/audit/split-evidence-source.js";
import {CHAIN_NAMESPACES,BOUNDARY,META_CONTROLS} from "../../src/audit/split-evidence-registry.js";
import {gatherExportStatement,exportSnapshot,exportDependencies} from "../../src/evidence-pack/snapshot-export-cli.js";
import {classifySplitTopology} from "../../src/evidence-pack/split-statement-census.js";
import {gatherSnapshot} from "../../src/evidence-pack/snapshot-gather.js";
import {captureSnapshotDirectory} from "../../src/evidence-pack/snapshot-trust-cli.js";
import {verifySnapshot} from "../../src/evidence-pack/snapshot-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
const signal=()=>new AbortController().signal;
const absent=()=>Object.assign(new Error("synthetic absent"),{code:"ENOENT"});
type Store=Awaited<ReturnType<typeof physicalSplitFixture>>&{fortress:string;seams:Map<string,number>};
async function withStore(run:(s:Store)=>Promise<void>,split=false){const fixture=await physicalSplitFixture(split);try{const fortress=join(fixture.root,"alias");await symlink(fixture.root,fortress);const s:Store={...fixture,fortress,root:await realpath(fortress),state:await realpath(join(fortress,"state")),seams:new Map()};await run(s);for(const [name,hits] of s.seams)expect(hits,`${name} seam engaged`).toBeGreaterThan(0);}finally{await fixture.cleanup();}}
function seam(s:Store,name:string){s.seams.set(name,0);return ()=>{s.seams.set(name,s.seams.get(name)!+1);};}

function input(s:Store,io:SourceIO){return {storage:s.storage,masterKey:s.masterKey,fortress:s.fortress,generatedAt:"2026-01-01T00:00:00.000Z",localSign:false,source:{...exportDependencies.source,io},classify:exportDependencies.classify,resolvePin:exportDependencies.resolvePin,signal:signal(),identities:[],phase:async()=>{},quiesce:async()=>{throw new Error("V0 lifecycle");}};}
it("retains V0 during selector writes",()=>withStore(async s=>{
 await mkdir(join(s.state,CHAIN_NAMESPACES.operator.meta),{recursive:true});let writes=0;const engaged=seam(s,"selector writes");
 const io:SourceIO={...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
   const dir=await sourceIO.opendir(...args);
   if(String(args[0])!==join(s.state,CHAIN_NAMESPACES.operator.meta))return dir;engaged();
   return {async *[Symbol.asyncIterator](){for await(const entry of dir)yield entry;
     writes++;await writeFile(join(s.state,CHAIN_NAMESPACES.operator.entries,`.synthetic-${writes}`),"synthetic");await writeFile(join(s.state,CHAIN_NAMESPACES.operator.meta,`synthetic-${writes}`),"synthetic");
   }};
 }) as SourceIO["opendir"]};
 const expected=await gatherSnapshot(input(s,sourceIO));
 await expect(gatherExportStatement(input(s,io)),"writer production V0 equals base gather").resolves.toEqual(expected);
 expect(writes,"exactly one selector retry").toBe(SOURCE_ATTEMPTS);
}));
it("retains V0 above the chain inventory bound",()=>withStore(async s=>{
 const chains=[CHAIN_NAMESPACES.operator.entries,CHAIN_NAMESPACES.operator.checkpoints,"_transparency_checkpoints","_audit_integrity_alert"];
 let reads=0,visited=0;
 const io:SourceIO={...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
   if(chains.includes(basename(String(args[0])))){reads++;return {async *[Symbol.asyncIterator](){for(let i=0;i<=B.MAX_SOURCE_OBJECTS;i++){visited++;yield {name:Buffer.from(`entry-${i}.enc`)};}}};}
   return sourceIO.opendir(...args);
 }) as SourceIO["opendir"]};
 await expect(gatherExportStatement(input(s,io)),"large production V0 equals base gather").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
 expect(reads,"CLASSIFY chain reads").toBe(0);expect(visited,"CLASSIFY chain names").toBe(0);
}));
it.each(["notes!.txt","lost+found","Icon\r"])("retains V0 with unrelated root name %j",name=>withStore(async s=>{
 if(name==="lost+found")await mkdir(join(s.state,name));else await writeFile(join(s.state,name),"synthetic");
 await expect(gatherExportStatement(input(s,sourceIO)),"root name production V0 equals base gather").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
}));
it.each(["incomplete","unstable"])("retains V0 split refusal after %s selection",schedule=>withStore(async s=>{
 let attempts=0,accessErrors=0;const hiddenProbe=seam(s,"hidden fixed probe"),hiddenMeta=schedule==="unstable"?seam(s,"hidden marker listing"):()=>{},hiddenRoot=seam(s,"hidden root listing");
 const hidden=new Set<string>([BOUNDARY.namespace,...Object.values(CHAIN_NAMESPACES.daemon)]);
 const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<SourceIO["lstat"]>)=>{if(String(args[0]).startsWith(join(s.state,BOUNDARY.namespace))||String(args[0])===join(s.state,CHAIN_NAMESPACES.operator.meta,META_CONTROLS[2]+".enc")||hidden.has(basename(String(args[0])))){hiddenProbe();throw absent();}return sourceIO.lstat(...args);}) as SourceIO["lstat"],open:async(...args)=>{
   const path=String(args[0]);if(schedule==="incomplete"&&path===join(s.state,CHAIN_NAMESPACES.operator.meta)){accessErrors++;throw Object.assign(new Error("synthetic observation"),{code:"EACCES"});}
   if(hidden.has(basename(path)))throw absent();return sourceIO.open(...args);
 },opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
   const dir=await sourceIO.opendir(...args);
   if(String(args[0])===join(s.state,CHAIN_NAMESPACES.operator.meta)){hiddenMeta();return {async *[Symbol.asyncIterator](){for await(const entry of dir)if(String(entry.name)!==META_CONTROLS[2]+".enc")yield entry;}};}
   if(String(args[0])!==s.state)return dir;hiddenRoot();attempts++;
   return {async *[Symbol.asyncIterator](){for await(const entry of dir)if(!hidden.has(String(entry.name)))yield entry;
     if(schedule==="unstable")await writeFile(join(s.state,`synthetic-${attempts}`),"synthetic");
   }};
 }) as SourceIO["opendir"]};
 const expected=await gatherSnapshot(input(s,sourceIO));
 await expect(gatherExportStatement(input(s,io)),"hidden split production V0 equals base gather").resolves.toEqual(expected);
 expect(expected.audit,"base split probe").toEqual({state:"read_failed",reason:"split_store"});
 expect(attempts,"hidden split retry").toBe(SOURCE_ATTEMPTS);
 expect(accessErrors,"independent selector schedule").toBe(schedule==="incomplete"?SOURCE_ATTEMPTS:0);
 const signer=identity(),options={fortress:await realpath(s.fortress),output:join(s.root,"pack"),receipt:join(s.root,"receipt.json"),publicKeyFile:join(s.root,"key.txt")};
 await seedExportFortress(options.fortress);
 const deps={...exportDependencies,source:{...exportDependencies.source,io},runtimeRevision:SOURCE,buildRevision:SOURCE,boot:async()=>({config:{storage_path:options.fortress},masterKey:s.masterKey,identityManager:{getDefault:()=>signer,list:()=>[signer],get:()=>signer},cleanup:async()=>{}}),io:{stdout:()=>{},stderr:()=>{}}};
 expect(await exportSnapshot(options,deps as unknown as typeof exportDependencies),"hidden split export PARTIAL").toBe(C.EXIT_PARTIAL);
 const receipt=JSON.parse(await readFile(options.receipt,"utf8"));
 const pins={packKey:signer.public_key,descriptorBytes:await readFile(join(options.output,C.TRUST_FILENAME)),expectedManifestDigest:receipt.manifest_digest};
 pins.expectedManifestDigest=C.manifestDigest(await readFile(join(options.output,C.MANIFEST_FILENAME)));
 const result=verifySnapshot(await captureSnapshotDirectory(options.output,pins.packKey,pins.expectedManifestDigest),pins,SOURCE);
 expect([result.status,result.accepted],"hidden split never accepted").toEqual([C.STATUS.PARTIAL,false]);
 expect(JSON.parse(await readFile(join(options.output,C.MANIFEST_FILENAME),"utf8")).components.audit,"delivered split reason").toEqual({state:"read_failed",reason:"split_store"});
},true));
it.each(["_audit_unknown","_audit!.txt"])("retains topology doubt for %s",name=>withStore(async s=>{
 await writeFile(join(s.state,name),"synthetic");await expect(gatherExportStatement(input(s,sourceIO)),"audit root doubt").rejects.toMatchObject({code:"topology_ambiguous"});
}));
it("retains root access doubt",()=>withStore(async s=>{
 const engaged=seam(s,"root access fault");
 const io:SourceIO={...sourceIO,opendir:async(...args)=>{if(String(args[0])===s.state){engaged();throw Object.assign(new Error("synthetic"),{code:"EACCES"});}return sourceIO.opendir(...args);}};
 await expect(gatherExportStatement(input(s,io)),"root access doubt").rejects.toMatchObject({code:"topology_ambiguous"});
}));

import {splitExportFixture} from "./split-statement-fixtures.js";
it("gathers a split source through its resolved ancestor",async()=>{
 const s=await splitExportFixture();try{
  const alias=join(s.root,"alias");await symlink(s.fortress,alias);
  const gathering=gatherExportStatement({storage:s.storage,masterKey:s.masterKey,fortress:alias,generatedAt:"2026-01-01T00:00:00.000Z",localSign:true,source:s.deps.source,classify:s.deps.classify,resolvePin:s.deps.resolvePin,signal:signal(),identities:[s.signer],phase:async()=>{},quiesce:async()=>{await s.operator.flush();}});
  await expect(gathering,"resolved split gather").resolves.toMatchObject({kind:"split",gathered:{stable:true}});
  const gathered=await gathering;
  expect("kind" in gathered&&gathered.gathered.stable,"resolved split source is stable").toBe(true);
  expect("kind" in gathered&&gathered.gathered.projection.read.root,"READ uses CLASSIFY root").toBe(await realpath(s.state));
  expect("kind" in gathered&&gathered.gathered.validation.migration.state,"resolved split controls checked").toBe("operator_checked");
 }finally{await s.cleanup();}
});
it("rechecks the selected split root identity",()=>withStore(async s=>{
 const gathering=gatherExportStatement({...input(s,sourceIO),quiesce:async()=>{
  const before=await splitFixtureByteInventory(s.state);await rename(s.state,s.state+"-prior");await cp(s.state+"-prior",s.state,{recursive:true});
  expect(await splitFixtureByteInventory(s.state),"replacement source bytes equal").toEqual(before);
 }});
 await expect(gathering,"selected root replacement refuses").rejects.toMatchObject({code:"snapshot_changed"});
},true));

it("retains V0 for an absent state root",()=>withStore(async s=>{
 s.fortress=s.root;await rename(s.state,s.state+"-prior");let rootObservations=0;
 const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<SourceIO["lstat"]>)=>{if(String(args[0])===s.state)rootObservations++;return sourceIO.lstat(...args);}) as SourceIO["lstat"]};
 await expect(gatherExportStatement(input(s,io)),"absent root production V0 equals base gather").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
 expect(rootObservations,"absent root retries once").toBe(SOURCE_ATTEMPTS*2); // Ancestor and directory observation per attempt.
}));

it("retains V0 after incomplete ancestor observations",()=>withStore(async s=>{
 const engaged=seam(s,"ancestor access fault");
 const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<SourceIO["lstat"]>)=>{if(String(args[0])===s.root){engaged();throw Object.assign(new Error("synthetic ancestor observation"),{code:"EACCES"});}return sourceIO.lstat(...args);}) as SourceIO["lstat"]};
 await expect(gatherExportStatement(input(s,io)),"ancestor production V0 equals base gather").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
}));
it("retains positive daemon directory observations",()=>withStore(async s=>{
 await mkdir(join(s.state,CHAIN_NAMESPACES.daemon.entries));const engaged=seam(s,"hidden daemon listing");
 const io:SourceIO={...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
  const dir=await sourceIO.opendir(...args);if(String(args[0])!==s.state)return dir;engaged();
  return {async *[Symbol.asyncIterator](){for await(const entry of dir)if(String(entry.name)!==CHAIN_NAMESPACES.daemon.entries)yield entry;}};
 }) as SourceIO["opendir"]};
 await expect(classifySplitTopology(s.state,io,signal()),"observed directory selects split").resolves.toMatchObject({topology:"split"});
}));
