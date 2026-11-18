// fail-before-exempt: imports audit/split-evidence-source.js, which base lacks and cannot collect.
import {expect,it} from "vitest";
import {mkdir,writeFile,readFile,realpath,symlink} from "node:fs/promises";
import {join} from "node:path";
import {physicalSplitFixture} from "./split-statement-fixtures.js";
import {identity,SOURCE} from "./snapshot-fixtures.js";
import {sourceIO,type SourceIO} from "../../src/audit/split-evidence-source.js";
import {CHAIN_NAMESPACES,BOUNDARY,META_CONTROLS} from "../../src/audit/split-evidence-registry.js";
import {gatherExportStatement,exportSnapshot,exportDependencies} from "../../src/evidence-pack/snapshot-export-cli.js";
import {gatherSnapshot} from "../../src/evidence-pack/snapshot-gather.js";
import {captureSnapshotDirectory} from "../../src/evidence-pack/snapshot-trust-cli.js";
import {verifySnapshotByFormat} from "../../src/evidence-pack/snapshot-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
const junkNames={long:Buffer.from("x".repeat(C.MAX_NAME_BYTES+1)),bytes:Buffer.from([0xff])};
type Store=Awaited<ReturnType<typeof physicalSplitFixture>>&{fortress:string;seams:Map<string,number>};
async function withStore(run:(s:Store)=>Promise<void>,split=false){const fixture=await physicalSplitFixture(split);try{const fortress=join(fixture.root,"alias");await symlink(fixture.root,fortress);const s:Store={...fixture,fortress,root:await realpath(fortress),state:await realpath(join(fortress,"state")),seams:new Map()};await run(s);for(const [name,hits] of s.seams)expect(hits,`${name} seam engaged`).toBeGreaterThan(0);}finally{await fixture.cleanup();}}
function seam(s:Store,name:string){s.seams.set(name,0);return ()=>{s.seams.set(name,s.seams.get(name)!+1);};}

function orderedIO(s:Store,junk:Buffer,first:boolean):SourceIO {
 const engaged=seam(s,`root order ${first}`);
 return {...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
  const dir=await sourceIO.opendir(...args);if(String(args[0])!==s.state)return dir;engaged();
  return {async *[Symbol.asyncIterator](){const entries=[];for await(const entry of dir)entries.push(entry);if(junk.equals(junkNames.bytes))entries.push({name:junk} as never);entries.sort((a,b)=>Buffer.compare(a.name as unknown as Buffer,b.name as unknown as Buffer));const special=entries.filter(e=>Buffer.from(e.name).equals(junk)),rest=entries.filter(e=>!Buffer.from(e.name).equals(junk));for(const entry of first?[...special,...rest]:[...rest,...special])yield entry;}};
 }) as SourceIO["opendir"]};
}
async function addJunk(s:Store,junk:Buffer){if(!junk.equals(junkNames.bytes))await writeFile(join(s.state,junk.toString("utf8")),"synthetic");}
function input(s:Store,io:SourceIO){return {storage:s.storage,masterKey:s.masterKey,fortress:s.fortress,generatedAt:"2026-01-01T00:00:00.000Z",localSign:false,source:{...exportDependencies.source,io},classify:exportDependencies.classify,resolvePin:exportDependencies.resolvePin,signal:new AbortController().signal,identities:[],phase:async()=>{},quiesce:async()=>{}};}
async function summary(s:Store,io:SourceIO){try{const g=await gatherExportStatement(input(s,io));return "kind" in g?{kind:g.kind,stable:g.gathered.stable}: {kind:"v0"};}catch(error){return {code:(error as B.SplitError).code};}}
it.each(Object.entries(junkNames))("unsplit root %s",(label,junk)=>withStore(async s=>{
 await addJunk(s,junk);
 for(const first of [true,false])await expect(gatherExportStatement(input(s,orderedIO(s,junk,first))),"unrelated base equality").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
}));
it.each(Object.entries(junkNames))("split root %s",(label,junk)=>withStore(async s=>{
 await addJunk(s,junk);
 for(const first of [true,false])expect(await summary(s,orderedIO(s,junk,first)),"unrelated split census").toEqual({kind:"split",stable:true});
},true));
it.each(Object.entries(junkNames).flatMap(([label,junk])=>["empty","checkpoint"].map(shape=>({label,junk,shape}))))("selector order $label $shape",({junk,shape})=>withStore(async s=>{
 for(const namespace of Object.values(CHAIN_NAMESPACES.daemon))await mkdir(join(s.state,namespace));
 if(shape==="checkpoint"){const [checkpoint]=await s.storage.list(CHAIN_NAMESPACES.operator.checkpoints,"audit-checkpoint-");await s.storage.write(CHAIN_NAMESPACES.daemon.checkpoints,checkpoint.key,(await s.storage.read(checkpoint.namespace,checkpoint.key))!);}
 await addJunk(s,junk);const results=[];
 for(const first of [true,false]){
  const io=orderedIO(s,junk,first),gathered=await summary(s,io);
  expect(gathered,"daemon fixed selection").toEqual(shape==="empty"?{kind:"split",stable:true}:{code:"source_control_invalid"});
  const signer=identity(),options={fortress:s.fortress,output:join(s.root,`pack-${first}`),receipt:join(s.root,`receipt-${first}.json`),publicKeyFile:join(s.root,`key-${first}.txt`)};
  const deps={...exportDependencies,source:{...exportDependencies.source,io},runtimeRevision:SOURCE,buildRevision:SOURCE,boot:async()=>({config:{storage_path:s.fortress},masterKey:s.masterKey,identityManager:{getDefault:()=>signer,list:()=>[signer],get:()=>signer},cleanup:async()=>{}}),io:{stdout:()=>{},stderr:()=>{}}};
  const code=await exportSnapshot(options,deps as unknown as typeof exportDependencies);results.push({gathered,code});
  expect(code,"daemon export never PASS").not.toBe(C.EXIT_PASS);
  if(code===C.EXIT_PARTIAL){const pins={packKey:signer.public_key,descriptorBytes:await readFile(join(options.output,C.TRUST_FILENAME)),expectedManifestDigest:C.manifestDigest(await readFile(join(options.output,C.MANIFEST_FILENAME)))};const result=verifySnapshotByFormat(await captureSnapshotDirectory(options.output,pins.packKey,pins.expectedManifestDigest),pins,SOURCE);expect([result.status,result.accepted],"daemon recipient never accepted").toEqual(["PARTIAL",false]);}
 }
 expect(results[0],"order equality").toEqual(results[1]);
}));
it("later audit root doubt",()=>withStore(async s=>{
 const junk=junkNames.long;await addJunk(s,junk);await mkdir(join(s.state,"_audit_x"));
 await expect(gatherExportStatement(input(s,orderedIO(s,junk,true))),"later topology refusal").rejects.toMatchObject({code:"topology_ambiguous"});
}));
it.each(["long","bytes","budget"])("audit root bound %s",kind=>withStore(async s=>{
 const engaged=seam(s,"root bound");
 const io:SourceIO={...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{if(String(args[0])!==s.state)return sourceIO.opendir(...args);engaged();return {async *[Symbol.asyncIterator](){if(kind==="budget"){for(let i=0;i<=B.MAX_SOURCE_OBJECTS;i++)yield {name:Buffer.from(CHAIN_NAMESPACES.operator.entries)};}else yield {name:Buffer.concat([Buffer.from("_audit"),junkNames[kind as keyof typeof junkNames]])};}};}) as SourceIO["opendir"]};
 await expect(gatherExportStatement(input(s,io)),"audit bound topology refusal").rejects.toMatchObject({code:"topology_ambiguous"});
}));
const selectors=[...Object.values(CHAIN_NAMESPACES.daemon),join(BOUNDARY.namespace,BOUNDARY.name),join(CHAIN_NAMESPACES.operator.meta,META_CONTROLS[2]+".enc"),BOUNDARY.namespace];
it.each(selectors)("fixed access %s",selector=>withStore(async s=>{
 const engaged=seam(s,"fixed access fault");
 const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<SourceIO["lstat"]>)=>{if(String(args[0])===join(s.state,selector)){engaged();throw Object.assign(new Error("synthetic"),{code:"EACCES"});}return sourceIO.lstat(...args);}) as SourceIO["lstat"]};
 await expect(gatherExportStatement(input(s,io)),"fixed access refusal").rejects.toMatchObject({code:"topology_ambiguous"});
}));
it("fixed probes after a listing stop",()=>withStore(async s=>{
 const seen=new Set<string>(),engaged=seam(s,"stopped root listing");
 const io:SourceIO={...sourceIO,lstat:(async(...args:Parameters<SourceIO["lstat"]>)=>{seen.add(String(args[0]));return sourceIO.lstat(...args);}) as SourceIO["lstat"],opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{if(String(args[0])!==s.state)return sourceIO.opendir(...args);engaged();return {async *[Symbol.asyncIterator](){yield {name:Buffer.from("_audit"+"x".repeat(C.MAX_NAME_BYTES))};}};}) as SourceIO["opendir"]};
 await expect(gatherExportStatement(input(s,io)),"stopped listing refuses").rejects.toMatchObject({code:"topology_ambiguous"});
 expect(selectors.every(selector=>seen.has(join(s.state,selector))),"every fixed probe runs").toBe(true);
}));

it("fixed selector authority",()=>withStore(async s=>{
 const engaged=seam(s,"phantom root listing");
 const io:SourceIO={...sourceIO,opendir:(async(...args:Parameters<SourceIO["opendir"]>)=>{
  const dir=await sourceIO.opendir(...args);if(String(args[0])!==s.state)return dir;engaged();
  return {async *[Symbol.asyncIterator](){for await(const entry of dir)yield entry;yield {name:Buffer.from(CHAIN_NAMESPACES.daemon.entries)};}};
 }) as SourceIO["opendir"]};
 await expect(gatherExportStatement(input(s,io)),"fixed observation base equality").resolves.toEqual(await gatherSnapshot(input(s,sourceIO)));
}));

it.each(["empty daemon directories","boundary file","established marker"])("selects split from fixed evidence: %s",shape=>withStore(async s=>{
 if(shape==="empty daemon directories"){
  for(const namespace of Object.values(CHAIN_NAMESPACES.daemon))await mkdir(join(s.state,namespace));
  await mkdir(join(s.state,CHAIN_NAMESPACES.operator.meta),{recursive:true});
  await writeFile(join(s.state,CHAIN_NAMESPACES.operator.meta,junkNames.long.toString("utf8")),"synthetic");
 }else if(shape==="boundary file"){
  await mkdir(join(s.state,BOUNDARY.namespace));await writeFile(join(s.state,BOUNDARY.namespace,BOUNDARY.name),"{}");
 }else await s.storage.write(CHAIN_NAMESPACES.operator.meta,META_CONTROLS[2],Buffer.from("synthetic"));
 const phases:string[]=[];
 // The production split lifecycle starts before census can refuse incomplete evidence.
 await gatherExportStatement({...input(s,sourceIO),phase:async state=>{phases.push(state);}}).catch(error=>{expect(error).toBeInstanceOf(B.SplitError);});
 expect(phases,"fixed evidence selects split").toContain("CLASSIFY");
 const signer=identity(),options={fortress:s.fortress,output:join(s.root,"pack"),receipt:join(s.root,"receipt.json"),publicKeyFile:join(s.root,"key.txt")},exportPhases:string[]=[];
 const deps={...exportDependencies,runtimeRevision:SOURCE,buildRevision:SOURCE,phase:async(state:string)=>{exportPhases.push(state);},boot:async()=>({config:{storage_path:s.fortress},masterKey:s.masterKey,identityManager:{getDefault:()=>signer,list:()=>[signer],get:()=>signer},cleanup:async()=>{}}),io:{stdout:()=>{},stderr:()=>{}}};
 const code=await exportSnapshot(options,deps as unknown as typeof exportDependencies);
 expect(exportPhases,"fixed evidence export selects split").toContain("CLASSIFY");
 // Each shape lacks the migration evidence a split census requires, so the gather refuses before stage or commit.
 expect(code,"fixed evidence export refuses").toBe(C.EXIT_FAIL);
 // A refusal exit does not by itself prove no pack was committed, so any delivered manifest is verified as a recipient would.
 const delivered=await readFile(join(options.output,C.MANIFEST_FILENAME)).then(()=>true,(error:NodeJS.ErrnoException)=>{expect(error.code,"fixed evidence refusal delivers no manifest").toBe("ENOENT");return false;});
 if(delivered){
  // A pack the recipient tooling cannot even capture is not accepted; only an accepted verdict fails here.
  const accepted=await (async()=>{
   const pins={packKey:signer.public_key,descriptorBytes:await readFile(join(options.output,C.TRUST_FILENAME)),expectedManifestDigest:C.manifestDigest(await readFile(join(options.output,C.MANIFEST_FILENAME)))};
   return verifySnapshotByFormat(await captureSnapshotDirectory(options.output,pins.packKey,pins.expectedManifestDigest),pins,SOURCE).accepted;
  })().catch(()=>false);
  expect(accepted,"fixed evidence recipient never accepted").toBe(false);
 }
}));
