import {createFixtureLockRoot,disposeFixtureLockRoot,daemonStopRegistration} from "./split-statement-lock-root.js";
// Semantic entry witness: imports only modules present at the original base and committed public bytes.
import {describe,expect,it,vi} from "vitest";
import {readFileSync,constants as inventoryFs} from "node:fs";
import {verifySnapshot} from "../../src/evidence-pack/snapshot-verify.js";
const corpus=JSON.parse(readFileSync(new URL("./fixtures/split-statement-static-packs.json",import.meta.url),"utf8"));
const sample=corpus.cases.find((c:any)=>c.name==="complete");
const revision=corpus.provenance.source_base;
const pins={packKey:sample.pins.packKey,descriptorBytes:Buffer.from(sample.pins.descriptor_base64,"base64"),expectedManifestDigest:sample.pins.expectedManifestDigest,format:"SANCTUARY_EVIDENCE_SPLIT_TRUST_V1" as const};
const bytes=Object.entries(sample.files).map(([name,data])=>({name,bytes:Buffer.from(data as string,"base64")}));
const stat=(size:number,type="file")=>({type,size,nlink:1,dev:"1",ino:"1",mtime:"fixed",ctime:"fixed"});
describe("split production entry witness",()=>{
 it("accepts the complete static split statement through the existing verifier",()=>{
   const files=bytes.map(f=>({name:Buffer.from(f.name),bytes:f.bytes,before:stat(f.bytes.length),after:stat(f.bytes.length),metadata:[]}));
   const capture={files,rootBefore:stat(0,"directory"),rootAfter:stat(0,"directory"),finalNames:files.map(f=>f.name),rootMetadata:[]};
   const result=verifySnapshot(capture,pins,revision);
   expect([result.status,result.exit_code,result.accepted]).toEqual(["PASS",0,true]);
 });

});

import {mkdir,mkdtemp,readdir,lstat,unlink,rmdir,writeFile,open as openForInventory} from "node:fs/promises";
import {join,resolve,dirname} from "node:path";
import {FilesystemStorage} from "../../src/storage/filesystem.js";
import {AuditLog,__testSetAuditWriterUidForRole} from "../../src/operational/audit-log.js";
import {IdentityManager} from "../../src/cognitive/tools.js";
import {createIdentity,type StoredIdentity} from "../../src/core/identity.js";
import {derivePurposeKey} from "../../src/core/key-derivation.js";
import {createDaemonAuditLog} from "../../src/operational/audit-store-split.js";
import {TRANSPARENCY_NEVER_ABORTED} from "../../src/transparency/scheduler.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import {disposePhysicalFixture} from "./split-statement-dispose.js";

const splitNativeBoundary=vi.hoisted(()=>({ancestorModes:false,unavailableDirectory:"",ancestorPaths:[] as string[]}));
vi.mock("node:fs/promises",async importOriginal=>{
  const actual=await importOriginal<typeof import("node:fs/promises")>();
  return {...actual,open:async(...args:Parameters<typeof actual.open>)=>{if(splitNativeBoundary.unavailableDirectory===String(args[0]))throw Object.assign(new Error("synthetic native access refusal"),{code:"EACCES"});return actual.open(...args);},lstat:async(...args:Parameters<typeof actual.lstat>)=>{
    const value=await actual.lstat(...args),path=String(args[0]);
    // This same-uid witness simulates safe native ancestor modes only; source bytes and source modes remain real.
    if(value&&splitNativeBoundary.ancestorModes&&splitNativeBoundary.ancestorPaths.includes(path))return Object.assign(Object.create(Object.getPrototypeOf(value)),value,{mode:typeof value.mode==="bigint"?value.mode&~0o020n:value.mode&~0o020});
    return value;
  }};
});
vi.mock("node:fs",async importOriginal=>{
  const actual=await importOriginal<typeof import("node:fs")>();
  return {...actual,lstatSync:(...args:Parameters<typeof actual.lstatSync>)=>{
    const value=actual.lstatSync(...args),path=String(args[0]);
    // Match the asynchronous native ancestry observation without changing filesystem permissions.
    if(value&&splitNativeBoundary.ancestorModes&&splitNativeBoundary.ancestorPaths.includes(path))return Object.assign(Object.create(Object.getPrototypeOf(value)),value,{mode:typeof value.mode==="bigint"?value.mode&~0o020n:value.mode&~0o020});
    return value;
  }};
});
import {Writable} from "node:stream";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {readFile} from "node:fs/promises";
class SplitCaptureStream extends Writable {chunks:string[]=[];override _write(chunk:unknown,_encoding:BufferEncoding,done:(error?:Error|null)=>void){this.chunks.push(String(chunk));done();}}
/** Count the fixture's actual persisted heads, ordinary checkpoints and tail without invoking a writer. */
async function splitFixtureExtent(storage:FilesystemStorage,namespace:string){
  const entries=await storage.list(namespace,"entry-"),checkpoints=await storage.list(namespace+"_checkpoints","audit-checkpoint-");let head=0,covered=0;
  for(const row of entries){const value=JSON.parse(Buffer.from((await storage.read(namespace,row.key))!).toString());head=Math.max(head,value.sequence);}
  for(const row of checkpoints){const value=JSON.parse(Buffer.from((await storage.read(namespace+"_checkpoints",row.key))!).toString());covered=Math.max(covered,value.checkpoint_sequence);}
  return {entries:entries.length,checkpoints:checkpoints.length,head,tail:head-covered};
}
async function splitFixtureByteInventory(root:string){
  const directories=[root],files:Record<string,string>={};
  for(let i=0;i<directories.length;i++)for(const name of await readdir(directories[i])){const path=join(directories[i],name);const handle=await openForInventory(path,inventoryFs.O_RDONLY|inventoryFs.O_NOFOLLOW|inventoryFs.O_NONBLOCK).catch((error:NodeJS.ErrnoException)=>{if(error.code==="ELOOP"||error.code==="ENXIO"||error.code==="EOPNOTSUPP")return null;throw error;});if(!handle)continue;try{const meta=await handle.stat();if(meta.isDirectory())directories.push(path);else if(meta.isFile())files[path.slice(root.length+1)]=createHash("sha256").update(await handle.readFile()).digest("hex");}finally{await handle.close();}} // One no-follow descriptor is both checked and read, so a link or a file swapped in after its check is never hashed; links and sockets are skipped as before.
  return Object.fromEntries(Object.entries(files).sort(([a],[b])=>a<b?-1:1));
}
/** Real custody, migration, writers, scheduled emission, shutdown and registered export; only native startup is replaced. */
export async function wiredSplitFixture(options:{preSplitWindow?:boolean;liveTail?:boolean;emptyPrefix?:boolean;unavailable?:boolean}={}) {
  // CLI module resets require fresh producer brands for each independent fixture lifecycle.
  const {FilesystemStorage}=await import("../../src/storage/filesystem.js"),{AuditLog,__testSetAuditWriterUidForRole}=await import("../../src/operational/audit-log.js"),{IdentityManager}=await import("../../src/cognitive/tools.js"),{createIdentity}=await import("../../src/core/identity.js"),{derivePurposeKey}=await import("../../src/core/key-derivation.js"),{createDaemonAuditLog}=await import("../../src/operational/audit-store-split.js"),{TRANSPARENCY_NEVER_ABORTED}=await import("../../src/transparency/scheduler.js"),{establishMaster}=await import("../../src/core/master-custody.js"),{runDaemon,runProvisionPin,createTransparencyDaemonScheduledEmit}=await import("../../src/cli/castle-wall.js");

  const assigned=resolve(import.meta.dirname,"../../../"),scratch=join(assigned,".scratch");await mkdir(scratch,{recursive:true});
  const lockRoot=await createFixtureLockRoot(assigned);
  // Socket rendezvous alone uses a fit-checked /tmp root; every work artifact stays under repository scratch.
  const root=await mkdtemp(join(scratch,"wired-split-")),fortress=join(root,"fortress"),state=join(fortress,"state"),storage=new FilesystemStorage(state),passphrase="synthetic-split-fixture-passphrase";
  const envNames=["SANCTUARY_CUSTODY_LOCK_ROOT","SANCTUARY_STORAGE_PATH","SANCTUARY_FORTRESS_PATH","SANCTUARY_PASSPHRASE","SANCTUARY_CASTLE_LOCAL_SIGN","SANCTUARY_DASHBOARD_ENABLED","SANCTUARY_DASHBOARD_AUTO_OPEN","SANCTUARY_NO_UPDATE_CHECK"] as const;
  splitNativeBoundary.ancestorPaths=[];for(let path=assigned;path!==dirname(path);path=dirname(path))splitNativeBoundary.ancestorPaths.push(path);
  splitNativeBoundary.ancestorModes=true;
  const oldEnv=Object.fromEntries(envNames.map(name=>[name,process.env[name]]));
  Object.assign(process.env,{SANCTUARY_CUSTODY_LOCK_ROOT:lockRoot,SANCTUARY_STORAGE_PATH:fortress,SANCTUARY_FORTRESS_PATH:fortress,SANCTUARY_PASSPHRASE:passphrase,SANCTUARY_CASTLE_LOCAL_SIGN:"1",SANCTUARY_DASHBOARD_ENABLED:"false",SANCTUARY_DASHBOARD_AUTO_OPEN:"false",SANCTUARY_NO_UPDATE_CHECK:"1"});
  let masterKey:Uint8Array|undefined,lease:Awaited<ReturnType<typeof establishMaster>>["masterWriteBarrier"],stopCalls=0;
  const observed:Record<string,any>={},out=new SplitCaptureStream(),err=new SplitCaptureStream();
  const cleanup=async()=>{
    splitNativeBoundary.unavailableDirectory="";
    try {
      try {await lease?.release();} finally {lease=undefined;masterKey?.fill(0);}
      try {await disposePhysicalFixture(root);} finally {await disposeFixtureLockRoot(lockRoot);}
    } finally {
      splitNativeBoundary.ancestorModes=false;splitNativeBoundary.ancestorPaths=[];
      for(const name of envNames){if(oldEnv[name]===undefined)delete process.env[name];else process.env[name]=oldEnv[name];}
    }
  };
  try {
    const custody=await establishMaster({storage,passphrase,firstRun:{installMode:"headless",mintRecoveryKey:false},storagePathHint:fortress});masterKey=custody.masterKey;lease=custody.masterWriteBarrier;
    const identityKey=derivePurposeKey(masterKey,"identity-encryption"),manager=new IdentityManager(storage,masterKey);let signer:StoredIdentity;
    try{signer=createIdentity("Synthetic wired split operator",identityKey,"passphrase").storedIdentity;}finally{identityKey.fill(0);}
    await manager.saveNew(signer);await manager.setPrimary(signer.identity_id);
    const operator=new AuditLog(storage,masterKey);
    // Three prefix entries make the pre-split window visibly larger than the daemon's fresh sequence space.
    if(!options.emptyPrefix)for(let i=0;i<3;i++)await operator.appendCritical({layer:"l1",operation:"synthetic prefix",identity_id:signer.identity_id,result:"success"});await operator.flush();
    const fixtureEnv={...process.env,SANCTUARY_TRANSPARENCY_INTERVAL:"off"},globalPin=join(fortress,"absent-global-pin.bin");
    const pinCode=await runProvisionPin([],{out,err,env:fixtureEnv,globalPinnedPublicKeyPath:globalPin});if(pinCode!==0)throw new Error("synthetic pin provisioning failed");
    const rules=join(fortress,"policy","egress","rules");await mkdir(rules,{recursive:true});await writeFile(join(rules,"synthetic.json"),JSON.stringify({rule_id:"synthetic",host:"synthetic.invalid"}));
    const binary=join(fortress,"synthetic-binary");await writeFile(binary,"synthetic fixture native boundary");
    if(options.preSplitWindow){await createTransparencyDaemonScheduledEmit({storage,auditLog:operator,storagePath:fortress,masterKey,env:fixtureEnv,signer:{kind:"local"},globalPinnedPublicKeyPath:globalPin,binaryPath:binary,version:"synthetic",out,err})(TRANSPARENCY_NEVER_ABORTED);await operator.flush();}
    // Readiness follows the actual signal registration; no timing assumption enters the witness.
    const registration=daemonStopRegistration();
    __testSetAuditWriterUidForRole("root_daemon",0);
    const running=runDaemon([],{out,err,platform:"darwin",getuid:()=>0,env:fixtureEnv,globalPinnedPublicKeyPath:globalPin,fullDaemonStart:async input=>{
      await input.auditLog.appendCritical({layer:"l1",operation:"synthetic daemon",identity_id:signer.identity_id,result:"success"});
      await createTransparencyDaemonScheduledEmit({storage,auditLog:input.auditLog,storagePath:fortress,masterKey:input.masterKey,env:fixtureEnv,signer:{kind:"local"},globalPinnedPublicKeyPath:globalPin,binaryPath:binary,version:"synthetic",out,err})(TRANSPARENCY_NEVER_ABORTED);
      observed.daemonBeforeStop=await splitFixtureExtent(storage,"_audit-daemon");
      return {socketPath:join(fortress,"synthetic-native.sock"),stop:async()=>{stopCalls++;await input.auditLog.flush();}};
    }});
    let stop:(()=>void)|undefined;
    try {
      stop=await Promise.race([registration.registered,running.then(code=>{throw new Error("synthetic daemon stopped before readiness: "+code);})]);
      stop();const code=await running;if(code!==0)throw new Error("synthetic daemon normal shutdown failed");
      observed.daemonAfterStop=await splitFixtureExtent(storage,"_audit-daemon");
      if(options.liveTail){await createDaemonAuditLog(storage,masterKey).appendCritical({layer:"l1",operation:"synthetic resumed writer",identity_id:signer.identity_id,result:"success"});observed.liveTail=await splitFixtureExtent(storage,"_audit-daemon");}
    } finally {registration.close();stop?.();await running;__testSetAuditWriterUidForRole("root_daemon",undefined);}
    await lease?.release();lease=undefined;
    observed.stopCalls=stopCalls;observed.operatorBeforeBoot=await splitFixtureExtent(storage,"_audit");
    const revision=process.env.SANCTUARY_SPLIT_WITNESS_REVISION??execFileSync("git",["rev-parse","HEAD"],{cwd:resolve(import.meta.dirname,"../../../"),encoding:"utf8"}).trim();
    vi.stubGlobal("__SANCTUARY_SOURCE_SHA__",revision);vi.resetModules();
    const entry=await import("../../src/evidence-pack/snapshot-export-cli.js"),phase=entry.exportDependencies.phase;
    entry.exportDependencies.phase=async(stateName,stage)=>{await phase(stateName,stage);if(stateName==="CENSUS"&&options.unavailable)splitNativeBoundary.unavailableDirectory=join(state,"_audit-daemon");if(stateName==="QUIESCE_EXPORT_INSTANCE")observed.operatorBeforeCleanup=await splitFixtureExtent(storage,"_audit");if(stateName==="CENSUS"&&!options.unavailable)observed.beforeCensus=await splitFixtureByteInventory(state);if(stateName==="BUILD"&&!options.unavailable)observed.afterRecheck=await splitFixtureByteInventory(state);};
    const argv=process.argv,stdout:string[]=[],exits:number[]=[],output=join(root,"pack"),receipt=join(root,"receipt.json"),publicKeyFile=join(root,"pack-key.txt");
    const stdoutSpy=vi.spyOn(process.stdout,"write").mockImplementation(((text:string,callback?:(error?:Error)=>void)=>{stdout.push(String(text));callback?.();return true;}) as never),exitSpy=vi.spyOn(process,"exit").mockImplementation(((code:number)=>{exits.push(code);}) as never);
    process.argv=[process.execPath,resolve(import.meta.dirname,"../../src/cli.ts"),"export-evidence","--fortress",fortress,"--output",output,"--receipt",receipt,"--public-key-file",publicKeyFile];
    try{await(await import("../../src/cli.js")).cliEntryInvocation;}finally{process.argv=argv;stdoutSpy.mockRestore();exitSpy.mockRestore();entry.exportDependencies.phase=phase;vi.unstubAllGlobals();}
    const receiptBytes=await readFile(receipt),trust=await readFile(join(output,C.TRUST_FILENAME));
    observed.operatorAfterCapture=await splitFixtureExtent(storage,"_audit");
    return {root,fortress,state,storage,signer,revision,exits,stdout,observed,output,receipt,receiptBytes,trust,publicKeyFile,cleanup};
  } catch(error){__testSetAuditWriterUidForRole("root_daemon",undefined);await cleanup();throw error;}
}

it("exports real split storage through the existing registered command",async()=>{
  const x=await wiredSplitFixture();try{
    expect(x.exits).toEqual([0]);
    const manifest=JSON.parse(await readFile(join(x.output,C.MANIFEST_FILENAME),"utf8"));
    const expected=JSON.parse(Buffer.from(sample.files[C.MANIFEST_FILENAME],"base64").toString());
    expect([manifest.format,manifest.contract,manifest.topology]).toEqual([expected.format,expected.contract,expected.topology]);
  }finally{await x.cleanup();}
},120_000); // Real custody and boot have a bounded two-minute fixture allowance.
