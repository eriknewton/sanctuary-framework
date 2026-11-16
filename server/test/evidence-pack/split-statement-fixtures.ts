import {createFixtureLockRoot,disposeFixtureLockRoot,daemonStopRegistration} from "./split-statement-lock-root.js";
/** Synthetic evidence-pack inputs and task-owned production fixtures; no host bytes are used. */
import { computeAuditEntryHash, computeAuditRoot, checkpointSigningBytes } from "../../src/audit/chain.js";
import { AUDIT_CHAIN_SCHEMA_VERSION } from "../../src/audit/checkpoint-shape.js";
import type { EntryExportRecord, CheckpointExportRecord } from "../../src/cli/audit-chain-verify.js";
import { checkpointPayloadOf, computeCheckpointHash } from "../../src/transparency/checkpoint.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { fixture, NOW, signBytes, resignTransparency, syncAudit, syncTransparency } from "./snapshot-fixtures.js";

// First observation's counts are a fixture shape, never captured evidence or a golden.
export const UNSPLIT_SHAPE = {
  lowest: 174935,
  entries: 26199,
  signed: 5323,
  unsigned: 27,
  tail: 2,
  windows: [[1, 11546], [1, 23148], [21150, 61995]],
} as const;

/** Build disposable public records for V0 consumers without storage or credential access. */
export function syntheticPrunedUnsplitFixture() {
  const f = fixture();
  const entries: EntryExportRecord[] = [];
  let previous = C.sha256Hex(C.utf8("synthetic retained predecessor"));
  for (let offset = 0; offset < UNSPLIT_SHAPE.entries; offset++) {
    const entry: EntryExportRecord = {
      type: "entry", seq: UNSPLIT_SHAPE.lowest + offset, schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
      prev_hash: previous, entry_hash: "", timestamp: NOW,
      encrypted_payload_bytes: Buffer.from(`synthetic ciphertext ${offset}`).toString("base64url"),
    };
    entry.entry_hash = computeAuditEntryHash({
      sequence: entry.seq, schema_version: entry.schema_version, prev_hash: entry.prev_hash,
      timestamp: entry.timestamp, encrypted_payload_bytes: entry.encrypted_payload_bytes,
    });
    previous = entry.entry_hash;
    entries.push(entry);
  }
  const checkpoints: CheckpointExportRecord[] = [];
  const checkpointCount = UNSPLIT_SHAPE.signed + UNSPLIT_SHAPE.unsigned;
  const coveredEntries = entries.length - UNSPLIT_SHAPE.tail;
  let start = 0;
  for (let index = 0; index < checkpointCount; index++) {
    // Partition the retained covered entries evenly; the final two entries stay a tail.
    const end = Math.floor((index + 1) * coveredEntries / checkpointCount);
    const unsigned = index >= UNSPLIT_SHAPE.signed;
    const payload = {
      checkpoint_kind: "audit-checkpoint" as const,
      checkpoint_sequence: entries[end - 1].seq,
      from_sequence: entries[start].seq,
      root_hash: computeAuditRoot(entries.slice(start, end).map(entry => entry.entry_hash)),
      previous_checkpoint_sequence: start ? entries[start - 1].seq : UNSPLIT_SHAPE.lowest - 1,
      signed_at: NOW,
    };
    checkpoints.push({
      type: "checkpoint", ...payload, unsigned,
      signer_kid: unsigned ? null : f.audit.identity_id,
      signature: unsigned ? null : signBytes(checkpointSigningBytes(payload), f.audit),
      ...(unsigned ? {} : { public_key: f.audit.public_key }),
    });
    start = end;
  }
  f.records = [...entries, ...checkpoints];
  syncAudit(f);
  const template = f.bundle.checkpoints[0];
  let predecessor = "GENESIS";
  f.bundle.checkpoints = UNSPLIT_SHAPE.windows.map(([lowest, highest], index) => {
    const leaves = Array.from({ length: highest - lowest + 1 }, (_, offset) =>
      C.sha256Hex(C.utf8(`synthetic omitted leaf ${lowest + offset}`)));
    const checkpoint = {
      ...template, counter: index + 1, previous_checkpoint_hash: predecessor,
      audit: {
        lowest_sequence: lowest, highest_sequence: highest,
        entry_count: leaves.length, head_hash: leaves.at(-1)!, merkle_root: computeAuditRoot(leaves),
      },
    };
    resignTransparency(checkpoint, f.transparency);
    predecessor = computeCheckpointHash(checkpointPayloadOf(checkpoint));
    return checkpoint;
  });
  syncTransparency(f);
  return { f, entries, checkpoints };
}

import * as B from "../../src/evidence-pack/split-statement-contract.js";
import { capturedFile, stat, jsonBytes, trustRow, SOURCE, auditBytes } from "./snapshot-fixtures.js";
import { AUDIT_CHECKPOINT_SCHEMA_VERSION, type AuditCheckpointRecord } from "../../src/audit/checkpoint-shape.js";
export const FORTRESS = "fortress-1234567890abcdef";
/** Synthetic distinct sequence spaces with original persisted checkpoint envelopes. */
export function splitFixture() {
  const f = fixture();
  const chains = { operator: [] as Record<string,unknown>[], daemon: [] as Record<string,unknown>[] };
  for (const id of B.CHAIN_IDS) {
    const entries: EntryExportRecord[] = []; let prev = "GENESIS";
    const count = id === "operator" ? 2 : 1; // A cross-chain reset requires the operator head to be larger.
    for (let seq=1;seq<=count;seq++) {
      const e: EntryExportRecord = {type:"entry",seq,schema_version:AUDIT_CHAIN_SCHEMA_VERSION,prev_hash:prev,entry_hash:"",timestamp:NOW,encrypted_payload_bytes:Buffer.from(`${id}-${seq}`).toString("base64url")};
      e.entry_hash=computeAuditEntryHash({sequence:seq,schema_version:e.schema_version,prev_hash:e.prev_hash,timestamp:e.timestamp,encrypted_payload_bytes:e.encrypted_payload_bytes}); prev=e.entry_hash; entries.push(e);
    }
    const payload={checkpoint_kind:"audit-checkpoint" as const,checkpoint_sequence:count,from_sequence:1,root_hash:computeAuditRoot(entries.map(e=>e.entry_hash)),previous_checkpoint_sequence:0,signed_at:NOW};
    const cp: AuditCheckpointRecord = {schema_version:AUDIT_CHECKPOINT_SCHEMA_VERSION,...payload,signer_kid:id === "operator" ? f.audit.identity_id : null,signature:id === "operator" ? signBytes(checkpointSigningBytes(payload),f.audit) : null,signature_algorithm:id === "operator" ? C.ALGORITHM : null,payload_encoding:"domain-separated-canonical-json-v1",unsigned:id === "daemon",...(id === "operator" ? {public_key:f.audit.public_key} : {unsigned_reason:"no_signer"})};
    chains[id]=[...entries.map(e=>({...e})),{type:"checkpoint",persisted_base64url:Buffer.from(JSON.stringify(cp)).toString("base64url")}];
  }
  const bundle=structuredClone(f.bundle);
  for (const [i,cp] of bundle.checkpoints.entries()) {
    const id=B.CHAIN_IDS[i], entries=chains[id].filter(e=>e.type === "entry") as unknown as EntryExportRecord[];
    cp.fortress_id=FORTRESS;
    cp.audit={entry_count:entries.length,lowest_sequence:1,highest_sequence:entries.length,head_hash:entries.at(-1)!.entry_hash,merkle_root:computeAuditRoot(entries.map(e=>e.entry_hash))};
    cp.previous_checkpoint_hash=i === 0 ? "GENESIS" : computeCheckpointHash(checkpointPayloadOf(bundle.checkpoints[i-1])); resignTransparency(cp,f.transparency);
  }
  const keys=[trustRow(f.pack,B.PIN_ROLE.pack),trustRow(f.audit,B.PIN_ROLE.operator),trustRow(f.transparency,B.PIN_ROLE.transparency)].sort((a,b)=>(a.role+":"+a.key_id)<(b.role+":"+b.key_id)?-1:1);
  const trust=jsonBytes({format:B.TRUST_FORMAT,contract:B.CONTRACT,topology:B.TOPOLOGY,fortress_id:FORTRESS,keys});
  const files=new Map<string,Uint8Array>([[C.TRUST_FILENAME,trust],[C.REPORT_FILENAME,C.utf8("Synthetic split statement\n")],[C.PDF_FILENAME,C.utf8("%PDF-synthetic\n")],[C.RECIPIENT_FILENAME,C.utf8("Synthetic recipient procedure\n")]]);
  const census: any={format:B.CENSUS_FORMAT,export_id:f.manifest.export_id,fortress_id:FORTRESS,observed_from:NOW,observed_to:NOW,state:"complete",namespaces:[],objects:[],chains:[],migration:{state:"operator_checked",sealed_base_sequence:1,sealed_tip_sequence:2,sealed_tip_entry_hash:chains.operator[1].entry_hash,daemon_namespace:"_audit-daemon",daemon_genesis_entry_hash:chains.daemon[0].entry_hash,genesis_binding:"operator_checked"},transparency_floor:{state:"operator_checked",highest_counter:bundle.checkpoints.length},issues:[]};
  const manifest: any={...f.manifest,format:B.FORMAT,contract:B.CONTRACT,topology:B.TOPOLOGY,fortress_id:FORTRESS,components:{census:{state:"included",filename:B.FIXED_FILES.census[0]}}};
  const value={f,chains,bundle,trust,files,census,manifest,capture:f.capture,pins:{packKey:f.pack.public_key,descriptorBytes:trust,expectedManifestDigest:""}};
  refreshSplit(value); return value;
}
export type SplitFixture = ReturnType<typeof splitFixture>;
/** Rebuild only candidate synthetic fixtures; this never reads or rewrites the V0 golden. */
export function refreshSplit(s: {f:ReturnType<typeof fixture>;chains:Record<B.ChainId,Record<string,unknown>[]>;bundle:ReturnType<typeof fixture>["bundle"];trust:Uint8Array;files:Map<string,Uint8Array>;census:any;manifest:any;capture:C.CapturedSnapshot;pins:{packKey:string;descriptorBytes:Uint8Array;expectedManifestDigest:string}}) {
  s.census.objects=[];s.census.namespaces=[];s.census.chains=[];
  for (const id of B.CHAIN_IDS) {
    const rows=s.chains[id],filename=B.FIXED_FILES[`audit-${id}`][0],ns=id === "operator" ? "_audit" : "_audit-daemon";
    const entries=rows.filter(r=>r.type === "entry") as unknown as EntryExportRecord[];
    const checkpoints=rows.filter(r=>r.type === "checkpoint").map(r=>JSON.parse(Buffer.from(r.persisted_base64url as string,"base64url").toString()));
    if (rows.length) s.files.set(filename,C.utf8(rows.map(r=>JSON.stringify(r)).join(C.LF)+C.LF)); else s.files.delete(filename);
    for (const [index,r] of rows.entries()) s.census.objects.push({namespace:r.type === "entry" ? ns : ns+"_checkpoints",name_digest:C.sha256Hex(C.utf8(String(index))),kind:r.type,read_state:"read",source_sha256:C.sha256Hex(C.utf8(JSON.stringify(r))),output:{filename,record_index:index,record_sha256:C.sha256Hex(C.utf8(JSON.stringify(r)))}});
    for (const [namespace,listed_count] of [[ns,entries.length],[ns+"_checkpoints",checkpoints.length]]) s.census.namespaces.push({namespace,state:"listed",listed_count});
    s.census.chains.push({chain_id:id,census_state:entries.length ? "complete" : "empty",source_entries:entries.length,source_checkpoints:checkpoints.length,exported_entries:entries.length,exported_checkpoints:checkpoints.length,skipped:0,controls_state:"operator_checked",controls_issues:[]});
    s.manifest.components[id]=rows.length ? {state:"included",filename,extent:{entry_count:entries.length,first_sequence:entries[0]?.seq??null,last_sequence:entries.at(-1)?.seq??null,head_hash:entries.at(-1)?.entry_hash??null,checkpoint_count:checkpoints.length,first_checkpoint_sequence:checkpoints[0]?.checkpoint_sequence??null,last_checkpoint_sequence:checkpoints.at(-1)?.checkpoint_sequence??null,merkle_root:computeAuditRoot(entries.map(e=>e.entry_hash))}} : {state:"empty_verified",reason:"no_records"};
  }
  const b=s.bundle;
  s.files.set(C.TRANSPARENCY_FILENAME,jsonBytes(b));
  s.manifest.components.transparency={state:"included",filename:C.TRANSPARENCY_FILENAME,extent:{checkpoint_count:b.checkpoints.length,first_counter:b.checkpoints[0]?.counter,last_counter:b.checkpoints.at(-1)?.counter,last_checkpoint_payload_sha256:computeCheckpointHash(checkpointPayloadOf(b.checkpoints.at(-1)!)),fortress_id:FORTRESS}};
  s.census.namespaces.push({namespace:"_transparency_checkpoints",state:"listed",listed_count:b.checkpoints.length});
  b.checkpoints.forEach((cp,i)=>s.census.objects.push({namespace:"_transparency_checkpoints",name_digest:C.sha256Hex(C.utf8(String(i))),kind:"checkpoint",read_state:"read",source_sha256:C.sha256Hex(C.utf8(JSON.stringify(cp))),output:{filename:C.TRANSPARENCY_FILENAME,record_index:i,record_sha256:C.sha256Hex(C.utf8(JSON.stringify(cp)))}}));
  for(const namespace of B.SOURCE_NAMESPACES) if(!s.census.namespaces.some((n:any)=>n.namespace===namespace)) s.census.namespaces.push({namespace,state:namespace === "state" ? "listed" : "absent",listed_count:namespace === "state" ? 0 : null});
  s.census.objects.sort((a:any,b:any)=>(a.namespace+":"+a.name_digest)<(b.namespace+":"+b.name_digest)?-1:1);
  s.files.set(B.FIXED_FILES.census[0],jsonBytes(s.census));
  signSplit(s);
}
/** Sign current synthetic files after an intentional test mutation. */
export function signSplit(s: {f:ReturnType<typeof fixture>;files:Map<string,Uint8Array>;manifest:any;capture:C.CapturedSnapshot;pins:{expectedManifestDigest:string}}) {
  s.manifest.files=[...s.files].filter(([n])=>n!==C.MANIFEST_FILENAME).map(([filename,bytes])=>{const [role,pair]=Object.entries(B.FIXED_FILES).find(([,p])=>p[0]===filename)!;return {filename,role,content_type:pair[1],sha256:C.sha256Hex(bytes),size_bytes:bytes.length};}).sort((a,b)=>a.filename<b.filename?-1:1);
  s.manifest.manifest_signature=signBytes(B.manifestSigningBytes(s.manifest),s.f.pack);
  s.files.set(C.MANIFEST_FILENAME,jsonBytes(s.manifest));
  s.capture={files:[...s.files].map(([name,bytes])=>capturedFile(name,bytes)),rootBefore:stat(0,C.FILE_TYPE.directory),rootAfter:stat(0,C.FILE_TYPE.directory),finalNames:[...s.files.keys()].map(C.utf8),rootMetadata:[]};
  s.pins.expectedManifestDigest=C.manifestDigest(s.files.get(C.MANIFEST_FILENAME)!);
}

import {mkdir,mkdtemp,readdir,lstat,unlink,rmdir,open as openForInventory} from "node:fs/promises";import {constants as inventoryFs} from "node:fs";
import {resolve,join,dirname} from "node:path";
import {FilesystemStorage} from "../../src/storage/filesystem.js";
import {AuditLog,__testSetAuditWriterUidForRole} from "../../src/operational/audit-log.js";
import {migrateFortressAuditStoreSplit} from "../../src/operational/audit-store-split.js";
import {master as fixtureMaster} from "./snapshot-fixtures.js";
import {disposePhysicalFixture} from "./split-statement-dispose.js";
export {disposePhysicalFixture} from "./split-statement-dispose.js";
/** Production writers and migration in an explicitly assigned disposable root. */
export async function physicalSplitFixture(split=true) {
  const parent=resolve(import.meta.dirname,"../../../.scratch");await mkdir(parent,{recursive:true});
  const root=await mkdtemp(join(parent,"split-")),state=join(root,"state"),storage=new FilesystemStorage(state),masterKey=fixtureMaster.slice();
  const cleanup=async()=>{await disposePhysicalFixture(root);masterKey.fill(0);};
  try {
    const log=new AuditLog(storage,masterKey);
    await log.appendCritical({layer:"l1",operation:"synthetic",identity_id:"synthetic",result:"success",details:{}});await log.flush();
    if(split) {
      __testSetAuditWriterUidForRole("root_daemon",0);
      try {await migrateFortressAuditStoreSplit({storage,masterKey,identityId:"synthetic"});}
      finally {__testSetAuditWriterUidForRole("root_daemon",undefined);}
    }
    return {root,state,storage,masterKey,cleanup};
  } catch(error) {await cleanup();throw error;}
}

import {IdentityManager} from "../../src/cognitive/tools.js";
import {createIdentity,type StoredIdentity} from "../../src/core/identity.js";
import {derivePurposeKey} from "../../src/core/key-derivation.js";
import {createDaemonAuditLog} from "../../src/operational/audit-store-split.js";
import {emitEnforcementCheckpoint} from "../../src/transparency/emitter.js";
import {TRANSPARENCY_NEVER_ABORTED} from "../../src/transparency/scheduler.js";
import {fortressIdFromStoragePath} from "../../src/dashboard/v1_1/wiring.js";
import {exportDependencies,type ExportDependencies} from "../../src/evidence-pack/snapshot-export-cli.js";
import {writeFile} from "node:fs/promises";
/** Unit export fixture uses real stored ciphertext, migration, local validators and checkpoint emission. */
export async function splitExportFixture(unsignedOperator=false) {
  const parent=resolve(import.meta.dirname,"../../../.scratch");await mkdir(parent,{recursive:true});
  const root=await mkdtemp(join(parent,"split-export-")),fortress=join(root,"fortress"),state=join(fortress,"state"),storage=new FilesystemStorage(state),masterKey=fixtureMaster.slice();
  const manager=new IdentityManager(storage,masterKey),key=derivePurposeKey(masterKey,"identity-encryption");
  let signer:StoredIdentity;try{signer=createIdentity("Synthetic split operator",key,"passphrase").storedIdentity;}finally{key.fill(0);}
  const cleanup=async()=>{await disposePhysicalFixture(root);masterKey.fill(0);};
  try {
    if(!unsignedOperator){await manager.saveNew(signer);await manager.setPrimary(signer.identity_id);}
    const operator=new AuditLog(storage,masterKey);await operator.appendCritical({layer:"l1",operation:"synthetic",identity_id:signer.identity_id,result:"success"});await operator.flush();
    __testSetAuditWriterUidForRole("root_daemon",0); // Native root-role selection is scoped to fixture daemon work.
    try{await migrateFortressAuditStoreSplit({storage,masterKey,identityId:signer.identity_id});}finally{__testSetAuditWriterUidForRole("root_daemon",undefined);}
    if(unsignedOperator){await manager.saveNew(signer);await manager.setPrimary(signer.identity_id);}
    const daemon=createDaemonAuditLog(storage,masterKey);
    const castle=fixture().transparency;
    const rules=join(fortress,"policy","egress","rules");await mkdir(rules,{recursive:true});await writeFile(join(rules,"synthetic.json"),JSON.stringify({rule_id:"synthetic",host:"synthetic.invalid"}));
    const binary=join(fortress,"synthetic-binary");await writeFile(binary,"synthetic fixture binary");
    await emitEnforcementCheckpoint({storage,auditLog:daemon,fortressId:fortressIdFromStoragePath(fortress),fortressPath:fortress,masterKey,signer:{signer_kid:"castle-wall:"+castle.public_key,publicKey:C.publicKey(castle.public_key),sign:async bytes=>Buffer.from(signBytes(bytes,castle),"base64url")},binaryPath:binary,version:"synthetic",abortState:TRANSPARENCY_NEVER_ABORTED});
    const stdout:string[]=[],stderr:string[]=[],states:string[]=[];let cleanupCalls=0;
    const options={fortress,output:join(root,"pack"),receipt:join(root,"receipt.json"),publicKeyFile:join(root,"pack-key.txt")};
    const deps:ExportDependencies={...exportDependencies,runtimeRevision:SOURCE,buildRevision:SOURCE,boot:async()=>({config:{storage_path:fortress},identityManager:manager,masterKey,cleanup:async()=>{cleanupCalls++;await operator.flush();}}) as unknown as Awaited<ReturnType<ExportDependencies["boot"]>>,resolvePin:async()=>({key:castle.public_key,pathClass:"fortress-local"}),phase:async state=>{states.push(state);},io:{stdout:text=>{stdout.push(text);},stderr:text=>{stderr.push(text);}}};
    return {root,fortress,state,storage,masterKey,signer,castle,operator,daemon,manager,options,deps,stdout,stderr,states,cleanupCalls:()=>cleanupCalls,cleanup};
  }catch(error){await cleanup();throw error;}
}

import {vi} from "vitest";
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
/** Compare every ordinary fixture file before and after a source-root replacement. */
export async function splitFixtureByteInventory(root:string){
  const directories=[root],files:Record<string,string>={};
  for(let i=0;i<directories.length;i++)for(const name of await readdir(directories[i])){const path=join(directories[i],name);const handle=await openForInventory(path,inventoryFs.O_RDONLY|inventoryFs.O_NOFOLLOW|inventoryFs.O_NONBLOCK).catch((error:NodeJS.ErrnoException)=>{if(error.code==="ELOOP"||error.code==="ENXIO"||error.code==="EOPNOTSUPP")return null;throw error;});if(!handle)continue;try{const meta=await handle.stat();if(meta.isDirectory())directories.push(path);else if(meta.isFile())files[path.slice(root.length+1)]=createHash("sha256").update(await handle.readFile()).digest("hex");}finally{await handle.close();}} // One no-follow descriptor is both checked and read, so a link or a file swapped in after its check is never hashed; links and sockets are skipped as before.
  return Object.fromEntries(Object.entries(files).sort(([a],[b])=>a<b?-1:1));
}
/** Real custody, migration, writers, scheduled emission, shutdown and registered export; only native startup is replaced. */
export async function wiredSplitFixture(options:{preSplitWindow?:boolean;liveTail?:boolean;emptyPrefix?:boolean;unavailable?:boolean;invalidControl?:boolean}={}) {
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
    entry.exportDependencies.phase=async(stateName,stage)=>{await phase(stateName,stage);if(stateName==="CENSUS"&&options.invalidControl){const path=join(state,"_audit_migration","boundary-v1.json"),value=JSON.parse(await readFile(path,"utf8"));value.mac="A".repeat(43);await writeFile(path,JSON.stringify(value));}if(stateName==="CENSUS"&&options.unavailable)splitNativeBoundary.unavailableDirectory=join(state,"_audit-daemon");if(stateName==="QUIESCE_EXPORT_INSTANCE")observed.operatorBeforeCleanup=await splitFixtureExtent(storage,"_audit");if(stateName==="CENSUS"&&!options.unavailable)observed.beforeCensus=await splitFixtureByteInventory(state);if(stateName==="BUILD"&&!options.unavailable)observed.afterRecheck=await splitFixtureByteInventory(state);};
    const argv=process.argv,stdout:string[]=[],exits:number[]=[],output=join(root,"pack"),receipt=join(root,"receipt.json"),publicKeyFile=join(root,"pack-key.txt");
    const stdoutSpy=vi.spyOn(process.stdout,"write").mockImplementation(((text:string,callback?:(error?:Error)=>void)=>{stdout.push(String(text));callback?.();return true;}) as never),exitSpy=vi.spyOn(process,"exit").mockImplementation(((code:number)=>{exits.push(code);}) as never);
    process.argv=[process.execPath,resolve(import.meta.dirname,"../../src/cli.ts"),"export-evidence","--fortress",fortress,"--output",output,"--receipt",receipt,"--public-key-file",publicKeyFile];
    try{await(await import("../../src/cli.js")).cliEntryInvocation;}finally{process.argv=argv;stdoutSpy.mockRestore();exitSpy.mockRestore();entry.exportDependencies.phase=phase;vi.unstubAllGlobals();}
    if(options.invalidControl&&exits[0]===1)return {root,fortress,state,storage,signer,revision,exits,stdout,observed,output,receipt,receiptBytes:Buffer.alloc(0),trust:Buffer.alloc(0),publicKeyFile,cleanup};
    const receiptBytes=await readFile(receipt),trust=await readFile(join(output,C.TRUST_FILENAME));
    observed.operatorAfterCapture=await splitFixtureExtent(storage,"_audit");
    return {root,fortress,state,storage,signer,revision,exits,stdout,observed,output,receipt,receiptBytes,trust,publicKeyFile,cleanup};
  } catch(error){__testSetAuditWriterUidForRole("root_daemon",undefined);await cleanup();throw error;}
}
