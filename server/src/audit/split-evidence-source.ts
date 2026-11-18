/** Internal bounded read-set boundary; no writer, append lock or credential lookup is exposed. */
import {constants,type BigIntStats} from "node:fs";
import {open,opendir,lstat,realpath,type FileHandle} from "node:fs/promises";
import {resolve,dirname,join,parse as parsePath} from "node:path";
import type {StorageBackend,StorageEntryMeta} from "../storage/interface.js";
import {encodeFilesystemStorageName,decodeRawFilesystemStorageName} from "../storage/filesystem-name-codec.js";
import {READ_ONLY_STORAGE_MUTATING_METHODS} from "../storage/read-only-guard.js";
import * as C from "../evidence-pack/snapshot-contract.js";
import * as B from "../evidence-pack/split-statement-contract.js";
import {SOURCE_NAMESPACES,BOUNDARY,CHAIN_NAMESPACES,META_CONTROLS,sourceKind,excludedRawSourceName,producerRawSourceName,type SourceKind} from "./split-evidence-registry.js";
export const MAX_SOURCE_HANDLES=16; // One root, one namespace and one body handle fit beneath the request-wide ceiling.
export const SOURCE_ATTEMPTS=2; // Initial whole read plus one fresh retry; never an append-tolerant cut.
export interface SourceIO {open:typeof open;opendir:typeof opendir;lstat:typeof lstat}
export const sourceIO:SourceIO={open,opendir,lstat};
export type SourceState="listed"|"absent"|"unreadable"|"invalid";
export interface SourceObject {readonly namespace:string;readonly rawName:string;readonly key:string|null;readonly kind:SourceKind;readonly read_state:"read"|"absent"|"unreadable"|"invalid";readonly digest:string|null;readonly size:number;readonly bytes:Uint8Array|null}
export interface SourceNamespace {readonly namespace:string;readonly state:SourceState;readonly names:readonly string[]|null}
export type SourceMode="CLASSIFY"|"READ";
export interface SourceReadSet {readonly mode:SourceMode;readonly splitEvidenceObserved:boolean;readonly root:string;readonly namespaces:readonly SourceNamespace[];readonly objects:readonly SourceObject[];readonly issues:readonly B.PartialCode[];readonly bytesRead:number;readonly objectsSeen:number;readonly identity:readonly [string,string][];readonly started:string;readonly ended:string;readonly limited:boolean;readonly hard:readonly B.HardCode[];readonly io:SourceIO}
const stamp=(s:BigIntStats)=>[s.dev,s.ino,s.mode,s.nlink,s.size,s.mtimeNs,s.ctimeNs].join(":");
function stopped(signal:AbortSignal){if(signal.aborted)throw new B.SplitError("io_error");}
function errno(error:unknown){return (error as NodeJS.ErrnoException).code;}
/** Enumerate incrementally and read only registry-classified values within one aggregate byte allowance. */
export async function readSplitSource(rootPath:string,io:SourceIO,signal:AbortSignal,mode:SourceMode="READ"):Promise<SourceReadSet> {
  // Resolve V0 aliases first; if resolution is incomplete, root listing still decides access doubt and V0 owns the remaining uncertainty.
  const root=mode==="CLASSIFY"?await realpath(rootPath).catch(()=>resolve(rootPath)):resolve(rootPath),started=new Date().toISOString();let bytesRead=0,objectsSeen=0,handles=0,limited=false,splitEvidenceObserved=false;
  const objects:SourceObject[]=[],namespaces:SourceNamespace[]=[],identity:[string,string][]=[],issues=new Set<B.PartialCode>(),hard=new Set<B.HardCode>();
  const chargeObject=()=>{stopped(signal);if(objectsSeen===B.MAX_SOURCE_OBJECTS){limited=true;throw new B.SplitError("limit_exceeded");}objectsSeen++;};
  async function held(path:string,flags:number){stopped(signal);B.requireSplit(handles<MAX_SOURCE_HANDLES,"limit_exceeded");const fd=await io.open(path,flags);handles++;return fd;}
  async function close(fd:FileHandle){try{await fd.close();}finally{handles--;}}
  async function observe(path:string){const s=await io.lstat(path,{bigint:true});identity.push([path,stamp(s)]);return s;}
  async function body(path:string):Promise<{bytes:Uint8Array;digest:string;size:number}> {
    const before=await observe(path);B.requireSplit(before.isFile()&&!before.isSymbolicLink()&&before.nlink===1n,"file_type_invalid");
    const size=Number(before.size);C.integer(size);B.requireSplit(size<=C.MAX_FILE_BYTES,"limit_exceeded");
    // Charge before allocating, including bytes read during preliminary classification.
    B.requireSplit(size<=C.MAX_PACK_BYTES-bytesRead,"limit_exceeded");bytesRead+=size;
    const fd=await held(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try {
      B.requireSplit(stamp(before)===stamp(await fd.stat({bigint:true})),"snapshot_changed");
      const bytes=Buffer.alloc(size);let offset=0;
      while(offset<size){stopped(signal);const result=await fd.read(bytes,offset,size-offset,offset);B.requireSplit(result.bytesRead>0,"snapshot_changed");offset+=result.bytesRead;}
      stopped(signal);B.requireSplit(stamp(before)===stamp(await fd.stat({bigint:true}))&&stamp(before)===stamp(await io.lstat(path,{bigint:true})),"snapshot_changed");
      return {bytes,digest:C.sha256Hex(bytes),size};
    }finally{await close(fd);}
  }
  async function directory(namespace:string,path:string):Promise<SourceNamespace> {
    let fd:FileHandle|undefined;const names:string[]=[];
    try {
      const before=await observe(path);
      // An observed daemon selector is positive evidence even if the root listing did not retain its name.
      if(Object.values(CHAIN_NAMESPACES.daemon).includes(namespace as never))splitEvidenceObserved=true;
      B.requireSplit(before.isDirectory()&&!before.isSymbolicLink(),"file_type_invalid");
      fd=await held(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_DIRECTORY);B.requireSplit(stamp(before)===stamp(await fd.stat({bigint:true})),"snapshot_changed");
      const dir=await io.opendir(path,{encoding:"buffer" as BufferEncoding});
      for await(const entry of dir){const raw=entry.name as unknown as Buffer;B.requireSplit(Buffer.isBuffer(raw),"unsafe_path");
        // Unrelated root names cannot spend the audit inventory budget or prevent selector discovery.
        if(namespace==="state"&&!raw.subarray(0,Buffer.byteLength("_audit")).equals(Buffer.from("_audit")))continue;
        // Raw audit prefixes retain topology doubt even when the storage codec cannot address the name.
        if(namespace==="state"&&raw.subarray(0,Buffer.byteLength("_audit")).equals(Buffer.from("_audit"))&&!SOURCE_NAMESPACES.some(name=>raw.equals(Buffer.from(name))))hard.add("topology_ambiguous");
        chargeObject();B.requireSplit(raw.length<=C.MAX_NAME_BYTES,"limit_exceeded");let name:string;try{name=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(raw);}catch{throw new B.SplitError("unsafe_path");}B.requireSplit(!name.includes("/")&&name!=="."&&name!=="..","unsafe_path");names.push(name);
        // READ retains inventory evidence; CLASSIFY selects only from fixed-path observations.
        if(mode==="READ"&&((namespace==="state"&&Object.values(CHAIN_NAMESPACES.daemon).includes(name as never))||(namespace===BOUNDARY.namespace&&name===BOUNDARY.name)||(namespace===CHAIN_NAMESPACES.operator.meta&&name===META_CONTROLS[2]+".enc")))splitEvidenceObserved=true;}
      names.sort();B.requireSplit(new Set(names).size===names.length,"unsafe_path");
      for(const rawName of names) {
        stopped(signal);let key:string|null=null,kind:SourceKind="unsupported";
        try {key=namespace==="state"?decodeRawFilesystemStorageName(rawName,"namespace"):namespace===BOUNDARY.namespace?rawName:rawName.endsWith(".enc")?decodeRawFilesystemStorageName(rawName.slice(0,-".enc".length),"key"):null;if(key!==null)kind=sourceKind(namespace,key);}catch{if(namespace!=="state")issues.add("ambiguous_census");}
        // V0 ignores unrelated root names, including names outside the storage codec.
        if(namespace==="state"&&!rawName.startsWith("_audit")&&(key===null||!key.startsWith("_audit")))kind="excluded";
        if(excludedRawSourceName(namespace,rawName))kind="excluded";
        // A retained recovery incident has no dedicated closed reason; unknown_source_object keeps it non-PASS without trusting its contents.
        if(producerRawSourceName(namespace,rawName)==="incident")kind="unsupported";
        if(kind==="unsupported")issues.add("unknown_source_object");
        // Must match parseCensus in evidence-pack/split-statement-contract.ts; excluded names retain no read evidence.
        if(mode==="CLASSIFY"||namespace==="state"||kind==="excluded"||kind==="unsupported"){objects.push({namespace,rawName,key,kind,read_state:"absent",digest:null,size:0,bytes:null});continue;}
        try {const data=await body(join(path,rawName));objects.push({namespace,rawName,key,kind,read_state:"read",...data});}
        catch(error) {
          if(error instanceof B.SplitError&&error.code==="limit_exceeded"){limited=true;throw error;}
          if(error instanceof B.SplitError&&(error.code==="snapshot_changed"||error.code==="file_type_invalid"))throw error;
          issues.add("source_unreadable");objects.push({namespace,rawName,key,kind,read_state:"unreadable",digest:null,size:0,bytes:null});
        }
      }
      B.requireSplit(stamp(before)===stamp(await fd.stat({bigint:true}))&&stamp(before)===stamp(await io.lstat(path,{bigint:true})),"snapshot_changed");
      return {namespace,state:"listed",names};
    }catch(error){
      if(error instanceof B.SplitError&&error.code==="limit_exceeded"){if(namespace==="state")hard.add("topology_ambiguous");limited=true;issues.add("source_limit");return {namespace,state:"unreadable",names:null};}
      if(error instanceof B.SplitError&&error.code==="snapshot_changed"){
        if(mode==="CLASSIFY"){issues.add("source_changed");return {namespace,state:"unreadable",names:null};}
        if(hard.size)throw new B.SplitError([...hard][0]);throw error;
      }
      if(errno(error)==="ENOENT")return {namespace,state:"absent",names:null};
      // Only a root access error, not an incomplete bounded observation, prevents V0 routing.
      if(namespace==="state"&&!(error instanceof B.SplitError))hard.add("topology_ambiguous");
      if(error instanceof B.SplitError)hard.add("source_control_invalid");
      issues.add("source_unreadable");return {namespace,state:error instanceof B.SplitError?"invalid":"unreadable",names:null};
    }finally{if(fd)await close(fd);}
  }
  // Each ancestor is checked before and after the interval so a replacement cannot become a clean source.
  const ancestors:string[]=[];let ancestor=root;
  while(ancestor!==parsePath(ancestor).root){ancestors.push(ancestor);ancestor=dirname(ancestor);}
  for(const path of ancestors.reverse()) {try{const s=await io.lstat(path,{bigint:true});identity.push([path,"ancestor:"+[s.dev,s.ino,s.mode].join(":")]);B.requireSplit(s.isDirectory()&&!s.isSymbolicLink(),"file_type_invalid");}catch(error){if(mode==="CLASSIFY"){issues.add("source_unreadable");continue;}if(path!==root)throw error;}}
  if(mode==="CLASSIFY") {
    // Fixed probes are independent of listing progress; absence alone is not split evidence.
    const selectors=[...Object.values(CHAIN_NAMESPACES.daemon).map(namespace=>({path:join(root,namespace),positive:true})),
      {path:join(root,BOUNDARY.namespace,BOUNDARY.name),positive:true},
      {path:join(root,CHAIN_NAMESPACES.operator.meta,META_CONTROLS[2]+".enc"),positive:true},
      {path:join(root,BOUNDARY.namespace),positive:false}];
    for(const selector of selectors) {
      stopped(signal);
      try {await observe(selector.path);if(selector.positive)splitEvidenceObserved=true;}
      catch(error){if(errno(error)!=="ENOENT")hard.add("topology_ambiguous");}
    }
  }
  namespaces.push(await directory("state",root));
  // CLASSIFY needs selector scopes only; chain history belongs to the selected gather's own bounds.
  const scopes=mode==="CLASSIFY"?[BOUNDARY.namespace,CHAIN_NAMESPACES.operator.meta,...Object.values(CHAIN_NAMESPACES.daemon)]:SOURCE_NAMESPACES;
  for(const namespace of scopes)if(namespace!=="state") {
    if(limited){namespaces.push({namespace,state:"unreadable",names:null});continue;}
    namespaces.push(await directory(namespace,join(root,encodeFilesystemStorageName(namespace))));
  }
  stopped(signal);
  return Object.freeze({mode,splitEvidenceObserved,root,namespaces:Object.freeze(namespaces),objects:Object.freeze(objects),issues:Object.freeze([...issues]),bytesRead,objectsSeen,identity:Object.freeze(identity),started,ended:new Date().toISOString(),limited,hard:Object.freeze([...hard]),io});
}
/** Validators see only captured bytes and a fully enumerated bounded namespace, never live paths. */
export function capturedStorage(read:SourceReadSet,remap:Readonly<Record<string,string>>={}):StorageBackend {
  const records=new Map(read.objects.filter(o=>o.key!==null).map(o=>[o.namespace+"/"+o.key,o]));
  const inventory=new Map<string,StorageEntryMeta[]>();
  for(const o of read.objects)if(o.key!==null){const rows=inventory.get(o.namespace)??[];rows.push({namespace:o.namespace,key:o.key,size_bytes:o.size,modified_at:read.ended});inventory.set(o.namespace,rows);}
  const map=(namespace:string)=>remap[namespace]??namespace;
  const check=(namespace:string)=>{const state=read.namespaces.find(n=>n.namespace===namespace);B.requireSplit(state&&(state.state==="listed"||state.state==="absent"),"io_error");return state;};
  const api:StorageBackend={
    read:async(namespace,key)=>{const ns=map(namespace);const row=records.get(ns+"/"+key);if(!row){check(ns);return null;}B.requireSplit(row.read_state==="read"&&row.bytes,"io_error");return row.bytes.slice();},
    list:async(namespace,prefix)=>{const ns=map(namespace);check(ns);return (inventory.get(ns)??[]).filter(o=>!prefix||o.key.startsWith(prefix)).map(o=>({...o,namespace}));},
    exists:async(namespace,key)=>{const ns=map(namespace);if(records.has(ns+"/"+key))return true;check(ns);return false;},
    totalSize:async()=>read.bytesRead,
    write:async()=>{throw new B.SplitError("source_control_invalid");},delete:async()=>{throw new B.SplitError("source_control_invalid");},
  };
  // Must match READ_ONLY_STORAGE_MUTATING_METHODS in storage/read-only-guard.ts: every mutation method refuses before any effect.
  for(const method of READ_ONLY_STORAGE_MUTATING_METHODS)Object.defineProperty(api,method,{value:async()=>{throw new B.SplitError("source_control_invalid");}});
  return Object.freeze(api);
}
/** A full fresh enumeration/digest read is compared, never an append-tolerant suffix. */
export async function recheckSplitSource(read:SourceReadSet,signal:AbortSignal):Promise<boolean> {
  for(const [path,before] of read.identity){stopped(signal);try{const s=await read.io.lstat(path,{bigint:true});if((before.startsWith("ancestor:")?"ancestor:"+[s.dev,s.ino,s.mode].join(":"):stamp(s))!==before)return false;}catch{return false;}}
  const next=await readSplitSource(read.root,read.io,signal);
  // A hard file-shape finding observed during the fresh read must not become a retryable change.
  if(next.hard.length)throw new B.SplitError(next.hard[0]);
  const summary=(s:SourceReadSet)=>({namespaces:s.namespaces,objects:s.objects.map(({bytes:_bytes,...o})=>o),identity:s.identity,issues:s.issues,limited:s.limited});
  return C.canonicalSnapshotJSON(summary(next))===C.canonicalSnapshotJSON(summary(read));
}

/** The split gather reuses CLASSIFY's resolved root only while its recorded ancestor identities still hold. */
export async function requireSplitRootIdentity(read:SourceReadSet,signal:AbortSignal):Promise<void> {
  const ancestors=read.identity.filter(([,value])=>value.startsWith("ancestor:"));
  B.requireSplit(ancestors.some(([path])=>path===read.root),"snapshot_changed");
  for(const [path,before] of ancestors){
    stopped(signal);const current=await read.io.lstat(path,{bigint:true});
    // Directory contents may change during normal quiescence, but the selected root and ancestors cannot be replaced.
    B.requireSplit(before==="ancestor:"+[current.dev,current.ino,current.mode].join(":"),"snapshot_changed");
  }
}
