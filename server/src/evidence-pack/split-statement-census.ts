/** Source-only classification and public projection; local validation is a separate required stage. */
import {isPersistedAuditEnvelopeV2,parseEntryKeySequence,parseCheckpointKeySequence,AUDIT_CHECKPOINT_KEY_PREFIXES} from "../operational/audit-log.js";
import {isAuditCheckpointRecord} from "../audit/checkpoint-shape.js";
import {BOUNDARY,CHAIN_NAMESPACES,META_CONTROLS} from "../audit/split-evidence-registry.js";
import {readSplitSource,SOURCE_ATTEMPTS,type SourceIO,type SourceReadSet,type SourceObject} from "../audit/split-evidence-source.js";
import {SUPPORTED_PAYLOAD_VERSION,SUPPORTED_PAYLOAD_ALG,PAYLOAD_IV_BYTE_LENGTH} from "../core/encryption.js";
import {TRANSPARENCY_CHECKPOINT_NAMESPACE} from "../transparency/emitter.js";
import {computeAuditEntryHash} from "../audit/chain.js";
import * as B from "./split-statement-contract.js";
import * as C from "./snapshot-contract.js";
export interface SourceProjection {readonly read:SourceReadSet;readonly topology:"split"|"unsplit";readonly records:Readonly<Record<B.ChainId,readonly {source:SourceObject;record:Record<string,unknown>}[]>>;readonly transparency:readonly {source:SourceObject;record:Record<string,unknown>}[];readonly issues:readonly B.PartialCode[]}
/** Select split only from positive raw observations; unchanged V0 probes own incomplete observations. */
export async function classifySplitSource(read:SourceReadSet):Promise<"split"|"unsplit"> {
  const rawBoundaryPresent=read.objects.some(o=>o.namespace===BOUNDARY.namespace&&o.rawName===BOUNDARY.name);
  const establishedMarkerPresent=read.objects.some(o=>o.namespace===CHAIN_NAMESPACES.operator.meta&&o.key===META_CONTROLS[2]);
  const rawDaemon=read.objects.some(o=>o.namespace==="state"&&Object.values(CHAIN_NAMESPACES.daemon).includes(o.key as never));
  // Fixed selector access and unknown audit-prefixed root names establish topology doubt.
  B.requireSplit(!read.hard.includes("topology_ambiguous")&&!read.objects.some(o=>o.namespace==="state"&&o.kind==="unsupported"),"topology_ambiguous");
  // Positive observations select the split census; incomplete observations alone leave V0's probes authoritative.
  if(read.splitEvidenceObserved||(read.mode==="READ"&&(rawBoundaryPresent||establishedMarkerPresent||rawDaemon)))return "split";
  return "unsplit";
}
/** Project both chains separately while retaining the original persisted ordinary checkpoint bytes. */
export async function censusSplitSource(read:SourceReadSet):Promise<SourceProjection> {
  B.requireSplit(read.mode==="READ","source_control_invalid");
  const topology=await classifySplitSource(read),issues=new Set(read.issues),budget=new B.Budget();
  if(read.hard.length)throw new B.SplitError(read.hard[0]);
  const records:Record<B.ChainId,{source:SourceObject;record:Record<string,unknown>}[]>={operator:[],daemon:[]};
  const transparency:{source:SourceObject;record:Record<string,unknown>}[]=[];
  for(const object of read.objects) {
    if(object.read_state!=="read"||!object.bytes||object.key===null)continue;
    if(object.kind!=="entry"&&object.kind!=="checkpoint")continue;
    budget.charge("records",1);
    const value=C.parseSnapshotJSON(object.bytes,C.MAX_JSONL_LINE_BYTES);
    if(object.namespace===TRANSPARENCY_CHECKPOINT_NAMESPACE) {B.requireSplit(value!==null&&typeof value==="object"&&!Array.isArray(value));transparency.push({source:object,record:value as Record<string,unknown>});continue;}
    const id=B.CHAIN_IDS.find(id=>object.namespace===CHAIN_NAMESPACES[id].entries||object.namespace===CHAIN_NAMESPACES[id].checkpoints);B.requireSplit(id,"census_mismatch");
    if(object.kind==="entry") {
      if(!isPersistedAuditEnvelopeV2(value)){
        const legacy=C.object(value,["v","alg","iv","ct","ts"]);
        B.requireSplit(legacy.v===SUPPORTED_PAYLOAD_VERSION&&legacy.alg===SUPPORTED_PAYLOAD_ALG,"chain_invalid");C.base64(legacy.iv,PAYLOAD_IV_BYTE_LENGTH);C.base64(legacy.ct);C.timestamp(legacy.ts);
        issues.add("pre_v2_history");continue;
      }
      B.requireSplit(parseEntryKeySequence(object.key)===value.sequence && computeAuditEntryHash({schema_version:value.schema_version,sequence:value.sequence,prev_hash:value.prev_hash,timestamp:value.timestamp,encrypted_payload_bytes:value.encrypted_payload_bytes})===value.entry_hash,"chain_invalid");
      records[id].push({source:object,record:{type:"entry",seq:value.sequence,schema_version:value.schema_version,prev_hash:value.prev_hash,entry_hash:value.entry_hash,timestamp:value.timestamp,encrypted_payload_bytes:value.encrypted_payload_bytes}});
    } else {
      // Legacy anchors remain known producer objects, while B ordinary coverage requires V2 checkpoints.
      if(object.key.startsWith(AUDIT_CHECKPOINT_KEY_PREFIXES["legacy-anchor"])) {B.requireSplit(isAuditCheckpointRecord(value)&&value.checkpoint_kind==="legacy-anchor","checkpoint_invalid");issues.add("pre_v2_history");continue;}
      budget.charge("decoded",object.bytes.length);C.cap(Math.ceil(object.bytes.length*4/3)+C.utf8('{"type":"checkpoint","persisted_base64url":""}').length,C.MAX_JSONL_LINE_BYTES);const cp=B.parsePersistedCheckpoint(object.bytes);B.requireSplit(parseCheckpointKeySequence(object.key)===cp.checkpoint_sequence,"checkpoint_invalid");
      records[id].push({source:object,record:{type:"checkpoint",persisted_base64url:Buffer.from(object.bytes).toString("base64url")}});
    }
  }
  for(const id of B.CHAIN_IDS)records[id].sort((a,b)=>a.source.key!<b.source.key!?-1:1);
  transparency.sort((a,b)=>a.source.key!<b.source.key!?-1:1);
  return Object.freeze({read,topology,records,transparency,issues:Object.freeze([...issues])});
}

/** Preliminary selection enumerates bounded names without consuming values that normal cleanup will replace. */
export async function classifySplitTopology(root:string,io:SourceIO,signal:AbortSignal):Promise<{topology:"split";read:SourceReadSet}|{topology:"unsplit"}> {
  for(let attempt=0;attempt<SOURCE_ATTEMPTS;attempt++) {
    const read=await readSplitSource(root,io,signal,"CLASSIFY"),topology=await classifySplitSource(read);
    if(topology==="split")return {topology,read};
    const incomplete=read.namespaces.find(n=>n.namespace==="state")?.state==="absent"||read.limited||read.issues.length>0||read.namespaces.some(n=>n.state==="unreadable"||n.state==="invalid");
    if(!incomplete)return {topology:"unsplit"};
  }
  // Exactly one retry preserves availability while unchanged V0 probes refuse any hidden split as split_store.
  return {topology:"unsplit"};
}
