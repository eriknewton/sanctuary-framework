/** Source-only validation and stable read composition for the operator's signed testimony. */
import {AuditLog,deriveAuditEpochKeys,readCustodyEpochCount,deriveAuditStoreSplitBoundaryMacKey,readAuditStoreSplitEstablishedMarker,validateAuditStoreSplitBoundaryBytes,isHardIntegrityFinding,type AuditLogConfig} from "../operational/audit-log.js";
import {AUDIT_STORE_SPLIT_MIGRATION_OP} from "../operational/audit-store-split.js";
import {readTransparencyCounterFloor,TRANSPARENCY_FLOOR_META_KEY} from "../transparency/emitter.js";
import {AUDIT_NAMESPACE,AUDIT_CHECKPOINT_NAMESPACE,AUDIT_META_NAMESPACE,AUDIT_ROTATION_ANCHOR_KEY,AUDIT_EPOCH_KEYS_KEY,AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY} from "../operational/audit-log.js";
import {BOUNDARY,CHAIN_NAMESPACES,SOURCE_NAMESPACES} from "../audit/split-evidence-registry.js";
import {readSplitSource,recheckSplitSource,capturedStorage,SOURCE_ATTEMPTS,type SourceIO,type SourceReadSet} from "../audit/split-evidence-source.js";
import {censusSplitSource,type SourceProjection} from "./split-statement-census.js";
import * as B from "./split-statement-contract.js";
import * as C from "./snapshot-contract.js";
export interface SourceValidation {
  readonly controls:Readonly<Record<B.ChainId,{state:"operator_checked"|"unavailable";issues:readonly B.PartialCode[]}>>;
  readonly migration:B.Census["migration"];
  readonly floor:B.Census["transparency_floor"];
  readonly issues:readonly B.PartialCode[];
}
export interface SourceValidationInput {readonly projection:SourceProjection;readonly masterKey:Uint8Array;readonly resolveKey:NonNullable<AuditLogConfig["checkpointPublicKeyResolver"]>;readonly budget:B.Budget;readonly signal:AbortSignal}
const MAX_SOURCE_DECRYPT_ATTEMPTS=B.MAX_LEAF_VISITS; // Source decryption gets the same finite work ceiling as chain hashing.
function checkSignal(signal:AbortSignal){B.requireSplit(!signal.aborted,"io_error");}
/** Inspect all readable control MACs before any history budget can end validation. */
async function preflightSplitControls(read:SourceReadSet,masterKey:Uint8Array,signal:AbortSignal):Promise<void> {
  checkSignal(signal);const storage=capturedStorage(read),macKey=deriveAuditStoreSplitBoundaryMacKey(masterKey);
  const unreadable=(namespace:string,key:string)=>read.objects.some(o=>o.namespace===namespace&&o.key===key&&o.read_state!=="read")||read.namespaces.some(n=>n.namespace===namespace&&(n.state==="unreadable"||n.state==="invalid"));
  try {
    const boundary=read.objects.find(o=>o.namespace===BOUNDARY.namespace&&o.rawName===BOUNDARY.name);
    if(boundary?.read_state==="read")B.requireSplit(validateAuditStoreSplitBoundaryBytes(boundary.bytes!,macKey).status==="valid","migration_invalid");
    if(!unreadable(CHAIN_NAMESPACES.operator.meta,AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY))B.requireSplit(await readAuditStoreSplitEstablishedMarker(storage,macKey)!=="invalid_or_unreadable","migration_invalid");
    if(!unreadable(CHAIN_NAMESPACES.operator.meta,TRANSPARENCY_FLOOR_META_KEY))B.requireSplit((await readTransparencyCounterFloor(storage,masterKey)).status!=="invalid","source_control_invalid");
    for(const id of B.CHAIN_IDS) {
      const view=capturedStorage(read,{[AUDIT_NAMESPACE]:CHAIN_NAMESPACES[id].entries,[AUDIT_CHECKPOINT_NAMESPACE]:CHAIN_NAMESPACES[id].checkpoints,[AUDIT_META_NAMESPACE]:CHAIN_NAMESPACES[id].meta}),epochs=deriveAuditEpochKeys(masterKey);
      try {if(!unreadable(CHAIN_NAMESPACES[id].checkpoints,AUDIT_EPOCH_KEYS_KEY))B.requireSplit((await readCustodyEpochCount(view,epochs)).status!=="tampered","source_control_invalid");}
      finally {epochs.epochWrapKey.fill(0);epochs.epochMacKey.fill(0);}
      // No history or signatures enter this pass; both chains' readable controls precede leaf admission.
      const controls=await AuditLog.validateCapturedControls({storage:view,masterKey,signal,validateChain:false,checkpoints:[],checkpointPublicKeyResolver:()=>undefined,admit:()=>{}});
      B.requireSplit(!controls.invalidControl&&!controls.findings.some(isHardIntegrityFinding),"source_control_invalid");
    }
  }finally {macKey.fill(0);}
}
/** Run existing control cryptography only over captured immutable input; read failures never prove zero. */
export async function validateSplitSource(input:SourceValidationInput):Promise<SourceValidation> {
  const {projection:p,masterKey,resolveKey,budget,signal}=input,read=p.read,storage=capturedStorage(read),issues=new Set<B.PartialCode>(p.issues);
  checkSignal(signal);if(read.hard.length)throw new B.SplitError(read.hard[0]);
  await preflightSplitControls(read,masterKey,signal);
  const controls:Record<B.ChainId,{state:"operator_checked"|"unavailable";issues:B.PartialCode[]}>={operator:{state:"unavailable",issues:["controls_unavailable"]},daemon:{state:"unavailable",issues:["controls_unavailable"]}};
  let decryptAttempts=0;
  let daemonGenesis:Awaited<ReturnType<typeof AuditLog.validateCapturedControls>>["genesis"]=null;
  for(const id of B.CHAIN_IDS) {
    const namespaces=Object.values(CHAIN_NAMESPACES[id]);
    const unavailable=namespaces.some(ns=>{const n=read.namespaces.find(n=>n.namespace===ns);return !n||n.state==="unreadable"||n.state==="invalid"||(id==="daemon"&&ns===CHAIN_NAMESPACES.daemon.entries&&n.state==="absent");})||read.objects.some(o=>namespaces.includes(o.namespace as never)&&o.kind!=="excluded"&&(o.kind==="unsupported"||o.read_state!=="read"));
    const validateChain=!unavailable;
    if(!validateChain)issues.add("controls_unavailable");
    const view=capturedStorage(read,{[AUDIT_NAMESPACE]:CHAIN_NAMESPACES[id].entries,[AUDIT_CHECKPOINT_NAMESPACE]:CHAIN_NAMESPACES[id].checkpoints,[AUDIT_META_NAMESPACE]:CHAIN_NAMESPACES[id].meta});
    const epochObject=read.objects.find(o=>o.namespace===CHAIN_NAMESPACES[id].checkpoints&&o.key===AUDIT_EPOCH_KEYS_KEY);
    const epochs=deriveAuditEpochKeys(masterKey);
    try {const count=(epochObject?.read_state==="unreadable"||(!epochObject&&read.namespaces.some(n=>n.namespace===CHAIN_NAMESPACES[id].checkpoints&&(n.state==="unreadable"||n.state==="invalid"))))?{status:"absent" as const}:await readCustodyEpochCount(view,epochs);B.requireSplit(count.status!=="tampered","source_control_invalid");const attempts=read.objects.filter(o=>o.namespace===CHAIN_NAMESPACES[id].entries&&o.kind==="entry").length*(1+(count.status==="present"?count.count:0));B.requireSplit(attempts<=MAX_SOURCE_DECRYPT_ATTEMPTS-decryptAttempts,"limit_exceeded");decryptAttempts+=attempts;}
    finally {epochs.epochWrapKey.fill(0);epochs.epochMacKey.fill(0);}
    const checkpoints=p.records[id].filter(r=>r.record.type==="checkpoint").map(r=>B.parsePersistedCheckpoint(r.source.bytes!));
    const keys=new Map<string,Awaited<ReturnType<typeof resolveKey>>>();
    for(const cp of checkpoints)if(cp.signer_kid&&!keys.has(cp.signer_kid)) {const resolved=await resolveKey(cp.signer_kid);B.requireSplit(!Array.isArray(resolved)||resolved.length<=C.MAX_KEYS,"limit_exceeded");keys.set(cp.signer_kid,resolved);}
    const validated=await AuditLog.validateCapturedControls({storage:view,masterKey,signal,validateChain,checkpoints,checkpointPublicKeyResolver:kid=>keys.get(kid),admit:()=>{
      // Must match AuditLog.validateCapturedControls in operational/audit-log.ts; charge every planned span and signature before its one load pass.
      for(const cp of checkpoints){if(validateChain)budget.charge("leaves",cp.checkpoint_sequence-cp.from_sequence+1);if(!cp.unsigned){const resolved=keys.get(cp.signer_kid!);budget.charge("signatures",(validateChain?2:1)*(Array.isArray(resolved)?resolved.length:resolved?1:0));}}
    }});
    checkSignal(signal);B.requireSplit(!validated.invalidControl,"source_control_invalid");
    for(const finding of validated.findings) {
      if(finding.kind==="storage_unavailable"||finding.kind==="checkpoint_signature_unverifiable"||finding.kind==="checkpoint_signature_embedded_key_untrusted") {issues.add("controls_unavailable");controls[id].issues=["controls_unavailable"];}
      else B.requireSplit(!isHardIntegrityFinding(finding)&&!finding.kind.startsWith("checkpoint_signing_"),"source_control_invalid");
    }
    if(validateChain&&!validated.unavailableControl&&!validated.findings.some(f=>f.kind==="storage_unavailable"||f.kind==="checkpoint_signature_unverifiable"||f.kind==="checkpoint_signature_embedded_key_untrusted"))controls[id]={state:"operator_checked",issues:[]};
    if(id==="daemon")daemonGenesis=validated.genesis;
    if(read.objects.some(o=>o.namespace===CHAIN_NAMESPACES[id].checkpoints&&o.key===AUDIT_ROTATION_ANCHOR_KEY))issues.add("pruned_history");
  }
  let migration:B.Census["migration"]={state:"unavailable",reason:"migration_unavailable"};
  const boundary=read.objects.find(o=>o.namespace===BOUNDARY.namespace&&o.rawName===BOUNDARY.name),macKey=deriveAuditStoreSplitBoundaryMacKey(masterKey);
  try {
    const markerObject=read.objects.find(o=>o.namespace===CHAIN_NAMESPACES.operator.meta&&o.key===AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY);
    const metaUnavailable=read.namespaces.some(n=>n.namespace===CHAIN_NAMESPACES.operator.meta&&(n.state==="unreadable"||n.state==="invalid"));
    const marker=markerObject?.read_state==="unreadable"||(!markerObject&&metaUnavailable)?null:await readAuditStoreSplitEstablishedMarker(storage,macKey);
    B.requireSplit(marker!=="invalid_or_unreadable","migration_invalid");
    if(boundary?.read_state==="read") {
      const parsed=validateAuditStoreSplitBoundaryBytes(boundary.bytes!,macKey);
      // Raw presence is stronger than the legacy parser's absent result.
      B.requireSplit(parsed.status==="valid","migration_invalid");
      if(marker===null)issues.add("migration_unavailable");
      else B.requireSplit(marker==="present","migration_invalid");
      const b=parsed.boundary;
      if(b.sealed_tip_sequence>0&&read.namespaces.some(n=>n.namespace===CHAIN_NAMESPACES.operator.entries&&n.state==="absent")){controls.operator={state:"unavailable",issues:["missing_history","controls_unavailable"]};issues.add("missing_history");}
      B.requireSplit(b.daemon_namespace===CHAIN_NAMESPACES.daemon.entries,"migration_invalid");
      if(daemonGenesis&&controls.daemon.state==="operator_checked"&&marker==="present") {
        const e=daemonGenesis.entry,d=e.details;
        B.requireSplit(e.operation===AUDIT_STORE_SPLIT_MIGRATION_OP&&e.result==="success"&&d?.legacy_namespace===CHAIN_NAMESPACES.operator.entries&&d.legacy_tip_sequence===b.sealed_tip_sequence&&d.legacy_tip_entry_hash===b.sealed_tip_entry_hash&&d.daemon_namespace===b.daemon_namespace,"migration_invalid");
        migration={state:"operator_checked",sealed_base_sequence:b.sealed_base_sequence,sealed_tip_sequence:b.sealed_tip_sequence,sealed_tip_entry_hash:b.sealed_tip_entry_hash,daemon_namespace:CHAIN_NAMESPACES.daemon.entries,daemon_genesis_entry_hash:daemonGenesis.entry_hash,genesis_binding:"operator_checked"};
      }
    }
  } finally {macKey.fill(0);}
  if(migration.state!=="operator_checked")issues.add("migration_unavailable");
  let floor:B.Census["transparency_floor"]={state:"unavailable",reason:"controls_unavailable"};
  const floorObject=read.objects.find(o=>o.namespace===CHAIN_NAMESPACES.operator.meta&&o.key===TRANSPARENCY_FLOOR_META_KEY);
  if(floorObject?.read_state==="unreadable"||(!floorObject&&read.namespaces.some(n=>n.namespace===CHAIN_NAMESPACES.operator.meta&&(n.state==="unreadable"||n.state==="invalid"))))issues.add("controls_unavailable");
  else {
    const result=await readTransparencyCounterFloor(storage,masterKey);B.requireSplit(result.status!=="invalid","source_control_invalid");
    floor=result.status==="valid"?{state:"operator_checked",highest_counter:result.highest_counter}:{state:"absent"};
  }
  checkSignal(signal);return {controls,migration,floor,issues:[...issues]};
}
export interface SplitGatherDependencies {readonly io:SourceIO;readonly read:typeof readSplitSource;readonly census:typeof censusSplitSource;readonly validate:typeof validateSplitSource;readonly recheck:typeof recheckSplitSource;readonly budget:()=>B.Budget}
export interface SplitGather {readonly projection:SourceProjection;readonly validation:SourceValidation;readonly stable:boolean}
/** Discard an unavailable chain's partial read set; no individual read record is claimed without its output mapping. */
function retainUsableChains(p:SourceProjection,validation:SourceValidation):SourceProjection {
  const abandoned=B.CHAIN_IDS.filter(id=>{
    const namespace=CHAIN_NAMESPACES[id].entries;
    return p.read.namespaces.some(n=>n.namespace===namespace&&(n.state==="unreadable"||(n.state==="absent"&&validation.controls[id].state==="unavailable")))||p.read.objects.some(o=>o.namespace===namespace&&o.kind==="entry"&&o.read_state!=="read");
  });
  if(!abandoned.length)return p;
  const scopes=new Set(abandoned.flatMap(id=>Object.values(CHAIN_NAMESPACES[id]))),records={...p.records};for(const id of abandoned)records[id]=[];
  // Other readable controls were already checked; known hard failures cannot reach this diagnostic projection.
  return {...p,records,read:{...p.read,objects:p.read.objects.filter(o=>!scopes.has(o.namespace as never)),namespaces:p.read.namespaces.map(n=>scopes.has(n.namespace as never)?{...n,state:"unreadable",names:null}:n)}};
}
/** A refused stable history has unknown counts and no retained record bytes. */
function diagnosticProjection(read:SourceReadSet,reason:B.PartialCode):SourceProjection {
  return {topology:"split",read:{...read,objects:[],identity:[],namespaces:read.namespaces.map(n=>({...n,state:"unreadable",names:null})),issues:[reason],limited:reason==="source_limit"},records:{operator:[],daemon:[]},transparency:[],issues:[reason]};
}
function diagnosticValidation(reason:B.PartialCode):SourceValidation {
  return {controls:{operator:{state:"unavailable",issues:["controls_unavailable"]},daemon:{state:"unavailable",issues:["controls_unavailable"]}},migration:{state:"unavailable",reason:"migration_unavailable"},floor:{state:"unavailable",reason:"controls_unavailable"},issues:[reason,"controls_unavailable","migration_unavailable"]};
}
/** Compose the required bounded stages; a second change discards all unstable signature/count observations. */
export async function gatherSplitSource(root:string,masterKey:Uint8Array,resolveKey:SourceValidationInput["resolveKey"],signal:AbortSignal,deps:SplitGatherDependencies):Promise<SplitGather> {
  for(let attempt=0;attempt<SOURCE_ATTEMPTS;attempt++) {
    let read:SourceReadSet|undefined;
    try {
      checkSignal(signal);read=await deps.read(root,deps.io,signal);
      if(read.hard.length)throw new B.SplitError(read.hard[0]);
      await preflightSplitControls(read,masterKey,signal);
      const projection=await deps.census(read);B.requireSplit(projection.topology==="split","topology_ambiguous");
      // Validation precedes recheck so a known hard failure cannot become a retryable source-change diagnostic.
      const validation=await deps.validate({projection,masterKey,resolveKey,budget:deps.budget(),signal});checkSignal(signal);
      if(await deps.recheck(read,signal)){checkSignal(signal);return {projection:retainUsableChains(projection,validation),validation,stable:true};}
      if(attempt===SOURCE_ATTEMPTS-1)return {projection:diagnosticProjection(read,"source_changed"),validation:diagnosticValidation("source_changed"),stable:false};
    } catch(error) {
      checkSignal(signal);
      const code=error instanceof B.SplitError||error instanceof C.SnapshotError?error.code:null;
      if(code==="snapshot_changed") {
        if(attempt<SOURCE_ATTEMPTS-1)continue;
        // An exhausted capture race has no stable history; discard every abandoned byte and count.
        const observed=new Date().toISOString();
        const unavailable:SourceReadSet={mode:"READ",splitEvidenceObserved:true,root,namespaces:SOURCE_NAMESPACES.map(namespace=>({namespace,state:"unreadable",names:null})),objects:[],issues:["source_changed"],bytesRead:0,objectsSeen:0,identity:[],started:observed,ended:observed,limited:false,hard:[],io:deps.io};
        return {projection:diagnosticProjection(unavailable,"source_changed"),validation:diagnosticValidation("source_changed"),stable:false};
      }
      if(code==="limit_exceeded"&&read) {
        const projection=diagnosticProjection(read,"source_limit");
        // The same required dependency observes the unavailable scopes; it cannot produce operator_checked over this diagnostic set.
        await deps.validate({projection,masterKey,resolveKey,budget:deps.budget(),signal});checkSignal(signal);
        return {projection,validation:diagnosticValidation("source_limit"),stable:false};
      }
      throw error;
    }
  }
  throw new B.SplitError("io_error");
}
