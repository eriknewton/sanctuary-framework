/** Build bounded public statements from validated captured source observations. */
import {sign,type StoredIdentity} from "../core/identity.js";
import {derivePurposeKey} from "../core/key-derivation.js";
import {computeAuditRoot} from "../audit/chain.js";
import {checkpointPayloadHash} from "../transparency/verify.js";
import {TRANSPARENCY_BUNDLE_FORMAT} from "../transparency/checkpoint.js";
import {renderMarkdownDocumentsToPdf} from "../compliance/eu_ai_act/pdf.js";
import {CHAIN_NAMESPACES} from "../audit/split-evidence-registry.js";
import type {SourceObject} from "../audit/split-evidence-source.js";
import type {SplitGather} from "./split-statement-gather.js";
import type {CastlePin} from "./snapshot-gather.js";
import {projectIdentity,snapshotJSON} from "./snapshot-generate.js";
import {verifySplitNested,verifySplitTransparency} from "./split-statement-nested.js";
import {validateSplitPins} from "./split-statement-verify.js";
import {splitRecipient} from "./split-statement-recipient.js";
import * as B from "./split-statement-contract.js";
import * as C from "./snapshot-contract.js";
export interface SplitBuildInput {readonly gathered:SplitGather;readonly signer:StoredIdentity;readonly identities:readonly StoredIdentity[];readonly transparencyPin:CastlePin|null;readonly fortressId:string;readonly exportId:string;readonly generatedAt:string;readonly sourceRevision:string;readonly budget:B.Budget}
export interface SplitPlan {readonly files:Map<string,Uint8Array>;readonly manifest:B.Manifest;readonly trust:Uint8Array;readonly chains:readonly [B.ChainResult,B.ChainResult];readonly partial:readonly B.PartialCode[];readonly assignments:B.Result["transparency_assignments"];readonly nested:B.Result["nested"];readonly status:"PASS"|"PARTIAL"}
/** Encode finite public structures incrementally, admitting bytes before retaining a container. */
function boundedJSON(value:unknown,limit=C.MAX_FILE_BYTES):Uint8Array {
  const pieces:string[]=[];let used=0;
  const put=(text:string)=>{const count=Buffer.byteLength(text);C.cap(count,limit-used);used+=count;pieces.push(text);};
  const walk=(item:unknown,depth:number):void=>{
    C.cap(depth,C.MAX_JSON_DEPTH);
    if(Array.isArray(item)){put("[");item.forEach((row,index)=>{if(index)put(",");walk(row,depth+1);});put("]");}
    else if(item!==null&&typeof item==="object"){put("{");Object.entries(item).forEach(([key,row],index)=>{if(index)put(",");put(JSON.stringify(key));put(":");walk(row,depth+1);});put("}");}
    else {if(typeof item==="string")C.cap(item.length,C.MAX_JSONL_LINE_BYTES);const text=JSON.stringify(item);B.requireSplit(typeof text==="string");put(text);}
  };
  walk(value,0);put(C.LF);return C.utf8(pieces.join(""));
}
/** A limit retains no source counts, signature evaluations or over-budget record bytes. */
function limitedInput(input:SplitBuildInput):SplitBuildInput {
  const p=input.gathered.projection;
  const budget=new B.Budget();budget.charge("signatures",1);
  return {...input,budget,transparencyPin:null,gathered:{stable:false,projection:{...p,records:{operator:[],daemon:[]},transparency:[],issues:["source_limit"],read:{...p.read,objects:[],identity:[],namespaces:p.read.namespaces.map(n=>({...n,state:"unreadable",names:null})),issues:["source_limit"],limited:true}},validation:{controls:{operator:{state:"unavailable",issues:["source_limit","controls_unavailable"]},daemon:{state:"unavailable",issues:["source_limit","controls_unavailable"]}},migration:{state:"unavailable",reason:"migration_unavailable"},floor:{state:"unavailable",reason:"controls_unavailable"},issues:["source_limit","controls_unavailable","migration_unavailable"]}}};
}
/** Use the recipient budget and emit at most one bounded diagnostic; already found hard failures still refuse. */
export function planSplitStatement(input:SplitBuildInput):SplitPlan {
  // Reserve the outer manifest attempt so planning and the recipient admit the same aggregate signature work.
  try{input.budget.charge("signatures",1);return buildSplitStatement(input);}catch(error){
    if((error instanceof B.SplitError||error instanceof C.SnapshotError)&&error.code==="limit_exceeded")return buildSplitStatement(limitedInput(input));
    throw error;
  }
}
/** Select public keys from the already loaded identity roster; no private identity field reaches the descriptor. */
function buildSplitTrust(input:SplitBuildInput):Uint8Array {
  C.cap(input.signer.rotation_history.length,C.MAX_ROTATION_HOPS);
  const rows=[projectIdentity(input.signer,B.PIN_ROLE.pack)];
  for(const id of B.CHAIN_IDS) {
    const keys=new Map<string,{owner:StoredIdentity;key:string}>();
    for(const r of input.gathered.projection.records[id])if(r.record.type==="checkpoint") {
      const cp=B.parsePersistedCheckpoint(r.source.bytes!);if(cp.unsigned)continue;
      const owner=input.identities.find(who=>who.identity_id===cp.signer_kid);B.requireSplit(owner,"pin_invalid");
      C.cap(owner.rotation_history.length,C.MAX_ROTATION_HOPS);
      const candidates=cp.public_key?[cp.public_key]:[owner.public_key,...owner.rotation_history.map(h=>h.old_public_key)];
      for(const key of candidates){if(!keys.has(key))C.cap(keys.size+1,C.MAX_KEYS);keys.set(key,{owner,key});}
    }
    for(const {owner,key}of keys.values()){C.cap(rows.length+1,C.MAX_KEYS);rows.push(projectIdentity(owner,B.PIN_ROLE[id],key));}
  }
  if(input.transparencyPin) {const pin=input.transparencyPin,fingerprint=C.manifestDigest(C.publicKey(pin.key));rows.push({role:B.PIN_ROLE.transparency,key_id:fingerprint,algorithm:C.ALGORITHM,public_key_base64url:pin.key,fingerprint,rotation_evidence:{kind:C.ROTATION.castle,path_class:pin.pathClass}});}
  rows.sort((a,b)=>(a.role+":"+a.key_id)<(b.role+":"+b.key_id)?-1:1);
  C.cap(rows.length,C.MAX_KEYS);
  const trust=boundedJSON({format:B.TRUST_FORMAT,contract:B.CONTRACT,topology:B.TOPOLOGY,fortress_id:input.fortressId,keys:rows},C.MAX_TRUST_BYTES);
  validateSplitPins({packKey:input.signer.public_key,descriptorBytes:trust,expectedManifestDigest:C.manifestDigest(trust)},input.budget);return trust;
}
/** Hash the exact closed B file set; the shared parser checks role/MIME/name parity. */
export function hashSplitFiles(files:ReadonlyMap<string,Uint8Array>):B.Manifest["files"] {
  return [...files].map(([filename,bytes])=>{const row=Object.entries(B.FIXED_FILES).find(([,value])=>value[0]===filename);B.requireSplit(row,"file_set_mismatch");C.cap(bytes.length,C.MAX_FILE_BYTES);return {filename,role:row[0],content_type:row[1][1],size_bytes:bytes.length,sha256:C.sha256Hex(bytes)};}).sort((a,b)=>a.filename<b.filename?-1:1);
}
/** Plan with shared parsing and nested verification before producing any signed delivery. */
function buildSplitStatement(input:SplitBuildInput):SplitPlan {
  const p=input.gathered.projection,validation=input.gathered.validation,files=new Map<string,Uint8Array>(),mapping=new Map<SourceObject,{filename:string;record_index:number;record_sha256:string}>();
  const component:Record<string,unknown>={census:{state:"included",filename:B.FIXED_FILES.census[0]}},chainRows:Record<string,unknown>[]=[];
  for(const id of B.CHAIN_IDS) {
    const rows=p.records[id],filename=B.FIXED_FILES[`audit-${id}`][0],lines:Uint8Array[]=[];let lineBytes=0;
    for(const row of rows){const bytes=boundedJSON(row.record,C.MAX_JSONL_LINE_BYTES+C.utf8(C.LF).length);C.cap(bytes.length,C.MAX_FILE_BYTES-lineBytes);lineBytes+=bytes.length;lines.push(bytes);}
    const entries=rows.filter(r=>r.record.type==="entry").map(r=>r.record),checkpoints=rows.filter(r=>r.record.type==="checkpoint").map(r=>B.parsePersistedCheckpoint(r.source.bytes!));
    const scopes=Object.values(CHAIN_NAMESPACES[id]),listed=scopes.every(ns=>p.read.namespaces.some(n=>n.namespace===ns&&(n.state==="listed"||n.state==="absent"))),source=p.read.objects.filter(o=>scopes.includes(o.namespace as never));
    const sourceEntries=source.filter(o=>o.kind==="entry").length,sourceCheckpoints=source.filter(o=>o.kind==="checkpoint").length;
    const skipped=sourceEntries+sourceCheckpoints-rows.length,complete=listed&&skipped===0&&validation.controls[id].state==="operator_checked"&&!source.some(o=>o.kind==="unsupported");
    if(rows.length) {
      const bytes=Buffer.concat(lines,lineBytes);files.set(filename,bytes);
      rows.forEach((r,i)=>mapping.set(r.source,{filename,record_index:i,record_sha256:C.sha256Hex(lines[i].subarray(0,lines[i].length-C.utf8(C.LF).length))}));
      component[id]={state:"included",filename,extent:{entry_count:entries.length,first_sequence:entries[0]?.seq??null,last_sequence:entries.at(-1)?.seq??null,head_hash:entries.at(-1)?.entry_hash??null,checkpoint_count:checkpoints.length,first_checkpoint_sequence:checkpoints[0]?.checkpoint_sequence??null,last_checkpoint_sequence:checkpoints.at(-1)?.checkpoint_sequence??null,merkle_root:computeAuditRoot(entries.map(e=>e.entry_hash as string))}};
    } else component[id]=complete?{state:"empty_verified",reason:"no_records"}:{state:"read_failed",reason:p.issues.includes("source_limit")?"source_limit":p.issues.includes("source_changed")?"source_changed":p.issues.includes("source_unreadable")?"source_unreadable":"missing_history"};
    chainRows.push({chain_id:id,census_state:complete?(entries.length||checkpoints.length?"complete":"empty"):rows.length?"incomplete":"unavailable",source_entries:listed?sourceEntries:null,source_checkpoints:listed?sourceCheckpoints:null,exported_entries:rows.length?entries.length:complete?0:null,exported_checkpoints:rows.length?checkpoints.length:complete?0:null,skipped:listed?skipped:null,controls_state:validation.controls[id].state,controls_issues:validation.controls[id].issues});
  }
  const windows=p.transparency.map(r=>r.record);
  if(windows.length&&input.transparencyPin) {
    const bundle={format:TRANSPARENCY_BUNDLE_FORMAT,exported_at:input.generatedAt,public_key:input.transparencyPin.key,checkpoints:windows};
    const bytes=boundedJSON(bundle);C.cap(bytes.length,C.MAX_FILE_BYTES);const parsed=B.parseTransparency(bytes,new B.Budget());
    B.requireSplit(parsed.checkpoints.every(c=>c.public_key===input.transparencyPin!.key),"pin_invalid");
    const filename=C.TRANSPARENCY_FILENAME;files.set(filename,bytes);
    p.transparency.forEach((r,i)=>mapping.set(r.source,{filename,record_index:i,record_sha256:C.sha256Hex(C.utf8(JSON.stringify(r.record)))}));
    component.transparency={state:"included",filename,extent:{checkpoint_count:windows.length,first_counter:parsed.checkpoints[0].counter,last_counter:parsed.checkpoints.at(-1)!.counter,last_checkpoint_payload_sha256:checkpointPayloadHash(parsed.checkpoints.at(-1)!),fortress_id:input.fortressId}};
  } else component.transparency={state:"read_failed",reason:windows.length?"controls_unavailable":"transparency_absent"};
  const issues=new Set(validation.issues);if(windows.length&&!input.transparencyPin)issues.add("controls_unavailable");
  const objects=p.read.objects.map(o=>{
    const omitted=(o.kind==="entry"||o.kind==="checkpoint")&&o.read_state==="read"&&!mapping.has(o);
    // Must match parseCensus in split-statement-contract.ts; omitted legacy bytes are not a delivered read claim.
    return {namespace:o.namespace,name_digest:C.sha256Hex(C.utf8(o.rawName)),kind:omitted?"unsupported":o.kind,read_state:omitted?"absent":o.read_state,source_sha256:omitted?null:o.digest,output:mapping.get(o)??null};
  }).sort((a,b)=>(a.namespace+":"+a.name_digest)<(b.namespace+":"+b.name_digest)?-1:1);
  const census=B.parseCensus(boundedJSON({format:B.CENSUS_FORMAT,export_id:input.exportId,fortress_id:input.fortressId,observed_from:p.read.started,observed_to:p.read.ended,state:issues.size===0&&chainRows.every(r=>r.census_state==="complete"||r.census_state==="empty")?"complete":"incomplete",namespaces:p.read.namespaces.map(n=>({namespace:n.namespace,state:n.state,listed_count:n.names?.length??null})),objects,chains:chainRows,migration:validation.migration,transparency_floor:validation.floor,issues:[...issues]}));
  files.set(B.FIXED_FILES.census[0],boundedJSON(census));const trust=buildSplitTrust(input);files.set(C.TRUST_FILENAME,trust);
  // These schema-only placeholders never escape planning or create a verified capability.
  for(const name of [C.REPORT_FILENAME,C.PDF_FILENAME,C.RECIPIENT_FILENAME])files.set(name,C.utf8("pending"));
  const provisional={format:B.FORMAT,contract:B.CONTRACT,topology:B.TOPOLOGY,fortress_id:input.fortressId,signature_scheme:C.SIGNATURE_SCHEME,hash_algorithm:C.HASH_ALGORITHM,export_id:input.exportId,generated_at:input.generatedAt,source_revision:input.sourceRevision,signer:{identity_id:input.signer.identity_id,public_key_base64url:input.signer.public_key},files:hashSplitFiles(files),components:component,extensions:[],manifest_signature:Buffer.alloc(C.SIGNATURE_BYTES).toString("base64url")};
  const parsed=B.parseSplitStatement(provisional,trust,files,input.budget);B.requireSplit(parsed.kind==="parsed",parsed.kind==="rejected"?parsed.code:"nested_invalid");
  const nested=verifySplitNested(parsed.value);
  // Known hard chain evidence must refuse before later bounded transparency work can exhaust its allowance.
  B.requireSplit(nested.hard.length===0,nested.hard[0]??"nested_invalid");
  const transparency=verifySplitTransparency(parsed.value,nested);B.requireSplit(transparency.hard.length===0,transparency.hard[0]??"nested_invalid");
  const partial=[...new Set([...nested.partial,...transparency.partial])],status=partial.length?"PARTIAL":"PASS",rendered=B.renderChains(nested.chains),recipient=splitRecipient(nested.chains);
  const report=`# Sanctuary split-host statement\n\nExport id: ${input.exportId}\nGenerated at: ${input.generatedAt}\n\n${status==="PASS"?B.PASS_SENTENCE:C.HUMAN.PARTIAL}\n\n${rendered.historical_signatures}\n${rendered.coverage.join("\n")}\n\n${rendered.sentences.join("\n\n")}\n\n${partial.join("\n")}\n\n${C.NOT_CHECKED.join(" ")}\n\n${recipient}`;
  files.set(C.REPORT_FILENAME,C.utf8(report));files.set(C.RECIPIENT_FILENAME,C.utf8(recipient));files.set(C.PDF_FILENAME,renderMarkdownDocumentsToPdf([{title:"Sanctuary split-host statement",markdown:report}],{footerLabel:"Sanctuary split-host statement",footerDigestLabel:"Export id",footerDigest:input.exportId}));
  const manifest=B.parseManifest({...provisional,files:hashSplitFiles(files)});C.cap([...files.values()].reduce((n,b)=>n+b.length,0)+snapshotJSON(manifest).length,C.MAX_PACK_BYTES);
  return {files,manifest,trust,chains:nested.chains,partial,assignments:transparency.assignments,nested:{operator:nested.chains[0],daemon:nested.chains[1],transparency:transparency.report},status};
}
/** Sign once in the dedicated manifest domain, preserving every original ordinary checkpoint byte. */
export function signSplitPlan(plan:SplitPlan,signer:StoredIdentity,masterKey:Uint8Array):Uint8Array {
  const key=derivePurposeKey(masterKey,"identity-encryption");try {const manifest={...plan.manifest,manifest_signature:Buffer.from(sign(B.manifestSigningBytes(plan.manifest as unknown as Record<string,unknown>),signer.encrypted_private_key,key)).toString("base64url")};B.parseManifest(manifest);return snapshotJSON(manifest);}finally{key.fill(0);}
}
/** Final verification must reproduce the planning result before receipt or stdout can report success. */
export function requireSplitPlanParity(plan:SplitPlan,result:B.Result):void {
  const actual={chains:result.chains,partial:result.partial_reasons,assignments:result.transparency_assignments,nested:result.nested,status:result.status};
  const expected={chains:plan.chains,partial:plan.partial,assignments:plan.assignments,nested:plan.nested,status:plan.status};
  B.requireSplit(C.canonicalSnapshotJSON(actual)===C.canonicalSnapshotJSON(expected),"nested_invalid");
}
