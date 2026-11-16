/** Pure public linkage and ordinary-signature checks for separately named chains. */
import { verify } from "../core/identity.js";
import { verifyRotationChain } from "../core/rotation-chain.js";
import { computeAuditEntryHash, computeAuditRoot, checkpointSigningBytes } from "../audit/chain.js";
import * as C from "./snapshot-contract.js";
import * as B from "./split-statement-contract.js";
export interface IndexedChain { readonly id: B.ChainId; readonly entries: ReadonlyMap<number,B.Entry>; readonly complete: boolean; readonly result: B.ChainResult }
export interface NestedOutcome { readonly chains: readonly [B.ChainResult,B.ChainResult]; readonly indexes: readonly [IndexedChain,IndexedChain]; readonly hard: readonly B.HardCode[]; readonly partial: readonly B.PartialCode[] }
/** Unknown evidence stays null; this does not assert that a missing chain was empty. */
export function unavailableChain(id: B.ChainId, reason: B.UnevaluatedReason, partial: readonly B.PartialCode[] = []): B.ChainResult {
  return B.parseChainResult({chain_id:id,state:"unavailable",historical_signatures:null,signatures_evaluated:false,signatures_unevaluated_reason:reason,checkpoint_count:null,unsigned_count:null,signatures_verified:null,entries_verified:null,tail_entries:null,coverage:null,partial_reasons:partial});
}
function checkChain(id: B.ChainId, p: B.ParsedSplitStatement, hard: Set<B.HardCode>, partial: Set<B.PartialCode>): IndexedChain {
  const comp=p.manifest.components[id],census=p.census.chains[B.CHAIN_IDS.indexOf(id)],lines=p[id];
  const reasons=new Set<B.PartialCode>(census.controls_issues),entries=new Map<number,B.Entry>();
  const fail=(code:B.HardCode)=>{hard.add(code);}; const incomplete=(code:B.PartialCode)=>{partial.add(code);reasons.add(code);};
  for(const reason of reasons) partial.add(reason);
  if(census.controls_state === "invalid") fail("source_control_invalid");
  else if(census.controls_state !== "operator_checked") incomplete("controls_unavailable");
  if(comp.state === "read_failed") {
    incomplete(comp.reason); const reason:B.UnevaluatedReason=comp.reason === "source_limit" ? "source_limit" : comp.reason === "source_unreadable" ? "unreadable" : "missing_history";
    // A failed component cannot quietly carry delivered rows or claim a completed source census.
    if(lines.length || census.census_state === "complete" || census.census_state === "empty") fail("census_mismatch");
    return {id,entries,complete:false,result:unavailableChain(id,reason,[...reasons])};
  }
  if(comp.state === "empty_verified") {
    if(id === "daemon") fail("migration_invalid");
    const genuinelyEmpty=census.census_state === "empty" && census.controls_state === "operator_checked" && [census.source_entries,census.source_checkpoints,census.exported_entries,census.exported_checkpoints,census.skipped].every(n=>n === 0);
    if(!genuinelyEmpty) {fail("census_mismatch");return {id,entries,complete:false,result:unavailableChain(id,"missing_history")};}
    const result=B.parseChainResult({chain_id:id,state:"empty",historical_signatures:"all_pinned",signatures_evaluated:true,signatures_unevaluated_reason:null,checkpoint_count:0,unsigned_count:0,signatures_verified:0,entries_verified:0,tail_entries:0,coverage:{checkpointed:null,tail:null},partial_reasons:[]});
    return {id,entries,complete:id === "operator",result};
  }
  const checkpoints=lines.flatMap(l=>l.record.type === "checkpoint" ? [l.record.checkpoint] : []);
  let previous:B.Entry|undefined,pruned=false,chainInvalid=false;
  for(const line of lines) {
    if(line.record.type !== "entry")continue;
    const e=line.record;
    // Hash the supplied ciphertext once; a signed claimed entry hash is not evidence of its contents.
    if(computeAuditEntryHash({sequence:e.seq,schema_version:e.schema_version,prev_hash:e.prev_hash,timestamp:e.timestamp,encrypted_payload_bytes:e.encrypted_payload_bytes}) !== e.entry_hash || entries.has(e.seq) || (previous && (e.seq !== previous.seq+1 || e.prev_hash !== previous.entry_hash)) || (!previous && e.seq === 1 && e.prev_hash !== "GENESIS")) {fail("chain_invalid");chainInvalid=true;}
    if(!previous && e.seq !== 1) {pruned=true;incomplete("pruned_history");}
    entries.set(e.seq,e);previous=e;
  }
  const ordered=[...entries.values()],first=ordered[0],last=ordered.at(-1);
  const calculated={entry_count:ordered.length,first_sequence:first?.seq??null,last_sequence:last?.seq??null,head_hash:last?.entry_hash??null,checkpoint_count:checkpoints.length,first_checkpoint_sequence:checkpoints[0]?.checkpoint_sequence??null,last_checkpoint_sequence:checkpoints.at(-1)?.checkpoint_sequence??null,merkle_root:computeAuditRoot(ordered.map(e=>e.entry_hash))};
  if(C.canonicalSnapshotJSON(calculated)!==C.canonicalSnapshotJSON(comp.extent))fail("extent_mismatch");
  if(census.exported_entries!==ordered.length || census.exported_checkpoints!==checkpoints.length)fail("census_mismatch");
  if(census.census_state === "complete") {if(census.source_entries!==ordered.length || census.source_checkpoints!==checkpoints.length || census.skipped!==0)fail("census_mismatch");}
  else incomplete("source_incomplete");
  let unsigned=0,verified=0,signedErrors=census.controls_state === "invalid",previousCheckpoint=0,coveredThrough=0;
  const rolePins=p.trust.keys.filter(k=>k.role === B.PIN_ROLE[id]).map(pin=>{
    const history=pin.rotation_evidence;
    if(history.kind!==C.ROTATION.history)return {pin,rotation:null};
    p.budget.charge("signatures",history.history.length);
    return {pin,rotation:verifyRotationChain({identityId:history.identity_id,currentPublicKey:history.current_public_key,rotationHistory:history.history})};
  });
  for(const cp of checkpoints) {
    // An omitted checkpoint prefix is incomplete; contradictions between delivered predecessors still fail.
    if(cp.checkpoint_sequence <= previousCheckpoint || (previousCheckpoint!==0 && cp.previous_checkpoint_sequence!==previousCheckpoint) || !last || cp.checkpoint_sequence>last.seq)fail("checkpoint_invalid");
    if(previousCheckpoint===0 && cp.previous_checkpoint_sequence!==0)incomplete("checkpoint_coverage_absent");
    if(cp.from_sequence !== coveredThrough+1) {incomplete("checkpoint_coverage_absent");}
    const hashes:string[]=[];
    for(let seq=cp.from_sequence;seq<=cp.checkpoint_sequence;seq++) {
      p.budget.charge("leaves",1); const e=entries.get(seq);
      if(!e) {incomplete("missing_history");break;} hashes.push(e.entry_hash);
    }
    if(hashes.length === cp.checkpoint_sequence-cp.from_sequence+1 && computeAuditRoot(hashes)!==cp.root_hash)fail("checkpoint_invalid");
    if(cp.unsigned) unsigned++;
    else {
      let valid=false;
      for(const {pin,rotation} of rolePins) {
        p.budget.charge("signatures",1);
        const history=pin.rotation_evidence;if(history.kind!==C.ROTATION.history || history.identity_id!==cp.signer_kid)continue;
        if(cp.public_key!==undefined && cp.public_key!==pin.public_key_base64url)continue;
        if(!rotation || rotation.status!=="verified")continue;
        if(pin.public_key_base64url!==history.current_public_key) {const retired=rotation.chain.retired.find(r=>r.public_key_base64url===pin.public_key_base64url);if(!retired || retired.compromised || cp.signed_at>retired.retired_at)continue;}
        if(verify(checkpointSigningBytes({checkpoint_kind:cp.checkpoint_kind,checkpoint_sequence:cp.checkpoint_sequence,from_sequence:cp.from_sequence,root_hash:cp.root_hash,previous_checkpoint_sequence:cp.previous_checkpoint_sequence,signed_at:cp.signed_at}),C.base64(cp.signature,C.SIGNATURE_BYTES),C.publicKey(pin.public_key_base64url))) {valid=true;break;}
      }
      if(valid)verified++;else {signedErrors=true;fail("checkpoint_invalid");}
    }
    previousCheckpoint=cp.checkpoint_sequence;
    // Coverage denotes a contiguous prefix; later spans cannot establish any missing predecessor.
    if(cp.from_sequence<=coveredThrough+1)coveredThrough=Math.max(coveredThrough,cp.checkpoint_sequence);
  }
  if(!checkpoints.length && ordered.length) incomplete("checkpoint_coverage_absent");
  if(unsigned && verified)incomplete("checkpoint_mixed");
  if(id === "operator" && unsigned)incomplete("checkpoint_unsigned");
  const evaluated=checkpoints.length>0 || signedErrors;
  const historical=evaluated ? signedErrors ? "signed_with_errors" : unsigned ? "unsigned_present" : "all_pinned" : null;
  if(id === "daemon" && historical === "all_pinned")fail("daemon_basis_unsupported");
  const tail=ordered.filter(e=>e.seq>coveredThrough);
  if(tail.length)incomplete("audit_tail_unanchored");
  // Retained checkpoints below the retained entry prefix cannot produce a reversed coverage range.
  const checkpointed=first && coveredThrough>=first.seq ? {first:first.seq,last:Math.min(coveredThrough,last!.seq)} : null;
  const result=B.parseChainResult({chain_id:id,state:chainInvalid?"invalid":"included",historical_signatures:historical,signatures_evaluated:evaluated,signatures_unevaluated_reason:evaluated?null:"no_checkpoints",checkpoint_count:checkpoints.length,unsigned_count:unsigned,signatures_verified:verified,entries_verified:ordered.length,tail_entries:tail.length,coverage:{checkpointed,tail:tail.length?{first:tail[0].seq,last:tail.at(-1)!.seq}:null},partial_reasons:[...reasons]});
  // Subject exclusion depends on complete entry bytes; missing ordinary coverage does not hide a known extent.
  return {id,entries,complete:!chainInvalid&&!pruned&&census.census_state === "complete"&&census.controls_state === "operator_checked",result};
}
/** Verify every delivered record is uniquely accounted for by the signed source testimony. */
function reconcile(p:B.ParsedSplitStatement,hard:Set<B.HardCode>,partial:Set<B.PartialCode>):void {
  const c=p.census;
  if(c.export_id!==p.manifest.export_id || c.fortress_id!==p.manifest.fortress_id)hard.add("census_mismatch");
  if(c.state!=="complete")partial.add("source_incomplete");for(const issue of c.issues)partial.add(issue);
  const expected=new Map<string,{hash:string;namespace:string;kind:string}>();
  for(const id of B.CHAIN_IDS)for(const line of p[id]) expected.set(`${B.FIXED_FILES[`audit-${id}`][0]}:${line.index}`,{hash:line.sha256,namespace:(id === "operator"?"_audit":"_audit-daemon")+(line.record.type === "checkpoint"?"_checkpoints":""),kind:line.record.type});
  p.transparency?.checkpoints.forEach((cp,i)=>expected.set(`${C.TRANSPARENCY_FILENAME}:${i}`,{hash:C.sha256Hex(C.utf8(JSON.stringify(cp))),namespace:"_transparency_checkpoints",kind:"checkpoint"}));
  const mapped=new Set<string>(),counts=new Map<string,number>();
  for(const o of c.objects) {
    counts.set(o.namespace,(counts.get(o.namespace)??0)+1);
    if(o.kind === "unsupported")partial.add("unknown_source_object");
    if(o.read_state === "invalid")hard.add("source_control_invalid");
    else if(o.read_state === "unreadable")partial.add("source_unreadable");
    if(o.output) {
      const k=`${o.output.filename}:${o.output.record_index}`,target=expected.get(k);
      if(!target || mapped.has(k) || target.hash!==o.output.record_sha256 || target.namespace!==o.namespace || target.kind!==o.kind || o.read_state!=="read")hard.add("census_mismatch");
      mapped.add(k);
    } else if(o.read_state === "read" && (o.kind === "entry" || o.kind === "checkpoint"))hard.add("census_mismatch");
  }
  if(mapped.size!==expected.size || [...expected.keys()].some(k=>!mapped.has(k)))hard.add("census_mismatch");
  for(const ns of c.namespaces) {
    if(ns.state === "listed" && ns.listed_count!==(counts.get(ns.namespace)??0))hard.add("census_mismatch");
    if(ns.state === "absent" && counts.has(ns.namespace))hard.add("census_mismatch");
    if(ns.state === "unreadable" || ns.state === "invalid")partial.add("source_incomplete");
  }
  if([...counts.keys()].some(ns=>!c.namespaces.some(n=>n.namespace===ns)))hard.add("census_mismatch");
}
/** Recompute ordinary evidence and public migration linkage; transparency is composed separately. */
export function verifySplitNested(p:B.ParsedSplitStatement):NestedOutcome {
  const hard=new Set<B.HardCode>(),partial=new Set<B.PartialCode>();
  reconcile(p,hard,partial);
  const operator=checkChain("operator",p,hard,partial),daemon=checkChain("daemon",p,hard,partial);
  const m=p.census.migration;
  if(m.state === "invalid")hard.add("migration_invalid");
  else if(m.state === "unavailable")partial.add("migration_unavailable");
  else {
    // These assertions bind the operator's local check to the exact public chains, not to an independent witness.
    if(m.sealed_tip_sequence === 0) {if(m.sealed_base_sequence!==0 || m.sealed_tip_entry_hash!=="GENESIS")hard.add("migration_invalid");}
    else {
      if(m.sealed_base_sequence!==1)partial.add("pruned_history");
      const tip=operator.entries.get(m.sealed_tip_sequence);
      if(tip ? tip.entry_hash!==m.sealed_tip_entry_hash : operator.complete)hard.add("migration_invalid");else if(!tip)partial.add("missing_history");
    }
    if(operator.result.state === "empty" && m.sealed_tip_sequence!==0)hard.add("migration_invalid");
    const genesis=daemon.entries.get(1);
    if(genesis ? genesis.prev_hash!=="GENESIS" || genesis.entry_hash!==m.daemon_genesis_entry_hash : daemon.complete)hard.add("migration_invalid");else if(!genesis)partial.add("missing_history");
  }
  return {chains:[operator.result,daemon.result],indexes:[operator,daemon],hard:[...hard],partial:[...partial]};
}

import { createHash } from "node:crypto";
import { verifyTransparencyCounterChain, checkpointPayloadHash, TRANSPARENCY_AUDIT_CONTENTS_NOT_CHECKED } from "../transparency/verify.js";
/** Recompute unique nonempty subjects without treating timestamps or claimed chain labels as authority. */
export function verifySplitTransparency(p:B.ParsedSplitStatement,nested:NestedOutcome) {
  const hard=new Set<B.HardCode>(),partial=new Set<B.PartialCode>();
  const assignments:{counter:number;chain_id:B.ChainId}[]=[];
  const windowFindings:{code:"transparency_window_unavailable";counter:number}[]=[];let windowFindingsTotal=0;
  // Must match parseResult in split-statement-contract.ts; retain bounded counter diagnostics without hiding their total.
  const unavailableWindow=(counter:number)=>{partial.add("transparency_window_unavailable");windowFindingsTotal++;if(windowFindings.length<B.MAX_FINDINGS)windowFindings.push({code:"transparency_window_unavailable",counter});};
  const bundle=p.transparency,component=p.manifest.components.transparency;
  if(!bundle) {partial.add("transparency_absent");return {hard:[...hard],partial:[...partial],assignments,report:null};}
  const pins=p.trust.keys.filter(k=>k.role === B.PIN_ROLE.transparency);
  B.requireSplit(pins.length === 1,"pin_invalid");
  p.budget.charge("signatures",bundle.checkpoints.length);
  // Must match verifyTransparencyCounterChain in transparency/verify.ts: subject checks are mandatory here, never an unchecked skip option.
  const report=verifyTransparencyCounterChain(bundle,{publicKey:pins[0].public_key_base64url,trustEmbedded:false,allowPartial:true});
  if(report.verdict === "FAIL")hard.add("nested_invalid");
  if(report.verdict === "PARTIAL")partial.add("transparency_prefix_unverified");
  const checkpoints=[...bundle.checkpoints].sort((a,b)=>a.counter-b.counter);
  if(checkpoints.some(cp=>cp.fortress_id!==p.manifest.fortress_id || cp.public_key!==pins[0].public_key_base64url) || bundle.public_key!==pins[0].public_key_base64url)hard.add("transparency_subject_mismatch");
  const actualExtent={checkpoint_count:checkpoints.length,first_counter:checkpoints[0].counter,last_counter:checkpoints.at(-1)!.counter,last_checkpoint_payload_sha256:checkpointPayloadHash(checkpoints.at(-1)!),fortress_id:p.manifest.fortress_id};
  if(component.state!=="included" || C.canonicalSnapshotJSON(actualExtent)!==C.canonicalSnapshotJSON(component.extent))hard.add("extent_mismatch");
  const floor=p.census.transparency_floor;
  if(floor.state === "invalid")hard.add("source_control_invalid");
  else if(floor.state!=="operator_checked")partial.add("controls_unavailable");
  else if(floor.highest_counter!==checkpoints.at(-1)!.counter)hard.add("census_mismatch");
  const matches=new Map<number,B.ChainId[]>(),unknown=new Set<number>();
  for(const chain of nested.indexes) {
    const groups=new Map<number,typeof checkpoints>();
    const first=chain.entries.keys().next().value;
    const last=[...chain.entries.keys()].at(-1);
    for(const cp of checkpoints) {
      const w=cp.audit;
      if(w.entry_count === 0)continue;
      const available=first!==undefined && last!==undefined && w.lowest_sequence>=first && w.highest_sequence<=last;
      if(!available) {if(!chain.complete)unknown.add(cp.counter);continue;}
      const group=groups.get(w.lowest_sequence)??[];group.push(cp);groups.set(w.lowest_sequence,group);
    }
    for(const [low,windows] of groups) {
      windows.sort((a,b)=>a.audit.highest_sequence-b.audit.highest_sequence);
      const hash=createHash("sha256").update('{"leaf_hashes":[');let seq=low;let gap=false;
      for(const cp of windows) {
        // Charge each leaf once per candidate/lowest group; repeated prefix endpoints clone bounded hash state only.
        while(seq<=cp.audit.highest_sequence) {
          p.budget.charge("leaves",1);const entry=chain.entries.get(seq);
          if(!entry){gap=true;break;}
          if(seq>low)hash.update(",");hash.update(JSON.stringify(entry.entry_hash));seq++;
        }
        if(gap){if(!chain.complete)unknown.add(cp.counter);continue;}
        const root=hash.copy().update("]}").digest("hex"),head=chain.entries.get(cp.audit.highest_sequence)!;
        if(root===cp.audit.merkle_root && head.entry_hash===cp.audit.head_hash) {const ids=matches.get(cp.counter)??[];ids.push(chain.id);matches.set(cp.counter,ids);}
      }
    }
  }
  const heads=new Map<B.ChainId,number>();
  for(const cp of checkpoints) {
    if(cp.audit.entry_count===0){unavailableWindow(cp.counter);continue;}
    const ids=matches.get(cp.counter)??[];
    if(ids.length>1){hard.add("transparency_subject_mismatch");continue;}
    if(unknown.has(cp.counter)){unavailableWindow(cp.counter);continue;}
    if(ids.length!==1){hard.add("transparency_subject_mismatch");continue;}
    const id=ids[0];
    if(cp.audit.highest_sequence<(heads.get(id)??0))hard.add("transparency_subject_mismatch");
    heads.set(id,cp.audit.highest_sequence);assignments.push({counter:cp.counter,chain_id:id});
  }
  // Must match TRANSPARENCY_AUDIT_CONTENTS_NOT_CHECKED in transparency/verify.ts: B recomputes delivered windows but inherits every other offline limit.
  const notChecked=report.not_checked.filter(note=>note!==TRANSPARENCY_AUDIT_CONTENTS_NOT_CHECKED);
  if(windowFindingsTotal)notChecked.push("Audit windows without a unique complete assignment remain unverified.");
  const verdict:B.Result["status"]=hard.size?"FAIL":partial.size?"PARTIAL":"PASS";
  return {hard:[...hard],partial:[...partial],assignments,report:{verdict,checkpoints_verified:report.checkpoints_verified,window_findings:windowFindings,window_findings_total:windowFindingsTotal,window_findings_truncated:windowFindingsTotal>B.MAX_FINDINGS,not_checked:notChecked}};
}
