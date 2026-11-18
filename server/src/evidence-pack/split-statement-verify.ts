/** Pure authentication and final verdict for the expected split statement. */
import { verify } from "../core/identity.js";
import { validateRotationEvidence, type SnapshotPins } from "./snapshot-trust.js";
import * as C from "./snapshot-contract.js";
import * as B from "./split-statement-contract.js";
import { verifySplitNested, verifySplitTransparency, unavailableChain } from "./split-statement-nested.js";
const verifiedBrand:unique symbol=Symbol("verified split statement");
export interface VerifiedSplitStatement { readonly [verifiedBrand]:true; readonly parsed:B.ParsedSplitStatement }
export type SplitVerification = {status:"PASS";accepted:true;exit_code:0;evidence:VerifiedSplitStatement;result:B.Result} | {status:"PARTIAL";accepted:false;exit_code:10;result:B.Result} | {status:"FAIL";accepted:false;exit_code:1;result:B.Result};
function same(a:unknown,b:unknown){return C.canonicalSnapshotJSON(a)===C.canonicalSnapshotJSON(b);}
function fileName(bytes:Uint8Array):string {C.cap(bytes.length,C.MAX_NAME_BYTES);let name:string;try{name=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(bytes);}catch{throw new B.SplitError("unsafe_path");}C.safeName(name);return name;}
function checkMetadata(names:readonly string[]){B.requireSplit(new Set(names).size===names.length&&names.every(n=>C.OS_ATTACHED_METADATA.includes(n)),"unexpected_metadata");}
function stableFile(f:C.CapturedFile){C.validateCapturedStat(f.before);C.validateCapturedStat(f.after);B.requireSplit(f.before.type===C.FILE_TYPE.file&&f.after.type===C.FILE_TYPE.file&&f.before.nlink===1&&f.after.nlink===1,"file_type_invalid");checkMetadata(f.metadata);B.requireSplit(same(f.before,f.after)&&f.bytes.length===f.before.size,"snapshot_changed");}
function finalRecheck(c:C.CapturedSnapshot){B.requireSplit(same(c.rootBefore,c.rootAfter)&&same(c.files.map(f=>fileName(f.name)).sort(),c.finalNames.map(fileName).sort()),"snapshot_changed");for(const f of c.files)stableFile(f);}
/** Independent descriptor pins are validated before any embedded key may influence verification. */
export function validateSplitPins(pins:SnapshotPins,budget = new B.Budget()):B.Trust {
  C.publicKey(pins.packKey);C.text(pins.expectedManifestDigest,C.DIGEST);const trust=B.parseTrust(pins.descriptorBytes);
  B.requireSplit(trust.keys.find(k=>k.role===B.PIN_ROLE.pack)?.public_key_base64url===pins.packKey,"pin_invalid");
  // All outer and nested rotation attempts share the request budget before cryptographic work.
  for(const key of trust.keys){if(key.rotation_evidence.kind===C.ROTATION.history)budget.charge("signatures",key.rotation_evidence.history.length);validateRotationEvidence(key);}return trust;
}
function authenticate(capture:C.CapturedSnapshot,pins:SnapshotPins,budget:B.Budget) {
  const trust=validateSplitPins(pins,budget);C.cap(capture.files.length,C.MAX_FILES);
  C.validateCapturedStat(capture.rootBefore);C.validateCapturedStat(capture.rootAfter);
  B.requireSplit(capture.rootBefore.type===C.FILE_TYPE.directory&&capture.rootAfter.type===C.FILE_TYPE.directory,"file_type_invalid");checkMetadata(capture.rootMetadata);
  const mf=capture.files.filter(f=>fileName(f.name)===C.MANIFEST_FILENAME);B.requireSplit(mf.length===1,"file_set_mismatch");stableFile(mf[0]);
  const raw=B.parseManifestEnvelope(mf[0].bytes);
  // The independent pin authenticates all listed names before any nested schema can claim a subject.
  budget.charge("signatures",1);
  B.requireSplit(verify(B.manifestSigningBytes(raw),C.base64(raw.manifest_signature,C.SIGNATURE_BYTES),C.publicKey(pins.packKey)),"manifest_signature_invalid");
  B.requireSplit(C.manifestDigest(mf[0].bytes)===pins.expectedManifestDigest,"manifest_digest_mismatch");
  const manifest=B.parseManifest(raw);
  B.requireSplit(manifest.signer.public_key_base64url===pins.packKey,"embedded_key_mismatch");
  B.requireSplit(manifest.fortress_id===trust.fortress_id,"descriptor_mismatch");
  const pack=trust.keys.find(k=>k.role===B.PIN_ROLE.pack)!.rotation_evidence;
  B.requireSplit(pack.kind===C.ROTATION.history&&pack.identity_id===manifest.signer.identity_id&&pack.current_public_key===manifest.signer.public_key_base64url,"pin_invalid");
  const expected=[C.MANIFEST_FILENAME,...manifest.files.map(f=>f.filename)].sort();
  B.requireSplit(same(expected,capture.files.map(f=>fileName(f.name)).sort()),"file_set_mismatch");
  let total=0;const files=new Map<string,Uint8Array>();
  for(const f of capture.files){stableFile(f);C.cap(f.bytes.length,C.MAX_FILE_BYTES);total+=f.bytes.length;C.cap(total,C.MAX_PACK_BYTES);const name=fileName(f.name);files.set(name,f.bytes);if(name===C.MANIFEST_FILENAME)continue;const row=manifest.files.find(r=>r.filename===name)!;B.requireSplit(row.size_bytes===f.bytes.length&&row.sha256===C.sha256Hex(f.bytes),"file_digest_mismatch");}
  // Raw descriptor equality binds this recipient's selected role pins, not a delivery-provided replacement.
  B.requireSplit(Buffer.from(files.get(C.TRUST_FILENAME)!).equals(Buffer.from(pins.descriptorBytes)),"descriptor_mismatch");
  for(const e of manifest.extensions)for(const role of e.signing_roles)B.requireSplit(trust.keys.some(k=>k.role===role),"pin_invalid");
  return {manifest,trust,files};
}
/** Candidate extraction authenticates delivery bytes only; copied nested keys remain unauthenticated. */
export function authenticateSplitBytes(capture:C.CapturedSnapshot,packKey:string,expectedManifestDigest:string) {
  const descriptor=capture.files.find(f=>fileName(f.name)===C.TRUST_FILENAME)?.bytes;B.requireSplit(descriptor,"file_set_mismatch");
  authenticate(capture,{packKey,expectedManifestDigest,descriptorBytes:descriptor},new B.Budget());finalRecheck(capture);
  return {candidateDescriptorBytes:descriptor.slice(),keysAuthenticated:false as const};
}
/** Verify an expected archival delivery and construct a capability only after all checks pass. */
export function verifySplitStatement(capture:C.CapturedSnapshot,pins:SnapshotPins,revision:string,budget = new B.Budget()):SplitVerification {
  let state:C.ProtocolState=C.STATES.PIN_INPUTS,authenticated=false,exportId:string|null=null;
  let chains:readonly [B.ChainResult,B.ChainResult]=[unavailableChain("operator","missing_history"),unavailableChain("daemon","missing_history")];
  let assignments:B.Result["transparency_assignments"]=[],transparency:B.Result["nested"]["transparency"]=null;
  const finish=(status:B.Result["status"],hard:readonly B.HardCode[],partial:readonly B.PartialCode[])=>B.parseResult({format:B.RESULT_FORMAT,contract:B.CONTRACT,status,exit_code:status==="PASS"?0:status==="PARTIAL"?10:1,accepted:status==="PASS",snapshot_integrity:authenticated?C.INTEGRITY.bytes_match:C.INTEGRITY.unverified,export_id:exportId,manifest_digest:authenticated?pins.expectedManifestDigest:null,verifier_source_revision:typeof revision === "string" ? revision.slice(0,C.MAX_NAME_BYTES) : "",findings:hard.slice(0,B.MAX_FINDINGS).map(code=>({code,state,filename:null})),findings_total:hard.length,findings_truncated:hard.length>B.MAX_FINDINGS,partial_reasons:status==="PARTIAL"?[...new Set(partial)]:[],chains,transparency_assignments:assignments,nested:{operator:authenticated?chains[0]:null,daemon:authenticated?chains[1]:null,transparency},not_checked:C.NOT_CHECKED});
  try {
    C.text(revision,C.REVISION);state=C.STATES.MANIFEST_AUTHENTICATED;const outer=authenticate(capture,pins,budget);authenticated=true;exportId=outer.manifest.export_id;
    state=C.STATES.NESTED_VERIFIED;const parsed=B.parseSplitStatement(outer.manifest,pins.descriptorBytes,outer.files,budget);B.requireSplit(parsed.kind==="parsed",parsed.kind==="rejected"?parsed.code:"nested_invalid");
    const nested=verifySplitNested(parsed.value);chains=nested.chains;
    const t=verifySplitTransparency(parsed.value,nested);assignments=t.assignments;transparency=t.report;
    const hard=[...new Set([...nested.hard,...t.hard])],partial=[...new Set([...nested.partial,...t.partial])];
    if(outer.manifest.extensions.length||outer.trust.keys.some(k=>k.role.startsWith(C.PIN_ROLE.extension)))partial.push("extension_unverified");
    state=C.STATES.FINAL_RECHECK;finalRecheck(capture);
    if(hard.length)return {status:"FAIL",accepted:false,exit_code:1,result:finish("FAIL",hard,[])};
    if(partial.length)return {status:"PARTIAL",accepted:false,exit_code:10,result:finish("PARTIAL",[],partial)};
    const evidence:VerifiedSplitStatement=Object.freeze({[verifiedBrand]:true as const,parsed:parsed.value});
    return {status:"PASS",accepted:true,exit_code:0,evidence,result:finish("PASS",[],[])};
  }catch(error){const code=error instanceof B.SplitError?error.code:error instanceof C.SnapshotError?error.code:"io_error";return {status:"FAIL",accepted:false,exit_code:1,result:finish("FAIL",[code],[])};}
}
