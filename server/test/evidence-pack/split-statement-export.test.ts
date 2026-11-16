// Candidate-only delivery checks; production entry witnesses are maintained separately.
// fail-before-exempt: imports evidence-pack/split-statement-contract.js, which base lacks, so this candidate-only file cannot collect on base.
import {AUDIT_RAW_NAME_GRAMMARS} from "../../src/operational/audit-log.js";
import {describe,it,expect} from "vitest";
import {readFile,writeFile,lstat} from "node:fs/promises";
import {join} from "node:path";
import {splitExportFixture} from "./split-statement-fixtures.js";
import {exportSnapshot} from "../../src/evidence-pack/snapshot-export-cli.js";
import {captureSnapshotDirectory} from "../../src/evidence-pack/snapshot-trust-cli.js";
import {verifySnapshotByFormat} from "../../src/evidence-pack/snapshot-verify.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
async function withExport(run:(x:Awaited<ReturnType<typeof splitExportFixture>>)=>Promise<void>,unsigned=false){const x=await splitExportFixture(unsigned);try{await run(x);}finally{await x.cleanup();}}
async function result(x:Awaited<ReturnType<typeof splitExportFixture>>){const receipt=B.parseReceipt(JSON.parse(await readFile(x.options.receipt,"utf8"))),trust=await readFile(join(x.options.output,C.TRUST_FILENAME));const verified=verifySnapshotByFormat(await captureSnapshotDirectory(x.options.output,x.signer.public_key,receipt.manifest_digest),{packKey:x.signer.public_key,descriptorBytes:trust,expectedManifestDigest:receipt.manifest_digest},x.deps.buildRevision);if(verified.format!==B.RESULT_FORMAT)throw new Error("split result required");return {receipt,verified};}
describe("split statement export",()=>{
 it("delivers a self-verified split statement and matching receipt",()=>withExport(async x=>{expect(await exportSnapshot(x.options,x.deps)).toBe(0);const {receipt,verified}=await result(x);expect(verified.status).toBe("PASS");expect(receipt.chains).toEqual(verified.chains);expect(receipt.rendered).toEqual(B.renderChains(verified.chains));expect(verified.chains.map(c=>c.historical_signatures)).toEqual(["all_pinned","unsigned_present"]);}));
 it("settles its one cleanup before authoritative census",()=>withExport(async x=>{expect(await exportSnapshot(x.options,x.deps)).toBe(0);expect(x.cleanupCalls()).toBe(1);expect(x.states.indexOf("QUIESCE_EXPORT_INSTANCE")).toBeLessThan(x.states.indexOf("CENSUS"));expect(x.states).not.toContain("CLEANUP");}));
 it("refuses delivery if the export instance cannot finish cleanup",()=>withExport(async x=>{const boot=x.deps.boot;x.deps.boot=async input=>({...await boot(input),cleanup:async()=>{throw new Error("synthetic cleanup failure");}});expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);await expect(lstat(x.options.output)).rejects.toMatchObject({code:"ENOENT"});}));
 it("reaches the required source validator through production gathering",()=>withExport(async x=>{let calls=0;const validate=x.deps.source.validate;x.deps.source={...x.deps.source,validate:async input=>{calls++;return validate(input);}};expect(await exportSnapshot(x.options,x.deps)).toBe(0);expect(calls).toBe(1);}));
 it("keeps all_pinned tail coverage visible on every delivered human surface",()=>withExport(async x=>{const phase=x.deps.phase;let appended=false;x.deps.phase=async(state,stage)=>{await phase(state,stage);if(state==="CENSUS"&&!appended){appended=true;for(let i=0;i<3;i++)await x.operator.appendCritical({layer:"l1",operation:"synthetic tail",identity_id:x.signer.identity_id,result:"success"});}};expect(await exportSnapshot(x.options,x.deps)).toBe(10);const {receipt,verified}=await result(x);expect(verified.chains[0]).toMatchObject({historical_signatures:"all_pinned",tail_entries:3,coverage:{checkpointed:{first:1,last:1},tail:{first:2,last:4}}});const rendered=B.renderChains(verified.chains);for(const name of [C.REPORT_FILENAME,C.RECIPIENT_FILENAME]){const text=await readFile(join(x.options.output,name),"utf8");for(const line of [rendered.historical_signatures,...rendered.coverage,...rendered.sentences])expect(text).toContain(line);}const pdf=await readFile(join(x.options.output,C.PDF_FILENAME),"latin1"),pdfText=[...pdf.matchAll(/\(((?:\\.|[^\\)])*)\) Tj/g)].map(m=>m[1].replace(/\\([()\\])/g,"$1")).join("");for(const line of rendered.coverage)expect(pdfText.replace(/\s/g,"")).toContain(line.replace(/\s/g,""));expect(receipt.rendered).toEqual(rendered);for(const line of rendered.coverage)expect(x.stdout.join("")).toContain(line);}));
 it("retains a genuinely unsigned operator as PARTIAL",()=>withExport(async x=>{expect(await exportSnapshot(x.options,x.deps)).toBe(10);const {verified}=await result(x);expect(verified.chains[0].historical_signatures).toBe("unsigned_present");expect(verified.partial_reasons).toContain("checkpoint_unsigned");},true));
 it("keeps unavailable daemon history unevaluated",()=>withExport(async x=>{const io=x.deps.source.io;x.deps.source={...x.deps.source,io:{...io,open:async(...args)=>{if(String(args[0]).endsWith("/_audit-daemon"))throw Object.assign(new Error("synthetic access failure"),{code:"EACCES"});return io.open(...args);}}};expect(await exportSnapshot(x.options,x.deps)).toBe(10);const {verified}=await result(x);expect(verified.chains[1].signatures_unevaluated_reason,"unreadable source reason").toBe("unreadable");expect(verified.chains[1].historical_signatures).toBeNull();expect(verified.chains[1].coverage).toBeNull();expect(x.stdout.join("")).toContain(B.UNSIGNED_SENTENCE);}));
 it("refuses a changed final copy before receipt or success stdout",()=>withExport(async x=>{const phase=x.deps.phase;x.deps.phase=async(state,stage)=>{await phase(state,stage);if(state==="FINAL_VERIFY")await writeFile(join(x.options.output,C.REPORT_FILENAME),"synthetic changed report");};expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);await expect(lstat(x.options.receipt)).rejects.toMatchObject({code:"ENOENT"});}));
 it("retains the committed pack when exclusive receipt creation fails",()=>withExport(async x=>{x.deps.phase=async state=>{if(state==="RECEIPT")await writeFile(x.options.receipt,"existing receipt");};expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);expect(await readFile(x.options.receipt,"utf8")).toBe("existing receipt");expect((await lstat(join(x.options.output,C.MANIFEST_FILENAME))).isFile()).toBe(true);}));
 it.each(["failure","cancelled completion"] as const)("keeps stdout %s from reporting a successful exit",mode=>withExport(async x=>{const controller=new AbortController();x.deps.signal=()=>controller.signal;x.deps.io.stdout=async()=>{if(mode==="failure")throw new Error("synthetic stdout failure");controller.abort();};expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);expect((await lstat(join(x.options.output,C.MANIFEST_FILENAME))).isFile()).toBe(true);}));
 it("keeps a readable invalid signature hard when daemon entries are unavailable",()=>withExport(async x=>{
   const rows=await x.storage.list("_audit-daemon_checkpoints","audit-checkpoint-");const cp=JSON.parse(Buffer.from((await x.storage.read("_audit-daemon_checkpoints",rows[0].key))!).toString());Object.assign(cp,{unsigned:false,signer_kid:x.signer.identity_id,public_key:x.signer.public_key,signature_algorithm:"Ed25519",signature:Buffer.alloc(C.SIGNATURE_BYTES).toString("base64url")});delete cp.unsigned_reason;await x.storage.write("_audit-daemon_checkpoints",rows[0].key,Buffer.from(JSON.stringify(cp)));
   const io=x.deps.source.io;x.deps.source={...x.deps.source,io:{...io,open:async(...args)=>{if(String(args[0]).endsWith("/_audit-daemon"))throw Object.assign(new Error("synthetic access failure"),{code:"EACCES"});return io.open(...args);}}};expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);expect(x.stderr.join("")).toContain("source_control_invalid");
 }));
 it.each(["CLASSIFY","QUIESCE_EXPORT_INSTANCE","CENSUS","READ","VALIDATE_SOURCE","RECHECK_SOURCE","BUILD","SIGN","COMMIT","RECEIPT"])("refuses a fault at %s",state=>withExport(async x=>{x.deps.phase=async current=>{if(current===state)throw new Error("synthetic phase failure");};expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);}));
});

it.each(["leaves","signatures"] as const)("delivers a bounded diagnostic when BUILD reaches the recipient %s ceiling",counter=>withExport(async x=>{
  let allocations=0;x.deps.source={...x.deps.source,budget:()=>{const budget=new B.Budget();if(++allocations===2)budget.charge(counter,counter==="leaves"?B.MAX_LEAF_VISITS:B.MAX_SIGNATURE_ATTEMPTS);return budget;}};
  expect(await exportSnapshot(x.options,x.deps)).toBe(10);const {verified}=await result(x);expect(verified.partial_reasons).toContain("source_limit");for(const chain of verified.chains)expect(chain).toMatchObject({historical_signatures:null,signatures_unevaluated_reason:"source_limit",coverage:null});
}));
it.each(["CENSUS","SIGN","COMMIT","RECEIPT"])("refuses late completion after cancellation at %s",state=>withExport(async x=>{
  const controller=new AbortController();x.deps.signal=()=>controller.signal;let release!:()=>void,admit!:()=>void;const waiting=new Promise<void>(resolve=>{release=resolve;}),admitted=new Promise<void>(resolve=>{admit=resolve;});
  x.deps.phase=async current=>{if(current===state){admit();await waiting;}};
  const run=exportSnapshot(x.options,x.deps);await admitted;controller.abort();release();expect(await run).toBe(1);expect(x.stdout).toEqual([]);
}));

it("preserves the existing explicit V0 gather dependency boundary",()=>withExport(async x=>{
  const {boot,runtimeRevision,buildRevision,phase,io}=x.deps;
  const legacy={boot,runtimeRevision,buildRevision,phase,io,gather:async()=>({audit:{state:"read_failed",reason:"split_store"},transparency:{state:"read_failed",reason:"read_error"}} as const)};
  expect(await exportSnapshot(x.options,legacy)).toBe(10);expect(x.states).not.toContain("CLASSIFY");expect(JSON.parse(await readFile(join(x.options.output,C.MANIFEST_FILENAME),"utf8")).format).toBe(C.SNAPSHOT_FORMAT);expect(x.cleanupCalls()).toBe(1);
}));
it("refuses split output from the V0-only dependency boundary",()=>withExport(async x=>{
  const {boot,runtimeRevision,buildRevision,phase,io}=x.deps;
  const legacy={boot,runtimeRevision,buildRevision,phase,io,gather:async()=>({kind:"split"} as unknown as import("../../src/evidence-pack/snapshot-gather.js").SnapshotGather)};
  expect(await exportSnapshot(x.options,legacy)).toBe(1);expect(x.stderr.join("")).toContain("source_control_invalid");expect(x.stdout).toEqual([]);await expect(lstat(x.options.output)).rejects.toMatchObject({code:"ENOENT"});
}));

it("retains a known migration refusal before subsequent window admission",()=>withExport(async x=>{
  let ordinaryLeaves=0;
  for(const namespace of ["_audit_checkpoints","_audit-daemon_checkpoints"])for(const row of await x.storage.list(namespace,"audit-checkpoint-")){
    const cp=B.parsePersistedCheckpoint((await x.storage.read(namespace,row.key))!);ordinaryLeaves+=cp.checkpoint_sequence-cp.from_sequence+1;
  }
  let allocations=0;const validate=x.deps.source.validate;
  x.deps.source={...x.deps.source,validate:async input=>{const value=await validate(input);expect(value.migration.state).toBe("operator_checked");return {...value,migration:value.migration.state==="operator_checked"?{...value.migration,sealed_tip_entry_hash:"0".repeat(64 /* SHA-256 hexadecimal width */)}:value.migration};},budget:()=>{const budget=new B.Budget();if(++allocations===2)budget.charge("leaves",B.MAX_LEAF_VISITS-ordinaryLeaves);return budget;}};
  expect(await exportSnapshot(x.options,x.deps)).toBe(1);expect(x.stdout).toEqual([]);expect(x.stderr.join("")).toContain("migration_invalid");
}));

it("reads the V0 identity roster after gather and public trust admission",()=>withExport(async x=>{
  const events:string[]=[],list=x.manager.list.bind(x.manager);
  x.manager.list=()=>{events.push("identities");return list();};
  const {boot,runtimeRevision,buildRevision,phase,io}=x.deps;
  const legacy={boot,runtimeRevision,buildRevision,io,
    phase:async(...args:Parameters<typeof phase>)=>{await phase(...args);if(args[0]==="BUILD_PUBLIC_TRUST")events.push(args[0]);},
    gather:async()=>{events.push("gather");return {audit:{state:"read_failed",reason:"split_store"},transparency:{state:"read_failed",reason:"read_error"}} as const;},
  };
  expect(await exportSnapshot(x.options,legacy)).toBe(10);
  expect(events).toEqual(["gather","BUILD_PUBLIC_TRUST","identities"]);
}));

it("delivers a complete split statement with anchor configuration",()=>withExport(async x=>{
 const {TRANSPARENCY_ANCHOR_CONFIG_META_KEY}=await import("../../src/transparency/anchoring.js");
 await x.storage.write("_meta",TRANSPARENCY_ANCHOR_CONFIG_META_KEY,Buffer.from("{}"));
 expect(await exportSnapshot(x.options,x.deps),"configured split export").toBe(0);
 expect((await result(x)).verified.status).toBe("PASS");
}));

it("validates split receipt path capacity before STAGE",()=>withExport(async x=>{
 x.options.output=join(x.root,"p".repeat(220 /* A valid filename with an absolute path beyond the receipt cap. */));
 expect(await exportSnapshot(x.options,x.deps)).toBe(1);
 expect(x.states,"receipt path admitted before staging").not.toContain("STAGE");
 await expect(lstat(x.options.output)).rejects.toMatchObject({code:"ENOENT"});
}));
import {runOfflineCommand} from "../../src/evidence-pack/snapshot-offline-cli.js";
import {splitFixture} from "./split-statement-fixtures.js";
it.each(["pin","capture","key"])("uses the declared split failure schema for %s",stage=>withExport(async x=>{
 const s=splitFixture(),trust=JSON.parse(Buffer.from(s.trust).toString());
 if(stage==="pin")trust.keys=trust.keys.filter((k:any)=>k.role!==B.PIN_ROLE.pack);
 const descriptor=join(x.root,"independent-trust.json"),key=join(x.root,"independent-key.txt");
 await writeFile(descriptor,JSON.stringify(trust));await writeFile(key,stage==="key"?"invalid-key":s.pins.packKey);
 let stdout="";expect(await runOfflineCommand(["--pack",join(x.root,"absent-pack"),"--public-key-file",key,"--trust-descriptor-file",descriptor,"--expect-manifest-digest",s.pins.expectedManifestDigest,"--json"],{stdout:text=>{stdout+=text;},stderr:()=>{}})).toBe(1);
 const failure=JSON.parse(stdout);expect(failure.format,"descriptor-selected failure format").toBe(B.RESULT_FORMAT);
 expect(()=>B.parseResult(failure)).not.toThrow();expect(failure.findings[0].code,"typed early failure").toBe(stage==="capture"?"io_error":"pin_invalid");
}));

it("retained producer incident stays partial",()=>withExport(async x=>{
 const name=`.audit-write.lock.evidence.${process.pid}.${"ab".repeat(AUDIT_RAW_NAME_GRAMMARS.auditClaim.nonceBytes)}.tomb`;
 await writeFile(join(x.state,"_audit",name),"synthetic incident");
 expect(await exportSnapshot(x.options,x.deps),"incident export PARTIAL").toBe(10);
 const {verified}=await result(x);
 expect([verified.status,verified.accepted],"incident never accepted").toEqual(["PARTIAL",false]);
}));
