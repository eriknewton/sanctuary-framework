// Semantic entry witness: imports only modules present at the original base and committed public bytes.
import {describe,expect,it} from "vitest";
import {readFileSync} from "node:fs";
import {mkdir,mkdtemp,writeFile} from "node:fs/promises";
import {disposePhysicalFixture} from "./split-statement-dispose.js";
import {resolve,join} from "node:path";
import {verifySnapshot} from "../../src/evidence-pack/snapshot-verify.js";
import {captureSnapshotDirectory} from "../../src/evidence-pack/snapshot-trust-cli.js";
const corpus=JSON.parse(readFileSync(new URL("./fixtures/split-statement-static-packs.json",import.meta.url),"utf8"));
const sample=corpus.cases.find((c:any)=>c.name==="complete");
const revision=corpus.provenance.source_base;
const pins={packKey:sample.pins.packKey,descriptorBytes:Buffer.from(sample.pins.descriptor_base64,"base64"),expectedManifestDigest:sample.pins.expectedManifestDigest,format:"SANCTUARY_EVIDENCE_SPLIT_TRUST_V1" as const};
const bytes=Object.entries(sample.files).map(([name,data])=>({name,bytes:Buffer.from(data as string,"base64")}));
const stat=(size:number,type="file")=>({type,size,nlink:1,dev:"1",ino:"1",mtime:"fixed",ctime:"fixed"});
describe("split recipient production entry",()=>{
 it("accepts the complete static split statement through the existing verifier",()=>{
   const files=bytes.map(f=>({name:Buffer.from(f.name),bytes:f.bytes,before:stat(f.bytes.length),after:stat(f.bytes.length),metadata:[]}));
   const capture={files,rootBefore:stat(0,"directory"),rootAfter:stat(0,"directory"),finalNames:files.map(f=>f.name),rootMetadata:[]};
   const result=verifySnapshot(capture,pins,revision);
   expect([result.status,result.exit_code,result.accepted]).toEqual(["PASS",0,true]);
 });
 it("captures the static split statement before verifying it",async()=>{
   const parent=resolve(import.meta.dirname,"../../../.scratch");await mkdir(parent,{recursive:true});
   const root=await mkdtemp(join(parent,"split-semantic-1-")),pack=join(root,"pack");
   try {
     await mkdir(pack);
     for(const f of bytes)await writeFile(join(pack,f.name),f.bytes,{flag:"wx"});
     await expect(captureSnapshotDirectory(pack,pins.packKey,pins.expectedManifestDigest).then(captured=>verifySnapshot(captured,pins,revision).status)).resolves.toBe("PASS");
   } finally {
     await disposePhysicalFixture(root);
   }
 });
});

it.each(corpus.cases as {name:string;[key:string]:any}[])("verifies static corpus $name",sample=>{
 const files=Object.entries(sample.files).map(([name,data])=>{const bytes=Buffer.from(data as string,"base64");return {name:Buffer.from(name),bytes,before:stat(bytes.length),after:stat(bytes.length),metadata:[]};});
 const capture={files,rootBefore:stat(0,"directory"),rootAfter:stat(0,"directory"),finalNames:files.map(f=>f.name),rootMetadata:[]};
 const result=verifySnapshot(capture,{packKey:sample.pins.packKey,descriptorBytes:Buffer.from(sample.pins.descriptor_base64,"base64"),expectedManifestDigest:sample.pins.expectedManifestDigest,format:"SANCTUARY_EVIDENCE_SPLIT_TRUST_V1" as const},sample.result.verifier_source_revision);
 expect([result.status,result.exit_code],"recorded static status").toEqual([sample.expected.status,sample.expected.exit_code]);
 expect(result,"recorded static result").toEqual(sample.result);
 if(sample.name==="null-basis")expect(result).toMatchObject({accepted:false,chains:[{historical_signatures:null,signatures_unevaluated_reason:"unreadable"},{}]});
});
