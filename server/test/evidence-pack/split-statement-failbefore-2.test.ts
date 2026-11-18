// Semantic entry witness: imports only modules present at the original base and committed public bytes.
import {describe,expect,it} from "vitest";
import {readFileSync} from "node:fs";
import {verifySnapshot} from "../../src/evidence-pack/snapshot-verify.js";
const corpus=JSON.parse(readFileSync(new URL("./fixtures/split-statement-static-packs.json",import.meta.url),"utf8"));
const sample=corpus.cases.find((c:any)=>c.name==="complete");
const revision=corpus.provenance.source_base;
const pins={packKey:sample.pins.packKey,descriptorBytes:Buffer.from(sample.pins.descriptor_base64,"base64"),expectedManifestDigest:sample.pins.expectedManifestDigest,format:"SANCTUARY_EVIDENCE_SPLIT_TRUST_V1" as const};
const bytes=Object.entries(sample.files).map(([name,data])=>({name,bytes:Buffer.from(data as string,"base64")}));
const stat=(size:number,type="file")=>({type,size,nlink:1,dev:"1",ino:"1",mtime:"fixed",ctime:"fixed"});
describe("carried-forward split format witness",()=>{
 it("accepts the complete static split statement through the existing verifier",()=>{
   const files=bytes.map(f=>({name:Buffer.from(f.name),bytes:f.bytes,before:stat(f.bytes.length),after:stat(f.bytes.length),metadata:[]}));
   const capture={files,rootBefore:stat(0,"directory"),rootAfter:stat(0,"directory"),finalNames:files.map(f=>f.name),rootMetadata:[]};
   const v0Descriptor=Buffer.from(JSON.stringify({format:"SANCTUARY_EVIDENCE_TRUST_V0",keys:JSON.parse(pins.descriptorBytes.toString()).keys.filter((key:any)=>key.role==="pack-manifest")}));
   const v0=verifySnapshot(capture,{packKey:pins.packKey,descriptorBytes:v0Descriptor,expectedManifestDigest:pins.expectedManifestDigest},revision);
   expect(v0.findings.map(f=>f.code),"V0 format refusal is explicit").toEqual(["unsupported_format"]);
   const result=verifySnapshot(capture,pins,revision);
   expect([result.status,result.exit_code,result.accepted]).toEqual(["PASS",0,true]);
 });

});
