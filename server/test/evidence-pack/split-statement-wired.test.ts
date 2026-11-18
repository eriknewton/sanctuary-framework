// fail-before-exempt: imports evidence-pack/split-statement-contract.js, which base lacks, so this candidate-only file cannot collect on base.
import {beforeAll,afterAll,it,expect} from "vitest";
import {readFile,mkdir,writeFile} from "node:fs/promises";
import {join,resolve} from "node:path";
import {createHash} from "node:crypto";
import {wiredSplitFixture} from "./split-statement-fixtures.js";
import {verifySnapshot} from "../../src/evidence-pack/snapshot-verify.js";
import {captureSnapshotDirectory} from "../../src/evidence-pack/snapshot-trust-cli.js";
import * as B from "../../src/evidence-pack/split-statement-contract.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
const fixtureDeadline=120_000; // Real custody derivation and boot share a two-minute fixture ceiling.
type Fixture=Awaited<ReturnType<typeof wiredSplitFixture>>;
async function verified(x:Fixture) {
  const receiptBytes=Buffer.from(x.receiptBytes),receipt=B.parseReceipt(JSON.parse(receiptBytes.toString()));
  const pins={format:B.TRUST_FORMAT as typeof B.TRUST_FORMAT,packKey:x.signer.public_key,descriptorBytes:x.trust,expectedManifestDigest:receipt.manifest_digest};
  const capture=await captureSnapshotDirectory(x.output,pins.packKey,pins.expectedManifestDigest);
  return {receipt,receiptBytes,keyBytes:Buffer.from(pins.packKey+"\n"),capture,result:verifySnapshot(capture,pins,x.revision)};
}
async function retainVerified(x:Fixture,proof:Awaited<ReturnType<typeof verified>>,destination:string,afterWrite?:(path:string)=>Promise<void>) {
  expect(proof.result.status).toBe("PASS");expect(proof.result.accepted).toBe(true);
  const assigned=resolve(import.meta.dirname,"../../../");
  expect(destination.startsWith(assigned+"/.scratch/")).toBe(true);
  await mkdir(destination);
  const sources=new Map(proof.capture.files.map(file=>[Buffer.from(file.name).toString(),Buffer.from(file.bytes)]));
  sources.set("receipt.json",proof.receiptBytes);sources.set("pack-key.txt",proof.keyBytes);
  for(const [name,bytes] of sources) {
    const path=join(destination,name);
    await writeFile(path,bytes,{flag:"wx"});
    await afterWrite?.(path);
  }
  const hashes:Record<string,string>={};
  for(const [name,bytes] of sources) {
    const retainedBytes=await readFile(join(destination,name));
    // Every retained file equals the bytes used by verification before the success witness is written.
    expect(retainedBytes,`retained bytes must match verified source: ${name}`).toEqual(bytes);
    hashes[name]=createHash("sha256").update(retainedBytes).digest("hex"); // Recorded hashes describe the bytes read back from disk.
  }
  await writeFile(join(destination,"witness.json"),JSON.stringify({source_revision:x.revision,platform:process.platform,scope:"synthetic same-uid production wiring with native startup and ancestor-mode observations substituted",result:proof.result,observed:x.observed,hashes},null,2),{flag:"wx"});
}
let normal:Fixture;
beforeAll(async()=>{normal=await wiredSplitFixture();},fixtureDeadline);
afterAll(async()=>{if(normal)await normal.cleanup();},fixtureDeadline);
it("exports a PASS statement through real boot and the registered command",async()=>{
  expect(normal.exits).toEqual([0]);const proof=await verified(normal);
  expect(proof.result.status).toBe("PASS");expect(proof.result.accepted).toBe(true);
  const retained=process.env.SANCTUARY_SPLIT_RETAIN_PATH;
  if(retained)await retainVerified(normal,proof,resolve(retained));
});
it("records verified bytes and disk hashes for every retained file",async()=>{
  const proof=await verified(normal),destination=join(normal.root,"retained-complete");
  await retainVerified(normal,proof,destination);
  const witness=JSON.parse(await readFile(join(destination,"witness.json"),"utf8"));
  const manifest=JSON.parse(await readFile(join(destination,C.MANIFEST_FILENAME),"utf8"));
  expect(Object.keys(witness.hashes).sort()).toEqual([C.MANIFEST_FILENAME,...manifest.files.map((row:{filename:string})=>row.filename),"receipt.json","pack-key.txt"].sort());
  const sources=new Map(proof.capture.files.map(file=>[Buffer.from(file.name).toString(),Buffer.from(file.bytes)]));
  sources.set("receipt.json",proof.receiptBytes);sources.set("pack-key.txt",proof.keyBytes);
  for(const [name,bytes] of sources) {
    const retainedBytes=await readFile(join(destination,name));
    expect(retainedBytes).toEqual(bytes);
    expect(witness.hashes[name]).toBe(createHash("sha256").update(retainedBytes).digest("hex"));
  }
  expect(witness.result).toEqual(proof.result);
});
it.each([C.REPORT_FILENAME,"receipt.json"])("requires retained %s bytes to equal verified bytes",async name=>{
  const proof=await verified(normal),destination=join(normal.root,"retained-"+name);
  let scheduled=false;
  try {
    await expect(retainVerified(normal,proof,destination,async path=>{
      if(path===join(destination,name)){await writeFile(path,"different retained bytes");scheduled=true;}
    })).rejects.toThrow("retained bytes must match verified source: "+name);
    await expect(readFile(join(destination,"witness.json"))).rejects.toMatchObject({code:"ENOENT"});
  } finally {expect(scheduled).toBe(true);}
});
it("delivers distinct genesis-based chain files and original signature counts",async()=>{const {result}=await verified(normal);expect(result.chains.map(c=>c.historical_signatures)).toEqual(["all_pinned","unsigned_present"]);expect(result.chains[1].unsigned_count).toBe(normal.observed.daemonAfterStop.checkpoints);for(const id of B.CHAIN_IDS){const rows=(await readFile(join(normal.output,B.FIXED_FILES[`audit-${id}`][0]),"utf8")).trim().split("\n").map(line=>JSON.parse(line));expect(rows.find(row=>row.type==="entry").seq).toBe(1);expect(rows.filter(row=>row.type==="entry")).toHaveLength(result.chains.find(c=>c.chain_id===id)!.entries_verified!);}});
it("observes the boot-created tail close through normal cleanup before capture",async()=>{const {result}=await verified(normal);expect(normal.observed.operatorBeforeCleanup.entries).toBeGreaterThan(normal.observed.operatorBeforeBoot.entries);expect(normal.observed.operatorBeforeCleanup.tail).toBeGreaterThan(0);expect(normal.observed.operatorAfterCapture.tail).toBe(0);expect(result.chains.map(c=>c.tail_entries)).toEqual([0,0]);});
it("leaves every source byte unchanged throughout census and recheck",()=>{expect(normal.observed.beforeCensus).toEqual(normal.observed.afterRecheck);expect(normal.observed.stopCalls).toBe(1);expect(normal.observed.daemonBeforeStop.tail).toBeGreaterThan(0);expect(normal.observed.daemonAfterStop.tail).toBe(0);});
it("preserves locally checked boundary and public genesis linkage",async()=>{const census=JSON.parse(await readFile(join(normal.output,B.FIXED_FILES.census[0]),"utf8"));expect(census.migration.state).toBe("operator_checked");expect(census.migration.genesis_binding).toBe("operator_checked");expect(census.chains.map((c:any)=>c.controls_state)).toEqual(["operator_checked","operator_checked"]);const {result}=await verified(normal);expect(result.transparency_assignments).toEqual([{counter:1,chain_id:"daemon"}]);});
it("keeps report, recipient, receipt and stdout on the same basis and coverage",async()=>{const {receipt,result}=await verified(normal),rendered=B.renderChains(result.chains);expect(receipt.chains).toEqual(result.chains);expect(receipt.rendered).toEqual(rendered);for(const line of [rendered.historical_signatures,...rendered.coverage,...rendered.sentences]){expect(normal.stdout.join("")).toContain(line);for(const name of [C.REPORT_FILENAME,C.RECIPIENT_FILENAME])expect(await readFile(join(normal.output,name),"utf8")).toContain(line);}});
it("keeps a resumed daemon tail PARTIAL without an export-triggered flush",async()=>{const x=await wiredSplitFixture({liveTail:true});try{const {result}=await verified(x);expect(x.exits).toEqual([10]);expect(result.partial_reasons).toContain("audit_tail_unanchored");expect(result.chains[1].tail_entries).toBe(x.observed.liveTail.tail);expect(x.observed.liveTail.tail).toBeGreaterThan(0);}finally{await x.cleanup();}},fixtureDeadline);
it("checks a genuinely empty sealed prefix before the operator boot suffix",async()=>{const x=await wiredSplitFixture({emptyPrefix:true});try{const {result}=await verified(x),census=JSON.parse(await readFile(join(x.output,B.FIXED_FILES.census[0]),"utf8"));expect(result.status).toBe("PASS");expect(census.migration).toMatchObject({state:"operator_checked",sealed_base_sequence:0,sealed_tip_sequence:0});expect(x.observed.operatorBeforeBoot.entries).toBe(0);}finally{await x.cleanup();}},fixtureDeadline);
it("assigns a pre-split operator window and later daemon window to separate heads",async()=>{const x=await wiredSplitFixture({preSplitWindow:true});try{const {result}=await verified(x);expect(result.status).toBe("PASS");expect(result.transparency_assignments).toEqual([{counter:1,chain_id:"operator"},{counter:2,chain_id:"daemon"}]);}finally{await x.cleanup();}},fixtureDeadline);
it("keeps unreadable daemon files unevaluated through the registered command",async()=>{const x=await wiredSplitFixture({unavailable:true});try{const {result}=await verified(x);expect(x.exits).toEqual([10]);expect(result.chains[1]).toMatchObject({historical_signatures:null,signatures_evaluated:false,coverage:null});}finally{await x.cleanup();}},fixtureDeadline);

it("refuses a failed local control through the real production source validator",async()=>{const x=await wiredSplitFixture({invalidControl:true});try{expect(x.exits).toEqual([1]);expect(x.stdout.join("")).toBe("");await expect(readFile(x.receipt)).rejects.toMatchObject({code:"ENOENT"});}finally{await x.cleanup();}},fixtureDeadline);
