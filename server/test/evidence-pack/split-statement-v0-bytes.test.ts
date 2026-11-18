// fail-before-exempt: version 0 byte regression must pass on base by design; repository-local delivery substitutes only the pinned receipt pack_path in original-source bytes.
import { beforeAll, describe, expect, it, vi } from "vitest";
import { computeAuditEntryHash } from "../../src/audit/chain.js";
import { verifyAuditChainRecords } from "../../src/cli/audit-chain-verify.js";
import { verifyTransparencyCheckpoints } from "../../src/transparency/verify.js";
import { verifySnapshot } from "../../src/evidence-pack/snapshot-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
import { SOURCE } from "./snapshot-fixtures.js";
import { syntheticPrunedUnsplitFixture, UNSPLIT_SHAPE, disposePhysicalFixture } from "./split-statement-fixtures.js";

// This source regression does not substitute for the separately captured V0 byte golden.
describe("synthetic unsplit retained-history V0 regression", () => {
  let sample: ReturnType<typeof syntheticPrunedUnsplitFixture>;
  beforeAll(() => { sample = syntheticPrunedUnsplitFixture(); });

  it("retains the first observation's counts and ranges", () => {
    const { f, entries, checkpoints } = sample;
    expect(entries).toHaveLength(UNSPLIT_SHAPE.entries);
    expect(entries[0].seq).toBe(UNSPLIT_SHAPE.lowest);
    expect(entries.at(-1)!.seq).toBe(UNSPLIT_SHAPE.lowest + UNSPLIT_SHAPE.entries - 1);
    expect(checkpoints.filter(cp => !cp.unsigned)).toHaveLength(UNSPLIT_SHAPE.signed);
    expect(checkpoints.filter(cp => cp.unsigned)).toHaveLength(UNSPLIT_SHAPE.unsigned);
    expect(entries.at(-1)!.seq - checkpoints.at(-1)!.checkpoint_sequence).toBe(UNSPLIT_SHAPE.tail);
    expect(f.bundle.checkpoints.map(cp => [cp.audit.lowest_sequence, cp.audit.highest_sequence])).toEqual(UNSPLIT_SHAPE.windows);
    expect(f.bundle.checkpoints.every(cp => cp.audit.highest_sequence < entries[0].seq)).toBe(true);
    expect(f.manifest.format).toBe(C.SNAPSHOT_FORMAT);
    expect(Object.keys(f.manifest.components).sort()).toEqual(["audit", "transparency"]);
  });

  it("contains only contiguous synthetic retained entry bytes", () => {
    const { entries } = sample;
    expect(entries[0].prev_hash).not.toBe("GENESIS");
    expect(entries.every((entry, index) =>
      entry.entry_hash === computeAuditEntryHash({
        sequence: entry.seq, schema_version: entry.schema_version, prev_hash: entry.prev_hash,
        timestamp: entry.timestamp, encrypted_payload_bytes: entry.encrypted_payload_bytes,
      })
      && (index === 0 || (entry.seq === entries[index - 1].seq + 1 && entry.prev_hash === entries[index - 1].entry_hash))
    )).toBe(true);
  });

  it("reports original ordinary signature counts and incomplete retained history", () => {
    const { f } = sample;
    const report = verifyAuditChainRecords([...sample.entries, ...sample.checkpoints], { publicKey: f.audit.public_key, trustEmbedded: false });
    expect(report.verdict).toBe("FAIL");
    expect(report.signatures_verified).toBe(UNSPLIT_SHAPE.signed);
    expect(report.signatures_skipped).toBe(UNSPLIT_SHAPE.unsigned);
    expect([...new Set(report.findings.map(finding => finding.kind))].sort()).toEqual(["checkpoint_unsigned", "sequence_gap"]);
  });

  it("preserves the V0 transparency verifier's separate signature result", () => {
    const { f } = sample;
    const report = verifyTransparencyCheckpoints(f.bundle, { publicKey: f.transparency.public_key, trustEmbedded: false, allowPartial: false });
    expect(report.verdict).toBe("PASS");
    expect(report.checkpoints_verified).toBe(UNSPLIT_SHAPE.windows.length);
    expect(report.findings).toEqual([]);
  });

  it("keeps the full retained-history pack nonaccepted in V0", () => {
    const { f } = sample;
    const report = verifySnapshot(f.capture, f.pins, SOURCE);
    expect([report.format, report.status, report.exit_code, report.accepted]).toEqual([C.RESULT_FORMAT, C.STATUS.FAIL, C.EXIT_FAIL, false]);
    expect(report.findings).toEqual([{ code: C.HARD.nested_invalid, state: C.STATES.NESTED_VERIFIED, filename: C.AUDIT_FILENAME }]);
  });
});


// Must match the exhaustive path-field assertion below; every other golden byte remains literal.
const V0_PATH_FIELDS = ["receipt.pack_path"] as const;
const goldenClock = vi.hoisted(() => ({ active: false }));
vi.mock("node:crypto", async importOriginal => {
  const original = await importOriginal<typeof import("node:crypto")>();
  return { ...original, randomUUID: () => goldenClock.active ? "12345678-1234-4123-8123-123456789012" : original.randomUUID() };
});
import { readFileSync } from "node:fs";
import { readFile, readdir, writeFile, mkdir, mkdtemp } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { StoredIdentity } from "../../src/core/identity.js";
import type { SnapshotGather } from "../../src/evidence-pack/snapshot-gather.js";
import { exportSnapshot, exportDependencies } from "../../src/evidence-pack/snapshot-export-cli.js";
import { captureSnapshotDirectory } from "../../src/evidence-pack/snapshot-trust-cli.js";
import { renderSnapshot, hashSnapshotFiles, signSnapshot } from "../../src/evidence-pack/snapshot-generate.js";
const golden = JSON.parse(readFileSync(new URL("./fixtures/split-statement-v0-golden.json", import.meta.url), "utf8"));
const decode = (value: string) => Buffer.from(value, "base64");
const encode = (value: Uint8Array | string) => Buffer.from(value).toString("base64");

// Expected bytes are read-only original-source artifacts. Only actual output is produced here.
describe.sequential("original V0 byte compatibility", () => {
  for (const sample of golden.cases) {
    it(`${sample.name}: preserves raw rendering, PDF, signature and manifest`, () => {
      const gathered = { ...sample.gathered, auditBytes: decode(sample.gathered.audit_base64), transparencyBytes: sample.gathered.transparency_base64 === null ? undefined : decode(sample.gathered.transparency_base64) } as SnapshotGather;
      const files = renderSnapshot(golden.inputs.export_id, golden.inputs.generated_at, gathered, decode(sample.pins.descriptor_base64));
      const manifest = JSON.parse(decode(sample.files[C.MANIFEST_FILENAME]).toString());
      expect(hashSnapshotFiles(files)).toEqual(manifest.files);
      expect(encode(signSnapshot(manifest, golden.inputs.identities[0], decode(golden.inputs.master_base64)))).toBe(sample.files[C.MANIFEST_FILENAME]);
      for (const [name, bytes] of files) {
        // The tampered report is intentionally different from its signed original.
        if (sample.name === "tampered" && name === C.REPORT_FILENAME) expect(encode(bytes)).not.toBe(sample.files[name]);
        else expect(encode(bytes)).toBe(sample.files[name]);
      }
    });
    it(`${sample.name}: preserves delivery, receipt, stdout, result and cleanup ordering`, async () => {
      const parent=resolve(import.meta.dirname,"../../../.scratch");await mkdir(parent,{recursive:true});
      const runRoot=await mkdtemp(join(parent,"v0-"));
      const options = { fortress: join(runRoot,"fortress"), output: join(runRoot,"pack"), receipt: join(runRoot,"receipt.json"), publicKeyFile: join(runRoot,"pack-key.txt") };
      const identities: StoredIdentity[] = golden.inputs.identities;
      const gathered = { ...sample.gathered, auditBytes: decode(sample.gathered.audit_base64), transparencyBytes: sample.gathered.transparency_base64 === null ? undefined : decode(sample.gathered.transparency_base64) } as SnapshotGather;
      let stdout = "", stderr = ""; const phases: string[] = [];
      goldenClock.active = true; vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date(golden.inputs.generated_at));
      const deps = { ...exportDependencies, runtimeRevision: golden.inputs.source_revision, buildRevision: golden.inputs.source_revision, gather: async () => gathered, boot: async () => ({ config: { storage_path: options.fortress }, identityManager: { getDefault: () => identities[0], list: () => identities, get: (id: string) => identities.find(i => i.identity_id === id) }, masterKey: decode(golden.inputs.master_base64), cleanup: async () => { phases.push("cleanup"); } }), phase: async (state: string) => { phases.push(state); }, io: { stdout: async (s: string) => { stdout += s; }, stderr: async (s: string) => { stderr += s; } } };
      try {
        const exit = await exportSnapshot(options, deps as unknown as typeof exportDependencies);
        expect([exit,encode(stdout),encode(stderr),phases]).toEqual([sample.export_exit,sample.export_stdout_base64,sample.export_stderr_base64,sample.phases]);
        if (sample.name === "tampered") await writeFile(join(options.output,C.REPORT_FILENAME),decode(sample.files[C.REPORT_FILENAME]));
        expect((await readdir(options.output)).sort()).toEqual(Object.keys(sample.files).sort());
        for (const [name,bytes] of Object.entries(sample.files)) expect(encode(await readFile(join(options.output,name)))).toBe(bytes);
        expect(encode(await readFile(options.receipt)),"raw receipt with pinned path substitution").toBe(receiptAtPath(sample,options.output));
        expect(encode(await readFile(options.publicKeyFile))).toBe(sample.pack_key_base64);
        const pins = { ...sample.pins, descriptorBytes: decode(sample.pins.descriptor_base64) };
        const actual = verifySnapshot(await captureSnapshotDirectory(options.output,pins.packKey,pins.expectedManifestDigest),pins,golden.inputs.source_revision);
        expect(actual).toEqual(sample.result);
        expect(encode(JSON.stringify(actual) + C.LF)).toBe(sample.outputs.json.stdout_base64);
        expect(encode(C.HUMAN[actual.status] + C.LF + [...actual.findings.map(f => f.code),...actual.partial_reasons].join(C.LF) + C.LF)).toBe(sample.outputs.human.stdout_base64);
      } finally {
        vi.useRealTimers(); goldenClock.active = false;
        // Inventory this run's leaves, including failed staging artifacts, before the final empty-directory removal.
        await disposePhysicalFixture(runRoot);
      }
    });
  }
});

function receiptAtPath(sample:typeof golden.cases[number],path:string):string {
  expect(V0_PATH_FIELDS,"pinned V0 path mask").toEqual(["receipt.pack_path"]);
  let raw=decode(sample.receipt_base64).toString();const receipt=JSON.parse(raw);
  for(const qualified of V0_PATH_FIELDS){
    const [component,field]=qualified.split(".");expect(component).toBe("receipt");
    const original=receipt[field],needle=JSON.stringify(field)+": "+JSON.stringify(original);
    expect(original).toBe(join(captureRoot(sample),"pack"));expect(raw.split(needle)).toHaveLength(2);
    // Replace only listed complete field values, preserving whitespace, ordering and every other byte.
    raw=raw.replace(needle,JSON.stringify(field)+": "+JSON.stringify(path));
  }
  return encode(raw);
}
it("pins the exhaustive V0 path field list",()=>{
 expect(V0_PATH_FIELDS,"pinned V0 path mask").toEqual(["receipt.pack_path"]);
 for(const sample of golden.cases){
  const paths:string[]=[];
  for(const [key,value] of Object.entries(JSON.parse(decode(sample.receipt_base64).toString())))if(typeof value==="string"&&value.includes(captureRoot(sample)))paths.push("receipt."+key);
  expect(paths).toEqual([...V0_PATH_FIELDS]);
  for(const bytes of Object.values(sample.files))expect(decode(bytes as string).includes(Buffer.from(captureRoot(sample)))).toBe(false);
  for(const key of ["export_stdout_base64","export_stderr_base64","pack_key_base64"])expect(decode(sample[key]).includes(Buffer.from(captureRoot(sample)))).toBe(false);
  expect(JSON.stringify(sample.result)).not.toContain(captureRoot(sample));
  for(const output of Object.values(sample.outputs))expect(decode((output as {stdout_base64:string}).stdout_base64).includes(Buffer.from(captureRoot(sample)))).toBe(false);
 }
});

function captureRoot(sample:typeof golden.cases[number]):string {
 return dirname(JSON.parse(decode(sample.receipt_base64).toString()).pack_path);
}
import {createHash} from "node:crypto";
it("preserves every captured V0 component hash",()=>{
 const expected=JSON.parse(readFileSync(new URL("./fixtures/split-statement-v0-hashes.json",import.meta.url),"utf8"));
 const hash=(bytes:string|Uint8Array)=>createHash("sha256").update(bytes).digest("hex");
 const actual:Record<string,string>={provenance:hash(JSON.stringify(golden.provenance)),inputs:hash(JSON.stringify(golden.inputs))};
 for(const sample of golden.cases)for(const [key,value] of Object.entries(sample)){
  const prefix=sample.name+"."+key;
  if(key==="files")for(const [name,bytes] of Object.entries(value as Record<string,string>))actual[prefix+"."+name]=hash(decode(bytes));
  else actual[prefix]=hash(key.endsWith("_base64")?decode(value as string):JSON.stringify(value));
 }
 expect(actual,"f936c787 component hashes").toEqual(expected);
});
