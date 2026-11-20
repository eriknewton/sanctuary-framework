/** Export lifecycle composition; all server imports resolve within this bundle. */
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile, lstat, unlink, rmdir, open } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { initializedFortressExists } from "./existing-fortress.js";
import { FORTRESS_STATE_DIRECTORY } from "../core/custody-markers.js";
import { createSanctuaryServer } from "../index.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { gatherSnapshot, resolveSnapshotTransparencyPin, type SnapshotGather, type CastlePin } from "./snapshot-gather.js";
import { buildPublicTrust, renderSnapshot, hashSnapshotFiles, signSnapshot, snapshotJSON } from "./snapshot-generate.js";
import { canonicalOutput, requireOutside, captureSnapshotDirectory, parseSnapshotFlags, commandIO, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, type CommandIO } from "./snapshot-trust-cli.js";
import { verifySnapshotByFormat } from "./snapshot-verify.js";
import * as C from "./snapshot-contract.js";
import type {StoredIdentity} from "../core/identity.js";
import {fortressIdFromStoragePath} from "../dashboard/v1_1/wiring.js";
import {readSplitSource,recheckSplitSource,requireSplitRootIdentity,sourceIO} from "../audit/split-evidence-source.js";
import {classifySplitTopology,censusSplitSource} from "./split-statement-census.js";
import {gatherSplitSource,validateSplitSource,type SplitGather,type SplitGatherDependencies} from "./split-statement-gather.js";
import {planSplitStatement,signSplitPlan,requireSplitPlanParity,type SplitPlan} from "./split-statement-generate.js";
import * as B from "./split-statement-contract.js";
declare const __SANCTUARY_SOURCE_SHA__: string;
// Must match __SANCTUARY_SOURCE_SHA__ in tsup.config.ts, the build-time revision definition.
export const SNAPSHOT_SOURCE_REVISION = typeof __SANCTUARY_SOURCE_SHA__ === "string" ? __SANCTUARY_SOURCE_SHA__ : "";
export const EXPORT_STATES = ["GATHER", "BUILD_PUBLIC_TRUST", "RENDER", "HASH", "SIGN", "HASH_MANIFEST_FILE", "STAGE", "SELF_VERIFY", "CLEANUP", "COMMIT", "RECEIPT"] as const;
export const SPLIT_EXPORT_STATES=["CLASSIFY","QUIESCE_EXPORT_INSTANCE","CENSUS","READ","VALIDATE_SOURCE","RECHECK_SOURCE","BUILD","FINAL_VERIFY"] as const;
export type ExportState = typeof EXPORT_STATES[number] | typeof SPLIT_EXPORT_STATES[number];
interface SplitExportGather {kind:"split";gathered:SplitGather;pin:CastlePin|null;fortressId:string}
interface ExportGatherInput extends ParametersGather {
  quiesce:()=>Promise<void>;
  identities:readonly StoredIdentity[];
  source:SplitGatherDependencies;
  classify:typeof classifySplitTopology;
  resolvePin:typeof resolveSnapshotTransparencyPin;
  signal:AbortSignal;
  phase:(state:ExportState)=>Promise<void>;
}
type ParametersGather=Parameters<typeof gatherSnapshot>[0];
/** Production selection requires bounded classification and validation; a positive split choice survives normal shutdown. */
export async function gatherExportStatement(input:ExportGatherInput):Promise<SnapshotGather|SplitExportGather> {
  // CLASSIFY has no extra V0 lifecycle event: the existing unsplit phase order is a byte-regression contract.
  const selection=await input.classify(join(input.fortress,FORTRESS_STATE_DIRECTORY),input.source.io,input.signal);
  if(selection.topology==="unsplit")return gatherSnapshot(input);
  await input.phase("CLASSIFY");await input.phase("QUIESCE_EXPORT_INSTANCE");await input.quiesce();
  const identities=new Map(input.identities.map(who=>[who.identity_id,who]));
  const resolveKey=(kid:string)=>{const who=identities.get(kid);return who?[who.public_key,...who.rotation_history.map(h=>h.old_public_key)]:undefined;};
  await input.phase("CENSUS");
  const source:SplitGatherDependencies={...input.source,
    read:async(...args)=>{await input.phase("READ");return input.source.read(...args);},
    validate:async args=>{await input.phase("VALIDATE_SOURCE");return input.source.validate(args);},
    recheck:async(...args)=>{await input.phase("RECHECK_SOURCE");return input.source.recheck(...args);},
  };
  await requireSplitRootIdentity(selection.read,input.signal);
  const gathered=await gatherSplitSource(selection.read.root,input.masterKey,resolveKey,input.signal,source);
  let pin:CastlePin|null=null;
  if(gathered.projection.transparency.length)try{pin=await input.resolvePin(input.fortress,input.localSign,input.globalPinPath);}catch{ /* An unavailable public pin stays explicitly incomplete. */ }
  B.requireSplit(!input.signal.aborted,"io_error");
  return {kind:"split",gathered,pin,fortressId:fortressIdFromStoragePath(input.fortress)};
}
/** Open the required filesystem fortress with no first-run custody authority. */
function openExistingFortress(fortressPath: string): ReturnType<typeof createSanctuaryServer> {
  return createSanctuaryServer({ existingFortressPath: resolve(fortressPath) });
}

export interface ExportOptions { fortress: string; output: string; receipt: string; publicKeyFile: string }
export interface ExportDependencies {
  boot: typeof openExistingFortress;
  gather: typeof gatherExportStatement;
  classify:typeof classifySplitTopology;
  source:SplitGatherDependencies;
  resolvePin:typeof resolveSnapshotTransparencyPin;
  signal:()=>AbortSignal;
  runtimeRevision: string;
  buildRevision: string;
  phase: (state: ExportState, stage: string | undefined) => Promise<void>;
  io: CommandIO;
}
/** Existing pure V0 callers supply their own single-chain gather; this boundary cannot produce a split statement. */
export interface V0ExportDependencies extends Pick<ExportDependencies,"boot"|"runtimeRevision"|"buildRevision"|"phase"|"io"> {
  gather:(input:ParametersGather)=>Promise<SnapshotGather>;
}
export const exportDependencies: ExportDependencies = { boot: openExistingFortress, gather: gatherExportStatement, classify:classifySplitTopology, source:{io:sourceIO,read:readSplitSource,census:censusSplitSource,validate:validateSplitSource,recheck:recheckSplitSource,budget:()=>new B.Budget()},resolvePin:resolveSnapshotTransparencyPin,signal:()=>new AbortController().signal, runtimeRevision: SNAPSHOT_SOURCE_REVISION, buildRevision: SNAPSHOT_SOURCE_REVISION, phase: async () => {}, io: commandIO };
const FAILED_DESTINATION_MARKER = "EXPORT_FAILED";
async function reportExportFailure(io: CommandIO, message: string, error: unknown): Promise<void> {
  // Only the closed codes from snapshot-contract.ts may cross the diagnostic boundary because errors can contain private paths.
  const code = error instanceof B.SplitError ? error.code : error instanceof C.SnapshotError && Object.values(C.HARD).includes(error.code) ? error.code : C.HARD.io_error;
  await io.stderr(`${message}\nEXPORT_FINDING=${code}\n`);
}
export async function exportSnapshot(options: ExportOptions, deps: ExportDependencies | V0ExportDependencies = exportDependencies): Promise<number> {
  let instance: Awaited<ReturnType<typeof openExistingFortress>> | undefined;
  let cleanupAttempted = false, stage: string | undefined, committed = false;
  let createdDestination: string | undefined;
  const splitDeps="source" in deps?deps:null;
  const signal=splitDeps?splitDeps.signal():new AbortController().signal;let splitSelected=false;
  const phase = async (state: ExportState) => {if(splitSelected)B.requireSplit(!signal.aborted,"io_error");await deps.phase(state, stage);if(splitSelected)B.requireSplit(!signal.aborted,"io_error");};
  const oldStorage = process.env.SANCTUARY_STORAGE_PATH;
  try {
    // Provenance is fixed by this bundle; runtime equality is a test seam because production uses the same build constant on both sides.
    C.text(deps.buildRevision, C.REVISION); C.requireSnapshot(deps.runtimeRevision === deps.buildRevision);
    const fortress = resolve(options.fortress);
    // Evidence reads require existing custody markers before boot, credentials, or output effects, and never follow the final root link.
    if (!(await initializedFortressExists(fortress, false))) {
      await reportExportFailure(deps.io, "Evidence export requires an initialized fortress. The path must be the fortress directory itself, not a symbolic link.", new C.SnapshotError(C.HARD.unsafe_path));
      return C.EXIT_FAIL;
    }
    const output = await canonicalOutput(options.output), receiptPath = await canonicalOutput(options.receipt), keyPath = await canonicalOutput(options.publicKeyFile);
    requireOutside(output, receiptPath); requireOutside(output, keyPath); C.requireSnapshot(receiptPath !== keyPath, C.HARD.unsafe_path);
    for (const path of [output, receiptPath, keyPath]) {
      try { await lstat(path); throw new C.SnapshotError(C.HARD.file_set_mismatch); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    process.env.SANCTUARY_STORAGE_PATH = fortress;
    await phase("GATHER"); instance = await deps.boot(fortress);
    // Must match createSanctuaryServer in ../index.ts; boot binds this path and withholds first-run custody authority.
    C.requireSnapshot(resolve(instance.config.storage_path) === fortress, C.HARD.unsafe_path);
    const signer = instance.identityManager.getDefault(); C.requireSnapshot(signer, C.HARD.pin_invalid);
    const generatedAt = new Date().toISOString(), exportId = randomUUID();
    // Must match FORTRESS_STATE_DIRECTORY in ../core/custody-markers.ts; gathering uses the admitted custody root.
    // V0 reads its roster after gather; B shares one roster first read after normal shutdown in gatherExportStatement.
    let identityRoster: readonly StoredIdentity[] | undefined;
    const readIdentities = () => identityRoster ??= instance!.identityManager.list().map(i => instance!.identityManager.get(i.identity_id)!);
    const input={storage:new FilesystemStorage(join(fortress,FORTRESS_STATE_DIRECTORY)),masterKey:instance.masterKey,fortress,generatedAt,localSign:process.env.SANCTUARY_CASTLE_LOCAL_SIGN==="1"};
    const gathered="source" in deps?await deps.gather({...input,get identities(){return readIdentities();},source:deps.source,classify:deps.classify,resolvePin:deps.resolvePin,signal,phase:async state=>{splitSelected=true;await phase(state);},quiesce:async()=>{cleanupAttempted=true;await instance!.cleanup();B.requireSplit(!signal.aborted,"io_error");}}):await deps.gather(input);
    await phase("BUILD_PUBLIC_TRUST");
    const identities = readIdentities();
    let trust:Uint8Array,files:Map<string,Uint8Array>,manifestBytes:Uint8Array,plan:SplitPlan|undefined;
    const fingerprint = C.manifestDigest(C.publicKey(signer.public_key));
    if("kind" in gathered) {
      // The legacy single-chain injection has no split authority; B always requires the complete production dependency graph.
      B.requireSplit(splitDeps,"source_control_invalid");
      splitSelected=true;await phase("BUILD");
      plan=planSplitStatement({gathered:gathered.gathered,signer,identities,transparencyPin:gathered.pin,fortressId:gathered.fortressId,exportId,generatedAt,sourceRevision:deps.buildRevision,budget:splitDeps.source.budget()});
      trust=plan.trust;await phase("RENDER");files=plan.files;await phase("HASH");await phase("SIGN");manifestBytes=signSplitPlan(plan,signer,instance.masterKey);
    } else {
      trust=buildPublicTrust(signer,identities,gathered);
      await phase("RENDER");files=renderSnapshot(exportId,generatedAt,gathered,trust);
      await phase("HASH");const rows=hashSnapshotFiles(files);
      const manifest:C.SnapshotManifest={format:C.SNAPSHOT_FORMAT,signature_scheme:C.SIGNATURE_SCHEME,hash_algorithm:C.HASH_ALGORITHM,export_id:exportId,generated_at:generatedAt,source_revision:deps.buildRevision,signer:{identity_id:signer.identity_id,public_key_base64url:signer.public_key},files:rows,components:{audit:gathered.audit,transparency:gathered.transparency},extensions:[],manifest_signature:""};
      await phase("SIGN");manifestBytes=signSnapshot(manifest,signer,instance.masterKey);
    }
    await phase("HASH_MANIFEST_FILE"); const digest = C.manifestDigest(manifestBytes); files.set(C.MANIFEST_FILENAME, manifestBytes);
    // Must match parseReceipt in split-statement-contract.ts; receipt admissibility is decided before staging or committing files.
    if(plan)C.cap(C.utf8(output).length,B.MAX_TEXT_BYTES);
    await phase("STAGE"); stage = await mkdtemp(join(dirname(output), ".evidence-failed-stage-"));
    for (const [name, bytes] of files) {if(plan)B.requireSplit(!signal.aborted,"io_error");await writeFile(join(stage, name), bytes, { flag: "wx", mode: PRIVATE_FILE_MODE });}
    // The recipient verifier must accept the staged bytes before any destination is created.
    await phase("SELF_VERIFY"); const pins = { packKey: signer.public_key, descriptorBytes: trust, expectedManifestDigest: digest };
    const self = verifySnapshotByFormat(await captureSnapshotDirectory(stage, signer.public_key, digest), pins, deps.buildRevision);
    if(plan){B.requireSplit(self.format===B.RESULT_FORMAT);requireSplitPlanParity(plan,self);}
    B.requireSplit(self.status === C.STATUS.PASS || self.status === C.STATUS.PARTIAL, self.findings[0]?.code ?? C.HARD.nested_invalid);
    // The pin is written from the signing identity with exclusive creation, never read from delivered evidence.
    if(plan)B.requireSplit(!signal.aborted,"io_error");
    await writeFile(keyPath, signer.public_key + C.LF, { flag: "wx", mode: PRIVATE_FILE_MODE });
    // Cleanup must finish successfully before the pack can become a committed delivery.
    if(!cleanupAttempted){await phase("CLEANUP"); cleanupAttempted = true; await instance.cleanup();}
    await phase("COMMIT");
    // Exclusive directory creation closes the absent-check race and never replaces an existing destination.
    await mkdir(output, { mode: PRIVATE_DIRECTORY_MODE }); createdDestination = output;
    // Use verified in-memory bytes and exclusive creates so a late writer cannot be overwritten.
    for (const [name, bytes] of files) {
      if(plan)B.requireSplit(!signal.aborted,"io_error");
      const fd = await open(join(output, name), "wx", PRIVATE_FILE_MODE);
      try { if(plan)B.requireSplit(!signal.aborted,"io_error");await fd.writeFile(bytes); } finally { await fd.close(); }
    }
    if(plan)await phase("FINAL_VERIFY");
    const final = verifySnapshotByFormat(await captureSnapshotDirectory(output, signer.public_key, digest), pins, deps.buildRevision);
    if(plan){B.requireSplit(final.format===B.RESULT_FORMAT);requireSplitPlanParity(plan,final);B.requireSplit(C.canonicalSnapshotJSON(final)===C.canonicalSnapshotJSON(self),"snapshot_changed");}
    B.requireSplit(final.status === self.status, final.findings[0]?.code ?? C.HARD.snapshot_changed); if(plan)B.requireSplit(!signal.aborted,"io_error"); committed = true;
    for (const name of files.keys()) await unlink(join(stage, name));
    await rmdir(stage);
    await phase("RECEIPT");
    const receipt = { format: C.RECEIPT_FORMAT, export_id: exportId, manifest_digest: digest, source_revision: deps.buildRevision, trust_descriptor_sha256: C.manifestDigest(trust), pack_path: output, status: self.status, pack_key_fingerprint: fingerprint };
    // Receipt failure must leave the committed pack intact and cannot print a success line.
    await writeFile(receiptPath, snapshotJSON(final.format===B.RESULT_FORMAT?B.parseReceipt({...receipt,format:B.RECEIPT_FORMAT,status:final.status,contract:B.CONTRACT,chains:final.chains,rendered:B.renderChains(final.chains)}):receipt), { flag: "wx", mode: PRIVATE_FILE_MODE });
    const rendered=final.format===B.RESULT_FORMAT?B.renderChains(final.chains):null;
    if(plan)B.requireSplit(!signal.aborted,"io_error");
    await deps.io.stdout(`EXPORT_ID=${exportId}\nMANIFEST_DIGEST=${digest}\nEXPORT_STATUS=${final.status}\nPACK_KEY_FINGERPRINT=${fingerprint}\n`+(rendered?[final.status==="PASS"?B.PASS_SENTENCE:C.HUMAN.PARTIAL,rendered.historical_signatures,...rendered.coverage,...rendered.sentences].join(C.LF)+C.LF:""));
    // Awaited output can settle after cancellation; completion cannot authorize a successful exit then.
    if(plan)B.requireSplit(!signal.aborted,"io_error");
    return final.exit_code;
  } catch (error) {
    if (createdDestination && !committed) {
      // A failed delivery is labeled, never deleted: removal by name could reach a file another writer substituted, and the unlisted marker alone makes the directory fail verification.
      try { await writeFile(join(createdDestination, FAILED_DESTINATION_MARKER), "", { flag: "wx", mode: PRIVATE_FILE_MODE }); }
      catch { /* A missing or unwritable destination cannot accept the fixed marker. */ }
    }
    if (instance && !cleanupAttempted) {
      try { await instance.cleanup(); } catch { /* Preserve the original closed failure code. */ }
    }
    await reportExportFailure(deps.io, committed ? "Evidence export finalization failed; committed pack retained." : "Evidence export failed; any failed stage is retained.", error);
    return C.EXIT_FAIL;
  } finally {
    if (oldStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH; else process.env.SANCTUARY_STORAGE_PATH = oldStorage;
  }
}
export async function runSnapshotExportCommand(argv: string[], deps: ExportDependencies = exportDependencies): Promise<number> {
  const help = "Usage: sanctuary export-evidence --fortress <dir> --output <new-dir> --receipt <new-file> --public-key-file <new-external-file>\n";
  if (argv.length === 1 && argv[0] === "--help") { await deps.io.stdout(help); return C.EXIT_PASS; }
  let flags: Record<string, string>;
  try { flags = parseSnapshotFlags(argv, ["--fortress", "--output", "--receipt", "--public-key-file"]); }
  catch { await deps.io.stderr(help); return C.EXIT_USAGE; }
  try { return await exportSnapshot({ fortress: flags["--fortress"], output: flags["--output"], receipt: flags["--receipt"], publicKeyFile: flags["--public-key-file"] }, deps); }
  catch (error) { await reportExportFailure(deps.io, "Evidence export cleanup failed.", error); return C.EXIT_FAIL; }
}
