/** Export lifecycle composition; all server imports resolve within this bundle. */
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile, lstat, unlink, rmdir, open } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { createSanctuaryServer } from "../index.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { gatherSnapshot, type SnapshotGather } from "./snapshot-gather.js";
import { buildPublicTrust, renderSnapshot, hashSnapshotFiles, signSnapshot, snapshotJSON } from "./snapshot-generate.js";
import { canonicalOutput, requireOutside, captureSnapshotDirectory, parseSnapshotFlags, commandIO, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, type CommandIO } from "./snapshot-trust-cli.js";
import { verifySnapshot } from "./snapshot-verify.js";
import * as C from "./snapshot-contract.js";
declare const __SANCTUARY_SOURCE_SHA__: string;
// Must match __SANCTUARY_SOURCE_SHA__ in tsup.config.ts, the build-time revision definition.
export const SNAPSHOT_SOURCE_REVISION = typeof __SANCTUARY_SOURCE_SHA__ === "string" ? __SANCTUARY_SOURCE_SHA__ : "";
export const EXPORT_STATES = ["GATHER", "BUILD_PUBLIC_TRUST", "RENDER", "HASH", "SIGN", "HASH_MANIFEST_FILE", "STAGE", "SELF_VERIFY", "CLEANUP", "COMMIT", "RECEIPT"] as const;
export type ExportState = typeof EXPORT_STATES[number];
export interface ExportOptions { fortress: string; output: string; receipt: string; publicKeyFile: string }
export interface ExportDependencies {
  boot: typeof createSanctuaryServer;
  gather: typeof gatherSnapshot;
  runtimeRevision: string;
  buildRevision: string;
  phase: (state: ExportState, stage: string | undefined) => Promise<void>;
  io: CommandIO;
}
export const exportDependencies: ExportDependencies = { boot: createSanctuaryServer, gather: gatherSnapshot, runtimeRevision: SNAPSHOT_SOURCE_REVISION, buildRevision: SNAPSHOT_SOURCE_REVISION, phase: async () => {}, io: commandIO };
const FAILED_DESTINATION_MARKER = "EXPORT_FAILED";
async function reportExportFailure(io: CommandIO, message: string, error: unknown): Promise<void> {
  // Only the closed codes from snapshot-contract.ts may cross the diagnostic boundary because errors can contain private paths.
  const code = error instanceof C.SnapshotError && Object.values(C.HARD).includes(error.code) ? error.code : C.HARD.io_error;
  await io.stderr(`${message}\nEXPORT_FINDING=${code}\n`);
}
export async function exportSnapshot(options: ExportOptions, deps: ExportDependencies = exportDependencies): Promise<number> {
  let instance: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;
  let cleanupAttempted = false, stage: string | undefined, committed = false;
  let createdDestination: string | undefined;
  const phase = async (state: ExportState) => deps.phase(state, stage);
  const oldStorage = process.env.SANCTUARY_STORAGE_PATH;
  try {
    // Provenance is fixed by this bundle; runtime equality is a test seam because production uses the same build constant on both sides.
    C.text(deps.buildRevision, C.REVISION); C.requireSnapshot(deps.runtimeRevision === deps.buildRevision);
    const fortress = resolve(options.fortress), output = await canonicalOutput(options.output), receiptPath = await canonicalOutput(options.receipt), keyPath = await canonicalOutput(options.publicKeyFile);
    requireOutside(output, receiptPath); requireOutside(output, keyPath); C.requireSnapshot(receiptPath !== keyPath, C.HARD.unsafe_path);
    for (const path of [output, receiptPath, keyPath]) {
      try { await lstat(path); throw new C.SnapshotError(C.HARD.file_set_mismatch); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    process.env.SANCTUARY_STORAGE_PATH = fortress;
    await phase("GATHER"); instance = await deps.boot({ passphrase: process.env.SANCTUARY_PASSPHRASE });
    C.requireSnapshot(resolve(instance.config.storage_path) === fortress, C.HARD.unsafe_path);
    const signer = instance.identityManager.getDefault(); C.requireSnapshot(signer, C.HARD.pin_invalid);
    const generatedAt = new Date().toISOString(), exportId = randomUUID();
    // Must match the storage root in src/index.ts because the boot result does not expose its storage object.
    const gathered: SnapshotGather = await deps.gather({ storage: new FilesystemStorage(join(fortress, "state")), masterKey: instance.masterKey, fortress, generatedAt, localSign: process.env.SANCTUARY_CASTLE_LOCAL_SIGN === "1" });
    await phase("BUILD_PUBLIC_TRUST");
    const identities = instance.identityManager.list().map(i => instance!.identityManager.get(i.identity_id)!);
    const trust = buildPublicTrust(signer, identities, gathered);
    const fingerprint = C.manifestDigest(C.publicKey(signer.public_key));
    await phase("RENDER"); const files = renderSnapshot(exportId, generatedAt, gathered, trust);
    await phase("HASH"); const rows = hashSnapshotFiles(files);
    const manifest: C.SnapshotManifest = { format: C.SNAPSHOT_FORMAT, signature_scheme: C.SIGNATURE_SCHEME, hash_algorithm: C.HASH_ALGORITHM, export_id: exportId, generated_at: generatedAt, source_revision: deps.buildRevision, signer: { identity_id: signer.identity_id, public_key_base64url: signer.public_key }, files: rows, components: { audit: gathered.audit, transparency: gathered.transparency }, extensions: [], manifest_signature: "" };
    await phase("SIGN"); const manifestBytes = signSnapshot(manifest, signer, instance.masterKey);
    await phase("HASH_MANIFEST_FILE"); const digest = C.manifestDigest(manifestBytes); files.set(C.MANIFEST_FILENAME, manifestBytes);
    await phase("STAGE"); stage = await mkdtemp(join(dirname(output), ".evidence-failed-stage-"));
    for (const [name, bytes] of files) await writeFile(join(stage, name), bytes, { flag: "wx", mode: PRIVATE_FILE_MODE });
    // The recipient verifier must accept the staged bytes before any destination is created.
    await phase("SELF_VERIFY"); const pins = { packKey: signer.public_key, descriptorBytes: trust, expectedManifestDigest: digest };
    const self = verifySnapshot(await captureSnapshotDirectory(stage, signer.public_key, digest), pins, deps.buildRevision);
    C.requireSnapshot(self.status === C.STATUS.PASS || self.status === C.STATUS.PARTIAL, self.findings[0]?.code ?? C.HARD.nested_invalid);
    // The pin is written from the signing identity with exclusive creation, never read from delivered evidence.
    await writeFile(keyPath, signer.public_key + C.LF, { flag: "wx", mode: PRIVATE_FILE_MODE });
    // Cleanup must finish successfully before the pack can become a committed delivery.
    await phase("CLEANUP"); cleanupAttempted = true; await instance.cleanup();
    await phase("COMMIT");
    // Exclusive directory creation closes the absent-check race and never replaces an existing destination.
    await mkdir(output, { mode: PRIVATE_DIRECTORY_MODE }); createdDestination = output;
    // Use verified in-memory bytes and exclusive creates so a late writer cannot be overwritten.
    for (const [name, bytes] of files) {
      const fd = await open(join(output, name), "wx", PRIVATE_FILE_MODE);
      try { await fd.writeFile(bytes); } finally { await fd.close(); }
    }
    const final = verifySnapshot(await captureSnapshotDirectory(output, signer.public_key, digest), pins, deps.buildRevision);
    C.requireSnapshot(final.status === self.status, final.findings[0]?.code ?? C.HARD.snapshot_changed); committed = true;
    for (const name of files.keys()) await unlink(join(stage, name));
    await rmdir(stage);
    await phase("RECEIPT");
    const receipt = { format: C.RECEIPT_FORMAT, export_id: exportId, manifest_digest: digest, source_revision: deps.buildRevision, trust_descriptor_sha256: C.manifestDigest(trust), pack_path: output, status: self.status, pack_key_fingerprint: fingerprint };
    // Receipt failure must leave the committed pack intact and cannot print a success line.
    await writeFile(receiptPath, snapshotJSON(receipt), { flag: "wx", mode: PRIVATE_FILE_MODE });
    await deps.io.stdout(`EXPORT_ID=${exportId}\nMANIFEST_DIGEST=${digest}\nEXPORT_STATUS=${self.status}\nPACK_KEY_FINGERPRINT=${fingerprint}\n`);
    return self.exit_code;
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
