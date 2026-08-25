/**
 * Explicit local CLI composition for Exit V2 SDW memory archive carriage.
 *
 * The artifact recovery material is accepted and disclosed only through a
 * local OS dialog that requires a console-user interaction. It never enters
 * argv, the process environment, ordinary stdin, structured output, or
 * persisted metadata. Terminal presence is deliberately not treated as proof
 * that a local console user is controlling the process.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  open,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { Writable } from "node:stream";

import { IdentityManager } from "../cognitive/tools.js";
import type { ExitV2SdwMemoryManifest } from "../contracts/v1.2/exit-bundle-manifest.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { sign } from "../core/identity.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  exportExitV2SdwMemoryArchive,
  importExitV2SdwMemoryArchive,
  planExitV2SdwMemoryAdmission,
  verifyExitV2SdwMemoryArchive,
} from "../exit/v2-memory-archive.js";
import { AuditLog } from "../operational/audit-log.js";
import {
  createExitAdmissionWriteGuard,
  recoverInterruptedExitImportsOrThrow,
  runJournaledExitMemoryAdmission,
  type ExitAdmissionWriteGuard,
} from "../exit/bundle.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../principal-policy/types.js";
import { SdwMemoryBackendAdapter } from "../sdw/adapters/sdw-memory-backend.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../sdw/memory-provenance-signing.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import { MemoryProvenanceBadSignerStore } from "../sdw/memory-provenance-bad-signers.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { StorageBackend } from "../storage/interface.js";
import { KnownSignersStore } from "../reputation/known-signers-store.js";
import { getSanctuaryVersion } from "../version.js";
import { consumeFlagValue } from "./argv.js";

const TRANSFER_KEY_BYTES = 32;
// 43 = the unpadded base64url length of 32 bytes: ceil(32 * 8 / 6).
const TRANSFER_KEY_TEXT_BYTES = 43;
const MAX_HIDDEN_INPUT_BYTES = TRANSFER_KEY_TEXT_BYTES;
// Five minutes is the existing default Tier-1 approval window (300 seconds).
const LOCAL_DIALOG_TIMEOUT_MS = 5 * 60 * 1000;
// A dialog returns only a 43-byte key or a short decision; 4 KiB is ample headroom.
const MAX_LOCAL_DIALOG_OUTPUT_BYTES = 4 * 1024;
const ASCII_LINE_FEED = 10;
const ASCII_CARRIAGE_RETURN = 13;
const ASCII_SPACE = 32;
const MAX_MANIFEST_BYTES = 1024 * 1024;
// Must match the artifact path returned by exportExitV2SdwMemoryArchive.
const ARTIFACT_PATH = "artifacts/sdw-memory-archive.json";
// 24 MiB must match MAX_ARTIFACT_BYTES in exit/v2-memory-archive.ts.
const MAX_ARTIFACT_BYTES = 24 * 1024 * 1024;
// One sentinel byte proves the opened file did not grow beyond its declared bound.
const BOUND_EXCESS_SENTINEL_BYTES = 1;
const ARCHIVE_ID = /^[a-f0-9]{32}$/;
const SAFE_OWNER_REF = /^[A-Za-z0-9:._-]{1,256}$/;
const BASE64URL_ALPHABET = Buffer.from(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  "ascii",
);

export interface PrivateMemoryArchiveInteraction extends ApprovalChannel {
  discloseAndConfirm(value: Uint8Array): Promise<boolean>;
  readHidden(prompt: string): Promise<Uint8Array>;
  close(): void;
}

export interface MemoryArchiveDialogResult {
  readonly status: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: Uint8Array;
}

export type MemoryArchiveDialogRunner = (script: Uint8Array) => MemoryArchiveDialogResult;

export interface MemoryArchiveCommandArgs {
  readonly argv: string[];
  readonly out?: Writable;
  readonly err?: Writable;
  /** Present only to prove ordinary stdin is outside the recovery-material path. */
  readonly stdin?: NodeJS.ReadableStream;
  readonly env?: NodeJS.ProcessEnv;
  /** Undefined opens the local OS dialog; null forces its fail-closed path. */
  readonly interaction?: PrivateMemoryArchiveInteraction | null;
  /** Test seam for the local OS dialog subprocess. */
  readonly dialogRunner?: MemoryArchiveDialogRunner;
  readonly approvalChannel?: ApprovalChannel;
}

interface ParsedBadSigner {
  readonly signerDid: string;
  readonly publicKeySha256: string;
  readonly reason?: string;
  readonly ownerRef: string;
  readonly fortressPath: string;
  readonly json: boolean;
}

interface ParsedExport {
  readonly archiveId: string;
  readonly outputPath: string;
  readonly ownerRef: string;
  readonly fortressPath: string;
  readonly json: boolean;
}

interface ParsedImport {
  readonly inputPath: string;
  readonly ownerRef: string;
  readonly fortressPath: string;
  readonly json: boolean;
}

interface Bootstrapped {
  readonly storage: StorageBackend;
  readonly journalStorage: FilesystemStorage;
  readonly admissionWriteGuard: ExitAdmissionWriteGuard;
  readonly masterKey: Uint8Array;
  readonly identityKey: Uint8Array;
  readonly auditLog: AuditLog;
  readonly baseline: BaselineTracker;
  readonly adapter: SdwMemoryBackendAdapter;
  readonly memoryProvenanceSigners: KnownSignersStore;
  readonly badSignerStore: MemoryProvenanceBadSignerStore;
  readonly resolveProvenanceSigner: (identityId: string, did: string) => Uint8Array | undefined;
  readonly rememberProvenanceSigner: (did: string, publicKey: Uint8Array) => void;
  readonly signer: {
    readonly identity_id: string;
    readonly fortress_id: string;
    readonly public_key: string;
    readonly did: string;
    sign(bytes: Uint8Array): Uint8Array;
  };
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runMemoryArchiveExportCommand(
  args: MemoryArchiveCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    printExportHelp(out);
    return 0;
  }
  const parsed = parseExport(args.argv, err);
  if (!parsed) return 2;

  const interaction = resolveInteraction(args.interaction, args.dialogRunner, err);
  if (!interaction) return 1;
  let boot: Bootstrapped | null = null;
  let stagedPath: string | undefined;
  let committed = false;
  let disclosed = false;
  let transferKey: Uint8Array | undefined;
  try {
    boot = await bootstrap(parsed, args.env ?? process.env, err);
    if (!boot) return 1;
    if (await exists(parsed.outputPath)) {
      write(err, "memory_archive_export failed: output path already exists\n");
      return 1;
    }

    const approvalArgs = {
      // This operator-only CLI has no acting agent principal. Keeping the field
      // explicit prevents a missing value from being mistaken for an inferred one.
      agent_id: null,
      archive_id: parsed.archiveId,
      owner_ref: parsed.ownerRef,
      output_path: parsed.outputPath,
    };
    const gate = new ApprovalGate(
      await loadPrincipalPolicy(parsed.fortressPath),
      boot.baseline,
      args.approvalChannel ?? interaction,
      boot.auditLog,
    );
    const decision = await gate.evaluate("memory_archive_export", approvalArgs);
    if (!decision.allowed) {
      write(err, "Denied: memory archive export was not approved.\n");
      return 1;
    }
    const approvalAuditId = decision.approval_audit_id;
    // A signed export must name the gate's durable decision event; an allowed
    // result without that provenance fails closed rather than minting a substitute.
    if (!approvalAuditId) throw new Error("approved export lacks audit provenance");
    const approvedArgs = { ...approvalArgs, approval_audit_id: approvalAuditId };

    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_archive_export_started",
      identity_id: boot.signer.identity_id,
      result: "success",
      details: approvedArgs,
    });
    const exported = await exportExitV2SdwMemoryArchive({
      adapter: boot.adapter,
      archiveId: parsed.archiveId,
      sourceFortressId: boot.signer.fortress_id,
      exportApprovalAuditId: approvalAuditId,
      sourceSanctuaryVersion: getSanctuaryVersion(),
      signer: boot.signer,
      formatVersion: 2,
      resolveProvenanceSigner: boot.resolveProvenanceSigner,
    });
    transferKey = exported.transfer_key;

    const outputParent = dirname(parsed.outputPath);
    await mkdir(outputParent, { recursive: true, mode: 0o700 });
    stagedPath = await mkdtemp(join(outputParent, ".sanctuary-exit-v2-"));
    await mkdir(join(stagedPath, "artifacts"), { mode: 0o700 });
    await writeFile(
      join(stagedPath, "manifest.json"),
      JSON.stringify(exported.manifest, null, 2) + "\n",
      { mode: 0o600, flag: "wx" },
    );
    await writeFile(join(stagedPath, ARTIFACT_PATH), exported.artifact_bytes, {
      mode: 0o600,
      flag: "wx",
    });
    const encodedKey = encodeTransferKey(transferKey);
    // Once encoded, the raw key has no remaining caller-side purpose. The
    // library-owned artifact already contains the ciphertext it produced.
    transferKey.fill(0);
    transferKey = undefined;
    try {
      // A successful export requires proof that the console user recorded the
      // exact one-use key; displaying it without re-entry is not custody.
      if (!(await interaction.discloseAndConfirm(encodedKey))) {
        throw new Error("recovery material custody was not confirmed");
      }
      disclosed = true;
    } finally {
      encodedKey.fill(0);
    }

    // The requested bundle path appears only after exact key re-entry. A
    // crash or dialog failure before custody confirmation cannot leave behind
    // a successfully named but unrecoverable export.
    await rename(stagedPath, parsed.outputPath);
    stagedPath = undefined;
    committed = true;

    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_archive_export",
      identity_id: boot.signer.identity_id,
      result: "success",
      details: {
        ...approvedArgs,
        artifact_sha256: exported.artifact_sha256,
        source_lineage_ref: exported.source_lineage_ref,
      },
    });
    const receipt = {
      bundle_dir: parsed.outputPath,
      artifact_sha256: exported.artifact_sha256,
      source_lineage_ref: exported.source_lineage_ref,
      owner_ref: parsed.ownerRef,
      approval_audit_id: approvalAuditId,
    };
    write(
      out,
      parsed.json
        ? JSON.stringify(receipt) + "\n"
        : `memory_archive_export: wrote ${parsed.outputPath}\n`,
    );
    return 0;
  } catch {
    // Reachable states only: (a) neither flag set, the failure happened
    // before recovery-material disclosure; (b) disclosed only, the failure
    // happened between disclosure and the rename that commits the bundle;
    // (c) both set, the failure happened after commit (e.g. the post-commit
    // audit-log append). `committed` is set only in the statement immediately
    // after `disclosed = true`, so committed-without-disclosed can never
    // occur and there is no separate cleanup branch for it.
    write(
      err,
      disclosed && committed
        ? "memory_archive_export failed after recovery material disclosure; the bundle remains at the requested path\n"
        : disclosed
          ? "memory_archive_export failed after recovery material disclosure; no bundle was committed\n"
          : "memory_archive_export failed\n",
    );
    return 1;
  } finally {
    transferKey?.fill(0);
    if (stagedPath !== undefined) {
      await rm(stagedPath, { recursive: true, force: true }).catch(() => undefined);
    }
    await dispose(boot);
    interaction.close();
  }
}

export async function runMemoryArchiveImportCommand(
  args: MemoryArchiveCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    printImportHelp(out);
    return 0;
  }
  if (containsSecretArgvFlag(args.argv)) {
    write(err, "Error: recovery material and fortress passphrases cannot be supplied in argv.\n");
    return 2;
  }
  const parsed = parseImport(args.argv, err);
  if (!parsed) return 2;

  const interaction = resolveInteraction(args.interaction, args.dialogRunner, err);
  if (!interaction) return 1;
  let boot: Bootstrapped | null = null;
  let hiddenBytes: Uint8Array | undefined;
  let transferKey: Uint8Array | undefined;
  // Set true only once importExitV2SdwMemoryArchive itself has returned; the
  // catch block below uses this to distinguish a failure that happened before
  // the destination archive was written from one that happened after (e.g. a
  // post-commit audit-log append), since those two cases need different,
  // non-misdiagnosing operator guidance.
  let committed = false;
  try {
    const bundle = await readBundle(parsed.inputPath);

    // Authentication precedes fortress bootstrap, policy creation, approval
    // auditing, and every destination write. A wrong key therefore leaves the
    // complete destination tree byte-for-byte unchanged.
    hiddenBytes = await interaction.readHidden(
      "Enter Exit V2 recovery material to authenticate the archive",
    );
    try {
      transferKey = decodeTransferKey(hiddenBytes);
    } finally {
      hiddenBytes.fill(0);
      hiddenBytes = undefined;
    }
    await verifyExitV2SdwMemoryArchive({
      manifest: bundle.manifest,
      artifactBytes: bundle.artifactBytes,
      transferKey,
    });
    // Verification consumes and clears its caller-owned key buffer.
    transferKey = undefined;

    boot = await bootstrap(parsed, args.env ?? process.env, err);
    if (!boot) return 1;

    const approvalArgs = {
      // This operator-only CLI has no acting agent principal. Keeping the field
      // explicit prevents a missing value from being mistaken for an inferred one.
      agent_id: null,
      bundle_path: parsed.inputPath,
      owner_ref: parsed.ownerRef,
      artifact_sha256: bundle.artifactSha256,
    };
    const gate = new ApprovalGate(
      await loadPrincipalPolicy(parsed.fortressPath),
      boot.baseline,
      args.approvalChannel ?? interaction,
      boot.auditLog,
    );
    const decision = await gate.evaluate("memory_archive_import", approvalArgs);
    if (!decision.allowed) {
      write(err, "Denied: memory archive import was not approved.\n");
      return 1;
    }
    const approvalAuditId = decision.approval_audit_id;
    // Import audit records must resolve to the exact gate decision that the
    // operator made; caller-generated correlation ids are not approval evidence.
    if (!approvalAuditId) throw new Error("approved import lacks audit provenance");
    const approvedArgs = { ...approvalArgs, approval_audit_id: approvalAuditId };

    hiddenBytes = await interaction.readHidden(
      "Re-enter Exit V2 recovery material to import the approved archive",
    );
    try {
      transferKey = decodeTransferKey(hiddenBytes);
    } finally {
      hiddenBytes.fill(0);
      hiddenBytes = undefined;
    }
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_archive_import_started",
      identity_id: boot.signer.identity_id,
      result: "success",
      details: approvedArgs,
    });
    const importedAt = new Date().toISOString();
    const plan = await planExitV2SdwMemoryAdmission({
      adapter: boot.adapter,
      signer: boot.signer,
      manifest: bundle.manifest,
      artifactBytes: bundle.artifactBytes,
      transferKey: new Uint8Array(transferKey),
      importedAt,
      badSignerAuthority: boot.badSignerStore,
    });
    const receipt = await runJournaledExitMemoryAdmission({
      storage: boot.journalStorage,
      importId: plan.importId,
      identityId: boot.signer.identity_id,
      locations: plan.locations,
      operation: async (journal) => {
        boot!.admissionWriteGuard.activate(plan.locations, journal.recordPostImage);
        try {
          return await importExitV2SdwMemoryArchive({
            adapter: boot!.adapter,
            signer: boot!.signer,
            knownSignersStore: boot!.memoryProvenanceSigners,
            manifest: bundle.manifest,
            artifactBytes: bundle.artifactBytes,
            transferKey: transferKey!,
            now: () => importedAt,
            badSignerAuthority: boot!.badSignerStore,
          });
        } finally {
          boot!.admissionWriteGuard.deactivate();
        }
      },
    });
    // The destination archive is durably written by the call above; anything
    // that fails from this point on is a post-commit step, not an import
    // failure, and must be reported as such (see the `committed` comment).
    committed = true;
    // Publish resolver state only after the journal has committed. A failed
    // admission may have its signer rows rolled back and must not leave a
    // process-local trust residue.
    for (const entry of await boot.memoryProvenanceSigners.loadAll()) {
      boot.rememberProvenanceSigner(entry.did, entry.publicKey);
    }
    // Import consumes and clears its caller-owned key buffer.
    transferKey = undefined;
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_archive_import",
      identity_id: boot.signer.identity_id,
      result: "success",
      details: {
        ...approvedArgs,
        replayed: receipt.replayed,
        source_lineage_ref: receipt.source_lineage_ref,
        destination_archive_id: receipt.destination_archive_id,
      },
    });
    write(
      out,
      parsed.json
        ? JSON.stringify(receipt) + "\n"
        : `memory_archive_import: imported ${receipt.destination_archive_id}\n`,
    );
    return 0;
  } catch {
    // Pre-commit failures are genuinely authentication/validation failures
    // (bad recovery material, a malformed bundle, a denied approval). A
    // post-commit failure is a different situation entirely: the destination
    // archive already exists, so reporting it as an authentication failure
    // would misdiagnose a completed irreversible operation and could prompt
    // an operator to needlessly re-authenticate or distrust a successful
    // import. importExitV2SdwMemoryArchive treats a repeat of the same source
    // lineage as a replay (see `replayed` in its result), so re-running this
    // command with the same bundle is safe either way.
    write(
      err,
      committed
        ? "memory_archive_import failed after the archive was imported; a post-import step (audit logging or receipt output) failed. Re-running memory_archive_import with the same bundle is safe.\n"
        : "memory_archive_import failed: archive authentication or validation failed\n",
    );
    return 1;
  } finally {
    transferKey?.fill(0);
    hiddenBytes?.fill(0);
    await dispose(boot);
    interaction.close();
  }
}

export async function runMemoryProvenanceMarkBadSignerCommand(
  args: MemoryArchiveCommandArgs,
): Promise<number> {
  return runMemoryProvenanceBadSignerCommand("mark", args);
}

export async function runMemoryProvenanceClearBadSignerCommand(
  args: MemoryArchiveCommandArgs,
): Promise<number> {
  return runMemoryProvenanceBadSignerCommand("clear", args);
}

async function runMemoryProvenanceBadSignerCommand(
  action: "mark" | "clear",
  args: MemoryArchiveCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const operation = action === "mark"
    ? "memory_provenance_mark_bad_signer"
    : "memory_provenance_clear_bad_signer";
  if (args.argv.includes("--help") || args.argv.includes("-h")) {
    write(out, `Usage: sanctuary ${operation} --signer-did <did> --public-key-sha256 <hex> ${action === "mark" ? "--reason <text> " : ""}--owner-ref <id> --fortress <path>\n`);
    return 0;
  }
  const parsed = parseBadSigner(args.argv, action, err);
  if (parsed === null) return 2;
  const interaction = resolveInteraction(args.interaction, args.dialogRunner, err);
  if (interaction === null) return 1;
  let boot: Bootstrapped | null = null;
  try {
    boot = await bootstrap(parsed, args.env ?? process.env, err);
    if (boot === null) return 1;
    const gateArgs = {
      agent_id: null,
      signer_did: parsed.signerDid,
      public_key_sha256: parsed.publicKeySha256,
      ...(parsed.reason === undefined ? {} : { reason: parsed.reason }),
    };
    const gate = new ApprovalGate(
      await loadPrincipalPolicy(parsed.fortressPath),
      boot.baseline,
      args.approvalChannel ?? interaction,
      boot.auditLog,
    );
    const decision = await gate.evaluate(operation, gateArgs);
    if (!decision.allowed || decision.approval_audit_id === undefined) {
      write(err, `Denied: ${operation} was not approved.\n`);
      return 1;
    }
    if (action === "mark") {
      const record = await boot.badSignerStore.mark({
        signerDid: parsed.signerDid,
        publicKeySha256: parsed.publicKeySha256,
        reason: parsed.reason!,
        approvalAuditId: decision.approval_audit_id,
      }, boot.auditLog);
      write(out, parsed.json ? JSON.stringify({ marked: true, ...record }) + "\n" :
        `memory_provenance_mark_bad_signer: marked ${record.signer_did}\n`);
    } else {
      const scan = await boot.badSignerStore.clear({
        signerDid: parsed.signerDid,
        publicKeySha256: parsed.publicKeySha256,
        approvalAuditId: decision.approval_audit_id,
      }, boot.auditLog);
      write(out, parsed.json ? JSON.stringify({ cleared: true, ...scan }) + "\n" :
        `memory_provenance_clear_bad_signer: cleared after ${scan.affected} re-verification(s)\n`);
    }
    return 0;
  } catch {
    write(err, `${operation} failed\n`);
    return 1;
  } finally {
    await dispose(boot);
    interaction.close();
  }
}

async function bootstrap(
  parsed: Pick<ParsedExport, "fortressPath" | "ownerRef">,
  env: NodeJS.ProcessEnv,
  err: Writable,
): Promise<Bootstrapped | null> {
  const passphrase = env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(err, "Error: fortress recovery material is required.\n");
    return null;
  }
  let masterKey: Uint8Array | undefined;
  let identityKey: Uint8Array | undefined;
  try {
    await access(parsed.fortressPath);
    const journalStorage = new FilesystemStorage(join(parsed.fortressPath, "state"));
    const admissionWriteGuard = createExitAdmissionWriteGuard(journalStorage);
    const storage = admissionWriteGuard.storage;
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: parsed.fortressPath,
    });
    const identityManager = new IdentityManager(storage, masterKey);
    const loaded = await identityManager.load();
    const primary = identityManager.getDefault();
    if (loaded.loaded === 0 || !primary) {
      masterKey.fill(0);
      write(err, "Error: fortress identity is unavailable.\n");
      return null;
    }
    const signingKey = derivePurposeKey(masterKey, "identity-encryption");
    identityKey = signingKey;
    const fortressId = fortressIdFromStoragePath(parsed.fortressPath);
    // MEDIUM-C (coordinator gate, 2026-08-22): this verb is part of the
    // Exit V2 memory-archive carriage family, so it is directly in scope
    // for the fortress-open recovery wiring, not just structurally
    // discovered by the mechanical pin.
    const memoryArchiveAuditLog = new AuditLog(storage, masterKey);
    await recoverInterruptedExitImportsOrThrow(storage, memoryArchiveAuditLog);
    const signingHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identityManager, masterKey);
    const signerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identityManager);
    const memoryProvenanceSigners = new KnownSignersStore(storage, masterKey, {
      partition: "memory_provenance",
    });
    const persistedMemorySigners = await memoryProvenanceSigners.loadAll();
    const persistedByDid = new Map(persistedMemorySigners.map((entry) => [entry.did, entry.publicKey]));
    const resolveProvenanceSigner = (identityId: string, did: string) =>
      signerPublicKey(identityId, did) ?? persistedByDid.get(did)?.slice();
    const rememberProvenanceSigner = (did: string, publicKey: Uint8Array) => {
      const prior = persistedByDid.get(did);
      if (prior !== undefined && !Buffer.from(prior).equals(Buffer.from(publicKey))) {
        throw new Error("Persisted memory-provenance signer conflicts with the runtime resolver");
      }
      persistedByDid.set(did, publicKey.slice());
    };
    const migration = new SdwMemoryProvenanceMigration({
      storage,
      masterKey,
      fortressId,
      ownerRef: parsed.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: signerPublicKey,
    });
    const badSignerStore: MemoryProvenanceBadSignerStore = new MemoryProvenanceBadSignerStore({
      storage,
      masterKey,
      fortressId,
      resolveSignerPublicKey: (did) => persistedByDid.get(did)?.slice(),
      isLocallyRootedSigner: (did, publicKey) => {
        if (primary.did !== did) return false;
        return Buffer.from(primary.public_key, "base64url").equals(Buffer.from(publicKey));
      },
      scanForeignDependencies: (did, fingerprint) =>
        adapter.scanForeignSignerDependencies(did, fingerprint),
    });
    const adapter: SdwMemoryBackendAdapter = new SdwMemoryBackendAdapter({
      storage,
      masterKey,
      fortressId,
      ownerRef: parsed.ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey: resolveProvenanceSigner,
      resolveMemoryIntegrityState: () => migration.getState(),
      badSignerAuthority: badSignerStore,
    });
    return {
      storage,
      journalStorage,
      admissionWriteGuard,
      masterKey,
      identityKey,
      auditLog: memoryArchiveAuditLog,
      baseline: new BaselineTracker(storage, masterKey),
      adapter,
      memoryProvenanceSigners,
      badSignerStore,
      resolveProvenanceSigner,
      rememberProvenanceSigner,
      signer: {
        identity_id: primary.identity_id,
        fortress_id: fortressId,
        public_key: primary.public_key,
        did: primary.did,
        sign: (bytes) => sign(bytes, primary.encrypted_private_key, signingKey),
      },
    };
  } catch {
    identityKey?.fill(0);
    masterKey?.fill(0);
    write(err, "Error: could not open or unlock the fortress.\n");
    return null;
  }
}

async function dispose(boot: Bootstrapped | null): Promise<void> {
  if (!boot) return;
  await boot.auditLog.flush().catch(() => undefined);
  boot.identityKey.fill(0);
  boot.masterKey.fill(0);
}

async function readBundle(inputPath: string): Promise<{
  manifest: ExitV2SdwMemoryManifest;
  artifactBytes: Uint8Array;
  artifactSha256: string;
}> {
  const manifestPath = join(inputPath, "manifest.json");
  const artifactPath = join(inputPath, ARTIFACT_PATH);
  const [manifestBytes, artifactBytes] = await Promise.all([
    readBoundedRegularFile(manifestPath, MAX_MANIFEST_BYTES),
    readBoundedRegularFile(artifactPath, MAX_ARTIFACT_BYTES),
  ]);
  const manifest = JSON.parse(
    new TextDecoder().decode(manifestBytes),
  ) as ExitV2SdwMemoryManifest;
  const artifactEntry = manifest.body?.artifacts?.find(
    (entry) => entry.path === ARTIFACT_PATH,
  );
  if (!artifactEntry) throw new Error("missing artifact entry");
  return {
    manifest,
    artifactBytes,
    artifactSha256: createHash("sha256").update(artifactBytes).digest("hex"),
  };
}

async function readBoundedRegularFile(path: string, maxBytes: number): Promise<Uint8Array> {
  // The descriptor is opened once and is the object both bounded and read, so
  // replacing the path cannot swap in a larger allocation after validation.
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maxBytes) {
      throw new Error("invalid bundle bounds");
    }
    const bounded = new Uint8Array(maxBytes + BOUND_EXCESS_SENTINEL_BYTES);
    let offset = 0;
    while (offset < bounded.byteLength) {
      const { bytesRead } = await handle.read(
        bounded,
        offset,
        bounded.byteLength - offset,
        offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > maxBytes) {
      bounded.fill(0);
      throw new Error("invalid bundle bounds");
    }
    const exact = bounded.slice(0, offset);
    bounded.fill(0);
    return exact;
  } finally {
    await handle.close();
  }
}

function resolveInteraction(
  injected: PrivateMemoryArchiveInteraction | null | undefined,
  dialogRunner: MemoryArchiveDialogRunner | undefined,
  err: Writable,
): PrivateMemoryArchiveInteraction | null {
  if (injected === null) {
    write(err, "Error: a local OS approval dialog is required.\n");
    return null;
  }
  if (injected !== undefined) return injected;
  if (process.platform !== "darwin" && dialogRunner === undefined) {
    // A PTY cannot prove a local human. Platforms without the reviewed local
    // dialog boundary fail closed until they gain an equivalent OS primitive.
    write(err, "Error: a local OS approval dialog is unavailable on this platform.\n");
    return null;
  }
  return new MacOsLocalHumanInteraction(dialogRunner ?? runMacOsDialog);
}

// Exported so tests can exercise the splice-site alphabet guard in
// discloseAndConfirm directly, with a dialogRunner that asserts it is never
// invoked for a rejected value. Production callers still reach this class
// only through resolveInteraction.
export class MacOsLocalHumanInteraction implements PrivateMemoryArchiveInteraction {
  constructor(private readonly runDialog: MemoryArchiveDialogRunner) {}

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    const prompt =
      "Sanctuary Tier-1 approval required\n\n" +
      `Operation: ${request.operation}\n` +
      `Metadata: ${JSON.stringify(request.context)}`;
    const script = textBytes(
      "const app = Application.currentApplication();\n" +
        "app.includeStandardAdditions = true;\n" +
        "(() => { try {\n" +
        `const chosen = app.displayDialog(${javaScriptString(prompt)}, ` +
        '{buttons: ["Deny", "Approve"], defaultButton: "Deny", ' +
        'cancelButton: "Deny", withTitle: "Sanctuary"});\n' +
        'return chosen.buttonReturned === "Approve" ? "approve" : "deny";\n' +
        '} catch (_) { return "deny"; } })();\n',
    );
    const answerBytes = this.invoke(script);
    try {
      const answer = new TextDecoder().decode(answerBytes).trim();
      return {
        decision: answer === "approve" ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    } finally {
      answerBytes.fill(0);
    }
  }

  async discloseAndConfirm(value: Uint8Array): Promise<boolean> {
    if (value.byteLength !== TRANSFER_KEY_TEXT_BYTES) return false;
    // `value` is spliced verbatim into the JXA source string below rather than
    // passed as a separate data argument, so any byte outside the base64url
    // alphabet could close the quoted string literal and inject script into
    // the osascript source. The length check above bounds size, not content;
    // this assertion, at the splice site, bounds content before it is used.
    if (!isBase64urlAlphabet(value)) return false;
    const script = joinBytes([
      textBytes(
        "const app = Application.currentApplication();\n" +
          "app.includeStandardAdditions = true;\n" +
          'app.displayDialog("Exit V2 recovery material (shown once):\\n\\n',
      ),
      value,
      textBytes(
        '\\n\\nStore it separately before continuing.", {buttons: ["Cancel", "I stored it"], ' +
          'defaultButton: "I stored it", cancelButton: "Cancel", withTitle: "Sanctuary"});\n' +
          'const entered = app.displayDialog("Re-enter the recovery material to confirm custody", ' +
          '{defaultAnswer: "", hiddenAnswer: true, buttons: ["Cancel", "Confirm"], ' +
          'defaultButton: "Confirm", cancelButton: "Cancel", withTitle: "Sanctuary"});\n' +
          "entered.textReturned;\n",
      ),
    ]);
    const entered = this.invoke(script);
    try {
      return entered.byteLength === value.byteLength &&
        timingSafeEqual(entered, value);
    } finally {
      entered.fill(0);
    }
  }

  async readHidden(prompt: string): Promise<Uint8Array> {
    const script = textBytes(
      "const app = Application.currentApplication();\n" +
        "app.includeStandardAdditions = true;\n" +
        "(() => { try {\n" +
        `const entered = app.displayDialog(${javaScriptString(prompt)}, ` +
        '{defaultAnswer: "", hiddenAnswer: true, buttons: ["Cancel", "Continue"], ' +
        'defaultButton: "Continue", cancelButton: "Cancel", withTitle: "Sanctuary"});\n' +
        "return entered.textReturned;\n" +
        '} catch (_) { return ""; } })();\n',
    );
    const entered = this.invoke(script);
    if (entered.byteLength > MAX_HIDDEN_INPUT_BYTES) {
      entered.fill(0);
      throw new Error("hidden input too long");
    }
    return entered;
  }

  close(): void {}

  private invoke(script: Uint8Array): Uint8Array {
    try {
      const result = this.runDialog(script);
      if (result.status !== 0 || result.signal !== null) {
        result.stdout.fill(0);
        throw new Error("local OS dialog failed");
      }
      const output = trimAsciiWhitespace(result.stdout);
      result.stdout.fill(0);
      return output;
    } finally {
      script.fill(0);
    }
  }
}

function runMacOsDialog(script: Uint8Array): MemoryArchiveDialogResult {
  const result = spawnSync("/usr/bin/osascript", ["-l", "JavaScript", "-"], {
    input: script,
    encoding: null,
    maxBuffer: MAX_LOCAL_DIALOG_OUTPUT_BYTES,
    timeout: LOCAL_DIALOG_TIMEOUT_MS,
    killSignal: "SIGKILL",
    shell: false,
    windowsHide: true,
  });
  const stdout = new Uint8Array(result.stdout ?? new Uint8Array());
  result.stdout?.fill(0);
  result.stderr?.fill(0);
  if (result.error !== undefined) {
    stdout.fill(0);
    throw new Error("local OS dialog failed");
  }
  return { status: result.status, signal: result.signal, stdout };
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function joinBytes(parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function trimAsciiWhitespace(value: Uint8Array): Uint8Array {
  let start = 0;
  let end = value.byteLength;
  while (
    start < end &&
    (value[start] === ASCII_LINE_FEED ||
      value[start] === ASCII_CARRIAGE_RETURN ||
      value[start] === ASCII_SPACE)
  ) start++;
  while (
    end > start &&
    (value[end - 1] === ASCII_LINE_FEED ||
      value[end - 1] === ASCII_CARRIAGE_RETURN ||
      value[end - 1] === ASCII_SPACE)
  ) end--;
  // Uint8Array.from always copies; Buffer.slice would alias the source and be
  // erased when invoke() clears the subprocess output buffer below.
  return Uint8Array.from(value.subarray(start, end));
}

function javaScriptString(value: string): string {
  return JSON.stringify(value);
}

function encodeTransferKey(key: Uint8Array): Uint8Array {
  if (key.byteLength !== TRANSFER_KEY_BYTES) throw new Error("invalid key length");
  const output = new Uint8Array(TRANSFER_KEY_TEXT_BYTES);
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (const byte of key) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      output[offset++] = BASE64URL_ALPHABET[(accumulator >>> bits) & 63]!;
    }
  }
  if (bits > 0) output[offset++] = BASE64URL_ALPHABET[(accumulator << (6 - bits)) & 63]!;
  if (offset !== TRANSFER_KEY_TEXT_BYTES) throw new Error("invalid encoded length");
  return output;
}

function decodeTransferKey(input: Uint8Array): Uint8Array {
  if (input.byteLength !== TRANSFER_KEY_TEXT_BYTES) throw new Error("invalid key length");
  const output = new Uint8Array(TRANSFER_KEY_BYTES);
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (const byte of input) {
    const value = base64urlValue(byte);
    if (value < 0) {
      output.fill(0);
      throw new Error("invalid key encoding");
    }
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (offset < output.length) output[offset++] = (accumulator >>> bits) & 255;
    }
  }
  if (offset !== TRANSFER_KEY_BYTES || bits !== 2 || (accumulator & 3) !== 0) {
    output.fill(0);
    throw new Error("invalid key encoding");
  }
  return output;
}

function isBase64urlAlphabet(value: Uint8Array): boolean {
  for (const byte of value) {
    if (base64urlValue(byte) < 0) return false;
  }
  return true;
}

function base64urlValue(byte: number): number {
  if (byte >= 65 && byte <= 90) return byte - 65;
  if (byte >= 97 && byte <= 122) return byte - 97 + 26;
  if (byte >= 48 && byte <= 57) return byte - 48 + 52;
  if (byte === 45) return 62;
  if (byte === 95) return 63;
  return -1;
}

function parseExport(argv: string[], err: Writable): ParsedExport | null {
  if (containsSecretArgvFlag(argv)) {
    write(err, "Error: recovery material and fortress passphrases cannot be supplied in argv.\n");
    return null;
  }
  const parsed = parseFlags(argv, ["--archive-id", "--out", "--owner-ref", "--fortress"]);
  if (!parsed || parsed.unknown.length > 0) {
    write(err, "Usage: sanctuary memory_archive_export --archive-id <id> --out <dir> --owner-ref <id> --fortress <path>\n");
    return null;
  }
  const archiveId = parsed.values.get("--archive-id");
  const outputPath = parsed.values.get("--out");
  const fortressPath = parsed.values.get("--fortress");
  const ownerRef = parsed.values.get("--owner-ref");
  if (!archiveId || !ARCHIVE_ID.test(archiveId) || !outputPath || !ownerRef || !fortressPath || !SAFE_OWNER_REF.test(ownerRef)) {
    write(err, "Usage: sanctuary memory_archive_export --archive-id <id> --out <dir> --owner-ref <id> --fortress <path>\n");
    return null;
  }
  return {
    archiveId,
    outputPath: resolve(outputPath),
    ownerRef,
    fortressPath: resolve(fortressPath),
    json: parsed.switches.has("--json"),
  };
}

function parseImport(argv: string[], err: Writable): ParsedImport | null {
  const parsed = parseFlags(argv, ["--in", "--owner-ref", "--fortress"]);
  if (!parsed || parsed.unknown.length > 0) {
    write(err, "Usage: sanctuary memory_archive_import --in <dir> --owner-ref <id> --fortress <path>\n");
    return null;
  }
  const inputPath = parsed.values.get("--in");
  const fortressPath = parsed.values.get("--fortress");
  const ownerRef = parsed.values.get("--owner-ref");
  if (!inputPath || !ownerRef || !fortressPath || !SAFE_OWNER_REF.test(ownerRef)) {
    write(err, "Usage: sanctuary memory_archive_import --in <dir> --owner-ref <id> --fortress <path>\n");
    return null;
  }
  return {
    inputPath: resolve(inputPath),
    ownerRef,
    fortressPath: resolve(fortressPath),
    json: parsed.switches.has("--json"),
  };
}

function parseBadSigner(
  argv: string[],
  action: "mark" | "clear",
  err: Writable,
): ParsedBadSigner | null {
  const parsed = parseFlags(argv, [
    "--signer-did", "--public-key-sha256", "--reason", "--owner-ref", "--fortress",
  ]);
  const signerDid = parsed?.values.get("--signer-did");
  const publicKeySha256 = parsed?.values.get("--public-key-sha256");
  const reason = parsed?.values.get("--reason");
  const ownerRef = parsed?.values.get("--owner-ref");
  const fortressPath = parsed?.values.get("--fortress");
  if (parsed === null || parsed.unknown.length > 0 || signerDid === undefined ||
      publicKeySha256 === undefined || ownerRef === undefined || fortressPath === undefined ||
      !SAFE_OWNER_REF.test(ownerRef) || (action === "mark" && reason === undefined) ||
      (action === "clear" && reason !== undefined)) {
    write(err, `Usage: sanctuary memory_provenance_${action === "mark" ? "mark" : "clear"}_bad_signer --signer-did <did> --public-key-sha256 <hex> ${action === "mark" ? "--reason <text> " : ""}--owner-ref <id> --fortress <path>\n`);
    return null;
  }
  return {
    signerDid,
    publicKeySha256,
    ...(reason === undefined ? {} : { reason }),
    ownerRef,
    fortressPath: resolve(fortressPath),
    json: parsed.switches.has("--json"),
  };
}

function parseFlags(argv: string[], valueFlags: readonly string[]): {
  values: Map<string, string>;
  switches: Set<string>;
  unknown: string[];
} | null {
  const values = new Map<string, string>();
  const switches = new Set<string>();
  const unknown: string[] = [];
  let remaining = [...argv];
  for (const flag of valueFlags) {
    const consumed = consumeFlagValue(remaining, flag);
    if (consumed.error !== undefined) return null;
    remaining = consumed.argv;
    if (consumed.value !== undefined) values.set(flag, consumed.value);
  }
  for (const token of remaining) {
    if (token === "--json") {
      switches.add(token);
      continue;
    }
    unknown.push(token.split("=", 1)[0]!);
  }
  return { values, switches, unknown };
}

function containsSecretArgvFlag(argv: readonly string[]): boolean {
  return argv.some((token) => {
    const name = token.split("=", 1)[0]!.toLowerCase();
    return name === "--passphrase" || name === "--key" ||
      (name.startsWith("--") && /(?:transfer|recovery).*key/.test(name));
  });
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function printExportHelp(out: Writable): void {
  write(out, `Usage: sanctuary memory_archive_export --archive-id <id> --out <dir> --owner-ref <id> --fortress <path> [options]\n\nExports one completed SDW transcode archive through Exit V2 after Tier-1 approval.\nRecovery material is shown once in a local OS dialog and must be re-entered before success.\nFortress custody is read from SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY, never argv.\n\nOptions:\n  --owner-ref <id>       Required exact SDW owner scope.\n  --json                 Emit a metadata-only JSON receipt.\n  --help, -h             Show this help.\n`);
}

function printImportHelp(out: Writable): void {
  write(out, `Usage: sanctuary memory_archive_import --in <dir> --owner-ref <id> --fortress <path> [options]\n\nAuthenticates one Exit V2 SDW memory archive before any destination write, then imports it after Tier-1 approval.\nRecovery material is read through a hidden local OS dialog and is re-entered after approval.\nFortress custody is read from SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY, never argv.\n\nOptions:\n  --owner-ref <id>       Required exact destination SDW owner scope.\n  --json                 Emit a metadata-only JSON receipt.\n  --help, -h             Show this help.\n`);
}
