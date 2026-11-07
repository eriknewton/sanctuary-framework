/**
 * Exit V2 SDW memory archive CLI composition tests.
 *
 * Every fortress and bundle is disposable. Transfer material is observable
 * only through the injected local-human interaction seam.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  constants as fsConstants,
  mkdir,
  mkdtemp,
  open as openFile,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

// fail-before-exempt: C4 adds subprocess help assertions that execute the already-built dist/cli.js, which source-only reversal intentionally leaves in place; live C4 admission, authority, Tier-1, and structural tests fail against pre-C4 source. This file also retains its C3 fixture-only durable-state resolver wiring, covered by the C3 migration and contract suites.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as crossProcessLock from "../../src/storage/cross-process-lock.js";
import * as custody from "../../src/core/master-custody.js";
import * as localUnlock from "../../src/cli/local-fortress-unlock.js";
import * as baselineModule from "../../src/principal-policy/baseline.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import { kernelBackedCrossProcessLockPlatformSupported, withExclusiveMasterRotationBarrier, type MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { stringToBytes } from "../../src/core/encoding.js";
import {
  MacOsLocalHumanInteraction,
  runMemoryArchiveExportCommand,
  runMemoryArchiveImportCommand,
  runMemoryProvenancePruneSignersCommand,
  runMemoryProvenanceMarkBadSignerCommand,
  runMemoryProvenanceClearBadSignerCommand,
  type MemoryArchiveDialogRunner,
  type PrivateMemoryArchiveInteraction,
} from "../../src/cli/memory-archive.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../../src/principal-policy/types.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../../src/sdw/memory-provenance-signing.js";
import { ingestClaudeCodeMemoryDirectory } from "../../src/sdw/adapters/claude-code-file-adapter.js";
import { transcodeMemoryDirectory } from "../../src/sdw/memory-transcode.js";
import { SdwMemoryProvenanceMigration } from "../../src/sdw/memory-provenance-migration.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  persistUserProvidedPassphrase,
  readStoredPassphrase,
} from "../../src/wrap/passphrase.js";
import { runExitCommand } from "../../src/exit/cli.js";
import { MAX_ARTIFACT_BYTES as MEMORY_ARCHIVE_ARTIFACT_MAX_BYTES } from "../../src/exit/v2-memory-archive.js";
import {
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  runCli,
} from "./helpers/run-cli.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url),
);
const PASSPHRASE = "exit-v2-memory-cli-disposable-passphrase";
// Must match the memory archive artifact path written by runMemoryArchiveExportCommand.
const MEMORY_ARCHIVE_ARTIFACT_PATH = "artifacts/sdw-memory-archive.json";
const OVER_CAP_SENTINEL_BYTES = 1; // One byte over the artifact ceiling must be refused.
// A blocking FIFO read waits forever; the descriptor reader returns quickly,
// so the old 250 ms probe can keep 20x headroom and still catch the regression.
const FIFO_REJECTION_PROBE_MS = 250;
const FIFO_REJECTION_HEADROOM_MULTIPLIER = 20;
const FIFO_REJECTION_DEADLINE_MS =
  FIFO_REJECTION_PROBE_MS * FIFO_REJECTION_HEADROOM_MULTIPLIER;
// Five seconds bounds the fixture setup command that creates a FIFO node.
const FIFO_SETUP_TIMEOUT_MS = 5_000;
const cleanup: string[] = [];

class Sink extends Writable {
  readonly chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

// Fails synchronously on every write, unlike Sink. Used to force a failure at
// the receipt-write step, which runs only after an import has already
// committed the destination archive, to exercise the post-commit phase-aware
// error message rather than the pre-commit authentication/validation one.
class ThrowingSink extends Writable {
  override write(): boolean {
    throw new Error("synthetic post-commit sink failure");
  }
}

class TestTerminal implements PrivateMemoryArchiveInteraction {
  readonly secretWrites: Uint8Array[] = [];
  readonly returnedHiddenValues: Uint8Array[] = [];
  hiddenReads = 0;
  hiddenValue = new Uint8Array();
  async requestApproval(): Promise<ApprovalResponse> {
    return {
      decision: "approve",
      decided_at: "2026-08-15T21:00:00.000Z",
      decided_by: "human",
    };
  }
  async discloseAndConfirm(value: Uint8Array): Promise<boolean> {
    this.secretWrites.push(value.slice());
    // Model an operator who records the disclosed value and re-enters it to
    // prove custody before export may report success.
    this.hiddenValue = value.slice();
    this.hiddenReads++;
    return true;
  }
  async readHidden(_prompt: string): Promise<Uint8Array> {
    this.hiddenReads++;
    const returned = Uint8Array.from(this.hiddenValue);
    this.returnedHiddenValues.push(returned);
    return returned;
  }
  close(): void {}
}

class RecordingApprovalChannel implements ApprovalChannel {
  readonly requests: ApprovalRequest[] = [];
  constructor(
    private readonly response: ApprovalResponse | Error = {
      decision: "approve",
      decided_at: "2026-08-15T21:00:00.000Z",
      decided_by: "human",
    },
  ) {}
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    this.requests.push(structuredClone(request));
    if (this.response instanceof Error) throw this.response;
    return this.response;
  }
}

function interactionWithApproval(
  terminal: TestTerminal,
  approval: RecordingApprovalChannel,
): PrivateMemoryArchiveInteraction {
  return {
    requestApproval: (request) => approval.requestApproval(request),
    discloseAndConfirm: (value) => terminal.discloseAndConfirm(value),
    readHidden: (prompt) => terminal.readHidden(prompt),
    close: () => terminal.close(),
  };
}

interface Fortress {
  readonly path: string;
  readonly storage: FilesystemStorage;
  readonly masterKey: Uint8Array;
  readonly archiveId?: string;
}

const rescueLeases: MasterWriteBarrierLease[] = [];
beforeEach(() => {
  const acquire = crossProcessLock.acquireMasterWriteBarrier;
  vi.spyOn(crossProcessLock, "acquireMasterWriteBarrier").mockImplementation(async (...args) => {
    const lease = await acquire(...args);
    rescueLeases.push(lease);
    return lease;
  });
});

afterEach(async () => {
  // Rescue runs after assertions so retained fixture sessions cannot affect another case.
  try {
    await Promise.all(rescueLeases.splice(0).map(lease => lease.release()));
  } finally {
    vi.restoreAllMocks();
  }
  delete process.env.SANCTUARY_STORAGE_PATH;
  while (cleanup.length > 0) {
    await rm(cleanup.pop()!, { recursive: true, force: true });
  }
});

async function tempDir(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanup.push(path);
  return path;
}

async function fortress(prefix: string, ownerRef: string, withArchive: boolean): Promise<Fortress> {
  const path = join(await tempDir(prefix), ".sanctuary");
  const statePath = join(path, "state");
  await mkdir(statePath, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(statePath);
  const { key: masterKey, params } = await deriveMasterKey(PASSPHRASE);
  await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
  const identityManager = new IdentityManager(storage, masterKey);
  const { storedIdentity } = createIdentity(
    `${prefix}-identity`,
    derivePurposeKey(masterKey, "identity-encryption"),
    "passphrase",
  );
  const writes: Promise<void>[] = [];
  const write = storage.write.bind(storage);
  const spy = vi.spyOn(storage, "write").mockImplementation((...args) => {
    const pending = write(...args);
    writes.push(pending);
    return pending;
  });
  try {
    await identityManager.save(storedIdentity);
  } finally {
    await Promise.all(writes);
    spy.mockRestore();
  }
  if (!withArchive) {
    await completeMemoryMigration(storage, masterKey, path, ownerRef);
    return { path, storage, masterKey };
  }

  const adapter = await productionAdapter(storage, masterKey, fortressId(path), ownerRef);
  await ingestClaudeCodeMemoryDirectory(adapter, FIXTURE_ROOT);
  const projectionParent = await tempDir(`${prefix}-projection`);
  const transcoded = await transcodeMemoryDirectory(
    adapter,
    "claude-code",
    "codex",
    join(projectionParent, "projection"),
  );
  await completeMemoryMigration(storage, masterKey, path, ownerRef);
  return { path, storage, masterKey, archiveId: transcoded.archive_id };
}

async function completeMemoryMigration(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  path: string,
  ownerRef: string,
): Promise<void> {
  const identities = new IdentityManager(storage, masterKey);
  await identities.load();
  const migration = new SdwMemoryProvenanceMigration({
    storage, masterKey, fortressId: fortressId(path), ownerRef,
    resolvePrimarySigningHandle: createPrimaryMemoryProvenanceSigningHandleResolver(identities, masterKey),
    resolveSignerPublicKey: createPrimaryMemoryProvenancePublicKeyResolver(identities),
  });
  for (let page = 0; page < 20; page++) {
    const progress = await migration.migratePage();
    if (progress.completed) break;
    if (page === 19) throw new Error("disposable memory provenance migration did not complete");
  }
}

async function productionAdapter(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  boundFortressId: string,
  ownerRef: string,
): Promise<SdwMemoryBackendAdapter> {
  const identities = new IdentityManager(storage, masterKey);
  await identities.load();
  return new SdwMemoryBackendAdapter({
    storage,
    masterKey,
    fortressId: boundFortressId,
    ownerRef,
    resolvePrimarySigningHandle: createPrimaryMemoryProvenanceSigningHandleResolver(identities, masterKey),
    resolveSignerPublicKey: createPrimaryMemoryProvenancePublicKeyResolver(identities),
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
  });
}

function fortressId(path: string): string {
  return `fortress-${createHash("sha256").update(path).digest("hex").slice(0, 16)}`;
}

function sinkPair(): { out: Sink; err: Sink } {
  return { out: new Sink(), err: new Sink() };
}

async function releaseFifoReaderIfWaiting(path: string): Promise<void> {
  try {
    const handle = await openFile(
      path,
      fsConstants.O_WRONLY | fsConstants.O_NONBLOCK,
    );
    await handle.close();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENXIO") throw error;
  }
}

async function exportBundle(source: Fortress, ownerRef = "owner-a", json = false) {
  const bundle = join(await tempDir("exit-v2-cli-bundle-parent"), "bundle");
  const terminal = new TestTerminal();
  const approval = new RecordingApprovalChannel();
  const { out, err } = sinkPair();
  let observedMaster: Uint8Array | undefined;
  const code = await runMemoryArchiveExportCommand({
    argv: [
      "--archive-id", source.archiveId!,
      "--out", bundle,
      "--owner-ref", ownerRef,
      "--fortress", source.path,
      ...(json ? ["--json"] : []),
    ],
    out,
    err,
    stdin: Readable.from(["ordinary-stdin-must-not-be-read\n"]),
    env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    interaction: interactionWithApproval(terminal, approval),
    observeMasterKey: (master) => { observedMaster = master; },
  });
  return { bundle, terminal, approval, out, err, code, observedMaster };
}

function secretText(terminal: TestTerminal): string {
  return Buffer.concat(terminal.secretWrites.map((item) => Buffer.from(item))).toString("ascii");
}

async function allFiles(root: string): Promise<string[]> {
  const result: string[] = [];
  async function walk(dir: string): Promise<void> {
    for (const name of await readdir(dir)) {
      const path = join(dir, name);
      if ((await stat(path)).isDirectory()) await walk(path);
      else result.push(path);
    }
  }
  await walk(root);
  return result;
}

async function treeSnapshot(root: string): Promise<Map<string, Buffer>> {
  const snapshot = new Map<string, Buffer>();
  for (const path of await allFiles(root)) {
    snapshot.set(path.slice(root.length), await readFile(path));
  }
  return snapshot;
}

describe("Exit V2 memory archive CLI", () => {
  it("exports after Tier-1 approval and discloses a fresh key exactly once in the local OS dialog", async () => {
    const source = await fortress("exit-v2-cli-source", "owner-a", true);
    const result = await exportBundle(source, "owner-a", true);
    expect(result.code).toBe(0);
    expect(result.observedMaster).toBeDefined();
    expect([...result.observedMaster!].every((byte) => byte === 0)).toBe(true);
    expect(result.terminal.secretWrites).toHaveLength(1);
    expect(result.terminal.hiddenReads).toBe(1);
    const transferKey = secretText(result.terminal);
    expect(transferKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.out.text()).not.toContain(transferKey);
    expect(result.err.text()).not.toContain(transferKey);
    expect(JSON.parse(result.out.text())).not.toHaveProperty("transfer_key");
    expect(result.approval.requests).toHaveLength(1);
    expect(result.approval.requests[0]).toMatchObject({
      operation: "memory_archive_export",
      tier: 1,
      context: {
        operation: "memory_archive_export",
        args_summary: {
          agent_id: null,
          archive_id: source.archiveId,
          owner_ref: "owner-a",
          output_path: result.bundle,
        },
      },
    });

    const receipt = JSON.parse(result.out.text()) as {
      approval_audit_id: string;
    };
    const manifest = JSON.parse(
      await readFile(join(result.bundle, "manifest.json"), "utf8"),
    ) as { body: { export_approval_audit_id: string } };
    const artifact = JSON.parse(
      await readFile(join(result.bundle, "artifacts", "sdw-memory-archive.json"), "utf8"),
    ) as { format: string };
    expect(artifact.format).toBe("SANCTUARY_EXIT_V2_SDW_MEMORY_ARCHIVE_V2");
    const gateEvents = await new AuditLog(source.storage, source.masterKey).query({
      operation_type: "gate_approve:memory_archive_export",
      limit: 10,
    });
    expect(gateEvents.entries).toHaveLength(1);
    expect(gateEvents.entries[0]?.details).toMatchObject({
      approval_audit_id: receipt.approval_audit_id,
      normalized_args_hash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(manifest.body.export_approval_audit_id).toBe(receipt.approval_audit_id);

    const filenames = (await allFiles(result.bundle)).map((path) => path.slice(result.bundle.length));
    const bundleBytes = Buffer.concat(await Promise.all(
      (await allFiles(result.bundle)).map((path) => readFile(path)),
    )).toString("utf8");
    expect(filenames.join("\n")).not.toContain(transferKey);
    expect(bundleBytes).not.toContain(transferKey);
    const rawTransferKey = Buffer.from(transferKey, "base64url");
    for (const path of await allFiles(result.bundle)) {
      expect((await readFile(path)).indexOf(rawTransferKey), path).toBe(-1);
    }
    const auditBytes = Buffer.concat(await Promise.all(
      (await allFiles(join(source.path, "state", "_audit"))).map((path) => readFile(path)),
    )).toString("utf8");
    expect(auditBytes).not.toContain(transferKey);
    const auditEntries = await new AuditLog(source.storage, source.masterKey).query({
      limit: 100,
    });
    expect(JSON.stringify(auditEntries.entries)).not.toContain(transferKey);
    for (const path of await allFiles(join(source.path, "state", "_audit"))) {
      expect((await readFile(path)).indexOf(rawTransferKey), path).toBe(-1);
    }
  }, 60_000);

  it("denial and approval-channel failure happen before export mutation", async () => {
    const source = await fortress("exit-v2-cli-denied-source", "owner-a", true);
    for (const response of [
      {
        decision: "deny",
        decided_at: "2026-08-15T21:00:00.000Z",
        decided_by: "human",
      } as ApprovalResponse,
      new Error("approval unavailable"),
    ]) {
      const bundle = join(await tempDir("exit-v2-cli-denied-parent"), "bundle");
      const { out, err } = sinkPair();
      const code = await runMemoryArchiveExportCommand({
        argv: [
          "--archive-id", source.archiveId!, "--out", bundle,
          "--owner-ref", "owner-a", "--fortress", source.path,
        ],
        out,
        err,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        interaction: interactionWithApproval(
          new TestTerminal(),
          new RecordingApprovalChannel(response),
        ),
      });
      expect(code).toBe(1);
      await expect(stat(bundle)).rejects.toMatchObject({ code: "ENOENT" });
    }
  }, 60_000);

  it("binds the signer-prune CLI to the real Tier-1 approval decision before signer mutation", async () => {
    const target = await fortress("signer-prune-cli-denied", "fleet-self", false);
    const approval = new RecordingApprovalChannel({
      decision: "deny",
      decided_at: "2026-08-25T00:00:00.000Z",
      decided_by: "human",
    });
    const before = await target.storage.list("_known_signers");
    const { out, err } = sinkPair();
    expect(await runMemoryProvenancePruneSignersCommand({
      argv: ["--fortress", target.path, "--json"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(new TestTerminal(), approval),
    })).toBe(1);
    expect(approval.requests).toHaveLength(1);
    expect(approval.requests[0]!.operation).toBe("memory_provenance_prune_signers");
    expect(await target.storage.list("_known_signers")).toEqual(before);
    expect(out.text()).toBe("");
  }, 60_000);

  it("imports only a hidden local-dialog key, ignores env and ordinary stdin, and preserves destination-local identity", async () => {
    const source = await fortress("exit-v2-cli-import-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-destination", "owner-a", false);
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const approval = new RecordingApprovalChannel();
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: [
        "--in", exported.bundle,
        "--owner-ref", "owner-a",
        "--fortress", destination.path,
        "--json",
      ],
      out,
      err,
      stdin: Readable.from([`${secretText(exported.terminal)}\n`]),
      env: {
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_EXIT_TRANSFER_KEY: "wrong-env-value-must-be-ignored",
      },
      interaction: interactionWithApproval(terminal, approval),
    });
    expect(code, err.text()).toBe(0);
    expect(terminal.hiddenReads).toBe(2);
    expect(terminal.returnedHiddenValues.every((value) => value.every((byte) => byte === 0))).toBe(true);
    expect(out.text()).not.toContain(secretText(exported.terminal));
    expect(err.text()).not.toContain(secretText(exported.terminal));
    const receipt = JSON.parse(out.text()) as Record<string, unknown>;
    expect(receipt).toMatchObject({ replayed: false });
    expect(receipt).not.toHaveProperty("transfer_key");
    expect(String(receipt.destination_archive_id)).not.toBe(source.archiveId);
    expect(approval.requests[0]?.context).toMatchObject({
      args_summary: {
        agent_id: null,
        owner_ref: "owner-a",
      },
    });
    expect(approval.requests[0]?.context).not.toHaveProperty("transfer_key");
    expect(approval.requests[0]?.context.args_summary).not.toHaveProperty(
      "approval_audit_id",
    );
    const destinationAudit = new AuditLog(destination.storage, destination.masterKey);
    const importGateEvents = await destinationAudit.query({
      operation_type: "gate_approve:memory_archive_import",
      limit: 10,
    });
    const importEvents = await destinationAudit.query({
      operation_type: "memory_archive_import",
      limit: 10,
    });
    expect(importGateEvents.entries).toHaveLength(1);
    expect(importEvents.entries).toHaveLength(1);
    const importApprovalAuditId = (
      importEvents.entries[0]!.details as Record<string, unknown>
    ).approval_audit_id;
    expect(importGateEvents.entries[0]?.details).toMatchObject({
      approval_audit_id: importApprovalAuditId,
      normalized_args_hash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    const otherOwner = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), "owner-b");
    const destinationOwner = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), "owner-a");
    expect(await destinationOwner.countPassages()).toBeGreaterThan(0);
    expect(await otherOwner.countPassages()).toBe(0);
  }, 60_000);

  it("refuses an over-cap archive artifact before opening the destination fortress", async () => {
    const source = await fortress("exit-v2-cli-overcap-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-overcap-destination", "owner-a", false);
    const destinationBefore = await treeSnapshot(destination.path);
    const artifactPath = join(exported.bundle, MEMORY_ARCHIVE_ARTIFACT_PATH);
    await writeFile(
      artifactPath,
      Buffer.alloc(MEMORY_ARCHIVE_ARTIFACT_MAX_BYTES + OVER_CAP_SENTINEL_BYTES),
    );
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
    });
    expect(code).toBe(1);
    expect(err.text()).toContain(artifactPath);
    expect(err.text()).toContain("exceeds");
    expect(terminal.hiddenReads).toBe(0);
    expect(await treeSnapshot(destination.path)).toEqual(destinationBefore);
  }, 60_000);

  it("refuses a symlinked archive artifact before opening the destination fortress", async () => {
    const source = await fortress("exit-v2-cli-symlink-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-symlink-destination", "owner-a", false);
    const destinationBefore = await treeSnapshot(destination.path);
    const artifactPath = join(exported.bundle, MEMORY_ARCHIVE_ARTIFACT_PATH);
    const targetPath = join(exported.bundle, "artifacts", "artifact-copy.json");
    await writeFile(targetPath, await readFile(artifactPath));
    await rm(artifactPath);
    await symlink(targetPath, artifactPath);
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
    });
    expect(code).toBe(1);
    expect(err.text()).toContain(artifactPath);
    expect(err.text()).toContain("symbolic links are not permitted");
    expect(terminal.hiddenReads).toBe(0);
    expect(await treeSnapshot(destination.path)).toEqual(destinationBefore);
  }, 60_000);

  it("refuses a symlinked archive artifacts directory before opening the destination fortress", async () => {
    const source = await fortress("exit-v2-cli-symlink-dir-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-symlink-dir-destination", "owner-a", false);
    const destinationBefore = await treeSnapshot(destination.path);
    const artifactPath = join(exported.bundle, MEMORY_ARCHIVE_ARTIFACT_PATH);
    const originalArtifact = await readFile(artifactPath);
    const outsideArtifacts = await tempDir("exit-v2-cli-artifacts-target");
    await writeFile(join(outsideArtifacts, "sdw-memory-archive.json"), originalArtifact);
    await rm(join(exported.bundle, "artifacts"), { recursive: true, force: true });
    await symlink(outsideArtifacts, join(exported.bundle, "artifacts"));
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
    });
    expect(code).toBe(1);
    expect(err.text()).toContain(artifactPath);
    expect(err.text()).toContain("symbolic links are not permitted");
    expect(terminal.hiddenReads).toBe(0);
    expect(await treeSnapshot(destination.path)).toEqual(destinationBefore);
  }, 60_000);

  it("refuses a FIFO archive artifact without waiting for a writer", async () => {
    const source = await fortress("exit-v2-cli-fifo-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-fifo-destination", "owner-a", false);
    const destinationBefore = await treeSnapshot(destination.path);
    const artifactPath = join(exported.bundle, MEMORY_ARCHIVE_ARTIFACT_PATH);
    await rm(artifactPath);
    const mkfifo = spawnSync("mkfifo", [artifactPath], {
      encoding: "utf8",
      timeout: FIFO_SETUP_TIMEOUT_MS,
    });
    expect(mkfifo.status, mkfifo.stderr).toBe(0);
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const { out, err } = sinkPair();
    const run = runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
    });
    const raced = await Promise.race([
      run.then((code) => ({ code })),
      delay(FIFO_REJECTION_DEADLINE_MS).then(() => ({ timedOut: true })),
    ]);
    if ("timedOut" in raced) {
      await releaseFifoReaderIfWaiting(artifactPath);
      await run.catch(() => undefined);
    }
    expect(raced).toHaveProperty("code", 1);
    expect(err.text()).toContain(artifactPath);
    expect(err.text()).toContain("not a regular file");
    expect(terminal.hiddenReads).toBe(0);
    expect(await treeSnapshot(destination.path)).toEqual(destinationBefore);
  }, 60_000);

  it("refuses import without a local OS dialog and never reads ordinary stdin", async () => {
    const source = await fortress("exit-v2-cli-notty-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-notty-destination", "owner-a", false);
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out,
      err,
      stdin: Readable.from([`${secretText(exported.terminal)}\n`]),
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: null,
    });
    expect(code).toBe(1);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("local OS approval dialog");
    const adapter = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), "owner-a");
    expect(await adapter.countPassages()).toBe(0);
  }, 60_000);

  it("wrong key, denial, and a different owner scope leave destination archive state untouched", async () => {
    const source = await fortress("exit-v2-cli-fail-source", "owner-a", true);
    const exported = await exportBundle(source);
    for (const ownerRef of ["owner-a", "owner-b"]) {
      const destination = await fortress(`exit-v2-cli-fail-destination-${ownerRef}`, ownerRef, false);
      const destinationBefore = await treeSnapshot(destination.path);
      const terminal = new TestTerminal();
      terminal.hiddenValue = Buffer.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ascii");
      const { out, err } = sinkPair();
      const code = await runMemoryArchiveImportCommand({
        argv: ["--in", exported.bundle, "--owner-ref", ownerRef, "--fortress", destination.path],
        out,
        err,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
      });
      expect(code).toBe(1);
      expect(`${out.text()}${err.text()}`).not.toContain(
        Buffer.from(terminal.hiddenValue).toString("ascii"),
      );
      const adapter = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), ownerRef);
      expect(await adapter.countPassages()).toBe(0);
      expect(await treeSnapshot(destination.path)).toEqual(destinationBefore);
    }

    for (const response of [
      {
        decision: "deny",
        decided_at: "2026-08-15T21:00:00.000Z",
        decided_by: "human",
      } as ApprovalResponse,
      new Error("approval unavailable"),
    ]) {
      const deniedDestination = await fortress("exit-v2-cli-import-denied", "owner-a", false);
      const terminal = new TestTerminal();
      terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
      const code = await runMemoryArchiveImportCommand({
        argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", deniedDestination.path],
        out: new Sink(),
        err: new Sink(),
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        interaction: interactionWithApproval(
          terminal,
          new RecordingApprovalChannel(response),
        ),
      });
      expect(code).toBe(1);
      expect(terminal.hiddenReads).toBe(1);
      const adapter = await productionAdapter(deniedDestination.storage, deniedDestination.masterKey, fortressId(deniedDestination.path), "owner-a");
      expect(await adapter.countPassages()).toBe(0);
    }
  }, 60_000);

  it("reports a distinct, retry-safe message when a post-commit step fails after the archive was already imported", async () => {
    const source = await fortress("exit-v2-cli-postcommit-source", "owner-a", true);
    const exported = await exportBundle(source);
    const destination = await fortress("exit-v2-cli-postcommit-destination", "owner-a", false);
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const approval = new RecordingApprovalChannel();
    const err = new Sink();
    const code = await runMemoryArchiveImportCommand({
      argv: [
        "--in", exported.bundle,
        "--owner-ref", "owner-a",
        "--fortress", destination.path,
        "--json",
      ],
      out: new ThrowingSink(),
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      interaction: interactionWithApproval(terminal, approval),
    });
    expect(code).toBe(1);
    // The old catch-all message misdiagnosed a completed irreversible
    // operation as an authentication/validation failure; this asserts the
    // phase-aware message instead, and that it says retry is safe.
    expect(err.text()).toContain("failed after the archive was imported");
    expect(err.text().toLowerCase()).toContain("safe");
    expect(err.text()).not.toContain("archive authentication or validation failed");
    // The import itself must have durably committed despite the later
    // failure, proving this exercised the post-commit branch and not a
    // pre-commit failure that happens to share the same exit code.
    const adapter = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), "owner-a");
    expect(await adapter.countPassages()).toBeGreaterThan(0);
  }, 60_000);

  it("discloseAndConfirm refuses a non-base64url 43-byte value before any subprocess spawn", async () => {
    let dialogCalls = 0;
    const dialogRunner: MemoryArchiveDialogRunner = () => {
      dialogCalls++;
      throw new Error("the local OS dialog must never be invoked for a rejected splice value");
    };
    const interaction = new MacOsLocalHumanInteraction(dialogRunner);

    // 43 valid base64url bytes with the final byte replaced by `"`, the
    // character that would close the surrounding JXA string literal at the
    // splice site if it reached osascript unchecked.
    const almostValid = new Uint8Array(43).fill(65); // 'A', in-alphabet
    almostValid[42] = 34; // '"'
    await expect(interaction.discloseAndConfirm(almostValid)).resolves.toBe(false);

    // A value built entirely from bytes outside the base64url alphabet.
    const allInvalid = new Uint8Array(43).fill(92); // '\\'
    await expect(interaction.discloseAndConfirm(allInvalid)).resolves.toBe(false);

    expect(dialogCalls).toBe(0);
  });

  it("refuses every argv transfer-key spelling without echoing its value", async () => {
    const secret = "argv-secret-must-never-be-accepted";
    for (const argv of [
      ["--in", "/not-opened", "--transfer-key", secret],
      ["--in", "/not-opened", `--transfer-key=${secret}`],
      ["--in", "/not-opened", "--recovery-key", secret],
      ["--in", "/not-opened", "--passphrase", secret],
      ["--in", "/not-opened", `--passphrase=${secret}`],
    ]) {
      const { out, err } = sinkPair();
      const terminal = new TestTerminal();
      const code = await runMemoryArchiveImportCommand({
        argv,
        out,
        err,
        env: {},
        interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
      });
      expect(code).toBe(2);
      expect(`${out.text()}${err.text()}`).not.toContain(secret);
      expect(terminal.hiddenReads).toBe(0);
    }
  });

  it("requires an explicit owner scope before opening a fortress or bundle", async () => {
    for (const run of [
      () => runMemoryArchiveExportCommand({
        argv: [
          "--archive-id", "a".repeat(32),
          "--out", "/not-created",
          "--fortress", "/not-opened",
        ],
        out: new Sink(),
        err: new Sink(),
        env: {},
        interaction: new TestTerminal(),
      }),
      () => runMemoryArchiveImportCommand({
        argv: ["--in", "/not-read", "--fortress", "/not-opened"],
        out: new Sink(),
        err: new Sink(),
        env: {},
        interaction: new TestTerminal(),
      }),
    ]) {
      await expect(run()).resolves.toBe(2);
    }
  });

  it("uses the production local-dialog path, confirms custody, and clears every dialog script buffer", async () => {
    const source = await fortress("exit-v2-cli-dialog-source", "owner-a", true);
    const bundle = join(await tempDir("exit-v2-cli-dialog-bundle-parent"), "bundle");
    const compiledDialogs = await tempDir("exit-v2-cli-dialog-compile");
    const scriptRefs: Uint8Array[] = [];
    const compileResults: Array<{ status: number | null; stderr: string }> = [];
    let disclosedKey = "";
    const dialogRunner: MemoryArchiveDialogRunner = (script) => {
      scriptRefs.push(script);
      const text = Buffer.from(script).toString("utf8");
      if (process.platform === "darwin") {
        const compiled = spawnSync(
          "/usr/bin/osacompile",
          [
            "-l", "JavaScript",
            "-o", join(compiledDialogs, `dialog-${String(scriptRefs.length)}.scpt`),
            "-",
          ],
          { input: script, encoding: null },
        );
        compileResults.push({
          status: compiled.status,
          stderr: Buffer.from(compiled.stderr ?? []).toString("utf8"),
        });
        compiled.stdout?.fill(0);
        compiled.stderr?.fill(0);
      }
      if (text.includes("Tier-1 approval required")) {
        return { status: 0, signal: null, stdout: Buffer.from("approve\n") };
      }
      const match = text.match(/([A-Za-z0-9_-]{43})\\n\\nStore/);
      if (!match) return { status: 1, signal: null, stdout: new Uint8Array() };
      disclosedKey = match[1]!;
      return { status: 0, signal: null, stdout: Buffer.from(`${disclosedKey}\n`) };
    };
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveExportCommand({
      argv: [
        "--archive-id", source.archiveId!, "--out", bundle,
        "--owner-ref", "owner-a", "--fortress", source.path, "--json",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      dialogRunner,
    });
    expect(code, err.text()).toBe(0);
    expect(disclosedKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(`${out.text()}${err.text()}`).not.toContain(disclosedKey);
    expect(scriptRefs).toHaveLength(2);
    expect(scriptRefs.every((value) => value.every((byte) => byte === 0))).toBe(true);
    // osacompile exists only on darwin, so the syntax check above only runs
    // there; on other platforms the production dialog scripts are never
    // spawned (resolveInteraction fails closed first) and no result is pushed.
    const expectedCompileResults = process.platform === "darwin"
      ? [
          { status: 0, stderr: "" },
          { status: 0, stderr: "" },
        ]
      : [];
    expect(compileResults, compileResults.map((result) => result.stderr).join("\n")).toEqual(
      expectedCompileResults,
    );
  }, 60_000);

  // Runs only where the reviewed macOS dialog boundary is absent: it witnesses
  // the real resolveInteraction refusal with no injected seam, so Linux CI
  // proves the platform fail-closed branch rather than trusting it.
  it.skipIf(process.platform === "darwin")(
    "fails closed on platforms without the local dialog boundary when no seam is injected",
    async () => {
      const parent = await tempDir("exit-v2-cli-nondarwin-parent");
      const { out, err } = sinkPair();
      const code = await runMemoryArchiveExportCommand({
        argv: [
          "--archive-id", "0123456789abcdef0123456789abcdef",
          "--out", join(parent, "bundle"),
          "--owner-ref", "owner-a",
          "--fortress", join(parent, "missing-fortress"),
        ],
        out,
        err,
        env: {},
      });
      expect(code).toBe(1);
      expect(err.text()).toContain(
        "a local OS approval dialog is unavailable on this platform",
      );
      await expect(stat(join(parent, "bundle"))).rejects.toMatchObject({ code: "ENOENT" });
    },
    60_000,
  );

  it("fails closed and removes the bundle when the local custody dialog is interrupted", async () => {
    const source = await fortress("exit-v2-cli-dialog-signal-source", "owner-a", true);
    const bundle = join(await tempDir("exit-v2-cli-dialog-signal-parent"), "bundle");
    let calls = 0;
    const interruptedOutput = Buffer.from("must-be-cleared");
    const dialogRunner: MemoryArchiveDialogRunner = () => {
      calls++;
      return calls === 1
        ? { status: 0, signal: null, stdout: Buffer.from("approve\n") }
        : { status: null, signal: "SIGTERM", stdout: interruptedOutput };
    };
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveExportCommand({
      argv: [
        "--archive-id", source.archiveId!, "--out", bundle,
        "--owner-ref", "owner-a", "--fortress", source.path,
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      dialogRunner,
    });
    expect(code).toBe(1);
    await expect(stat(bundle)).rejects.toMatchObject({ code: "ENOENT" });
    expect(`${out.text()}${err.text()}`).not.toContain("must-be-cleared");
    expect(interruptedOutput.every((byte) => byte === 0)).toBe(true);
  }, 60_000);

  it("wires the memory archive and bad-signer CLI routes and keeps the V1 manifest surface unchanged", async () => {
    const [exportHelp, importHelp, markHelp, clearHelp, pruneHelp] = await Promise.all([
      runCli("memory_archive_export", "--help"),
      runCli("memory_archive_import", "--help"),
      runCli("memory_provenance_mark_bad_signer", "--help"),
      runCli("memory_provenance_clear_bad_signer", "--help"),
      runCli("memory_provenance_prune_signers", "--help"),
    ]);
    expect(exportHelp).toMatchObject({ code: 0, stderr: "" });
    expect(exportHelp.stdout).toContain("Usage: sanctuary memory_archive_export");
    expect(importHelp).toMatchObject({ code: 0, stderr: "" });
    expect(importHelp.stdout).toContain("Usage: sanctuary memory_archive_import");
    expect(markHelp).toMatchObject({ code: 0, stderr: "" });
    expect(markHelp.stdout).toContain("Usage: sanctuary memory_provenance_mark_bad_signer");
    expect(clearHelp).toMatchObject({ code: 0, stderr: "" });
    expect(clearHelp.stdout).toContain("Usage: sanctuary memory_provenance_clear_bad_signer");
    expect(pruneHelp).toMatchObject({ code: 0, stderr: "" });
    expect(pruneHelp.stdout).toContain("Usage: sanctuary memory_provenance_prune_signers");
    expect(exportHelp.stdout).not.toContain("--passphrase");
    expect(importHelp.stdout).not.toContain("--passphrase");

    const out = new Sink();
    expect(await runExitCommand({ argv: ["manifest-shape"], out, err: new Sink(), env: {} })).toBe(0);
    // Independent gate item 5 (2026-08-23): manifest-shape reflects what a
    // CURRENT export actually produces - the SEPARATE known-signers manifest
    // version and its own exact 8-kind contract - never the frozen V1
    // literal or its 7-kind contract (which stay byte-stable and untouched;
    // see contracts/v1.1/constants.ts), matching this test's own title.
    expect(JSON.parse(out.text())).toMatchObject({
      manifest_version: "SANCTUARY_EXIT_BUNDLE_V1_KNOWN_SIGNERS",
      artifacts: [
        "public_identity",
        "encrypted_state",
        "policy_set",
        "audit_receipts",
        "reputation_bundle",
        "commitments",
        "placeholder_vault_metadata",
        "known_signers",
      ],
    });
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("contains no background, retry, or network machinery", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../../src/cli/memory-archive.ts", import.meta.url)),
      "utf8",
    );
    for (const forbidden of [
      "node:http", "node:https", "node:net", "node:dgram", "fetch(",
      "setInterval(", "setTimeout(", ".watch(", "watchFile(", "retry",
      "schedule", "daemon", "WebSocket", "node:tty", "/dev/tty", "setRawMode(",
    ]) {
      expect(source, forbidden).not.toContain(forbidden);
    }
    expect(source).not.toContain("stat(manifestPath)");
    expect(source).not.toContain("stat(artifactPath)");
    expect(source).not.toContain("readFile(manifestPath)");
    expect(source).not.toContain("readFile(artifactPath)");
    expect(source).toContain("readFileCustody(path, { maxBytes })");
    const bundleFailureMapper = source.slice(
      source.indexOf("function describeBundleReadFailure("),
      source.indexOf("function resolveInteraction("),
    );
    expect(bundleFailureMapper).toContain("custody check failed");
    expect(bundleFailureMapper).not.toContain("error.message");
  });
});

describe("Rung 1 memory-archive stored-custody wiring (F6)", () => {
  async function exportWithEnv(
    source: Fortress,
    env: NodeJS.ProcessEnv,
    ownerRef = "owner-a",
  ) {
    const bundle = join(await tempDir("f6-archive-bundle-parent"), "bundle");
    const terminal = new TestTerminal();
    const approval = new RecordingApprovalChannel();
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveExportCommand({
      argv: [
        "--archive-id", source.archiveId!,
        "--out", bundle,
        "--owner-ref", ownerRef,
        "--fortress", source.path,
        "--json",
      ],
      out,
      err,
      stdin: Readable.from(["ordinary-stdin-must-not-be-read\n"]),
      env,
      interaction: interactionWithApproval(terminal, approval),
    });
    return { bundle, terminal, approval, out, err, code };
  }

  it("opens the EXACT fortress via stored custody with NO argv/env secret; the transfer key is fresh and distinct from fortress custody", async () => {
    const source = await fortress("f6-archive-stored", "owner-a", true);
    // Store the fortress passphrase in this host's (in-memory) keyring for the
    // EXACT fortress path — exactly what `sanctuary protect` does.
    await persistUserProvidedPassphrase(PASSPHRASE, { storagePath: source.path });

    // Run with env:{} — no SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY.
    const r = await exportWithEnv(source, {});
    expect(r.code).toBe(0);
    expect(r.err.text()).not.toContain("could not unlock the fortress");

    // The transfer/recovery artifact key is fresh and NOT the fortress custody.
    const transferKey = secretText(r.terminal);
    expect(transferKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(transferKey).not.toBe(PASSPHRASE);
    // No secret in stdout / JSON / stderr.
    expect(r.out.text()).not.toContain(PASSPHRASE);
    expect(r.out.text()).not.toContain(transferKey);
    expect(r.err.text()).not.toContain(PASSPHRASE);
    expect(JSON.parse(r.out.text())).not.toHaveProperty("transfer_key");
  });

  it("no generation: a fortress with no stored credential and no argv/env secret refuses, and never mints one", async () => {
    const source = await fortress("f6-archive-nocred", "owner-a", true);
    const r = await exportWithEnv(source, {});
    expect(r.code).not.toBe(0);
    expect(r.err.text()).toContain("could not unlock the fortress");
    // The refusal never GENERATED a credential for this fortress.
    const after = await readStoredPassphrase({ storagePath: source.path, readOnly: true });
    expect(after).toBeNull();
  });

  it("mismatch: a stored credential that does not open the fortress is refused", async () => {
    const source = await fortress("f6-archive-mismatch", "owner-a", true);
    await persistUserProvidedPassphrase("not-the-fortress-passphrase", {
      storagePath: source.path,
    });
    const r = await exportWithEnv(source, {});
    expect(r.code).not.toBe(0);
    expect(r.err.text()).toContain("could not unlock the fortress");
  });

  it("cross-fortress isolation: a --fortress target never reads a DIFFERENT fortress's stored credential", async () => {
    const source = await fortress("f6-archive-isolation", "owner-a", true);
    // Store a credential for an UNRELATED sibling fortress path only.
    const otherPath = join(await tempDir("f6-archive-other"), ".sanctuary");
    await persistUserProvidedPassphrase(PASSPHRASE, { storagePath: otherPath });
    // The target fortress has NO credential of its own → must refuse, never
    // borrow the sibling's entry (the keyring lookup is namespaced to the exact
    // fortress path).
    const r = await exportWithEnv(source, {});
    expect(r.code).not.toBe(0);
    expect(r.err.text()).toContain("could not unlock the fortress");
  });

  it("import opens the destination fortress via stored custody with no argv/env secret", async () => {
    // Export from a source (env credential), then import into a destination
    // opened via its STORED credential only (env:{}).
    const src = await fortress("f6-import-src", "owner-a", true);
    const exported = await exportBundle(src);
    expect(exported.code).toBe(0);

    const dest = await fortress("f6-import-dest", "owner-a", false);
    await persistUserProvidedPassphrase(PASSPHRASE, { storagePath: dest.path });
    const terminal = new TestTerminal();
    // The operator re-enters the transfer key disclosed at export time.
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const { out, err } = sinkPair();
    const code = await runMemoryArchiveImportCommand({
      argv: [
        "--in", exported.bundle,
        "--owner-ref", "owner-a",
        "--fortress", dest.path,
        "--json",
      ],
      out,
      err,
      stdin: Readable.from(["ordinary-stdin-must-not-be-read\n"]),
      env: {}, // no argv/env secret — opens via the stored credential
      interaction: interactionWithApproval(terminal, new RecordingApprovalChannel()),
    });
    expect(err.text()).not.toContain("could not unlock the fortress");
    expect(code, err.text()).toBe(0);
    // No fortress secret leaked to stdout/JSON.
    expect(out.text()).not.toContain(PASSPHRASE);
    expect(out.text()).not.toContain(secretText(exported.terminal));
  });
});

function custodyDeferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

async function withArchiveCustody(
  withIdentity: boolean,
  check: (fixture: {
    path: string;
    outputPath: string;
    exclusive: () => Promise<string>;
    lease: () => MasterWriteBarrierLease;
    release: ReturnType<typeof vi.fn<() => Promise<void>>>;
    failRelease: (error: unknown) => void;
  }) => Promise<void>,
): Promise<void> {
  const home = await createTempHome("archive-custody");
  const path = home.defaultFortressPath;
  const storage = new FilesystemStorage(join(path, "state"));
  const leases: MasterWriteBarrierLease[] = [];
  let releaseOutcome: { ok: true } | { ok: false; error: unknown } = { ok: true };
  try {
    const seed = await custody.establishMaster({
      storage, passphrase: PASSPHRASE, storagePathHint: path,
      firstRun: { installMode: "stdio-server", mintRecoveryKey: true },
    });
    try {
      if (withIdentity) {
        const identities = new IdentityManager(storage, seed.masterKey);
        const identityKey = derivePurposeKey(seed.masterKey, "identity-encryption");
        try {
          const { storedIdentity } = createIdentity("archive-custody", identityKey, "passphrase");
          const writes: Promise<void>[] = [];
          const write = storage.write.bind(storage);
          const spy = vi.spyOn(storage, "write").mockImplementation((...args) => {
            const pending = write(...args);
            writes.push(pending);
            return pending;
          });
          try {
            await identities.save(storedIdentity);
          } finally {
            await Promise.all(writes);
            spy.mockRestore();
          }
        } finally { identityKey.fill(0); }
      }
    } finally {
      seed.masterKey.fill(0);
      await seed.masterWriteBarrier?.release();
    }
    const outputPath = join(home.home, "existing-output");
    await mkdir(outputPath);
    const unlock = localUnlock.unlockLocalFortress;
    const release = vi.fn(async () => {
      await leases.at(-1)!.release();
      if (!releaseOutcome.ok) throw releaseOutcome.error;
    });
    vi.spyOn(localUnlock, "unlockLocalFortress").mockImplementation(async options => {
      const result = await unlock(options);
      if (!result.ok || !result.barrier) return result;
      leases.push(result.barrier);
      return { ...result, barrier: { ...result.barrier, release } };
    });
    await check({
      path, outputPath, release,
      lease: () => leases.at(-1)!,
      failRelease: error => { releaseOutcome = { ok: false, error }; },
      exclusive: () => withExclusiveMasterRotationBarrier(
        new FilesystemStorage(join(path, "state")),
        custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
        async () => "entered", { timeoutMs: 0 },
      ),
    });
  } finally {
    for (const lease of leases) await lease.release();
    vi.restoreAllMocks();
    await home.cleanup();
  }
}

// Archive identifiers contain 32 lowercase hexadecimal digits.
function custodyExportArgs(path: string, outputPath: string, terminal: TestTerminal) {
  return {
    argv: ["--archive-id", "a".repeat(32), "--out", outputPath, "--owner-ref", "owner-a", "--fortress", path],
    ...sinkPair(), env: { SANCTUARY_PASSPHRASE: PASSPHRASE }, interaction: terminal,
  };
}

describe.skipIf(!kernelBackedCrossProcessLockPlatformSupported(process.platform))("archive custody cleanup", () => {
  it.each(["zero identities", "no default identity"])("bootstrap releases custody with %s", async mode => {
    await withArchiveCustody(false, async fixture => {
      if (mode === "no default identity") {
        vi.spyOn(IdentityManager.prototype, "load").mockResolvedValue({ total: 1, loaded: 1, failed: 0 });
        vi.spyOn(IdentityManager.prototype, "getDefault").mockReturnValue(undefined);
      }
      const terminal = new TestTerminal();
      const close = vi.spyOn(terminal, "close");
      const args = custodyExportArgs(fixture.path, fixture.outputPath, terminal);
      expect(await runMemoryArchiveExportCommand(args)).toBe(1);
      expect(args.err.text()).toBe("Error: fortress identity is unavailable.\n");
      expect(fixture.lease().signal.aborted).toBe(true);
      await expect(fixture.exclusive()).resolves.toBe("entered");
      expect(fixture.release).toHaveBeenCalledOnce();
      expect(close).toHaveBeenCalledOnce();
    });
  });

  it.each(["observer", "undefined observer", "baseline"])("bootstrap releases custody after failed %s construction", async mode => {
    await withArchiveCustody(true, async fixture => {
      const error = mode.startsWith("undefined") ? undefined : new Error("fixture construction");
      if (mode === "baseline") vi.spyOn(baselineModule, "BaselineTracker").mockImplementation(function () { throw error; });
      const args = custodyExportArgs(fixture.path, fixture.outputPath, new TestTerminal());
      expect(await runMemoryArchiveExportCommand({
        ...args,
        ...(mode === "baseline" ? {} : { observeMasterKey: () => { throw error; } }),
      })).toBe(1);
      expect(fixture.lease().signal.aborted).toBe(true);
      await expect(fixture.exclusive()).resolves.toBe("entered");
      expect(fixture.release).toHaveBeenCalledOnce();
      expect(args.err.text()).toBe("Error: could not open or unlock the fortress.\n");
    });
  });

  it.each(["identity", "observer", "undefined observer"])("bootstrap reports release failure after %s refusal", async mode => {
    await withArchiveCustody(false, async fixture => {
      const operationError = mode.startsWith("undefined") ? undefined : new Error("fixture observer");
      const releaseError = new Error("fixture release");
      fixture.failRelease(releaseError);
      const terminal = new TestTerminal();
      const close = vi.spyOn(terminal, "close");
      const result = await runMemoryArchiveExportCommand({
        ...custodyExportArgs(fixture.path, fixture.outputPath, terminal),
        ...(mode === "identity" ? {} : { observeMasterKey: () => { throw operationError; } }),
      }).then(code => ({ code }), error => ({ error }));
      expect(fixture.lease().signal.aborted).toBe(true);
      await expect(fixture.exclusive()).resolves.toBe("entered");
      expect(result).toHaveProperty("error");
      if ("error" in result) {
        if (mode === "identity") expect(result.error).toBe(releaseError);
        else {
          expect(result.error).toBeInstanceOf(AggregateError);
          expect(result.error.errors).toEqual([operationError, releaseError]);
        }
      }
      expect(close).toHaveBeenCalledOnce();
    });
  });

  it.each(["normal", "flush", "release", "flush and release", "operation and release", "release and close"])(
    "command finalization preserves %s outcomes", async mode => {
      await withArchiveCustody(true, async fixture => {
        const operationError = new Error("fixture operation");
        const flushError = new Error("fixture flush");
        const releaseError = new Error("fixture release");
        const closeError = new Error("fixture close");
        const terminal = new TestTerminal();
        const close = vi.spyOn(terminal, "close").mockImplementation(() => {
          if (mode.includes("close")) throw closeError;
        });
        if (mode.includes("release")) fixture.failRelease(releaseError);
        const args = custodyExportArgs(fixture.path, fixture.outputPath, terminal);
        if (mode.includes("operation")) vi.spyOn(args.err, "write").mockImplementation(() => { throw operationError; });
        const flush = AuditLog.prototype.flush;
        const flushSpy = vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
          expect(fixture.lease().signal.aborted).toBe(false);
          await flush.call(this);
          if (mode.includes("flush")) throw flushError;
        });
        const result = await runMemoryArchiveExportCommand(args).then(code => ({ code }), error => ({ error }));
        expect(fixture.lease().signal.aborted).toBe(true);
        await expect(fixture.exclusive()).resolves.toBe("entered");
        expect(fixture.release).toHaveBeenCalledOnce();
        expect(flushSpy).toHaveBeenCalledOnce();
        expect(close).toHaveBeenCalledOnce();
        const errors = [
          ...(mode.includes("operation") ? [operationError] : []),
          ...(mode.includes("flush") ? [flushError] : []),
          ...(mode.includes("release") ? [releaseError] : []),
          ...(mode.includes("close") ? [closeError] : []),
        ];
        if (errors.length === 0) expect(result).toEqual({ code: 1 });
        else {
          expect(result).toHaveProperty("error");
          if ("error" in result) {
            if (errors.length === 1) expect(result.error).toBe(errors[0]);
            else {
              expect(result.error).toBeInstanceOf(AggregateError);
              expect(result.error.errors).toEqual(errors);
            }
          }
        }
      });
    },
  );

  it("command retains custody until pending final persistence completes", async () => {
    await withArchiveCustody(true, async fixture => {
      const entered = custodyDeferred();
      const finish = custodyDeferred();
      const flush = AuditLog.prototype.flush;
      vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
        entered.resolve();
        await finish.promise;
        await flush.call(this);
      });
      const run = runMemoryArchiveExportCommand(custodyExportArgs(fixture.path, fixture.outputPath, new TestTerminal()));
      try {
        await entered.promise;
        expect(fixture.lease().signal.aborted).toBe(false);
        expect(fixture.release).not.toHaveBeenCalled();
        await expect(fixture.exclusive()).rejects.toMatchObject({ kind: "contention" });
        finish.resolve();
        expect(await run).toBe(1);
        expect(fixture.lease().signal.aborted).toBe(true);
        await expect(fixture.exclusive()).resolves.toBe("entered");
      } finally {
        finish.resolve();
        await run.catch(() => undefined);
      }
    });
  });
});


function rejectArchiveRelease(error: Error) {
  const unlock = localUnlock.unlockLocalFortress;
  const release = vi.fn<() => Promise<void>>();
  let captured: MasterWriteBarrierLease | undefined;
  vi.spyOn(localUnlock, "unlockLocalFortress").mockImplementation(async options => {
    const result = await unlock(options);
    if (!result.ok || !result.barrier) return result;
    captured = result.barrier;
    release.mockImplementation(async () => {
      await result.barrier!.release();
      throw error;
    });
    return { ...result, barrier: { ...result.barrier, release } };
  });
  return {
    release,
    async expectReleased(path: string) {
      expect(release).toHaveBeenCalledOnce();
      expect(captured?.signal.aborted).toBe(true);
      await expect(withExclusiveMasterRotationBarrier(
        new FilesystemStorage(join(path, "state")),
        custody.CUSTODY_WRITE_LOCK_NAMESPACE, custody.MASTER_ROTATION_BARRIER_NAME,
        async () => "entered", { timeoutMs: 0 },
      )).resolves.toBe("entered");
    },
  };
}

describe.skipIf(!kernelBackedCrossProcessLockPlatformSupported(process.platform))("archive finalizer release witnesses", () => {
  it("reports the committed export and rejects when final release fails", async () => {
    const source = await fortress("release-export", "owner-a", true);
    const releaseError = new Error("fixture final release");
    const release = rejectArchiveRelease(releaseError);
    const bundle = join(await tempDir("release-export-bundle"), "bundle");
    const terminal = new TestTerminal();
    const close = vi.spyOn(terminal, "close");
    const args = custodyExportArgs(source.path, bundle, terminal);
    args.argv[args.argv.indexOf("--archive-id") + 1] = source.archiveId!;
    await expect(runMemoryArchiveExportCommand(args)).rejects.toBe(releaseError);
    expect(args.out.text()).toBe(`memory_archive_export: wrote ${bundle}\n`);
    expect(args.err.text()).toBe("");
    expect(JSON.parse(await readFile(join(bundle, "manifest.json"), "utf8"))).toHaveProperty("body");
    expect(await readFile(join(bundle, MEMORY_ARCHIVE_ARTIFACT_PATH))).not.toHaveLength(0);
    expect(terminal.secretWrites).toHaveLength(1);
    expect(close).toHaveBeenCalledOnce();
    await release.expectReleased(source.path);
  });

  it.each(["before commit", "after commit"])("keeps the import message and both failures %s", async phase => {
    const source = await fortress("release-import-source", "owner-a", true);
    const exported = await exportBundle(source);
    expect(exported.code, exported.err.text()).toBe(0);
    const destination = await fortress("release-import-destination", "owner-a", false);
    const releaseError = new Error("fixture final release");
    const operationError = new Error("fixture import operation");
    const release = rejectArchiveRelease(releaseError);
    const terminal = new TestTerminal();
    terminal.hiddenValue = Buffer.from(secretText(exported.terminal), "ascii");
    const close = vi.spyOn(terminal, "close");
    const { out, err } = sinkPair();
    if (phase === "before commit") vi.spyOn(terminal, "readHidden").mockResolvedValueOnce(Uint8Array.from(terminal.hiddenValue)).mockRejectedValueOnce(operationError);
    else vi.spyOn(out, "write").mockImplementation(() => { throw operationError; });
    const result = runMemoryArchiveImportCommand({
      argv: ["--in", exported.bundle, "--owner-ref", "owner-a", "--fortress", destination.path],
      out, err, env: { SANCTUARY_PASSPHRASE: PASSPHRASE }, interaction: terminal,
    });
    await expect(result).rejects.toMatchObject({ errors: [operationError, releaseError] });
    expect(err.text()).toBe(phase === "after commit"
      ? "memory_archive_import failed after the archive was imported; a post-import step (audit logging or receipt output) failed. Re-running memory_archive_import with the same bundle is safe.\n"
      : "memory_archive_import failed: archive authentication or validation failed\n");
    const adapter = await productionAdapter(destination.storage, destination.masterKey, fortressId(destination.path), "owner-a");
    if (phase === "after commit") expect(await adapter.countPassages()).toBeGreaterThan(0);
    else expect(await adapter.countPassages()).toBe(0);
    expect(close).toHaveBeenCalledOnce();
    await release.expectReleased(destination.path);
  });

  it.each([
    ["prune", runMemoryProvenancePruneSignersCommand],
    ["mark", runMemoryProvenanceMarkBadSignerCommand],
    ["clear", runMemoryProvenanceClearBadSignerCommand],
  ] as const)("finalizes the %s command without losing release failure", async (action, run) => {
    const destination = await fortress(`release-${action}`, "owner-a", false);
    const releaseError = new Error("fixture final release");
    const release = rejectArchiveRelease(releaseError);
    const terminal = new TestTerminal();
    const close = vi.spyOn(terminal, "close");
    const { out, err } = sinkPair();
    // A SHA-256 fingerprint contains 64 hexadecimal digits.
    const signerArgs = ["--signer-did", "did:key:fixture", "--public-key-sha256", "a".repeat(64)];
    const result = run({
      argv: ["--owner-ref", "owner-a", "--fortress", destination.path,
        ...(action === "prune" ? [] : signerArgs), ...(action === "mark" ? ["--reason", "fixture"] : [])],
      out, err, env: { SANCTUARY_PASSPHRASE: PASSPHRASE }, interaction: terminal,
    });
    if (action === "prune") {
      await expect(result).rejects.toBe(releaseError);
      expect(out.text()).toContain("deleted");
      expect(err.text()).toBe("");
    } else {
      await expect(result).rejects.toMatchObject({ errors: [
        expect.objectContaining({ message: action === "mark" ? "foreign signer mapping is unknown" : "foreign signer is not marked" }),
        releaseError,
      ] });
      expect(err.text()).toBe(`memory_provenance_${action}_bad_signer failed\n`);
    }
    expect(close).toHaveBeenCalledOnce();
    await release.expectReleased(destination.path);
  });

  it("keeps a caught export error with release failure when the error writer returns normally", async () => {
    await withArchiveCustody(true, async fixture => {
      const operationError = new Error("fixture export operation");
      const releaseError = new Error("fixture final release");
      fixture.failRelease(releaseError);
      const terminal = new TestTerminal();
      const close = vi.spyOn(terminal, "close");
      const args = custodyExportArgs(fixture.path, join(fixture.path, "new-output"), terminal);
      vi.spyOn(ApprovalGate.prototype, "evaluate").mockRejectedValue(operationError);
      await expect(runMemoryArchiveExportCommand(args)).rejects.toMatchObject({ errors: [operationError, releaseError] });
      expect(args.err.text()).toBe("memory_archive_export failed\n");
      expect(fixture.release).toHaveBeenCalledOnce();
      expect(fixture.lease().signal.aborted).toBe(true);
      await expect(fixture.exclusive()).resolves.toBe("entered");
      expect(close).toHaveBeenCalledOnce();
    });
  });
});

describe.skipIf(!kernelBackedCrossProcessLockPlatformSupported(process.platform))("archive aggregate grouping", () => {
  it.each(["bootstrap", "operation"])("preserves a lease aggregate and close error during %s failure", async phase => {
    await withArchiveCustody(true, async fixture => {
      const operationError = new Error("fixture operation");
      const leaseCauses = [new Error("fixture listener"), new Error("fixture reaper")];
      const releaseError = new AggregateError(leaseCauses, "fixture lease grouping");
      const closeError = new Error("fixture interaction close");
      fixture.failRelease(releaseError);
      const terminal = new TestTerminal();
      vi.spyOn(terminal, "close").mockImplementation(() => { throw closeError; });
      const args = custodyExportArgs(fixture.path, join(fixture.path, "new-output"), terminal);
      if (phase === "operation") vi.spyOn(ApprovalGate.prototype, "evaluate").mockRejectedValue(operationError);
      const result = await runMemoryArchiveExportCommand({
        ...args, ...(phase === "bootstrap" ? { observeMasterKey: () => { throw operationError; } } : {}),
      }).catch((error: unknown) => error);
      expect(result).toBeInstanceOf(AggregateError);
      // Each phase keeps its own aggregate, including the lease's original grouping message.
      const expected = phase === "bootstrap"
        ? [expect.objectContaining({ errors: [operationError, releaseError] }), closeError]
        : [operationError, releaseError, closeError];
      expect((result as AggregateError).errors).toEqual(expected);
      const [firstFailure, secondFailure] = (result as AggregateError).errors;
      const [operationFailure, leaseFailure] = phase === "bootstrap"
        ? (firstFailure as AggregateError).errors : [firstFailure, secondFailure];
      expect(operationFailure).toBe(operationError);
      expect(leaseFailure).toBe(releaseError);
      expect((leaseFailure as AggregateError).errors).toEqual(leaseCauses);
      expect(releaseError.message).toBe("fixture lease grouping");
      expect(fixture.release).toHaveBeenCalledOnce();
      expect(fixture.lease().signal.aborted).toBe(true);
      await expect(fixture.exclusive()).resolves.toBe("entered");
    });
  });
});
