/**
 * Exit V2 SDW memory archive CLI composition tests.
 *
 * Every fortress and bundle is disposable. Transfer material is observable
 * only through the injected local-human interaction seam.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { IdentityManager } from "../../src/cognitive/tools.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { stringToBytes } from "../../src/core/encoding.js";
import {
  runMemoryArchiveExportCommand,
  runMemoryArchiveImportCommand,
  type MemoryArchiveDialogRunner,
  type PrivateMemoryArchiveInteraction,
} from "../../src/cli/memory-archive.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../../src/principal-policy/types.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { ingestClaudeCodeMemoryDirectory } from "../../src/sdw/adapters/claude-code-file-adapter.js";
import { transcodeMemoryDirectory } from "../../src/sdw/memory-transcode.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { runExitCommand } from "../../src/exit/cli.js";
import {
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  runCli,
} from "./helpers/run-cli.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/basic/", import.meta.url),
);
const PASSPHRASE = "exit-v2-memory-cli-disposable-passphrase";
// One second bounds the fixture-only wait for IdentityManager's documented
// fire-and-forget primary-identity pointer write (100 attempts * 10 ms).
const PRIMARY_IDENTITY_SETTLE_ATTEMPTS = 100;
const PRIMARY_IDENTITY_SETTLE_MS = 10;
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

interface Fortress {
  readonly path: string;
  readonly storage: FilesystemStorage;
  readonly masterKey: Uint8Array;
  readonly archiveId?: string;
}

afterEach(async () => {
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
  await identityManager.save(storedIdentity);
  await waitForPrimaryIdentityPointer(storage);
  if (!withArchive) return { path, storage, masterKey };

  const adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey,
    fortressId: fortressId(path),
    ownerRef,
  });
  await ingestClaudeCodeMemoryDirectory(adapter, FIXTURE_ROOT);
  const projectionParent = await tempDir(`${prefix}-projection`);
  const transcoded = await transcodeMemoryDirectory(
    adapter,
    "claude-code",
    "codex",
    join(projectionParent, "projection"),
  );
  return { path, storage, masterKey, archiveId: transcoded.archive_id };
}

async function waitForPrimaryIdentityPointer(storage: FilesystemStorage): Promise<void> {
  for (let attempt = 0; attempt < PRIMARY_IDENTITY_SETTLE_ATTEMPTS; attempt++) {
    if (await storage.read("_meta", "primary_identity_id") !== null) return;
    await delay(PRIMARY_IDENTITY_SETTLE_MS);
  }
  throw new Error("disposable fortress primary identity pointer did not settle");
}

function fortressId(path: string): string {
  return `fortress-${createHash("sha256").update(path).digest("hex").slice(0, 16)}`;
}

function sinkPair(): { out: Sink; err: Sink } {
  return { out: new Sink(), err: new Sink() };
}

async function exportBundle(source: Fortress, ownerRef = "owner-a", json = false) {
  const bundle = join(await tempDir("exit-v2-cli-bundle-parent"), "bundle");
  const terminal = new TestTerminal();
  const approval = new RecordingApprovalChannel();
  const { out, err } = sinkPair();
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
    interaction: terminal,
    approvalChannel: approval,
  });
  return { bundle, terminal, approval, out, err, code };
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
        interaction: new TestTerminal(),
        approvalChannel: new RecordingApprovalChannel(response),
      });
      expect(code).toBe(1);
      await expect(stat(bundle)).rejects.toMatchObject({ code: "ENOENT" });
    }
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
      interaction: terminal,
      approvalChannel: approval,
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
    const otherOwner = new SdwMemoryBackendAdapter({
      storage: destination.storage,
      masterKey: destination.masterKey,
      fortressId: fortressId(destination.path),
      ownerRef: "owner-b",
    });
    const destinationOwner = new SdwMemoryBackendAdapter({
      storage: destination.storage,
      masterKey: destination.masterKey,
      fortressId: fortressId(destination.path),
      ownerRef: "owner-a",
    });
    expect(await destinationOwner.countPassages()).toBeGreaterThan(0);
    expect(await otherOwner.countPassages()).toBe(0);
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
      approvalChannel: new RecordingApprovalChannel(),
    });
    expect(code).toBe(1);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("local OS approval dialog");
    const adapter = new SdwMemoryBackendAdapter({
      storage: destination.storage,
      masterKey: destination.masterKey,
      fortressId: fortressId(destination.path),
      ownerRef: "owner-a",
    });
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
        interaction: terminal,
        approvalChannel: new RecordingApprovalChannel(),
      });
      expect(code).toBe(1);
      expect(`${out.text()}${err.text()}`).not.toContain(
        Buffer.from(terminal.hiddenValue).toString("ascii"),
      );
      const adapter = new SdwMemoryBackendAdapter({
        storage: destination.storage,
        masterKey: destination.masterKey,
        fortressId: fortressId(destination.path),
        ownerRef,
      });
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
        interaction: terminal,
        approvalChannel: new RecordingApprovalChannel(response),
      });
      expect(code).toBe(1);
      expect(terminal.hiddenReads).toBe(1);
      const adapter = new SdwMemoryBackendAdapter({
        storage: deniedDestination.storage,
        masterKey: deniedDestination.masterKey,
        fortressId: fortressId(deniedDestination.path),
        ownerRef: "owner-a",
      });
      expect(await adapter.countPassages()).toBe(0);
    }
  }, 60_000);

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
        interaction: terminal,
        approvalChannel: new RecordingApprovalChannel(),
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

  it("wires both shipping CLI routes and keeps the V1 manifest surface unchanged", async () => {
    const [exportHelp, importHelp] = await Promise.all([
      runCli("memory_archive_export", "--help"),
      runCli("memory_archive_import", "--help"),
    ]);
    expect(exportHelp).toMatchObject({ code: 0, stderr: "" });
    expect(exportHelp.stdout).toContain("Usage: sanctuary memory_archive_export");
    expect(importHelp).toMatchObject({ code: 0, stderr: "" });
    expect(importHelp.stdout).toContain("Usage: sanctuary memory_archive_import");
    expect(exportHelp.stdout).not.toContain("--passphrase");
    expect(importHelp.stdout).not.toContain("--passphrase");

    const out = new Sink();
    expect(await runExitCommand({ argv: ["manifest-shape"], out, err: new Sink(), env: {} })).toBe(0);
    expect(JSON.parse(out.text())).toMatchObject({
      manifest_version: "SANCTUARY_EXIT_BUNDLE_V1",
      artifacts: [
        "public_identity",
        "encrypted_state",
        "policy_set",
        "audit_receipts",
        "reputation_bundle",
        "commitments",
        "placeholder_vault_metadata",
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
    expect(source).toContain("open(path, \"r\")");
  });
});
