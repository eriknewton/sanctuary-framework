import { Buffer } from "node:buffer";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { closeSync, constants as fsConstants, openSync, readSync } from "node:fs";
import { chmod, lstat, mkdtemp, mkdir, readFile, readdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IdentityManager } from "../../src/cognitive/tools.js";
import { defaultConfig } from "../../src/config.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME, establishMaster } from "../../src/core/master-custody.js";
import {
  EXIT_CLEAN,
  EXIT_FATAL_BRIDGE,
  EXIT_STARTUP_REFUSED,
  HERMES_BRIDGE_ENV_ALLOWLIST,
  HERMES_MAX_CALL_RECORDS,
  HERMES_MAX_PUBLIC_CONNECTIONS,
  MAX_PENDING_WRITE_BYTES,
  MAX_PRIVATE_FRAME_BYTES,
  DRAIN_TAIL_MS,
  RELAY_CHILD_SIGTERM_GRACE_MS,
  type HermesBridgeProcessOptions,
  PrivateFrameDecoder,
  encodePrivateFrame,
  hermesBridgeMain,
  resolveHermesBridgeFortress,
  runHermesBridgeProcess as runProductionHermesBridgeProcess,
} from "../../src/hermes-memory-bridge/index.js";
import { HermesBridgeCore } from "../../src/hermes-memory-bridge/bridge-core.js";
import { HermesApprovalLedger } from "../../src/hermes-memory-bridge/approval-ledger.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { TRAP_STORE_KEY_PREFIX, TRAP_STORE_NAMESPACE } from "../../src/honeypot/trap-store.js";
import { SdwDocumentCorpusStore } from "../../src/sdw/document-corpus-store.js";
import { verifyMemoryProvenanceCompanion } from "../../src/sdw/memory-provenance-contract.js";
import { createPrimaryMemoryProvenancePublicKeyResolver } from "../../src/sdw/memory-provenance-signing.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { memoryProvenancePublicKeyFingerprint } from "../../src/sdw/memory-provenance-bad-signers.js";
import {
  MEMORY_BATCH_LOCK_NAMESPACE,
  hermesBridgePassageTextDigest,
  sdwMemoryCorpusBatchLockFile,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { __testListMasterBarrierReaderSockets } from "../../src/storage/cross-process-lock.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";

const PASS = "correct horse battery staple hermes";
const encoder = new TextEncoder();
const cliEntry = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
const keychainExecEntry = fileURLToPath(new URL("../../src/wrap/keychain-exec.ts", import.meta.url));
const keychainStoreEntry = fileURLToPath(new URL("../setup/keychain-memory-store.ts", import.meta.url));
const processShellSource = fileURLToPath(new URL("../../src/hermes-memory-bridge/process-shell.ts", import.meta.url));

const cleanups: Array<() => Promise<void>> = [];
let fortressCounter = 0;

class TrapListingStorage extends FilesystemStorage {
  constructor(root: string, private readonly trapMode: "present" | "error") {
    super(root);
  }

  override async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    if (namespace === TRAP_STORE_NAMESPACE && prefix === TRAP_STORE_KEY_PREFIX) {
      if (this.trapMode === "error") throw new Error("trap list failed");
      return [{ namespace, key: `${TRAP_STORE_KEY_PREFIX}truncated`, size_bytes: 1, modified_at: new Date(0).toISOString() }];
    }
    return super.list(namespace, prefix);
  }
}

class SlowTrapListStorage extends FilesystemStorage {
  private releaseList: (() => void) | undefined;
  trapListParked = false;
  readonly parked = new Promise<void>((resolve) => {
    this.releaseList = resolve;
  });

  constructor(root: string) {
    super(root);
  }

  override async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    if (namespace === TRAP_STORE_NAMESPACE && prefix === TRAP_STORE_KEY_PREFIX) {
      this.trapListParked = true;
      await this.parked;
    }
    return super.list(namespace, prefix);
  }

  release(): void {
    this.releaseList?.();
  }
}

class ParkingDocumentWriteStorage extends FilesystemStorage {
  private releaseWrite: (() => void) | undefined;
  parkedSettled = false;
  readonly parked = new Promise<void>((resolve) => {
    this.releaseWrite = resolve;
  });

  constructor(root: string) {
    super(root);
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith("doc.")) {
      this.parkedSettled = true;
      await this.parked;
    }
    return super.write(namespace, key, data);
  }

  release(): void {
    this.releaseWrite?.();
  }
}

class ParkingAuditStorage extends FilesystemStorage {
  private readonly pendingAuditWrites = new Set<Promise<void>>();
  private releaseAudit: (() => void) | undefined;
  auditWriteParked = false;
  // Set by a test once shell.exited resolved; every later write-family call counts as backend work
  // reaching a fortress the shell no longer owns.
  exitObserved = false;
  backendWritesAfterExit = 0;
  readonly parked = new Promise<void>((resolve) => {
    this.releaseAudit = resolve;
  });

  // Which writes park: every `_audit` entry write by default; a test of the graceful-shutdown
  // checkpoint parks only checkpoint records (keys ending in the 20-digit sequence), so the per-append
  // head anchor in the same namespace still passes.
  constructor(root: string, private readonly parks: (namespace: string, key: string) => boolean = (namespace) => namespace === "_audit") {
    super(root);
  }

  private trackAuditWrite(write: Promise<void>): Promise<void> {
    this.pendingAuditWrites.add(write);
    void write.then(
      () => { this.pendingAuditWrites.delete(write); },
      () => { this.pendingAuditWrites.delete(write); },
    );
    return write;
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (this.exitObserved) this.backendWritesAfterExit += 1;
    if (this.parks(namespace, key)) {
      this.auditWriteParked = true;
      return this.trackAuditWrite((async () => { await this.parked; await super.write(namespace, key, data); })());
    }
    return super.write(namespace, key, data);
  }

  override async writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (this.exitObserved) this.backendWritesAfterExit += 1;
    if (this.parks(namespace, key)) {
      this.auditWriteParked = true;
      return this.trackAuditWrite((async () => { await this.parked; await super.writeDurable(namespace, key, data); })());
    }
    return super.writeDurable(namespace, key, data);
  }

  release(): void {
    this.releaseAudit?.();
  }

  // Drains to quiescence, not one snapshot: a write released here can settle a queued caller that
  // starts another write before the first allSettled returns.
  async releaseAndDrain(): Promise<void> {
    this.release();
    do {
      await Promise.allSettled([...this.pendingAuditWrites]);
      await new Promise((resolve) => setImmediate(resolve));
    } while (this.pendingAuditWrites.size > 0);
  }
}

class ThrowingReadyDuplex extends Duplex {
  _read(): void {}
  _write(_chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    callback();
  }

  override write(_chunk: Uint8Array | string, _encoding?: BufferEncoding | ((error?: Error | null) => void), _callback?: (error?: Error | null) => void): boolean {
    throw new Error("ready write refused by test stream");
  }
}

class CallbackErrorDuplex extends Duplex {
  _read(): void {}
  _write(_chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    callback();
  }

  override write(_chunk: Uint8Array | string, encoding?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void): boolean {
    const done = typeof encoding === "function" ? encoding : callback;
    done?.(new Error("write callback refused by test stream"));
    return true;
  }
}

class NeverDrainingDuplex extends Duplex {
  acceptedWriteBytes = 0;
  queuedBytes = 0;
  writeCount = 0;

  _read(): void {}

  _write(chunk: Buffer, _encoding: BufferEncoding, _callback: (error?: Error | null) => void): void {
    this.queuedBytes += chunk.byteLength;
    this.writeCount += 1;
  }

  override write(chunk: Uint8Array | string, encoding?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void): boolean {
    this.acceptedWriteBytes += Buffer.byteLength(chunk as string | Uint8Array);
    if (typeof encoding === "function") return super.write(chunk, encoding);
    if (encoding === undefined) return callback === undefined ? super.write(chunk) : super.write(chunk, callback);
    return super.write(chunk, encoding, callback);
  }

  inject(chunk: Buffer): void {
    this.push(chunk);
  }
}

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

describe("Hermes memory process shell", () => {
  it("refuses an environment outside the relay allowlist before constructing the socket", async () => {
    const home = await tempHome("env-refusal");
    const env = allowlistedEnv(home, "a".repeat(64), "agent-one", "fortress-one");
    const called = { value: false };

    await expect(runHermesBridgeProcess({
      env: { ...env, NODE_OPTIONS: "--require ./preload.js" },
      relaySocketFactory: () => {
        called.value = true;
        throw new Error("must not construct socket");
      },
      storageFor: () => new MemoryStorage(),
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({
      state: "state_ENV_REPLACED",
      message: expect.stringContaining("NODE_OPTIONS"),
    });
    expect(called.value).toBe(false);
  });

  it("keeps process-shell fixtures under temporary homes", async () => {
    const source = await readFile(processShellSource, "utf8");
    const testSource = await readFile(fileURLToPath(import.meta.url), "utf8");
    expect(source).not.toContain(["user", "Info().", "home", "dir"].join(""));
    expect(source).not.toContain(["user", "Info"].join(""));
    expect(source).not.toContain(["home", "dir"].join(""));
    expect(testSource).not.toContain(["user", "Info("].join(""));
    expect(testSource).not.toContain(["home", "dir("].join(""));
  });

  it("keeps reader, custody-key, and encode-failure invariants at the process shell", async () => {
    const source = await readFile(processShellSource, "utf8");
    expect(source).toMatch(/stream\.on\("data", \(chunk: Buffer\) => \{\n    if \(stopped\) return;\n    decoder\.push\(chunk\);/);
    expect(source).toContain('if (resolved.kind === "keychain-key") resolved.key.fill(0);');
    expect(source).toContain('this.failAndThrow("encode_failed", error);');
  });

  it("keeps startup subtractions out of the process shell surface", async () => {
    const source = await readFile(processShellSource, "utf8");
    for (const removed of [
      "afterCustodyEstablished",
      "flushAudit",
      "releaseBarrier",
      "effectHandlesConstructed",
      "configuredEffectHandles",
      "readBridgeConfigFile",
      "readDistressConfig",
      "startupStateForError",
    ]) {
      expect(source).not.toContain(removed);
    }
    expect(source).toContain("hermes-memory-bridge ${error.state}: startup refused");
    expect(source).not.toContain("startup refused: ${");
  });

  it("keeps the credential helper spawn from inheriting the relay descriptor", async () => {
    const source = await readFile(keychainExecEntry, "utf8");
    expect(source).toContain('stdio: ["pipe", "pipe", "pipe"],');
    expect(source).toContain('const detached = process.platform !== "win32";');
    expect(source).toContain("detached,");
  });

  it("passes the production environment unchanged to the bridge validator", async () => {
    const source = await readFile(cliEntry, "utf8");
    expect(source).toContain("env: process.env,");
    expect(source).not.toContain("delete bridgeEnv.VITEST");
  });

  it("sends ready first and exits cleanly on relay shutdown", async () => {
    const fixture = await seededFortress("ready-clean");
    const pair = await socketPair();

    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });

    expect(Object.keys(fixture.env).sort()).toEqual([...HERMES_BRIDGE_ENV_ALLOWLIST].sort());
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    expect(shell.report.adapterMode).toBe("hermes-bridge");
    expect(shell.report.adapterOwnerRef).toBe("agent-ready-clean");
    expect(shell.report.forwardersBound).toEqual({
      adapter: true,
      audit: true,
      badSignerScanner: true,
    });
    expect(shell.report.adapterCount).toBe(1);
    const barrierSocketPath = shell.report.custodyHandlesConstructed[0]?.socketPath;
    expect(barrierSocketPath).toEqual(expect.any(String));
    await expect(lstat(barrierSocketPath!)).resolves.toBeTruthy();
    pair.relay.write(privateFrame({ type: "relay_shutdown" }));
    await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    await expect(lstat(barrierSocketPath!)).rejects.toMatchObject({ code: "ENOENT" });
    pair.close();
  });

  it("ignores runtime effect config and opens no optional listener", async () => {
    const fixture = await seededFortress("composition-effects");
    await seedRuntimeEffectConfig(fixture.fortressDir);
    const pair = await socketPair();

    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      const barrierSocketPath = shell.report.custodyHandlesConstructed[0]?.socketPath;
      expect(shell.report.adapterCount).toBe(1);
      expect(shell.report.persistedTrapSpecCount).toBe(0);
      expect(shell.report.listeningSockets).toEqual([
        { kind: "master_write_barrier", socketPath: barrierSocketPath },
      ]);
      // The custody barrier intentionally unrefs its server, so the active-handle census proves only that no optional ref'd listener was opened.
      expect(activeServerSocketPaths()).toEqual([]);
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    } finally {
      pair.close();
    }
  });

  it("reaches ready and clean shutdown through the real CLI subprocess", async () => {
    const fixture = await seededFortress("subprocess-ready");
    const child = spawnBridgeCli(fixture.env);
    const relay = child.stdio[3] as Duplex;
    try {
      expect(await readNodeFrame(relay)).toEqual({ type: "ready" });
      relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_CLEAN, signal: null });
    } finally {
      killChild(child);
    }
  }, 30_000);

  it("refuses VITEST in the real CLI subprocess", async () => {
    const fixture = await seededFortress("vitest-refusal");
    const child = spawnBridgeCli({ ...fixture.env, VITEST: "true" });
    const stderr = collectChildStderr(child);
    const relay = child.stdio[3] as Duplex;
    relay.on("error", () => undefined);
    relay.write(privateFrame({ type: "relay_shutdown" }));
    try {
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_STARTUP_REFUSED, signal: null });
      expect(stderr()).toContain("state_ENV_REPLACED");
    } finally { child.kill("SIGKILL"); }
  }, 30_000);

  it.each([{ args: [] }, { args: ["--help"] }, { args: ["-h"] }])("prints bridge usage without custody for $args", async ({ args }) => {
    const home = await tempHome("help-without-custody");
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", fixtureChildScript(), "hermes-memory-bridge", ...args], {
      cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, HERMES_FIXTURE_ENV: JSON.stringify({ HOME: home }) },
    });
    const stderr = collectChildStderr(child);
    let stdout = "";
    child.stdout!.on("data", (data) => { stdout += String(data); });
    try {
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_CLEAN, signal: null });
      expect(stdout).toBe("Usage: sanctuary hermes-memory-bridge run --relay-fd <fd>\n");
      expect(stderr()).not.toContain("startup refused");
      expect(await readdir(home)).toEqual([]);
    } finally { child.kill("SIGKILL"); }
  }, 30_000);

  it("exposes no owner decision capability from the production process handle", async () => {
    const fixture = await seededFortress("handle-authority");
    const pair = await socketPair();
    const shell = await runProductionHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      expect(Object.keys(shell).sort()).toEqual(["crash", "exited", "report", "signalStop"]);
    } finally {
      shell.signalStop("SIGTERM");
      await shell.exited;
      pair.close();
    }
  });

  it("keeps production CLI inserts pending without an approval channel", async () => {
    const fixture = await seededFortress("cli-no-approval");
    const coreEntry = fileURLToPath(new URL("../../src/hermes-memory-bridge/bridge-core.ts", import.meta.url));
    // Observe actual approval calls in the isolated CLI child without replacing
    // their behavior. A short no-output window alone cannot prove no approval.
    const instrumentApproval = `
      const { HermesBridgeCore } = await import(pathToFileURL(${JSON.stringify(coreEntry)}).href);
      const originalApprove = HermesBridgeCore.prototype.ownerApprove;
      let approvalCalls = 0;
      HermesBridgeCore.prototype.ownerApprove = function(...args) {
        approvalCalls++;
        return originalApprove.apply(this, args);
      };
      process.on("exit", () => process.stderr.write("CLI_OWNER_APPROVAL_CALLS=" + approvalCalls + "\\n"));
    `;
    const script = fixtureChildScript().replace("    await import(pathToFileURL", instrumentApproval + "    await import(pathToFileURL");
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script, "hermes-memory-bridge", "run", "--relay-fd", "3"], {
      cwd: process.cwd(),
      stdio: ["ignore", "ignore", "pipe", "pipe"],
      env: { ...process.env, HERMES_FIXTURE_ENV: JSON.stringify(fixture.env) },
    });
    const relay = child.stdio[3] as Duplex;
    const stderr = collectChildStderr(child);
    try {
      expect(await readNodeFrame(relay)).toEqual({ type: "ready" });
      relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      relay.write(relayPublicFrame("c1", {
        type: "tools_call", request_id: "no-approval", name: "memory_insert",
        arguments: { text: "must require owner approval", taint: "user_content", passage_id: "no-approval" },
      }));
      await waitUntil(() => stderr().includes("owner approval is deferred"));
      // An admitted write would emit a probe; the delivered CLI has no owner authority to reach it.
      await expectNoRelayBytes(relay);
      relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_CLEAN, signal: null });
      const approvalCounts = [...stderr().matchAll(/CLI_OWNER_APPROVAL_CALLS=(\d+)/g)].map((match) => Number(match[1]));
      console.log("CLI_OWNER_APPROVAL_COUNTS", approvalCounts);
      expect(approvalCounts).toEqual([0]);
      const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
      expect(await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).toEqual([]);
    } finally { killChild(child); }
  }, 30_000);

  it.each(["reject", "deadline", "late_reject"] as const)("preserves clean audit flush tail %s", async (mode) => {
    const fixture = await seededFortress(`audit-tail-${mode.replaceAll("_", "-")}`);
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    let settle: (() => void) | undefined;
    const flush = vi.spyOn(AuditLog.prototype, "flush").mockImplementation(() => mode === "reject"
      ? Promise.reject(new Error("fixture audit failure"))
      : new Promise<void>((resolve, reject) => { settle = mode === "late_reject" ? () => reject(new Error("late audit rejection")) : resolve; }));
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expectExitWithin(shell.exited, EXIT_CLEAN);
      expect(flush).toHaveBeenCalledOnce();
      settle?.();
      await new Promise((resolve) => setImmediate(resolve));
    } finally { settle?.(); flush.mockRestore(); pair.close(); }
  });

  it("preserves a clean drain when a terminal audit append rejects", async () => {
    const fixture = await seededFortress("terminal-audit-reject");
    const pair = await socketPair();
    let stderrText = "";
    const shell = await runHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    const append = vi.spyOn(AuditLog.prototype, "appendCritical");
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(relayPublicFrame("c1", { type: "tools_call", request_id: "terminal-audit", name: "memory_insert", arguments: { text: "pending", taint: "user_content", passage_id: "terminal-audit" } }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      append.mockRejectedValue(new Error("fixture terminal audit failure"));
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
      expect(append.mock.calls.some(([record]) => record.details?.kind === "terminal")).toBe(true);
    } finally { append.mockRestore(); pair.close(); }
  });

  it("refuses NODE_OPTIONS in the real CLI subprocess without writing ready", async () => {
    const fixture = await seededFortress("subprocess-env");
    const child = spawnBridgeCli({ ...fixture.env, NODE_OPTIONS: "--no-warnings" });
    const relay = child.stdio[3] as Duplex;
    const stderr = collectChildStderr(child);
    try {
      await expect(childExit(child)).resolves.toMatchObject({ code: 78, signal: null });
      await expectNoRelayBytes(relay);
      expect(stderr()).toContain("state_ENV_REPLACED");
    } finally {
      killChild(child);
    }
  }, 30_000);

  it.each([
    ["regular file", async () => {
      const dir = await mkdtemp(join(tmpdir(), "hermes-fd-regular-"));
      cleanups.push(() => rm(dir, { recursive: true, force: true }));
      const filePath = join(dir, "relay-fd");
      await writeFile(filePath, "");
      const fd = openSync(filePath, "r+");
      return { stdioFd: fd, close: () => closeSync(fd), observeBytes: async () => (await lstat(filePath)).size };
    }],
    ["FIFO", async () => {
      const dir = await mkdtemp(join(tmpdir(), "hermes-fd-fifo-"));
      cleanups.push(() => rm(dir, { recursive: true, force: true }));
      const fifoPath = join(dir, "relay-fd");
      const made = spawnSync("mkfifo", [fifoPath]);
      if (made.status !== 0) throw new Error(`mkfifo failed: ${made.stderr.toString("utf8")}`);
      const fd = openSync(fifoPath, fsConstants.O_RDWR | fsConstants.O_NONBLOCK);
      return {
        stdioFd: fd,
        close: () => closeSync(fd),
        observeBytes: async () => {
          const buffer = Buffer.alloc(64);
          try {
            return readSync(fd, buffer, 0, buffer.byteLength, null);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "EAGAIN") return 0;
            throw error;
          }
        },
      };
    }],
  ])("refuses fd 3 when it is a %s and writes no relay bytes", async (_name, makeFd) => {
    const fixture = await seededFortress(`subprocess-fd-${String(_name).replaceAll(" ", "-")}`);
    const fd = await makeFd();
    const child = spawnBridgeCliWithFd(fixture.env, fd.stdioFd);
    const stderr = collectChildStderr(child);
    try {
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_STARTUP_REFUSED, signal: null });
      expect(stderr()).toContain("state_FD_CHECKED");
      await expect(fd.observeBytes()).resolves.toBe(0);
    } finally {
      fd.close();
      killChild(child);
    }
  }, 30_000);

  it.each([false, true])("refuses a TCP-family relay before custody even after reset %s", async (reset) => {
    const fixture = await seededFortress("tcp-family");
    const tcp = await tcpSocketPair();
    tcp.shell.on("error", () => undefined);
    if (reset) {
      const closed = new Promise<void>((resolve) => tcp.shell.once("close", () => resolve()));
      tcp.relay.resetAndDestroy();
      tcp.shell.resume();
      await closed;
      expect(tcp.shell.remoteFamily).toBeUndefined();
    }
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    try {
      const outcome = await runProductionHermesBridgeProcess({
        env: fixture.env,
        relaySocketFactory: () => tcp.shell,
        storageFor: () => storage,
        uid: process.getuid?.() ?? 0,
      }).then(async (handle) => {
        handle.signalStop("SIGTERM");
        await handle.exited;
        return { returned: true, error: undefined };
      }, (error: unknown) => ({ returned: false, error }));
      console.log("TCP_CUSTODY_ORACLES", JSON.stringify({ reset, returned: outcome.returned, reads: reads.mock.calls.length }));
      expect(reads).not.toHaveBeenCalled();
      expect(outcome).toMatchObject({ returned: false, error: { name: "HermesBridgeStartupRefusal", state: "state_CONFIG_CHECKED" } });
      if (!reset) await expectNoRelayBytes(tcp.relay);
    } finally {
      reads.mockRestore();
      tcp.close();
    }
  });

  it("refuses an inherited listening TCP fd before custody without an uncaught error", async () => {
    const fixture = await seededFortress("listening-fd");
    const listener = net.createServer();
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    const fd = (listener as unknown as { _handle: { fd: number } })._handle.fd;
    const storageEntry = fileURLToPath(new URL("../../src/storage/filesystem.ts", import.meta.url));
    const instrument = `
      const { FilesystemStorage } = await import(pathToFileURL(${JSON.stringify(storageEntry)}).href);
      const originalRead = FilesystemStorage.prototype.read;
      let storageReads = 0;
      FilesystemStorage.prototype.read = function (...args) { storageReads++; return originalRead.apply(this, args); };
      process.on("exit", () => process.stderr.write("LISTENING_STORAGE_READS=" + storageReads + "\\n"));
      const net = await import("node:net");
      const originalAddress = net.Socket.prototype.address;
      net.Socket.prototype.address = function (...args) {
        const address = originalAddress.apply(this, args);
        if (this._handle?.fd === 3) process.stderr.write("LISTENING_FD_STATE=" + JSON.stringify({
          remoteFamily: this.remoteFamily ?? null, destroyed: this.destroyed,
          readable: this.readable, writable: this.writable, family: address.family,
        }) + "\\n");
        return address;
      };
      // Observe the fd independently if the family predicate is removed: delegate the actual probe unchanged.
      const originalWrite = net.Socket.prototype.write;
      net.Socket.prototype.write = function (...args) {
        if (this._handle?.fd === 3) this.address();
        return originalWrite.apply(this, args);
      };
    `;
    const script = fixtureChildScript().replace("    await import(pathToFileURL", instrument + "    await import(pathToFileURL");
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script, "hermes-memory-bridge", "run", "--relay-fd", "3"], {
      cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe", fd],
      env: { ...process.env, HERMES_FIXTURE_ENV: JSON.stringify(fixture.env) },
    });
    const stderr = collectChildStderr(child);
    try {
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_STARTUP_REFUSED, signal: null });
      expect(stderr()).toContain("state_CONFIG_CHECKED: startup refused");
      expect(stderr()).toContain("LISTENING_STORAGE_READS=0");
      const observed = stderr().split("\n").find((line) => line.startsWith("LISTENING_FD_STATE="));
      expect(JSON.parse(observed!.slice("LISTENING_FD_STATE=".length))).toEqual({
        remoteFamily: null, destroyed: false, readable: true, writable: true, family: "IPv4",
      });
      expect(stderr()).not.toContain("Unhandled 'error'");
    } finally {
      killChild(child);
      await childExit(child);
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  }, 30_000);

  it.each(["cli", "injected"] as const)("native UNIX listener is refused before custody by transport admission through %s", async (entry) => {
    const fixture = await seededFortress("listening-unix");
    const listener = net.createServer();
    const socketDir = await tempHome("listener-unix");
    await new Promise<void>((resolve) => listener.listen(join(socketDir, "relay.sock"), resolve));
    const fd = (listener as unknown as { _handle: { fd: number } })._handle.fd;
    const storageEntry = fileURLToPath(new URL("../../src/storage/filesystem.ts", import.meta.url));
    const instrument = `
      const { FilesystemStorage } = await import(pathToFileURL(${JSON.stringify(storageEntry)}).href);
      const originalRead = FilesystemStorage.prototype.read;
      let storageReads = 0;
      let uncaughtErrors = 0;
      process.on("uncaughtExceptionMonitor", () => { uncaughtErrors++; });
      process.on("exit", () => process.stderr.write("NATIVE_UNCAUGHT=" + uncaughtErrors + "\\n"));
      FilesystemStorage.prototype.read = function (...args) { storageReads++; return originalRead.apply(this, args); };
      process.on("exit", () => process.stderr.write("LISTENING_STORAGE_READS=" + storageReads + "\\n"));
      const net = await import("node:net");
      const originalAddress = net.Socket.prototype.address;
      net.Socket.prototype.address = function (...args) {
        const address = originalAddress.apply(this, args);
        if (this._handle?.fd === 3) process.stderr.write("LISTENING_FD_STATE=" + JSON.stringify({
          remoteFamily: this.remoteFamily ?? null, destroyed: this.destroyed,
          readable: this.readable, writable: this.writable, family: address.family,
        }) + "\\n");
        return address;
      };
    `;
    let script = fixtureChildScript().replace("    await import(pathToFileURL", instrument + "    await import(pathToFileURL");
    if (entry === "injected") {
      script = script.replace(`await import(pathToFileURL(${JSON.stringify(cliEntry)}).href);`, `
        const { hermesBridgeMain } = await import(pathToFileURL(${JSON.stringify(processShellSource)}).href);
        process.exitCode = await hermesBridgeMain({
          argv: ["run", "--relay-fd", "3"], env: fixtureEnv,
          relaySocketFactory: () => new net.Socket({ fd: 3 }),
        });
      `);
    }
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script, "hermes-memory-bridge", "run", "--relay-fd", "3"], {
      cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe", fd],
      env: { ...process.env, HERMES_FIXTURE_ENV: JSON.stringify(fixture.env) },
    });
    const stderr = collectChildStderr(child);
    try {
      // Collect both negative oracles before an assertion can stop the test.
      const exit = await childExit(child);
      const reads = [...stderr().matchAll(/LISTENING_STORAGE_READS=(\d+)/g)].map((match) => Number(match[1]));
      console.log("NATIVE_ADMISSION_ORACLES", JSON.stringify({ exit, reads }));
      expect({ exit, reads }).toEqual({ exit: { code: EXIT_STARTUP_REFUSED, signal: null }, reads: [0] });
      expect(stderr()).toContain("state_CONFIG_CHECKED: startup refused");
      const observed = stderr().split("\n").find((line) => line.startsWith("LISTENING_FD_STATE="));
      expect(JSON.parse(observed!.slice("LISTENING_FD_STATE=".length))).toEqual({
        remoteFamily: null, destroyed: false, readable: true, writable: true,
      });
      expect(stderr()).toContain("NATIVE_UNCAUGHT=0");
      expect(stderr()).not.toContain("Unhandled 'error'");
    } finally {
      killChild(child);
      await childExit(child);
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  }, 30_000);

  it.each(["ordinary", "onread"] as const)("native admission requires successful zero-byte callback before custody and preserves early input through %s", async (transport) => {
    const fixture = await seededFortress("probe-success");
    const pair = transport === "onread" ? await onreadSocketPair() : await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    const frames = vi.spyOn(HermesBridgeCore.prototype, "relayFrame");
    const realWrite = pair.shell.write.bind(pair.shell);
    let probeCallback: ((error?: Error | null) => void) | undefined;
    let probes = 0;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((chunk: Buffer, callback: (error?: Error | null) => void) => {
      if (chunk.byteLength === 0) { probes++; probeCallback = callback; return false; }
      return realWrite(chunk, callback);
    }) as typeof pair.shell.write);
    const early = Buffer.concat([
      privateFrame({ type: "accepted", connection_id: "c1" }),
      privateFrame({ type: "relay_shutdown" }),
    ]);
    const startup = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0 });
    try {
      await waitUntil(() => probeCallback !== undefined);
      expect(pair.shell.readableFlowing).toBe(false); // Assert before a readable observer can itself pause the stream.
      const observeReadable = () => undefined;
      pair.shell.on("readable", observeReadable);
      pair.relay.write(early);
      await waitUntil(() => pair.shell.readableLength === early.length);
      pair.shell.off("readable", observeReadable);
      expect(pair.shell.isPaused()).toBe(true);
      expect(reads).not.toHaveBeenCalled();
      expect(frames).not.toHaveBeenCalled();
      expect(probes).toBe(1);
      // The write return was false; only its explicit successful callback permits custody.
      probeCallback!();
      const shell = await startup;
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
      expect(frames.mock.calls.map(([frame]) => frame.kind)).toEqual(["accepted", "relay_shutdown"]);
      expect(probes).toBe(1);
      expect(reads.mock.calls.length).toBeGreaterThan(0);
    } finally {
      probeCallback?.(new Error("fixture cleanup"));
      write.mockRestore(); reads.mockRestore(); frames.mockRestore(); pair.close();
      await startup.catch(() => undefined);
    }
  });

  it("preserves early CLI frame order and writes ready before any response", async () => {
    const testStarted = performance.now();
    const fixture = await seededFortress("cli-early-probe");
    const child = spawnBridgeCli(fixture.env);
    const relay = child.stdio[3] as Duplex;
    const peerClosed = new Promise<void>((resolve) => relay.once("close", () => resolve()));
    const stderr = collectChildStderr(child);
    const decoder = new PrivateFrameDecoder();
    const output: Array<Record<string, unknown>> = [];
    const peerErrors: string[] = [];
    let rejectObservation!: (error: Error) => void;
    let shutdownSent = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    const observed = new Promise<void>((resolve, reject) => {
      rejectObservation = reject;
      child.once("close", () => {
        if (output.length < 2) reject(new Error("CLI closed before ready and response"));
        else resolve();
      });
      // Reserve five seconds of this test's existing 30-second bound for teardown.
      timer = setTimeout(() => reject(new Error("CLI frame and exit observation deadline")), Math.max(0, 25_000 - (performance.now() - testStarted)));
    });
    const onError = (error: Error) => {
      peerErrors.push(error.message);
      rejectObservation(error);
    };
    const onData = (chunk: Buffer) => {
      try {
        decoder.push(chunk);
        for (;;) {
          const next = decoder.next();
          if (next.kind === "need_more") return;
          if (next.kind === "fatal") { rejectObservation(next.error); return; }
          output.push(JSON.parse(Buffer.from(next.body).toString("utf8")) as Record<string, unknown>);
          if (output.length === 2 && !shutdownSent) {
            shutdownSent = true;
            relay.write(privateFrame({ type: "relay_shutdown" }));
          }
        }
      } catch (error) { rejectObservation(error instanceof Error ? error : new Error(String(error))); }
    };
    relay.on("error", onError);
    child.on("error", onError);
    relay.on("data", onData);
    try {
      // Observe events before sending: both frames still precede CLI readiness.
      relay.write(Buffer.concat([
        privateFrame({ type: "accepted", connection_id: "c1" }),
        relayPublicFrame("c1", { type: "hello", request_id: "early-hello", protocol_version: "2026-10-12", client_name: "hermes" }),
      ]));
      await observed;
      const [actualExit] = await Promise.all([exit, peerClosed]);
      console.log("EARLY_CLI_ORACLES", JSON.stringify({ output, actualExit, stderr: stderr(), peerErrors }));
      expect(output).toHaveLength(2);
      expect(output[0]).toEqual({ type: "ready" });
      expect(output[1]).toMatchObject({ type: "response", request_id: "early-hello" });
      expect(JSON.parse(Buffer.from(String(output[1]!.result_b64), "base64").toString("utf8"))).toMatchObject({ type: "result" });
      expect(actualExit).toEqual({ code: EXIT_CLEAN, signal: null });
      expect(peerErrors).toEqual([]);
      expect(stderr()).toBe("");
    } finally {
      clearTimeout(timer);
      killChild(child);
      await Promise.all([exit, peerClosed]);
      // Keep error ownership until the child and inherited peer have closed.
      relay.off("data", onData);
      relay.off("error", onError);
      child.off("error", onError);
    }
  }, 30_000);

  it("bounds a corked native admission and owns its late error callback through close", async () => {
    const fixture = await seededFortress("probe-cork");
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    const realWrite = pair.shell.write.bind(pair.shell);
    const callbacks: Array<Error | null | undefined> = [];
    let probes = 0;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((chunk: Buffer, callback: (error?: Error | null) => void) => {
      if (chunk.byteLength === 0) probes++;
      return realWrite(chunk, (error) => { callbacks.push(error); callback(error); });
    }) as typeof pair.shell.write);
    const closed = new Promise<void>((resolve) => pair.shell.once("close", () => resolve()));
    pair.shell.cork();
    const started = performance.now();
    try {
      await expectStartupRefusal({ env: fixture.env, relaySocketFactory: () => pair.shell,
        storageFor: () => storage, uid: process.getuid?.() ?? 0 }, "state_CONFIG_CHECKED");
      await closed;
      expect(performance.now() - started).toBeGreaterThanOrEqual(2_000);
      expect(probes).toBe(1);
      expect(callbacks).toHaveLength(1);
      expect(callbacks[0]).toMatchObject({ code: "ERR_STREAM_DESTROYED" });
      expect(reads).not.toHaveBeenCalled();
      expect(pair.shell.destroyed).toBe(true);
      await expectNoRelayBytes(pair.relay);
    } finally { write.mockRestore(); reads.mockRestore(); pair.close(); }
  });

  it.each([
    { kind: "signal", complete: true }, { kind: "crash", complete: true },
    { kind: "signal", complete: false }, { kind: "crash", complete: false },
  ] as const)("refuses $kind during native admission without custody with callback completion=$complete", async ({ kind, complete }) => {
    const fixture = await seededFortress(`probe-stop-${kind}`);
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    let callback: ((error?: Error | null) => void) | undefined;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((_chunk: Buffer, cb: (error?: Error | null) => void) => {
      callback = cb; return true;
    }) as typeof pair.shell.write);
    let stderr = "";
    const result = hermesBridgeMain({ argv: ["run", "--relay-fd", String(socketFd(pair.shell))],
      env: fixture.env, relaySocketFactory: () => pair.shell, storageFor: () => storage,
      stderr: { write: (chunk: string | Uint8Array) => { stderr += String(chunk); return true; } }, uid: process.getuid?.() ?? 0 });
    try {
      await waitUntil(() => callback !== undefined);
      if (kind === "signal") process.emit("SIGTERM");
      else process.emit("uncaughtException", new Error("probe crash fixture"));
      if (complete) callback!();
      await expect(result).resolves.toBe(EXIT_STARTUP_REFUSED);
      expect(stderr).toContain("state_CONFIG_CHECKED");
      expect(reads).not.toHaveBeenCalled();
      expect(pair.shell.destroyed).toBe(true);
    } finally { callback?.(); await result; write.mockRestore(); reads.mockRestore(); pair.close(); }
  });

  it.each(["callback-error", "success-then-error", "success-then-microtask-error", "end", "close"] as const)("owns native admission %s before custody without uncaught errors", async (kind) => {
    const fixture = await seededFortress(`probe-order-${kind}`);
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    let callback: ((error?: Error | null) => void) | undefined;
    let observedErrors = 0;
    let uncaught = 0;
    const observeUncaught = () => { uncaught++; };
    process.on("uncaughtExceptionMonitor", observeUncaught);
    pair.shell.on("error", () => { observedErrors++; });
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((_chunk: Buffer, cb: (error?: Error | null) => void) => {
      callback = cb; return true;
    }) as typeof pair.shell.write);
    const result = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0 }).then(
      async (handle) => { handle.signalStop("SIGTERM"); await handle.exited; return { returned: true, error: undefined }; },
      (error: unknown) => ({ returned: false, error }),
    );
    try {
      await waitUntil(() => callback !== undefined);
      // The fixture observer is one listener; product ownership must already be present.
      expect(pair.shell.listenerCount("error")).toBeGreaterThan(1);
      if (kind === "callback-error") {
        callback!(new Error("first callback failure"));
        pair.shell.emit("error", new Error("later emitted failure"));
      } else if (kind === "success-then-error" || kind === "success-then-microtask-error") {
        callback!();
        if (kind === "success-then-error") pair.shell.emit("error", new Error("observed after success"));
        else queueMicrotask(() => pair.shell.emit("error", new Error("admission continuation failure")));
      } else {
        pair.shell.emit(kind);
        callback!();
      }
      const outcome = await result;
      expect(outcome.returned).toBe(false);
      expect(outcome.error).toMatchObject({ state: "state_CONFIG_CHECKED" });
      expect(reads).not.toHaveBeenCalled();
      expect(observedErrors).toBe(kind.includes("error") ? 1 : 0);
      if (kind === "callback-error") expect(outcome.error).toMatchObject({ message: "relay socket admission write failed" });
      expect(uncaught).toBe(0);
      expect(pair.shell.destroyed).toBe(true);
    } finally {
      callback?.(new Error("fixture cleanup")); await result;
      process.off("uncaughtExceptionMonitor", observeUncaught);
      write.mockRestore(); reads.mockRestore(); pair.close();
    }
  });

  it("keeps startup ownership across the last pre-ready await", async () => {
    const fixture = await seededFortress("last-await-error");
    const pair = await socketPair();
    const storage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const before = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    let released = false;
    let injected = false;
    const output: Buffer[] = [];
    pair.relay.on("data", (chunk: Buffer) => output.push(chunk));
    const result = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0,
      startupStopRequested: () => {
        if (released && !injected) {
          injected = true;
          queueMicrotask(() => pair.shell.emit("error", new Error("last pre-ready continuation")));
        }
        return undefined;
      },
    }).then(async (handle) => { handle.signalStop("SIGTERM"); await handle.exited; return { returned: true, error: undefined }; },
      (error: unknown) => ({ returned: false, error }));
    try {
      await waitUntil(() => storage.trapListParked);
      const barrierPath = await fortressCustodySocket(storage, before);
      released = true; storage.release();
      const outcome = await result;
      expect(injected).toBe(true);
      expect(outcome).toMatchObject({ returned: false, error: { state: "state_GATE_WIRED" } });
      expect(Buffer.concat(output)).toHaveLength(0);
      await expect(lstat(barrierPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally { storage.release(); pair.close(); await result; }
  });

  it("keeps native paused admission buffering within the observed stream allocation bound", async () => {
    const fixture = await seededFortress("probe-buffer-bound");
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    const frames = vi.spyOn(HermesBridgeCore.prototype, "relayFrame");
    let callback: ((error?: Error | null) => void) | undefined;
    let stop = false;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((_chunk: Buffer, cb: (error?: Error | null) => void) => {
      callback = cb; return true;
    }) as typeof pair.shell.write);
    pair.relay.on("error", () => undefined);
    const startup = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0, startupStopRequested: () => stop ? { kind: "signal" } : undefined });
    const observed = startup.catch((error: unknown) => error);
    try {
      await waitUntil(() => callback !== undefined);
      expect(pair.shell.readableFlowing).toBe(false); // Assert before observer attachment changes stream state.
      const observeReadable = () => undefined;
      pair.shell.on("readable", observeReadable);
      pair.relay.write(Buffer.alloc(1024 * 1024, 0x61));
      await waitUntil(() => pair.shell.readableLength >= pair.shell.readableHighWaterMark);
      pair.shell.off("readable", observeReadable);
      expect(pair.shell.isPaused()).toBe(true);
      // Observed native allocation allowance only: this is not an exact heap or all-offered-bytes-delivered claim.
      expect(pair.shell.readableLength).toBeLessThanOrEqual(pair.shell.readableHighWaterMark + 64 * 1024);
      expect(reads).not.toHaveBeenCalled();
      expect(frames).not.toHaveBeenCalled();
      stop = true; callback!();
      await expect(observed).resolves.toMatchObject({ state: "state_CONFIG_CHECKED" });
    } finally { stop = true; callback?.(); await observed; write.mockRestore(); reads.mockRestore(); frames.mockRestore(); pair.close(); }
  });

  it.each(["fresh", "connecting", "write-ended"] as const)("refuses native %s state before custody", async (kind) => {
    const fixture = await seededFortress(`probe-shape-${kind}`);
    const pair = await socketPair(true);
    const stream = kind === "fresh" ? new net.Socket() : pair.shell;
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    if (kind === "connecting") Object.defineProperty(stream, "connecting", { value: true, configurable: true });
    if (kind === "write-ended") {
      await new Promise<void>((resolve) => stream.end(resolve));
      expect(stream.writable).toBe(false);
      expect(stream.readable).toBe(true);
    }
    try {
      await expectStartupRefusal({ env: fixture.env, relaySocketFactory: () => stream,
        storageFor: () => storage, uid: process.getuid?.() ?? 0 }, "state_CONFIG_CHECKED");
      expect(reads).not.toHaveBeenCalled();
      expect(stream.destroyed).toBe(true);
    } finally { reads.mockRestore(); stream.destroy(); pair.close(); }
  });

  it("hands native ready-write errors to runtime ownership after the admission callback", async () => {
    const fixture = await seededFortress("probe-runtime-handoff");
    const pair = await socketPair();
    const realWrite = pair.shell.write.bind(pair.shell);
    let probeCalls = 0;
    let readyCalls = 0;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((chunk: Buffer, cb: (error?: Error | null) => void) => {
      if (chunk.byteLength === 0) { probeCalls++; return realWrite(chunk, cb); }
      readyCalls++;
      cb(new Error("ready callback failed"));
      pair.shell.emit("error", new Error("ready emitted error"));
      return false;
    }) as typeof pair.shell.write);
    try {
      const shell = await runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
        storageFor: (dir) => new FilesystemStorage(join(dir, "state")), uid: process.getuid?.() ?? 0 });
      await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
      expect(probeCalls).toBe(1);
      expect(readyCalls).toBeGreaterThanOrEqual(1);
    } finally { write.mockRestore(); pair.close(); }
  });

  it("keeps a timer-first native admission refusal settled despite repeated late callbacks", async () => {
    const fixture = await seededFortress("probe-late-success");
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    let callback: ((error?: Error | null) => void) | undefined;
    let probes = 0;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((_chunk: Buffer, cb: (error?: Error | null) => void) => {
      probes++; callback = cb; return true;
    }) as typeof pair.shell.write);
    const result = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0 });
    const closed = new Promise<void>((resolve) => pair.shell.once("close", () => resolve()));
    try {
      await expect(result).rejects.toMatchObject({ state: "state_CONFIG_CHECKED", message: "relay socket admission timed out" });
      callback!(); callback!();
      await closed;
      expect(probes).toBe(1);
      expect(reads).not.toHaveBeenCalled();
      expect(pair.shell.destroyed).toBe(true);
    } finally { write.mockRestore(); reads.mockRestore(); pair.close(); }
  });

  it("refuses a native admission callback invoked after its deadline while the real timer is pending", async () => {
    const fixture = await seededFortress("probe-callback-deadline");
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    let callback: ((error?: Error | null) => void) | undefined;
    let probes = 0;
    let nonemptyWrites = 0;
    let settlements = 0;
    const write = vi.spyOn(pair.shell, "write").mockImplementation(((chunk: Buffer, cb: (error?: Error | null) => void) => {
      if (chunk.byteLength === 0) { probes++; callback = cb; return true; }
      nonemptyWrites++;
      return false;
    }) as typeof pair.shell.write);
    const result = runProductionHermesBridgeProcess({ env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => storage, uid: process.getuid?.() ?? 0 });
    const observed = result.then(
      (handle) => { settlements++; handle.signalStop("SIGTERM"); return { handle }; },
      (error: unknown) => { settlements++; return { error }; },
    );
    try {
      await waitUntil(() => callback !== undefined);
      const afterProbe = performance.now();
      expect(settlements).toBe(0); // The actual admission timer has not dispatched.
      expect(probes).toBe(1);
      expect(reads).not.toHaveBeenCalled();
      expect(nonemptyWrites).toBe(0);
      const now = vi.spyOn(performance, "now").mockReturnValue(afterProbe + 2001);
      try { callback!(); } finally { now.mockRestore(); }
      callback!(); // Repeated completion must not settle startup again.
      const outcome = await observed;
      if (!("error" in outcome)) throw new Error("admission unexpectedly succeeded");
      expect(outcome.error).toMatchObject({ state: "state_CONFIG_CHECKED", message: "relay socket admission timed out" });
      expect(settlements).toBe(1);
      expect(reads).not.toHaveBeenCalled();
      expect(nonemptyWrites).toBe(0); // No Ready frame was offered.
      expect(pair.shell.destroyed).toBe(true);
    } finally {
      callback?.(new Error("fixture cleanup"));
      const outcome = await observed;
      if ("handle" in outcome) {
        outcome.handle.signalStop("SIGTERM");
        await outcome.handle.exited;
      }
      write.mockRestore(); reads.mockRestore(); pair.close();
    }
  });

  it.each([
    { entry: "handle", allowHalfOpen: false },
    { entry: "main", allowHalfOpen: false },
    { entry: "handle", allowHalfOpen: true },
    { entry: "main", allowHalfOpen: true },
  ] as const)("refuses observed UNIX EOF while custody is parked through $entry with allowHalfOpen=$allowHalfOpen", async ({ entry, allowHalfOpen }) => {
    const fixture = await seededFortress(`parked-eof-${entry}-${allowHalfOpen}`);
    const pair = await socketPair(allowHalfOpen);
    const parkedStorage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const before = await __testListMasterBarrierReaderSockets(parkedStorage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const received: Buffer[] = [];
    pair.relay.on("data", (chunk: Buffer) => received.push(chunk));
    let stderrText = "";
    const options = {
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage, uid: process.getuid?.() ?? 0,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
    };
    // Observe both outcomes immediately so a failing old-product witness still drains its handle.
    const result = entry === "main"
      ? hermesBridgeMain({ ...options, argv: ["run", "--relay-fd", String(socketFd(pair.shell))] })
        .then((code) => ({ code, handleReturned: false, error: undefined }))
      : runProductionHermesBridgeProcess(options).then(
        async (handle) => {
          handle.signalStop("SIGTERM");
          return { code: await handle.exited, handleReturned: true, error: undefined };
        },
        (error: unknown) => ({ code: undefined, handleReturned: false, error }),
      );
    try {
      await waitUntil(() => parkedStorage.trapListParked);
      const barrierSocketPath = await fortressCustodySocket(parkedStorage, before);
      await expect(lstat(barrierSocketPath)).resolves.toBeTruthy();
      let eofObserved = false;
      pair.shell.once("end", () => { eofObserved = true; });
      pair.relay.end();
      await waitUntil(() => eofObserved);
      // Actual EOF, not a scheduling delay, establishes the pre-ready half-close.
      expect(pair.shell.readableEnded).toBe(true);
      expect(pair.shell.readable).toBe(false);
      // Default destruction is asynchronous; only the half-open control has a stable pre-release invariant.
      if (allowHalfOpen) {
        expect(pair.shell.destroyed).toBe(false);
        expect(pair.shell.writable).toBe(true);
      }
      expect(parkedStorage.trapListParked).toBe(true);
      parkedStorage.release();
      const outcome = await result;
      await expect(lstat(barrierSocketPath)).rejects.toMatchObject({ code: "ENOENT" });
      expect(pair.shell.destroyed).toBe(true);
      expect(Buffer.concat(received)).toHaveLength(0);
      if (entry === "main") {
        expect(outcome.code).toBe(EXIT_STARTUP_REFUSED);
        expect(stderrText.trim()).toBe("hermes-memory-bridge state_GATE_WIRED: startup refused");
      } else {
        expect(outcome.handleReturned).toBe(false);
        expect(outcome.error).toMatchObject({ name: "HermesBridgeStartupRefusal", state: "state_GATE_WIRED" });
      }
    } finally {
      parkedStorage.release();
      pair.close();
      await result;
    }
  });

  it("onread transparent bridge consumer processes a real hello before clean shutdown", async () => {
    const fixture = await seededFortress("onread-healthy");
    const pair = await onreadSocketPair();
    const output: Array<Record<string, unknown>> = [];
    const decodeError = collectNodeFrames(pair.relay, output);
    const result = runProductionHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: () => new FilesystemStorage(join(fixture.fortressDir, "state")),
    });
    let exit: number | "deadline" = "deadline";
    try {
      const handle = await result;
      pair.relay.write(Buffer.concat([
        privateFrame({ type: "accepted", connection_id: "c1" }),
        relayPublicFrame("c1", { type: "hello", request_id: "onread-hello", protocol_version: "2026-10-12", client_name: "hermes" }),
      ]));
      await boundedObservation(() => output.length >= 2, pair.relay, "data");
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      exit = await boundedValue(handle.exited, 4_000, "deadline" as const);
    } finally { pair.close(); await result.catch(() => undefined); }
    console.log("ONREAD_HEALTHY_ORACLES", JSON.stringify({ output, exit, decodeError: decodeError() }));
    expect({ output: output.map((frame) => frame.type), exit, decodeError: decodeError() }).toEqual({
      output: ["ready", "response"], exit: EXIT_CLEAN, decodeError: undefined,
    });
    expect(output[1]).toMatchObject({ request_id: "onread-hello" });
    expect(JSON.parse(Buffer.from(String(output[1]!.result_b64), "base64").toString("utf8"))).toMatchObject({ type: "result" });
  }, 30_000);

  it("FIN custody witness refuses a transparent public-onread native socket without fixture read or resume", async () => {
    const fixture = await seededFortress("onread-fin");
    const pair = await onreadSocketPair();
    const storage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const reads = vi.spyOn(storage, "read");
    const prior = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const bytes: Buffer[] = [];
    pair.relay.on("data", (chunk: Buffer) => bytes.push(chunk));
    let endObserved = false;
    pair.shell.once("end", () => { endObserved = true; });
    let stderr = "";
    const result = hermesBridgeMain({ argv: ["run", "--relay-fd", String(socketFd(pair.shell))], env: fixture.env,
      relaySocketFactory: () => pair.shell, storageFor: () => storage,
      stderr: { write: (chunk: string | Uint8Array) => { stderr += String(chunk); return true; } },
    });
    let parked = false;
    let finCompleted = false;
    let endBeforeRelease = false;
    let beforeRelease: { readableEnded: boolean; readable: boolean; writable: boolean } | undefined;
    let exit: number | "deadline" = "deadline";
    let barrierPaths: string[] = [];
    try {
      parked = await boundedValue((async () => { await waitUntil(() => storage.trapListParked); return true; })().catch(() => false), 3_000, false);
      barrierPaths = (await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME)).filter((path) => !prior.includes(path));
      finCompleted = await boundedValue(new Promise<boolean>((resolve) => pair.relay.end(() => resolve(true))), 1_000, false);
      endBeforeRelease = await boundedObservation(() => endObserved, pair.shell, "end");
      beforeRelease = { readableEnded: pair.shell.readableEnded, readable: pair.shell.readable, writable: pair.shell.writable };
      storage.release();
      exit = await boundedValue(result, 4_000, "deadline" as const);
    } finally { storage.release(); pair.close(); await result; }
    const remaining = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const observation = { parked, finCompleted, endBeforeRelease, beforeRelease, exit,
      readyBytes: Buffer.concat(bytes).length, reads: reads.mock.calls.length,
      barrierCount: barrierPaths.length, barrierReleased: barrierPaths.every((path) => !remaining.includes(path)), stderr };
    reads.mockRestore();
    console.log("FIN_CUSTODY_ORACLES", JSON.stringify({ entry: "onread", ...observation }));
    expect({ parked, finCompleted, endBeforeRelease, exit, readyBytes: observation.readyBytes,
      barrierCount: observation.barrierCount, barrierReleased: observation.barrierReleased }).toEqual({
      parked: true, finCompleted: true, endBeforeRelease: true, exit: EXIT_STARTUP_REFUSED,
      readyBytes: 0, barrierCount: 1, barrierReleased: true,
    });
    expect(beforeRelease).toMatchObject({ readableEnded: true, readable: false, writable: true });
    expect(observation.reads).toBeGreaterThan(0);
    expect(stderr.trim()).toBe("hermes-memory-bridge state_GATE_WIRED: startup refused");
  }, 30_000);

  it("FIN custody witness refuses the default CLI socket without fixture read or resume", async () => {
    const fixture = await seededFortress("cli-fin");
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const prior = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const storageEntry = fileURLToPath(new URL("../../src/storage/filesystem.ts", import.meta.url));
    const instrument = `
      const { FilesystemStorage } = await import(pathToFileURL(${JSON.stringify(storageEntry)}).href);
      let reads = 0;
      const originalRead = FilesystemStorage.prototype.read;
      FilesystemStorage.prototype.read = function (...args) { reads++; return originalRead.apply(this, args); };
      let release;
      const parked = new Promise(resolve => { release = resolve; });
      process.on("message", message => { if (message === "release") release(); });
      const originalList = FilesystemStorage.prototype.list;
      FilesystemStorage.prototype.list = async function (namespace, prefix) {
        if (namespace === ${JSON.stringify(TRAP_STORE_NAMESPACE)} && prefix === ${JSON.stringify(TRAP_STORE_KEY_PREFIX)}) {
          process.send({ kind: "parked", reads });
          await parked;
        }
        return originalList.call(this, namespace, prefix);
      };
      const net = await import("node:net");
      const originalEmit = net.Socket.prototype.emit;
      net.Socket.prototype.emit = function (event, ...args) {
        if (event === "end" && this._handle?.fd === 3) process.send({ kind: "end", readableEnded: this.readableEnded, readable: this.readable });
        return originalEmit.call(this, event, ...args);
      };
      process.on("exit", () => process.stderr.write("FIN_STORAGE_READS=" + reads + "\\n"));
    `;
    const script = fixtureChildScript().replace("    await import(pathToFileURL", instrument + "    await import(pathToFileURL");
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script, "hermes-memory-bridge", "run", "--relay-fd", "3"], {
      cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe", "pipe", "ipc"],
      env: { ...process.env, HERMES_FIXTURE_ENV: JSON.stringify(fixture.env) },
    });
    const stderr = collectChildStderr(child);
    const relay = child.stdio[3] as Duplex;
    const bytes: Buffer[] = [];
    relay.on("data", (chunk: Buffer) => bytes.push(chunk));
    const messages: Array<{ kind: string; readableEnded?: boolean; readable?: boolean }> = [];
    child.on("message", (message) => messages.push(message as typeof messages[number]));
    let parked = false;
    let finCompleted = false;
    let endBeforeRelease = false;
    let barrierPaths: string[] = [];
    let exit: Awaited<ReturnType<typeof childExit>> | "deadline" = "deadline";
    try {
      parked = await boundedObservation(() => messages.some((message) => message.kind === "parked"), child, "message", 5_000);
      barrierPaths = (await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME)).filter((path) => !prior.includes(path));
      finCompleted = await boundedValue(new Promise<boolean>((resolve) => relay.end(() => resolve(true))), 1_000, false);
      endBeforeRelease = await boundedObservation(() => messages.some((message) => message.kind === "end"), child, "message");
      if (child.connected) child.send("release");
      exit = await boundedValue(childExit(child), 5_000, "deadline" as const);
    } finally { if (child.connected) child.send("release"); killChild(child); await childExit(child); }
    const remaining = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const reads = [...stderr().matchAll(/FIN_STORAGE_READS=(\d+)/g)].map((match) => Number(match[1]));
    const observation = { parked, finCompleted, endBeforeRelease, exit, readyBytes: Buffer.concat(bytes).length,
      reads, messages, barrierCount: barrierPaths.length, barrierReleased: barrierPaths.every((path) => !remaining.includes(path)), stderr: stderr() };
    console.log("FIN_CUSTODY_ORACLES", JSON.stringify({ entry: "cli", ...observation }));
    expect({ parked, finCompleted, endBeforeRelease, exit, readyBytes: observation.readyBytes,
      barrierCount: observation.barrierCount, barrierReleased: observation.barrierReleased }).toEqual({
      parked: true, finCompleted: true, endBeforeRelease: true, exit: { code: EXIT_STARTUP_REFUSED, signal: null },
      readyBytes: 0, barrierCount: 1, barrierReleased: true,
    });
    expect(messages.find((message) => message.kind === "end")).toMatchObject({ readableEnded: true, readable: false });
    expect(reads).toHaveLength(1);
    expect(reads[0]).toBeGreaterThan(0);
    expect(stderr()).toContain("state_GATE_WIRED: startup refused");
  }, 30_000);

  it("exits cleanly on a real SIGTERM after ready in the CLI subprocess", async () => {
    const fixture = await seededFortress("subprocess-signal");
    const child = spawnBridgeCli(fixture.env);
    const relay = child.stdio[3] as Duplex;
    try {
      expect(await readNodeFrame(relay)).toEqual({ type: "ready" });
      if (child.pid === undefined) throw new Error("child pid was unavailable");
      process.kill(child.pid, "SIGTERM");
      await expect(childExit(child)).resolves.toMatchObject({ code: EXIT_CLEAN, signal: null });
    } finally {
      killChild(child);
    }
  }, 30_000);

  it("refuses a signal while the trap list is parked before ready and releases the barrier", async () => {
    const fixture = await seededFortress("signal-before-ready");
    const pair = await socketPair();
    const shellFd = socketFd(pair.shell);
    let stderrText = "";
    const parkedStorage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const beforeBarrierSockets = await __testListMasterBarrierReaderSockets(parkedStorage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const exit = hermesBridgeMain({
      argv: ["run", "--relay-fd", String(shellFd)],
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    let unrelatedCustody: Awaited<ReturnType<typeof establishMaster>> | undefined;
    try {
      await waitUntil(() => parkedStorage.trapListParked);
      // Another worker can acquire a same-uid lock while this startup is parked.
      const unrelated = await seededFortress("unrelated-reader");
      unrelatedCustody = await establishMaster({
        storage: new FilesystemStorage(join(unrelated.fortressDir, "state")), passphrase: PASS,
      });
      const barrierSocketPath = await fortressCustodySocket(parkedStorage, beforeBarrierSockets);
      await expect(lstat(barrierSocketPath!)).resolves.toBeTruthy();
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(relayPublicFrame("c1", {
        type: "hello",
        request_id: "hello-before-ready",
        protocol_version: "2026-10-12",
        client_name: "hermes",
      }));
      process.emit("SIGTERM");
      parkedStorage.release();
      await expect(exit).resolves.toBe(EXIT_STARTUP_REFUSED);
      await expect(lstat(barrierSocketPath!)).rejects.toMatchObject({ code: "ENOENT" });
      expect(stderrText.trim().split("\n")).toEqual([
        "hermes-memory-bridge state_CHILD_READY: startup refused",
      ]);
      await expectNoRelayBytes(pair.relay);
    } finally {
      await unrelatedCustody?.masterWriteBarrier?.release();
      unrelatedCustody?.masterKey.fill(0);
      parkedStorage.release();
      pair.close();
    }
  });

  it("writes one startup line for a crash while the trap list is parked before ready", async () => {
    const fixture = await seededFortress("crash-before-ready");
    const pair = await socketPair();
    const shellFd = socketFd(pair.shell);
    let stderrText = "";
    const parkedStorage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const beforeBarrierSockets = await __testListMasterBarrierReaderSockets(parkedStorage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const exit = hermesBridgeMain({
      argv: ["run", "--relay-fd", String(shellFd)],
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      await waitUntil(() => parkedStorage.trapListParked);
      const barrierSocketPath = await fortressCustodySocket(parkedStorage, beforeBarrierSockets);
      await expect(lstat(barrierSocketPath)).resolves.toBeTruthy();
      process.emit("uncaughtException", new Error("startup crash"));
      parkedStorage.release();
      await expect(exit).resolves.toBe(EXIT_STARTUP_REFUSED);
      await expect(lstat(barrierSocketPath)).rejects.toMatchObject({ code: "ENOENT" });
      expect(stderrText.trim().split("\n")).toEqual([
        "hermes-memory-bridge state_CHILD_READY: startup refused",
      ]);
      await expectNoRelayBytes(pair.relay);
    } finally {
      parkedStorage.release();
      pair.close();
    }
  });

  it("commits an approved passage and reads it back over the process socket", async () => {
    const fixture = await seededFortress("full-call");
    const pair = await socketPair();
    let stderrText = "";
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(relayPublicFrame("c1", {
        type: "hello",
        request_id: "hello-1",
        protocol_version: "2026-10-12",
        client_name: "hermes",
      }));
      expect(await readPublicResponse(pair.relay, "hello-1")).toMatchObject({ type: "result" });

      const passageText = "the process shell passage";
      pair.relay.write(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-1",
        name: "memory_insert",
        arguments: { text: passageText, taint: "user_content", tags: ["hermes"], passage_id: "passage-full" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      shell.decisions.approve("hermes-entry-1", hermesBridgePassageTextDigest(passageText));
      const probe = await readNodeFrame(pair.relay);
      expect(probe).toMatchObject({ type: "probe", connection_id: "c1" });
      pair.relay.write(privateFrame({ type: "probe_reply", connection_id: "c1", nonce: probe.nonce }));
      expect(await readPublicResponse(pair.relay, "insert-1")).toMatchObject({ type: "result" });

      pair.relay.write(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "get-1",
        name: "memory_get",
        arguments: { passage_id: "passage-full" },
      }));
      const get = await readPublicResponse(pair.relay, "get-1");
      const content = (get.payload as { content?: Array<{ text: string }> }).content;
      const body = JSON.parse(content?.[0]?.text ?? "{}") as { passage?: { text?: string; provenance_status?: string } };
      expect(body.passage?.text).toBe(passageText);
      // Verify the encrypted companion directly: the public result intentionally projects fewer fields.
      const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
      const custody = await establishMaster({ storage, passphrase: PASS });
      try {
        const identities = new IdentityManager(storage, custody.masterKey);
        await identities.load();
        const corpus = new SdwDocumentCorpusStore({ storage, masterKey: custody.masterKey, fortressId: shell.report.fortressId });
        const persisted = await corpus.getProvenanceRaw(`mem.${shell.report.adapterOwnerRef}.passage-full`);
        expect(persisted).not.toBeNull();
        const verified = verifyMemoryProvenanceCompanion(persisted!.record.companion, {
          size: 1, resolve: createPrimaryMemoryProvenancePublicKeyResolver(identities),
        }, {
          origin: {
            origin_fortress_id: shell.report.fortressId, owner_ref: shell.report.adapterOwnerRef,
            passage_id: "passage-full", content_hash: passageContentHash(passageText), chunk_count: 1,
          },
          destination: {
            destination_fortress_id: shell.report.fortressId,
            destination_owner_ref: shell.report.adapterOwnerRef, passage_id: "passage-full",
          },
        });
        expect(verified).toMatchObject({ ok: true });
        expect(persisted!.record.companion.origin.body).toMatchObject({
          // Owner scope does not assert who authored the supplied text.
          author_agent_id: "unknown_local", ingress_channel: "memory_insert", source_class: "user_content",
        });
      } finally {
        await custody.masterWriteBarrier?.release();
        custody.masterKey.fill(0);
      }

      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    } finally {
      pair.close();
    }
  });

  it("handles bytes queued before the relay socket factory is called", async () => {
    const fixture = await seededFortress("prefactory-bytes");
    await commitPassage(fixture, "passage-prefactory", "queued before factory");
    const pair = await socketPair();
    pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
    pair.relay.write(relayPublicFrame("c1", {
      type: "tools_call",
      request_id: "get-prefactory",
      name: "memory_get",
      arguments: { passage_id: "passage-prefactory" },
    }));

    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      const get = await readPublicResponse(pair.relay, "get-prefactory");
      const content = (get.payload as { content?: Array<{ text: string }> }).content;
      const body = JSON.parse(content?.[0]?.text ?? "{}") as { passage?: { text?: string } };
      expect(body.passage?.text).toBe("queued before factory");
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    } finally {
      pair.close();
    }
  });

  it("refuses memory storage in bridge mode before ready", async () => {
    const fixture = await seededFortress("memory-storage");
    const pair = await socketPair();

    await expect(runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => new MemoryStorage(),
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({ state: "state_CONFIG_CHECKED" });
    expect(pair.relay.readableLength).toBe(0);
    pair.close();
  });

  it.each([
    ["persisted trap spec", "state_CONFIG_CHECKED", async (fixture: Awaited<ReturnType<typeof seededFortress>>) => ({
      env: fixture.env,
      storageFor: () => new TrapListingStorage(join(fixture.fortressDir, "state"), "present"),
    })],
    ["unreadable trap store", "state_CONFIG_CHECKED", async (fixture: Awaited<ReturnType<typeof seededFortress>>) => ({
      env: fixture.env,
      storageFor: () => new TrapListingStorage(join(fixture.fortressDir, "state"), "error"),
    })],
    ["content pin mismatch", "state_FORTRESS_UNLOCKED", async (fixture: Awaited<ReturnType<typeof seededFortress>>) => ({
      env: { ...fixture.env, HERMES_MEMORY_BRIDGE_IDENTITY: "0".repeat(64) },
      storageFor: (fortressDir: string) => new FilesystemStorage(join(fortressDir, "state")),
    })],
  ])("refuses %s before ready with the startup state", async (_name, state, build) => {
    const fixture = await seededFortress(`refuse-${_name.replaceAll(" ", "-")}`);
    const pair = await socketPair();
    const options = await build(fixture);

    await expectStartupRefusal({
      ...options,
      relaySocketFactory: () => pair.shell,
      uid: process.getuid?.() ?? 0,
    }, state);
    await expectNoRelayBytes(pair.relay);
    pair.close();
  });

  it("refuses a symlinked fortress path component before storage opens", async () => {
    const home = await tempHome("symlink");
    const target = await mkdtemp(join(tmpdir(), "hermes-symlink-target-"));
    cleanups.push(() => rm(target, { recursive: true, force: true }));
    const fortressId = `fortress-symlink-${fortressCounter++}`;
    const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
    await mkdirChain([
      join(home, "Library"),
      join(home, "Library", "Application Support"),
      join(home, "Library", "Application Support", "Sanctuary"),
      join(home, "Library", "Application Support", "Sanctuary", "Fortresses"),
    ]);
    cleanups.push(() => rm(fortressDir, { recursive: true, force: true }));
    await symlink(target, fortressDir);

    const pair = await socketPair();
    await expectStartupRefusal({
      env: allowlistedEnv(home, "1".repeat(64), "agent-symlink", fortressId),
      relaySocketFactory: () => pair.shell,
      storageFor: () => { throw new Error("storage must not be opened"); },
      uid: process.getuid?.() ?? 0,
    }, "state_FORTRESS_UNLOCKED");
    await expectNoRelayBytes(pair.relay);
    pair.close();
  });

  it("prints the startup state without the raw storage error message", async () => {
    const fixture = await seededFortress("storage-label");
    const pair = await socketPair();
    const shellFd = socketFd(pair.shell);
    const marker = "storage-marker-should-stay-private";
    let stderrText = "";

    try {
      const exit = await hermesBridgeMain({
        argv: ["run", "--relay-fd", String(shellFd)],
        env: fixture.env,
        relaySocketFactory: () => pair.shell,
        storageFor: () => { throw new Error(marker); },
        stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
        uid: process.getuid?.() ?? 0,
      });

      expect(exit).toBe(EXIT_STARTUP_REFUSED);
      expect(stderrText.trim()).toBe("hermes-memory-bridge state_FORTRESS_UNLOCKED: startup refused");
      expect(stderrText).not.toContain(marker);
      await expectNoRelayBytes(pair.relay);
    } finally {
      pair.close();
    }
  });

  it.each([
    ["equals", (home: string, fortressDir: string) => symlink(fortressDir, join(home, ".sanctuary"))],
    ["contains", (home: string) => symlink(join(home, "Library", "Application Support", "Sanctuary", "Fortresses"), join(home, ".sanctuary"))],
  ])("refuses when the default fortress realpath %s the dedicated fortress", async (_name, linkDefault) => {
    const home = await mkdtemp(join(tmpdir(), "hermes-default-containment-"));
    cleanups.push(() => rm(home, { recursive: true, force: true }));
    const fortressId = `fortress-contained-${fortressCounter++}`;
    const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
    await mkdirChain([
      join(home, "Library"),
      join(home, "Library", "Application Support"),
      join(home, "Library", "Application Support", "Sanctuary"),
      join(home, "Library", "Application Support", "Sanctuary", "Fortresses"),
      fortressDir,
    ]);
    await linkDefault(home, fortressDir);

    await expect(resolveHermesBridgeFortress({
      env: allowlistedEnv(home, "3".repeat(64), "agent-contained", fortressId),
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({ state: "state_FORTRESS_UNLOCKED" });
  });

  it.each(["pending", "unreadable"] as const)("refuses %s exit-import recovery before opening the relay", async (kind) => {
    const fixture = await seededFortress(`exit-${kind}`);
    const path = join(fixture.fortressDir, "state");
    const storage = new FilesystemStorage(path);
    const journal = new TextEncoder().encode("interrupted fixture journal");
    await storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "pending", journal);
    class UnreadableJournalStorage extends FilesystemStorage {
      override async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
        if (namespace === EXIT_IMPORT_JOURNAL_NAMESPACE) throw new Error("unreadable fixture journal");
        return super.list(namespace, prefix);
      }
    }
    let relayOpened = false;
    await expectStartupRefusal({
      env: fixture.env,
      storageFor: () => kind === "unreadable" ? new UnreadableJournalStorage(path) : storage,
      relaySocketFactory: () => { relayOpened = true; return new ThrowingReadyDuplex(); },
      uid: process.getuid?.() ?? 0,
    }, "state_CONFIG_CHECKED");
    expect(relayOpened).toBe(false);
    expect(await storage.read(EXIT_IMPORT_JOURNAL_NAMESPACE, "pending")).toEqual(journal);
    expect(activeServerSocketPaths()).toEqual([]);
  });

  it("refuses a leftover corpus lock and leaves it in place", async () => {
    const fixture = await seededFortress("leftover-lock");
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const lockDir = storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE);
    await mkdir(lockDir, { recursive: true, mode: 0o700 });
    const lockPath = join(lockDir, sdwMemoryCorpusBatchLockFile());
    await writeFile(lockPath, "held", { mode: 0o600 });

    await expect(runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => { throw new Error("must not construct socket"); },
      storageFor: () => storage,
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({ state: "state_CONFIG_CHECKED" });
    await expect(lstat(lockPath)).resolves.toBeTruthy();
  });

  it("treats EOF with a partial private frame as fatal", async () => {
    const fixture = await seededFortress("truncated");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.relay.write(Buffer.from([0, 0, 0, 1]));
    pair.relay.end();
    await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    pair.close();
  });

  it("treats a private frame over the cap as fatal", async () => {
    const fixture = await seededFortress("frame-over-cap");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    const frame = Buffer.alloc(4 + MAX_PRIVATE_FRAME_BYTES + 1);
    frame.writeUInt32BE(MAX_PRIVATE_FRAME_BYTES + 1, 0);
    pair.relay.write(frame);
    await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    pair.close();
  });

  it("keeps a clean stop when the peer closes before the final writer flush", async () => {
    const fixture = await seededFortress("clean-peer-close");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.relay.write(privateFrame({ type: "relay_shutdown" }));
    pair.relay.destroy();
    await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    pair.close();
  });

  it("reports a peer close before a clean cause without an uncaught exception", async () => {
    const fixture = await seededFortress("fatal-peer-close");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.relay.destroy();
    await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
    pair.close();
  });

  it("refuses when the relay socket factory throws before custody", async () => {
    const fixture = await seededFortress("factory-throw");
    await expectStartupRefusal({
      env: fixture.env,
      relaySocketFactory: () => { throw new Error("relay socket construction failed"); },
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    }, "state_CONFIG_CHECKED");
    expect(activeServerSocketPaths()).toEqual([]);
  });

  it("refuses startup when the ready write throws synchronously", async () => {
    const fixture = await seededFortress("ready-write-throw");
    const parkedStorage = new SlowTrapListStorage(join(fixture.fortressDir, "state"));
    const beforeBarrierSockets = await __testListMasterBarrierReaderSockets(parkedStorage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    const startup = runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => new ThrowingReadyDuplex(),
      storageFor: () => parkedStorage,
      uid: process.getuid?.() ?? 0,
    });
    try {
      await waitUntil(() => parkedStorage.trapListParked);
      const barrierSocketPath = await fortressCustodySocket(parkedStorage, beforeBarrierSockets);
      await expect(lstat(barrierSocketPath)).resolves.toBeTruthy();
      parkedStorage.release();
      await expect(startup).rejects.toMatchObject({ state: "state_CHILD_READY", message: "ready write refused" });
      await expect(lstat(barrierSocketPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      parkedStorage.release();
    }
  });

  it("refuses a peer that closes during startup and releases custody", async () => {
    const fixture = await seededFortress("prefactory-peer-destroyed");
    const pair = await socketPair();
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const before = new Set(await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME));
    pair.relay.destroy();
    try {
      await expect(runHermesBridgeProcess({
        env: fixture.env,
        relaySocketFactory: () => pair.shell,
        storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
        uid: process.getuid?.() ?? 0,
      })).rejects.toMatchObject({ name: "HermesBridgeStartupRefusal" });
      const after = await __testListMasterBarrierReaderSockets(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
      expect(after.filter((path) => !before.has(path))).toEqual([]);
    } finally { pair.close(); }
  });

  it("refuses a default fortress fallback when the bridge fortress id is absent", async () => {
    const home = await tempHome("no-fallback");
    const defaultFortress = join(home, ".sanctuary");
    await mkdir(defaultFortress, { recursive: true, mode: 0o700 });
    await chmod(defaultFortress, 0o700);
    const env = allowlistedEnv(home, "2".repeat(64), "agent-no-fallback", "fortress-unused");
    delete env.HERMES_MEMORY_FORTRESS_ID;
    const pair = await socketPair();
    await expect(runHermesBridgeProcess({
      env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => { throw new Error("default fortress must not open"); },
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({ state: "state_ENV_REPLACED" });
    await expectNoRelayBytes(pair.relay);
    pair.close();
  });

  it("refuses a default fortress fallback inside path resolution", async () => {
    const home = await tempHome("resolver-no-fallback");
    const defaultFortress = join(home, ".sanctuary");
    await mkdir(defaultFortress, { recursive: true, mode: 0o700 });
    await chmod(defaultFortress, 0o700);
    const env = allowlistedEnv(home, "2".repeat(64), "agent-no-fallback-resolver", "fortress-unused");
    delete env.HERMES_MEMORY_FORTRESS_ID;

    await expect(resolveHermesBridgeFortress({
      env,
      uid: process.getuid?.() ?? 0,
    })).rejects.toMatchObject({ state: "state_FORTRESS_UNLOCKED" });
  });

  it("waits for a post-allow document write before a signal stop resolves cleanly", async () => {
    const fixture = await seededFortress("signal-drain");
    const pair = await socketPair();
    let stderrText = "";
    const parkedStorage = new ParkingDocumentWriteStorage(join(fixture.fortressDir, "state"));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      const passageText = "drain waits for this document";
      pair.relay.write(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-drain",
        name: "memory_insert",
        arguments: { text: passageText, taint: "user_content", passage_id: "passage-drain" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      shell.decisions.approve("hermes-entry-1", hermesBridgePassageTextDigest(passageText));
      const probe = await readNodeFrame(pair.relay);
      pair.relay.write(privateFrame({ type: "probe_reply", connection_id: "c1", nonce: probe.nonce }));
      await waitUntil(() => parkedStorage.parkedSettled);

      shell.signalStop("SIGTERM");
      expect(await shortOutcome(shell.exited)).toBe("timeout");
      parkedStorage.release();
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
      expect(await documentCount(parkedStorage, fixture.env.HERMES_MEMORY_AGENT_ID!)).toBe(1);
    } finally {
      parkedStorage.release();
      pair.close();
    }
  });

  it("reports a crash during drain as fatal even after a clean stop began", async () => {
    const fixture = await seededFortress("fatal-drain");
    const pair = await socketPair();
    let stderrText = "";
    const parkedStorage = new ParkingDocumentWriteStorage(join(fixture.fortressDir, "state"));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      const passageText = "fatal during drain";
      pair.relay.write(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-fatal-drain",
        name: "memory_insert",
        arguments: { text: passageText, taint: "user_content", passage_id: "passage-fatal-drain" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      shell.decisions.approve("hermes-entry-1", hermesBridgePassageTextDigest(passageText));
      const probe = await readNodeFrame(pair.relay);
      pair.relay.write(privateFrame({ type: "probe_reply", connection_id: "c1", nonce: probe.nonce }));
      await waitUntil(() => parkedStorage.parkedSettled);

      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await new Promise((resolve) => setImmediate(resolve));
      shell.crash(new Error("crash during drain"));
      parkedStorage.release();
      await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    } finally {
      parkedStorage.release();
      pair.close();
    }
  });

  it("routes a socket write error after ready to a fatal exit", async () => {
    const fixture = await seededFortress("write-error");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.shell.destroy(Object.assign(new Error("simulated EPIPE"), { code: "EPIPE" }));
    await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    pair.close();
  });

  it("routes a write callback error to a fatal exit", async () => {
    const fixture = await seededFortress("write-callback-error");
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => new CallbackErrorDuplex(),
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    await expectExitWithinMs(shell.exited, EXIT_FATAL_BRIDGE, DRAIN_TAIL_MS + Math.floor(DRAIN_TAIL_MS / 2));
  });

  it("classifies a core lifecycle fatal as a fatal process exit", async () => {
    const fixture = await seededFortress("core-lifecycle-fatal");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    } finally { pair.close(); }
  });

  it("preserves a clean drain when audit flush rejects", async () => {
    const fixture = await seededFortress("audit-flush-reject");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    const flush = vi.spyOn(AuditLog.prototype, "flush").mockRejectedValue(new Error("fixture flush rejection"));
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
      expect(flush).toHaveBeenCalledOnce();
    } finally { flush.mockRestore(); pair.close(); }
  });

  it("classifies a ledger invariant failure during clean drain as fatal", async () => {
    const fixture = await seededFortress("ledger-drain-fatal");
    const pair = await socketPair();
    let stderrText = "";
    const shell = await runHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    const originalStop = HermesApprovalLedger.prototype.stop;
    const stop = vi.spyOn(HermesApprovalLedger.prototype, "stop").mockImplementation(function (this: HermesApprovalLedger) {
      const result = originalStop.call(this);
      return { ...result, fatal: "ledger_order" as const };
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(relayPublicFrame("c1", { type: "tools_call", request_id: "ledger-fatal", name: "memory_insert", arguments: { text: "pending insert", taint: "user_content", passage_id: "ledger-fatal" } }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expectExitWithin(shell.exited, EXIT_FATAL_BRIDGE);
      expect(stop).toHaveBeenCalled();
    } finally { stop.mockRestore(); pair.close(); }
  });

  it("classifies an unmatched core waiter reply as fatal", async () => {
    const fixture = await seededFortress("waiter-fatal");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env, relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(privateFrame({ type: "probe_reply", connection_id: "c1", nonce: "a".repeat(32) }));
      await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    } finally { pair.close(); }
  });

  it("routes parser refusal to a fatal exit", async () => {
    const fixture = await seededFortress("parser-refusal");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.relay.write(privateFrame({ type: "unknown_private" }));
    await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    pair.close();
  });

  it("exits within the shared tail when the audit tail and writer drain are both slow", async () => {
    const fixture = await seededFortress("shared-exit-deadline");
    const relay = new NeverDrainingDuplex();
    let stderrText = "";
    const parkedStorage = new ParkingAuditStorage(join(fixture.fortressDir, "state"));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => relay,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      relay.inject(privateFrame({ type: "accepted", connection_id: "c1" }));
      relay.inject(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-audit-tail",
        name: "memory_insert",
        arguments: { text: "audit tail deadline", taint: "user_content", passage_id: "passage-audit-tail" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      const sharedTailBoundMs = DRAIN_TAIL_MS + Math.floor(DRAIN_TAIL_MS / 2);
      const exitWithinSharedTail = expectExitWithinMs(shell.exited, EXIT_CLEAN, sharedTailBoundMs);
      relay.inject(privateFrame({ type: "relay_shutdown" }));
      await exitWithinSharedTail;
      expect(parkedStorage.auditWriteParked).toBe(true);
    } finally {
      await parkedStorage.releaseAndDrain();
    }
  });

  it("refuses audit records still queued at exit without touching the released fortress", async () => {
    const fixture = await seededFortress("shared-exit-queued-audit");
    const relay = new NeverDrainingDuplex();
    let stderrText = "";
    const parkedStorage = new ParkingAuditStorage(join(fixture.fortressDir, "state"));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => relay,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      relay.inject(privateFrame({ type: "accepted", connection_id: "c1" }));
      relay.inject(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-queued-audit",
        name: "memory_insert",
        arguments: { text: "queued audit at exit", taint: "user_content", passage_id: "passage-queued-audit" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      const sharedTailBoundMs = DRAIN_TAIL_MS + Math.floor(DRAIN_TAIL_MS / 2);
      const exitWithinSharedTail = expectExitWithinMs(shell.exited, EXIT_CLEAN, sharedTailBoundMs);
      relay.inject(privateFrame({ type: "relay_shutdown" }));
      await exitWithinSharedTail;
      parkedStorage.exitObserved = true;
      expect(parkedStorage.auditWriteParked).toBe(true);
      // The shutdown appended one record behind the parked one. It is refused at close, before exit,
      // even though the record ahead of it is still parked and may never settle.
      expect(stderrText).toContain("hermes-memory-bridge audit: 1 record(s) unconfirmed at exit\n");
      expect(stderrText).toContain("hermes-memory-bridge audit: refused terminal record at exit\n");
      await parkedStorage.releaseAndDrain();
      expect(parkedStorage.backendWritesAfterExit).toBe(0);
    } finally {
      await parkedStorage.releaseAndDrain();
    }
  });

  it("reports a shutdown checkpoint that missed the drain tail and starts no audit write after exit", async () => {
    const fixture = await seededFortress("shared-exit-slow-checkpoint");
    const relay = new NeverDrainingDuplex();
    let stderrText = "";
    const parkedStorage = new ParkingAuditStorage(join(fixture.fortressDir, "state"),
      (namespace, key) => namespace === "_audit_checkpoints" && /-\d{20}$/.test(key));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => relay,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      relay.inject(privateFrame({ type: "accepted", connection_id: "c1" }));
      relay.inject(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-slow-checkpoint",
        name: "memory_insert",
        arguments: { text: "slow checkpoint at exit", taint: "user_content", passage_id: "passage-slow-checkpoint" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      const sharedTailBoundMs = DRAIN_TAIL_MS + Math.floor(DRAIN_TAIL_MS / 2);
      const exitWithinSharedTail = expectExitWithinMs(shell.exited, EXIT_CLEAN, sharedTailBoundMs);
      relay.inject(privateFrame({ type: "relay_shutdown" }));
      await exitWithinSharedTail;
      parkedStorage.exitObserved = true;
      // The appends drained; the checkpoint write parked, so flush() missed its deadline.
      expect(parkedStorage.auditWriteParked).toBe(true);
      expect(stderrText).toContain("hermes-memory-bridge audit: shutdown checkpoint unconfirmed at exit\n");
      expect(stderrText).not.toContain("record(s) unconfirmed at exit");
      await parkedStorage.releaseAndDrain();
      expect(parkedStorage.backendWritesAfterExit).toBe(0);
    } finally {
      await parkedStorage.releaseAndDrain();
    }
  });

  it("exits within the stop budget when the barrier release rejects", async () => {
    const fixture = await seededFortress("barrier-release-failure");
    const pair = await socketPair();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      const barrierSocketPath = shell.report.custodyHandlesConstructed[0]?.socketPath;
      expect(barrierSocketPath).toEqual(expect.any(String));
      await unlink(barrierSocketPath!);
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await expectExitWithin(shell.exited, EXIT_FATAL_BRIDGE);
    } finally {
      pair.close();
    }
  });

  it("stops at the pending write cap without queuing bytes beyond the cap", async () => {
    const fixture = await seededFortress("pending-cap");
    const relay = new NeverDrainingDuplex();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => relay,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    relay.inject(privateFrame({ type: "accepted", connection_id: "c1" }));
    for (let index = 0; index < 30_000; index += 1) {
      relay.inject(relayPublicFrame("c1", {
        type: "hello",
        request_id: `hello-${index}`,
        protocol_version: "2026-10-12",
        client_name: "hermes",
      }));
      if (index % 250 === 249) {
        await new Promise((resolve) => setTimeout(resolve, 0));
        if (await shortOutcome(shell.exited, 1) !== "timeout") break;
      }
    }

    await expect(shell.exited).resolves.toBe(EXIT_FATAL_BRIDGE);
    expect(relay.acceptedWriteBytes).toBeLessThanOrEqual(MAX_PENDING_WRITE_BYTES);
  }, 30_000);

  it("keeps a legal memory_get burst under the pending write cap", async () => {
    const fixture = await seededFortress("legal-get-burst");
    const passageText = "g".repeat(Math.floor((MAX_PRIVATE_FRAME_BYTES * 3) / 5));
    await commitPassage(fixture, "passage-legal-burst", passageText);
    const relay = new NeverDrainingDuplex();
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => relay,
      storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
      uid: process.getuid?.() ?? 0,
    });
    const legalBurstCount = HERMES_MAX_CALL_RECORDS + HERMES_MAX_PUBLIC_CONNECTIONS;
    relay.inject(privateFrame({ type: "accepted", connection_id: "c1" }));
    await waitUntil(() => relay.acceptedWriteBytes > 0);
    for (let index = 0; index < legalBurstCount; index += 1) {
      const before = relay.acceptedWriteBytes;
      relay.inject(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: `get-burst-${index}`,
        name: "memory_get",
        arguments: { passage_id: "passage-legal-burst" },
      }));
      await waitUntil(() => relay.acceptedWriteBytes > before);
      expect(await shortOutcome(shell.exited, 1)).toBe("timeout");
    }
    expect(relay.acceptedWriteBytes).toBeGreaterThan(Math.floor(MAX_PENDING_WRITE_BYTES / 2));
    expect(relay.acceptedWriteBytes).toBeLessThanOrEqual(MAX_PENDING_WRITE_BYTES);
    relay.inject(privateFrame({ type: "relay_shutdown" }));
    await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
  }, 30_000);

  it("awaits a pending terminal audit append after drain", async () => {
    const fixture = await seededFortress("audit-drain");
    const pair = await socketPair();
    let stderrText = "";
    const parkedStorage = new ParkingAuditStorage(join(fixture.fortressDir, "state"));
    const shell = await runHermesBridgeProcess({
      env: fixture.env,
      relaySocketFactory: () => pair.shell,
      storageFor: () => parkedStorage,
      stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
      uid: process.getuid?.() ?? 0,
    });
    try {
      expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
      pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
      pair.relay.write(relayPublicFrame("c1", {
        type: "tools_call",
        request_id: "insert-audit-drain",
        name: "memory_insert",
        arguments: { text: "audit pending at drain", taint: "user_content", passage_id: "passage-audit-drain" },
      }));
      await waitUntil(() => stderrText.includes("owner approval is deferred"));
      pair.relay.write(privateFrame({ type: "relay_shutdown" }));
      await waitUntil(() => parkedStorage.auditWriteParked);
      expect(await shortOutcome(shell.exited)).toBe("timeout");
      parkedStorage.release();
      await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
      const custody = await establishMaster({ storage: parkedStorage, passphrase: PASS });
      try {
        const audit = new AuditLog(parkedStorage, custody.masterKey);
        const entries = await audit.query({ operation_type: "hermes_memory_bridge", limit: 20 });
        expect(entries.entries.some((entry) => entry.details?.kind === "terminal")).toBe(true);
      } finally {
        await custody.masterWriteBarrier?.release();
        custody.masterKey.fill(0);
      }
    } finally {
      parkedStorage.release();
      pair.close();
    }
  });
});

async function seededFortress(label: string): Promise<{
  readonly env: NodeJS.ProcessEnv;
  readonly fortressDir: string;
}> {
  const home = await tempHome(label);
  const unique = `${label}-${process.pid}-${fortressCounter++}`.replace(/[^a-z0-9-]/g, "-").slice(0, 50);
  const fortressId = `fortress-${unique}`;
  const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  cleanups.push(() => rm(fortressDir, { recursive: true, force: true }));
  await mkdirChain([
    join(home, "Library"),
    join(home, "Library", "Application Support"),
    join(home, "Library", "Application Support", "Sanctuary"),
    join(home, "Library", "Application Support", "Sanctuary", "Fortresses"),
    fortressDir,
    join(fortressDir, "state"),
  ]);
  const storage = new FilesystemStorage(join(fortressDir, "state"));
  await persistUserProvidedPassphrase(PASS, {
    home,
    storagePath: fortressDir,
    platformOverride: "freebsd",
  });
  const custody = await establishMaster({
    storage,
    passphrase: PASS,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  const identityManager = new IdentityManager(storage, custody.masterKey);
  await identityManager.load();
  const { storedIdentity } = createIdentity(
    `hermes-${label}`,
    derivePurposeKey(custody.masterKey, "identity-encryption"),
    "passphrase",
  );
  await identityManager.save(storedIdentity);
  const bridgeIdentity = memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key));
  await custody.masterWriteBarrier?.release();
  custody.masterKey.fill(0);
  return {
    fortressDir,
    env: allowlistedEnv(home, bridgeIdentity, `agent-${label}`, fortressId),
  };
}

async function tempHome(label: string): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), `hermes-home-${label}-`));
  await chmod(home, 0o700);
  cleanups.push(() => rm(home, { recursive: true, force: true }));
  return home;
}

async function seedRuntimeEffectConfig(fortressDir: string): Promise<void> {
  const config = defaultConfig();
  config.storage_path = fortressDir;
  config.dashboard.enabled = true;
  config.verascore.auto_publish_to_verascore = true;
  await writeFile(join(fortressDir, "sanctuary.json"), JSON.stringify(config), { mode: 0o600 });
  const distressDir = join(fortressDir, "policy", "egress");
  await mkdir(distressDir, { recursive: true, mode: 0o700 });
  await chmod(distressDir, 0o700);
  await writeFile(join(distressDir, "distress.json"), JSON.stringify({
    webhook_url: "http://127.0.0.1:8741/distress",
    webhook_secret: "local-secret-for-process-shell",
  }), { mode: 0o600 });
}

async function commitPassage(
  fixture: Awaited<ReturnType<typeof seededFortress>>,
  passageId: string,
  passageText: string,
): Promise<void> {
  const pair = await socketPair();
  let stderrText = "";
  const shell = await runHermesBridgeProcess({
    env: fixture.env,
    relaySocketFactory: () => pair.shell,
    storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
    stderr: { write: (chunk: string | Uint8Array) => { stderrText += String(chunk); return true; } },
    uid: process.getuid?.() ?? 0,
  });
  try {
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
    pair.relay.write(relayPublicFrame("c1", {
      type: "tools_call",
      request_id: "insert-seed",
      name: "memory_insert",
      arguments: { text: passageText, taint: "user_content", passage_id: passageId },
    }));
    await waitUntil(() => stderrText.includes("owner approval is deferred"));
    shell.decisions.approve("hermes-entry-1", hermesBridgePassageTextDigest(passageText));
    const probe = await readNodeFrame(pair.relay);
    pair.relay.write(privateFrame({ type: "probe_reply", connection_id: "c1", nonce: probe.nonce }));
    expect(await readPublicResponse(pair.relay, "insert-seed")).toMatchObject({ type: "result" });
    pair.relay.write(privateFrame({ type: "relay_shutdown" }));
    await expect(shell.exited).resolves.toBe(EXIT_CLEAN);
  } finally {
    pair.close();
  }
}

// Test-only capture retains real core approval-path coverage without granting
// that authority through the production process handle.
async function runHermesBridgeProcess(options: HermesBridgeProcessOptions) {
  let capturedCore: HermesBridgeCore | undefined;
  const original = HermesBridgeCore.prototype.onDrained;
  const capture = vi.spyOn(HermesBridgeCore.prototype, "onDrained").mockImplementation(function (this: HermesBridgeCore, listener) {
    capturedCore = this;
    return original.call(this, listener);
  });
  try {
    const shell = await runProductionHermesBridgeProcess(options);
    const core = capturedCore as HermesBridgeCore | undefined;
    if (core === undefined) throw new Error("test failed to capture the composed bridge core");
    return { ...shell, decisions: {
      approve: (entryId: string, textSha256: string) => core.ownerApprove(entryId, textSha256),
      deny: (entryId: string) => core.ownerDeny(entryId),
    } };
  } finally { capture.mockRestore(); }
}

function allowlistedEnv(home: string, bridgeIdentity: string, agentId: string, fortressId: string): NodeJS.ProcessEnv {
  return {
    HOME: home,
    LANG: "C",
    TMPDIR: tmpdir(),
    HERMES_MEMORY_BRIDGE_IDENTITY: bridgeIdentity,
    HERMES_MEMORY_AGENT_ID: agentId,
    HERMES_MEMORY_FORTRESS_ID: fortressId,
  };
}

async function mkdirChain(paths: readonly string[]): Promise<void> {
  for (const path of paths) {
    await mkdir(path, { recursive: true, mode: 0o700 });
    await chmod(path, 0o700);
  }
}

function privateFrame(value: Record<string, unknown>): Buffer {
  return encodePrivateFrame(encoder.encode(JSON.stringify(value)));
}

function socketFd(socket: net.Socket): number {
  const fd = (socket as unknown as { _handle?: { fd?: unknown } })._handle?.fd;
  if (typeof fd !== "number" || fd < 3) throw new Error("socket fd was unavailable");
  return fd;
}

function relayPublicFrame(connectionId: string, value: Record<string, unknown>): Buffer {
  return privateFrame({
    type: "frame",
    connection_id: connectionId,
    frame_b64: Buffer.from(JSON.stringify(value), "utf8").toString("base64"),
  });
}

async function socketPair(allowHalfOpen = false): Promise<{ relay: net.Socket; shell: net.Socket; close(): void }> {
  const dir = await mkdtemp(join(tmpdir(), "hermes-shell-socket-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "pair.sock");
  const server = net.createServer({ allowHalfOpen });
  cleanups.push(async () => {
    await new Promise<void>((resolve) => {
      try {
        server.close(() => resolve());
      } catch {
        resolve();
      }
    });
  });
  const accepted = new Promise<net.Socket>((resolve) => {
    server.once("connection", resolve);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
    server.listen(path, resolve);
  });
  const relay = net.createConnection(path);
  const shell = await accepted;
  // A test may fail before its local finally; close peers before server cleanup.
  cleanups.push(async () => { relay.destroy(); shell.destroy(); });
  server.close();
  return {
    relay,
    shell,
    close() {
      relay.destroy();
      shell.destroy();
      try { server.close(); } catch { /* already closed */ }
    },
  };
}

async function onreadSocketPair(): Promise<{ relay: net.Socket; shell: net.Socket; close(): void }> {
  const dir = await mkdtemp(join(tmpdir(), "hermes-onread-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "pair.sock");
  const server = net.createServer({ allowHalfOpen: true });
  const accepted = new Promise<net.Socket>((resolve) => server.once("connection", resolve));
  // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
  let shell: net.Socket;
  shell = net.createConnection({ path, allowHalfOpen: true,
    onread: { buffer: Buffer.alloc(64 * 1024), callback: (length, bytes) => shell.push(Buffer.from(bytes.subarray(0, length))) },
  });
  const connected = new Promise<void>((resolve, reject) => { shell.once("connect", resolve); shell.once("error", reject); });
  const relay = await accepted;
  await connected;
  const close = () => { shell.destroy(); relay.destroy(); server.close(); };
  cleanups.push(async () => { close(); });
  return { shell, relay, close };
}

function boundedValue<T, F>(promise: Promise<T>, milliseconds: number, fallback: F): Promise<T | F> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(fallback), milliseconds);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function boundedObservation(
  predicate: () => boolean,
  emitter: { on(event: string, callback: () => void): unknown; off(event: string, callback: () => void): unknown },
  event: string,
  milliseconds = 1_000,
): Promise<boolean> {
  if (predicate()) return Promise.resolve(true);
  return new Promise((resolve) => {
    const finish = (observed: boolean) => { clearTimeout(timer); emitter.off(event, check); resolve(observed); };
    const check = () => { if (predicate()) finish(true); };
    const timer = setTimeout(() => finish(predicate()), milliseconds);
    emitter.on(event, check);
    check();
  });
}

function collectNodeFrames(socket: Duplex, output: Array<Record<string, unknown>>): () => string | undefined {
  const decoder = new PrivateFrameDecoder();
  let error: string | undefined;
  socket.on("data", (chunk: Buffer) => {
    decoder.push(chunk);
    for (;;) {
      const next = decoder.next();
      if (next.kind === "need_more") return;
      if (next.kind === "fatal") { error = String(next.error); return; }
      output.push(JSON.parse(Buffer.from(next.body).toString("utf8")) as Record<string, unknown>);
    }
  });
  return () => error;
}

function activeServerSocketPaths(): string[] {
  const handles = (process as unknown as { _getActiveHandles?: () => unknown[] })._getActiveHandles?.() ?? [];
  return handles
    .filter((handle): handle is net.Server => handle instanceof net.Server)
    .map((server) => server.address())
    .filter((address): address is string => typeof address === "string")
    .sort();
}

async function fortressCustodySocket(storage: StorageBackend, before: readonly string[]): Promise<string> {
  // A parked trap read occurs after custody acquisition. Query only this fortress:
  // other workers may hold many sockets in the same uid-owned runtime directory.
  const candidates = await __testListMasterBarrierReaderSockets(
    storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
  );
  // Stale sockets can share a recycled inode prefix. Exclude the exact fixture's
  // pre-start snapshot with a Set: unref'ed barrier listeners are not active handles.
  const prior = new Set(before);
  const sockets = candidates.filter((path) => !prior.has(path));
  expect(sockets).toHaveLength(1);
  return sockets[0]!;
}

function spawnBridgeCli(env: NodeJS.ProcessEnv): ChildProcess {
  return spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", fixtureChildScript(), "hermes-memory-bridge", "run", "--relay-fd", "3"], {
    cwd: process.cwd(),
    stdio: ["ignore", "ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      VITEST: process.env.VITEST ?? "true",
      HERMES_FIXTURE_ENV: JSON.stringify(env),
    },
  });
}

function spawnBridgeCliWithFd(env: NodeJS.ProcessEnv, fd: number): ChildProcess {
  return spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", fixtureChildScript(), "hermes-memory-bridge", "run", "--relay-fd", "3"], {
    cwd: process.cwd(),
    stdio: ["ignore", "ignore", "pipe", fd],
    env: {
      ...process.env,
      VITEST: process.env.VITEST ?? "true",
      HERMES_FIXTURE_ENV: JSON.stringify(env),
    },
  });
}

function fixtureChildScript(): string {
  return `
    const fixtureEnv = JSON.parse(process.env.HERMES_FIXTURE_ENV);
    const { pathToFileURL } = await import("node:url");
    const { installInMemoryKeychainStore } = await import(pathToFileURL(${JSON.stringify(keychainStoreEntry)}).href);
    installInMemoryKeychainStore();
    process.argv = [process.execPath, ${JSON.stringify(cliEntry)}, ...process.argv.slice(1)];
    process.env = { ...fixtureEnv };
    await import(pathToFileURL(${JSON.stringify(cliEntry)}).href);
  `;
}

async function tcpSocketPair(): Promise<{ relay: net.Socket; shell: net.Socket; close(): void }> {
  const server = net.createServer();
  cleanups.push(async () => {
    await new Promise<void>((resolve) => {
      try {
        server.close(() => resolve());
      } catch {
        resolve();
      }
    });
  });
  const accepted = new Promise<net.Socket>((resolve) => {
    server.once("connection", resolve);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP test server did not expose a port");
  const relay = net.createConnection(address.port, "127.0.0.1");
  const shell = await accepted;
  // A test may fail before its local finally; close peers before server cleanup.
  cleanups.push(async () => { relay.destroy(); shell.destroy(); });
  return {
    relay,
    shell,
    close() {
      relay.destroy();
      shell.destroy();
      server.close();
    },
  };
}

function childExit(child: ChildProcess): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

function collectChildStderr(child: ChildProcess): () => string {
  const chunks: Buffer[] = [];
  child.stderr?.on("data", (chunk: Buffer) => chunks.push(chunk));
  return () => Buffer.concat(chunks).toString("utf8");
}

function killChild(child: ChildProcess): void {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}

async function shortOutcome<T>(promise: Promise<T>, timeoutMs = 50): Promise<"resolved" | "rejected" | "timeout"> {
  return Promise.race([
    promise.then(() => "resolved" as const, () => "rejected" as const),
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
  ]);
}

async function expectExitWithin(promise: Promise<number>, code: number): Promise<void> {
  await expect(Promise.race([
    promise,
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), RELAY_CHILD_SIGTERM_GRACE_MS)),
  ])).resolves.toBe(code);
}

async function expectExitWithinMs(promise: Promise<number>, code: number, timeoutMs: number): Promise<void> {
  await expect(Promise.race([
    promise,
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
  ])).resolves.toBe(code);
}

async function documentCount(storage: StorageBackend, ownerRef: string): Promise<number> {
  return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${ownerRef}.`)).length;
}

function readNodeFrame(socket: Pick<Duplex, "on" | "off">): Promise<Record<string, unknown>> {
  const decoder = new PrivateFrameDecoder();
  return new Promise((resolve, reject) => {
    const onData = (chunk: Buffer) => {
      decoder.push(chunk);
      const next = decoder.next();
      if (next.kind === "need_more") return;
      socket.off("data", onData);
      if (next.kind === "fatal") reject(next.error);
      else resolve(JSON.parse(Buffer.from(next.body).toString("utf8")) as Record<string, unknown>);
    };
    socket.on("data", onData);
  });
}

async function expectStartupRefusal(
  options: HermesBridgeProcessOptions,
  state: string,
): Promise<void> {
  await expect(runHermesBridgeProcess(options)).rejects.toMatchObject({ state });
}

async function expectNoRelayBytes(socket: Pick<Duplex, "readableLength">): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 25));
  expect(socket.readableLength).toBe(0);
}

async function readPublicResponse(socket: net.Socket, requestId: string): Promise<Record<string, unknown>> {
  for (;;) {
    const frame = await readNodeFrame(socket);
    if (frame.type !== "response" || frame.request_id !== requestId) continue;
    return JSON.parse(Buffer.from(String(frame.result_b64), "base64").toString("utf8")) as Record<string, unknown>;
  }
}
