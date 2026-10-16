import { Buffer } from "node:buffer";
import { fstatSync } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import net from "node:net";
import { isAbsolute, join, relative, sep } from "node:path";
import { Duplex } from "node:stream";

import { IdentityManager } from "../cognitive/tools.js";
import { fromBase64url } from "../core/encoding.js";
import { establishMaster, type EstablishMasterResult } from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { TRAP_STORE_KEY_PREFIX, TRAP_STORE_NAMESPACE } from "../honeypot/trap-store.js";
import { AuditLog } from "../operational/audit-log.js";
import { KnownSignersStore } from "../reputation/known-signers-store.js";
import { createSdwMemoryAdapter } from "../index.js";
import {
  MEMORY_BATCH_LOCK_NAMESPACE,
  type HermesBridgeCommitCheck,
  type SdwMemoryBackendAdapter,
  sdwMemoryCorpusBatchLockFile,
} from "../sdw/adapters/sdw-memory-backend.js";
import { MemoryProvenanceBadSignerStore, memoryProvenancePublicKeyFingerprint } from "../sdw/memory-provenance-bad-signers.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import {
  createPrimaryMemoryProvenancePublicKeyResolver,
  createPrimaryMemoryProvenanceSigningHandleResolver,
} from "../sdw/memory-provenance-signing.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { MasterWriteBarrierLease } from "../storage/cross-process-lock.js";
import { KERNEL_LOCK_RELEASE_TIMEOUT_MS } from "../storage/cross-process-lock.js";
import type { StorageBackend } from "../storage/interface.js";
import { readKeychainCustodyKeyStatus } from "../wrap/keychain-custody.js";
import { readStoredPassphrase } from "../wrap/passphrase.js";
import { resolveHostLocalBootCredential } from "../wrap/custody-credential.js";
import {
  HERMES_MAX_CALL_RECORDS,
  LENGTH_PREFIX_BYTES,
  MAX_PRIVATE_FRAME_BYTES,
  PROBE_REPLY_BOUND_MS,
} from "./constants.js";
import { encodeNodeToRelay, parseRelayToNode, type NodeToRelayInput } from "./envelopes.js";
import { PrivateFrameDecoder } from "./framing.js";
import {
  HermesBridgeCore,
  type HermesApprovalPromptSummary,
  type HermesBridgeAuditRecord,
  type HermesBridgeMemoryAdapter,
} from "./bridge-core.js";

export const EXIT_CLEAN = 0;
export const EXIT_FATAL_BRIDGE = 70;
export const EXIT_STARTUP_REFUSED = 78;

// Must match `childReadyTimeoutMilliseconds` in the relay package Constants.swift.
export const CHILD_READY_TIMEOUT_MS = 5_000;
// Must match `childSigtermGraceMilliseconds` in the relay package Constants.swift.
export const RELAY_CHILD_SIGTERM_GRACE_MS = 3_000;
// Must match `relayChildExitBoundMilliseconds` in the relay package Constants.swift.
export const RELAY_CHILD_EXIT_BOUND_MS = PROBE_REPLY_BOUND_MS + RELAY_CHILD_SIGTERM_GRACE_MS;

export const DRAIN_TAIL_MS = 400;
export const BARRIER_RELEASE_BOUND_MS = KERNEL_LOCK_RELEASE_TIMEOUT_MS;
// 500 ms leaves relay-side scheduling room after the child gives up its own handles.
export const EXIT_MARGIN_MS = 500;
export const EXIT_BUDGET_MS = RELAY_CHILD_SIGTERM_GRACE_MS - EXIT_MARGIN_MS;
export const STOP_BUDGET_TABLE_MS = Object.freeze({
  drainTail: DRAIN_TAIL_MS,
  barrierRelease: BARRIER_RELEASE_BOUND_MS,
  exitMargin: EXIT_MARGIN_MS,
});
// 2900 = 400 ms drain tail + 2000 ms barrier release + 500 ms relay handoff margin.
export const STOP_LATENCY_BUDGET_MS = DRAIN_TAIL_MS + BARRIER_RELEASE_BOUND_MS + EXIT_MARGIN_MS;

// Legal unflushed output is bounded by every live call closing, one probe, and every live call answering.
export const MAX_PENDING_WRITE_BYTES =
  (HERMES_MAX_CALL_RECORDS + 1 + HERMES_MAX_CALL_RECORDS) *
  (LENGTH_PREFIX_BYTES + MAX_PRIVATE_FRAME_BYTES);

export const HERMES_BRIDGE_ENV_ALLOWLIST = Object.freeze([
  "HOME",
  "LANG",
  "TMPDIR",
  "HERMES_MEMORY_BRIDGE_IDENTITY",
  "HERMES_MEMORY_AGENT_ID",
  "HERMES_MEMORY_FORTRESS_ID",
] as const);

const STATE_FD_CHECKED = "state_FD_CHECKED";
const STATE_ENV_REPLACED = "state_ENV_REPLACED";
const STATE_CONFIG_CHECKED = "state_CONFIG_CHECKED";
const STATE_CUSTODY_PRESENT = "state_CUSTODY_PRESENT";
const STATE_FORTRESS_UNLOCKED = "state_FORTRESS_UNLOCKED";
const STATE_GATE_WIRED = "state_GATE_WIRED";
const STATE_CHILD_READY = "state_CHILD_READY";

const MIN_INHERITED_SOCKET_FD = 3;
const GROUP_OR_WORLD_WRITE_BITS = 0o022;
const ID_GRAMMAR = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const BRIDGE_IDENTITY_GRAMMAR = /^[a-f0-9]{64}$/u;

type FirstCause = "clean" | "fatal" | "startup_refused";
type ExitEvent = "clean_stop" | "transport_fatal" | "core_fatal" | "crash" | "audit_tail_failure" | "release_failure";
type ProcessSignal = "SIGTERM" | "SIGINT" | "SIGHUP";

export interface HermesBridgeCompositionReport {
  readonly adapterMode: "hermes-bridge";
  readonly adapterCount: number;
  readonly adapterOwnerRef: string;
  readonly forwardersBound: {
    readonly adapter: boolean;
    readonly audit: boolean;
    readonly badSignerScanner: boolean;
  };
  readonly constructed: readonly string[];
  readonly persistedTrapSpecCount: number;
  readonly custodyHandlesConstructed: readonly { readonly kind: "master_write_barrier"; readonly socketPath: string | null }[];
  readonly listeningSockets: readonly { readonly kind: "master_write_barrier"; readonly socketPath: string }[];
  readonly fortressDir: string;
  readonly fortressId: string;
}

export interface HermesBridgeProcessHandle {
  readonly report: HermesBridgeCompositionReport;
  readonly exited: Promise<number>;
  signalStop(signal: ProcessSignal): void;
  crash(error: unknown): void;
}

export interface HermesBridgeMainOptions {
  readonly argv: readonly string[];
  readonly env: NodeJS.ProcessEnv;
  readonly stdout?: Pick<NodeJS.WriteStream, "write">;
  readonly stderr?: Pick<NodeJS.WriteStream, "write">;
  readonly relaySocketFactory?: () => Duplex;
  readonly storageFor?: (fortressDir: string) => StorageBackend;
  readonly uid?: number;
}

export interface HermesBridgeProcessOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly relaySocketFactory: () => Duplex;
  readonly storageFor: (fortressDir: string) => StorageBackend;
  readonly stderr?: Pick<NodeJS.WriteStream, "write">;
  readonly uid?: number;
  readonly startupStopRequested?: () => { readonly kind: "signal" | "crash"; readonly error?: unknown } | undefined;
}

export interface ResolvedHermesBridgeFortress {
  readonly fortressDir: string;
  readonly storagePath: string;
}

class StartupRefusal extends Error {
  constructor(readonly state: string, message: string) {
    super(message);
    this.name = "HermesBridgeStartupRefusal";
  }
}

class StartupTransportOwner {
  private failure: string | undefined;
  private failProbe: (() => void) | undefined;
  private readonly onError = () => { this.recordFailure("relay socket error during startup"); };
  private readonly onEnd = () => { this.recordFailure("relay socket ended during startup"); };
  private readonly onClose = () => {
    this.recordFailure("relay socket closed during startup");
    this.handoff();
  };

  constructor(private readonly stream: Duplex) {
    // Own failures before any async work; pausing preserves early bytes for the runtime reader.
    stream.on("error", this.onError);
    stream.on("end", this.onEnd);
    stream.on("close", this.onClose);
    // Set defensive JS pause state without Socket's onread-specific native readStop; synchronous reader attachment, handoff and Ready write precede resume.
    if (stream instanceof net.Socket) Duplex.prototype.pause.call(stream);
    else stream.pause();
  }

  assertLive(state: string): void {
    if (this.failure !== undefined || this.stream.destroyed || !this.stream.readable || !this.stream.writable) {
      throw new StartupRefusal(state, this.failure ?? "relay socket closed during startup");
    }
  }

  async validateNative(stopRequested: HermesBridgeProcessOptions["startupStopRequested"]): Promise<void> {
    if (stopRequested?.() !== undefined) throw new StartupRefusal(STATE_CONFIG_CHECKED, "process stopped before ready");
    const stream = this.stream;
    // Generic Duplex injection is trusted application/test code, not native descriptor attestation.
    if (!(stream instanceof net.Socket)) return;
    this.assertLive(STATE_CONFIG_CHECKED);
    // Wrapper state and TCP family reject known-invalid shapes; only the operation callback admits a native UNIX stream.
    if (stream.pending || stream.connecting || stream.remoteFamily !== undefined || "family" in stream.address()) {
      throw new StartupRefusal(STATE_CONFIG_CHECKED, "relay fd must be a live UNIX socket");
    }
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      // Reuse the relay health budget; this bounds only the added admission operation.
      const deadline = performance.now() + PROBE_REPLY_BOUND_MS;
      const finish = (failure?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.failProbe = undefined;
        if (failure !== undefined) {
          this.recordFailure(failure);
          reject(new StartupRefusal(STATE_CONFIG_CHECKED, this.failure!));
        } else resolve();
      };
      const timer = setTimeout(() => finish("relay socket admission timed out"), PROBE_REPLY_BOUND_MS);
      this.failProbe = () => finish(this.failure);
      try {
        // Exactly one empty write: its boolean return, a read-start or a quiet turn cannot establish a connected transport.
        stream.write(Buffer.alloc(0), (error) => {
          if (settled) return;
          if (error) finish("relay socket admission write failed");
          else if (performance.now() >= deadline) finish("relay socket admission timed out");
          else finish(this.failure);
        });
      } catch {
        finish("relay socket admission write failed");
      }
    });
  }

  handoff(): void {
    this.stream.off("error", this.onError);
    this.stream.off("end", this.onEnd);
    this.stream.off("close", this.onClose);
  }

  refuse(): void {
    // A native write callback can fail before its error event; retain this owner until close.
    this.stream.destroy();
  }

  private recordFailure(reason: string): void {
    this.failure ??= reason;
    this.failProbe?.();
  }
}

class SingleBindForwarder<T extends object> {
  private target: T | undefined;

  bind(target: T): void {
    if (this.target !== undefined) throw new Error("Hermes bridge forwarder was already bound");
    this.target = target;
  }

  get bound(): boolean {
    return this.target !== undefined;
  }

  protected requireTarget(): T {
    if (this.target === undefined) throw new Error("Hermes bridge forwarder is not bound");
    return this.target;
  }
}

class AdapterForwarder extends SingleBindForwarder<HermesBridgeMemoryAdapter> implements HermesBridgeMemoryAdapter {
  insertPassage: HermesBridgeMemoryAdapter["insertPassage"] = (input, taint) =>
    this.requireTarget().insertPassage(input, taint);
  getPassage: HermesBridgeMemoryAdapter["getPassage"] = (passageId) =>
    this.requireTarget().getPassage(passageId);
  searchPassages: HermesBridgeMemoryAdapter["searchPassages"] = (query) =>
    this.requireTarget().searchPassages(query);
}

class AuditForwarder extends SingleBindForwarder<AuditLog> {
  readonly pending = new Set<Promise<void>>();
  // Records reach the audit log one at a time. The log serializes appends itself, so this changes no
  // ordering; it exists so a record still waiting its turn at close can be refused before the log
  // starts its filesystem preamble (namespace directories, lock files) inside a fortress whose master
  // write barrier this process has already given up.
  private turnQueue: Promise<void> = Promise.resolve();
  private handedOff = 0;
  private refuseAtExit: ((record: HermesBridgeAuditRecord) => void) | undefined;

  append(record: HermesBridgeAuditRecord): Promise<void> {
    const target = this.requireTarget();
    const turn = this.turnQueue.then(() => {
      // Once the barrier is released no append can persist (the storage refuses a raw write without
      // a live lease). A record that has not been handed off by then is refused here, reported on
      // stderr, and still rejects back to the core's durability handling: lost loudly, never silently.
      if (this.refuseAtExit !== undefined) {
        this.refuseAtExit(record);
        throw new Error(`Hermes bridge audit record ${record.kind} refused at exit`);
      }
      this.handedOff += 1;
      return this.appendCritical(target, record).finally(() => { this.handedOff -= 1; });
    });
    this.turnQueue = turn.then(() => undefined, () => undefined);
    return this.track(turn);
  }

  // Returns the count of records already handed to the audit log and still unconfirmed; the caller
  // reports it so an audit tail abandoned at the drain deadline is visible to the operator.
  close(refuse: (record: HermesBridgeAuditRecord) => void): number {
    this.refuseAtExit ??= refuse;
    return this.handedOff;
  }

  private appendCritical(target: AuditLog, record: HermesBridgeAuditRecord): Promise<void> {
    return target.appendCritical({
      layer: "l1",
      operation: "hermes_memory_bridge",
      identity_id: "hermes-memory-bridge",
      result: "success",
      details: { ...record },
    });
  }

  private track(promise: Promise<void>): Promise<void> {
    this.pending.add(promise);
    void promise.then(() => this.pending.delete(promise), () => this.pending.delete(promise));
    return promise;
  }

  flush(): Promise<void> {
    return this.requireTarget().flush();
  }
}

class FrameWriterForwarder {
  private writer: HermesSocketWriter | undefined;

  bind(writer: HermesSocketWriter): void {
    if (this.writer !== undefined) throw new Error("Hermes bridge writer was already bound");
    this.writer = writer;
  }

  write(input: NodeToRelayInput): void {
    if (this.writer === undefined) throw new Error("Hermes bridge writer is not bound");
    this.writer.writeFrame(input);
  }
}

class BadSignerScannerForwarder {
  private adapter: SdwMemoryBackendAdapter | undefined;

  bind(adapter: SdwMemoryBackendAdapter): void {
    if (this.adapter !== undefined) throw new Error("Hermes bridge bad-signer scanner was already bound");
    this.adapter = adapter;
  }

  get bound(): boolean {
    return this.adapter !== undefined;
  }

  scanForeignDependencies(did: string, fingerprint: string) {
    if (this.adapter === undefined) throw new Error("Hermes bridge bad-signer scanner is not bound");
    return this.adapter.scanForeignSignerDependencies(did, fingerprint);
  }
}

class HermesSocketWriter {
  private failed = false;
  private readyWritten = false;
  private pendingBytes = 0;
  private readonly pendingCallbacks = new Set<Promise<void>>();
  private failureReported = false;

  constructor(
    private readonly stream: Duplex,
    private readonly onFailure: (reason: string) => void,
  ) {}

  writeFrame(input: NodeToRelayInput): void {
    if (this.failed) throw new Error("Hermes bridge writer is latched");
    if (input.type === "ready") {
      if (this.readyWritten) this.failAndThrow("ready_twice");
      this.readyWritten = true;
    }
    let frame: Buffer;
    try {
      frame = encodeNodeToRelay(input);
    } catch (error) {
      this.failAndThrow("encode_failed", error);
    }
    if (this.pendingBytes + frame.byteLength > MAX_PENDING_WRITE_BYTES) {
      this.failAndThrow("pending_write_cap");
    }
    this.pendingBytes += frame.byteLength;
    let resolveDone: () => void = () => undefined;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    const callback = (error?: Error | null) => {
      this.pendingBytes -= frame.byteLength;
      if (error) {
        this.recordFailure("write_callback_error");
      }
      resolveDone();
    };
    try {
      this.stream.write(frame, callback);
    } catch (error) {
      this.pendingBytes -= frame.byteLength;
      this.failAndThrow("write_throw", error);
    }
    this.pendingCallbacks.add(done);
    void done.then(() => this.pendingCallbacks.delete(done), () => this.pendingCallbacks.delete(done));
  }

  socketError(error: unknown): void {
    this.recordFailure(error instanceof Error && error.message ? error.message : "write_error");
  }

  async endAndFlush(deadlineMs: number): Promise<void> {
    await withDeadline(Promise.allSettled([...this.pendingCallbacks]).then(() => undefined), deadlineMs, () => {
      this.stream.destroy();
    });
    await withDeadline(new Promise<void>((resolve) => {
      if (typeof (this.stream as { end?: unknown }).end === "function") {
        this.stream.end(resolve);
      } else {
        resolve();
      }
    }), deadlineMs, () => this.stream.destroy());
  }

  private recordFailure(reason: string): void {
    if (this.failed) return;
    this.failed = true;
    if (this.failureReported) return;
    this.failureReported = true;
    // A writer failure discovered inside stream internals is reported on the next microtask so the core never re-enters its stop path under a write stack.
    queueMicrotask(() => this.onFailure(reason));
  }

  private failAndThrow(reason: string, cause?: unknown): never {
    this.recordFailure(reason);
    throw cause instanceof Error ? cause : new Error(`Hermes bridge writer failed: ${reason}`);
  }
}

class ShellController {
  private cause: FirstCause | undefined;
  private exitStarted = false;
  private core: HermesBridgeCore | undefined;
  private writer: HermesSocketWriter | undefined;
  private readonly cleanupCallbacks: Array<() => void> = [];
  private readonly stopCallbacks: Array<() => void> = [];
  private readonly keepaliveErrorListener = () => undefined;
  private exitResolve: (code: number) => void = () => undefined;
  readonly exited: Promise<number>;

  constructor(
    private readonly audit: AuditForwarder,
    private readonly barrier: MasterWriteBarrierLease | undefined,
    private readonly stream: Duplex,
    private readonly stderr: Pick<NodeJS.WriteStream, "write">,
  ) {
    this.stream.on("error", this.keepaliveErrorListener);
    this.exited = new Promise((resolve) => {
      this.exitResolve = resolve;
    });
  }

  attach(core: HermesBridgeCore, writer: HermesSocketWriter): void {
    this.core = core;
    this.writer = writer;
    core.onDrained(({ fatalBridge }) => {
      if (fatalBridge) this.observeExit("core_fatal");
      void this.exitWhenDrained();
    });
  }

  observeExit(event: ExitEvent): void {
    // Protocol/ledger invariants and crashes override clean drain; transport errors
    // retain the first cause. Audit tail failure preserves the admitted clean-drain contract.
    switch (event) {
      case "audit_tail_failure": return;
      case "core_fatal":
      case "crash":
      case "release_failure": this.cause = "fatal"; break;
      case "clean_stop": this.cause ??= "clean"; break;
      case "transport_fatal": this.cause ??= "fatal"; break;
    }
    this.notifyStop();
  }

  signalStop(_signal: ProcessSignal): void {
    if (this.core === undefined) {
      this.cause = "startup_refused";
      this.exitResolve(EXIT_STARTUP_REFUSED);
      return;
    }
    this.observeExit("clean_stop");
    this.core.relayEof();
  }

  crash(_error: unknown): void {
    if (this.core === undefined) {
      this.cause = "startup_refused";
      this.exitResolve(EXIT_STARTUP_REFUSED);
      return;
    }
    this.observeExit("crash");
    this.core.relayFatal("crash");
  }

  writerFailed(): void {
    this.observeExit("transport_fatal");
    this.core?.relayFatal("write_failed");
  }

  addCleanup(fn: () => void): void {
    this.cleanupCallbacks.push(fn);
  }

  onStop(fn: () => void): void {
    this.stopCallbacks.push(fn);
  }

  private notifyStop(): void {
    for (const callback of this.stopCallbacks.splice(0)) callback();
  }

  private async exitWhenDrained(): Promise<void> {
    if (this.exitStarted) return;
    this.exitStarted = true;
    const drainedAt = performance.now();
    const drainTailDeadline = drainedAt + DRAIN_TAIL_MS;
    const exitDeadline = drainedAt + EXIT_BUDGET_MS;
    const tailDrained = await this.step(() => withDeadline(Promise.allSettled([...this.audit.pending]).then(() => true), drainTailDeadline), "audit_tail_failure");
    // flush() begins by awaiting the same pending appends, so once the tail missed its deadline the
    // flush cannot finish inside the budget either; starting it would leave a detached continuation
    // that attempts the graceful-shutdown checkpoint after the barrier below is released.
    if (this.audit.bound && tailDrained === true) {
      await this.step(() => withDeadline(this.audit.flush(), drainTailDeadline), "audit_tail_failure");
    }
    await this.step(() => this.writer?.endAndFlush(drainTailDeadline) ?? Promise.resolve());
    // Close before the barrier is released: every append from here on would be refused by the
    // storage anyway, and must not touch the fortress tree while the process is tearing down.
    const unconfirmedAuditRecords = this.audit.close((record) => {
      this.stderr.write(`hermes-memory-bridge audit: refused ${record.kind} record at exit\n`);
    });
    if (unconfirmedAuditRecords > 0) {
      this.stderr.write(`hermes-memory-bridge audit: ${unconfirmedAuditRecords} record(s) unconfirmed at exit\n`);
    }
    await this.step(() => withDeadline(this.barrier?.release() ?? Promise.resolve(), exitDeadline), "release_failure");
    this.stream.destroy();
    this.stream.removeAllListeners();
    for (const cleanup of this.cleanupCallbacks.splice(0)) {
      try { cleanup(); } catch { /* cleanup is best effort after drained */ }
    }
    this.exitResolve(this.cause === "fatal" ? EXIT_FATAL_BRIDGE : EXIT_CLEAN);
  }

  private async step<T>(run: () => Promise<T>, failure: ExitEvent = "transport_fatal"): Promise<T | undefined> {
    try {
      return await run();
    } catch {
      this.observeExit(failure);
      return undefined;
    }
  }
}

export async function hermesBridgeMain(options: HermesBridgeMainOptions): Promise<number> {
  const stderr = options.stderr ?? process.stderr;
  let shell: HermesBridgeProcessHandle | undefined;
  const signalHandlers: Array<[ProcessSignal, () => void]> = [];
  let preReadyStop: { kind: "signal" | "crash"; error?: unknown } | undefined;
  const crashHandler = (error: unknown) => {
    if (shell === undefined) {
      preReadyStop = { kind: "crash", error };
      return;
    }
    stderr.write("hermes-memory-bridge crash: process error after ready\n");
    shell.crash(error);
  };
  try {
    const fd = state_FD_CHECKED(options.argv);
    const env = state_ENV_REPLACED(options.env);
    const storageFor = options.storageFor ?? ((fortressDir) => new FilesystemStorage(join(fortressDir, "state")));
    const relaySocketFactory = options.relaySocketFactory ?? (() => new net.Socket({ fd }));
    for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
      const handler = () => {
        if (shell === undefined) {
          preReadyStop = { kind: "signal" };
          return;
        }
        shell.signalStop(signal);
      };
      process.on(signal, handler);
      signalHandlers.push([signal, handler]);
    }
    process.on("uncaughtException", crashHandler);
    process.on("unhandledRejection", crashHandler);
    const run = await runHermesBridgeProcess({
      env,
      relaySocketFactory,
      storageFor,
      stderr,
      uid: options.uid,
      startupStopRequested: () => preReadyStop,
    });
    shell = run;
    return await run.exited;
  } catch (error) {
    if (error instanceof StartupRefusal) {
      stderr.write(`hermes-memory-bridge ${error.state}: startup refused\n`);
      return EXIT_STARTUP_REFUSED;
    }
    stderr.write(`hermes-memory-bridge ${STATE_GATE_WIRED}: startup refused\n`);
    return EXIT_STARTUP_REFUSED;
  } finally {
    for (const [signal, handler] of signalHandlers) process.off(signal, handler);
    process.off("uncaughtException", crashHandler);
    process.off("unhandledRejection", crashHandler);
  }
}

export async function runHermesBridgeProcess(options: HermesBridgeProcessOptions): Promise<HermesBridgeProcessHandle> {
  const stderr = options.stderr ?? process.stderr;
  const env = state_ENV_REPLACED(options.env);
  state_CONFIG_CHECKED();
  let currentState = STATE_FORTRESS_UNLOCKED;
  const enter = (state: string) => { currentState = state; };
  let custody: EstablishMasterResult | undefined;
  let barrier: MasterWriteBarrierLease | undefined;
  let stream: Duplex | undefined;
  let startupTransport: StartupTransportOwner | undefined;
  try {
    const resolved = await resolveHermesBridgeFortress({ env, uid: options.uid ?? process.getuid?.() ?? 0 });
    const storage = options.storageFor(resolved.fortressDir);
    enter(STATE_CONFIG_CHECKED);
    assertFilesystemBridgeStorage(storage);
    await assertNoLeftoverCorpusLock(storage);
    // The bridge never opens an interrupted import: recovery belongs to the operator exit-recover path.
    // Must match the explicit refusal exception in fortress-open-recovery-wiring.test.ts.
    await assertNoInterruptedExitImport(storage);
    try {
      stream = options.relaySocketFactory();
    } catch (error) {
      throw new StartupRefusal(STATE_CONFIG_CHECKED, error instanceof Error ? error.message : "relay socket construction failed");
    }
    startupTransport = new StartupTransportOwner(stream);
    await startupTransport.validateNative(options.startupStopRequested);
    // Recheck in the caller's continuation: a successful callback cannot mask a stop or failure queued before custody.
    if (options.startupStopRequested?.() !== undefined) throw new StartupRefusal(STATE_CONFIG_CHECKED, "process stopped before ready");
    startupTransport.assertLive(STATE_CONFIG_CHECKED);
    enter(STATE_CUSTODY_PRESENT);
    custody = await state_CUSTODY_PRESENT(storage, resolved.storagePath, env.HOME!);
    await refusePreReadyStop(options.startupStopRequested?.(), custody, STATE_CUSTODY_PRESENT);
    barrier = custody.masterWriteBarrier;
    const establishedCustody = custody;
    enter(STATE_CONFIG_CHECKED);
    const persistedTrapSpecCount = await assertNoPersistedTraps(storage);
    enter(STATE_GATE_WIRED);
    const composition = await composeHermesBridge({
      env,
      storage,
      storagePath: resolved.storagePath,
      fortressDir: resolved.fortressDir,
      masterBarrierSocketPath: barrier?.socketPath ?? null,
      masterKey: custody.masterKey,
      persistedTrapSpecCount,
      stderr,
    });
    const core = composition.core;
    enter(STATE_CHILD_READY);
    await refusePreReadyStop(options.startupStopRequested?.(), custody, STATE_CHILD_READY);
    if (options.startupStopRequested?.() !== undefined) throw new StartupRefusal(STATE_CHILD_READY, "process stopped before ready");
    // The last pre-ready await must precede this guard: observed transport failure cannot cross the handoff into readiness.
    startupTransport.assertLive(STATE_GATE_WIRED);
    const controller = new ShellController(composition.auditForwarder, barrier, stream, stderr);
    const writer = new HermesSocketWriter(stream, () => controller.writerFailed());
    composition.writerForwarder.bind(writer);
    controller.attach(core, writer);
    controller.addCleanup(() => stream?.removeAllListeners());
    controller.addCleanup(() => establishedCustody.masterKey.fill(0));
    controller.addCleanup(() => composition.clearTimers());
    // Attach runtime ownership while paused, before releasing startup ownership; no await splits this handoff.
    const startReader = attachReader(stream, core, writer, controller);
    startupTransport.handoff();
    try {
      writer.writeFrame({ type: "ready" });
    } catch {
      throw new StartupRefusal(STATE_CHILD_READY, "ready write refused");
    }
    state_CHILD_READY();
    // Ready is the first output; only now may the reader consume bytes parked during admission and custody.
    startReader();
    // This process handle intentionally grants no owner decision capability.
    // Adding one requires restart-recovery handling before any write can be authorized.
    return {
      report: composition.report,
      exited: controller.exited,
      signalStop: (signal) => controller.signalStop(signal),
      crash: (error) => controller.crash(error),
    };
  } catch (error) {
    startupTransport?.refuse();
    stream?.destroy();
    await barrier?.release().catch(() => undefined);
    custody?.masterKey.fill(0);
    if (error instanceof StartupRefusal) throw error;
    throw new StartupRefusal(currentState, "startup refused");
  }
}

function state_FD_CHECKED(argv: readonly string[]): number {
  if (argv.length !== 3 || argv[0] !== "run" || argv[1] !== "--relay-fd") {
    throw new StartupRefusal(STATE_FD_CHECKED, "expected run --relay-fd <fd>");
  }
  const fd = Number(argv[2]);
  if (!Number.isInteger(fd) || fd < MIN_INHERITED_SOCKET_FD) {
    throw new StartupRefusal(STATE_FD_CHECKED, "relay fd must be an inherited socket descriptor");
  }
  let stats;
  try {
    stats = fstatSync(fd);
  } catch {
    throw new StartupRefusal(STATE_FD_CHECKED, "relay fd is not open");
  }
  if (!stats.isSocket()) {
    throw new StartupRefusal(STATE_FD_CHECKED, "relay fd is not a socket");
  }
  return fd;
}

function state_ENV_REPLACED(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  // Must match ChildSupervisor.configuredEnvironment in the relay package: the relay passes exactly these keys.
  const allowed = new Set<string>(HERMES_BRIDGE_ENV_ALLOWLIST);
  const offenders = Object.keys(env).filter((key) => !allowed.has(key)).sort();
  if (offenders.length > 0) {
    throw new StartupRefusal(STATE_ENV_REPLACED, `unexpected environment keys: ${offenders.join(",")}`);
  }
  const home = env.HOME;
  if (home === undefined || !isAbsolute(home)) {
    throw new StartupRefusal(STATE_ENV_REPLACED, "HOME must be absolute");
  }
  const bridgeIdentity = env.HERMES_MEMORY_BRIDGE_IDENTITY;
  const agentId = env.HERMES_MEMORY_AGENT_ID;
  const fortressId = env.HERMES_MEMORY_FORTRESS_ID;
  if (bridgeIdentity === undefined || !BRIDGE_IDENTITY_GRAMMAR.test(bridgeIdentity)) {
    throw new StartupRefusal(STATE_ENV_REPLACED, "HERMES_MEMORY_BRIDGE_IDENTITY is malformed");
  }
  if (agentId === undefined || !ID_GRAMMAR.test(agentId)) {
    throw new StartupRefusal(STATE_ENV_REPLACED, "HERMES_MEMORY_AGENT_ID is malformed");
  }
  if (fortressId === undefined || !ID_GRAMMAR.test(fortressId)) {
    throw new StartupRefusal(STATE_ENV_REPLACED, "HERMES_MEMORY_FORTRESS_ID is malformed");
  }
  return env;
}

function state_CONFIG_CHECKED(): void {
  // The bridge owns only the grace slice after the relay's probe wait; each term is independently derived above.
  if (STOP_LATENCY_BUDGET_MS > RELAY_CHILD_SIGTERM_GRACE_MS) {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, "shutdown stop budget exceeds relay SIGTERM grace");
  }
}

async function state_CUSTODY_PRESENT(storage: StorageBackend, storagePath: string, home: string): Promise<EstablishMasterResult> {
  const resolved = await resolveHostLocalBootCredential({
    storage,
    storagePath,
    // Must match the HOME accepted by state_ENV_REPLACED: bridge custody lookup belongs to the relay-configured fortress tree, not the account default.
    home,
    readStored: readStoredPassphrase,
    readCustodyKey: readKeychainCustodyKeyStatus,
  });
  if (resolved.kind === "virgin") {
    throw new StartupRefusal(STATE_CUSTODY_PRESENT, "fortress custody is absent");
  }
  if (resolved.kind === "fail-closed") {
    throw new StartupRefusal(STATE_CUSTODY_PRESENT, resolved.message);
  }
  try {
    return await establishMaster({
      storage,
      ...(resolved.kind === "passphrase" ? { passphrase: resolved.value } : {}),
      ...(resolved.kind === "keychain-key" ? { keychainKey: resolved.key } : {}),
      storagePathHint: storagePath,
      barrierDegradeMode: "fail-closed",
    });
  } finally {
    if (resolved.kind === "keychain-key") resolved.key.fill(0);
  }
}

export async function resolveHermesBridgeFortress(input: {
  readonly env: NodeJS.ProcessEnv;
  readonly uid: number;
}): Promise<ResolvedHermesBridgeFortress> {
  const home = input.env.HOME;
  const fortressId = input.env.HERMES_MEMORY_FORTRESS_ID;
  if (home === undefined || !isAbsolute(home)) {
    throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "HOME must be absolute");
  }
  if (fortressId === undefined || !ID_GRAMMAR.test(fortressId)) {
    throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "HERMES_MEMORY_FORTRESS_ID is malformed");
  }
  const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  await assertOwnedNoSymlinkChain(home, fortressDir, input.uid);
  const defaultFortress = join(home, ".sanctuary");
  const realFortress = await realpath(fortressDir);
  const realDefault = await realpath(defaultFortress).catch(() => defaultFortress);
  if (isInsideOrEqual(realFortress, realDefault) || isInsideOrEqual(realDefault, realFortress)) {
    throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "dedicated fortress path must be separate from the default fortress");
  }
  return { fortressDir: realFortress, storagePath: realFortress };
}

async function assertOwnedNoSymlinkChain(home: string, target: string, uid: number): Promise<void> {
  const relativePath = relative(home, target);
  if (relativePath.startsWith("..") || relativePath === "") {
    throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "fortress path must be below HOME");
  }
  let current = home;
  const parts = relativePath.split(sep).filter(Boolean);
  for (const part of ["", ...parts]) {
    if (part !== "") current = join(current, part);
    const stats = await lstat(current).catch(() => {
      throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, `path component is missing: ${current}`);
    });
    if (stats.isSymbolicLink()) {
      throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, `path component is a symlink: ${current}`);
    }
    if (stats.uid !== uid) {
      throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, `path component has the wrong owner: ${current}`);
    }
    if ((stats.mode & GROUP_OR_WORLD_WRITE_BITS) !== 0) {
      throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, `path component is group or world writable: ${current}`);
    }
    if (current === target && (stats.mode & 0o777) !== 0o700) {
      throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, `fortress directory mode must be 0700: ${current}`);
    }
  }
}

function isInsideOrEqual(path: string, parent: string): boolean {
  const rel = relative(parent, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function assertFilesystemBridgeStorage(storage: StorageBackend): asserts storage is FilesystemStorage {
  if (!(storage instanceof FilesystemStorage)) {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, "bridge storage must be filesystem backed");
  }
}

async function assertNoLeftoverCorpusLock(storage: FilesystemStorage): Promise<void> {
  const lockPath = join(storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), sdwMemoryCorpusBatchLockFile());
  const exists = await lstat(lockPath).then(
    () => true,
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return false;
      throw new StartupRefusal(STATE_CONFIG_CHECKED, `leftover corpus lock status is unreadable at ${lockPath}`);
    },
  );
  if (exists) {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, `leftover corpus lock remains at ${lockPath}`);
  }
}

async function assertNoPersistedTraps(storage: StorageBackend): Promise<number> {
  let metas;
  try {
    metas = await storage.list(TRAP_STORE_NAMESPACE, TRAP_STORE_KEY_PREFIX);
  } catch {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, "persisted trap store is unreadable");
  }
  if (metas.length > 0) {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, "persisted trap specs are present");
  }
  return metas.length;
}

async function assertNoInterruptedExitImport(storage: StorageBackend): Promise<void> {
  const { hasInterruptedExitImport } = await import("../storage/exit-import-journal.js");
  if (await hasInterruptedExitImport(storage)) {
    throw new StartupRefusal(STATE_CONFIG_CHECKED, "interrupted exit-import journal is present");
  }
}

async function composeHermesBridge(input: {
  readonly env: NodeJS.ProcessEnv;
  readonly storage: StorageBackend;
  readonly storagePath: string;
  readonly fortressDir: string;
  readonly masterBarrierSocketPath: string | null;
  readonly masterKey: Uint8Array;
  readonly persistedTrapSpecCount: number;
  readonly stderr: Pick<NodeJS.WriteStream, "write">;
}): Promise<{
  readonly core: HermesBridgeCore;
  readonly auditForwarder: AuditForwarder;
  readonly writerForwarder: FrameWriterForwarder;
  readonly clearTimers: () => void;
  readonly report: HermesBridgeCompositionReport;
}> {
  const adapterForwarder = new AdapterForwarder();
  const auditForwarder = new AuditForwarder();
  const writerForwarder = new FrameWriterForwarder();
  const badSignerScanner = new BadSignerScannerForwarder();
  const timers = new Set<NodeJS.Timeout>();
  const abort = new AbortController();
  const core = new HermesBridgeCore({
    writeFrame: (input) => writerForwarder.write(input),
    appendAudit: (record) => auditForwarder.append(record),
    nowMs: () => performance.now(),
    setTimer: (ms, fire) => {
      const handle = setTimeout(fire, ms);
      timers.add(handle);
      return handle;
    },
    clearTimer: (handle) => {
      const timer = handle as NodeJS.Timeout;
      clearTimeout(timer);
      timers.delete(timer);
    },
    adapter: adapterForwarder,
    ownerSurface: {
      promptOwner(_entryId: string, _summary: HermesApprovalPromptSummary) {
        // The production CLI has no approval channel and cannot authorize writes.
        // Enabling approval requires restart-recovery handling for process-local latches.
        input.stderr.write("hermes-memory-bridge owner approval is deferred in this release\n");
      },
    },
    abort,
  });
  const identityManager = new IdentityManager(input.storage, input.masterKey);
  const loaded = await identityManager.load();
  if (loaded.loaded < 1) throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "no primary identity is available");
  const primary = identityManager.getDefault();
  if (primary === undefined) throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "primary identity is unavailable");
  const primaryFingerprint = memoryProvenancePublicKeyFingerprint(fromBase64url(primary.public_key));
  // Must match the install-side bridge identity value that the relay passes through configuredEnvironment.
  if (primaryFingerprint !== input.env.HERMES_MEMORY_BRIDGE_IDENTITY) {
    throw new StartupRefusal(STATE_FORTRESS_UNLOCKED, "primary identity does not match bridge identity pin");
  }
  const auditLog = new AuditLog(input.storage, input.masterKey);
  auditForwarder.bind(auditLog);
  // Must match fortressIdFromStoragePath in ../dashboard/v1_1/wiring.ts: this child uses the same local namespace key as the owner process.
  const fortressId = fortressIdFromStoragePath(input.storagePath);
  const signingHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identityManager, input.masterKey);
  const signerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identityManager);
  const migration = new SdwMemoryProvenanceMigration({
    storage: input.storage,
    masterKey: input.masterKey,
    fortressId,
    ownerRef: input.env.HERMES_MEMORY_AGENT_ID!,
    resolvePrimarySigningHandle: signingHandle,
    resolveSignerPublicKey: signerPublicKey,
  });
  const knownSigners = new KnownSignersStore(input.storage, input.masterKey, {
    partition: "memory_provenance",
  });
  const persistedSigners = new Map((await knownSigners.loadAll()).map((entry) => [entry.did, entry.publicKey]));
  const resolveSignerPublicKey = (identityId: string, did: string) =>
    signerPublicKey(identityId, did) ?? persistedSigners.get(did)?.slice();
  const badSignerStore = new MemoryProvenanceBadSignerStore({
    storage: input.storage,
    masterKey: input.masterKey,
    fortressId,
    resolveSignerPublicKey: (did) => persistedSigners.get(did)?.slice(),
    isLocallyRootedSigner: (did, publicKey) => {
      const current = identityManager.getDefault();
      return current?.did === did && Buffer.from(fromBase64url(current.public_key)).equals(Buffer.from(publicKey));
    },
    scanForeignDependencies: (did, fingerprint) => badSignerScanner.scanForeignDependencies(did, fingerprint),
  });
  const adapter = createSdwMemoryAdapter({
    mode: "hermes-bridge",
    storage: input.storage,
    masterKey: input.masterKey,
    fortressId,
    ownerRef: input.env.HERMES_MEMORY_AGENT_ID!,
    resolvePrimarySigningHandle: signingHandle,
    resolveSignerPublicKey,
    resolveMemoryIntegrityState: () => migration.getState(),
    commitCheck: core.commitCheck,
    badSignerAuthority: badSignerStore,
  });
  adapterForwarder.bind(adapter);
  badSignerScanner.bind(adapter);
  if (adapter.mode !== "hermes-bridge") {
    throw new StartupRefusal(STATE_GATE_WIRED, "memory adapter is not in bridge mode");
  }
  if ((adapter as unknown as { hermesBridgeCommitCheck?: HermesBridgeCommitCheck }).hermesBridgeCommitCheck !== core.commitCheck) {
    throw new StartupRefusal(STATE_GATE_WIRED, "memory adapter commit check is not the bridge core check");
  }
  if (core.commitCheck.abortSignal !== abort.signal) {
    throw new StartupRefusal(STATE_GATE_WIRED, "bridge commit check abort signal is not the process abort signal");
  }
  const constructedComponents = [
    identityManager,
    auditLog,
    migration,
    knownSigners,
    badSignerStore,
    adapter,
  ] as const;
  const adapterComponents = [adapter] as const;
  const listeningSockets = input.masterBarrierSocketPath === null
    ? []
    : [{ kind: "master_write_barrier" as const, socketPath: input.masterBarrierSocketPath }];
  state_GATE_WIRED();
  return {
    core,
    auditForwarder,
    writerForwarder,
    clearTimers: () => {
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
    },
    report: {
      adapterMode: adapter.mode,
      adapterCount: adapterComponents.length,
      adapterOwnerRef: adapter.ownerRef,
      forwardersBound: {
        adapter: adapterForwarder.bound,
        audit: auditForwarder.bound,
        badSignerScanner: badSignerScanner.bound,
      },
      constructed: constructedComponents.map((component) => component.constructor.name),
      persistedTrapSpecCount: input.persistedTrapSpecCount,
      custodyHandlesConstructed: [{ kind: "master_write_barrier", socketPath: input.masterBarrierSocketPath }],
      listeningSockets,
      fortressDir: input.fortressDir,
      fortressId,
    },
  };
}

function state_GATE_WIRED(): void {}
function state_CHILD_READY(): void {
  void STATE_CHILD_READY;
}

function attachReader(
  stream: Duplex,
  core: HermesBridgeCore,
  writer: HermesSocketWriter,
  controller: ShellController,
): () => void {
  const decoder = new PrivateFrameDecoder();
  let stopped = false;
  const stopFeeding = () => { stopped = true; };
  controller.onStop(stopFeeding);
  core.onDrained(stopFeeding);
  stream.on("data", (chunk: Buffer) => {
    if (stopped) return;
    decoder.push(chunk);
    for (;;) {
      const next = decoder.next();
      if (next.kind === "need_more") return;
      if (next.kind === "fatal") {
        controller.observeExit("transport_fatal");
        core.relayFatal(next.error.code);
        return;
      }
      if (stopped) return;
      const parsed = parseRelayToNode(next.body);
      if (parsed.kind === "fatal") {
        controller.observeExit("transport_fatal");
        core.relayFatal(parsed.reason);
        return;
      }
      if (parsed.frame.kind === "relay_shutdown") controller.observeExit("clean_stop");
      core.relayFrame(parsed.frame);
    }
  });
  stream.on("end", () => {
    if (stopped) return;
    if (decoder.bufferedBytes() > 0) {
      controller.observeExit("transport_fatal");
      core.relayFatal("truncated_frame");
      return;
    }
    controller.observeExit("clean_stop");
    core.relayEof();
  });
  stream.on("error", (error) => {
    writer.socketError(error);
  });
  return () => {
    if (typeof (stream as { resume?: unknown }).resume === "function") stream.resume();
  };
}

async function refusePreReadyStop(
  stop: { readonly kind: "signal" | "crash"; readonly error?: unknown } | undefined,
  custody: EstablishMasterResult,
  state: string,
): Promise<void> {
  if (stop === undefined) return;
  await custody.masterWriteBarrier?.release().catch(() => undefined);
  custody.masterKey.fill(0);
  throw new StartupRefusal(state, "process stopped before ready");
}

async function withDeadline<T>(promise: Promise<T>, deadlineMs: number, onTimeout?: () => void): Promise<T | undefined> {
  let timer: NodeJS.Timeout | undefined;
  const timeoutMs = Math.max(0, deadlineMs - performance.now());
  return Promise.race([
    promise,
    new Promise<undefined>((resolve) => {
      timer = setTimeout(() => {
        onTimeout?.();
        resolve(undefined);
      }, timeoutMs);
      timer.unref?.();
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}
