/** SDW observation and scope lifetime over a required, private bound-disk port. */
import { AsyncLocalStorage } from "node:async_hooks";
import { z } from "zod";
import { withPathLock, withCrossProcessLock, CrossProcessLockError, ExitAdmissionLockError,
  EXIT_IMPORT_JOURNAL_NAMESPACE, EXIT_ADMISSION_LOCK_FILE, type CrossProcessLockLease } from "./cross-process-lock.js";
import { encodeFilesystemStorageName } from "./filesystem-name-codec.js";
import type { StorageBackend } from "./interface.js";

export const SDW_MAX_STAGED_BYTES = 64 * 1024 * 1024;
export const SDW_MAX_PENDING_CALLS = 1;
export const SDW_READ_RETRIES = 2;
export const SDW_LOCK_WAIT_MS = 10_000;
export const SDW_JOURNAL_NAMESPACE = "_sdw_journal_v1";
export const SDW_NAMESPACE_MUTATION_LOCK = ".sdw-mutation.lock";
// Must match the six constants in sdw/records.ts and the contract's namespace
// membership schema. sdw-journal-plan.test.ts checks full-set equality. Payload
// type imports would introduce a storage/custody cycle through Exit admission.
export const SDW_JOURNAL_NAMESPACES = Object.freeze([
  "_sdw_catalog", "_sdw_document_corpus", "_sdw_meta",
  "_sdw_query_history", "_sdw_vector_memory", "_sdw_working_state",
] as const);
export type SdwDecision = "none" | "unknown" | "committed";
export type SdwStorageReason = "storage_busy" | "storage_capability_unavailable" |
  "storage_limit_exceeded" | "storage_recovery_pending" | "storage_holder_lost" |
  "storage_io_failed" | "operation_aborted" | "storage_plan_invalid" | "storage_scope_invalid";
/** Preserve decision uncertainty through wrappers; this error never authorizes cleanup. */
export class SdwStorageError extends Error {
  constructor(
    readonly reason: SdwStorageReason,
    readonly decision: SdwDecision,
    readonly transaction_id?: string,
    options?: ErrorOptions,
  ) {
    super(reason, options);
    this.name = "SdwStorageError";
  }
}
const MAX_EPOCH = Number.MAX_SAFE_INTEGER;
const integer = (max: number) => z.number().int().min(0).max(max).refine(Number.isSafeInteger);
const transactionSchema = z.string().regex(/^[0-9a-f]{32}$/);
export const sdwEpochsSchema = z.object({
  [SDW_JOURNAL_NAMESPACES[0]]: integer(MAX_EPOCH),
  [SDW_JOURNAL_NAMESPACES[1]]: integer(MAX_EPOCH),
  [SDW_JOURNAL_NAMESPACES[2]]: integer(MAX_EPOCH),
  [SDW_JOURNAL_NAMESPACES[3]]: integer(MAX_EPOCH),
  [SDW_JOURNAL_NAMESPACES[4]]: integer(MAX_EPOCH),
  [SDW_JOURNAL_NAMESPACES[5]]: integer(MAX_EPOCH),
}).strict();
export const sdwGenerationSchema = z.object({
  version: z.literal(1), epochs: sdwEpochsSchema, transaction_id: transactionSchema.nullable(),
  affected_mask: integer((1 << SDW_JOURNAL_NAMESPACES.length) - 1),
  phase: z.enum(["CLEAN", "BUSY", "APPLIED", "RETIRED"]),
}).strict().refine(g => g.phase === "CLEAN" ? g.transaction_id === null && g.affected_mask === 0 : g.transaction_id !== null && g.affected_mask !== 0);

export type SdwGeneration = z.infer<typeof sdwGenerationSchema>;
export type SdwEpochs = z.infer<typeof sdwEpochsSchema>;
declare const SDW_ADMISSION_BRAND: unique symbol;
/** Engine must also validate its private WeakMap lease/root/fortress/invocation; casts confer nothing. */
export interface SdwAdmissionToken { readonly [SDW_ADMISSION_BRAND]: true }

type Namespace = typeof SDW_JOURNAL_NAMESPACES[number];
type State = "ABSENT" | "CLEAN" | "BUILDING" | "PREPARED" | "COMMIT" | "APPLIED" | "RETIRED" | "INVALID";
/** A private observer's authenticated control classification, never caller metadata. */
export interface SdwObservation {
  readonly state: State;
  readonly generation: SdwGeneration | null;
  /** Stable storage-root device/inode and fortress identity, checked by the port. */
  readonly binding: string;
  /** COMMIT/APPLIED evidence already observed must survive subsequent parse failures. */
  readonly decision: SdwDecision;
}
/**
 * Engine-owned port: observe reads generation/at most five headers/generation,
 * authenticates certificates against injected primary history, and returns only
 * matching samples. It never creates paths, locks, children, or caches attempts.
 * An unanswerable observation throws capability_unavailable, never plan_invalid.
 * No production port or filesystem write-set producer is installed by this module.
 */
export interface SdwFencePort {
  readonly binding: string;
  assertBinding(): Promise<void>;
  observe(): Promise<SdwObservation>;
  withFence<T>(operation: (lease: CrossProcessLockLease) => Promise<T>): Promise<T>;
  /** Private bound namespace directory; never forwarded as a backend capability. */
  mutationDirectory(namespace: Namespace): string;
}

const fences = new WeakMap<StorageBackend, SdwFence>();
const ports = new WeakMap<SdwFence, SdwFencePort>();
const tokens = new WeakMap<object, { fence: SdwFence; lifetime: Lifetime; lease: CrossProcessLockLease }>();
const invocation = new AsyncLocalStorage<Lifetime>();
const readScope = new AsyncLocalStorage<{ fence: SdwFence; open: boolean; pending?: Promise<unknown> }>();
// Only live engine calls occupy this map; no queued plans or expired-holder takeover.
const engineSlots = new Set<string>();
const ALL_MASK = (1 << SDW_JOURNAL_NAMESPACES.length) - 1;

function failure(reason: ConstructorParameters<typeof SdwStorageError>[0], decision: SdwDecision = "none"): SdwStorageError {
  return new SdwStorageError(reason, decision);
}
function strongest(a: SdwDecision, b: SdwDecision): SdwDecision {
  return a === "committed" || b === "committed" ? "committed" : a === "unknown" || b === "unknown" ? "unknown" : "none";
}
function preserve(error: unknown, decision: SdwDecision): unknown {
  if (error instanceof SdwStorageError) decision = strongest(decision, error.decision);
  if (decision === "none") return error;
  if (error instanceof SdwStorageError) {
    const preserved = new SdwStorageError(error.reason, decision, error.transaction_id, { cause: error });
    preserved.message = error.message;
    return preserved;
  }
  return new SdwStorageError("storage_io_failed", decision, undefined, { cause: error });
}

/** One accepted operation at a time; callback closure revokes authority before drain. */
class Lifetime {
  open = true;
  decision: SdwDecision = "none";
  aborted = false;
  private pending: Promise<unknown> | undefined;
  private failed = false;
  private error: unknown;
  constructor(private readonly check: () => Promise<void>) {}
  accept<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.open || invocation.getStore() !== this) return Promise.reject(failure("storage_scope_invalid", this.decision));
    if (this.pending) return Promise.reject(failure("storage_busy", this.decision));
    const work = (async () => {
      await this.check();
      // Cancellation during the binding check must not admit new effects.
      if (!this.open) throw failure("storage_scope_invalid", this.decision);
      try { return await operation(); }
      finally { await this.check(); }
    })();
    this.pending = work;
    // Attach rejection handling even when the caller detaches its accepted I/O.
    void work.then(() => { this.pending = undefined; }, error => {
      this.failed = true; this.error = error; this.open = false; this.pending = undefined;
    });
    return work;
  }
  async run<T>(operation: () => Promise<T>): Promise<T> {
    let value!: T;
    let failed = false;
    let error: unknown;
    try { value = await invocation.run(this, operation); }
    catch (cause) { failed = true; error = cause; }
    finally {
      this.open = false;
      // Accepted work owns capacity and locks until it settles, even after abort.
      await this.pending?.catch(() => {});
    }
    if (failed || this.failed) throw preserve(failed ? error : this.error, this.decision);
    if (this.aborted) throw failure("operation_aborted", this.decision);
    return value;
  }
}

/** Install one required private observer for this backend; duplicate installation refuses. */
export function installSdwFence(storage: StorageBackend, port: SdwFencePort): SdwFence {
  if (fences.has(storage) || !port || !port.binding || typeof port.observe !== "function" ||
      typeof port.assertBinding !== "function" || typeof port.withFence !== "function" ||
      typeof port.mutationDirectory !== "function") throw failure("storage_capability_unavailable");
  const fence = new SdwFence(port);
  fences.set(storage, fence);
  ports.set(fence, port);
  return fence;
}
/** Internal admission lookup; absence never grants access to an existing journal. */
export function installedSdwFence(storage: StorageBackend): SdwFence | undefined { return fences.get(storage); }

// Must match ROTATION_JOURNAL_KEY in core/master-custody.ts; the full-set
// preflight test pins parity without importing the higher custody layer.
export const SDW_ROTATION_JOURNAL_KEY = "rotation-journal";

/** The sole token mint acquires real Exit admission and checks both journals first. */
export async function withSdwJournalAdmission<T>(storage: StorageBackend,
  operation: (token: SdwAdmissionToken) => Promise<T>): Promise<T> {
  if (invocation.getStore() || readScope.getStore()) throw failure("storage_scope_invalid");
  let acquired = false;
  try {
    return await withCrossProcessLock(storage, EXIT_IMPORT_JOURNAL_NAMESPACE, EXIT_ADMISSION_LOCK_FILE, async lease => {
      acquired = true;
      try {
        if ((await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).length > 0) {
          const error = failure("storage_recovery_pending");
          error.message = "Exit recovery is pending. Run `sanctuary exit recover --fortress <fortress path>` before SDW admission.";
          throw error;
        }
        if (await storage.read("_meta", SDW_ROTATION_JOURNAL_KEY) !== null) {
          const error = failure("storage_recovery_pending");
          error.message = "Master rotation is pending. Run `sanctuary rotate-master --resume` before SDW admission.";
          throw error;
        }
      } catch (cause) {
        if (cause instanceof SdwStorageError) throw cause;
        throw new SdwStorageError("storage_capability_unavailable", "none", undefined, { cause });
      }
      const fence = fences.get(storage);
      const port = fence && ports.get(fence);
      if (!fence || !port) throw failure("storage_capability_unavailable");
      lease.assertHeld();
      await port.assertBinding();
      const lifetime = new Lifetime(async () => { lease.assertHeld(); await port.assertBinding(); });
      const token = Object.freeze({}) as SdwAdmissionToken;
      tokens.set(token, { fence, lifetime, lease });
      try { return await lifetime.run(() => operation(token)); }
      finally { tokens.delete(token); }
    }, { timeoutMs: 0, metadata: { owner: "sdw_journal", pid: process.pid } });
  } catch (error) {
    if (!acquired && error instanceof CrossProcessLockError && error.kind === "contention") {
      throw new ExitAdmissionLockError("SDW admission is busy. Inspect the Exit admission lock only after confirming its holder has stopped; never remove a live holder's lock.");
    }
    throw error;
  }
}

/** Independent guard model. Raw filesystem methods are wired in the later filesystem packet. */
export class SdwFence {
  constructor(private readonly port: SdwFencePort) {}

  private async observe(): Promise<SdwObservation> {
    let observation: SdwObservation;
    try { await this.port.assertBinding(); observation = await this.port.observe(); }
    catch (cause) {
      if (cause instanceof SdwStorageError) throw cause;
      throw new SdwStorageError("storage_capability_unavailable", "none", undefined, { cause });
    }
    const decision = observation.state === "COMMIT" || observation.state === "APPLIED" || observation.state === "RETIRED"
      ? "committed" : observation.decision;
    try {
      if (observation.binding !== this.port.binding) throw failure("storage_holder_lost", decision);
      const generation = observation.generation === null ? null
        : sdwGenerationSchema.parse(observation.generation);
      if (!["ABSENT", "CLEAN", "BUILDING", "PREPARED", "COMMIT", "APPLIED", "RETIRED", "INVALID"].includes(observation.state) ||
          !["none", "unknown", "committed"].includes(decision) ||
          (observation.state === "ABSENT" && generation !== null) ||
          (observation.state === "CLEAN" && generation?.phase !== "CLEAN")) throw failure("storage_plan_invalid", decision);
      // Snapshot caller-owned observation bytes before any later await can mutate them.
      return { ...observation, generation, decision };
    } catch (cause) { throw preserve(cause instanceof SdwStorageError ? cause : new SdwStorageError("storage_plan_invalid", decision, undefined, { cause }), decision); }
  }

  private assertReadable(observation: SdwObservation, namespaces: readonly Namespace[]): void {
    if (observation.state === "INVALID") throw new SdwStorageError("storage_plan_invalid", observation.decision, observation.generation?.transaction_id ?? undefined);
    const mask = observation.generation?.affected_mask || ALL_MASK;
    const affected = namespaces.some(ns => (mask & (1 << SDW_JOURNAL_NAMESPACES.indexOf(ns))) !== 0);
    if (!affected) return;
    if (["BUILDING", "PREPARED", "COMMIT"].includes(observation.state) ||
        (["APPLIED", "RETIRED"].includes(observation.state) && observation.generation?.phase !== observation.state)) {
      const error = new SdwStorageError("storage_recovery_pending", observation.decision, observation.generation?.transaction_id ?? undefined);
      error.message = "SDW recovery is pending. This build has no SDW recovery command; use the storage recovery API. Exit recovery does not clear this state.";
      throw error;
    }
  }

  private same(a: SdwObservation, b: SdwObservation, namespaces: readonly Namespace[]): boolean {
    if (a.binding !== b.binding) return false;
    if (a.state === "ABSENT" || b.state === "ABSENT") return a.state === b.state;
    return namespaces.every(ns => a.generation?.epochs[ns] !== undefined &&
      a.generation.epochs[ns] === b.generation?.epochs[ns]);
  }

  /** A pure read/list/exists may retry twice; candidates never escape changing epochs. */
  async read<T>(namespace: Namespace, operation: () => Promise<T>): Promise<T> {
    this.namespaces([namespace]);
    const scope = readScope.getStore();
    if (scope && (!scope.open || scope.fence !== this || scope.pending)) throw failure("storage_scope_invalid");
    const work = this.readAttempts(namespace, operation);
    if (scope) {
      scope.pending = work;
      // A detached call cannot outlive the scope or become an unhandled rejection.
      void work.then(() => { scope.pending = undefined; }, () => { scope.pending = undefined; });
    }
    return work;
  }

  private async readAttempts<T>(namespace: Namespace, operation: () => Promise<T>): Promise<T> {
    let decision: SdwDecision = "none";
    try {
      for (let attempt = 0; attempt <= SDW_READ_RETRIES; attempt++) {
        try {
          const before = await this.observe();
          decision = strongest(decision, before.decision);
          this.assertReadable(before, [namespace]);
          const value = await operation();
          const after = await this.observe();
          decision = strongest(decision, after.decision);
          this.assertReadable(after, [namespace]);
          if (readScope.getStore()?.open === false) throw failure("storage_scope_invalid", decision);
          if (this.same(before, after, [namespace])) return value;
        } catch (cause) {
          if (!(cause instanceof SdwStorageError) || cause.reason !== "storage_busy") throw cause;
          decision = strongest(decision, cause.decision);
        }
      }
      throw failure("storage_busy", decision);
    } catch (cause) { throw preserve(cause, decision); }
  }

  /** A multi-read callback runs once; movement or detached work refuses its whole result. */
  async withReadScope<T>(operation: () => Promise<T>): Promise<T> {
    if (readScope.getStore() || invocation.getStore()) throw failure("storage_scope_invalid");
    const before = await this.observe();
    this.assertReadable(before, SDW_JOURNAL_NAMESPACES);
    const scope: { fence: SdwFence; open: boolean; pending?: Promise<unknown> } = { fence: this, open: true };
    try {
      const value = await readScope.run(scope, operation);
      // Close immediately on callback return, before any post-observation await.
      scope.open = false;
      if (scope.pending) throw failure("storage_scope_invalid", before.decision);
      const after = await this.observe();
      this.assertReadable(after, SDW_JOURNAL_NAMESPACES);
      if (!this.same(before, after, SDW_JOURNAL_NAMESPACES)) throw failure("storage_busy", after.decision);
      return value;
    } catch (cause) { throw preserve(cause, before.decision); }
    finally { scope.open = false; await scope.pending?.catch(() => {}); }
  }

  /** Ordinary mutations use only the existing plain namespace interlock, never the fence. */
  async mutate<T>(namespace: Namespace, operation: () => Promise<T>): Promise<T> {
    this.namespaces([namespace]);
    if (readScope.getStore() || invocation.getStore()) throw failure("storage_scope_invalid");
    return withPathLock(this.port.mutationDirectory(namespace), SDW_NAMESPACE_MUTATION_LOCK, async lease => {
      const before = await this.observe();
      let decision = before.decision;
      try {
        this.assertReadable(before, [namespace]);
        lease.assertHeld();
        const value = await operation();
        // A possibly effective mutation is never replayed after an observation change.
        const after = await this.observe();
        decision = strongest(decision, after.decision);
        this.assertReadable(after, [namespace]);
        if (!this.same(before, after, [namespace])) throw failure("storage_io_failed", decision);
        return value;
      } catch (cause) { throw preserve(cause, decision); }
    }, { timeoutMs: SDW_LOCK_WAIT_MS });
  }

  /** Engine-only one-slot scope. Recovery/retirement may enter an occupied durable slot. */
  async withEngine<T>(token: SdwAdmissionToken, mode: "new" | "recover" | "retire",
    namespaces: readonly Namespace[], signal: AbortSignal | undefined,
    operation: (scope: { accept<T>(io: () => Promise<T>): Promise<T>; observe(): Promise<SdwObservation>;
      drainMutations<T>(publishBusy: () => Promise<T>): Promise<T> }) => Promise<T>): Promise<T> {
    const admission = tokens.get(token);
    if (!admission || admission.fence !== this || !admission.lifetime.open ||
        invocation.getStore() !== admission.lifetime || readScope.getStore()) throw failure("storage_scope_invalid");
    const selected = this.namespaces(namespaces);
    if (!["new", "recover", "retire"].includes(mode)) throw failure("storage_scope_invalid");
    if (engineSlots.has(this.port.binding)) throw failure("storage_busy");
    engineSlots.add(this.port.binding);
    try {
      return await admission.lifetime.accept(() => this.port.withFence(async lease => {
        const lifetime = new Lifetime(async () => {
          admission.lease.assertHeld(); lease.assertHeld(); await this.port.assertBinding();
        });
        const abort = (): void => { lifetime.aborted = true; lifetime.open = false; };
        signal?.addEventListener("abort", abort, { once: true });
        try {
          return await lifetime.run(async () => {
            if (signal?.aborted) throw failure("operation_aborted");
            const initial = await this.observe();
            lifetime.decision = initial.decision;
            if (mode === "new" && initial.state !== "ABSENT" && initial.state !== "CLEAN") throw failure("storage_busy");
            const result = await operation({
              accept: io => lifetime.accept(io),
              observe: () => lifetime.accept(async () => {
                const observation = await this.observe();
                lifetime.decision = strongest(lifetime.decision, observation.decision);
                return observation;
              }),
              drainMutations: publishBusy => lifetime.accept(() => this.drain(selected, publishBusy)),
            });
            if (signal?.aborted) throw failure("operation_aborted", lifetime.decision);
            return result;
          });
        } finally {
          admission.lifetime.decision = strongest(admission.lifetime.decision, lifetime.decision);
          signal?.removeEventListener("abort", abort);
        }
      }));
    } finally { engineSlots.delete(this.port.binding); }
  }

  /** A1: classify without creating a fence scaffold; acquired Exit admission excludes engines. */
  async preflight(namespaces: readonly Namespace[], admission: CrossProcessLockLease): Promise<void> {
    const selected = this.namespaces(namespaces);
    admission.assertHeld();
    this.assertReadable(await this.observe(), selected);
    admission.assertHeld();
  }

  private namespaces(namespaces: readonly Namespace[]): Namespace[] {
    if (!namespaces.length || namespaces.length > SDW_JOURNAL_NAMESPACES.length ||
        new Set(namespaces).size !== namespaces.length ||
        namespaces.some(ns => !SDW_JOURNAL_NAMESPACES.includes(ns))) throw failure("storage_scope_invalid");
    return [...namespaces].sort((a, b) => encodeFilesystemStorageName(a) < encodeFilesystemStorageName(b) ? -1 : 1);
  }
  private async drain<T>(namespaces: readonly Namespace[], operation: () => Promise<T>, index = 0): Promise<T> {
    if (index === namespaces.length) return operation();
    return withPathLock(this.port.mutationDirectory(namespaces[index]!), SDW_NAMESPACE_MUTATION_LOCK,
      () => this.drain(namespaces, operation, index + 1), { timeoutMs: SDW_LOCK_WAIT_MS });
  }
}
