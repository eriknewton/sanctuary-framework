/**
 * In-process backend with the strict lock and strict writes the local stores
 * require. Locks are exclusive per (namespace, lock name), strict writes
 * refuse outside their namespace's lock, acquiring the results lock inside
 * the operator-log lock is refused, and the acquire wait uses an injected
 * timer so a timeout test never sleeps.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { MemoryStorage } from "../../../src/storage/memory.js";
import {
  CROSS_PROCESS_LOCK_TIMEOUT_MS,
  CrossProcessLockError,
  type CrossProcessLockLease,
} from "../../../src/storage/cross-process-lock.js";
import type { NamespaceLockOptions } from "../../../src/storage/interface.js";
import { LOCAL_OPLOG_NAMESPACE, LOCAL_RESULTS_NAMESPACE } from "../../../src/local-recompile/store-record.js";

export interface StorageCall {
  op: "lock" | "unlock" | "read" | "write" | "create" | "delete";
  namespace: string;
  key?: string;
}

export class StrictMemoryStorage extends MemoryStorage {
  readonly calls: StorageCall[] = [];
  /** Resolves when an acquire wait of `ms` has elapsed; tests replace it to control time. */
  acquireWait: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  /** Runs before every strict write or delete; a test can throw or stall here. */
  beforeMutation: (call: StorageCall) => void | Promise<void> = () => undefined;
  private readonly held = new Map<string, Promise<void>>();
  private readonly scope = new AsyncLocalStorage<readonly string[]>();

  async withStrictNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: (lease: CrossProcessLockLease) => Promise<T>,
    options: NamespaceLockOptions = {},
  ): Promise<T> {
    if (options.kernelBacked !== true) throw new Error("fixture requires the kernel-backed option");
    const outer = this.scope.getStore() ?? [];
    if (namespace === LOCAL_RESULTS_NAMESPACE && outer.includes(LOCAL_OPLOG_NAMESPACE)) {
      throw new Error("fixture lock order violated");
    }
    const identity = `${namespace}\u0000${lockFileName}`;
    for (;;) {
      const current = this.held.get(identity);
      if (current === undefined) break;
      const timedOut = Symbol("timeout");
      const winner = await Promise.race([
        current.then(() => undefined),
        this.acquireWait(options.timeoutMs ?? CROSS_PROCESS_LOCK_TIMEOUT_MS).then(() => timedOut),
      ]);
      if (winner === timedOut) throw new CrossProcessLockError("fixture lock contended", "contention");
    }
    let release!: () => void;
    this.held.set(identity, new Promise<void>((resolve) => { release = resolve; }));
    this.calls.push({ op: "lock", namespace });
    const controller = new AbortController();
    try {
      return await this.scope.run([...outer, namespace], () =>
        operation({ signal: controller.signal, assertHeld: () => undefined }),
      );
    } finally {
      this.calls.push({ op: "unlock", namespace });
      this.held.delete(identity);
      release();
    }
  }

  private requireHeld(namespace: string): void {
    if (!(this.scope.getStore() ?? []).includes(namespace)) throw new Error("fixture strict write outside its lock");
  }

  async writeStrict(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.requireHeld(namespace);
    const call: StorageCall = { op: "write", namespace, key };
    await this.beforeMutation(call);
    this.calls.push(call);
    await super.write(namespace, key, data);
  }

  async writeIfAbsentStrict(namespace: string, key: string, data: Uint8Array): Promise<boolean> {
    this.requireHeld(namespace);
    const call: StorageCall = { op: "create", namespace, key };
    await this.beforeMutation(call);
    this.calls.push(call);
    return super.writeIfAbsent(namespace, key, data);
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    const call: StorageCall = { op: "delete", namespace, key };
    await this.beforeMutation(call);
    this.calls.push(call);
    return super.delete(namespace, key);
  }

  async readBounded(namespace: string, key: string, maxBytes: number): Promise<Uint8Array | null> {
    this.calls.push({ op: "read", namespace, key });
    return super.readBounded(namespace, key, maxBytes);
  }
}

/** Fresh random store keys; the caller zeroes them. */
export function fixtureStoreKeys(): { oplogKey: Uint8Array; resultsKey: Uint8Array } {
  const STORE_KEY_BYTES = 32; // AES-256 key size
  return {
    oplogKey: crypto.getRandomValues(new Uint8Array(STORE_KEY_BYTES)),
    resultsKey: crypto.getRandomValues(new Uint8Array(STORE_KEY_BYTES)),
  };
}

/** A distinct 32-hex request id for fixture index `n`. */
export function fixtureRequestId(n: number): string {
  const REQUEST_ID_HEX = 32; // 128 bits as hex
  return n.toString(16).padStart(REQUEST_ID_HEX, "0");
}

// A fixed 32-hex seat id (an identity id shape).
export const FIXTURE_SEAT = "ab".repeat(16);
