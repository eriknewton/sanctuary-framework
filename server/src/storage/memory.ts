/**
 * Sanctuary MCP Server — In-Memory Storage Backend
 *
 * Used for testing. Implements the same interface as filesystem storage
 * but stores everything in memory. Data does not persist across restarts.
 */

import type {
  NamespaceLockStorageCapabilities,
  StorageBackend,
  StorageEntryMeta,
} from "./interface.js";
import type {
  CrossProcessLockLease,
  CrossProcessLockOptions,
} from "./cross-process-lock.js";
import { constantTimeEqual } from "../core/encoding.js";
import { assertSdwRawWriteAuthorized } from "../sdw/write-gate.js";
import { SdwValidationError } from "../sdw/errors.js";
import { NAMESPACE_DISCOVERY_LIMIT_REMEDIATION, MAX_DISCOVERED_NAMESPACES } from "./interface.js";
import { assertStorageNamespacePathComponent } from "./namespace-component.js";

export class MemoryStorage implements StorageBackend, NamespaceLockStorageCapabilities {
  private store = new Map<string, { data: Uint8Array; modified_at: string }>();
  // Composite store keys are `${namespace}/${key}` and a namespace may itself
  // contain "/", so live namespaces are tracked explicitly (entry counts)
  // rather than re-parsed out of composite keys.
  private namespaceCounts = new Map<string, number>();
  private namespaceLockTails = new Map<string, Promise<void>>();

  async withNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: (lease: CrossProcessLockLease) => Promise<T>,
    options: CrossProcessLockOptions = {},
  ): Promise<T> {
    assertStorageNamespacePathComponent(namespace);
    const identity = `${namespace.length}:${namespace}${lockFileName}`;
    const predecessor = this.namespaceLockTails.get(identity) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const tail = predecessor.catch(() => undefined).then(() => gate);
    this.namespaceLockTails.set(identity, tail);
    void tail.then(() => {
      // The map retains this tail until both the predecessor and this waiter's
      // gate settle, so an aborting waiter cannot hide a still-held namespace.
      if (this.namespaceLockTails.get(identity) === tail) {
        this.namespaceLockTails.delete(identity);
      }
    });
    const controller = new AbortController();
    try {
      // The tail is published before waiting so later callers chain behind this
      // waiter; abort still releases the gate so that chain cannot wedge.
      await waitForNamespaceLockTurn(predecessor.catch(() => undefined), options.abortSignal);
      assertNamespaceLockWaitNotAborted(options.abortSignal);
      return await operation({ signal: controller.signal, assertHeld: () => undefined });
    } finally {
      release();
    }
  }

  private storageKey(namespace: string, key: string): string {
    assertStorageNamespacePathComponent(namespace);
    return `${namespace}/${key}`;
  }

  async writeIfAbsent(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<boolean> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const storageKey = this.storageKey(namespace, key);
    // Deliberately no await between the check and set: this is the in-memory
    // backend's atomic create-if-absent critical section.
    if (this.store.has(storageKey)) return false;
    this.namespaceCounts.set(
      namespace,
      (this.namespaceCounts.get(namespace) ?? 0) + 1,
    );
    this.store.set(storageKey, {
      data: new Uint8Array(checkedData),
      modified_at: new Date().toISOString(),
    });
    return true;
  }

  async replaceIfEquals(
    namespace: string,
    key: string,
    expected: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const storageKey = this.storageKey(namespace, key);
    const current = this.store.get(storageKey);
    // Deliberately no await between the compare and set: this is the
    // in-memory backend's atomic compare-and-replace critical section.
    if (current === undefined || !constantTimeEqual(current.data, expected)) {
      return false;
    }
    this.store.set(storageKey, {
      data: new Uint8Array(checkedData),
      modified_at: new Date().toISOString(),
    });
    return true;
  }

  async write(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const storageKey = this.storageKey(namespace, key);
    if (!this.store.has(storageKey)) {
      this.namespaceCounts.set(
        namespace,
        (this.namespaceCounts.get(namespace) ?? 0) + 1
      );
    }
    this.store.set(storageKey, {
      data: checkedData,
      modified_at: new Date().toISOString(),
    });
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const entry = this.store.get(this.storageKey(namespace, key));
    if (!entry) return null;
    return new Uint8Array(entry.data); // Copy to prevent external mutation
  }

  async delete(
    namespace: string,
    key: string,
    _secureOverwrite?: boolean
  ): Promise<boolean> {
    const deleted = this.store.delete(this.storageKey(namespace, key));
    if (deleted) {
      const count = (this.namespaceCounts.get(namespace) ?? 1) - 1;
      if (count <= 0) {
        this.namespaceCounts.delete(namespace);
      } else {
        this.namespaceCounts.set(namespace, count);
      }
    }
    return deleted;
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    assertStorageNamespacePathComponent(namespace);
    const entries: StorageEntryMeta[] = [];
    const nsPrefix = `${namespace}/`;

    for (const [storeKey, entry] of this.store) {
      if (!storeKey.startsWith(nsPrefix)) continue;
      const key = storeKey.slice(nsPrefix.length);
      if (prefix && !key.startsWith(prefix)) continue;

      entries.push({
        key,
        namespace,
        size_bytes: entry.data.length,
        modified_at: entry.modified_at,
      });
    }

    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.store.has(this.storageKey(namespace, key));
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const entry of this.store.values()) {
      total += entry.data.length;
    }
    return total;
  }

  async listNamespaces(): Promise<string[]> {
    // Must match listNamespaces in interface.ts: refuse before allocating an
    // attacker-sized snapshot; filtering internal names cannot bypass the cap.
    if (this.namespaceCounts.size > MAX_DISCOVERED_NAMESPACES) {
      throw new Error(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
    }
    return [...this.namespaceCounts.keys()].sort();
  }

  /** Clear all stored data (useful in tests) */
  clear(): void {
    this.store.clear();
    this.namespaceCounts.clear();
  }
}

async function waitForNamespaceLockTurn(
  predecessor: Promise<void>,
  signal: AbortSignal | undefined,
): Promise<void> {
  assertNamespaceLockWaitNotAborted(signal);
  if (signal === undefined) {
    await predecessor;
    return;
  }
  let abort: (() => void) | undefined;
  try {
    await Promise.race([
      predecessor,
      new Promise<never>((_resolve, reject) => {
        abort = () => reject(namespaceLockAbortedError());
        signal.addEventListener("abort", abort, { once: true });
      }),
    ]);
  } finally {
    if (abort !== undefined) signal.removeEventListener("abort", abort);
  }
  // A grant that races an abort is still refused; no caller may enter the
  // namespace critical section on a stale bridge shutdown signal.
  assertNamespaceLockWaitNotAborted(signal);
}

function assertNamespaceLockWaitNotAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted !== true) return;
  throw namespaceLockAbortedError();
}

function namespaceLockAbortedError(): SdwValidationError {
  return new SdwValidationError(
    "operation_aborted",
    "namespace lock wait aborted",
  );
}
