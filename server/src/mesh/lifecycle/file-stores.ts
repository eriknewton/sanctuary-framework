/**
 * Disk-backed NodeKeyStore + CounterStore (WP-MVP-3 follow-up #2 pairing item).
 *
 * In-memory implementations ship in `node-key-binding.ts` and `counters.ts` for
 * tests. Production libp2p nodes MUST survive process restart with:
 *
 *   - The per-node Ed25519 private key re-derivable (stored as a master-key-
 *     wrapped AES-256-GCM blob under `AAD = "node:<node_id>"`, matching the
 *     Q8 binding that `node-key-binding.ts` establishes). A lost key means the
 *     node cannot re-authenticate to the mesh; a silently-recreated key means
 *     the peer-id shifts, which the remote noise handshake rejects.
 *
 *   - Monotonic counters persisted fsync-before-ack. A counter resetting
 *     across restart is indistinguishable from a rolled-back node per §8.3;
 *     the canonical audit node drops the resulting events, visible to the
 *     operator as "rollback detected" alerts on a benign restart. fsync is
 *     the defense.
 *
 * Both stores live under the fortress config directory (caller-supplied
 * path). Filenames include the node_id so a single directory can host multiple
 * test nodes without collision — this matches how operator deployments
 * typically run one fortress per directory but lets the test suite boot
 * three in one `tmpdir`.
 *
 * Spec: §2.2, §3.5, §8.3. Hard rules: no Concordia imports, crypto reuse
 * via `node-key-binding.ts`.
 */

import {
  promises as fs,
  closeSync,
  fsyncSync,
  openSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import * as path from "node:path";
import type { EncryptedPayload } from "../../core/encryption.js";
import type { CounterName, CounterStore, NodeKeyStore } from "./types.js";
import { COUNTER_NAMES, wouldOverflowOnNext } from "./counters.js";

// ═══════════════════════════════════════════════════════════════════════
// FileNodeKeyStore — per-node Ed25519 private key at-rest wrap
// ═══════════════════════════════════════════════════════════════════════

/**
 * File-backed NodeKeyStore. Stores the master-key-wrapped `EncryptedPayload` as
 * a JSON file per node_id under the fortress directory. The wrap itself uses
 * AAD `"node:<node_id>"` (see `wrapNodePrivateKey` in node-key-binding.ts),
 * which is what prevents an attacker who reads the file off one disk from
 * substituting it onto a different node.
 *
 * File naming: `{dir}/nodekey-{nodeId}.enc.json`.
 * File permissions: 0o600 on write (owner-only read/write).
 */
export class FileNodeKeyStore implements NodeKeyStore {
  constructor(private readonly dir: string) {}

  /**
   * Make sure the backing directory exists with safe perms. Idempotent.
   * Call once at MeshNode boot before `save` / `load`.
   */
  async init(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
  }

  async save(nodeId: string, wrapped: EncryptedPayload): Promise<void> {
    assertSafeNodeId(nodeId);
    const file = this.path(nodeId);
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    const payload = JSON.stringify(wrapped);
    // Write to a tmp file, fsync, then rename — avoids torn writes if the
    // process dies mid-save.
    const tmp = file + ".tmp";
    const fh = await fs.open(tmp, "w", 0o600);
    try {
      await fh.writeFile(payload, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fs.rename(tmp, file);
  }

  async load(nodeId: string): Promise<EncryptedPayload | null> {
    assertSafeNodeId(nodeId);
    try {
      const bytes = await fs.readFile(this.path(nodeId), "utf8");
      return JSON.parse(bytes) as EncryptedPayload;
    } catch (e) {
      if (isNotFound(e)) return null;
      throw e;
    }
  }

  async remove(nodeId: string): Promise<void> {
    assertSafeNodeId(nodeId);
    try {
      await fs.unlink(this.path(nodeId));
    } catch (e) {
      if (isNotFound(e)) return;
      throw e;
    }
  }

  private path(nodeId: string): string {
    return path.join(this.dir, `nodekey-${nodeId}.enc.json`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// FileCounterStore — monotonic counters, fsync-before-ack
// ═══════════════════════════════════════════════════════════════════════

/**
 * File-backed CounterStore. All counters for a single node live in one JSON
 * file (`counters-{nodeId}.json`). Every write is fsync'd before returning
 * so a crash between "bumped in memory" and "flushed to disk" cannot result
 * in the post-restart value being lower than a value already observed by the
 * mesh.
 *
 * Strict-advance guarantee: `set(name, value)` rejects any value strictly
 * less than the on-disk prior, matching `InMemoryCounterStore.set`.
 *
 * Boot discipline: callers MUST `await init()` before the first `next/peek/
 * set` — init loads the on-disk state and primes the in-memory cache. After
 * that every `next` is synchronous (sync fsync still happens asynchronously
 * in the background; see `next` doc).
 */
export class FileCounterStore implements CounterStore {
  private readonly values = new Map<CounterName, number>();
  private file: string;
  private loaded = false;

  constructor(private readonly dir: string, nodeId: string) {
    assertSafeNodeId(nodeId);
    this.file = path.join(dir, `counters-${nodeId}.json`);
  }

  /**
   * Load existing counter state from disk into the in-memory cache.
   * Creates the backing directory if missing. Idempotent.
   */
  async init(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    try {
      const bytes = await fs.readFile(this.file, "utf8");
      const parsed: unknown = JSON.parse(bytes);

      // Fail CLOSED on a present-but-malformed store. A genuine persisted store
      // is always a non-empty plain object (every next()/set() persists the
      // full snapshot, which carries at least the one counter just touched).
      // A present file that parses to a primitive, an array, or an empty object
      // is therefore corruption/truncation/tampering — NOT a clean first boot.
      // Only an absent store (ENOENT, handled below) starts clean. Booting such
      // a file would let every real counter resolve via `?? 0` and RESTART at 0
      // — the exact rollback the counter exists to detect (§8.3).
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        throw new Error(
          `FileCounterStore.init: persisted store is not a counter object ` +
            `(${JSON.stringify(parsed)}); refusing to start — a reset counter ` +
            `is indistinguishable from a rolled-back node (§8.3). The store at ` +
            `${this.file} may be corrupt or tampered.`
        );
      }
      const entries = Object.entries(parsed as Record<string, unknown>);
      if (entries.length === 0) {
        throw new Error(
          `FileCounterStore.init: persisted store is empty; refusing to start ` +
            `— an empty store is indistinguishable from a wiped/rolled-back ` +
            `node (§8.3). The store at ${this.file} may be corrupt or tampered.`
        );
      }

      for (const [name, v] of entries) {
        // Fail CLOSED on any present-but-invalid persisted counter, including
        // an unknown/tampered key. A bogus key (e.g. a renamed or stale field)
        // that carries a value while the real counters default to 0 is itself a
        // silent reset and must halt the boot.
        if (!COUNTER_NAMES.has(name as CounterName)) {
          throw new Error(
            `FileCounterStore.init: persisted store has unknown counter key ` +
              `${JSON.stringify(name)}; refusing to start — an unrecognized ` +
              `field is a corruption/tamper signal (§8.3). The store at ` +
              `${this.file} may be corrupt or tampered.`
          );
        }
        if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
          throw new Error(
            `FileCounterStore.init: persisted counter ${name} is invalid ` +
              `(${JSON.stringify(v)}); refusing to start — a reset counter is ` +
              `indistinguishable from a rolled-back node (§8.3). The store at ` +
              `${this.file} may be corrupt or tampered.`
          );
        }
        this.values.set(name as CounterName, v);
      }
    } catch (e) {
      if (!isNotFound(e)) throw e;
    }
    this.loaded = true;
  }

  /**
   * Atomic bump + persist. The prior-value return is what the caller
   * embeds in an envelope; the increment-and-persist must land before
   * any caller acts on the returned value. We therefore synchronously
   * write-to-tmp + rename via blocking fsync in-line — the persisted
   * value is always ≥ any value the caller has observed.
   *
   * CounterStore's base contract is synchronous, matching `InMemoryCounterStore`.
   * We retain that by using `fs.*Sync` for the on-disk commit here; the tests
   * that pipe large volumes of audit entries through can still saturate fsync
   * throughput, but correctness does not depend on async scheduling.
   */
  next(name: CounterName): number {
    this.requireLoaded();
    const current = this.values.get(name) ?? 0;
    if (wouldOverflowOnNext(current)) {
      // Refuse to cross 2^53: see InMemoryCounterStore.next. Past the safe-
      // integer ceiling, current + 1 collides onto an already-issued value
      // (§8.3), and the persisted value would also be rejected by init() on
      // the next restart.
      throw new Error(
        `FileCounterStore.next: ${name} is at the safe-integer ceiling ` +
          `(${current}); refusing to advance — incrementing past 2^53 would ` +
          `collide two sequence values and defeat the rollback canary (§8.3).`
      );
    }
    const nextValue = current + 1;
    this.values.set(name, nextValue);
    this.persistSync();
    return current;
  }

  peek(name: CounterName): number {
    this.requireLoaded();
    return this.values.get(name) ?? 0;
  }

  set(name: CounterName, value: number): void {
    this.requireLoaded();
    // Number.isSafeInteger (not Number.isInteger): see InMemoryCounterStore.set
    // — integers above 2^53 collide under next()'s `current + 1`. Fail closed.
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(
        `FileCounterStore.set: value must be non-negative safe integer; got ${value}`
      );
    }
    const prior = this.values.get(name) ?? 0;
    if (value < prior) {
      throw new Error(
        `FileCounterStore.set: refuses to lower ${name} from ${prior} to ${value} — would appear as rollback to the mesh`
      );
    }
    this.values.set(name, value);
    this.persistSync();
  }

  private requireLoaded(): void {
    if (!this.loaded) {
      throw new Error(
        "FileCounterStore: call await init() before next/peek/set"
      );
    }
  }

  private persistSync(): void {
    // Pure-ESM: use the top-level static imports. The prior `require("node:fs")`
    // pattern silently broke under `npx tsx` / real Node.js ESM runtimes
    // — vitest's module wrapper polyfilled `require` but nothing else did,
    // so the pilot onboarding script failed at `emitHeartbeat` on every
    // counter persist.
    const tmp = this.file + ".tmp";
    const snapshot: Record<string, number> = {};
    for (const [k, v] of this.values) snapshot[k] = v;
    const bytes = JSON.stringify(snapshot);
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeFileSync(fd, bytes, { encoding: "utf8" });
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.file);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

/**
 * Defend against nodeId strings that would escape the target directory.
 * Sanctuary nodeIds are 128-bit hex (see `generateFortressId`) but the
 * store takes operator input, so we belt-and-braces on path-traversal.
 */
function assertSafeNodeId(nodeId: string): void {
  if (!/^[A-Za-z0-9_-]+$/.test(nodeId)) {
    throw new Error(
      `file-stores: nodeId contains unsafe characters: ${JSON.stringify(nodeId)}`
    );
  }
}

function isNotFound(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    (e as { code?: string }).code === "ENOENT"
  );
}
