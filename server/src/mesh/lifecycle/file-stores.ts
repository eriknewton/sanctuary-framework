/**
 * Disk-backed NodeKeyStore + CounterStore (WP-MVP-3 follow-up #2 pairing item).
 *
 * In-memory implementations ship in `cocoon-binding.ts` and `counters.ts` for
 * tests. Production libp2p nodes MUST survive process restart with:
 *
 *   - The per-node Ed25519 private key re-derivable (stored as a cocoon-
 *     wrapped AES-256-GCM blob under `AAD = "node:<node_id>"`, matching the
 *     Q8 binding that `cocoon-binding.ts` establishes). A lost key means the
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
 * via `cocoon-binding.ts`.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EncryptedPayload } from "../../core/encryption.js";
import type { CounterName, CounterStore, NodeKeyStore } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// FileNodeKeyStore — per-node Ed25519 private key at-rest wrap
// ═══════════════════════════════════════════════════════════════════════

/**
 * File-backed NodeKeyStore. Stores the cocoon-wrapped `EncryptedPayload` as
 * a JSON file per node_id under the fortress directory. The wrap itself uses
 * AAD `"node:<node_id>"` (see `wrapNodePrivateKey` in cocoon-binding.ts),
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
      const parsed = JSON.parse(bytes) as Partial<Record<CounterName, number>>;
      for (const [name, v] of Object.entries(parsed)) {
        if (typeof v === "number" && Number.isInteger(v) && v >= 0) {
          this.values.set(name as CounterName, v);
        }
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
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(
        `FileCounterStore.set: value must be non-negative integer; got ${value}`
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
    // Lazily-imported sync-fs functions; avoids the top-level cost when
    // tests construct but never write.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fss = require("node:fs") as typeof import("node:fs");
    const tmp = this.file + ".tmp";
    const snapshot: Record<string, number> = {};
    for (const [k, v] of this.values) snapshot[k] = v;
    const bytes = JSON.stringify(snapshot);
    const fd = fss.openSync(tmp, "w", 0o600);
    try {
      fss.writeFileSync(fd, bytes, { encoding: "utf8" });
      fss.fsyncSync(fd);
    } finally {
      fss.closeSync(fd);
    }
    fss.renameSync(tmp, this.file);
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
