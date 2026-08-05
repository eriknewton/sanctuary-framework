/**
 * Register C6 (Mini2, 2026-08-05): a live append read as tail truncation.
 *
 * On the production host every `flow_decision_recorded` was refused with
 * `audit head anchor floor N exceeds highest surviving sequence N-1 (tail
 * truncation or replay detected)` while the store on disk was intact. These
 * tests drive the real `AuditLog` against a real `FilesystemStorage` and pin
 * the two ordering properties that made a healthy writer look like an attacker:
 *
 *   1. the head anchor is sampled BEFORE the entry listing (an append writes its
 *      entry file first and its anchor second, so any other order lets an append
 *      that lands mid-pass raise a floor the just-taken listing cannot reach);
 *   2. a first pass that finds a tear always gets a second look, even when that
 *      one pass already outlived the read-consistency budget.
 *
 * The storage wrapper below is a real backend with a hook, not a stub: every
 * read, write, and listing goes to the real filesystem. The hook only decides
 * WHEN a concurrent event lands relative to the pass, which is the whole
 * mechanism under test.
 */
import { mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";

const MASTER_KEY = () => generateRandomKey();

/**
 * Longer than `AUDIT_READ_CONSISTENCY_MAX_MS` (2_000) in
 * `src/operational/audit-log.ts`, so ONE pass spends the entire read-consistency
 * budget. That is the ordinary case on a production chain, not a contrivance:
 * the eager-read backstop note in that file measures a single full pass at
 * 11-30s on a 10k-entry chain, and the host in register C6 carries ~166k.
 * 2_100 = the 2_000ms budget plus a 100ms margin for scheduling jitter.
 */
const ONE_PASS_OUTLIVES_THE_BUDGET_MS = 2_100;

async function appendCritical(log: AuditLog, operation: string): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: "id-1",
    result: "success",
    details: { operation },
  });
}

/** On-disk `.enc` files of the `_audit` namespace, in key order. */
async function auditEntryFiles(storage: FilesystemStorage): Promise<string[]> {
  const dir = storage.namespacePath("_audit");
  const files = await readdir(dir);
  return files
    .filter((file) => file.endsWith(".enc"))
    .sort()
    .map((file) => join(dir, file));
}

/**
 * Real `FilesystemStorage`, with hooks that fire around the FIRST full `_audit`
 * listing of a verification pass. `beforeList` lands a concurrent mutation the
 * pass will see; `afterList` lands one it will not, and stalls the pass so it
 * outlives the read-consistency budget.
 */
class HookedAuditListing implements StorageBackend {
  auditListCalls = 0;
  constructor(
    private readonly inner: FilesystemStorage,
    private readonly hooks: {
      beforeFirstList?: () => Promise<void>;
      afterFirstList?: () => Promise<void>;
      stallAfterFirstListMs?: number;
    }
  ) {}
  async write(ns: string, key: string, data: Uint8Array): Promise<void> {
    return this.inner.write(ns, key, data);
  }
  async read(ns: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(ns, key);
  }
  async delete(ns: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    return this.inner.delete(ns, key, secureOverwrite);
  }
  async list(ns: string, prefix?: string): Promise<StorageEntryMeta[]> {
    // Only the unprefixed `_audit` listing starts a verification pass; the
    // `entry-`-prefixed one is the append path's O(1) tail scan.
    const isPassListing = ns === "_audit" && prefix === undefined;
    if (isPassListing) {
      this.auditListCalls += 1;
      if (this.auditListCalls === 1) await this.hooks.beforeFirstList?.();
    }
    const result = await this.inner.list(ns, prefix);
    if (isPassListing && this.auditListCalls === 1) {
      await this.hooks.afterFirstList?.();
      if (this.hooks.stallAfterFirstListMs !== undefined) {
        await new Promise((resolve) =>
          setTimeout(resolve, this.hooks.stallAfterFirstListMs)
        );
      }
    }
    return result;
  }
  async exists(ns: string, key: string): Promise<boolean> {
    return this.inner.exists(ns, key);
  }
  async totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
  namespacePath(ns: string): string {
    return this.inner.namespacePath(ns);
  }
}

describe("AuditLog read-vs-append ordering (register C6)", () => {
  it("does not report a live append as tail truncation", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-c6-anchor-"));
    try {
      const storage = new FilesystemStorage(join(root, "state"));
      const masterKey = MASTER_KEY();
      const writer = new AuditLog(storage, masterKey, {});
      for (let i = 0; i < 5; i++) await appendCritical(writer, `seed-${i}`);
      await writer.flush();

      // One genuine append lands after the pass has listed the entries. The
      // store stays fully intact: nothing is deleted, edited, or rolled back.
      const reader = new AuditLog(
        new HookedAuditListing(storage, {
          afterFirstList: async () => {
            await appendCritical(writer, "lands-after-the-listing");
          },
          stallAfterFirstListMs: ONE_PASS_OUTLIVES_THE_BUDGET_MS,
        }),
        masterKey,
        {}
      );

      expect(await reader.getIntegrityFindings()).toEqual([]);
      // Corroboration that the store was never actually damaged: an
      // uninstrumented reader over the same bytes agrees.
      const quiet = new AuditLog(storage, masterKey, {});
      expect(await quiet.getIntegrityFindings()).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("still fails closed when the tail is genuinely truncated mid-pass", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-c6-truncation-"));
    try {
      const storage = new FilesystemStorage(join(root, "state"));
      const masterKey = MASTER_KEY();
      const writer = new AuditLog(storage, masterKey, {});
      for (let i = 0; i < 5; i++) await appendCritical(writer, `seed-${i}`);
      await writer.flush();

      // The anti-truncation guard must keep firing when the tail really is
      // removed while a pass is running: earlier anchor sampling must not be a
      // way to launder a deletion.
      const files = await auditEntryFiles(storage);
      const reader = new AuditLog(
        new HookedAuditListing(storage, {
          beforeFirstList: async () => {
            await unlink(files.at(-1)!);
          },
          stallAfterFirstListMs: ONE_PASS_OUTLIVES_THE_BUDGET_MS,
        }),
        masterKey,
        {}
      );

      expect(await reader.getIntegrityFindings()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "tail_anchor_invalid" }),
        ])
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("gives a healed tear a second look even when one pass spends the whole budget", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-c6-retry-"));
    try {
      const storage = new FilesystemStorage(join(root, "state"));
      const masterKey = MASTER_KEY();
      const writer = new AuditLog(storage, masterKey, {});
      for (let i = 0; i < 5; i++) await appendCritical(writer, `seed-${i}`);
      await writer.flush();

      // A mid-chain entry is momentarily absent from the first listing and is
      // back, byte-for-byte, before the second one: the transient tear shape the
      // read-consistency retry exists for (a prune caught mid-flight).
      const files = await auditEntryFiles(storage);
      const torn = files[2]!;
      const tornBytes = await readFile(torn);
      const hooked = new HookedAuditListing(storage, {
        beforeFirstList: async () => {
          await unlink(torn);
        },
        afterFirstList: async () => {
          await writeFile(torn, tornBytes, { mode: 0o600 });
        },
        stallAfterFirstListMs: ONE_PASS_OUTLIVES_THE_BUDGET_MS,
      });
      const reader = new AuditLog(hooked, masterKey, {});

      expect(await reader.getIntegrityFindings()).toEqual([]);
      // The clean verdict came from a SECOND pass, not from a lenient first one.
      expect(hooked.auditListCalls).toBeGreaterThanOrEqual(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);
});
