/** Exact-byte verification reuse preserves every pass and bounds retained summaries. */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuditIntegrityError,
  BoundedVerificationEntries,
  AUDIT_EAGER_SENTINEL_INTERVAL_MS,
  AUDIT_VERIFY_CACHE_MAX_ENTRIES,
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  computeAuditEntryHash,
} from "../../src/audit/chain.js";


class MtimeStableStorage extends MemoryStorage {
  entryReads = 0;
  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (namespace === "_audit") this.entryReads++;
    return super.read(namespace, key);
  }
  private mtimes = new Map<string, string>();
  override async write(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<void> {
    const composite = `${namespace}/${key}`;
    const prior = (await super.read(namespace, key))?.length;
    await super.write(namespace, key, data);
    // If an entry of identical size already existed, pin mtime back to its prior
    // value so the fingerprint is byte-for-byte preserved across this overwrite.
    if (prior && prior === data.length) {
      const pinned = this.mtimes.get(composite) ?? new Date(0).toISOString();
      this.mtimes.set(composite, pinned);
    }
  }
  override async list(
    namespace: string,
    prefix?: string,
  ): Promise<StorageEntryMeta[]> {
    const metas = await super.list(namespace, prefix);
    return metas.map((m) => {
      const pinned = this.mtimes.get(`${namespace}/${m.key}`);
      return { ...m, modified_at: pinned ?? new Date(0).toISOString() };
    });
  }
}

async function buildChain(
  count: number, config: { verifyCacheMaxEntries?: number; eagerBytePassIntervalMs?: number } = {},
): Promise<{ storage: MtimeStableStorage; masterKey: Uint8Array; reader: AuditLog }> {
  const storage = new MtimeStableStorage();
  const masterKey = generateRandomKey();
  const encryptionKey = derivePurposeKey(masterKey, "audit-log");

  // Write count-1 raw valid envelopes, then one real append for the head anchor.
  const rawCount = Math.max(count - 1, 0);
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (let i = 0; i < rawCount; i++) {
    const sequence = i + 1;
    const timestamp = new Date(Date.now() - (count - sequence) * 1000).toISOString();
    const normalized = {
      timestamp,
      layer: "l1" as const,
      operation: "egress_allowed",
      identity_id: `agent-${i % 4}`,
      result: "success" as const,
      details: { op: i },
    };
    const serialized = stringToBytes(JSON.stringify(normalized));
    const encrypted = encrypt(serialized, encryptionKey);
    const encryptedPayloadBytes = toBase64url(
      stringToBytes(JSON.stringify(encrypted)),
    );
    const entryHash = computeAuditEntryHash({
      sequence,
      prev_hash: prevHash,
      timestamp,
      encrypted_payload_bytes: encryptedPayloadBytes,
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
    });
    const envelope: PersistedAuditEnvelopeV2 = {
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
      sequence,
      prev_hash: prevHash,
      entry_hash: entryHash,
      timestamp,
      encrypted_payload_bytes: encryptedPayloadBytes,
    };
    const key = `entry-${String(sequence).padStart(20, "0")}-fixture-${i}`;
    await storage.write("_audit", key, stringToBytes(JSON.stringify(envelope)));
    prevHash = entryHash;
  }

  // One genuine critical append: it freshens chain state from disk (picking up
  // the raw prefix), chains entry `count` from the real head, and writes a VALID
  // master-MAC'd head anchor + the established marker over the new head. The
  // writer runs in lenient mode ONLY for this bootstrap append: the raw prefix is
  // an established-but-anchorless store (no head anchor written yet), which strict
  // mode would reject before the append can write the anchor. After the append the
  // anchor is valid, so the FRESH strict-mode reader below loads cleanly.
  const writer = new AuditLog(storage, masterKey, {
    checkpointInterval: 0,
    integrityMode: "lenient",
  });
  await writer.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: "agent-tail",
    result: "success",
    details: { op: "tail" },
  });
  await writer.flush();

  const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0, ...config });
  return { storage, masterKey, reader };
}
const BYTE_INTERVAL = 1; // Smallest positive millisecond test cadence.
afterEach(() => vi.restoreAllMocks());
async function rewriteHash(storage: MtimeStableStorage, key: string) {
  const raw = (await storage.read("_audit", key))!;
  const envelope = JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2;
  envelope.entry_hash = (envelope.entry_hash[0] === "a" ? "b" : "a") + envelope.entry_hash.slice(1);
  const changed = stringToBytes(JSON.stringify(envelope));
  expect(changed.length).toBe(raw.length);
  await storage.write("_audit", key, changed);
  return raw;
}
async function eager(reader: AuditLog) {
  return reader.runAllowingIntegrityFindings(() => reader.queryEager({ limit: 100_000 }));
}
describe("entry-byte verification cache", () => {
  it("detects and clears an unchanged-metadata edit at the first byte pass", async () => {
    const { reader, storage } = await buildChain(4, { eagerBytePassIntervalMs: BYTE_INTERVAL });
    let clock = Date.now(); vi.spyOn(Date, "now").mockImplementation(() => clock);
    expect((await eager(reader)).integrity_findings).toEqual([]);
    const before = await storage.list("_audit"); const key = before[1]!.key;
    const raw = await rewriteHash(storage, key);
    expect(await storage.list("_audit")).toEqual(before);
    clock += BYTE_INTERVAL;
    expect((await eager(reader)).integrity_findings.length).toBeGreaterThan(0);
    await storage.write("_audit", key, raw); clock += BYTE_INTERVAL;
    expect((await eager(reader)).integrity_findings).toEqual([]);
  });
  it("never caches failed entries and re-raises their findings on every pass", async () => {
    const { reader, storage } = await buildChain(4, { eagerBytePassIntervalMs: BYTE_INTERVAL });
    await eager(reader);
    const key = (await storage.list("_audit"))[1]!.key;
    await rewriteHash(storage, key);
    const decrypt = vi.spyOn(reader as any, "decryptEntryPayload");
    for (let pass = 0; pass < 3; pass++) {
      decrypt.mockClear();
      const result = await reader.runAllowingIntegrityFindings(() => reader.query({}));
      expect(result.integrity_findings.some(f => f.kind === "entry_hash_mismatch")).toBe(true);
      // A static integrity finding gets two passes: first observation and stability retry.
      expect(decrypt).toHaveBeenCalledTimes(2);
      expect(reader.verificationCacheStats().cached_entries).toBe(3);
    }
  });
  it("reads the whole chain while decrypting exactly the uncached entries and a changed hit", async () => {
    const K = 4, M = 3; // Tiny cap plus three excess entries exercise the production eviction rule.
    const { reader, storage } = await buildChain(K + M, { verifyCacheMaxEntries: K });
    await reader.query({});
    const decrypt = vi.spyOn(reader as any, "decryptEntryPayload");
    storage.entryReads = 0;
    await reader.query({});
    expect(storage.entryReads).toBe(K + M);
    expect(decrypt).toHaveBeenCalledTimes(M);
    expect(reader.verificationCacheStats()).toEqual({ cached_entries: K, cache_cap: K, verified_uncached_last_pass: M });
    const key = (await storage.list("_audit"))[M]!.key;
    // Reordered envelope properties change bytes while preserving the authenticated entry.
    const envelope = JSON.parse(bytesToString((await storage.read("_audit", key))!));
    await storage.write("_audit", key, stringToBytes(JSON.stringify(Object.fromEntries(Object.entries(envelope).reverse()))));
    storage.entryReads = 0; decrypt.mockClear();
    await reader.runAllowingIntegrityFindings(() => reader.query({}));
    expect(storage.entryReads).toBe(K + M);
    expect(decrypt).toHaveBeenCalledTimes(M + 1);
  });
  it("evicts missing entries, clears storage-failed passes, and bypasses streaming caches", async () => {
    const { reader, storage } = await buildChain(5, { verifyCacheMaxEntries: 4 });
    await reader.query({});
    const decrypt = vi.spyOn(reader as any, "decryptEntryPayload");
    await reader.streamVerifiedChain({ onEntry: () => undefined });
    expect(decrypt).toHaveBeenCalledTimes(5);
    expect(reader.verificationCacheStats().cached_entries).toBe(4);
    const keys = await storage.list("_audit");
    for (const key of keys.slice(0, 3)) await storage.delete("_audit", key.key);
    await reader.runAllowingIntegrityFindings(() => reader.query({}));
    expect(reader.verificationCacheStats().cached_entries).toBeLessThanOrEqual(2);
    vi.spyOn(storage, "list").mockRejectedValue(new Error("storage unavailable"));
    await reader.runAllowingIntegrityFindings(() => reader.query({}));
    expect(reader.verificationCacheStats().cached_entries).toBe(0);
  });
  it("keeps the cap and a loose heap bound over fifty append waves", async () => {
    const K = 8, M = 4, WAVES = 50;
    const { reader, storage, masterKey } = await buildChain(K + M, { verifyCacheMaxEntries: K });
    const writer = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    await reader.query({}); const initialHeap = process.memoryUsage().heapUsed;
    for (let wave = 0; wave < WAVES; wave++) {
      await writer.appendCritical({ layer: "l1", operation: "cache_wave", identity_id: "fixture", result: "success" });
      await reader.query({});
      expect(reader.verificationCacheStats().cached_entries).toBe(K);
      expect(reader.verificationCacheStats().verified_uncached_last_pass).toBe(M + wave + 1);
    }
    // 1 MiB per wave is loose headroom for V8's uncollected crypto/test temporaries.
    expect(process.memoryUsage().heapUsed - initialHeap).toBeLessThan(WAVES * 1024 * 1024);
  });
  it("validates test bounds without enlarging production limits", () => {
    for (const cap of [0, -1, 1.5, AUDIT_VERIFY_CACHE_MAX_ENTRIES + 1]) expect(() => new AuditLog(new MemoryStorage(), generateRandomKey(), { verifyCacheMaxEntries: cap })).toThrow();
    for (const interval of [0, -1, Infinity, AUDIT_EAGER_SENTINEL_INTERVAL_MS + 1]) expect(() => new AuditLog(new MemoryStorage(), generateRandomKey(), { eagerBytePassIntervalMs: interval })).toThrow();
  });
  it("measures warm and one-change passes on ten thousand entries", async () => {
    const TOTAL = 10_000;
    const { reader, storage } = await buildChain(TOTAL);
    await reader.query({});
    const decrypt = vi.spyOn(reader as any, "decryptEntryPayload");
    storage.entryReads = 0;
    const start = performance.now(); await reader.query({}); const warmMs = performance.now() - start;
    const warmReads = storage.entryReads, warmDecrypts = decrypt.mock.calls.length;
    expect(warmReads).toBe(TOTAL); expect(warmDecrypts).toBe(0);
    const changedKey = (await storage.list("_audit"))[TOTAL - 2]!.key;
    const changedEnvelope = JSON.parse(bytesToString((await storage.read("_audit", changedKey))!));
    await storage.write("_audit", changedKey, stringToBytes(JSON.stringify(Object.fromEntries(Object.entries(changedEnvelope).reverse()))));
    storage.entryReads = 0; decrypt.mockClear();
    const changedStart = performance.now(); await reader.runAllowingIntegrityFindings(() => reader.query({}));
    const changedMs = performance.now() - changedStart;
    expect(storage.entryReads).toBe(TOTAL); expect(decrypt).toHaveBeenCalledTimes(1);
    process.stdout.write(JSON.stringify({ measurement: "verification-cache", entries: TOTAL, warm_ms: warmMs, warm_reads: warmReads,
      warm_decrypts: warmDecrypts, changed_ms: changedMs, changed_reads: storage.entryReads, changed_decrypts: decrypt.mock.calls.length }) + "\n");
  });
});

it("bounds the ascending accumulator before each insertion", () => {
  const CAP = 2; // Two retained summaries and one overflow exercise the eviction edge.
  const entries = new BoundedVerificationEntries<{ sequence: number }>(CAP);
  for (let sequence = 1; sequence <= CAP + 1; sequence++) entries.retain(String(sequence), { sequence });
  expect(entries.size).toBe(CAP);
  expect([...entries.entries.values()].map(entry => entry.sequence)).toEqual([2, 3]);
  expect(entries.evicted).toBe(1);
});
it("bounds the accumulator throughout a pass three times its cap", async () => {
  const CAP = 4, MULTIPLE = 3; // Two complete windows must be evicted during this pass.
  const { reader } = await buildChain(CAP * MULTIPLE, { verifyCacheMaxEntries: CAP });
  const original = BoundedVerificationEntries.prototype.retain;
  let peak = 0;
  const inserts = vi.spyOn(BoundedVerificationEntries.prototype, "retain").mockImplementation(function (this: BoundedVerificationEntries<unknown>, key, value) {
    const result = original.call(this, key, value);
    peak = Math.max(peak, this.size);
    expect(this.size).toBeLessThanOrEqual(CAP);
    return result;
  });
  await reader.query({});
  expect(inserts).toHaveBeenCalledTimes(CAP * MULTIPLE);
  expect(peak).toBe(CAP);
  expect(reader.verificationCacheStats()).toEqual({ cache_cap: CAP, cached_entries: CAP, verified_uncached_last_pass: CAP * (MULTIPLE - 1) });
});
it("pins verification retention to the configured in-memory window", () => {
  const WINDOW = 512; // Two times the minimum 256-entry window, smaller than default retention.
  const reader = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxInMemoryEntries: WINDOW });
  expect(reader.verificationCacheStats().cache_cap).toBe(WINDOW);
});
