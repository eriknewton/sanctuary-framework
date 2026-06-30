/**
 * Reload-amplification bound (the REAL Slice-M daemon OOM on a large on-disk
 * log; #821 fixed a smaller APPEND-path leak).
 *
 * Before the fix, every `verifiedChainView()` / reload re-decrypted the WHOLE
 * on-disk chain into a fresh `AuditEntry[]`, so a daemon emitting transparency
 * checkpoints / re-verifying on a tick against a large log allocated the whole
 * multi-GB chain PER TICK. `streamVerifiedChain` delivers the full verified
 * chain one decrypted entry at a time and releases each, so the instance never
 * materializes the full decrypted chain into `this.entries`.
 *
 * These tests pin the two properties that must BOTH hold:
 *   1. memory is bounded   — a streaming pass over a large log does not grow the
 *      instance's in-memory window to the full chain, and the consumer is free
 *      to hold only its incremental fold.
 *   2. tamper is detected  — a tampered/reordered/missing entry on a LARGE log
 *      still makes the streaming pass throw `AuditIntegrityError` (strict mode),
 *      exactly as the array view did; and the streamed fold is byte-identical
 *      to the materialized array view over a clean chain.
 */
import { describe, expect, it } from "vitest";
import {
  AuditIntegrityError,
  AuditLog,
  type PersistedAuditEnvelopeV2,
  type VerifiedChainItem,
} from "../../src/operational/audit-log.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WorkloadLifecycleSchemaError,
  WorkloadRegistry,
} from "../../src/workload-lifecycle/index.js";

const IN_MEMORY_FLOOR = 256;

function createLog(maxInMemoryEntries = IN_MEMORY_FLOOR): {
  log: AuditLog;
  storage: MemoryStorage;
  masterKey: Uint8Array;
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const log = new AuditLog(storage, masterKey, {
    // Big disk cap so nothing rotates out; small in-memory window so the
    // "instance does not hold the full chain" assertion is meaningful.
    maxEntries: 1_000_000,
    maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
    maxInMemoryEntries,
  });
  return { log, storage, masterKey };
}

async function seed(log: AuditLog, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    const op = i % 2 === 0 ? "egress_allowed" : "egress_blocked";
    await log.append("l1", op, `id-${i % 4}`, {
      rule_id: `rule-${i % 8}`,
      // A non-trivial payload so a materialized full chain would be visibly
      // larger than the bounded window — the amplification this test guards.
      blob: "x".repeat(256),
      i,
    });
  }
  await log.flush();
}

describe("AuditLog reload amplification bound", () => {
  // The "large log" property only needs to be large RELATIVE TO the 256-entry
  // in-memory window (IN_MEMORY_FLOOR): 1024 on-disk entries vs a 256 window
  // still proves the instance never materializes the full chain (the bound), at
  // ~4x the floor, while keeping the per-test crypto-seed cost (1024 authenticated
  // append+decrypt round-trips) inside CI's default 30s vitest budget. At
  // TOTAL=4000 each heavy test ran ~12s locally but 42-60s on the 2-core CI
  // runners and timed out at 30s — a deterministic budget overflow, not a flake
  // and not a tamper-detection regression (the logic is identical; see git
  // history). HEAVY_TIMEOUT_MS adds margin so CI-runner variance can never
  // re-trip the wall even on a slow host.
  const TOTAL = 1024;
  const HEAVY_TIMEOUT_MS = 60_000;

  it("streamVerifiedChain serves the FULL verified chain in order without materializing it into the instance", async () => {
    const { log } = createLog();
    await seed(log, TOTAL);

    // Precondition: the in-memory window is trimmed FAR below the on-disk total,
    // so a pass that materialized the full chain into the instance would blow it
    // past the floor — exactly the amplification we are bounding.
    expect(log.size).toBe(IN_MEMORY_FLOOR);
    expect(log.size).toBeLessThan(TOTAL);

    // Stream the whole chain, folding only a running count + the last sequence
    // (the consumer never retains the full AuditEntry[] — that is the bound).
    let count = 0;
    let lastSeq = 0;
    let prevSeq = 0;
    let ascending = true;
    let payloadsSeen = 0;
    await log.streamVerifiedChain({
      onEntry: (item: VerifiedChainItem) => {
        count++;
        if (count > 1 && item.sequence !== prevSeq + 1) ascending = false;
        prevSeq = item.sequence;
        lastSeq = item.sequence;
        // Prove the decrypted payload really reached the consumer.
        if (typeof item.entry.details?.blob === "string") payloadsSeen++;
      },
      reset: () => {
        count = 0;
        prevSeq = 0;
        lastSeq = 0;
        ascending = true;
        payloadsSeen = 0;
      },
    });

    expect(count).toBe(TOTAL); // full chain delivered
    expect(ascending).toBe(true); // strictly ascending sequence, no gaps
    expect(lastSeq).toBe(TOTAL); // up to the head
    expect(payloadsSeen).toBe(TOTAL); // every decrypted payload reached the consumer

    // The streaming pass did NOT grow the instance's in-memory window to the
    // full chain: it is still the trimmed window, not TOTAL. This is the
    // memory bound — a large on-disk log is never fully resident in the instance.
    expect(log.size).toBe(IN_MEMORY_FLOOR);
    expect(log.size).toBeLessThan(TOTAL);
  }, HEAVY_TIMEOUT_MS);

  it("streamed fold is byte-identical to the materialized verifiedChainView over a clean large chain", async () => {
    const { log } = createLog();
    await seed(log, TOTAL);

    const array = await log.verifiedChainView();
    const arrayHashes = array.map((item) => item.entry_hash);
    const arraySeqs = array.map((item) => item.sequence);

    let streamedHashes: string[] = [];
    let streamedSeqs: number[] = [];
    await log.streamVerifiedChain({
      onEntry: (item) => {
        streamedHashes.push(item.entry_hash);
        streamedSeqs.push(item.sequence);
      },
      reset: () => {
        streamedHashes = [];
        streamedSeqs = [];
      },
    });

    expect(streamedHashes).toEqual(arrayHashes);
    expect(streamedSeqs).toEqual(arraySeqs);
  }, HEAVY_TIMEOUT_MS);

  it("DETECTS a tampered payload on a large log (streaming pass throws AuditIntegrityError)", async () => {
    const { log, storage, masterKey } = createLog();
    await seed(log, TOTAL);

    // Tamper with one entry's persisted envelope deep in the chain: flip its
    // entry_hash so the recomputed hash no longer matches. A fresh reader must
    // surface this on the STREAMING verify path, not just the array view.
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const victimKey = keys[Math.floor(keys.length / 2)]!;
    const raw = await storage.read("_audit", victimKey);
    const env = JSON.parse(bytesToString(raw!)) as PersistedAuditEnvelopeV2;
    env.entry_hash = "0".repeat(env.entry_hash.length);
    await storage.write("_audit", victimKey, stringToBytes(JSON.stringify(env)));

    const reader = new AuditLog(storage, masterKey, {
      maxEntries: 1_000_000,
      maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
      maxInMemoryEntries: IN_MEMORY_FLOOR,
    });

    await expect(
      reader.streamVerifiedChain({ onEntry: () => undefined })
    ).rejects.toBeInstanceOf(AuditIntegrityError);
  }, HEAVY_TIMEOUT_MS);

  it("DETECTS a missing (truncated) entry on a large log via the streaming pass", async () => {
    const { log, storage, masterKey } = createLog();
    await seed(log, TOTAL);

    // Delete an interior entry — a hole in the middle of the chain. The forward
    // walk must localize the break and the strict reader must throw.
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const victimKey = keys[Math.floor(keys.length / 2)]!;
    await storage.delete("_audit", victimKey);

    const reader = new AuditLog(storage, masterKey, {
      maxEntries: 1_000_000,
      maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
      maxInMemoryEntries: IN_MEMORY_FLOOR,
    });

    await expect(
      reader.streamVerifiedChain({ onEntry: () => undefined })
    ).rejects.toBeInstanceOf(AuditIntegrityError);
  }, HEAVY_TIMEOUT_MS);

  it("DETECTS reordered entries on a large log via the streaming pass", async () => {
    const { log, storage, masterKey } = createLog();
    await seed(log, TOTAL);

    // Swap two adjacent interior entries' persisted payloads under their keys:
    // the keys stay sequence-ordered but the envelope sequences/hashes no longer
    // match their slot, so the forward walk flags a sequence/prev-hash break.
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const i = Math.floor(keys.length / 2);
    const a = await storage.read("_audit", keys[i]!);
    const b = await storage.read("_audit", keys[i + 1]!);
    await storage.write("_audit", keys[i]!, b!);
    await storage.write("_audit", keys[i + 1]!, a!);

    const reader = new AuditLog(storage, masterKey, {
      maxEntries: 1_000_000,
      maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
      maxInMemoryEntries: IN_MEMORY_FLOOR,
    });

    await expect(
      reader.streamVerifiedChain({ onEntry: () => undefined })
    ).rejects.toBeInstanceOf(AuditIntegrityError);
  }, HEAVY_TIMEOUT_MS);

  it("propagates a CONSUMER's rejection AS ITSELF, not relabeled as a decrypt/storage finding", async () => {
    // A consumer (here workload replay) that throws on a malformed-but-decrypted
    // entry must surface its REAL error, not be miscategorized. Before the hoist,
    // onEntry ran inside the decrypt try/catch, so a consumer throw was relabeled
    // `entry_decrypt_failed` (decrypt actually SUCCEEDED) and, under a lenient
    // pass, would be silently skipped (the #504 under-report). The hoist makes the
    // consumer error propagate verbatim.
    const { log } = createLog();
    // A clean lifecycle entry first, then a lifecycle op with malformed details
    // (decrypts fine; fails validateWorkloadLifecyclePayload). appendCritical
    // does NOT validate the lifecycle payload shape, so the malformed details
    // reach the chain decrypted and intact, exercising exactly the consumer path.
    await log.appendCritical({
      layer: "l1",
      operation: WORKLOAD_LIFECYCLE_OPS.REGISTERED,
      identity_id: "id-good",
      result: "success",
      details: { lifecycle_schema: "definitely-not-the-real-schema", junk: true },
    });
    await log.flush();

    // The registry consumer streams the verified chain and calls apply ->
    // validateWorkloadLifecyclePayload, which throws WorkloadLifecycleSchemaError.
    await expect(WorkloadRegistry.fromAuditLog(log)).rejects.toBeInstanceOf(
      WorkloadLifecycleSchemaError
    );
    // It must NOT be swallowed/relabeled as an integrity finding.
    await expect(WorkloadRegistry.fromAuditLog(log)).rejects.not.toBeInstanceOf(
      AuditIntegrityError
    );
  });

  it("a genuinely undecryptable entry STILL surfaces as a decrypt finding (decrypt-error semantics preserved)", async () => {
    // The hoist must not weaken the real decrypt path: corrupt an entry's
    // ciphertext so decryption fails, and confirm strict mode still throws
    // AuditIntegrityError (an entry_decrypt_failed finding), distinct from the
    // consumer-rejection path above.
    const { log, storage, masterKey } = createLog();
    await log.append("l1", "egress_allowed", "id-1", { rule_id: "r" });
    await log.flush();

    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const victimKey = keys[keys.length - 1]!;
    const env = JSON.parse(
      bytesToString((await storage.read("_audit", victimKey))!)
    ) as PersistedAuditEnvelopeV2;
    // Truncate the encrypted payload so the inner decrypt/JSON.parse throws. The
    // entry_hash covers these bytes, so a strict reader surfaces a finding
    // (decrypt failure and/or hash mismatch) and throws AuditIntegrityError; the
    // point is that this is an INTEGRITY finding, NOT the consumer-rejection
    // error class from the previous test.
    env.encrypted_payload_bytes = env.encrypted_payload_bytes.slice(0, 8);
    await storage.write(
      "_audit",
      victimKey,
      stringToBytes(JSON.stringify(env))
    );

    const reader = new AuditLog(storage, masterKey, {
      maxEntries: 1_000_000,
      maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
      maxInMemoryEntries: IN_MEMORY_FLOOR,
    });
    await expect(
      reader.streamVerifiedChain({ onEntry: () => undefined })
    ).rejects.toBeInstanceOf(AuditIntegrityError);
  });
});
