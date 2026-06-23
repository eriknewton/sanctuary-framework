/**
 * Eager (bounded-cost) audit read path - perf + never-stale-green honesty.
 *
 * Backs the #714 fix: the always-on posture surface (home board + per-panel
 * endpoints + SSE push) used to re-read, re-decrypt, re-hash and chain-walk the
 * ENTIRE audit chain from disk on EVERY read (`AuditLog.query`). On a real
 * 10k-entry / 40MB chain that was 11-30s per paint and pegged the event loop;
 * the SSE cadence made an open board recompute it continuously and wedge the
 * server. The fix adds `AuditLog.queryEager` / `runEagerReads`: reads serve from
 * the eagerly-maintained in-memory verified view with a THROTTLED out-of-band
 * on-disk re-verify, so per-request cost no longer scales with chain length.
 *
 * These tests are the synthetic-fixture replacement for a wall-clock soak (the
 * soaks-are-fake-without-users rule): they construct a >=10k valid chain and
 * assert (a) the eager read is fast AND does not scale with chain length, and
 * (b) the never-stale-green honesty invariant holds on the eager path.
 */
import { describe, expect, it } from "vitest";
import {
  AuditIntegrityError,
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  computeAuditEntryHash,
} from "../../src/audit/chain.js";

const LARGE_CHAIN = 10_200; // > 10k, the drill's real chain size class.

/**
 * Build a valid chain of `count` entries CHEAPLY: write raw valid v2 envelopes
 * directly into MemoryStorage (the exact bytes `persistChainedEntry` would write
 * - same hash, same encryption, same chaining), then do ONE real `appendCritical`
 * so the writer establishes a valid head anchor over the resulting head. This
 * yields a genuinely valid >=count chain in a fraction of the time `count`
 * durability-verified appends take (10k appends is ~70s; this is sub-second),
 * while staying byte-identical to a real chain. Returns a FRESH reader over the
 * store so the first eager read pays the unconditional load-time full verify,
 * exactly as a freshly-booted dashboard would.
 */
async function buildChain(
  count: number,
): Promise<{ storage: MemoryStorage; masterKey: Uint8Array; reader: AuditLog }> {
  const storage = new MemoryStorage();
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

  const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
  return { storage, masterKey, reader };
}

describe("AuditLog eager read - performance (does not scale with chain length)", () => {
  it(
    "serves a warm eager read over a >=10k chain well under the bound, and warm reads do not scale with chain length",
    async () => {
      const { reader } = await buildChain(LARGE_CHAIN);

      // Cold read pays the unconditional load-time full verify (the tamper floor).
      const cold0 = performance.now();
      const cold = await reader.queryEager({ limit: 50 });
      const coldMs = performance.now() - cold0;
      expect(cold.total).toBe(LARGE_CHAIN);
      expect(cold.integrity_findings).toEqual([]);

      // Warm reads (within the re-verify throttle) serve from the eager view and
      // must be FAST and bounded - independent of chain length.
      const warmTimings: number[] = [];
      for (let r = 0; r < 5; r++) {
        const t0 = performance.now();
        const res = await reader.queryEager({ limit: 50 });
        warmTimings.push(performance.now() - t0);
        expect(res.total).toBe(LARGE_CHAIN);
      }
      const maxWarm = Math.max(...warmTimings);
      // Defensible bound: a warm eager read over 10k entries must complete well
      // under 500ms (the drill measured 11-30s on the OLD full-rescan path). In
      // practice the warm path is a few ms; 500ms leaves generous CI headroom
      // while still failing hard if the full-rescan regressed back in.
      expect(maxWarm).toBeLessThan(500);

      // Scale-independence: a warm read on a 10k chain is not dramatically slower
      // than a warm read on a tiny chain (it would be ~linear if it re-scanned).
      const small = await buildChain(50);
      await small.reader.queryEager({ limit: 50 }); // warm it
      const s0 = performance.now();
      await small.reader.queryEager({ limit: 50 });
      const smallWarmMs = performance.now() - s0;
      // The 10k warm read must stay within a small constant factor of the 50-entry
      // warm read (allow a floor for timer noise). A per-request FULL re-scan would
      // make the 10k read ~200x the small one and blow this assertion.
      expect(maxWarm).toBeLessThan(smallWarmMs * 25 + 100);

      // Sanity: cold (full-verify) over 10k is itself far under the OLD 11-30s.
      expect(coldMs).toBeLessThan(10_000);
    },
    60_000,
  );
});

describe("AuditLog eager read - never-stale-green honesty", () => {
  it("a newly-appended entry is reflected by the very next eager read with NO stale lag", async () => {
    const { storage, masterKey } = await buildChain(100);
    // A live server instance: same instance appends AND serves the board, which
    // is the real never-stale path (eager view maintained on each append).
    const server = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    const before = await server.queryEager({ limit: 5 });
    expect(before.total).toBe(100);

    // Append through the SAME instance (the sole-appender invariant).
    await server.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "agent-x",
      result: "failure",
      details: { op: "new" },
    });

    // The very next eager read - WITHOUT waiting out the throttle window - must
    // reflect the new entry. This is the eager-maintenance guarantee: the view is
    // updated on append, not lazily on a cache-miss.
    const after = await server.queryEager({ limit: 5 });
    expect(after.total).toBe(101);
    expect(after.integrity_findings).toEqual([]);
    expect(after.entries.at(-1)?.operation).toBe("egress_blocked");
  });

  it("an out-of-band tampered entry surfaces an integrity finding on the eager path - NEVER green", async () => {
    const { storage, masterKey } = await buildChain(200);

    // Out-of-band tamper: edit an on-disk entry's ciphertext directly (bypassing
    // the server), exactly the threat the load-time full verify defends against.
    const keys = (await storage.list("_audit"))
      .map((m) => m.key)
      .sort((a, b) => a.localeCompare(b));
    const victimKey = keys[100]!;
    const raw = await storage.read("_audit", victimKey);
    const env = JSON.parse(bytesToString(raw!)) as PersistedAuditEnvelopeV2;
    env.encrypted_payload_bytes = env.encrypted_payload_bytes
      .split("")
      .reverse()
      .join("");
    await storage.write(
      "_audit",
      victimKey,
      stringToBytes(JSON.stringify(env)),
    );

    // A FRESH reader's first eager read pays the unconditional load-time full
    // verify and MUST catch the tamper - strict mode throws (never green).
    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    await expect(reader.queryEager({ limit: 50 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
    } satisfies Partial<AuditIntegrityError>);

    // And in lenient mode (the shape the posture builders consume via
    // runAllowingIntegrityFindings) the finding is SURFACED, not hidden: the
    // builder turns a non-empty integrity_findings into chain_verified=false.
    const lenient = new AuditLog(storage, masterKey, {
      checkpointInterval: 0,
      integrityMode: "lenient",
    });
    const res = await lenient.queryEager({ limit: 50 });
    expect(res.integrity_findings.length).toBeGreaterThan(0);
  });

  it("the load-time full verify still catches a PRE-EXISTING bad chain on the eager path (tamper floor preserved)", async () => {
    const { storage, masterKey } = await buildChain(300);
    // Delete a middle entry on disk: a sequence gap a fresh boot must detect.
    const keys = (await storage.list("_audit"))
      .map((m) => m.key)
      .sort((a, b) => a.localeCompare(b));
    await storage.delete("_audit", keys[150]!);

    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    // Eager read's unconditional load-time verify fails loud on the gap.
    await expect(reader.queryEager({ limit: 50 })).rejects.toMatchObject({
      name: "AuditIntegrityError",
    } satisfies Partial<AuditIntegrityError>);
  });

  it("a clean empty chain reads cleanly on the eager path (neutral-empty, never green-from-absence)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    const res = await reader.queryEager({ limit: 50 });
    // Empty is empty: zero entries, zero findings. The posture builders map this
    // to honest empty/neutral panels (counts of 0), not a fabricated green.
    expect(res.total).toBe(0);
    expect(res.entries).toEqual([]);
    expect(res.integrity_findings).toEqual([]);
  });

  it("runEagerReads scopes the throttle to query() too, and parallel eager reads share one verified view", async () => {
    const { reader } = await buildChain(500);
    // Composing several reads in one eager scope (as buildHome does) returns a
    // consistent verified view to every read, with bounded cost.
    const [a, b, c] = await reader.runEagerReads(() =>
      Promise.all([
        reader.query({ limit: 10 }),
        reader.query({ layer: "l1", limit: 10 }),
        reader.query({ operation_type: "egress_allowed", limit: 10 }),
      ]),
    );
    expect(a.total).toBe(500);
    expect(a.integrity_findings).toEqual([]);
    expect(b.total).toBe(500);
    expect(c.total).toBe(500);
  });
});
